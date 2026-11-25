// The example's Worker: one run of crates/wasmnet-host/examples/http.rs, in the browser.
//
//   client (http-get) ──100 µs── switch ──150 µs── server (http-server)
//     10.0.0.2                                        10.0.0.1
//
// One run per Worker (jco's runtime and the kit's event loop are global), started by the page
// with the kit's `runInWorker`: `init` carries the seed and the compiled modules, the journal
// streams back as messages while the network runs, and the outcome and the captures are the
// run's value.
//
// With `init.scenario = 'controls'` it runs the same network with what an embedder controls at
// run time instead: the server gets arguments and an environment variable and puts them in its
// page, and the switch is programmed by command, between runs and as an operator event. The
// page's test runs it (`window.wasmnetScenario`), and `runtime` (below): devices created while
// the network runs.

import { serveRun } from './codelib-web/dist/worker/index.js';
import { Network, type CommandAnswer, type ComponentSource, type JournalEntry, type Outcome } from './network.js';

declare const self: DedicatedWorkerGlobalScope;

export interface Init {
  seed: string;
  simulator: WebAssembly.Module;
  components: Record<string, ComponentSource>;
  scenario?: 'example' | 'controls' | 'runtime';
}

export interface Done {
  outcome: Outcome;
  links: { name: string; pcap: Uint8Array }[];
  /** Wall-clock time of the run itself (after loading), in ms. */
  ms: number;
  /** The `controls` scenario's command answers, by label (null: the device takes none). */
  answers?: Record<string, CommandAnswer | null>;
  /** A scenario's other results, by label. */
  notes?: Record<string, string>;
}

/** A message the Worker posts while the network runs. */
export type Progress = { type: 'journal'; entries: JournalEntry[] };

/** Deterministic CBOR (RFC 8949 §4.2) of strings and maps of strings: a device spec. */
type Cbor = string | { [key: string]: Cbor };
function cbor(v: Cbor): number[] {
  const head = (major: number, n: number) => (n < 24 ? [(major << 5) | n] : n < 256 ? [(major << 5) | 24, n] : [(major << 5) | 25, n >> 8, n & 0xff]);
  if (typeof v === 'string') {
    const b = [...new TextEncoder().encode(v)];
    return [...head(3, b.length), ...b];
  }
  // Keys sorted by their encoded bytes.
  const entries = Object.entries(v)
    .map(([k, x]) => [cbor(k), cbor(x)] as const)
    .sort(([a], [b]) => {
      for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
      return a.length - b.length;
    });
  return [...head(5, entries.length), ...entries.flatMap(([k, x]) => [...k, ...x])];
}
const hex = (bytes: number[]) => bytes.map((b) => b.toString(16).padStart(2, '0')).join('');

/**
 * The `runtime` scenario: devices the network creates while it runs. An `infra-script`
 * controller creates a router, commands it, stops it, starts it again (a fresh instance) and
 * commands it once more; a `replicas` controller (an async app, woken by `changes.wait`) keeps
 * two web servers running, and a client fetches from one of them. Every one of those devices is
 * instantiated by the page when the simulator asks for it.
 */
async function runtime(net: Network): Promise<Record<string, string>> {
  // A component that imports `wasmnet:infra`, for a device without the grant: refused before
  // it is instantiated, as natively.
  let refused = '';
  try {
    await net.device('nogrant', 'infra_script');
  } catch (err) {
    refused = err instanceof Error ? err.message : String(err);
  }
  net.setCatalog(['router', 'node-http-server']);
  const sw = await net.device('sw', 'switch', { ports: '8' });
  const r1 = hex(cbor({ component: 'router', config: { mac: '02:00:00:00:fe:10', 'port0.ipv4': '10.0.1.1/24', 'port1.ipv4': '10.0.2.1/24' } }));
  const steps = [
    `0ms apply r1 ${r1}`,
    '1ms id=q control r1 routes',
    '2ms answer q',
    '3ms stop r1',
    '4ms start r1',
    '5ms id=q2 control r1 route-add 10.0.3.0/24 via 10.0.2.2',
    '6ms answer q2',
  ];
  await net.device('ctl', 'infra_script', Object.fromEntries(steps.map((s, n) => [`step.${n}`, s])), { infra: true, infraPrefix: 'r' });
  const rep = await net.device(
    'rep',
    'node-replicas',
    {
      mac: '02:00:00:00:00:09',
      ipv4: '10.0.0.9/24',
      'app.replicas.replicas': '2',
      'app.replicas.prefix': 'web',
      // A long period: what happens before it, happens because `changes.wait` woke the app.
      'app.replicas.period': '10s',
      'app.replicas.wake': 'true',
      'app.replicas.template.component': 'node-http-server',
      'app.replicas.template.config.mac': '02:00:00:00:01:{n+10}',
      'app.replicas.template.config.ipv4': '10.0.0.{n+10}/24',
      'app.replicas.template.wire.0.port': '0',
      'app.replicas.template.wire.0.to': 'sw:{n+2}',
    },
    { infra: true, infraPrefix: 'web' },
  );
  const client = await net.device('client', 'node-http-get', {
    mac: '02:00:00:00:00:02',
    ipv4: '10.0.0.2/24',
    'app.http-get.url': 'http://10.0.0.11/',
    'app.http-get.start': '500ms',
  });
  net.link(rep.port(0), sw.port(0), 50_000n);
  net.link(client.port(0), sw.port(1), 50_000n);
  return { refused };
}

serveRun<Init, Done>(async (init, ctx) => {
  const net = await Network.create(init.simulator, { seed: BigInt(init.seed), components: init.components });
  if (init.scenario === 'runtime') {
    const notes = await runtime(net);
    ctx.running();
    const t0 = performance.now();
    // The replicas controller never rests: run to a deadline.
    const outcome = await net.run({ deadline: 3_000_000_000n, onJournal: (entries) => ctx.post({ type: 'journal', entries } satisfies Progress) });
    return { outcome, links: net.links().map((l) => ({ name: l.name, pcap: net.pcap(l) })), ms: Math.round(performance.now() - t0), notes };
  }
  const controls = init.scenario === 'controls';

  // The same network as examples/http.rs.
  const sw = await net.device('sw', 'switch', { ports: '4' });
  const page: Record<string, string> = controls ? { 'app.http-server.route.e.path': '/', 'app.http-server.route.e.body': '{args}|{env:GREETING}' } : {};
  const server = await net.device(
    'server',
    'node-http-server',
    {
      mac: '02:00:00:00:00:01',
      ipv4: '10.0.0.1/24',
      'app.http-server.listen': '0.0.0.0:80',
      ...page,
    },
    controls ? { args: ['-v', 'two words'], env: [['GREETING', 'hello from the tab']] } : {},
  );
  const client = await net.device('client', 'node-http-get', {
    mac: '02:00:00:00:00:02',
    ipv4: '10.0.0.2/24',
    'hosts.web': '10.0.0.1',
    'app.http-get.url': 'http://web/',
    'app.http-get.start': '1ms',
  });
  net.link(server.port(0), sw.port(1), 150_000n);
  net.link(client.port(0), sw.port(2), 100_000n);

  const answers: Record<string, CommandAnswer | null> = {};
  if (controls) {
    // Ports 0 and 3 are free: blocking between them leaves the fetch alone.
    answers.block = await net.command(sw, 'block', '0 3');
    answers.paths = await net.command(sw, 'paths');
    answers.unknown = await net.command(sw, 'nope');
    answers.server = await net.command(server, 'paths');
    net.scheduleCommand(sw, 5_000_000n, 'unblock', '0 3');
  }

  ctx.running();
  const t0 = performance.now();
  const outcome = await net.run({ onJournal: (entries) => ctx.post({ type: 'journal', entries } satisfies Progress) });
  const ms = Math.round(performance.now() - t0);
  if (controls) answers.after = await net.command(sw, 'paths');
  return { outcome, links: net.links().map((l) => ({ name: l.name, pcap: net.pcap(l) })), ms, ...(controls ? { answers } : {}) };
});

void self;
