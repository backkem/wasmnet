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
// page's test runs it (`window.wasmnetScenario`).

import { serveRun } from './codelib-web/dist/worker/index.js';
import { Network, type CommandAnswer, type ComponentSource, type JournalEntry, type Outcome } from './network.js';

declare const self: DedicatedWorkerGlobalScope;

export interface Init {
  seed: string;
  simulator: WebAssembly.Module;
  components: Record<string, ComponentSource>;
  scenario?: 'example' | 'controls';
}

export interface Done {
  outcome: Outcome;
  links: { name: string; pcap: Uint8Array }[];
  /** Wall-clock time of the run itself (after loading), in ms. */
  ms: number;
  /** The `controls` scenario's command answers, by label (null: the device takes none). */
  answers?: Record<string, CommandAnswer | null>;
}

/** A message the Worker posts while the network runs. */
export type Progress = { type: 'journal'; entries: JournalEntry[] };

serveRun<Init, Done>(async (init, ctx) => {
  const net = await Network.create(init.simulator, { seed: BigInt(init.seed), components: init.components });
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
    answers.block = net.command(sw, 'block', '0 3');
    answers.paths = net.command(sw, 'paths');
    answers.unknown = net.command(sw, 'nope');
    answers.server = net.command(server, 'paths');
    net.scheduleCommand(sw, 5_000_000n, 'unblock', '0 3');
  }

  ctx.running();
  const t0 = performance.now();
  const outcome = await net.run({ onJournal: (entries) => ctx.post({ type: 'journal', entries } satisfies Progress) });
  const ms = Math.round(performance.now() - t0);
  if (controls) answers.after = net.command(sw, 'paths');
  return { outcome, links: net.links().map((l) => ({ name: l.name, pcap: net.pcap(l) })), ms, ...(controls ? { answers } : {}) };
});

void self;
