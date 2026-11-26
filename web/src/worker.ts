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
  scenario?: 'example' | 'controls' | 'runtime' | 'portable' | 'portable-cost' | 'exports' | 'disks' | 'disk-cost';
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

/** Deterministic CBOR (RFC 8949 §4.2) of strings, arrays and maps: a device spec. */
type Cbor = string | Cbor[] | { [key: string]: Cbor };
function cbor(v: Cbor): number[] {
  const head = (major: number, n: number) => (n < 24 ? [(major << 5) | n] : n < 256 ? [(major << 5) | 24, n] : [(major << 5) | 25, n >> 8, n & 0xff]);
  if (typeof v === 'string') {
    const b = [...new TextEncoder().encode(v)];
    return [...head(3, b.length), ...b];
  }
  if (Array.isArray(v)) return [...head(4, v.length), ...v.flatMap(cbor)];
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
 * commands it once more, and reads its events (`events.read`, a rule armed with `events.arm`); a
 * `replicas` controller (an async app, woken by `changes.wait-any`) keeps
 * two web servers running, and a client fetches from one of them; a second `replicas` fetches a
 * component's bytes from a store node, supplies them and runs two instances by digest. Every one
 * of those devices is instantiated by the page when the simulator asks for it.
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
  const sw = await net.device('sw', 'switch', { ports: '16' });
  const r1 = hex(cbor({ component: 'router', config: { mac: '02:00:00:00:fe:10', 'port0.ipv4': '10.0.1.1/24', 'port1.ipv4': '10.0.2.1/24' } }));
  const steps = [
    `0ms apply r1 ${r1}`,
    '1ms id=q control r1 routes',
    '2ms answer q',
    '3ms stop r1',
    '4ms start r1',
    '5ms id=q2 control r1 route-add 10.0.3.0/24 via 10.0.2.2',
    '6ms answer q2',
    // The router's events (`wasmnet:infra/events.read`).
    '7ms events r1 route-*',
  ];
  // A rule: each `route-added` of r1 makes the controller read r1's events (`events.read`, then
  // `events.arm` for the next one).
  const rules = { 'on.0': 'r1 route-added : events r1 route-added' };
  await net.device('ctl', 'infra_script', { ...Object.fromEntries(steps.map((s, n) => [`step.${n}`, s])), ...rules }, { infra: true, infraPrefix: 'r' });
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
  // A link with capture options (64 bytes of each frame), set through the generic path.
  const clientLink = net.link(client.port(0), sw.port(1), 50_000n, { capture: { snapLen: 64 } });

  // Operator events through the generic path: a line on the replicas controller's stdin (its
  // console: `replicas=3`), and the client's link going down; and one the simulator refuses.
  net.op({ kind: 'stdin', device: 'rep', bytes: 'replicas=3\n', at: 1_000_000_000n });
  net.op({ kind: 'link-state', link: clientLink.name, up: false, at: 2_500_000_000n });
  let badOp = '';
  try {
    net.op({ kind: 'stop-device', at: 0n });
  } catch (err) {
    badOp = err instanceof Error ? err.message : String(err);
  }
  // A memory limit the device does not start within: refused, as natively.
  let memory = '';
  try {
    await net.device('tiny', 'switch', { ports: '1' }, { memory: 1024 });
  } catch (err) {
    memory = err instanceof Error ? err.message : String(err);
  }

  // A component supplied as bytes: a store node serves the switch's component, a second
  // replicas controller fetches it, supplies it (`wasmnet:infra/components`) and runs two
  // instances of it by its digest, which the page runs from its own transpile of those bytes.
  net.setSupplyAdmission(['wasi:*', 'wasmnet:link/*']);
  const bytes = new Uint8Array(await (await fetch(new URL('raw/switch.wasm', self.location.href))).arrayBuffer());
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const digest = `sha256:${[...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
  const store = await net.device('store', 'node-http-server', {
    mac: '02:00:00:00:00:20',
    ipv4: '10.0.0.20/24',
    'app.http-server.route.sw.path': '/sw.wasm',
    'app.http-server.route.sw.body-base64': btoa(binary),
  });
  const sup = await net.device(
    'sup',
    'node-replicas',
    {
      mac: '02:00:00:00:00:21',
      ipv4: '10.0.0.21/24',
      'app.replicas.replicas': '2',
      'app.replicas.prefix': 'sup',
      'app.replicas.period': '200ms',
      'app.replicas.start': '10ms',
      'app.replicas.template.fetch': 'http://10.0.0.20/sw.wasm',
      'app.replicas.template.digest': digest,
      'app.replicas.template.config.ports': '2',
      'app.replicas.template.wire.0.port': '0',
      'app.replicas.template.wire.0.to': 'sw:{n+10}',
    },
    { infra: true, infraPrefix: 'sup', infraSupply: true },
  );
  net.link(store.port(0), sw.port(9), 50_000n);
  net.link(sup.port(0), sw.port(10), 50_000n);
  return { refused, digest, badOp, memory, clientLink: clientLink.name };
}

// What `NetworkOptions.deviceImports` and `instantiateCore` were asked (the `exports` scenario reports them).
const asked: string[] = [];
const cores = { n: 0 };

serveRun<Init, Done>(async (init, ctx) => {
  // The fixture's simulator imports `pad_page.stamp` (an embedder's own import); other modules ignore it.
  const net = await Network.create(init.simulator, {
    seed: BigInt(init.seed),
    components: init.components,
    imports: { pad_page: { stamp: (n: number) => n + 1 } },
    // The per-device imports and the kit's core hook, passed through: what they were asked.
    deviceImports: (d) => {
      asked.push(`${d.name}:${d.component}`);
      return undefined;
    },
    instantiateCore: async (module, imports) => {
      cores.n += 1;
      return WebAssembly.instantiate(module, imports);
    },
  });
  if (init.scenario === 'disk-cost') {
    const notes = await diskCost(net);
    return { outcome: notes.outcome as Outcome, links: [], ms: 0, notes: notes.notes };
  }
  if (init.scenario === 'disks') {
    const t0 = performance.now();
    const notes = await disksScenario(net);
    return { outcome: notes.outcome as Outcome, links: [], ms: Math.round(performance.now() - t0), notes: notes.notes };
  }
  if (init.scenario === 'exports') {
    const t0 = performance.now();
    const notes = await exportsScenario(net);
    return { outcome: notes.outcome as Outcome, links: [], ms: Math.round(performance.now() - t0), notes: notes.notes };
  }
  if (init.scenario === 'portable' || init.scenario === 'portable-cost') {
    const t0 = performance.now();
    const notes = init.scenario === 'portable' ? await portable(net) : await portableCost(net);
    return { outcome: notes.outcome as Outcome, links: [], ms: Math.round(performance.now() - t0), notes: notes.notes };
  }
  if (init.scenario === 'runtime') {
    const notes = await runtime(net);
    ctx.running();
    const t0 = performance.now();
    // The replicas controller never rests: run to a deadline.
    const outcome = await net.run({ deadline: 3_000_000_000n, onJournal: (entries) => ctx.post({ type: 'journal', entries } satisfies Progress) });
    // What the run measured: the operator events' states, the devices' peak memory, and the
    // snap length the client's capture recorded (its interface description block).
    notes.opStates = JSON.stringify(net.opStates().map((s) => s.state));
    notes.peakMemory = String(net.costs().find((c) => c.name === 'sw')?.peakMemory ?? 0n);
    const pcap = net.pcap(net.links().find((l) => l.name === notes.clientLink)!);
    const view = new DataView(pcap.buffer, pcap.byteOffset, pcap.byteLength);
    const shb = view.getUint32(4, true);
    notes.snapLen = String(view.getUint32(shb + 12, true));
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

/** A device's journalled events, one line each: `<at> <device> <kind> k=v ...`. */
function eventLines(entries: JournalEntry[], kinds: RegExp): string {
  return entries
    .filter((e): e is Extract<JournalEntry, { record: 'event' }> => e.record === 'event' && kinds.test(e.kind))
    .map((e) => `${e.at} ${e.device} ${e.kind} ${e.fields.map(([k, v]) => `${k}=${v}`).join(' ')}`)
    .join('\n');
}

/**
 * The `portable` scenario: a portable extension in the page. The simulator is an embedder's own
 * build with the test fixture `wasmnet-pad` installed (`crates/wasmnet-web/examples/pad_page.rs`),
 * whose interface the binding links from its names alone. The same network as the native test
 * `page_scenario_native` (`crates/wasmnet-host/tests/portable.rs`): the page test compares the
 * lines. `p` moves 1 MiB through the interface and is stopped, started, crashed and started;
 * `q` is faulted inside its third append; `r`, a controller's device, is recreated, removed and
 * created again.
 */
async function portable(net: Network): Promise<{ outcome: unknown; notes: Record<string, string> }> {
  net.setCatalog(['pad_probe']);
  await net.device('p', 'pad_probe', { period: '10ms', big: '1048576' }, { crashAlone: true });
  // An option of the extension's, from a plain object: `q`'s third append faults it.
  await net.device('q', 'pad_probe', { period: '10ms' }, { crashAlone: true, 'pad.fault-at': 3 });
  // A device the extension gives no server: its first call faults it.
  await net.device('lonely', 'pad_probe', { period: '10ms' }, { crashAlone: true });
  const spec = (period: string) => hex(cbor({ component: 'pad_probe', config: { period } }));
  await net.device(
    'ctl',
    'infra_script',
    {
      'step.0': `0ms apply r ${spec('10ms')}`,
      'step.1': `45ms apply r ${spec('20ms')}`,
      'step.2': '70ms remove r',
      'step.3': `80ms apply r ${spec('10ms')}`,
    },
    { infra: true },
  );
  const ms = (n: number) => BigInt(n) * 1_000_000n;
  net.op({ kind: 'stop-device', device: 'p', at: ms(55) });
  net.op({ kind: 'start-device', device: 'p', at: ms(60) });
  net.op({ kind: 'crash-device', device: 'p', message: 'operator crash', at: ms(85) });
  net.op({ kind: 'start-device', device: 'p', at: ms(90) });
  // An operator event of the extension's, timed at a device, from a plain object.
  net.op({ kind: 'extension', device: 'p', op: 'pad.clear', at: ms(100) });
  const entries: JournalEntry[] = [];
  const outcome = await net.run({ deadline: ms(120), onJournal: (e) => entries.push(...e) });
  // The embedder's own exports: the extension's state between steps, and its own import.
  const decoder = new TextDecoder();
  const notesOfR = decoder.decode(net.callExport('wn_pad_notes', new TextEncoder().encode('r')));
  const stamped = new DataView(net.callExport('wn_pad_stamp', new Uint8Array([41, 0, 0, 0])).buffer).getUint32(0, true);
  let refused = '';
  try {
    net.callExport('wn_pad_stamp', new Uint8Array([1]));
  } catch (err) {
    refused = err instanceof Error ? err.message : String(err);
  }
  return { outcome, notes: { lines: eventLines(entries, /^(pad-|device-)/), notesOfR, stamped: String(stamped), refused } };
}

/**
 * The `portable-cost` scenario: what a big `list<u8>` costs through the page's half of a
 * portable call (jco's lowering, the binding's encoding, the boundary, the server). A device
 * appends 4 MiB once, then 31 times; the difference over 30 is the cost of one append.
 */
async function portableCost(net: Network): Promise<{ outcome: unknown; notes: Record<string, string> }> {
  const time = async (name: string, reps: number) => {
    await net.device(name, 'pad_probe', { period: '1000ms', big: String(4 << 20), reps: String(reps) });
    const t0 = performance.now();
    await net.run({ deadline: BigInt(name === 'one' ? 1_000_000 : 2_000_000) });
    return performance.now() - t0;
  };
  const one = await time('one', 1);
  const many = await time('many', 31);
  const outcome = { one, many };
  return { outcome, notes: { oneMs: one.toFixed(1), manyMs: many.toFixed(1), perAppendMs: ((many - one) / 30).toFixed(2) } };
}

/**
 * The `exports` scenario: portable exports in the page. The pad's probe exports
 * `wasmnet-test:pad/inspect`; the binding calls it by name between runs (`invoke`), as an
 * operator event (`scheduleInvoke`) and with 4 MiB (what it costs). The same calls as
 * `portable_exports_are_called_alike` (`crates/wasmnet-web/tests/parity.rs`). Also measures
 * what a JSPI `Suspending` import that answers at once costs against a plain one (`jspi`).
 */
async function exportsScenario(net: Network): Promise<{ outcome: unknown; notes: Record<string, string> }> {
  const ms = (n: number) => BigInt(n) * 1_000_000n;
  const p = await net.device('p', 'pad_probe', { period: '10ms' });
  await net.run({ deadline: ms(1) });
  const show = (a: unknown) =>
    JSON.stringify(a, (_, v) => (typeof v === 'bigint' ? `${v}n` : v instanceof Uint8Array ? `bytes:${new TextDecoder().decode(v)}` : v === undefined ? null : v));
  const iface = 'wasmnet-test:pad/inspect';
  const enc = new TextEncoder();
  const notes: Record<string, string> = { exports: net.exports(p).join(',') };
  notes.write = show(await net.invoke(p, `${iface}#write`, ['ext', enc.encode('hello')]));
  net.scheduleInvoke(p, ms(5), `${iface}#write`, ['ext', enc.encode(' world')]);
  const entries: JournalEntry[] = [];
  const outcome = await net.run({ deadline: ms(30), onJournal: (e) => entries.push(...e) });
  notes.size = show(await net.invoke(p, `${iface}#size`, ['ext']));
  notes.none = show(await net.invoke(p, `${iface}#size`, ['none']));
  notes.read = show(await net.invoke(p, `${iface}#read`, ['ext', 0n, 100]));
  notes.missing = show(await net.invoke(p, `${iface}#missing`, []));
  notes.nope = show(await net.invoke(p, 'wasmnet-test:pad/nope#x', []));
  notes.lines = eventLines(entries, /^pad-written/);
  // A 4 MiB argument, best of five.
  const big = new Uint8Array(4 << 20).fill(3);
  let best = Infinity;
  for (let i = 0; i < 5; i++) {
    const t = performance.now();
    await net.invoke(p, `${iface}#write`, [`big${i}`, big]);
    best = Math.min(best, performance.now() - t);
  }
  notes.bigMs = best.toFixed(2);
  // An embedder's own run loop (the module's `wn_pad_run`): one instant at a time to 60 ms.
  const until = new Uint8Array(8);
  new DataView(until.buffer).setBigUint64(0, ms(60), true);
  const instants = await net.callExport('wn_pad_run', until, { promising: true });
  notes.instants = String(new DataView(instants.buffer, instants.byteOffset).getUint32(0, true));
  notes.log = show(await net.invoke(p, `${iface}#size`, ['log']));
  notes.asked = asked.join(',');
  notes.cores = String(cores.n);
  Object.assign(notes, await jspiCost());
  return { outcome, notes };
}

/**
 * What a call through a `Suspending` import that answers at once costs, against a plain import:
 * a tiny module (`run(n)` calls its import `n` times) instantiated twice, the second time with
 * the import wrapped in `WebAssembly.Suspending` and `run` in `WebAssembly.promising`.
 */
async function jspiCost(): Promise<Record<string, string>> {
  // (module (import "env" "f" (func)) (func (export "run") (param i32)
  //   (loop (call 0) (local.set 0 (i32.sub (local.get 0) (i32.const 1))) (br_if 0 (local.get 0)))))
  const bytes = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x08, 0x02, 0x60, 0x00, 0x00, 0x60, 0x01, 0x7f, 0x00,
    0x02, 0x09, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x01, 0x66, 0x00, 0x00,
    0x03, 0x02, 0x01, 0x01,
    0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x01,
    0x0a, 0x14, 0x01, 0x12, 0x00, 0x03, 0x40, 0x10, 0x00, 0x20, 0x00, 0x41, 0x01, 0x6b, 0x21, 0x00, 0x20, 0x00, 0x0d, 0x00, 0x0b, 0x0b,
  ]);
  const module = new WebAssembly.Module(bytes);
  const n = 1_000_000;
  const plain = new WebAssembly.Instance(module, { env: { f: () => {} } }).exports.run as (n: number) => void;
  const W = WebAssembly as unknown as { Suspending: new (f: () => unknown) => unknown; promising: (f: unknown) => (n: number) => Promise<void> };
  const suspending = W.promising(new WebAssembly.Instance(module, { env: { f: new W.Suspending(() => {}) } as unknown as WebAssembly.ModuleImports }).exports.run);
  plain(1000);
  let t = performance.now();
  plain(n);
  const plainNs = ((performance.now() - t) * 1e6) / n;
  // V8 suspends at every `Suspending` call, even one whose function answers at once: each call
  // is a round through the microtask queue.
  const m = 100_000;
  await suspending(1000);
  t = performance.now();
  await suspending(m);
  const suspendingNs = ((performance.now() - t) * 1e6) / m;
  return { jspiPlainNs: plainNs.toFixed(1), jspiSuspendingNs: suspendingNs.toFixed(1) };
}

/** A `wasmnet-disk/1` image of `pairs` (ascending by key): `crates/wasmnet-disk/src/image.rs`. */
function diskImage(pairs: [string, Uint8Array][]): Uint8Array {
  const parts: Uint8Array[] = [new TextEncoder().encode('wasmnet-disk/1\n')];
  const u32 = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
  const u64 = (n: bigint) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n); return b; };
  let bytes = 0n;
  for (const [k, v] of pairs) {
    const key = new TextEncoder().encode(k);
    parts.push(u32(key.length), key, u64(BigInt(v.length)), v);
    bytes += BigInt(key.length + v.length);
  }
  parts.push(u32(0xffffffff), u64(BigInt(pairs.length)), u64(bytes));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

const le64 = (n: number) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };

/**
 * The `disks` scenario: the disks in the page. The simulator is the embedder's build with the
 * disks installed (`crates/wasmnet-disk-page`), whose four interfaces the binding links from their
 * names alone. The same network as the native test `page_scenario_native`
 * (`crates/wasmnet-disk/tests/wasmtime.rs`), in the same generic forms: the page test compares the
 * lines and the digests.
 */
async function disksScenario(net: Network): Promise<{ outcome: unknown; notes: Record<string, string> }> {
  net.setCatalog(['disk_probe']);
  const ms = (n: number) => BigInt(n) * 1_000_000n;
  await net.device('p', 'disk_probe', { period: '10ms', big: '1048576' }, {
    crashAlone: true,
    'disk.specs': [{ name: 'state' }, { name: 'log', durability: 'on-sync' }],
  });
  await net.device('q', 'disk_probe', { period: '1000ms', fill: '4096' }, {
    crashAlone: true,
    'disk.specs': [{ name: 'state', quota: 2048, initial: diskImage([['boots', le64(41)]]) }, { name: 'log' }],
  });
  const spec = (period: string) =>
    hex(cbor({ component: 'disk_probe', config: { period }, 'disk.specs': [{ name: 'state' }, { name: 'log', durability: 'on-sync' }] }));
  await net.device(
    'ctl',
    'infra_script',
    {
      'step.0': `0ms apply r ${spec('10ms')}`,
      'step.1': `45ms apply r ${spec('20ms')}`,
      'step.2': '70ms remove r',
      'step.3': `80ms apply r ${spec('10ms')}`,
    },
    { infra: true },
  );
  for (const [at, kind] of [[25, 'stop-device'], [30, 'start-device'], [55, 'crash-device'], [58, 'start-device'], [62, 'start-device'], [86, 'stop-device'], [87, 'start-device']] as const) {
    net.op(kind === 'crash-device' ? { kind, device: 'p', message: 'operator crash', at: ms(at) } : { kind, device: 'p', at: ms(at) });
  }
  const faults: [number, string, Record<string, unknown>][] = [
    [35, 'disk.power-loss', { disk: 'log', keep: 'prefix', tear: true }],
    [56, 'disk.crash-at', { disk: 'state', call: 1, keep: 'prefix' }],
    [60, 'disk.lose', { disk: 'log' }],
    [70, 'disk.fail', { disk: 'log', count: 1, text: 'a bad sector' }],
    [85, 'disk.corrupt', { disk: 'state', prefix: 'boots', how: 'garbage' }],
    [90, 'disk.quota', { disk: 'log', bytes: 10 }],
  ];
  for (const [at, op, value] of faults) net.op({ kind: 'extension', device: 'p', op, value, at: ms(at) });
  // An image loaded before the run, through the module's own export.
  const enc = new TextEncoder();
  const names = (dev: string, disk: string) => enc.encode(`${dev}\0${disk}`);
  const log = diskImage([['e/00000001', new Uint8Array(64).fill(1)], ['e/00000002', new Uint8Array(64).fill(2)], ['last', le64(2)]]);
  const load = new Uint8Array([...names('q', 'log'), 0, ...log]);
  net.callExport('wn_disk_load', load);
  const entries: JournalEntry[] = [];
  const outcome = await net.run({ deadline: ms(100), onJournal: (e) => entries.push(...e) });
  let text = eventLines(entries, /^(disk-|kv-|device-)/);
  for (const [dev, disk] of [['p', 'state'], ['p', 'log'], ['q', 'state'], ['q', 'log'], ['r', 'state'], ['r', 'log']]) {
    let digest = '';
    try {
      digest = [...net.callExport('wn_disk_digest', names(dev!, disk!))].map((b) => b.toString(16).padStart(2, '0')).join('');
    } catch {
      digest = '';
    }
    text += `\ndigest ${dev} ${disk} ${digest}`;
  }
  return { outcome, notes: { lines: text } };
}

/**
 * The `disk-cost` scenario: what a disk costs in the page. A `set` plus a 16-byte `get-range` by
 * value size (a device that makes `reps` of them at boot, less one that makes one, over
 * `reps - 1`), and the digest of a disk of 64 MiB in 64 KiB values (loaded through the module's
 * export, hashed in the simulator's `wasm32` memory).
 */
async function diskCost(net: Network): Promise<{ outcome: unknown; notes: Record<string, string> }> {
  const notes: Record<string, string> = {};
  let n = 0;
  const time = async (size: number, reps: number) => {
    const name = `c${n++}`;
    await net.device(name, 'disk_probe', { period: '1000ms', big: String(size), reps: String(reps) }, { 'disk.specs': [{ name: 'state', quota: 1 << 30 }] });
    const t0 = performance.now();
    await net.run({ deadline: net.now() + 1_000_000n });
    return performance.now() - t0;
  };
  for (const [size, reps, label] of [[64, 2001, '64B'], [4096, 2001, '4KiB'], [1 << 20, 41, '1MiB'], [16 << 20, 5, '16MiB']] as const) {
    const per = ((await time(size, reps)) - (await time(size, 1))) / (reps - 1);
    notes[`call${label}Us`] = (per * 1000).toFixed(1);
  }
  const enc = new TextEncoder();
  await net.device('big', 'disk_probe', { period: '1000ms' }, { 'disk.specs': [{ name: 'state' }, { name: 'store', quota: 128 << 20 }] });
  const value = new Uint8Array(64 << 10).fill(0x5a);
  const pairs: [string, Uint8Array][] = [];
  for (let i = 0; i < 1024; i++) pairs.push([`k/${String(i).padStart(12, '0')}`, value]);
  const names = enc.encode('big\0store');
  const img = diskImage(pairs);
  const load = new Uint8Array(names.length + 1 + img.length);
  load.set(names);
  load.set(img, names.length + 1);
  net.callExport('wn_disk_load', load);
  let t0 = performance.now();
  net.callExport('wn_disk_digest', names);
  notes.digest64MiBMs = (performance.now() - t0).toFixed(0);
  t0 = performance.now();
  net.callExport('wn_disk_export', names);
  notes.export64MiBMs = (performance.now() - t0).toFixed(0);
  return { outcome: {}, notes };
}
