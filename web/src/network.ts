// A wasmnet network in the browser: the simulator (`wasmnet_web.wasm`, the Rust crate
// crates/wasmnet-web compiled to wasm32-unknown-unknown) with devices that are components
// transpiled by jco and hosted by the codelib-web kit.
//
//   const net = await Network.create(simulator, { seed: 42n, components });
//   const sw = await net.device('sw', 'switch', { ports: '4' });
//   const web = await net.device('web', 'node-http-server', { ... });
//   net.link(web.port(0), sw.port(1), 150_000n);
//   const outcome = await net.run();          // to quiescence, or { deadline }
//   net.journal(); net.links(); net.pcap(link);
//
// The split: the simulator owns virtual time, the event queue, links, pcap taps and the
// journal; this file instantiates the devices and serves their imports. A device's WASI comes
// from the kit's `wasiImports` over a `World` that asks the simulator (clock, timers, seeded
// entropy, stdout, config); its `wasmnet:link` imports go straight to the simulator.
//
// The boundary is documented in crates/wasmnet-web/src/ffi.rs (exports `wn_*`, imports
// `wasmnet_js.*`, who allocates, re-entry) and codec.rs (the encodings). One `Network` per
// Worker: jco's runtime and the kit's event loop are global, so a fresh run is a fresh Worker.

import { instantiate, type Imports } from './codelib-web/dist/load.js';
import { settle, touch } from './codelib-web/dist/loop.js';
import { wasiImports } from './codelib-web/dist/wasi/index.js';
import type { RandomStream, World } from './codelib-web/dist/worlds.js';
import * as codec from './codec.js';
import type { JournalEntry, Outcome, PortInfo } from './codec.js';

export type { JournalEntry, Outcome } from './codec.js';

/** Where a component's transpiled glue is, and its core modules if already compiled. */
export interface ComponentSource {
  /** URL of the module `codelib-web transpile` wrote (`<stem>.js`). */
  url: string;
  /** Its core modules, compiled, by file name (see the kit's `compileModules`). */
  modules?: Record<string, WebAssembly.Module>;
}

export interface NetworkOptions {
  /** Seeds every device's entropy (and nothing else: time is virtual). */
  seed: bigint | number;
  /** The components devices can be made from, by the key `device()` names. */
  components: Record<string, ComponentSource>;
}

/** One end of a link: a device's port. */
export interface PortRef {
  device: number;
  port: number;
}

/** A device of the network. */
export interface Device {
  /** Creation order: the first device is 0. */
  index: number;
  name: string;
  port(id: number): PortRef;
}

/** A link of the network. */
export interface Link {
  index: number;
  /** After its two ends: `<device>:<port>-<device>:<port>`. */
  name: string;
}

export interface RunOptions {
  /** Stop at this virtual time (ns) instead of running to quiescence. */
  deadline?: bigint;
  /** Called with the journal's new entries after every step. */
  onJournal?: (entries: JournalEntry[]) => void;
}

/** The simulator module's exports (crates/wasmnet-web/src/ffi.rs). */
interface Exports {
  memory: WebAssembly.Memory;
  wn_alloc(len: number): number;
  wn_free(ptr: number, len: number): void;
  wn_result_ptr(): number;
  wn_result_len(): number;
  wn_network_new(seed: bigint): number;
  wn_add_device(name: number, nameLen: number, component: number, componentLen: number, config: number, configLen: number, flags: number): number;
  wn_link(devA: number, portA: number, devB: number, portB: number, latency: bigint): number;
  wn_step(until: bigint): number;
  wn_take_dirty(): number;
  wn_next_event(): bigint;
  wn_now(): bigint;
  wn_finish(deadline: bigint): number;
  wn_journal(from: number): number;
  wn_link_count(): number;
  wn_link_name(link: number): number;
  wn_pcap(link: number): number;
  wn_counters(dev: number): number;
  wn_stdout(dev: number, stderr: number): number;
  wn_wall_now(): bigint;
  wn_transmit(dev: number, port: number, frame: number, len: number): void;
  wn_log(dev: number, level: number, msg: number, len: number): void;
  wn_event(dev: number, event: number, len: number): void;
  wn_output(dev: number, stderr: number, data: number, len: number): void;
  wn_config_get(dev: number, key: number, len: number): number;
  wn_config_all(dev: number): number;
  wn_random_u64(dev: number, which: number): bigint;
  wn_random_fill(dev: number, which: number, buf: number, len: number): void;
  wn_insecure_seed(dev: number, out: number): void;
  wn_timer(dev: number, at: bigint): number;
  wn_call_done(dev: number, call: number, end: number, msg: number, len: number): void;
}

/** The parts of a transpiled device's exports this file calls (jco camel-cases names). */
interface Root {
  device: {
    ports(): PortInfo[];
    receive(now: bigint, port: number, frame: Uint8Array): void;
    poll(now: bigint): bigint | undefined;
    linkState(now: bigint, port: number, up: boolean): void;
  };
  lifecycle?: { start(): Promise<void> };
  counters?: { counters(): [string, bigint][] };
  [app: string]: unknown;
}

interface Instance {
  name: string;
  component: string;
  root: Root;
  /** A composed node's apps (`app-<name>` exports), sorted by name: their start order. */
  apps: { name: string; run: () => Promise<unknown> }[];
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const U64 = (v: bigint) => BigInt.asUintN(64, v);

function message(err: unknown): string {
  if (err instanceof Error) return err.stack ?? err.message;
  return String(err);
}

/** Whether a jco export returned a promise: an export the transpile step wrapped for JSPI. */
function isPromise(v: unknown): v is Promise<unknown> {
  return typeof (v as { then?: unknown } | null)?.then === 'function';
}

export class Network {
  private readonly x: Exports;
  private readonly sources: Record<string, ComponentSource>;
  /** Devices by index; a slot is filled while `wn_add_device` asks for it. */
  private readonly instances: Instance[] = [];
  /** An instance waiting for `js_instantiate` to claim it. */
  private pending: { index: number; instance: Instance } | null = null;
  /** What an import left for the simulator's `js_take`. */
  private stash: Uint8Array = new Uint8Array();
  /** Virtual timers by the simulator's id: the guest's wake-up. */
  private readonly timers = new Map<number, () => void>();
  private journalNext = 0;
  private panicked: string | null = null;

  private constructor(instance: WebAssembly.Instance, options: NetworkOptions) {
    this.x = instance.exports as unknown as Exports;
    this.sources = options.components;
    if (this.x.wn_network_new(U64(BigInt(options.seed))) !== 0) throw new Error(this.resultText());
  }

  /**
   * Loads the simulator (`wasmnet_web.wasm`: a URL, its bytes or a compiled module) and creates
   * an empty network with `options.seed`.
   */
  static async create(simulator: string | URL | BufferSource | WebAssembly.Module, options: NetworkOptions): Promise<Network> {
    let module: WebAssembly.Module;
    if (simulator instanceof WebAssembly.Module) module = simulator;
    else if (typeof simulator === 'string' || simulator instanceof URL) module = await WebAssembly.compileStreaming(fetch(simulator));
    else module = await WebAssembly.compile(simulator);
    let self: Network | null = null;
    const imports = { wasmnet_js: Network.jsImports(() => self!) };
    const instance = await WebAssembly.instantiate(module, imports);
    self = new Network(instance, options);
    return self;
  }

  // ---- bytes across the boundary ------------------------------------------------------------

  /** A view of the simulator's memory (re-made each time: memory may have grown). */
  private view(ptr: number, len: number): Uint8Array {
    return new Uint8Array(this.x.memory.buffer, ptr >>> 0, len >>> 0);
  }

  private withBytes<T>(bytes: Uint8Array, f: (ptr: number, len: number) => T): T {
    const ptr = this.x.wn_alloc(bytes.length);
    this.view(ptr, bytes.length).set(bytes);
    try {
      return f(ptr, bytes.length);
    } finally {
      this.x.wn_free(ptr, bytes.length);
    }
  }

  private result(len = this.x.wn_result_len()): Uint8Array {
    return this.view(this.x.wn_result_ptr(), len).slice();
  }

  private resultText(): string {
    return decoder.decode(this.result());
  }

  /** Leaves `bytes` for `js_take`; answers their length. */
  private put(bytes: Uint8Array): number {
    this.stash = bytes;
    return bytes.length;
  }

  /** Leaves an error message for `js_take`; answers its negative length. */
  private fail(err: unknown): number {
    const text = message(err) || 'error';
    return -this.put(encoder.encode(text));
  }

  private instance(dev: number): Instance {
    const d = this.instances[dev];
    if (!d) throw new Error(`no device ${dev}`);
    return d;
  }

  // ---- what the simulator imports (module `wasmnet_js`) -------------------------------------

  private static jsImports(net: () => Network): Record<string, (...args: never[]) => unknown> {
    const n = net;
    return {
      js_take: (ptr: number) => {
        const self = n();
        self.view(ptr, self.stash.length).set(self.stash);
        self.stash = new Uint8Array();
      },
      js_stash_len: () => n().stash.length,
      js_instantiate: (dev: number, ptr: number, len: number) => n().claim(dev, ptr, len),
      js_receive: (dev: number, port: number, now: bigint, ptr: number, len: number) => {
        const self = n();
        try {
          self.sync(self.instance(dev).root.device.receive(U64(now), port, self.view(ptr, len).slice()), 'receive');
          return 0;
        } catch (err) {
          return self.fail(err);
        }
      },
      js_link_state: (dev: number, port: number, up: number, now: bigint) => {
        const self = n();
        try {
          self.sync(self.instance(dev).root.device.linkState(U64(now), port, up !== 0), 'link-state');
          return 0;
        } catch (err) {
          return self.fail(err);
        }
      },
      js_poll: (dev: number, now: bigint) => {
        const self = n();
        try {
          const next = self.sync(self.instance(dev).root.device.poll(U64(now)), 'poll');
          return next === undefined ? -1n : BigInt.asIntN(64, next);
        } catch (err) {
          self.fail(err);
          return -2n;
        }
      },
      js_counters: (dev: number) => {
        const self = n();
        try {
          const counters = self.instance(dev).root.counters;
          if (!counters) throw new Error('no counters export');
          return self.put(codec.encodeCounters(self.sync(counters.counters(), 'counters')));
        } catch (err) {
          return self.fail(err);
        }
      },
      js_start: (dev: number, call: number) => {
        const self = n();
        try {
          const lifecycle = self.instance(dev).root.lifecycle;
          if (!lifecycle) throw new Error('no lifecycle export');
          self.track(dev, call, lifecycle.start(), false);
          return 0;
        } catch (err) {
          return self.fail(err);
        }
      },
      js_run_app: (dev: number, app: number, call: number) => {
        const self = n();
        try {
          const a = self.instance(dev).apps[app];
          if (!a) throw new Error(`no app ${app}`);
          self.track(dev, call, a.run(), true);
          return 0;
        } catch (err) {
          return self.fail(err);
        }
      },
      js_timer_fire: (timer: number) => {
        const self = n();
        const wake = self.timers.get(timer);
        self.timers.delete(timer);
        wake?.();
      },
      js_panic: (ptr: number, len: number) => {
        const self = n();
        self.panicked = decoder.decode(self.view(ptr, len));
        console.error(`wasmnet simulator panicked: ${self.panicked}`);
      },
    };
  }

  /** A sync device export's answer; a promise means it was transpiled for JSPI, which this host does not drive. */
  private sync<T>(v: T, what: string): T {
    if (isPromise(v)) throw new Error(`${what} returned a promise: this host calls device exports synchronously`);
    return v;
  }

  /** Reports an async export call's end to the simulator: 0 ok, 1 an app's `err`, 2 a trap. */
  private track(dev: number, call: number, p: Promise<unknown>, app: boolean): void {
    p.then(
      () => {
        touch();
        this.callDone(dev, call, 0, '');
      },
      (err: unknown) => {
        touch();
        // jco throws a returned `result::err` as a ComponentError; anything else is a trap.
        const appError = app && (err as { constructor?: { name?: string } } | null)?.constructor?.name === 'ComponentError';
        this.callDone(dev, call, appError ? 1 : 2, appError ? '' : message(err));
      },
    );
  }

  private callDone(dev: number, call: number, end: number, text: string): void {
    this.withBytes(encoder.encode(text), (p, l) => this.x.wn_call_done(dev, call, end, p, l));
  }

  /** `js_instantiate`: hands the instance `device()` prepared to the simulator. */
  private claim(dev: number, ptr: number, len: number): number {
    try {
      const plan = codec.decodePlan(this.view(ptr, len).slice());
      const p = this.pending;
      if (!p || p.index !== dev || p.instance.component !== plan.component) {
        throw new Error(`device ${dev} (${plan.name}): no instance prepared for it`);
      }
      this.pending = null;
      this.instances[dev] = p.instance;
      const { root, apps } = p.instance;
      const ports = this.sync(root.device.ports(), 'ports');
      return this.put(
        codec.encodeInstance(
          ports,
          { counters: root.counters !== undefined, lifecycle: root.lifecycle !== undefined },
          apps.map((a) => a.name),
        ),
      );
    } catch (err) {
      return this.fail(err);
    }
  }

  // ---- a device's imports ---------------------------------------------------------------------

  /** Device `dev`'s world, as the kit's WASI reads it: everything from the simulator. */
  private world(dev: number, name: string): World {
    const x = this.x;
    const stream = (s: RandomStream) => (s === 'secure' ? 0 : 1);
    const output = (stderr: number) => (bytes: Uint8Array) => {
      touch();
      this.withBytes(bytes, (p, l) => x.wn_output(dev, stderr, p, l));
    };
    return {
      now: () => U64(x.wn_now()),
      wallNow: () => U64(x.wn_wall_now()),
      timer: (at, wake) => {
        touch();
        this.timers.set(x.wn_timer(dev, at), wake);
      },
      randomU64: (s) => U64(x.wn_random_u64(dev, stream(s))),
      randomFill: (s, out) => {
        const ptr = x.wn_alloc(out.length);
        try {
          x.wn_random_fill(dev, stream(s), ptr, out.length);
          out.set(this.view(ptr, out.length));
        } finally {
          x.wn_free(ptr, out.length);
        }
      },
      insecureSeed: () => {
        const ptr = x.wn_alloc(16);
        try {
          x.wn_insecure_seed(dev, ptr);
          const v = new DataView(x.memory.buffer, ptr >>> 0, 16);
          return [v.getBigUint64(0, true), v.getBigUint64(8, true)];
        } finally {
          x.wn_free(ptr, 16);
        }
      },
      stdout: output(0),
      stderr: output(1),
      config: {
        get: (key) => {
          const len = this.withBytes(encoder.encode(key), (p, l) => x.wn_config_get(dev, p, l));
          return len < 0 ? undefined : decoder.decode(this.result(len));
        },
        all: () => {
          const len = x.wn_config_all(dev);
          return len < 0 ? [] : codec.decodeConfig(this.result(len));
        },
      },
      args: [name],
      env: [],
    };
  }

  private imports(dev: number, name: string): Imports {
    const x = this.x;
    return {
      ...wasiImports(this.world(dev, name)),
      'wasmnet:link/types': {},
      'wasmnet:link/wire': {
        transmit: (port: number, frame: Uint8Array) => {
          touch();
          this.withBytes(frame, (p, l) => x.wn_transmit(dev, port, p, l));
        },
      },
      'wasmnet:link/log': {
        log: (level: string, text: string) => {
          touch();
          const code = codec.LEVELS.indexOf(level as codec.Level);
          this.withBytes(encoder.encode(text), (p, l) => x.wn_log(dev, code < 0 ? 4 : code, p, l));
        },
        event: (kind: string, fields: [string, string][]) => {
          touch();
          this.withBytes(codec.encodeEvent(kind, fields), (p, l) => x.wn_event(dev, p, l));
        },
      },
    };
  }

  // ---- the network API --------------------------------------------------------------------------

  /**
   * Instantiates `component` (a key of `options.components`) as a device called `name`, with
   * flat `key = value` config (nested keys dotted, as natively). `journalStdio` puts its stdout
   * and stderr lines in the journal.
   */
  async device(name: string, component: string, config: Record<string, string> = {}, options: { journalStdio?: boolean } = {}): Promise<Device> {
    const source = this.sources[component];
    if (!source) throw new Error(`no component ${component} (known: ${Object.keys(this.sources).join(', ')})`);
    const index = this.instances.length;
    const loaded = await instantiate(source.url, this.imports(index, name), source.modules ? { modules: source.modules } : {});
    const root = loaded.exports as unknown as Root;
    // A composed node exports one `app-<name>` instance per app; the kit lists them by WIT name
    // (`app-http-get#run`), whatever jco keys them by.
    const apps = loaded
      .exportNames('app-')
      .filter((n) => n.endsWith('#run'))
      .map((n) => ({ name: n.slice('app-'.length, -'#run'.length), run: loaded.exportFn(n) as () => Promise<unknown> }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    this.pending = { index, instance: { name, component, root, apps } };
    const pairs = Object.entries(config).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const n = encoder.encode(name);
    const c = encoder.encode(component);
    const got = this.withBytes(n, (np, nl) =>
      this.withBytes(c, (cp, cl) =>
        this.withBytes(codec.encodeConfig(pairs), (gp, gl) => this.x.wn_add_device(np, nl, cp, cl, gp, gl, options.journalStdio ? 1 : 0)),
      ),
    );
    this.pending = null;
    if (got < 0) {
      this.instances.length = index;
      throw new Error(this.resultText());
    }
    return { index: got, name, port: (port) => ({ device: got, port }) };
  }

  /** Wires two ports with a point-to-point link of one-way `latency` (virtual ns). */
  link(a: PortRef, b: PortRef, latency: bigint | number): Link {
    const got = this.x.wn_link(a.device, a.port, b.device, b.port, U64(BigInt(latency)));
    if (got < 0) throw new Error(this.resultText());
    return { index: got, name: this.linkName(got) };
  }

  /** One step: every event at or before `until`. False once a device crashed. */
  private step(until: bigint): boolean {
    const r = this.x.wn_step(until);
    if (r < 0) throw new Error(this.resultText());
    return r === 1;
  }

  /**
   * Runs to quiescence, or to `options.deadline`, and reports how it ended. Between steps the
   * kit's event loop settles, so the guests' async work (an app's `run`, a timer's wake-up) runs
   * at the instant it belongs to; virtual time moves only once JavaScript is idle.
   */
  async run(options: RunOptions = {}): Promise<Outcome> {
    const { deadline, onJournal } = options;
    const report = () => {
      if (!onJournal) return;
      const fresh = this.journalFrom(this.journalNext);
      if (fresh.length > 0) onJournal(fresh);
    };
    let ok = this.step(U64(this.x.wn_now()));
    while (ok) {
      report();
      await settle();
      if (this.panicked !== null) break;
      if (this.x.wn_take_dirty() !== 0) {
        ok = this.step(U64(this.x.wn_now()));
        continue;
      }
      const next = this.x.wn_next_event();
      if (next < 0n || (deadline !== undefined && next > deadline)) break;
      ok = this.step(next);
    }
    if (this.panicked !== null) throw new Error(`the simulator panicked: ${this.panicked}`);
    const len = this.x.wn_finish(deadline === undefined ? -1n : BigInt.asIntN(64, deadline));
    if (len < 0) throw new Error(this.resultText());
    const outcome = codec.decodeOutcome(this.result(len));
    report();
    return outcome;
  }

  /** Current virtual time (ns). */
  now(): bigint {
    return U64(this.x.wn_now());
  }

  /** The journal from entry `from` on (all of it by default). */
  journalFrom(from = 0): JournalEntry[] {
    const next = this.x.wn_journal(from);
    const entries = codec.decodeJournal(this.result());
    if (next > this.journalNext) this.journalNext = next;
    return entries;
  }

  /** Every journal entry so far. */
  journal(): JournalEntry[] {
    return this.journalFrom(0);
  }

  private linkName(index: number): string {
    if (this.x.wn_link_name(index) < 0) throw new Error(this.resultText());
    return this.resultText();
  }

  /** Every link, in creation order. */
  links(): Link[] {
    const out: Link[] = [];
    for (let i = 0; i < this.x.wn_link_count(); i++) out.push({ index: i, name: this.linkName(i) });
    return out;
  }

  /** The link's pcap-ng capture so far (timestamps in virtual ns). */
  pcap(link: Link | number): Uint8Array {
    const index = typeof link === 'number' ? link : link.index;
    const len = this.x.wn_pcap(index);
    if (len < 0) throw new Error(this.resultText());
    return this.result(len);
  }

  /** The device's counters (`wasmnet:link/counters`), or null if it exports none. */
  counters(device: Device | number): [string, bigint][] | null {
    const dev = typeof device === 'number' ? device : device.index;
    const len = this.x.wn_counters(dev);
    if (len === -2) return null;
    if (len < 0) throw new Error(this.resultText());
    return codec.decodeCounters(this.result(len));
  }

  /** Everything the device wrote to stdout (or stderr) so far. */
  output(device: Device | number, stream: 'stdout' | 'stderr' = 'stdout'): Uint8Array {
    const dev = typeof device === 'number' ? device : device.index;
    const len = this.x.wn_stdout(dev, stream === 'stderr' ? 1 : 0);
    if (len < 0) throw new Error(this.resultText());
    return this.result(len);
  }
}
