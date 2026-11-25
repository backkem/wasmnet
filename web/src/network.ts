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
// entropy, stdout, config, arguments and environment); its `wasmnet:link` imports go straight
// to the simulator, and so do its `wasmnet:infra` calls, as generic values (codec.ts): the
// simulator serves them, so nothing here knows what a call does. A device's commands
// (`wasmnet:control/commands`) and reconfiguration (`wasmnet:reconfigure`) are called when the
// simulator asks, like `receive`. No decision is made in this file.
//
// The boundary is documented in crates/wasmnet-web/src/ffi.rs (exports `wn_*`, imports
// `wasmnet_js.*`, who allocates, re-entry) and codec.rs (the encodings). One `Network` per
// Worker: jco's runtime and the kit's event loop are global, so a fresh run is a fresh Worker.

import { instantiate, type Imports } from './codelib-web/dist/load.js';
import { settle, touch } from './codelib-web/dist/loop.js';
import { wasiImports } from './codelib-web/dist/wasi/index.js';
import type { RandomStream, World } from './codelib-web/dist/worlds.js';
import * as codec from './codec.js';
import type { CommandAnswer, DeviceCost, DeviceOptions, JournalEntry, LinkOptions, Op, OpState, Outcome, PortInfo } from './codec.js';

export type { CommandAnswer, DeviceCost, DeviceOptions, Impairments, JournalEntry, LinkOptions, Op, OpState, Outcome } from './codec.js';

/** Where a component's transpiled glue is, and its core modules if already compiled. */
export interface ComponentSource {
  /** URL of the module `codelib-web transpile` wrote (`<stem>.js`). */
  url: string;
  /** Its core modules, compiled, by file name (see the kit's `compileModules`). */
  modules?: Record<string, WebAssembly.Module>;
  /**
   * The component's import names (`wasmnet:infra/devices@0.1.2`, ...), if known: the simulator
   * then refuses a component that imports `wasmnet:infra` for a device without the grant before
   * it is instantiated, as the native host does. Without them every infra call of such a device
   * is `denied` instead.
   */
  imports?: string[];
  /**
   * Its digest reference, `sha256:<hex>` of the component's bytes: a component a controller
   * supplies with these bytes runs from this source (no `NetworkOptions.supply` needed).
   */
  digest?: string;
}

export interface NetworkOptions {
  /** Seeds every device's entropy (and nothing else: time is virtual). */
  seed: bigint | number;
  /** The components devices can be made from, by the key `device()` names. */
  components: Record<string, ComponentSource>;
  /**
   * Makes a component a controller supplied (`wasmnet:infra/components`) instantiable: given its
   * digest and bytes (already checked by the simulator: digest, admission, imports), the source
   * to load it from, for example the embedder's own transpile of it. Without it, a supplied
   * component runs only if one of `components` has its `digest`.
   */
  supply?: (digest: string, bytes: Uint8Array) => ComponentSource | Promise<ComponentSource>;
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
  wn_add_device(name: number, nameLen: number, component: number, componentLen: number, config: number, configLen: number, options: number, optionsLen: number): Promise<number>;
  wn_command(dev: number, command: number, commandLen: number, argument: number, argumentLen: number): Promise<number>;
  wn_set_catalog(names: number, len: number): number;
  wn_set_supply_admission(patterns: number, len: number): number;
  wn_schedule_command(dev: number, at: bigint, command: number, commandLen: number, argument: number, argumentLen: number): number;
  wn_args(dev: number): number;
  wn_env(dev: number): number;
  wn_infra(dev: number, call: number, len: number): number;
  wn_infra_wait(dev: number, call: number, len: number): number;
  wn_link(devA: number, portA: number, devB: number, portB: number, latency: bigint): number;
  wn_link_with(devA: number, portA: number, devB: number, portB: number, options: number, len: number): number;
  wn_add_op(op: number, len: number): number;
  wn_op_states(): number;
  wn_costs(): number;
  wn_stdin(dev: number): number;
  wn_step(until: bigint): Promise<number>;
  wn_take_dirty(): number;
  wn_next_event(): bigint;
  wn_now(): bigint;
  wn_finish(deadline: bigint): Promise<number>;
  wn_journal(from: number): number;
  wn_link_count(): number;
  wn_link_name(link: number): number;
  wn_pcap(link: number): number;
  wn_counters(dev: number): Promise<number>;
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
  // Portable interfaces extensions serve (crates/wasmnet-web/src/ffi.rs).
  wn_import(dev: number, call: number, len: number): number;
  wn_import_drop(dev: number, name: number, len: number, handle: number): void;
  wn_interfaces(): number;
  // An embedder's own build of this module (`wasmnet_web::install!`) sets its installer here.
  wn_install?(): void;
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
  /** `wasmnet:control/commands`: `ok` returns, a refusal throws (jco's `ComponentError`). */
  commands?: { invoke(now: bigint, command: string, argument: string): string };
  /** `wasmnet:reconfigure/reconfigure`: a refusal throws `{ tag: 'restart' | 'invalid', val }`. */
  reconfigure?: { reconfigure(now: bigint, config: [string, string][]): void };
  [app: string]: unknown;
}

/** The functions of `wasmnet:infra` the simulator serves, by interface (jco's names). */
const INFRA: Record<string, string[]> = {
  devices: ['apply', 'start', 'stop', 'remove', 'control', 'wire', 'unwire', 'controlAnswer', 'get', 'list', 'watch', 'logs'],
  components: ['supply', 'release', 'list'],
  events: ['read', 'arm'],
};

/** The functions of `wasmnet:infra` that wait (async in WIT): the simulator answers them later. */
const INFRA_WAITS: Record<string, string[]> = { changes: ['wait', 'waitAny'] };

const kebab = (s: string) => s.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
const camel = (s: string) => s.replace(/-([a-z0-9])/g, (_, c: string) => c.toUpperCase());
const pascal = (s: string) => camel(s).replace(/^[a-z]/, (c) => c.toUpperCase());
/** Marks a resource class's construction from a handle the server answered (not the WIT constructor). */
const FROM_HANDLE = Symbol('from handle');

/** A `result`'s `err` that jco threw as a `ComponentError`: its payload. Anything else is a trap, thrown on. */
function errPayload(err: unknown): unknown {
  const e = err as { constructor?: { name?: string }; payload?: unknown } | null;
  if (e?.constructor?.name === 'ComponentError') return e.payload;
  throw err;
}

interface Instance {
  name: string;
  component: string;
  root: Root;
  /** Its core instances' memories (each once), measured for the simulator (`js_memory`). */
  memories: Set<WebAssembly.Memory>;
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

/**
 * WebAssembly JSPI, which the page needs anyway (jco's async runtime does). The simulator's
 * exports that run or add devices (`wn_add_device`, `wn_step`, `wn_finish`, `wn_command`,
 * `wn_counters`) are `promising`, and `js_instantiate` is `Suspending`: a device the network
 * creates while it runs (an operator event, a controller's `apply` or `start`) is instantiated
 * on demand, and the step waits for it. V8 suspends at every `Suspending` call, even one that
 * answers at once, so every export that may reach `js_instantiate` must be `promising`.
 */
type AnyFn = (...args: never[]) => unknown;
const jspi = WebAssembly as unknown as {
  Suspending: new (f: AnyFn) => AnyFn;
  promising: (f: AnyFn) => AnyFn;
};

/** The exports that may wait for a `Suspending` import: wrapped with `promising`. */
const PROMISING = ['wn_add_device', 'wn_step', 'wn_finish', 'wn_command', 'wn_counters'] as const;

export class Network {
  private readonly x: Exports;
  private readonly sources: Record<string, ComponentSource>;
  private readonly supply: NetworkOptions['supply'];
  /** Devices by index; a slot is filled while `wn_add_device` asks for it. */
  private readonly instances: Instance[] = [];
  /** An instance waiting for `js_instantiate` to claim it. */
  private pending: { index: number; instance: Instance } | null = null;
  /** What an import left for the simulator's `js_take`. */
  private stash: Uint8Array = new Uint8Array();
  /** Virtual timers by the simulator's id: the guest's wake-up. */
  private readonly timers = new Map<number, () => void>();
  /** `changes.wait` calls by the simulator's id: their promise's resolution. */
  private readonly waits = new Map<number, (reply: codec.InfraReply) => void>();
  /** Guest stdin reads waiting for bytes, by device. */
  private readonly stdinWaiters = new Map<number, () => void>();
  private journalNext = 0;
  private panicked: string | null = null;

  private constructor(instance: WebAssembly.Instance, options: NetworkOptions) {
    const raw = instance.exports as unknown as Record<string, AnyFn>;
    const wrapped: Record<string, unknown> = { ...raw };
    for (const name of PROMISING) wrapped[name] = jspi.promising(raw[name]!);
    this.x = wrapped as unknown as Exports;
    this.sources = { ...options.components };
    this.supply = options.supply;
    this.x.wn_install?.();
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

  /** `withBytes` for an export that may wait (`promising`): the bytes live until it answers. */
  private async withBytesAsync<T>(bytes: Uint8Array, f: (ptr: number, len: number) => Promise<T>): Promise<T> {
    const ptr = this.x.wn_alloc(bytes.length);
    this.view(ptr, bytes.length).set(bytes);
    try {
      return await f(ptr, bytes.length);
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
      // A number when `device()` prepared the instance, a promise when the network creates the
      // device while it runs: then the step waits (JSPI) while it is instantiated.
      js_instantiate: new jspi.Suspending(((dev: number, ptr: number, len: number) => n().claim(dev, ptr, len)) as AnyFn),
      js_imports: (ptr: number, len: number) => {
        const self = n();
        const key = decoder.decode(self.view(ptr, len));
        return self.put(codec.encodeImports(self.sources[key]?.imports));
      },
      js_memory: (dev: number) => {
        const d = n().instances[dev];
        if (!d) return -1n;
        let total = 0;
        for (const m of d.memories) total += m.buffer.byteLength;
        return BigInt(total);
      },
      js_stdin_ready: (dev: number) => {
        const self = n();
        const wake = self.stdinWaiters.get(dev);
        self.stdinWaiters.delete(dev);
        touch();
        wake?.();
      },
      js_release: (dev: number) => {
        delete n().instances[dev];
      },
      js_compile: new jspi.Suspending(((dp: number, dl: number, bp: number, bl: number) => n().compile(dp, dl, bp, bl)) as AnyFn),
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
      js_invoke: (dev: number, now: bigint, cp: number, cl: number, ap: number, al: number) => {
        const self = n();
        try {
          const commands = self.instance(dev).root.commands;
          if (!commands) throw new Error('no commands export');
          const [command, argument] = [decoder.decode(self.view(cp, cl)), decoder.decode(self.view(ap, al))];
          let answer: CommandAnswer;
          try {
            answer = { ok: self.sync(commands.invoke(U64(now), command, argument), 'invoke') };
          } catch (err) {
            answer = { err: String(errPayload(err)) };
          }
          return self.put(codec.encodeCommandAnswer(answer));
        } catch (err) {
          return self.fail(err);
        }
      },
      js_reconfigure: (dev: number, now: bigint, ptr: number, len: number) => {
        const self = n();
        try {
          const reconfigure = self.instance(dev).root.reconfigure;
          if (!reconfigure) throw new Error('no reconfigure export');
          const config = codec.decodeConfig(self.view(ptr, len).slice());
          try {
            self.sync(reconfigure.reconfigure(U64(now), config), 'reconfigure');
            return self.put(codec.encodeReconfigured(0));
          } catch (err) {
            const r = errPayload(err) as { tag: string; val: string };
            return self.put(codec.encodeReconfigured(r.tag === 'restart' ? 1 : 2, r.val));
          }
        } catch (err) {
          return self.fail(err);
        }
      },
      js_wait_done: (wait: number, ptr: number, len: number) => {
        const self = n();
        const done = self.waits.get(wait);
        self.waits.delete(wait);
        done?.(codec.decodeInfraReply(self.view(ptr, len).slice()));
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

  /**
   * `js_instantiate`: hands the instance `device()` prepared to the simulator, or (a device the
   * network creates while it runs) instantiates the component it names now and answers once it
   * exists. Which device, from what, and when is the simulator's decision.
   */
  private claim(dev: number, ptr: number, len: number): number | Promise<number> {
    let plan: ReturnType<typeof codec.decodePlan>;
    try {
      plan = codec.decodePlan(this.view(ptr, len).slice());
    } catch (err) {
      return this.fail(err);
    }
    const p = this.pending;
    if (p && p.index === dev && p.instance.component === plan.component) {
      this.pending = null;
      return this.answer(dev, p.instance);
    }
    return this.load(dev, plan.name, plan.component).then(
      (instance) => this.answer(dev, instance),
      (err: unknown) => this.fail(err),
    );
  }


  /**
   * `js_compile`: a supplied component becomes instantiable under its digest. The simulator
   * checked the bytes already; this only finds where to load them from.
   */
  private compile(dp: number, dl: number, bp: number, bl: number): Promise<number> {
    const digest = decoder.decode(this.view(dp, dl));
    const bytes = this.view(bp, bl).slice();
    const known = () => {
      const source = Object.values(this.sources).find((s) => s.digest === digest);
      if (!source) throw new Error(`no compiled form of it on this page (NetworkOptions.supply, or a component with its digest)`);
      return source;
    };
    return Promise.resolve()
      .then(() => (this.supply ? this.supply(digest, bytes) : known()))
      .then(
        (source) => {
          this.sources[digest] = source;
          return 0;
        },
        (err: unknown) => this.fail(err instanceof Error ? err.message : err),
      );
  }

  /** Instantiates `component` as device `dev` called `name`, its imports served for `dev`. */
  private async load(dev: number, name: string, component: string): Promise<Instance> {
    const source = this.sources[component];
    if (!source) throw new Error(`no component ${component} (known: ${Object.keys(this.sources).join(', ')})`);
    // Every core instance it makes, for its memories: what the simulator counts and bounds.
    const memories = new Set<WebAssembly.Memory>();
    const instantiateCore = async (module: WebAssembly.Module, imports?: WebAssembly.Imports) => {
      const instance = await WebAssembly.instantiate(module, imports);
      for (const e of Object.values(instance.exports)) if (e instanceof WebAssembly.Memory) memories.add(e);
      return instance;
    };
    const loaded = await instantiate(source.url, this.imports(dev), { ...(source.modules ? { modules: source.modules } : {}), instantiateCore });
    const root = loaded.exports as unknown as Root;
    // A composed node exports one `app-<name>` instance per app; the kit lists them by WIT name
    // (`app-http-get#run`), whatever jco keys them by.
    const apps = loaded
      .exportNames('app-')
      .filter((n) => n.endsWith('#run'))
      .map((n) => ({ name: n.slice('app-'.length, -'#run'.length), run: loaded.exportFn(n) as () => Promise<unknown> }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    return { name, component, root, apps, memories };
  }

  /** The `instance` message for device `dev`'s instance: its ports and what it exports. */
  private answer(dev: number, instance: Instance): number {
    try {
      this.instances[dev] = instance;
      const { root, apps } = instance;
      const ports = this.sync(root.device.ports(), 'ports');
      return this.put(
        codec.encodeInstance(
          ports,
          {
            counters: root.counters !== undefined,
            lifecycle: root.lifecycle !== undefined,
            commands: root.commands !== undefined,
            reconfigure: root.reconfigure !== undefined,
          },
          apps.map((a) => a.name),
        ),
      );
    } catch (err) {
      return this.fail(err);
    }
  }

  // ---- a device's imports ---------------------------------------------------------------------

  /** Device `dev`'s world, as the kit's WASI reads it: everything from the simulator. */
  private world(dev: number): World {
    const x = this.x;
    const self = this;
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
      // Read when the guest asks (the simulator registers the device after the instance exists).
      get args() {
        return codec.decodeStrs(self.result(x.wn_args(dev)));
      },
      get env() {
        return codec.decodeConfig(self.result(x.wn_env(dev)));
      },
      // What `Op::Stdin` wrote, queued by the simulator; a read with nothing queued waits for
      // more (the kit treats that promise as patient: under a virtual clock input may never come).
      stdin: () => {
        const read = (): Uint8Array | Promise<Uint8Array> => {
          const chunk = self.result(x.wn_stdin(dev));
          return chunk.length > 0 ? chunk : new Promise<void>((wake) => self.stdinWaiters.set(dev, wake)).then(read);
        };
        return read();
      },
    };
  }

  /** One `wasmnet:infra` call, served by the simulator; its error is thrown, as jco expects. */
  private infra(dev: number, fn: string, args: unknown[]): unknown {
    touch();
    const len = this.withBytes(codec.encodeInfraCall(fn, args), (p, l) => this.x.wn_infra(dev, p, l));
    const reply = codec.decodeInfraReply(this.result(len));
    if ('value' in reply) return reply.value;
    if ('error' in reply) throw { payload: reply.error };
    throw new Error(reply.failed);
  }

  /** A `wasmnet:infra` call that waits (`changes.wait`, `changes.wait-any`): settles when the simulator answers it (during a later step). */
  private infraWait(dev: number, fn: string, args: unknown[]): Promise<unknown> {
    touch();
    const settle = (reply: codec.InfraReply): Promise<unknown> => {
      if ('value' in reply) return Promise.resolve(reply.value);
      if ('error' in reply) return Promise.reject({ payload: reply.error });
      return Promise.reject(new Error(reply.failed));
    };
    const id = this.withBytes(codec.encodeInfraCall(fn, args), (p, l) => this.x.wn_infra_wait(dev, p, l));
    if (id < 0) return settle(codec.decodeInfraReply(this.result()));
    return new Promise((resolve) => this.waits.set(id, resolve)).then((reply) => settle(reply as codec.InfraReply));
  }

  /** One call of a portable interface (`interface#function`), served by the simulator; its error is thrown, as jco expects. */
  private portable(dev: number, call: string, args: unknown[]): unknown {
    touch();
    const len = this.withBytes(codec.encodeInfraCall(call, args), (p, l) => this.x.wn_import(dev, p, l));
    const reply = codec.decodeInfraReply(this.result(len));
    if ('value' in reply) return reply.value;
    if ('error' in reply) throw { payload: reply.error };
    throw new Error(reply.failed);
  }

  /**
   * The imports of the portable interfaces the simulator's extensions serve, built from their
   * names alone (`wn_interfaces`): a function per function, calling `wn_import`; a class per
   * resource, per device, whose instances carry the server's handle (they extend
   * `codec.ResourceHandle`, so they cross as handles); a handle the server answers comes back
   * as an instance of its class, at the top of an answer or inside an `option`.
   */
  private portableImports(dev: number): Imports {
    const reply = codec.decodeInfraReply(this.result(this.x.wn_interfaces()));
    const interfaces = ('value' in reply ? reply.value : []) as { name: string; functions: string[]; resources: string[] }[];
    const classes = new Map<string, new (...args: unknown[]) => codec.ResourceHandle>();
    const wrap = (v: unknown): unknown => {
      if (v instanceof codec.ResourceHandle) {
        const cls = classes.get(v.resource);
        return cls ? new cls(FROM_HANDLE, v.handle) : v;
      }
      return v;
    };
    const out: Imports = {};
    for (const i of interfaces) {
      const obj: Record<string, unknown> = {};
      const self = this;
      for (const r of i.resources) {
        const ctor = i.functions.includes(`[constructor]${r}`) ? `${i.name}#[constructor]${r}` : null;
        // jco constructs it for the WIT constructor (`new Note(name)`): the server makes the note.
        const cls = class extends codec.ResourceHandle {
          constructor(...args: unknown[]) {
            const made = args[0] === FROM_HANDLE ? args[1] : ctor ? (self.portable(dev, ctor, args) as codec.ResourceHandle).handle : undefined;
            if (typeof made !== 'number') throw new Error(`${r} has no constructor`);
            super(r, made);
          }
        };
        Object.defineProperty(cls, 'name', { value: pascal(r) });
        const dispose = function (this: codec.ResourceHandle) {
          self.withBytes(encoder.encode(`${i.name}#${r}`), (p, l) => self.x.wn_import_drop(dev, p, l, this.handle));
        };
        const proto = cls.prototype as unknown as Record<symbol, unknown>;
        proto[Symbol.for('dispose')] = dispose;
        const symbolDispose = (Symbol as { dispose?: symbol }).dispose;
        if (symbolDispose) proto[symbolDispose] = dispose;
        classes.set(r, cls);
        obj[pascal(r)] = cls;
      }
      for (const f of i.functions) {
        const call = (args: unknown[]) => wrap(this.portable(dev, `${i.name}#${f}`, args));
        const m = /^\[(constructor|method|static)\]([^.]+)(?:\.(.+))?$/.exec(f);
        if (!m) {
          obj[camel(f)] = (...args: unknown[]) => call(args);
          continue;
        }
        const [, kind, res, name] = m;
        const cls = classes.get(res!) as unknown as { prototype: Record<string, unknown> } & Record<string, unknown>;
        if (!cls) continue;
        if (kind === 'method') cls.prototype[camel(name!)] = function (this: codec.ResourceHandle, ...args: unknown[]) {
          return call([this, ...args]);
        };
        else if (kind === 'static') cls[camel(name!)] = (...args: unknown[]) => call(args);
      }
      out[i.name.split('@')[0]!] = obj;
    }
    return out;
  }

  private imports(dev: number): Imports {
    const x = this.x;
    const infra: Imports = { 'wasmnet:infra/types': {} };
    for (const [iface, fns] of Object.entries(INFRA)) {
      infra[`wasmnet:infra/${iface}`] = Object.fromEntries(fns.map((f) => [f, (...args: unknown[]) => this.infra(dev, `${iface}.${kebab(f)}`, args)]));
    }
    for (const [iface, fns] of Object.entries(INFRA_WAITS)) {
      infra[`wasmnet:infra/${iface}`] = Object.fromEntries(fns.map((f) => [f, (...args: unknown[]) => this.infraWait(dev, `${iface}.${kebab(f)}`, args)]));
    }
    return {
      ...wasiImports(this.world(dev)),
      ...infra,
      ...this.portableImports(dev),
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
   * flat `key = value` config (nested keys dotted, as natively) and `options` (its arguments
   * and environment, a `wasmnet:infra` grant, its stdout and stderr lines in the journal: see
   * `DeviceOptions`).
   */
  async device(name: string, component: string, config: Record<string, string> = {}, options: DeviceOptions = {}): Promise<Device> {
    // The device's index: the network numbers devices in creation order, and every device it
    // created (also while running) has its slot here.
    const index = this.instances.length;
    this.pending = { index, instance: await this.load(index, name, component) };
    const pairs = Object.entries(config).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const n = encoder.encode(name);
    const c = encoder.encode(component);
    const got = await this.withBytesAsync(n, (np, nl) =>
      this.withBytesAsync(c, (cp, cl) =>
        this.withBytesAsync(codec.encodeConfig(pairs), (gp, gl) =>
          this.withBytesAsync(codec.encodeValue(codec.plainOptions(options)), (op, ol) => this.x.wn_add_device(np, nl, cp, cl, gp, gl, op, ol)),
        ),
      ),
    );
    this.pending = null;
    if (got < 0) {
      this.instances.length = index;
      throw new Error(this.resultText());
    }
    return { index: got, name, port: (port) => ({ device: got, port }) };
  }

  /**
   * The components in-world controllers may create devices from (`devices.apply`), by their keys
   * in `options.components`: a controller's spec names one of them, and the page instantiates it
   * when the network asks.
   */
  setCatalog(components: readonly string[]): void {
    const got = this.withBytes(new codec.Writer().strs(components).finish(), (p, l) => this.x.wn_set_catalog(p, l));
    if (got < 0) throw new Error(this.resultText());
  }

  /**
   * Admits the components controllers supply by their imports: every import must match one of
   * `patterns` (`wasi:*`, `wasmnet:link/*`; the simulator's `ImportPolicy`). Without it every
   * supply is refused.
   */
  setSupplyAdmission(patterns: readonly string[]): void {
    const got = this.withBytes(new codec.Writer().strs(patterns).finish(), (p, l) => this.x.wn_set_supply_admission(p, l));
    if (got < 0) throw new Error(this.resultText());
  }

  /**
   * Wires two ports with a point-to-point link of one-way `latency` (virtual ns), with `options`
   * (MTU, impairments by direction, capture options: `LinkOptions`, read by the simulator).
   */
  link(a: PortRef, b: PortRef, latency: bigint | number, options: LinkOptions = {}): Link {
    const got = this.withBytes(codec.encodeValue({ ...options, latency: BigInt(latency) }), (p, l) => this.x.wn_link_with(a.device, a.port, b.device, b.port, p, l));
    if (got < 0) throw new Error(this.resultText());
    return { index: got, name: this.linkName(got) };
  }

  /** One step: every event at or before `until`. False once a device crashed. */
  private async step(until: bigint): Promise<boolean> {
    const r = await this.x.wn_step(until);
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
    let ok = await this.step(U64(this.x.wn_now()));
    while (ok) {
      report();
      await settle();
      if (this.panicked !== null) break;
      if (this.x.wn_take_dirty() !== 0) {
        ok = await this.step(U64(this.x.wn_now()));
        continue;
      }
      const next = this.x.wn_next_event();
      if (next < 0n || (deadline !== undefined && next > deadline)) break;
      ok = await this.step(next);
    }
    if (this.panicked !== null) throw new Error(`the simulator panicked: ${this.panicked}`);
    const len = await this.x.wn_finish(deadline === undefined ? -1n : BigInt.asIntN(64, deadline));
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
  async counters(device: Device | number): Promise<[string, bigint][] | null> {
    const dev = typeof device === 'number' ? device : device.index;
    const len = await this.x.wn_counters(dev);
    if (len === -2) return null;
    if (len < 0) throw new Error(this.resultText());
    return codec.decodeCounters(this.result(len));
  }

  /**
   * Runs `command` with `argument` in the device's `wasmnet:control/commands` export now,
   * between runs: its answer, or null if the device takes no commands. Throws if the device
   * trapped (the network failed) or refused the call (a paused device).
   */
  async command(device: Device | number, command: string, argument = ''): Promise<CommandAnswer | null> {
    const dev = typeof device === 'number' ? device : device.index;
    const len = await this.withBytesAsync(encoder.encode(command), (cp, cl) =>
      this.withBytesAsync(encoder.encode(argument), (ap, al) => this.x.wn_command(dev, cp, cl, ap, al)),
    );
    if (len === -2) return null;
    if (len < 0) throw new Error(this.resultText());
    return codec.decodeCommandAnswer(this.result(len));
  }

  /**
   * Sends `command` with `argument` to the device at the start of virtual instant `at` (ns), as
   * an operator event, during a later `run()`. Throws if the device takes no commands.
   */
  scheduleCommand(device: Device | number, at: bigint | number, command: string, argument = ''): void {
    const dev = typeof device === 'number' ? device : device.index;
    const got = this.withBytes(encoder.encode(command), (cp, cl) =>
      this.withBytes(encoder.encode(argument), (ap, al) => this.x.wn_schedule_command(dev, U64(BigInt(at)), cp, cl, ap, al)),
    );
    if (got < 0) throw new Error(this.resultText());
  }


  /**
   * Adds an operator event (`Op`: its `kind`, `at` and fields, read by the simulator, which
   * refuses an unknown kind or field); answers its index in `opStates()`.
   */
  op(op: Op): number {
    const got = this.withBytes(codec.encodeValue(op), (p, l) => this.x.wn_add_op(p, l));
    if (got < 0) throw new Error(this.resultText());
    return got;
  }

  /** The operator events' states, in the order they were added. */
  opStates(): OpState[] {
    const len = this.x.wn_op_states();
    if (len < 0) throw new Error(this.resultText());
    return codec.decodeValue(this.result(len)) as OpState[];
  }

  /** Every device's cost so far: its memory and peak memory (bytes), calls and polls. */
  costs(): DeviceCost[] {
    const len = this.x.wn_costs();
    if (len < 0) throw new Error(this.resultText());
    return codec.decodeValue(this.result(len)) as DeviceCost[];
  }

  /** Everything the device wrote to stdout (or stderr) so far. */
  output(device: Device | number, stream: 'stdout' | 'stderr' = 'stdout'): Uint8Array {
    const dev = typeof device === 'number' ? device : device.index;
    const len = this.x.wn_stdout(dev, stream === 'stderr' ? 1 : 0);
    if (len < 0) throw new Error(this.resultText());
    return this.result(len);
  }
}
