// The byte encoding of the simulator module's boundary, the JavaScript half of
// crates/wasmnet-web/src/codec.rs (whose header is the reference):
//
//   u8; u32 and u64 little-endian; bytes = u32 length + bytes; str = UTF-8 bytes;
//   list<T> = u32 count + items; pairs = list<(str, str)>
//
// Both halves are built together: there is no version negotiation. A reader rejects truncated
// input and trailing bytes.

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Builds one message. Small fields gather in a list of numbers; a byte string of 64 bytes or
 * more is kept as it is, by reference, so a large `list<u8>` is copied once, when the message
 * is written out ([`finish`], or [`writeInto`] the simulator's memory), never byte by byte.
 */
export class Writer {
  private bytes: number[] = [];
  private parts: Uint8Array[] = [];
  private size = 0;

  private flush(): void {
    if (this.bytes.length > 0) {
      this.parts.push(Uint8Array.from(this.bytes));
      this.size += this.bytes.length;
      this.bytes = [];
    }
  }

  /** The message's length in bytes. */
  get length(): number {
    return this.size + this.bytes.length;
  }

  /** Writes the message into `target` (at least [`length`] bytes). */
  writeInto(target: Uint8Array): void {
    this.flush();
    let at = 0;
    for (const p of this.parts) {
      target.set(p, at);
      at += p.length;
    }
  }

  u8(v: number): this {
    this.bytes.push(v & 0xff);
    return this;
  }

  u32(v: number): this {
    for (let i = 0; i < 4; i++) this.bytes.push((v >>> (8 * i)) & 0xff);
    return this;
  }

  u64(v: bigint): this {
    let x = BigInt.asUintN(64, v);
    for (let i = 0; i < 8; i++) {
      this.bytes.push(Number(x & 0xffn));
      x >>= 8n;
    }
    return this;
  }

  raw(v: Uint8Array): this {
    this.u32(v.length);
    if (v.length < 64) {
      for (const b of v) this.bytes.push(b);
    } else {
      this.flush();
      this.parts.push(v);
      this.size += v.length;
    }
    return this;
  }

  str(v: string): this {
    return this.raw(encoder.encode(v));
  }

  strs(v: readonly string[]): this {
    this.u32(v.length);
    for (const s of v) this.str(s);
    return this;
  }

  pairs(v: readonly (readonly [string, string])[]): this {
    this.u32(v.length);
    for (const [k, x] of v) this.str(k).str(x);
    return this;
  }

  finish(): Uint8Array {
    const out = new Uint8Array(this.length);
    this.writeInto(out);
    return out;
  }
}

/** Reads one message. */
export class Reader {
  private at = 0;
  private readonly view: DataView;

  constructor(private readonly buf: Uint8Array) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  private need(n: number, what: string): number {
    if (this.at + n > this.buf.length) throw new Error(`malformed ${what} at byte ${this.at}`);
    const at = this.at;
    this.at += n;
    return at;
  }

  u8(): number {
    return this.buf[this.need(1, 'u8')]!;
  }

  u32(): number {
    return this.view.getUint32(this.need(4, 'u32'), true);
  }

  u64(): bigint {
    return this.view.getBigUint64(this.need(8, 'u64'), true);
  }

  raw(): Uint8Array {
    const n = this.u32();
    const at = this.need(n, 'bytes');
    return this.buf.subarray(at, at + n);
  }

  str(): string {
    return decoder.decode(this.raw());
  }

  strs(): string[] {
    const n = this.u32();
    const out: string[] = [];
    for (let i = 0; i < n; i++) out.push(this.str());
    return out;
  }

  pairs(): [string, string][] {
    const n = this.u32();
    const out: [string, string][] = [];
    for (let i = 0; i < n; i++) out.push([this.str(), this.str()]);
    return out;
  }

  end(): void {
    if (this.at !== this.buf.length) throw new Error(`malformed message: ${this.buf.length - this.at} trailing bytes`);
  }
}

function whole<T>(bytes: Uint8Array, f: (r: Reader) => T): T {
  const r = new Reader(bytes);
  const v = f(r);
  r.end();
  return v;
}

// ---- messages ---------------------------------------------------------------------------

/** One port of a device, as its `ports()` answers. */
export interface PortInfo {
  id: number;
  name: string;
  mac?: Uint8Array;
  mtu: number;
}

/** What `js_instantiate` gets: the device's name, its component key and its config. */
export function decodePlan(bytes: Uint8Array): { name: string; component: string; config: [string, string][] } {
  return whole(bytes, (r) => ({ name: r.str(), component: r.str(), config: r.pairs() }));
}

/** What `js_instantiate` answers: the ports, which optional exports exist, the apps in start order. */
export function encodeInstance(
  ports: readonly PortInfo[],
  flags: { counters: boolean; lifecycle: boolean; commands: boolean; reconfigure: boolean },
  apps: readonly string[],
  exports: readonly string[] = [],
): Uint8Array {
  const w = new Writer().u32(ports.length);
  for (const p of ports) w.u32(p.id).str(p.name).raw(p.mac ?? new Uint8Array()).u32(p.mtu);
  return w
    .u32((flags.counters ? 1 : 0) | (flags.lifecycle ? 2 : 0) | (flags.commands ? 4 : 0) | (flags.reconfigure ? 8 : 0))
    .strs(apps)
    .strs(exports)
    .finish();
}

export function encodeCounters(values: readonly (readonly [string, bigint])[]): Uint8Array {
  const w = new Writer().u32(values.length);
  for (const [name, value] of values) w.str(name).u64(value);
  return w.finish();
}

export function decodeCounters(bytes: Uint8Array): [string, bigint][] {
  return whole(bytes, (r) => {
    const n = r.u32();
    const out: [string, bigint][] = [];
    for (let i = 0; i < n; i++) out.push([r.str(), r.u64()]);
    return out;
  });
}

export function encodeEvent(kind: string, fields: readonly (readonly [string, string])[]): Uint8Array {
  return new Writer().str(kind).pairs(fields).finish();
}

export function encodeConfig(config: readonly (readonly [string, string])[]): Uint8Array {
  return new Writer().pairs(config).finish();
}

export function decodeStrs(bytes: Uint8Array): string[] {
  return whole(bytes, (r) => r.strs());
}

export function decodeConfig(bytes: Uint8Array): [string, string][] {
  return whole(bytes, (r) => r.pairs());
}

export type Level = 'trace' | 'debug' | 'info' | 'warn' | 'error';
export const LEVELS: readonly Level[] = ['trace', 'debug', 'info', 'warn', 'error'];

/** One journal record, stamped with virtual time (ns) and the device that reported it. */
export type JournalEntry =
  | { at: bigint; device: string; record: 'log'; level: Level; message: string }
  | { at: bigint; device: string; record: 'event'; kind: string; fields: [string, string][] }
  | { at: bigint; device: string; record: 'output'; stream: 'stdout' | 'stderr'; line: string };

export function decodeJournal(bytes: Uint8Array): JournalEntry[] {
  return whole(bytes, (r) => {
    const n = r.u32();
    const out: JournalEntry[] = [];
    for (let i = 0; i < n; i++) {
      const at = r.u64();
      const device = r.str();
      const kind = r.u8();
      if (kind === 0) {
        const level = LEVELS[r.u8()];
        if (level === undefined) throw new Error('malformed journal: level');
        out.push({ at, device, record: 'log', level, message: r.str() });
      } else if (kind === 1) {
        out.push({ at, device, record: 'event', kind: r.str(), fields: r.pairs() });
      } else if (kind === 2) {
        const stream = r.u8() === 0 ? 'stdout' : 'stderr';
        out.push({ at, device, record: 'output', stream, line: r.str() });
      } else {
        // 255: a record kind newer than this decoder, as debug text.
        out.push({ at, device, record: 'log', level: 'debug', message: r.str() });
      }
    }
    return out;
  });
}

/** How a run ended. */
export type Outcome =
  /** Nothing left to do at `at`; `daemons` are calls still running (a server's `run`). */
  | { kind: 'quiescent'; at: bigint; parked: string[]; daemons: string[] }
  /** Stopped at the deadline `at` with `pending` events queued. */
  | { kind: 'deadline'; at: bigint; pending: bigint }
  /** A device crashed (or the network refused to go on) at `at`. */
  | { kind: 'failed'; at: bigint; message: string };

export function decodeOutcome(bytes: Uint8Array): Outcome {
  return whole(bytes, (r): Outcome => {
    const kind = r.u8();
    if (kind === 0) return { kind: 'quiescent', at: r.u64(), parked: r.strs(), daemons: r.strs() };
    if (kind === 1) return { kind: 'deadline', at: r.u64(), pending: r.u64() };
    if (kind === 2) return { kind: 'failed', at: r.u64(), message: r.str() };
    throw new Error(`malformed outcome: kind ${kind}`);
  });
}

// ---- device options, commands, reconfiguration ------------------------------------------------

/**
 * The plain objects the simulator reads as `value` messages (crates/wasmnet-web/src/ops.rs
 * decides their fields and refuses unknown ones; these types are only a guide). Field names are
 * camel case here and kebab case there.
 */

/** A device's options (`DeviceOptions`): what `Network.device` takes besides its config. */
export interface DeviceOptions {
  /** Journal its stdout and stderr lines. */
  journalStdio?: boolean;
  /** Its arguments after `argv[0]` (its name), for `wasi:cli/environment`. */
  args?: readonly string[];
  /** Its environment variables, in order (an object's entries in their order). */
  env?: readonly (readonly [string, string])[] | Record<string, string>;
  /** It may use `wasmnet:infra` (an in-world controller). */
  infra?: boolean;
  /** With `infra`: the prefix of the names it may create. */
  infraPrefix?: string;
  /** With `infra`: what becomes of its devices when it stops or is removed. */
  infraCascade?: 'keep' | 'stop' | 'remove';
  /** With `infra`: the most devices it may have at once. */
  infraMaxDevices?: number;
  /** With `infra`: it may supply components as bytes (`true`: the simulator's default limits). */
  infraSupply?: true | { maxBytes?: number | bigint; maxComponents?: number; maxTotal?: number | bigint };
  /** The most linear memory it may use, in bytes (checked after each call, see the docs). */
  memory?: number | bigint;
  /** Its fuel per virtual instant (the browser meters no fuel: kept for the same options). */
  fuelPerInstant?: number | bigint;
  /** A fault of this device crashes it alone, not the network. */
  crashAlone?: boolean;
  /**
   * The options of the simulator's extensions, by the key each declares (`pad.fault-at`): the
   * extension parses the value (`NetworkExtension::options`).
   */
  [extensionKey: `${string}.${string}`]: unknown;
}

/** One direction's impairments of a link (`docs/design/links.md`). */
export interface Impairments {
  rate?: number | bigint;
  queue?: number;
  lossPpm?: number;
  jitter?: number | bigint;
}

/** A link's options besides its latency. */
export interface LinkOptions {
  mtu?: number;
  /** Both directions' impairments, or each one's. */
  impair?: Impairments;
  impairAb?: Impairments;
  impairBa?: Impairments;
  /** What the link records. */
  capture?: { record?: boolean; snapLen?: number; nameEnds?: boolean };
}

/**
 * An operator event (`Op`) at virtual instant `at` (ns; `end`: after that instant's events): its
 * `kind` and the fields the simulator documents for it (`link-state`, `latency`, `impair`,
 * `inject`, `stdin`, `command`, `add-device`, `stop-device`, `pause-device`, `resume-device`,
  * `crash-device`, `start-device`, `remove-device`, `wire`, `unwire`), or an extension's:
 * `{ kind: 'extension', device, op, value }`, timed at the device called `device` when it applies
 * (one that an earlier op or a controller creates; none of that name then fails it), built by the
 * extension that declares `op` (`NetworkExtension::ops`). Since the device is found by name when
 * the op applies, `op()` accepts an extension op naming a device that does not exist yet; if none
 * has that name when it applies, the op fails then (`no device <name>` in its state), not when
 * added.
 */
export interface Op {
  kind: string;
  at: bigint | number;
  end?: boolean;
  [field: string]: unknown;
}

/** An operator event's state. */
export interface OpState {
  state: 'pending' | 'applied' | 'unreached' | 'failed' | 'other';
  at?: bigint;
  events?: bigint;
  message?: string;
}

/** A device's cost: what the simulator counted for it (memory in bytes). */
export interface DeviceCost {
  name: string;
  memory: bigint;
  peakMemory: bigint;
  fuel: bigint;
  peakFuel: bigint;
  calls: bigint;
  polls: bigint;
  idlePolls: bigint;
}

/** Device options as the simulator reads them: the environment as pairs. */
export function plainOptions(o: DeviceOptions): Record<string, unknown> {
  const env = o.env === undefined || Array.isArray(o.env) ? o.env : Object.entries(o.env);
  return { ...o, ...(env === undefined ? {} : { env }) };
}

/** The `value` message: one plain object, array or value (see `writeValue`). */
export function encodeValue(v: unknown): Uint8Array {
  const w = new Writer();
  writeValue(w, v);
  return w.finish();
}

export function decodeValue(bytes: Uint8Array): unknown {
  return whole(bytes, (r) => readValue(r));
}

/** A command's answer: `ok` text or the device's refusal. */
export type CommandAnswer = { ok: string } | { err: string };

export function decodeCommandAnswer(bytes: Uint8Array): CommandAnswer {
  return whole(bytes, (r) => (r.u8() === 0 ? { ok: r.str() } : { err: r.str() }));
}

// ---- values: wasmnet:infra calls --------------------------------------------------------------
//
// Generic in both directions, so this side knows no function of the interface: arguments as jco
// handed them to the import, answers in the shape jco expects (crates/wasmnet-web/src/codec.rs,
// `Value`, decides the shapes; crates/wasmnet-web/src/infra.rs serves the calls).

const camel = (s: string) => s.replace(/-([a-z0-9])/g, (_, c: string) => c.toUpperCase());

/** Writes a value jco handed over: an option's value bare, `undefined` for none. */
export function writeValue(w: Writer, v: unknown): void {
  if (v === undefined || v === null) w.u8(0);
  else if (typeof v === 'boolean') w.u8(2).u8(v ? 1 : 0);
  else if (typeof v === 'number') {
    if (!Number.isInteger(v) || v < 0) throw new Error(`only whole numbers cross: ${v}`);
    if (v <= 0xffffffff) w.u8(3).u32(v);
    else w.u8(4).u64(BigInt(v));
  }
  else if (typeof v === 'bigint') w.u8(4).u64(v);
  else if (typeof v === 'string') w.u8(5).str(v);
  else if (v instanceof ResourceHandle) w.u8(12).str(v.resource).u32(v.handle);
  else if (v instanceof Uint8Array) w.u8(6).raw(v);
  else if (Array.isArray(v)) {
    w.u8(7).u32(v.length);
    for (const x of v) writeValue(w, x);
  } else if (typeof v === 'object' && 'tag' in v) {
    const { tag, val } = v as { tag: string; val?: unknown };
    w.u8(10).str(tag);
    if (val === undefined) w.u8(0);
    else writeValue(w.u8(1), val);
  } else if (typeof v === 'object') {
    const entries = Object.entries(v);
    w.u8(9).u32(entries.length);
    for (const [k, x] of entries) writeValue(w.str(k.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)), x);
  } else throw new Error(`a value of type ${typeof v} cannot cross`);
}

/**
 * A resource of a portable interface as it crosses the boundary: its WIT name and the handle
 * its server chose. The page makes one class per resource that extends this, so the instances
 * jco hands back to the device are of that class (`network.ts`, `portableImports`).
 */
export class ResourceHandle {
  constructor(
    readonly resource: string,
    readonly handle: number,
  ) {}
}

/** Reads a value in the shape jco expects back. */
export function readValue(r: Reader): unknown {
  const kind = r.u8();
  switch (kind) {
    case 0:
      return undefined;
    case 1:
      return readValue(r);
    case 2:
      return r.u8() !== 0;
    case 3:
      return r.u32();
    case 4:
      return r.u64();
    case 5:
      return r.str();
    case 6:
      // A view: every reader decodes a copy of the simulator's result already (`Network.result`).
      return r.raw();
    case 7:
    case 8: {
      const n = r.u32();
      const out: unknown[] = [];
      for (let i = 0; i < n; i++) out.push(readValue(r));
      return out;
    }
    case 9: {
      const n = r.u32();
      const out: Record<string, unknown> = {};
      for (let i = 0; i < n; i++) {
        const k = r.str();
        out[camel(k)] = readValue(r);
      }
      return out;
    }
    case 10: {
      const tag = r.str();
      return r.u8() === 0 ? { tag } : { tag, val: readValue(r) };
    }
    case 11:
      return r.str();
    case 12:
      return new ResourceHandle(r.str(), r.u32());
    default:
      throw new Error(`malformed value: kind ${kind}`);
  }
}

/** Reads an `infra call` message (the simulator's call of an export by name, `js_export`). */
export function decodeInfraCall(bytes: Uint8Array): { fn: string; args: unknown[] } {
  return whole(bytes, (r) => {
    const fn = r.str();
    const n = r.u32();
    const args: unknown[] = [];
    for (let i = 0; i < n; i++) args.push(readValue(r));
    return { fn, args };
  });
}

/** Writes an `infra reply` message (an export's answer, for `js_export`). */
export function encodeInfraReply(reply: InfraReply): Uint8Array {
  const w = new Writer();
  if ('value' in reply) writeValue(w.u8(0), reply.value);
  else if ('error' in reply) writeValue(w.u8(1), reply.error);
  else w.u8(2).str(reply.failed);
  return w.finish();
}

/** The `infra call` message: the function (`devices.apply`) and the arguments jco passed. */
export function encodeInfraCall(fn: string, args: readonly unknown[]): Uint8Array {
  const w = new Writer().str(fn).u32(args.length);
  for (const a of args) writeValue(w, a);
  return w.finish();
}

/** [`encodeInfraCall`], unwritten: a large byte string in it is copied once, where it is written. */
export function infraCallWriter(fn: string, args: readonly unknown[]): Writer {
  const w = new Writer().str(fn).u32(args.length);
  for (const a of args) writeValue(w, a);
  return w;
}

/** The `infra reply` message: the value, the error to throw, or a failure of the call. */
export type InfraReply = { value: unknown } | { error: unknown } | { failed: string };

export function decodeInfraReply(bytes: Uint8Array): InfraReply {
  return whole(bytes, (r): InfraReply => {
    const kind = r.u8();
    if (kind === 0) return { value: readValue(r) };
    if (kind === 1) return { error: readValue(r) };
    return { failed: r.str() };
  });
}

/** The `imports` message (from `js_imports`): a component's import names, if known. */
export function encodeImports(imports: readonly string[] | undefined): Uint8Array {
  return imports === undefined ? new Writer().u8(0).finish() : new Writer().u8(1).strs(imports).finish();
}
