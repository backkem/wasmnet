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

/** Builds one message. */
export class Writer {
  private bytes: number[] = [];

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
    for (const b of v) this.bytes.push(b);
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
    return Uint8Array.from(this.bytes);
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
export function encodeInstance(ports: readonly PortInfo[], flags: { counters: boolean; lifecycle: boolean }, apps: readonly string[]): Uint8Array {
  const w = new Writer().u32(ports.length);
  for (const p of ports) w.u32(p.id).str(p.name).raw(p.mac ?? new Uint8Array()).u32(p.mtu);
  return w
    .u32((flags.counters ? 1 : 0) | (flags.lifecycle ? 2 : 0))
    .strs(apps)
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
