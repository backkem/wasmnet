# A device's disks

`crates/wasmnet-disk` gives devices disks: named, ordered key-value stores that belong to a
device and outlive its store. It is a portable extension
([runtime-and-extensions.md](runtime-and-extensions.md#portable-extensions)) written against the
library's public extension points only: the core, `wasmnet-host` and `wasmnet-web` know nothing
of it, and nothing installs it by default.

## The model

A disk is an ordered map from string keys to byte values. Keys sort ascending by their UTF-8
bytes everywhere: scans, `list-keys`, images and digests. A device declares its disks by name,
each with a quota and a durability; it opens one by that name and every call it makes is served
from its own disks only. Calls are synchronous, never yield and take no virtual time: a stepped
device, an async node and a Linux personality's syscall path can all make them.

```rust
let mut net = Network::new(&host, seed); // host = Host::builder().extension(DiskAdapter)
net.add_extension(Disks::default());
let mut options = DeviceOptions::default();
options.ext.set(DiskOptions::new(vec![
    DiskSpec::new("state").quota(64 << 20),
    DiskSpec::new("log").durability(Durability::OnSync),
]));
net.device_with_options("box", &component, config, options)?;
```

The same declaration from a controller's spec or a page's plain object is the option key
`disk.specs` (an extension's keys carry a dot, which keeps them apart from the core's): a list of `{name, quota, durability, initial}`, all but `name` optional
(`durability` is `each-call` or `on-sync`, `initial` an image's bytes). `check_options`
refuses a name declared twice, an empty name, a quota of 0 or past the network's total, and a
bad image.

## The contract

Guests import the standard `wasi:keyvalue@0.2.0-draft2` (`store`, `batch`; vendored in
`wit/deps/keyvalue` exactly as published) and `wasmnet:keyvalue-ext@0.1.0`
([wit/keyvalue-ext](../../wit/keyvalue-ext/keyvalue-ext.wit)): world
`wasmnet:keyvalue-ext/disk-user`.

| | |
|---|---|
| `store.open(name)` | the declared disk `name` as a `bucket`; `no-such-store` for any other name |
| `bucket.get`, `set`, `delete`, `exists` | one key |
| `bucket.list-keys(cursor)` | ascending, 1,024 keys a page; the cursor is the last key given |
| `batch.get-many`, `set-many`, `delete-many` | several keys; `set-many` and `delete-many` are atomic |
| `ordered.write(changes)` | ordered sets and deletes, all or none |
| `ordered.scan(prefix, after, limit, values)` | ascending entries with sizes and, if asked, values |
| `ordered.get-range(key, offset, len)` | part of one value |
| `durable.mode`, `durable.sync` | the disk's durability; make every change so far durable |

The standard functions are served with stronger guarantees than the standard asks (an order,
atomic batches), which it allows. `wasi:keyvalue/atomics` is not served. Limits per call: a key
of at most 4,096 bytes; a value of at most 16 MiB; a write of at most 4,096 changes and 32 MiB;
a scan of 1 to 4,096 entries and at most 8 MiB, but always at least one entry if there is one.
Errors: `no-such-store`, `too-large(why)`, `full(why)`, `failed(why)` from the extension;
`no-such-store` and `other(why)` from the standard functions, with the same texts.

A device that declares no disks is still served, so a call of `open` answers `no-such-store`
instead of faulting it. Supplied components that use disks need the import patterns
`wasmnet_disk::IMPORTS` (`wasi:keyvalue/store`, `wasi:keyvalue/batch`,
`wasmnet:keyvalue-ext/*`) beside `ImportPolicy::devices()`:
`ImportPolicy::devices().and(wasmnet_disk::IMPORTS)`.

## Durability and faults

Every call applies at once to the live map, so the device reads its own writes. In `each-call`
mode (the default) a call that returned `ok` is durable. In `on-sync` mode the changes of each
call join the **unsynced tail** until `sync`, which journals `disk-sync {disk, writes, records,
bytes}`. A **power loss** is the device's store going away: a stop, a crash of any cause, a
controller's recreation. At a power loss the tail is lost, unless a fault says otherwise. The
library has no orderly shutdown, so a stop is a power loss too. Calls never run concurrently
with operator events, so a power loss falls between calls, never inside one.

Faults are operator events timed at a device: `Op::extension_at(device,
ExtensionOp::new(DiskOp::new(disk, fault)))` by its id, `Op::extension_at_named(name, ...)` by
its name (resolved when the op applies, so it reaches a device that an earlier op or a
controller creates; `no device <name>` fails the op when none has the name then), or the op
kinds below from a page's plain objects (`{kind: 'extension', device, op, value, at}`, always
by name). A split network accepts them and applies them on the device's own site. Each is
journalled on the device when it applies.

| Fault (`DiskFault`) | Op kind and value | Effect | Record |
|---|---|---|---|
| `Lose` | `disk.lose {disk}` | emptied now: a drive replaced | `disk-lost {disk, records, bytes}` |
| `PowerLoss {keep, tear}` | `disk.power-loss {disk, keep, tear}` | armed: at the next power loss, none, all or a seeded prefix of the tail survives; with `tear`, the call after the kept ones survives as a seeded prefix of its changes | `disk-armed`, then `disk-power-loss {disk, kept, lost, torn, records, bytes}` |
| `CrashAt {call, keep}` | `disk.crash-at {disk, call, keep}` | the `call`-th changing call from now faults the device inside the call, keeping none, all or a seeded prefix of its changes | `disk-armed`, then `disk-crash {disk, write, kept, of}` and `device-crashed` with the disk's message |
| `CrashAt {call: 0, ..}` | `disk.crash-at {disk, call: 0}` | disarms the disk's crash-at; nothing armed is a no-op, still recorded | `disk-disarmed {disk, fault: crash-at, left}`: the changing calls it had left, or `none` |
| `AnyDiskOp::new(CrashAt {call, keep})` | `disk.crash-at {call, keep}` (no `disk`) | as `CrashAt`, counting the changing calls on any of the device's disks; `call: 0` disarms it | `disk-armed {disks: any, ...}`, then `disk-crash {disk, write, kept, of, disks: any}`; `disk-disarmed {disks: any, ...}` |
| `FailCalls {count, text}` | `disk.fail {disk, count, text}` | the next `count` calls on the disk answer `failed(text)` (`other(text)` from a standard function) and change nothing | `disk-armed` |
| `Corrupt {prefix, how}` | `disk.corrupt {disk, prefix, how, bytes}` | values under `prefix` change: `flip-first-byte` (XOR `0x5a`), `seeded-bytes` (`bytes` seeded positions), `garbage` (seeded bytes of the same length) | `disk-corrupted {disk, prefix, how, values}` |
| `Quota(bytes)` | `disk.quota {disk, bytes}` | the quota changes; below its use every growing call is `full` | `disk-quota {disk, quota, used}` |

A changing call is one that passed its checks (a call answered `full`, `too-large` or an
injected `failed` changes nothing and is not counted); `sync` is not one. A crash-at is
disarmed with `call: 0` rather than an op of its own: "the 0th call from now" is no call, as
`disk.fail` with `count: 0` fails none, so the table keeps one op per fault and the device-wide
form disarms the same way. A crash-at on one disk and one over any disk count apart, each
from when it was armed; whichever reaches its call first faults the device, and when both fall
on the same call the disk's own decides what the call keeps (its record has no `disks: any`).
The crash is a power loss, which disarms every crash-at of the device, as a stop does. Arming
again replaces what was armed. `AnyDiskOp` takes only `CrashAt`, and arming one on a device
without disks is refused.

**A crash fails the whole network unless the device crashes alone.** A device a controller
creates crashes alone; a device the embedder builds or adds with an op does only when its
options say so ([the one rule](topology-and-infra.md#one-rule-for-crashes)). Without it a
`disk.crash-at`, like any trap, ends the run with `Error::Trap`:

```rust
let options = DeviceOptions::default().crash_alone(true); // then options.ext.set(DiskOptions::new(...))
```

`keep` is `none`, `all` or `prefix`. Seeded faults draw from the core's seed derivation:
the `n`-th draw on a disk uses `derive_seed(seed, device, "disk:<name>:<n>")`, so the same
seed gives the same tear on every backend. Tears fall between the changes of one call, never
inside a value; a torn value is `Corrupt`. Faults may break a disk's promised contract on
purpose: that is what they are for. A crash inside a write on an `on-sync` disk loses what the
crash kept at the power loss that follows, as the mode says; a torn write that survives needs
an `each-call` disk.

## Lifetime

A disk survives a pause, a stop, a crash, a start and a controller's recreation (a new spec for
the same name: disks named in both specs stay, dropped names go, new names start empty). It is
dropped when its device is removed, journalled as `disk-dropped {disk, records, bytes}`; a later
device of the same name starts with empty disks. A disk is created empty, or from its spec's
`initial` image, journalled as `disk-created {disk, records, bytes, digest}`.

## Records, digests and images

Contents never enter the journal; sizes and digests do. `each-call` disks journal no per-call
record (a box may write thousands); `DiskRead::stats` counts calls, writes, syncs, errors and the
peak use instead.

Between runs, or from an embedder's action, `Disks` reads a disk: `read(device, disk, |r| ...)`
(entries by prefix, a key, sizes, stats), `digest` (SHA-256 of its image) and `export` (its
image, a piece at a time). `load(device, disk, image)` replaces a declared disk's contents with
an image before or between runs (`disk-loaded`). The image format, `wasmnet-disk/1`, is local to
this crate ([`image`](../../crates/wasmnet-disk/src/image.rs)):

```text
magic    "wasmnet-disk/1\n"
entry    u32 key length, key, u64 value length, value       per entry, keys strictly ascending
end      u32 0xFFFF_FFFF, u64 entries, u64 key and value bytes
```

Integers are big-endian. The image is written and hashed in one pass over the disk without a
copy of it, and read the same way, checked as it comes (order, limits, the end record, nothing
after it). Two disks with the same entries have the same image and digest, whatever happened to
them, on every backend.

## Quotas and memory

A disk's use is its key and value bytes plus 64 bytes per record (`RECORD_OVERHEAD`): tiny
records really hold about twice their bytes in memory, so counting key and value alone would
undercount. Each disk has its quota (default 64 MiB) and the network a total over every disk
(`Disks::total`, default 1 GiB on both backends). A call past either answers `full` and changes
nothing. Disks are not a device's linear memory: `MemoryBudget` does not count them.

Natively the disks live in the host process. In a page they live in the simulator module's
`wasm32` linear memory, which tops out at 4 GiB, and past it the whole simulator aborts, not
one device; so in a page the quotas are not optional: the 1 GiB default keeps a network well
clear of it.

**Choosing the numbers.** Quota bytes track memory: a record costs its key, its value and 64
bytes, which is what the allocator holds for it natively ([Measurements](#measurements)), a
little more than in `wasm32`. A spec's `initial` image is kept with the spec as well, outside
the count.

- **Per disk**: the most one disk may hold, counted that way: a disk of 100,000 records of a
  20-byte key and a 100-byte value uses 100,000 × (20 + 100 + 64) = 18.4 MB. The 64 MiB default
  fits a device's state, not its bulk data.
- **The network's total** is a pool, not a sum of reservations: quotas may add up to more than
  it. A call that fits its disk's quota but not the pool answers `full` too, so with
  overcommit the devices that write first get the room, in the same order on every run.
- **With N devices** of D disks each, start from the total and divide: a per-disk quota of
  total / (N × D) guarantees every disk its quota; quotas a few times larger overcommit safely
  when only some devices fill their disks. In a page, keep the total at or under the 1 GiB
  default (lower when the network also keeps large captures or journals, which share the
  simulator's memory); natively, size it to the host's spare memory. 200 devices with two
  disks each get 2.5 MiB per disk guaranteed under the default, or 6 MiB each if at most a third
  of the disks fill up.

## Running it

- **wasmtime**: the feature `wasmtime` gives the typed adapter `DiskAdapter`, generated by
  `portable_adapter!` from `wasmnet:keyvalue-ext/disk-user`:
  `Host::builder().extension(DiskAdapter)`, then `network.add_extension(Disks::default())`.
- **A page**: the embedder's own page module installs it
  ([crates/wasmnet-disk-page](../../crates/wasmnet-disk-page): `wasmnet_web::install!` with an
  installer that adds `Disks`, plus `wn_disk_digest`, `wn_disk_export` and `wn_disk_load` to
  read digests and images and to load one, for `Network.callExport`); the page links the four
  interfaces from their names. The page test's step "disks in the page" runs the native
  `page_scenario_native` network in Chromium and requires its 72 journal lines and six digests
  exactly.

`crates/wasmnet-disk/tests/wasmtime.rs` runs the probe device
([components/clock-probe/examples/disk_probe.rs](../../components/clock-probe/examples/disk_probe.rs))
on wasmtime at two seeds with byte-identical reruns: stops and starts, every fault, both modes,
a quota hit, a 16 MiB value, images loaded before the run and exported after, a controller's
device declared by its spec, and split networks whose merged runs equal the unsplit ones (one
with faults by name on a device the other site's controller creates, crash-ats over any disk
and a disarm). `crates/wasmnet-web/tests/parity.rs` (`disks_are_served_and_faulted_alike`, and
`disk_faults_by_name_from_plain_objects_apply_alike` for the page's plain objects) requires the
same records and digests from the browser backend.

## Layers on top

A filesystem is a component that exports `wasi:filesystem` and imports a disk, composed in front
of an app as the netstack is (inode and extent keys, `sync` under `sync` and `sync-data`); a
block device is one key per block with an atomic `write` for multi-block updates. Neither needs
anything of the host: both are guest code over the same imports.

## Keep your own WIT, put an adapter in front

A device that already has a storage contract of its own does not have to change its imports to
use a disk. A small component exports that contract and imports the disk; composed in front of
the device (`wac plug device.wasm --plug adapter.wasm`), it is the only part that names the
disk, and an embedder that served the contract from host extensions can delete them without
touching its devices.

The worked example is [components/store-adapter](../../components/store-adapter): it exports
`wasmnet-test:bytes-store` ([wit/test-store](../../wit/test-store/store.wit): records under
**byte** keys with an atomic write and an ordered prefix scan, and objects keyed by a 32-byte
hash with ranged reads) over the disks `state` and `objects`. The mapping is one call each way:

| Device's call | Disk call |
|---|---|
| `state.get` | `bucket.get` |
| `state.write` | `ordered.write` |
| `state.scan` | `ordered.scan` with values |
| `objects.keep` | `ordered.write` of one set (for a typed `full`) |
| `objects.read` | `ordered.get-range` |
| `objects.remove` | `bucket.delete` |
| `objects.held` | `ordered.scan` without values |

Byte keys become string keys in an encoding that keeps their byte order and their prefixes, so
a scan of a byte prefix is a scan of the encoded prefix. Two were measured
(`components/store-adapter/src/lib.rs`, `encoding_cost`, optimised, native):

| Keys | Hex | Latin-1 (each byte as the code point of that number) |
|---|---|---|
| 32-byte hashes | 2.00 bytes per byte; encode 108 ns, decode 174 ns | 1.50 bytes per byte; encode 198 ns, decode 300 ns |
| an ASCII prefix and a u64 | 2.00; encode 70 ns, decode 147 ns | 1.03; encode 78 ns, decode 151 ns |

The adapter uses **Latin-1**: a quarter to a half fewer key bytes (which a quota counts), ASCII
keys stay readable in an export, and its extra 100 ns per key is noise beside a call. Both are
order- and prefix-preserving (a property test checks it); a key of at most 1,024 bytes fits the
disk's 4,096-byte limit either way.

What the adapter costs (`crates/wasmnet-disk/tests/adapter.rs`, `adapter_cost`, wasmtime,
optimised; one write, through the adapter against the same write straight from the device to
the disk):

| Value | Through the adapter | Straight to the disk |
|---|---|---|
| 64 B | 2.6 µs | 1.5 µs |
| 4 KiB | 7.1 µs | 2.4 µs |
| 1 MiB | 1.09 ms | 0.21 ms |
| 16 MiB | 17.6 ms | 16.2 ms |

The difference is the value crossing one more component boundary (lowered into the adapter's
memory and lifted out of it again) and the adapter's allocations; its size cost is the adapter
component itself (120 KB, release build) and nothing per record.

## Measurements

On the maintainer's machine, optimised; the tests that print them are ignored by default.

**A call** (`set` plus a 16-byte `get-range`, by value size):

| Value | wasmtime (`tests/wasmtime.rs`, `call_cost`) | A page in Chromium (page test, "what a disk costs") |
|---|---|---|
| 64 B | 1.6 µs | 39 µs |
| 4 KiB | 1.7 µs | 47 µs |
| 1 MiB | 0.17 ms | 0.60 ms |
| 16 MiB | 2.4 ms | 13.9 ms |

**Digest and export** of one disk (`tests/measure.rs`; native, then the page's `wasm32`
simulator for a 64 MiB disk of 64 KiB values):

| Disk | Digest | Export (into memory) |
|---|---|---|
| 256 MiB in 64 KiB values | 0.11 s (2.3 GB/s) | 0.04 s (7 GB/s) |
| 256 MiB in 4 KiB values | 0.12 s (2.2 GB/s) | 0.04 s (6.5 GB/s) |
| 74 MiB in 64-byte values (a million records) | 0.10 s (0.75 GB/s) | 0.06 s (1.3 GB/s) |
| 1 GiB in 64 KiB values | 0.45 s | |
| 64 MiB in 64 KiB values, in the page | 181 ms (0.35 GB/s) | 43 ms (1.5 GB/s) |

**Memory per stored byte** (key and value bytes requested from the allocator, natively;
`tests/measure.rs`): 1.00 for 64 KiB values, 1.02 for 4 KiB values, 2.19 for 64-byte values
with 14-byte keys. That is what the 64 bytes per record of quota accounting cover. In `wasm32`
the pointers are half the size, so small records cost less there.
