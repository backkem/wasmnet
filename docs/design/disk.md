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
`disks`: a list of `{name, quota, durability, initial}`, all but `name` optional
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

Faults are operator events timed at a device (`Op::extension_at(device,
ExtensionOp::new(DiskOp::new(disk, fault)))`, or the op kinds below from a page's plain
objects). A split network accepts them and applies them on the device's own site. Each is
journalled on the device when it applies.

| Fault (`DiskFault`) | Op kind and value | Effect | Record |
|---|---|---|---|
| `Lose` | `disk.lose {disk}` | emptied now: a drive replaced | `disk-lost {disk, records, bytes}` |
| `PowerLoss {keep, tear}` | `disk.power-loss {disk, keep, tear}` | armed: at the next power loss, none, all or a seeded prefix of the tail survives; with `tear`, the call after the kept ones survives as a seeded prefix of its changes | `disk-armed`, then `disk-power-loss {disk, kept, lost, torn, records, bytes}` |
| `CrashAt {call, keep}` | `disk.crash-at {disk, call, keep}` | the `call`-th changing call from now faults the device inside the call, keeping none, all or a seeded prefix of its changes | `disk-armed`, then `disk-crash {disk, write, kept, of}` and `device-crashed` with the disk's message |
| `FailCalls {count, text}` | `disk.fail {disk, count, text}` | the next `count` calls on the disk answer `failed(text)` (`other(text)` from a standard function) and change nothing | `disk-armed` |
| `Corrupt {prefix, how}` | `disk.corrupt {disk, prefix, how, bytes}` | values under `prefix` change: `flip-first-byte` (XOR `0x5a`), `seeded-bytes` (`bytes` seeded positions), `garbage` (seeded bytes of the same length) | `disk-corrupted {disk, prefix, how, values}` |
| `Quota(bytes)` | `disk.quota {disk, bytes}` | the quota changes; below its use every growing call is `full` | `disk-quota {disk, quota, used}` |

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

## Running it

- **wasmtime**: the feature `wasmtime` gives the typed adapter `DiskAdapter`, generated by
  `portable_adapter!` from `wasmnet:keyvalue-ext/disk-user`:
  `Host::builder().extension(DiskAdapter)`, then `network.add_extension(Disks::default())`.
- **A page**: the embedder's own page module installs it
  ([crates/wasmnet-disk-page](../../crates/wasmnet-disk-page): `wasmnet_web::install!` with an
  installer that adds `Disks`, plus exports to read digests and images and to load one); the
  page links the four interfaces from their names.

`crates/wasmnet-disk/tests/wasmtime.rs` runs the probe device
([components/clock-probe/examples/disk_probe.rs](../../components/clock-probe/examples/disk_probe.rs))
on wasmtime at two seeds with byte-identical reruns: stops and starts, every fault, both modes,
a quota hit, a 16 MiB value, images loaded before the run and exported after, a controller's
device declared by its spec, and a split network whose merged run equals the unsplit one.
`crates/wasmnet-web/tests/parity.rs` (`disks_are_served_and_faulted_alike`) requires the same
records and digests from the browser backend.

## Layers on top

A filesystem is a component that exports `wasi:filesystem` and imports a disk, composed in front
of an app as the netstack is (inode and extent keys, `sync` under `sync` and `sync-data`); a
block device is one key per block with an atomic `write` for multi-block updates. Neither needs
anything of the host: both are guest code over the same imports.
