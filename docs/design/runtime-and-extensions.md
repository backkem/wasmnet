# Runtimes and extension points

`wasmnet-core` owns everything deterministic: the clock and its queue, the executor, the patch
panel, the journal, captured stdio, seeds and the device table. It runs no Wasm. A **runtime
backend** turns a component into a running device; `wasmnet-host` is the wasmtime backend. The
guarantee: whatever the backend, the order of events and records is decided by the sim core,
so a backend that keeps the contract below runs a network to the same bytes. Capabilities the
core does not know enter through a small set of extension points, each called at a fixed place
of the core's own flow, so an extension never reorders the queue or the journal.

## The `Runtime` contract

`wasmnet_core::Runtime` ([crates/wasmnet-core/src/network.rs](../../crates/wasmnet-core/src/network.rs))
has one associated type and four methods (three with defaults; `summarize` is the one not listed here):

- `type Component: ?Sized`: what a device is made from (wasmtime: a compiled `Component`).
- `instantiate(DeviceContext, &Component) -> Result<DeviceInstance>`.
- `install(&mut Network)`: called once when a network is created on this runtime; the place to
  register network extensions and cable kinds. The default does nothing.
- `compile_supplied(digest, bytes)`: turns a component a controller supplied as bytes into a
  component, once per digest (`docs/design/topology-and-infra.md`); its refusal fails the
  creation, never the network. The default refuses (a backend that compiles nothing at run
  time). The browser backend checks the bytes with the core and asks its page for a transpile
  of them ([browser.md](browser.md#components-a-controller-supplies)).

`DeviceContext` carries everything one device needs: its index and unique name, the network
seed, the shared `VirtualClock`, its `Wire` (`wire.transmit`), its `JournalEnd` (`log`), its
`DeviceConfig`, stdout and stderr captures, its `Inbox` and `Status`, its fuel per instant, an
`InfraEnd` if it was granted `wasmnet:infra`, and `DeviceExt`, the handles the network's
extensions made for it. `instantiate` must:

1. create the instance and call its `ports()` at the network's current instant, returning the
   answer in `DeviceInstance::ports`, plus whether it exports `counters`, the optional exports it
   serves control calls for (`exports`) and a node's app names (`apps`);
2. queue nothing for the device before it returns (the network registers the device and its
   first poll afterwards);
3. return one actor future (`ActorFuture`) that owns the instance for its whole life: it calls
   `start()` for an async device, then the apps' `run`s, then turns every `Command` from the
   inbox into an export call, recording in-flight calls with `Status::begin` and `Status::end`
   (daemon calls flagged) and live guest tasks with `Status::set_guest_tasks_alive`;
4. after a `receive` or `link-state`, call `VirtualClock::poll_by(index, now)`; after a `poll`,
   replace the deadline with `VirtualClock::set_poll`;
5. serve the device's time from `clock`, its entropy from seeds derived with
   `derive_seed(seed, name, stream)`, and refuse every infra call when `infra` is `None`;
6. end the actor with a `Fault` on a trap (it never ends otherwise), whatever raised it: the
   guest, its fuel or memory, or a host import that returned an error. The network then applies
   one rule: a device that crashes alone stops as crashed, any other fails the network
   ([topology-and-infra.md](topology-and-infra.md#one-rule-for-crashes)).

Two backends are in this repository: `wasmnet-host` on wasmtime, and `wasmnet-web`, where the
core itself is built for `wasm32-unknown-unknown` and a browser's engine runs the devices
([browser.md](browser.md)).

## What `wasmnet-host` adds

- **`Host`** ([crates/wasmnet-host/src/lib.rs](../../crates/wasmnet-host/src/lib.rs)): the
  engines and linkers, built once and shared (`Host::new`, or `Host::builder` for extensions
  and the settings below). The component model and its async support are on, and fuel is
  metered unless the builder turns it off (`fuel(false)`, and with it the fuel guard). On
  request (`unmetered_engine(true)`, embedder surface) a second, unmetered engine serves
  components loaded with `Host::load_unmetered`, for components whose guard is something other
  than wasmtime fuel. The crate re-exports the wasmtime it is built on (`wasmnet_host::wasmtime`),
  so an embedder names `Component` or `Linker` without pinning wasmtime's version and features
  itself.
- **One store per device**, with `HostState`: the WASI context, the resource table, the clock,
  the seed, the wire, the journal, the config, extension state and stdin.
- **Deterministic WASI** ([src/wasi.rs](../../crates/wasmnet-host/src/wasi.rs)): p2 and p3
  clocks (monotonic waits shadowed onto virtual timers; the wall clock is `SimConfig::wall_epoch`
  plus virtual time), `wasi:random` from per-device seeded PRNGs, `wasi:cli` with captured
  stdout and stderr and stdin from operator events, `wasi:config/store`, `wasmnet:link` and
  `wasmnet:infra`. `wasi:sockets` and `wasi:filesystem` are not linked: a component that imports
  them fails to instantiate. `wasi:random/random` is served from the seed on purpose,
  `get-random-bytes` included: a deliberate departure from WASI 0.3's note that a deterministic
  environment must omit that function, made so that ordinary programs run unmodified and repeat
  exactly (so no byte a guest draws here is a secret).
- **Guards**: each store's fuel is set to its per-instant budget (`Guard::fuel_per_instant`, or
  `DeviceOptions::fuel_per_instant`) the first time its actor runs at a new instant; how to
  choose it is under [Costs](#costs).
- **The compile cache** ([src/cache.rs](../../crates/wasmnet-host/src/cache.rs)), off unless
  enabled with `Host::with_cache_dir(dir)`. It stores serialized components as
  `<dir>/<content>-<engine>.cwasm`, keyed by the SHA-256 of the component bytes and the engine's
  compatibility hash, prunes least recently used artifacts past its budget (8 GiB unless
  `CompileCache::with_budget` says otherwise; `Host::with_compile_cache`), and coordinates
  processes with lock files. A loaded artifact runs the same machine code as a fresh compile,
  so only `Host::load`'s wall time changes. `default_cache_dir()` is the platform's per-user
  cache directory (`%LOCALAPPDATA%`, `~/Library/Caches`, `$XDG_CACHE_HOME` or `~/.cache`, then
  `wasmnet/compile-cache`); the embedder may pass any other.
  Components controllers supply go through it with `CompileCache::load_bytes`, named by their
  full SHA-256 ([topology-and-infra.md](topology-and-infra.md#components-a-controller-supplies)).
- **`ImportPolicy`** (the sim core's [admit.rs](../../crates/wasmnet-core/src/admit.rs), re-exported here): a ready-made
  admission for supplied components, an allow list of import patterns checked by parsing the
  component (`component_imports`), before anything is compiled.
- **`Sim`**: runs one `wasi:cli/run` command under its own virtual clock, outside any network.

A limit of the wasmtime backend: it drives instantiation and `ports()` with `block_on` on the
network's own clock, which fires only timers and drops any other event it pops. A component
must not wait on anything while it is instantiated or answers `ports()`.

## Costs

`Network::costs` (and `cost_of`) report what each device cost so far as a `DeviceCost`:
commands, actor polls, idle polls, wall time (not deterministic, only with
`Network::set_wall_clock`) and fuel. They are reports only: nothing in a run depends on them,
and all but the wall time are the same on every replay. A device started again counts from
zero.

**An instant**, for fuel, is one value of virtual time. The budget is per instant: the store's
fuel is set to `fuel_per_instant` the first time the device's actor runs at a new instant, and
everything the guest runs at that instant (every actor poll, command, timer and task, however
many times it is polled there) is paid from it. `fuel` is the total. `peak_fuel` is the most
one instant consumed, and `peak_fuel_at` that instant (the first one, if several consumed as
much). The backend reports fuel at each look into the store and names the instant it was
consumed under (`CostMeter::add_fuel_at`), so guest work that is only seen at the next
instant's first look still counts in its own. Instantiation and `ports()` run on a budget of
their own and are in neither figure. Without metering (the browser backend, `fuel(false)`, an
unmetered component) both are 0.

**Choosing `fuel_per_instant`.** Run the workload once with a generous budget and read the
devices' `peak_fuel`: a budget at or above it lets that run through unchanged (fuel never
changes behaviour; it only traps), so give the busiest device its peak with headroom for the
inputs the workload does not cover, say twice, through `DeviceOptions::fuel_per_instant`, and
keep the network's `Guard::fuel_per_instant` for the rest. `peak_fuel_at` says which instant
to look at in the journal when a peak is larger than expected. A device that runs out traps
with `OutOfFuel` at the same instant on every replay, so a budget too small for a new workload
shows up as a deterministic failure, never as a slow run.

**What some work costs.** Fuel counts Wasm instructions, so it is a fair, deterministic measure of
what a device does, and a reason to read `peak_fuel` before raising a budget. Measured by
`crates/wasmnet-host/tests/tunnel.rs` (`what_the_cryptography_costs`, seed 1), for a box router
at one end of a tunnel ([tunnels.md](tunnels.md)) carrying a 1 MB HTTP fetch (about 1,100
tunnel packets both ways together), everything the router does included (routing, the
NAT-facing port, ARP, the tunnel):

| | fuel per tunnel packet | whole fetch | peak in one instant |
|---|---|---|---|
| keyless (Geneve) | 23,772 | 25.7 M | 1.4 M |
| keyed (ESP, ChaCha20-Poly1305) | 110,479 | 122.2 M | 7.3 M |

So encryption and authentication add about 87,000 fuel per packet (about 60 per byte of a
full-size packet), 4.6 times the keyless router's work. A check costs 6,021 fuel without a key
and 38,811 with one (signing or checking `MESSAGE-INTEGRITY-SHA256`; measured on an idle tunnel
with a check each way every second, per check message the router sent or received). The
busiest instant of the keyed fetch used 7.3 M of the default 50 M per instant: a router at its
default budget carries this bulk transfer with room to spare, and about seven times as many
packets at one instant would exhaust it. Fuel is the guest's instruction count, not wall time:
these figures say nothing about how fast a native build is.

## Extension points

| point | registered with | called |
|---|---|---|
| `NetworkExtension` | `Network::add_extension`, or a runtime's `install` | `device_setup` first when a device's context is built: for a created device right after it entered its setup slot, for an added or restarted one in the op's own processing context; `device_life` right after the network journalled a pause, resume, stop, start, crash or removal |
| `CableModel` | `Network::register_cable(CableKind, model)` | on every message sent on a link of that kind (`LinkMut::kind(LinkKind::Cable(kind))`) |
| `ControlCall` | `Network::control`, `Op::Control`, `Op::ControlNamed`, `OpContext::control` | inside the device's event loop, at the current instant |
| `ExtOp` | `Op::Extension(ExtensionOp::new(op))` | when the operator event applies, in its own processing context |
| `Action` | `Network::register_action(name, closure)`, called by `Op::Action` | when the operator event applies, in its own processing context, after its `action` record |
| `HostExtension` | `Host::with_extension`, `Host::with_extensions` | at engine build, linking, store creation and device instantiation |
| Portable imports: `NetworkExtension::interfaces`, `DeviceExt::serve`, `ImportServer` | the extension, with the network; its wasmtime adapter (`portable_adapter!`) with the host; nothing in a page | the server is called inside the device's own call, at the current instant ([below](#portable-extensions)) |
| Portable exports: `ControlCall::invocation`, `ExportCall`, `ExportRequest` | `Network::invoke`, `Op::Control`, `OpContext::control`; typed on wasmtime by `portable_adapter!` with a world that exports the interface | inside the device's event loop, at the current instant ([below](#portable-exports)) |

All of them are in [crates/wasmnet-core/src/ext.rs](../../crates/wasmnet-core/src/ext.rs), except
`HostExtension` and its `ControlHandler`
([crates/wasmnet-host/src/extension.rs](../../crates/wasmnet-host/src/extension.rs)).

**Network extensions.** One per type; hooks run in registration order, and a second extension
of the same type replaces the first in its place. `device_setup` gets the device's index, name,
`SetupOrigin` (created, added or restarted), options, clock and journal end, and puts handles
into `DeviceExt`, keyed by type; the backend reads them from `DeviceContext::ext`. Per-device
options of an extension travel in `DeviceOptions::ext` (`ExtOptions`, one value per type).
`Network::extension` reaches the network-wide state.

`device_life` tells an extension what happens to a device, one call per journal record the
network makes about it: `LifeEvent::Paused` (`device-paused`), `Resumed` (`device-resumed`),
`Stopped` (`device-stopped`, by an operator, a controller or a cascade), `Started`
(`device-started`), `Crashed { message }` (`device-crashed`, whatever raised it) and
`Removed` (`device-removed`). The order is fixed: the network makes the change, journals its
record, then calls every extension's `device_life` in registration order, in the same
processing context and before anything else (a controller's cascade then stops or removes its
devices, each with its own record and call, in creation order; the event's rounds follow). So a
record an extension journals in the hook comes right after the network's. For `Stopped`,
`Crashed` and `Removed` the device's store is already gone, and with it every host extension's
per-store state; for `Started` the new store exists and has not run. **Removed is the end**:
the name is free, and a later device of that name (or a controller's recreation of it with a
new spec) is a new device, set up through `device_setup` again. A stop and a crash are not: the
device may start again with the same name. Creation has no life event; `device_setup` is it.

`HostExtension` has no hook of its own for these: its per-store state lives and dies with the
store. Whatever must outlive a store (a disk, a counter across restarts) belongs to a network
extension, which hears the life events and hands each new store a handle through `DeviceExt`.

**An example: a disk per device.** [crates/wasmnet-host/tests/faults.rs](../../crates/wasmnet-host/tests/faults.rs)
has a small, complete one. `DiskHost` (a `HostExtension`) serves a test-only import,
`wasmnet-test:disk/disk` (`read` and `write` of blocks), and registers the network extension
`Disks` from `install`. `Disks` keeps one disk per device name: `device_setup` puts the disk of
the device's name (a new one the first time) into `DeviceExt`, `DiskHost::init_device` copies
that handle into the store's state, and the import's host functions read and write through it.
The disk therefore survives a stop, a crash and a pause, and `device_life` drops it on
`Removed`. A failing disk is one line: the host function returns an error on the n-th write,
and the device crashes inside that call, alone or failing the network by the rule above. An
embedder action (`Op::Action` with a closure that calls `ctx.extension_mut::<Disks>()`) wipes a
disk at an exact place among an instant's events. The device that uses it is
[components/clock-probe/examples/disk_device.rs](../../components/clock-probe/examples/disk_device.rs):
it counts its boots in block 0, so the tests read the disk's life from its journal.

**Cables** carry something other than Ethernet frames. A cable kind has a code from 1 to 255 (0
is Ethernet). A cable has no pcap and no frame log and is counted in its link's `LinkStats`.
For each message the panel calls `well_formed` first (a malformed message is dropped and
counted as oversize), then `carry` with the panel locked (it may only update the link's state
and answers `Nothing`, `Forward` or `Deliver`), then `tap` with the panel unlocked, before the
deliveries are queued `latency` later. A cable never crosses sites ([sites.md](sites.md)).

**Control calls** go to a device's optional export. A call travels the device's inbox like
`counters` and runs at the current instant; the answer lands in the call's own slot
(`ControlAnswer`). Only a device that reports the export (`DeviceInstance::exports`) gets it:
`Network::control` returns `false` otherwise, and `add_op` refuses an `Op::Control`. A call
that `may_reschedule` is followed by a `poll` at the same instant. A call no handler serves is
answered by `unsupported`. An operator event carries a `ControlRequest` (wrapped in `Control`)
that makes a fresh call each time it applies; the device's refusal becomes the op's state.
Two kinds of control call are built in: device commands (`wasmnet_core::commands`), for the
`wasmnet:control/commands` export, and configuration changes in place
(`wasmnet_core::reconfigure`), for the `wasmnet:reconfigure/reconfigure` export. `wasmnet-host`
serves both itself (before any extension's handler); the browser backend calls the page for
both (`wasmnet-web`'s `JsHost::invoke` and `JsHost::reconfigure`)
([topology-and-infra.md](topology-and-infra.md#commands-into-a-running-device)).

The wasmtime backend also measures every device's linear memory, all its instances together,
as it grows (`DeviceCost::memory` and `peak_memory`, deterministic), and bounds it when the
device has `DeviceOptions::memory`: a growth past it traps at the growing instruction.

**Extension ops** apply like topology changes. `ExtOp::apply` gets an `OpContext`: the op's
instant, `running(name)`, `phase(name)`, `require_export`, `journal_event`, `control`
(answered in the op's rounds), `extension_mut` and `add_op` (a further operator event, with
`Network::add_op`'s refusals). An `Err` is the op's refusal (`OpState::Failed`).

**Embedder actions** are the same without a type: `Network::register_action(name, closure)`,
called by `Op::action(name, device, argument)` with the same `OpContext` and an
`ActionCall`, after an `action {name, argument}` record on `device`. What they may do, and what
replay means for them, is in [topology-and-infra.md](topology-and-infra.md#embedder-actions).

**Host extensions** link extra imports into every store. Hooks, each in the order the
extensions were added: `configure_engine` and `engine_built` (only for extensions given to
`Host::with_extensions`, once per engine; they must not change anything a guest can observe),
`add_to_linker` (once per engine; shadowing an import the host serves is an error),
`init_store` (every store, before instantiation), `init_device` (network devices, after every
`init_store`), `store_created`, `instance_ready` (may report an optional export and its
`ControlHandler`) and `install` (from `Runtime::install`). Whatever a guest can observe through
an extension must be a function of its inputs, virtual time (`HostState::now`) and seeds
(`HostState::seed`). A store's extension state is keyed by its type, not by the extension that
put it there (`HostState::insert_extension`, one value per type), so two extensions may share
one device's state by naming the same type, where a second `insert_extension` replaces the
first value instead of merging with it; an extension that wants state of its own keeps its
type private.

**What is implemented here.** `Runtime` has two implementations, `Host` (wasmtime) and
`wasmnet-web`'s `JsRuntime` (a browser). `HostExtension` has two, both tests: `Probe` in
[crates/wasmnet-host/tests/extension.rs](../../crates/wasmnet-host/tests/extension.rs)
(`name`, `add_to_linker` and `init_store`) and `DiskHost` in
[crates/wasmnet-host/tests/faults.rs](../../crates/wasmnet-host/tests/faults.rs) (also
`init_device` and `install`), whose `Disks` is the one `NetworkExtension` (`device_setup` and
`device_life`); a fake runtime's `Recorder` in the core's unit tests is another.
`ControlCall`, `ControlRequest`, `ControlAnswer` and `ControlHandler` have one each, device
commands (`CommandCall`, `DeviceCommand`, `CommandAnswer`, and the host's handler in
[crates/wasmnet-host/src/control.rs](../../crates/wasmnet-host/src/control.rs)). `CableModel`
and `ExtOp` have no implementation in this repository. An embedder grants a capability its
extension serves through `DeviceOptions::ext` (a typed value its extension reads in
`device_setup`); `Disks` gives every device a disk instead, to stay short. The portable
extension points have one user here, the test fixture `wasmnet-pad` (below).

## Portable extensions

A capability a device imports (a disk, a screen, a clock of its own kind) is served once, in
Rust, against the core's public API, and every backend links it: an extension does not write
wasmtime bindings for one backend and a page's imports for the other. It is a
`NetworkExtension` like any other, plus three things:

- **What it serves.** `NetworkExtension::interfaces` lists each interface (`Interface`: its
  full name with its version, its functions by their component-model names such as `open`,
  `[constructor]note`, `[method]note.append` and `[static]note.find`, and its resources).
- **Who serves it, per device.** In `device_setup` the extension hands the device a server of
  each interface it is given: `ext.serve(name, Arc<dyn ImportServer>)`. A device given none
  that imports the interface anyway faults at its first call, with `<interface> is not served
  to this device`, on both backends.
- **How a call is served.** `ImportServer::call(interface, function, args) -> Served`, inside
  the device's own call: synchronous, at the current virtual instant, in the device's
  processing context, so whatever the server does is ordered with the device's other effects.
  Arguments and answers are the core's `Value`s (`wasmnet_core::value`), close to jco's own
  shapes; a resource is `Value::Resource(name, handle)` with a handle the server chose
  (`drop_resource` says when the device lets go of one). `Served::Ok` and `Served::Err` are a
  value and a `result`'s error; `Served::Fault(message)` faults the device inside the call,
  and its crash is journalled with that message on every backend (the backend leaves it with
  `Status::set_fault`).

The rest is the existing points: options from `DeviceOptions::ext`, operator events as
`ExtOp`s, the device's life from `device_life` (`DeviceLife::replaced` tells a controller's
recreation of a device, which keeps its name, from a removal), and the network's seed in
`DeviceSetup::seed` for anything the extension draws.

**Options and operator events from outside Rust.** An extension's options and ops reach it from
three places that are not Rust: a controller's spec, the page's plain objects and an
embedder's own formats. Each goes through the extension's own parser, once per option or op:

- `NetworkExtension::options` declares each option: `ExtOption::new(key, parse)`, a key of the
  extension's own (`pad.fault-at`) and a parser from a `Value` to the option's type.
  `Network::parse_option(key, value)` and `Network::set_option(&mut options, key, value)` use
  it from Rust; a controller's spec takes the key beside the core's (its CBOR read as a
  `Value`: maps are records, arrays lists, numbers `U32` or `U64`), and keeps it as given in the
  canonical spec the device table shows; the page's device options take it as a field.
- `NetworkExtension::check_options(name, &options)` checks a device's options before it is
  created, by the embedder (`Error::Refused`), an operator event (the op fails) or a controller
  (the device is `failed` with the reason). A restart is not checked again.
- `NetworkExtension::ops` declares each operator event the page may build: `ExtOpParser::new(kind,
  parse)`, from a `Value` to an `ExtensionOp` (`Network::parse_op`).
- `Op::ExtensionAt { device, op }` is an extension's op timed at a device: it applies at its
  instant like `Op::Extension`, `OpContext::device` names the device, and a split network
  accepts it (only the device's own site applies it), where it refuses `Op::Extension`.
  `Op::ExtensionAtNamed { device, op }` names the device instead, resolved when the op applies
  (a device that an earlier op or a controller creates; `no device <name>` fails it when none
  has the name then), and a split network takes it too: every site queues it, the site that
  has the device applies it ([sites.md](sites.md) has the rule for a name no site has). The
  page's `{ kind: 'extension', device, ... }` builds it (`wasmnet_web::ops::op_in`).

No two extensions of a network declare one option key or one operator event kind: adding the
second is refused (`Network::try_add_extension` answers `Error::Refused` and changes nothing;
`add_extension` panics). `Network::register_cable`
refuses a cable kind that already has a model, so two extensions cannot share a code.

**On wasmtime** a typed adapter is generated from the interfaces' WIT:

```rust
wasmnet_host::portable_adapter!({
    name: PadAdapter,
    path: "wit/test-pad",
    world: "wasmnet-test:pad/user",
});
let host = Host::builder().extension(PadAdapter).build()?;
```

It runs wasmtime's `bindgen!` on the world and implements the generated host traits: each
call's typed arguments become `Value`s for the device's server, its answer becomes the typed
result, and a resource is a host resource whose representation is the server's handle (a
marker type of its own per resource, so two extensions' resources never mix). Bytes move as
they would through hand-written bindings: `crates/wasmnet-host/tests/portable_cost.rs`
measured, optimised, a 4 MiB append at 2.22 ms through the adapter against 2.17 ms written by
hand, and a 16 MiB one at 9.04 ms against 9.07 ms. `PadAdapter::interfaces()` is what its WIT
declares; a test compares it with the extension's own list. Linking an interface from its
names alone through wasmtime's dynamic `Val`s was measured too and is not offered: a `Val`
per list element made a 16 MiB value a hundred times slower and passed wasmtime's 128 MiB of
hostcall fuel at about 4 MiB.

**In a page** nothing is generated: the binding reads the network's interfaces when it is
created (`wn_interfaces`) and builds each device's imports from the names, a function per
function (calling `wn_import`) and a class per resource. The extension is compiled into the
page's simulator module by the embedder's own build ([browser.md](browser.md#an-embedders-own-page-module)).

**What the WIT may use.** `bool`, unsigned integers, `string`, records, variants, enums,
options, results, tuples, lists (`list<u8>` as bytes) and resources with constructors,
methods and static functions. Signed integers, floats, `char`, flags, streams, futures and
async functions are refused at compile time by the adapter: the page's boundary does not
carry them yet ([known-issues.md](../known-issues.md#the-embedder-surface)).

**Rules a server follows.** It is called with no lock of the network held and may journal
through the `JournalEnd` its `device_setup` was given, at the instant its clock reads. It
never waits: an answer that depends on later events (a wait) is not expressible yet. On
wasmtime a server may block the calling thread (a debugger holding a device until a person
answers), which stops that device's whole run; in a page it must not, since the page has one
thread. The order of extensions is the order they were added: `device_setup`, `device_life`
and the servers' records follow it on both backends.

**What a served call costs the device.** Only its own code's fuel: what the host does for the
call (copying an argument in, the server reading the bytes out of the device's memory) is not
metered. On wasmtime a 16 MiB write costs the device about what a 16-byte one does (3 566
against 3 014 units of fuel in `portable_exports.rs`); in a page fuel is not metered at all.

**A worked example: the test fixture `wasmnet-pad`** ([crates/wasmnet-pad](../../crates/wasmnet-pad),
`wit/test-pad/pad.wit`). Each device keeps named notes:

- `Pad` (a `NetworkExtension`) hands every device a server in `device_setup`, clears a device's
  notes when it crashes (`pad-cleared`), drops them when it is removed (`pad-dropped`) and
  keeps them through a stop, a start and a controller's recreation.
- Its server answers `note`'s constructor, `append`, `read`, `info` (a record with an enum),
  `find` (an `option<note>`), `names` (a list) and `totals` (a tuple), and faults the device at
  the append its options (`PadOptions::fault_at`) or a name rule (`Pad::fault_at`) arm.
- Its probe device ([components/clock-probe/examples/pad_probe.rs](../../components/clock-probe/examples/pad_probe.rs))
  counts its boots in a note and moves a large value through `append` and `read`.

It runs at two seeds with byte-identical reruns on wasmtime
([crates/wasmnet-host/tests/portable.rs](../../crates/wasmnet-host/tests/portable.rs)), alike
on both backends ([crates/wasmnet-web/tests/parity.rs](../../crates/wasmnet-web/tests/parity.rs),
`a_portable_extension_is_served_alike`), and in a real page (`web/test`), whose lines must
equal the native run's.

## Portable exports

The other direction: calling a function a device exports, by name, with `Value`s, on every
backend through one mechanism. It is a control call like a command, so it reaches the device
the three ways control calls do, inside the device's live event loop at the current instant:

- between runs: `Network::invoke(device, Invocation::new(interface, function, args))`, which
  answers `Ok(None)` when the device does not export the interface, else
  `Ok(Some(answer))`;
- as an operator event: `Op::control(device, ExportRequest::new(invocation).into_control())`
  (refused when it is added if the device does not export the interface; a refusal later is
  the op's state);
- from inside a run: `OpContext::control(device, Box::new(ExportCall::new(invocation)))` from an
  extension's op, whose rounds answer it.

`interface` is the export's name without a version (`wasmnet-test:pad/inspect`), `function` its
name in the interface. The answer (`ExportAnswer::get`) is `Ok(Ok(value))` (a `result`'s `ok`,
or the plain value), `Ok(Err(value))` (a `result`'s `err`), or `Err(why)` when no backend
served it (the device has no such function). Answers come in one shape whichever backend gave
them (`export::plain`: an option's value bare, tuples as lists), which is jco's. A trap in the
device, including an argument of the wrong type, is the device's fault, as any trap inside a
control call. `ExportCall::reschedule(true)` lets a call move a stepped device's deadline (a
`poll` at the same instant follows it); by default it does not.

`Network::device_exports(device)` lists every interface the device exports, without a version
and sorted, the same list on both backends (`wasmnet:link/device` included), so a caller can
ask before it calls.

**Underneath.** `ControlCall` has two methods with defaults: `invocation(now)` (the call as a
call of one export function by name, or `None`) and `invoked(answer, config)` (the device's
answer; `config` is what its `wasi:config/store` serves, which a reconfiguration taken in place
replaces). Commands (`CommandCall`: `invoke(now, command, argument)`) and reconfiguration
(`ReconfigureCall`: `reconfigure(now, config)`) implement them, which is how a page serves
them: it has no code of its own for either.

- **On wasmtime** the first handler that takes the call serves it: the host's own for commands
  and reconfiguration (typed, as before), then the extensions' (`HostExtension::instance_ready`),
  then a dynamic handler every device has, which converts the `Value`s with the function's own
  types into `Val`s. A `Val` per list element is slow for large byte strings, so a world that
  exports the interface gets a typed handler from the same macro that serves imports:

  ```rust
  wasmnet_host::portable_adapter!({
      name: PadKeeper,
      path: "wit/test-pad",
      world: "wasmnet-test:pad/keeper", // imports notes, exports inspect
  });
  ```

  The adapter links the world's imports as before and, for every device that exports one of
  its exported interfaces, serves calls of them typed. Only freestanding functions of an
  exported interface are supported (no resources yet).
- **In a page** every call goes to JavaScript as `js_export(dev, now, call)`: the binding finds
  the function by its WIT name through the kit (`exportFn`), calls it with the arguments in
  jco's shapes and answers its value, its thrown `ComponentError` payload (a `result`'s error),
  or, when there is no such function, a refusal. The page reports a device's exports from the
  kit's list of the component's exports. `Network.invoke(device, 'iface#function', args)` and
  `Network.scheduleInvoke(device, at, ...)` are the binding's methods.

`crates/wasmnet-web/tests/parity.rs` (`portable_exports_are_called_alike`) runs the three ways
on both backends with the pad's probe, which exports `wasmnet-test:pad/inspect` (`write`,
`read`, `size`); `crates/wasmnet-host/tests/portable_exports.rs` checks that the typed and the
dynamic handler answer and journal alike, and measures them (`export_cost`).

**An embedder's own run loop.** `Network::next_event_time` and `run_until` let an embedder run a
network one instant at a time and do its own work between instants (read a device through its
export, add an operator event): runs chain, so the journal is the one a single `run_until`
gives, as long as what it does between instants does not change the network
(`an_embedder_drives_the_run_instant_by_instant` in `portable_exports.rs`). In a page the same
loop runs from an embedder's own export on its module (`wn_pad_run` in
[crates/wasmnet-pad/examples/pad_page.rs](../../crates/wasmnet-pad/examples/pad_page.rs), called
`promising`); it does not let JavaScript settle between instants, so it suits stepped devices,
while the binding's `run` serves async ones.
