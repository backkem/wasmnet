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

## Extension points

| point | registered with | called |
|---|---|---|
| `NetworkExtension` | `Network::add_extension`, or a runtime's `install` | `device_setup` first when a device's context is built: for a created device right after it entered its setup slot, for an added or restarted one in the op's own processing context; `device_life` right after the network journalled a pause, resume, stop, start, crash or removal |
| `CableModel` | `Network::register_cable(CableKind, model)` | on every message sent on a link of that kind (`LinkMut::kind(LinkKind::Cable(kind))`) |
| `ControlCall` | `Network::control`, `Op::Control`, `Op::ControlNamed`, `OpContext::control` | inside the device's event loop, at the current instant |
| `ExtOp` | `Op::Extension(ExtensionOp::new(op))` | when the operator event applies, in its own processing context |
| `Action` | `Network::register_action(name, closure)`, called by `Op::Action` | when the operator event applies, in its own processing context, after its `action` record |
| `HostExtension` | `Host::with_extension`, `Host::with_extensions` | at engine build, linking, store creation and device instantiation |

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
`device_setup`); `Disks` gives every device a disk instead, to stay short.
