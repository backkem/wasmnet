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
has one associated type and two methods:

- `type Component: ?Sized`: what a device is made from (wasmtime: a compiled `Component`).
- `instantiate(DeviceContext, &Component) -> Result<DeviceInstance>`.
- `install(&mut Network)`: called once when a network is created on this runtime; the place to
  register network extensions and cable kinds. The default does nothing.

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
6. end the actor with a `Fault` on a trap (it never ends otherwise).

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
  `DeviceOptions::fuel_per_instant`) the first time its actor runs at a new instant.
- **The compile cache** ([src/cache.rs](../../crates/wasmnet-host/src/cache.rs)), off unless
  enabled with `Host::with_cache_dir(dir)`. It stores serialized components as
  `<dir>/<content>-<engine>.cwasm`, keyed by the SHA-256 of the component bytes and the engine's
  compatibility hash, prunes least recently used artifacts past its budget (8 GiB unless
  `CompileCache::with_budget` says otherwise; `Host::with_compile_cache`), and coordinates
  processes with lock files. A loaded artifact runs the same machine code as a fresh compile,
  so only `Host::load`'s wall time changes. `default_cache_dir()` is the platform's per-user
  cache directory (`%LOCALAPPDATA%`, `~/Library/Caches`, `$XDG_CACHE_HOME` or `~/.cache`, then
  `wasmnet/compile-cache`); the embedder may pass any other.
- **`Sim`**: runs one `wasi:cli/run` command under its own virtual clock, outside any network.

A limit of the wasmtime backend: it drives instantiation and `ports()` with `block_on` on the
network's own clock, which fires only timers and drops any other event it pops. A component
must not wait on anything while it is instantiated or answers `ports()`.

## Extension points

| point | registered with | called |
|---|---|---|
| `NetworkExtension` | `Network::add_extension`, or a runtime's `install` | `device_setup` first when a device's context is built: for a created device right after it entered its setup slot, for an added or restarted one in the op's own processing context |
| `CableModel` | `Network::register_cable(CableKind, model)` | on every message sent on a link of that kind (`LinkMut::kind(LinkKind::Cable(kind))`) |
| `ControlCall` | `Network::control`, `Op::Control`, `Op::ControlNamed`, `OpContext::control` | inside the device's event loop, at the current instant |
| `ExtOp` | `Op::Extension(ExtensionOp::new(op))` | when the operator event applies, in its own processing context |
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

**Extension ops** apply like topology changes. `ExtOp::apply` gets an `OpContext`: the op's
instant, `running(name)`, `require_export`, `journal_event`, `control` (answered in the op's
rounds) and `extension_mut`. An `Err` is the op's refusal (`OpState::Failed`).

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
`wasmnet-web`'s `JsRuntime` (a browser). `HostExtension` has one,
a test (`Probe` in [crates/wasmnet-host/tests/extension.rs](../../crates/wasmnet-host/tests/extension.rs))
that implements `name`, `add_to_linker` and `init_store`. `NetworkExtension`, `CableModel`,
`ControlCall`, `ControlRequest`, `ControlAnswer`, `ExtOp` and `ControlHandler` have no
implementation in this repository. An embedder grants a capability its extension serves
through `DeviceOptions::ext` (a typed value its extension reads in `device_setup`).
