# wasmnet in the browser

The same networks run in a browser tab: the simulator is Rust compiled to WebAssembly, the
devices are the same components, transpiled to JavaScript. A browser run repeats itself, but it
is live and best-effort: byte-identical runs are a property of the native host. The example page
is [web/](../../web) (live at <https://backkem.github.io/wasmnet/>).

## The split

```text
 page ── Worker ─────────────────────────────────────────────────────────────────────────┐
 │  web/src/network.ts: Network (device, link, run, journal, pcap)                          │
 │    │ wn_* exports                         ▲ wasmnet_js.* imports (js_receive, js_poll, …) │
 │    ▼                                      │                                               │
 │  wasmnet_web.wasm (crates/wasmnet-web)                                                     │
 │    wasmnet-core: clock, event queue, executor, links, pcap taps, journal                   │
 │    JsRuntime: the Runtime backend; one actor per device, calling JavaScript               │
 │                                                                                           │
 │  devices: components transpiled with jco, on the codelib-web kit                          │
 │    WASI from the kit's wasiImports over a World that asks the simulator                   │
 │    wasmnet:link (wire.transmit, log) straight to the simulator                             │
 └───────────────────────────────────────────────────────────────────────────────────────────┘
```

- **[`crates/wasmnet-web`](../../crates/wasmnet-web)** is `wasmnet-core` with a backend whose
  devices live in JavaScript (`JsHost`, `JsRuntime`), and a network API shaped like
  `wasmnet_host::Network` across a hand-rolled boundary: no wasm-bindgen, only numbers and
  bytes. `src/ffi.rs` is the boundary's reference (every export and import, who allocates,
  re-entry), `src/codec.rs` the encoding of everything that is more than a number. It is tested
  natively against a fake JavaScript host.
- **[codelib-web](https://github.com/backkem/codelib/tree/main/web)**, a browser host kit for
  components that knows nothing about networks: the pinned jco with its patches (the transpile
  step), the event loop the patched output runs on, virtual WASI 0.2 and 0.3 over a `World`, the
  loader and a Worker runner. It is vendored as a tarball in [web/vendor](../../web/vendor).
- **[web/src/network.ts](../../web/src/network.ts)** joins them: it loads the simulator,
  instantiates each device with the kit and serves its imports, and drives the run.

A device's imports, all served without a real clock, real entropy or the network:

| Import | Served by |
|---|---|
| `wasi:clocks` (monotonic, wall), timers | the simulator's virtual clock (`wn_now`, `wn_wall_now`, `wn_timer`) |
| `wasi:random` (random, insecure, insecure-seed) | the device's seeded streams (`wn_random_*`, `wn_insecure_seed`), seeded as natively |
| `wasi:config/store` | the device's config (`wn_config_get`, `wn_config_all`) |
| `wasi:cli` stdout and stderr | the device's captures (`wn_output`) |
| `wasi:cli/environment` | the device's `argv` (its name, then `DeviceOptions::args`) and `env` (`wn_args`, `wn_env`), read when the guest asks |
| `wasmnet:link/wire`, `wasmnet:link/log` | `wn_transmit`, `wn_log`, `wn_event` |
| `wasmnet:infra/{devices,components,events}` | `wn_infra`: the call's name and its arguments as generic values, answered by the core's `infra::Calls` |
| `wasmnet:infra/changes.{wait,wait-any}` | `wn_infra_wait`: one wait mechanism for both, a future of the core's (`infra::Calls::wait`, `wait_any`) that the device's actor polls; `js_wait_done` brings its answer, encoded like any other |

And the device's optional exports, which the simulator calls like `receive`:
`wasmnet:control/commands` (`js_invoke`, for `Network::command`, `Op::Control` and a
controller's `devices.control`) and `wasmnet:reconfigure/reconfigure` (`js_reconfigure`). The
page only reports which of them a device has.

## Adding a device

`wn_add_device` asks JavaScript for the instance synchronously (`js_instantiate`), but jco
instantiates asynchronously. So `Network.device()` instantiates the component first, with
imports bound to the index the device will get (devices are numbered in creation order), and
only then calls `wn_add_device`, whose `js_instantiate` hands over the waiting instance and
answers its `ports()`, its apps (`app-<name>` exports, sorted by name) and whether it exports
`counters`, `lifecycle`, `wasmnet:control/commands` and `wasmnet:reconfigure/reconfigure`. A
failed add leaves the index to the next device. The device's options (`DeviceOptions`: its
arguments and environment, a `wasmnet:infra` grant, journalled stdio) cross as one `options`
message; the simulator applies them as the native host does.

The same import adds a device while the network runs: when an operator event or a controller
(`apply`, `start`) asks for one in the middle of a step, there is no instance waiting, so the
page instantiates the component the simulator names (a key of `NetworkOptions.components`, the
same name the core's catalog uses) for the index it gives. `js_instantiate` is a JSPI
`Suspending` import, and the exports that may reach it (`wn_add_device`, `wn_step`, `wn_finish`,
`wn_command`, `wn_counters`) are `promising`: the step waits while the page loads the
component, and JavaScript's event loop runs meanwhile, so guests' async work may run inside
such a step (at the same virtual instant). V8 suspends at every `Suspending` call, even one that
answers at once, which is why `wn_add_device` is `promising` too. A browser without JSPI gets
the page's existing message: jco's runtime needs JSPI anyway. When a device stops, crashes or
is removed its actor is dropped: the registry forgets that instance (what its guest still
calls is an orphan) and the page lets go of it (`js_release`); a start makes a fresh one.

Before it instantiates anything the simulator asks the page for the component's import names
(`js_imports`: `ComponentSource.imports`, which the page build records with
`wasm-tools component wit`) and refuses a component that imports `wasmnet:infra` for a device
without the grant, by the core's rule (`infra::require_grant`), with the native error. A page
that does not know a component's imports skips that check, and every infra call of such a
device is `denied` instead.

## Components a controller supplies

A controller granted `infra_supply` supplies a component's bytes (`wasmnet:infra/components`)
and creates devices from its digest. Store, digest, limits and admission are the core's, as
natively; a page sets the admission with the core's `ImportPolicy` (`setSupplyAdmission`). When
a creation from a digest applies, the browser backend's `compile_supplied` checks the bytes with
the core (`component_imports`: a well-formed component; every import one the page serves) and
asks the page for something to instantiate (`js_compile`, `Suspending`):

- **a pre-transpiled component** (built): a `ComponentSource` whose `digest` is the bytes'
  digest reference. The page build records each component's (`sha256:` of the `.wasm` it
  transpiled), so a controller that supplies the bytes of a component the page ships runs that
  transpile. This is what the page test does.
- **the embedder's hook** (built): `NetworkOptions.supply(digest, bytes)` returns a
  `ComponentSource`, from wherever the embedder transpiles components (a build step, a service
  of its own).
- **transpiling in the tab** (not built): the kit's transpiler (`codelib-web/transpile`, jco's
  code generator plus the kit's patches) is a Node tool that writes files; running it in a page
  needs a browser build of it and a place to put the modules it writes. An embedder that wants
  it can do it inside its `supply` hook.

Refusals use the core's words on both backends (`supply::not_compiled`, `supply::not_linked`):
"`sha256:...` does not link on this host: ...", followed by the backend's own reason.


## The stepping protocol

jco runs a component's async work (a node's `start()`, an app's `run`, the wake-up after a
timer) on promises, outside the simulator's actor polls. So JavaScript drives a run in steps
and lets the kit's event loop settle between them; virtual time moves only when JavaScript is
idle:

```text
step(now)                                   // the first round: start(), apps, link-state
loop {
    settle()                                // the kit's loop: the guests' async work runs
    if take_dirty() { step(now); continue }  // JavaScript woke a device: same instant
    t = next_event()
    if t is none, or past the deadline: break
    step(t)
}
finish(deadline)                            // the outcome
```

`wn_step` runs every event at or before its argument and calls into JavaScript for each device
it runs: `js_receive`, `js_link_state` and `js_poll` call the device's sync exports;
`js_start` and `js_run_app` start async exports, whose ends come back later as `wn_call_done`;
`js_timer_fire` resolves a guest's virtual wait. Anything that reaches a device from JavaScript
(a completion, a new timer) marks the network dirty, and the next step serves it at the same
instant, so no wake is lost. While a step runs, JavaScript may call only the device-side exports
(`wn_transmit`, `wn_log`, the clocks, entropy, config, timers); a network export called from
inside one is refused.

## Live, not byte-identical

A browser run is repeatable: virtual time, seeded entropy and the event queue are the native
ones, the same seed gives the same journal and the same captures, and the timing of everything
the network sees follows the same rules. What differs is the order of work inside one instant:
natively wasmtime decides which guest task runs next, in the browser jco's runtime does. A
device can then report two things of one instant in another order, or (in a busier network) put
two frames of one instant on the wire in another order, and the bytes differ from the native
run's.

For the HTTP example the difference is small and visible: the journal has the same 35 lines at
the same virtual times as the native run, but at time 0 the server's app starts after the
client's stack instead of before it; the two captures come out byte-identical. The page's test
checks the lines against the native example's output (`NATIVE_JOURNAL`, see
[web/README.md](../../web/README.md)).

Chromium only: jco's async runtime needs WebAssembly JSPI (`WebAssembly.Suspending`,
`WebAssembly.promising`). The simulator runs in a Worker, one module instance per Worker,
because jco's runtime and the kit's event loop are global; it holds one network at a time and
runs networks in sequence ([below](#networks-in-sequence)). A page that wants a clean jco runtime
as well runs each network in a fresh Worker, and can compile the core modules once and pass them
in.

## Memory

A device's memories are measured and bounded by the core's `MemoryBudget`, as natively, but the
page learns of a growth only after it happened: jco's runtime grows a core module's memory
itself, and no JavaScript runs before a `memory.grow`. So the page records every core instance a
component makes (the kit's `instantiateCore` hook) and reports the sum of their memories' sizes,
each memory once (`js_memory`); the simulator counts it after the device is instantiated and
after every poll of its actor (`MemoryBudget::observe`). What differs from wasmtime:

- **When:** natively the growth past `DeviceOptions::memory` is refused at the growing
  instruction; in a page the device faults at the end of the poll in which its memories were
  found past the limit, with the same message ("memory limit: growing a linear memory by N
  bytes would take the device to M bytes, past its L bytes", N being everything grown since the
  last look). Until then the memory is really allocated; work that runs between steps (a guest's
  async tasks) is seen at the device's next poll.
- **What:** the same thing, every linear memory of the component's core instances; tables are
  counted on neither backend. A limit too small for a device to start fails its creation on
  both.
- `DeviceCost::memory` and `peak_memory` are the measured sizes (they include the memory jco's
  own shims allocate, which wasmtime does not have).

## Stdin

`Op::Stdin` (and `StdinNamed`) queue bytes in the device's core `InputQueue`, as natively, and
the simulator tells the page (`js_stdin_ready`). A guest's read takes what is queued
(`wn_stdin`); with nothing queued it waits, and the kit treats that wait as patient (the network
may go idle meanwhile). Natively a WASI 0.3 read waits the same way, while a WASI 0.2 read with
nothing queued is the end of the stream; in a page a WASI 0.2 read waits as well.

## Fuel

Not metered. Native fuel comes from wasmtime instrumenting the compiled code; in a page the core
modules run on the browser's engine, which counts nothing, and neither jco nor the kit can make
it (instrumenting the modules at build time would change what runs, and its cost would be the
page's). `fuel_per_instant` is accepted and ignored, and fuel costs stay 0. The guard an embedder
does get is `Guard::max_polls_per_instant` (100 000 polls of one virtual instant, set by
`wasmnet_web::Network::new`; past it the run fails) and, for a guest that never yields, the
Worker's own timeout (the kit's `runInWorker`).

## Options and operator events from TypeScript

The page's binding does not mirror the core's options and ops. Device options, link options and
operator events cross as plain objects (`value` messages); `crates/wasmnet-web/src/ops.rs` reads
them onto the core's own types and constructors (`DeviceOptions`, `CaptureOptions`,
`Impairments`, `Op::stop_device`, ...) and refuses an unknown field or kind, and op states and
costs come back the same way. A new op or option of the core needs a case there and, at most, a
type in `web/src/codec.ts` (`Op`, `DeviceOptions`, `LinkOptions` are guides, not mirrors). A
typed TypeScript surface per op was not built: it would be a second list of the core's ops to
keep in step, which is what this avoids; a thin typed wrapper over `Network.op` is easy to add
where an embedder wants one. Embedder actions and extensions' ops carry Rust closures and values
and stay Rust-only (`wasmnet_web::Network::sim_mut`).

## Portable imports

An interface an extension serves ([runtime-and-extensions.md](runtime-and-extensions.md#portable-extensions))
needs nothing written for the page. When a network is created the binding reads the
interfaces its extensions serve (`wn_interfaces`: name, functions, resources) and builds every
device's imports from those names:

- a function per function, which sends `interface#function` and the arguments as jco handed
  them over to `wn_import`, and returns the answer (a `result`'s error is thrown, a fault traps
  the device with the server's message);
- a class per resource and device, extending `codec.ResourceHandle`, whose instances carry the
  server's handle: jco calls `new Note(name)` for the WIT constructor (the server makes the
  note), the class's methods and static functions call their functions, a handle the server
  answers (at the top of an answer or inside an option) comes back as an instance, and
  disposing of one tells the server (`wn_import_drop`).

A device-side export like `wn_infra`: `wn_import` runs inside a step, never borrows the
network, and answers at once. Large byte strings cross with one copy each way in JavaScript:
the writer keeps them by reference and writes the call straight into the simulator's memory,
and a reply's bytes are a view of the copy the binding takes of the result; the Rust half
decodes them into the `Vec<u8>` the server receives. What one 4 MiB append costs through all
of it in Chromium is measured by the page test's step "a portable call carries 4 MiB through
the page".

## Portable exports

The other direction needs nothing written for the page either. Every control call reaches a
device in the page as one boundary import, `js_export(dev, now, call)`: `interface#function`
(the interface without a version) and the arguments in jco's shapes. The binding finds the
function by its WIT name through the kit (`exportFn`, by the interface's full name, so two
interfaces of one short name never mix), calls it and answers its value, a `result`'s error
(jco's thrown `ComponentError`), or, when the device has no such function, a refusal; anything
else thrown is a trap, the device's fault. Commands and configuration changes in place come
this way: the page has no code of its own for either (`CommandCall` and `ReconfigureCall` say
which function they are, [runtime-and-extensions.md](runtime-and-extensions.md#portable-exports)).

A device's exports are what the kit lists of its component (every exported interface, without a
version), the same list wasmtime reports: `Network.exports(device)`. `Network.invoke(device,
'iface#function', args)` calls one between runs and answers `{ value }`, `{ error }`,
`{ refused }` or null (the device does not export the interface); `Network.scheduleInvoke(device,
at, ...)` calls it as an operator event. The page test's step "portable exports in the page"
does both with the pad's probe and checks the answers wasmtime gives.

**Exports that wait.** `js_export` is a `WebAssembly.Suspending` import: an export jco made
async (or wrapped for JSPI) answers a promise, and the call waits for it while driving the event
loop (the kit's `until`), so it may itself reach a `Suspending` import of the embedder's. Virtual
time does not move inside the call: a promise that waits for a device timer never settles there,
and the kit's idle check fails the call (a trap). Every simulator export that runs devices is
`promising` already. V8 suspends at every `Suspending` call even when it answers at once; the
page test measures that (`jspiSuspendingNs`, a call through a `Suspending` import that answers
at once, against `jspiPlainNs`, a plain import): 63 ns against 4.8 ns per call in headless
Chromium, small beside the call itself.

**Per-device imports and the kit's hooks.** `NetworkOptions.deviceImports(device)` gives one
device's component extra imports, asked each time it is instantiated and merged over the
binding's own (by unversioned interface name): a capability the embedder serves in JavaScript to
the devices it chooses, in this page only. `NetworkOptions.compile` and
`NetworkOptions.instantiateCore` are the kit's hooks, passed through (the binding still sees every
core instance to count the device's memories). Both `deviceImports` and `instantiateCore` get the
device's descriptor (`DeviceDescriptor`: `index`, `name`, `component` and its clock, below);
`instantiateCore(module, imports, device)` is called for every core module of the device, in the
order its component instantiates them, so a code tier serving one device can keep that device's
own instances (the instance exporting its memory and table) and instantiate more modules against
them.

**A device's clock in its own imports.** The descriptor carries the device's virtual clock:
`now()`, `timer(at, wake)` and `sleepUntil(at)` (`timer` as a promise). It is the timer table
the device's own WASI timers use, so an import can answer at a later virtual instant: a WASI 0.3
async function served per device returns `device.sleepUntil(called + latency).then(...)`, and the
guest's call completes at exactly that instant (an HTTP client whose response arrives one
configured latency after the request). The rules are the binding's own timers':

- `wake` runs inside the simulator's step, when the device's actor serves its timers at that
  instant; two timers of one device due at one instant fire in the order they were set, and the
  devices of one round in their order. So a run repeats itself: the page test's step "a device's
  own import answers at a later virtual instant" runs the example with the client's `wait-for`
  served this way, twice, and requires equal records and every answer at its instant.
- From `wake` an import records what is due and resolves promises; the guest's code waiting on
  them runs when the event loop settles, at the same instant. It may call the descriptor's
  functions again (a further timer), never a `Network` method (a step is running).
- An instant already past fires at the device's next poll. A timer belongs to its network: one
  set before `reset` never fires.

This is the page's per-device form of what the portable extensions do not have yet: a served call
that completes at a later virtual instant ([runtime-and-extensions.md](runtime-and-extensions.md#portable-extensions),
"an answer that depends on later events"). A portable form would let a server answer later
through a timer on the device's virtual clock, which both backends already serve (here the
registry's timers, which this descriptor uses); nothing here is in its way, and an embedder who
needs the same on wasmtime waits for that form.

## Exports that answer with a promise

A composition can have sync device exports that wait: an input adapter composed in front of a
netstack, whose `receive` calls a sibling that may block, transpiled with JSPI so that the export
returns a promise. A device made from such a component is called through `Suspending` imports
(`js_receive_suspending`, `js_link_state_suspending`, `js_poll_suspending`,
`js_counters_suspending`; `ports()` inside `js_instantiate`, which suspends already): the call
waits for the promise, driving the event loop as `js_export` does, and the step goes on once it
is answered. A device is called so when its `ComponentSource.suspends` says so, or when its
`ports()` answers with a promise (the `instance` message's `suspends` flag); every other device
is called through the plain imports, which refuse a promise as before, so a network without such
devices costs what it did. Every simulator export that may reach those calls (`wn_step`,
`wn_finish`, `wn_add_device`, `wn_command`, `wn_invoke`, `wn_counters`) is `promising` already.

- **Deterministic.** While the export is pending the simulator is suspended inside the step: no
  event is popped, no other device is called, virtual time does not move. What may run is the
  guests' own JavaScript work already queued in the kit's loop (an async node's task woken
  earlier in the step), as it would run between steps; its calls into the simulator are served at
  that instant like any call from JavaScript. That order is the kit's and the same on every run:
  the page test's step "a device whose exports answer with a promise" runs the example with its
  switch wrapped so (every frame through it waits), twice, and requires equal records.
- **Replaced networks.** A replacement is refused while a step runs, so no export of a replaced
  network is pending when it goes.
- **Cost.** The page test's step "what a frame-heavy run costs in the page" fetches 2 MB through
  the switch (some 5,900 frames), with the plain switch and with the wrapped one. Measured in
  headless Chromium on one machine, three interleaved runs of three fetches each: the plain
  switch took 270 to 311 ms per fetch (about 21,400 frames a second at the median), against 264
  to 285 ms before the suspending path existed, so within the spread between runs; the wrapped
  switch took 298 to 318 ms (about 19,500 frames a second), some 9% slower than the plain one.
  That price is why the path is per device.

## An embedder's own page module

The page loads the simulator as `wasmnet_web.wasm`, this repository's build of
`crates/wasmnet-web`. An embedder whose devices need extensions of its own builds that module
itself: a crate with `crate-type = ["cdylib"]` that depends on `wasmnet-web` and on its
extensions, and names an installer:

```rust
fn install(network: &mut wasmnet_web::install::PageNetwork) {
    network.add_extension(wasmnet_pad::Pad::default());
}
wasmnet_web::install!(install);
```

`cargo build --release --target wasm32-unknown-unknown -p <that crate>` makes a module with every
export of `wasmnet-web` (they carry over from the dependency) plus `wn_install`. The page loads it
in place of `wasmnet_web.wasm`; the binding calls `wn_install` before it creates a network, and
the installer then runs on every network the module creates, before any device: it may add
extensions, register cable kinds, set a component resolver or a catalog, like a wasmtime
backend's `Runtime::install`. The test fixture's module is
[crates/wasmnet-pad/examples/pad_page.rs](../../crates/wasmnet-pad/examples/pad_page.rs), which
`cargo xtask web` builds and the page test loads for its portable-extension steps.

**Its own exports and imports.** The module may carry exports of the embedder's and import
what its extensions need from the page:

- `wasmnet_web::export!(name, |input: &[u8]| -> Result<Vec<u8>, String> { ... })` defines an
  export the page calls with `Network.callExport(name, bytes)`: bytes in, bytes out, an error
  thrown. Between steps it may reach the network with `wasmnet_web::install::with_network`
  (`None` while a network export runs; inside a step an extension reaches its state through the
  servers it handed devices, never through the network).
- `NetworkOptions.imports` adds import modules beside `wasmnet_js`. A function that must wait for
  the page is passed wrapped in `WebAssembly.Suspending`, and the export that reaches it is
  called with `callExport(name, bytes, { promising: true })`, which answers a promise.
- `wasmnet_web::install::new_network(seed)` replaces the module's network with an empty one
  ([Networks in sequence](#networks-in-sequence)). An export that then adds devices through
  `with_network` reaches the page's `js_instantiate`, which suspends: call it `promising`.

**Options and ops from plain objects.** A device's options take the keys of the network's
extensions as fields (`{ crashAlone: true, 'pad.fault-at': 3 }`), and an operator event of an
extension's is `{ kind: 'extension', device, op, value, at }`, timed at `device`; the
simulator hands each to the extension's parser (`NetworkExtension::options`, `ops`), and
refuses a field or an `op` no extension declares.

## Networks in sequence

A module instance holds one network at a time and may run any number of them in sequence, each
with its own seed. Two callers, one code path (`wn_network_new`, which calls
`wasmnet_web::Network::replace` when the module has a network):

- the binding: `Network.reset(seed)`, between runs;
- an embedder's own export: `wasmnet_web::install::new_network(seed)`, for a module that keeps
  state of its own across networks (a session serving a sequence of calls, whose next seed is
  known only once it has read its input).

A replacement releases the old network's devices (`js_release`), tells the page
(`js_network_replaced`), makes the new network and runs the installer on it; the page reads the
new network's interfaces when it next builds a device's imports. It is refused while a network
export runs (a step, a device being added, an embedder's export inside `with_network`).

| Per network: goes with it | Per module instance: stays |
|---|---|
| the core network: devices, links, journal, captures, operator events and their states, the device table, the extensions' state (the installer adds them again), the catalog, the supply admission and the components controllers supplied | the module, the installer, the embedder's own state in the module |
| the registry: each device's clock, entropy, config, stdin queue, timers, waits and async calls | the runtime of each earlier network, empty (about a hundred bytes each: the simulator borrows its runtime for its whole life) |
| in the page: the device instances, the instance waiting to be claimed, timers, waits, stdin reads, the journal cursor, the interfaces read, the sources of supplied components | in the page: `NetworkOptions` (the components and their compiled core modules, the import modules, the hooks), the kit's event loop and jco's runtime |

**Nothing of the old network reaches the next one.** Device indices start at 0 again, so a late
call of an old guest would name a device of the new network. The binding numbers its networks
(a generation) and builds every device's imports for the generation they were made in: once it
is over, a call the simulator would answer throws, a report (a frame, a log line, an async
call's end) is dropped, a timer never fires, a stdin read sees the end of stdin (a waiting read
is ended at the replacement, so the kit's loop has no patient work of the old network left), and
a wait's answer can never come, because the waits and timers were dropped with their ids. A
`run` or `device()` of the binding that was in progress across a `reset` throws. On the Rust
side each network has a fresh registry: a handle of the old one finds no device.

The page test's step "networks in sequence" replaces a network in the middle of a run
(controllers waiting in `changes.wait-any`, servers in `accept`, timers pending), then runs the
example twice on networks with one seed, and requires each run's journal, outcome and captures
to equal the example's on a fresh page at that seed. Its next step does the same from an
embedder's export (`wn_pad_sequence` in
[crates/wasmnet-pad/examples/pad_page.rs](../../crates/wasmnet-pad/examples/pad_page.rs)): the
export computes a seed, calls `new_network`, adds two devices through `with_network` (the page
instantiates them from inside the export, which is called `promising`), and runs them in six
steps, waiting in a `Suspending` import of its own between steps while it holds no borrow of the
network; the new network's journal must equal a fresh page's at that seed.
`crates/wasmnet-web/tests/parity.rs` (`a_network_replaced_in_mid_run_leaves_no_trace`) checks
the Rust half natively.

## Sites and host extensions

- **Host extensions** (`HostExtension`, wasmtime only) are not served in a page. A capability
  meant for both backends is a portable extension (above); an import only page code can serve
  (a blob fetched on demand, an HTTP client over `fetch`) is still the embedder's own import
  object, beside the ones `network.ts` serves.
- **Sites** (a network split over processes, `docs/design/sites.md`): each site is a network of
  its own driven in lockstep with the others; a page could run one site per Worker and pass the
  site-sync messages between them, but the stepping protocol and the WAN carriers (real
  sockets) have no browser form yet.

## What each backend does itself

One library, two backends: `wasmnet-host` runs devices on wasmtime, `wasmnet-web` hands them to
JavaScript. Everything that decides something lives once, in `wasmnet-core`; a backend
instantiates a component, finds its exports, calls them and serves its imports by handing each
call to the core. What the core decides for both:

| Shared in the core | Used by |
|---|---|
| a device's entropy streams and insecure seed (`DeviceEntropy`) | both backends' `wasi:random` |
| a device's `argv` (`argv`): its name, then `DeviceOptions::args` | both backends' `wasi:cli/environment` |
| an app's end in the journal (`JournalEnd::app_exit`) | both actors |
| `wasmnet:infra`: every call, the answers to a device without the grant, the stream names of `logs`, the refusal of an ungranted importer (`infra::Calls`, `infra::require_grant`); the events kept of the devices controllers created, and the wake of an armed wait (`events.arm`: one more `poll` of the controller, queued by the core) | the host's bindings; the browser's `wn_infra` |
| commands and their answers, a controller's `control-answer` (`commands`, `CommandCall::finish`); which function a command is (`ControlCall::invocation`) | the host's typed binding; the browser's generic export call |
| reconfiguration, and which config `wasi:config/store` serves after it (`ReconfigureCall::finish_serving`, `invoked`) | the host's typed binding; the browser's generic export call |
| portable exports: a call of any export function by name, its answer in one shape (`ExportCall`, `export::plain`) | the host's typed adapters and its dynamic handler (`exports`); the browser's `js_export` |
| a device's memory: what is counted, the limit and its error text (`MemoryBudget`: `growing` before a growth, `observe` after one) | the host's limiter; the browser's actor |
| a device's stdin queue (`InputQueue`) | the host's stdio streams; the browser's registry |
| which supplied bytes are admitted (`ImportPolicy`, `component_imports`) and how a refusal is worded (`supply::not_compiled`, `not_linked`) | the host's `compile_supplied`; the browser's `compile_supplied` |
| portable imports: which device has which server, what a call answers, a fault's crash text (`DeviceExt::serve`, `ImportServer`, `Status::set_fault`) | the host's generated adapters (`portable`); the browser's `wn_import` |
| validation, ordering, operator events, the device table, limits, digests, admission, the journal, captures | the network itself |

What each backend still does itself, module by module:

| `wasmnet-host` module | Kind |
|---|---|
| `runtime` (instantiate a component in a store, find its exports, `ports()`, compile supplied bytes, summarise wasmtime's reports) | wasmtime-specific |
| `actor` (one `run_concurrent` per device, a `call_concurrent` per command, fuel per instant) | wasmtime-specific |
| `control`, `reconfigure` (typed bindings of the two optional exports; the answers go to the core) | wasmtime-specific glue |
| `exports` (any export function by name: `Value`s to `Val`s by the function's types) | wasmtime-specific glue |
| `infra` (WIT types to and from the core's) | wasmtime-specific glue |
| `glue` (`wasmnet:link` and `wasi:config/store` to the core's wire, journal and config) | wasmtime-specific glue |
| `stdio` (wasmtime-wasi streams over the core's captures and stdin queue) | wasmtime-specific glue |
| `wasi` (the deterministic WASI linker; its memory limiter tells the core's budget of each growth) | wasmtime-specific |
| `cache`, `extension`, `command` (`Sim`), `lib` (engines, fuel) | wasmtime-specific |

| `wasmnet-web` module | Kind |
|---|---|
| `runtime` (the registry the page serves imports from, one actor per device calling JavaScript) | browser-specific |
| `infra` (a call's generic values to the core's `infra::Calls` and back, in jco's shapes) | browser-specific glue |
| `ops` (device options, link options and operator events from plain JavaScript objects, onto the core's types and constructors; op states and costs back) | browser-specific glue |
| `codec`, `ffi` (the boundary) | browser-specific |
| `web/src/network.ts` (instantiate with the kit, call exports, forward imports) | browser-specific glue; it decides nothing |

What the browser backend does not do: fuel, host extensions' imports and sites (below, and
[known-issues.md](../known-issues.md)).

**One set of scenarios for both.** `crates/wasmnet-web/tests/parity.rs` runs the same
scenarios on the wasmtime backend and on the browser backend's Rust half, and requires the
same answers and the same journalled events: device commands between runs and as operator
events, a controller that creates devices, commands them, reads the answers, reconfigures a
switch in place and restarts a router, a controller that follows the events of a router it
created (`events.read`, `events.arm`), a controller that supplies components (one runs, one is
no component, one does not link), and a device's arguments and environment. On the browser side wasmtime stands
in for the page: it runs the components and serves their imports through the registry and the
boundary's encoding, as `network.ts` does. It hosts stepped devices only, so the Rust a browser
runs for async components (their `start`, apps and the waits `changes.wait` and `wait-any`) is
exercised by the page test instead.
The page's own test (`web/test`) then has to prove only the TypeScript, in headless Chromium:
a command, an operator event, a server that reads its arguments and environment, and devices
created while the network runs (an `infra-script` controller creating, commanding and
restarting a router and following its events (`events.read`, `events.arm`); a `replicas` controller
woken by `changes.wait-any`; a second one that fetches
a component's bytes, supplies them and runs two instances from the page's own transpile; an
ungranted importer refused).
