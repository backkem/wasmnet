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
`WebAssembly.promising`). The simulator runs in a Worker, one network per Worker, because jco's
runtime and the kit's event loop are global; a page runs each network in a fresh Worker and can
compile the core modules once and pass them in.

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
| commands and their answers, a controller's `control-answer` (`commands`, `CommandCall::finish`) | both actors |
| reconfiguration, and which config `wasi:config/store` serves after it (`ReconfigureCall::finish_serving`) | both actors |
| which supplied bytes are admitted (`ImportPolicy`, `component_imports`) and how a refusal is worded (`supply::not_compiled`, `not_linked`) | the host's `compile_supplied`; the browser's `compile_supplied` |
| validation, ordering, operator events, the device table, limits, digests, admission, the journal, captures | the network itself |

What each backend still does itself, module by module:

| `wasmnet-host` module | Kind |
|---|---|
| `runtime` (instantiate a component in a store, find its exports, `ports()`, compile supplied bytes, summarise wasmtime's reports) | wasmtime-specific |
| `actor` (one `run_concurrent` per device, a `call_concurrent` per command, fuel per instant) | wasmtime-specific |
| `control`, `reconfigure` (bindings of the two optional exports; the answers go to the core) | wasmtime-specific glue |
| `infra` (WIT types to and from the core's) | wasmtime-specific glue |
| `glue` (`wasmnet:link` and `wasi:config/store` to the core's wire, journal and config) | wasmtime-specific glue |
| `stdio` (wasmtime-wasi streams over the core's captures and stdin queue) | wasmtime-specific glue |
| `wasi` (the deterministic WASI linker; its memory limiter decides the limit and its error) | wasmtime-specific, but the limit's decision would move to the core with a browser memory limit |
| `cache`, `extension`, `command` (`Sim`), `lib` (engines, fuel) | wasmtime-specific |

| `wasmnet-web` module | Kind |
|---|---|
| `runtime` (the registry the page serves imports from, one actor per device calling JavaScript) | browser-specific |
| `infra` (a call's generic values to the core's `infra::Calls` and back, in jco's shapes) | browser-specific glue |
| `codec`, `ffi` (the boundary) | browser-specific |
| `web/src/network.ts` (instantiate with the kit, call exports, forward imports) | browser-specific glue; it decides nothing |

What the browser backend does not do yet: stdin, fuel, memory (measured or bounded), host
extensions and sites ([known-issues.md](../known-issues.md)).

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
