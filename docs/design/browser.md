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
| `wasmnet:infra/{devices,components}` | `wn_infra`: the call's name and its arguments as generic values, answered by the core's `infra::Calls` |
| `wasmnet:infra/changes.wait` | `wn_infra_wait`: a wait the device's actor polls; `js_wait_done` resolves it |

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

The same order is why a page cannot yet add a device while the network runs: when an operator
event or a controller asks for one in the middle of a step, there is no instance waiting
([known-issues.md](../known-issues.md)).

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
| `admit` (`ImportPolicy`: a supplied component's imports, parsed from its bytes) | not wasmtime-specific: it moves to the core when the browser runs supplied components |
| `cache`, `extension`, `command` (`Sim`), `lib` (engines, fuel) | wasmtime-specific |

| `wasmnet-web` module | Kind |
|---|---|
| `runtime` (the registry the page serves imports from, one actor per device calling JavaScript) | browser-specific |
| `infra` (a call's generic values to the core's `infra::Calls` and back, in jco's shapes) | browser-specific glue |
| `codec`, `ffi` (the boundary) | browser-specific |
| `web/src/network.ts` (instantiate with the kit, call exports, forward imports) | browser-specific glue; it decides nothing |

What the browser backend does not do yet: create a device while the network runs (the page
instantiates asynchronously, see above), stdin, fuel, memory (measured or bounded), supplied
components, the refusal of an ungranted `wasmnet:infra` importer at instantiation (the page does
not see a component's imports; every call is `denied` instead), `changes.wait-any` (the page
links only `changes.wait`, whose answer is a number: a component that imports `wait-any` does
not instantiate there; `events.read` and `events.arm` are served), host extensions and sites
([known-issues.md](../known-issues.md)).

**One set of scenarios for both.** `crates/wasmnet-web/tests/parity.rs` runs the same
scenarios on the wasmtime backend and on the browser backend's Rust half, and requires the
same answers and the same journalled events: device commands between runs and as operator
events, a controller that creates devices, commands them, reads the answers and reconfigures a
switch in place, a controller that follows the events of a router it created (`events.read`,
`events.arm`), and a device's arguments and environment. On the browser side wasmtime stands
in for the page: it runs the components and serves their imports through the registry and the
boundary's encoding, as `network.ts` does, so every line of Rust a browser runs is exercised.
The page's own test (`web/test`) then has to prove only the TypeScript: it runs a command, an
operator event, and a server that reads its arguments and environment in headless Chromium.
