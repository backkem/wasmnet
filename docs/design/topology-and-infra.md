# Dynamic topology and in-world controllers

A network is usually built up front with the builder API: devices, links, scripted link
changes. Two mechanisms change it while it runs, both deterministically: topology operator
events placed by the caller, and requests from in-world controllers through `wasmnet:infra`.
A third changes a device in place: commands into its `wasmnet:control/commands` export
([below](#commands-into-a-running-device)), such as a router's routes.

## Topology changes are operator events the network applies

`wasmnet_core::Op` has topology variants: `AddDevice`, `StopDevice`, `StartDevice`,
`RemoveDevice`, `Wire`, `Unwire`, `SetLink` and `ImpairNamed` (a link's impairments,
[links.md](links.md)), plus name-resolved writes (`StdinNamed`, `ControlNamed`), extension
ops, and faults (`PauseDevice`, `ResumeDevice`, `CrashDevice`) and embedder actions (`Action`)
([below](#faults-pause-crash-and-embedder-actions)). They name devices and links by name and are resolved when they apply, so an op can refer
to a device an earlier op creates. They are queued like every
operator event (see [event-order.md](event-order.md)), but the network applies them, not the
executor: the executor returns from its run at such an event, the network applies it, and the
run goes on exactly where it was. That happens in the event's own processing context, before
its rounds, so everything the change queues (a new device's first poll and `start`, the
`link-state` calls) is keyed by that event and is the same on every replay.

A refused change (a name taken, a port in use, an unknown component) becomes the op's state
(`OpState::Failed`), never the network's failure.

- **Add.** The component comes from the network's component resolver
  (`Network::set_component_resolver`), which turns a catalog name into a component. Without a
  resolver, `add_op` refuses `AddDevice` and `StartDevice` at once. The new device gets the next
  index, and its creator's next number in event keys
  ([event-order.md](event-order.md#devices-created-while-the-network-runs)). Its cables are
  connected in the same op, before it first runs, like a cable plugged in before power-on.
- **Stop.** The device's store is dropped and its links go down, so their far ends see the
  carrier drop. Its name, ports and links stay.
- **Start.** A fresh instance of the same component and config in the same slot; the links its
  stop took down come back up. The network keeps every device's component from its creation
  (an owned copy, `Runtime::Component: ToOwned`), so no component resolver is needed: a device
  built with `Network::device*` starts again as well as one an op or a controller added. The
  new instance must declare the same ports.
- **Remove.** Stopped if running, every link unwired, the name free for a new device.
- **Seeds.** A device instantiated again under a name draws fresh numbers, as a rebooted host
  would. The first instance under a name uses the network seed; the instance after `n` earlier
  ones uses `derive_seed(seed, name, "incarnation-n")` as its root seed.
- **Links.** `Wire` connects two free ports (up at once, or down until a stopped end starts).
  Its latency, MTU and impairments (`impairments`, by sending end) are set before any frame
  crosses it, as are those of `AddDevice`'s cables.
  `Unwire` takes the link down (frames in flight are lost) and frees its ports; the link stays
  in the records with its capture. The same two ports wired again get a fresh name with a
  `-2`, `-3`, ... suffix, so link names and pcap files stay unique.

Every change is journalled under the device it concerns (`device-added`, `device-stopped`,
`device-started`, `device-removed`, `device-crashed`, `device-paused`, `device-resumed`,
`action`, `link-added`, `link-removed`, `link-changed`).

## Faults: pause, crash and embedder actions

Embedder surface, unstable. Tested end to end in
[crates/wasmnet-host/tests/faults.rs](../../crates/wasmnet-host/tests/faults.rs).

### Pause and resume

`Op::PauseDevice { device, link_down }` puts a running device to sleep, as a laptop's lid
closing does: it keeps its store (memory, sockets, connections, timers) but does not run, and
misses the time it sleeps. `Op::ResumeDevice` wakes it. Precisely:

- **Its store** is kept and never polled while paused. Its phase is `DevicePhase::Paused`.
- **Frames** that reach its ports are dropped there, as a powered-down NIC drops them. They
  crossed the link, so the link's capture has them; `device-resumed` counts them (`dropped`).
- **The carrier.** With `link_down: false` its links stay up: the far ends learn of the sleep
  only from its silence (a frozen machine). With `link_down: true` its links go down at the
  pause (the far ends see the carrier drop; frames in flight are lost) and come up at the
  resume, as a sleeping NIC's do. A link wired to it while it sleeps follows the same choice.
- **Its timers and poll deadline** are held as they come due (the guest's `wasi:clocks` waits,
  p2 and p3, a stepped device's `poll` deadline, a controller's `changes.wait` deadline).
  **Link changes, stdin and wakes** wait in its inbox. **Control calls** are refused: between
  runs `Network::counters`, `Network::control` and `Network::command` answer
  `Error::Refused` (the network goes on), an `Op::Control` or `Op::ControlNamed` fails (`is
  paused`), a controller's `devices.control` is `infra-failed`.
- **At the resume** its clocks read the network's time, so monotonic and wall clock alike jump
  by the length of the sleep. The resume's rounds come first: the device is polled with what
  waited in its inbox (the link changes, in order: a `link_down` pause shows the device its
  link going down and then up, as a waking NIC reports). Then its held timers and poll
  deadline fire, at the resume's instant, one event each, in the order they came due, before
  any other event still queued ([event-order.md](event-order.md)). The guest catches up from
  there as it would after any late wake (a TCP stack's overdue retransmission goes out at the
  resume instant). Everything it does at that instant is paid from one instant's fuel.
- **Records.** `device-paused {carrier: up|down}` and `device-resumed {overdue, dropped}`
  (held events, frames dropped at its ports). The device table that `wasmnet:infra` serves does
  not show a pause: a paused device is `running` there, as a frozen machine looks to its
  orchestrator until it stops answering, and no change is recorded.
- **Other ops.** A paused device can be stopped, removed or crashed (its held events go with its
  store); a controller's `stop`, `remove` and new spec apply to it as to a running one (a new
  config is a recreation, since it cannot answer in place). `PauseDevice` needs a running
  device and `ResumeDevice` a paused one (`OpState::Failed` otherwise). A network that goes
  quiet with a device still paused reports it neither parked nor deadlocked.
- **Split networks** refuse pauses, like every op that is not a timed write at a device
  ([sites.md](sites.md)).

### One rule for crashes

A device faults when its own code traps, when it runs out of fuel or memory, when a host
extension's import returns an error (a trap raised by the host), or when an operator event
says so: `Op::CrashDevice { device, message }` faults a running or paused device at the op's
position, as if its guest had trapped there. Whatever raised it, one rule decides what follows:

- a device that **crashes alone** stops as crashed: its store is dropped, its links go down
  (the far ends see it), `device-crashed {message}` is journalled (the trap's last cause, one
  line; the op's message for `CrashDevice`), its phase in the device table is `crashed` with the
  message, and the network runs on. `StartDevice` (or a controller's `start`) runs it again.
- any other device's fault **fails the network** with `Error::Trap`, at the same instant on
  every rerun.

A device crashes alone when an in-world controller created it, or when its options say so:
`DeviceOptions::crash_alone` (a device an embedder builds or adds with an op). An operator's
crash of a device that does not crash alone fails the network, as its guest's trap would. An
extension makes a device crash at a chosen import call by returning an error from that call
(`wasmtime::Error`); `tests/faults.rs` traps the n-th write of a disk. Failures before the device
runs (instantiation, `ports()`) are not crashes: they fail the creation (`OpState::Failed`,
`failed` in the table) or the builder call. A device the network was built with keeps failing
the network by default, as before.

`stopped` and `crashed` stay apart: an operator's or a controller's stop is `stopped` with no
message, an operator's crash is `crashed` with its message, the same as a trap.

### Embedder actions

`Network::register_action(name, closure)` registers a closure; `Op::Action { name, device,
argument }` calls it when the op applies, at its placement among the instant's operator events,
journalled first as `action {name, argument}` on `device` (which must exist). The closure gets
an `OpContext` (the op's instant, device phases, journal events, control calls, the network's
extensions through `extension_mut`, and `add_op` for further operator events) and an
`ActionCall` (name, device, argument); its `Err` is the op's refusal. It cannot run guest code,
change the topology directly (it places an op for that) or move time. `add_op` refuses an
action whose name is not registered.

Replay: a rerun calls the closure again at the same position. The network stays a function of
its inputs only as long as the closure's effects depend only on what it is given (the instant,
the argument, the state it changes); a closure that reads anything else makes the network a
function of that too. `tests/faults.rs` wipes a device's disk (an extension's state) between a
stop and a start at one instant.

## `wasmnet:infra`: the operational API for in-world controllers

`wasmnet:infra` lets a device inside the network (a controller, such as a replica manager)
manage sibling devices: `apply`, `start`, `stop` (with a grace
period), `remove`, `control` (a command into a running device, [below](#commands-into-a-running-device)),
`get`, `list` (by label selector), `watch` (a change feed polled from a
resource version) and `logs`, plus `changes.wait`, which waits for a change. Every `devices`
function is sync and never yields; a controller polls a watch on its own period, or waits on
`changes.wait` ([below](#a-change-feed-that-wakes-a-controller)). Specs are deterministic
CBOR: the device's component, config and options (its output journalled, its arguments and
environment, its fuel) plus the cables to plug in. Calls are idempotent by name and by request
id.

**The grant.** Only a device created with `DeviceOptions::infra` gets an `InfraEnd`
(`DeviceContext::infra`). The wasmtime host refuses to instantiate a component that imports
`wasmnet:infra` without the grant (`Error::Refused`), so an ungranted guest never gets to call
it. The host still links the interface into every store, and a store without an `InfraEnd`
answers `denied` to `apply`, `start`, `stop`, `remove`, `get` and `logs`, an empty `list`
(`(0, [])`) and an empty `watch` (the `since` it was given and no changes)
([crates/wasmnet-host/src/infra.rs](../../crates/wasmnet-host/src/infra.rs)). A controller may
create only the components in the network's catalog (`Network::set_infra_catalog`; without one,
anything the resolver knows), may change only the devices it created (applying to another
device's name is a `conflict`, any other mutation of it is `denied`, and so is a mutation of the
caller itself), and cannot grant `infra` to them.

**Calls are derived operator events.** The sim core keeps a device table (`wasmnet_core::Infra`)
with every device by name: uid, generation, labels, owner, spec, phase and its change log. A
mutation never changes the world inside the call: it validates, records what was asked,
journals `infra-<verb>` on the caller when something changed, and queues a derived event with
an ordinary causal key in the caller's own processing context, at `now` (a graceful stop at
`now + grace`; never before a request already queued for the same device), like a frame sent
with zero latency. The network applies it like a topology op in that event's processing
context. A refusal is journalled as `infra-failed` on the caller and shown on the device,
never the network's failure.

**What a controller sees.** A controller reads its own view of the table: the network's own
devices (those it was built with and those operator events added) and the devices it created,
not other controllers' devices. A resource version is the ordinal of a change in that view, so
a controller's versions count only the changes it sees (`Infra::list_for` and
`Infra::watch_for` show a tool the same; `Infra::list` and `Infra::watch` read the whole table,
with its own ordinals). Only the devices controllers created follow their apps' exits
(`apps`, and a `modified` change); the network's own devices keep an empty `apps`. `logs`
answers only for the caller's own devices (`denied` for the network's, `not-found` for
another controller's). These rules keep the view the same when the network is split over
sites, where a site's journal holds only its own devices ([sites.md](sites.md)). A mutation of
a name another controller owns is still refused (`conflict` for `apply`, `denied` otherwise).

**Name prefixes.** `DeviceOptions::infra_prefix` limits a controller to names that start with
it: any other name is `denied` to every mutation. No two controllers' prefixes may overlap
(one a prefix of the other; `Error::Refused` when the second is added). Controllers on more
than one site of a split network need one each.

**Determinism.** The world stays a function of how the embedder built the network, its
operator events and its seed: a rerun runs the controller again, which makes the same calls at
the same positions. A device's uid is a digest of the derived event that creates it (for other
devices, of their name and the ordinal of the change that added them), so reruns, and runs that
share the history up to that event ([event-order.md](event-order.md)), agree on it.

**A controller's device crashes alone.** A trap in a device that a controller created stops
only that device (its links go down), journals `device-crashed` with a one-line message, and
shows it as `crashed`; `start` runs it again. Elsewhere a trap fails the whole network unless
the device has `DeviceOptions::crash_alone` ([the one rule](#one-rule-for-crashes)).

**Arguments and environment.** A device's `wasi:cli/environment` serves `argv[0]` (its name),
then `DeviceOptions::args`, and `DeviceOptions::env` in the order given; a controller sets
them with the spec keys `args` (text) and `env` (a map of text, sorted by name), at most 256
each, 4 KiB a text, no NUL, no `=` in a name. In a composed node every app and the netstack
share them. Without any, a device sees `argv[0]` alone and no variables, as before. The
`http-server` app puts them in a route's body (`{args}`, `{env:NAME}`).

**A device's output, for its controller.** `logs` reads the lines a device wrote on stdout or
stderr, which the journal has only for a device with `DeviceOptions::journal_stdio`; a spec asks
for that with `"stdio": "journal"`. A controller can then read why a device it created failed:
a component that traps on a bad configuration usually says why on stderr first, and the lines
are journalled even when the device never got as far as running (a failed creation keeps its
name in the table, `failed`, with its lines).

**Devices with their controller.** `DeviceOptions::infra_cascade` says what becomes of the
devices a controller created when the controller stops or is removed (an operator event):
`Keep` (the default: they run on, as before), `Stop` (they stop with it, at once and in
creation order, as on a power cut; starting the controller again does not start them) or
`Remove` (they are removed with it). Each is journalled as `device-stopped` or
`device-removed` with `with-owner`. A request the controller made before it stopped and that
has not applied yet fails when it would apply (`infra-failed`: the controller stopped), so
nothing it asked for appears after the cut.

**Cables while it runs.** `devices.wire(request-id, name, cable)` plugs a cable into a port of
`name`, a device the caller created, and `devices.unwire(request-id, name, port)` unplugs the
one at that port (package 0.1.2). The cable is a spec's cable (CBOR: `port`, `to`, `latency`,
`mtu`, and now `impair`). They are derived requests like the others: queued at the caller's
position after what is still queued for `name`, applied there (journalled as `link-added` or
`link-removed` on `name`), refused when they apply if a port is taken or no cable is there
(`infra-failed`). One rule decides where any of a controller's cables may lead, a creation's
or a `wire`'s: to a device it created or to one of the network's own, never to another
controller's device (`denied` at the call when the table already shows it, `infra-failed`
when it applies). A name not in the table that starts with another controller's
`infra_prefix` counts as that controller's, so a split network, where such a device may live
on another site, refuses it exactly as the unsplit one. Before 0.1.2 a creation's cable could also lead to another controller's
device; it no longer can. In a split network a cable whose far end is on another site fails
the run, like a creation's ([sites.md](sites.md)); an `unwire` concerns the caller's own
device, so it stays on its site.

A cable's `impair` is one impairment for both directions or two by sending end (from `name`'s
port first), set before any frame crosses it. The operator's cables take them too:
`Op::Wire::impairments` and `Cable::impairments` (by sending end), so a link an operator event
wires no longer starts unimpaired for one event.

**Limits.** `DeviceOptions::infra_max_devices` bounds how many devices a controller may have
at once (every device it created that is in the table, whatever its phase): an `apply` of a
new name beyond it is refused at the call with `denied` (`may have at most N devices`) and
queues nothing; removing one makes room. `DeviceOptions::memory`, or a spec's `memory`, bounds
a device's linear memory, all its instances together (in a composed node the netstack and every
app): the wasmtime backend counts each growth, and the growth that would pass the limit traps
at the growing instruction, at the same instant in every run (`memory limit: ...`). It fails
like a device out of fuel: a device a controller created crashes alone (`device-crashed`,
`crashed`), and so does one with `crash_alone`; any other fails the network; a limit too small
for the device to start fails its creation (`failed`). The browser backend neither enforces nor measures it. Every device's
memory is measured either way: `DeviceCost::memory` (now, 0 once stopped) and `peak_memory`,
deterministic, read with `Network::costs` or `cost_of` during and after a run.

**A crash is not a stop.** A device that traps (a fault, its fuel or its memory) is `crashed`,
with the trap's first line as its `message`; one an operator or its controller stopped is
`stopped` with no `message`, and one stopped with its owner (a cascade) is `stopped` with
`stopped with its owner ...`. Since 0.1.2 a stop clears the device's `message` (before, a
stopped device could still show the message of an earlier refused request), which is the one
change to existing tables: `get`, `list` and `watch` show it, the journal does not change.

### Components a controller supplies

A controller creates devices from catalog names: the embedder declared every image in advance.
A platform that lets authors ship apps needs more: a controller that fetches a component over
the simulated network (from a store node, say) and runs it. With the grant below, a controller
hands the host the component's bytes, gets back their SHA-256, and applies specs that name the
component by that digest. Tested end to end in
[crates/wasmnet-host/tests/supply.rs](../../crates/wasmnet-host/tests/supply.rs).

**The grant.** `DeviceOptions::infra_supply` (`Some(SupplyLimits)`, beside `infra`, which it
needs). Without it nothing changes: `components.supply`, `release` and `list` answer `denied`
(an empty list), and a spec that names a digest is `denied` at `apply`. The catalog rule stays
for names.

**Bytes in, a digest out.** `wasmnet:infra/components.supply(digest, bytes)` is one sync call
that never yields: the controller passes the whole component, and optionally the digest it
expects. The host computes the bytes' SHA-256; a stated digest that differs is `invalid` and
stores nothing. One call, not chunks: the host must hold the whole component before it can
check its digest and before the embedder can judge it, and a component is bounded anyway (a
chunked form can be added later without changing this one). The answer is the reference
`sha256:<64 lowercase hex digits>`, which a spec's `component` may then be. The prefix
`sha256:` is reserved: a component name that starts with it is always a digest reference.

**Bounds** (`SupplyLimits`): the largest component (`max_bytes`, checked after the bytes crossed
the call and before anything else), and how many components (`max_components`) and bytes
(`max_total`) the controller's store may keep at once. A supply past a bound is `denied` and
stores nothing. Supplying bytes the store already keeps costs nothing and is not judged again.

**The embedder decides what may run.** Before bytes are kept, compiled or instantiated, the
network calls the embedder's admission callback (`Network::set_supply_admission`) with the
bytes, their digest and the calling controller. Its `Err(reason)` is the controller's
`denied(reason)`, and nothing is stored. Without a callback every supply is refused: a grant
alone runs nothing. This is where an embedder applies its import policy. The wasmtime host
offers one ready-made: `wasmnet_host::ImportPolicy` lists a component's imports by parsing it
(nothing is compiled) and refuses any import its patterns do not allow, and a component that is
not a well-formed component. The host links the same imports for every device whatever the
policy says, so a policy only narrows them: a supplied component that imports something the
host does not serve (`wasi:sockets`, an unknown package) never instantiates. The host checks
that when it compiles the component, so the creation fails cleanly (`failed`, the device's
`message` and `infra-failed` on the controller name the import), never the network. A supplied
component that imports `wasmnet:infra` is refused at instantiation like every component of a
spec, which can grant nothing.

**Compiled once per digest.** When a creation from a digest applies, the network asks the
runtime to compile the controller's bytes (`Runtime::compile_supplied`; the default refuses,
which is what the browser backend does) and keeps the result by digest for as long as any
controller's store keeps those bytes, so a second device, a recreation and a start of a stopped
one compile nothing (`Network::supplied_compiles` counts the compilations). On wasmtime, with a
compile cache directory ([runtime-and-extensions.md](runtime-and-extensions.md)), the
compilation goes through it: the artifact is named by the bytes' full SHA-256 and the engine's
compatibility hash. A stale artifact cannot be picked up (another engine has another hash), and
code inside the network cannot substitute other code: it chooses only bytes, the host names
their artifact by the digest it computed itself, and making two different components share an
artifact would take a SHA-256 collision. The admission callback runs before any lookup, so a
cached artifact never skips it. What remains is the known rule that the directory itself must
be trusted ([known-issues.md](../known-issues.md)): whoever can write files there can replace
any artifact, supplied or not.

**What the store keeps, and when it lets go.** Each controller has its own store; another
controller can neither read nor name its components. A digest stays in the store while the
controller holds it (from `supply` until `components.release`, or until the controller is
removed; a stop or a crash keeps the hold, like a disk), while a device in the table names it
(in any phase: a stopped or crashed device starts again from it, a failed one can be applied
again), or while a request still queued names it. At the first point none is left (a `release`,
a request applying, a device removed, the controller removed) the bytes and the compiled
component are dropped, journalled as `component-dropped {digest, size}` on the controller.
Devices already running keep their instances, and a device that was created from it keeps its
component to start again, as every device does.

**Records.** `infra-supply {digest, size}` on the controller when it takes the hold,
`infra-release {digest}` when it gives it up, `component-dropped` as above; the bytes are never
journalled. A device made from supplied bytes shows its digest reference as its `component`, in
its spec and in `device-added`. It is otherwise like any other device the controller created:
its fuel and memory limits, it crashes alone, `logs`, `control`, `stop`, `start` and
recreation.

**Deterministic and replayable.** The bytes come from inside the simulation (the controller
received them over the network), so a rerun makes the same supply at the same position, and
the admission callback is called again there; like an embedder action, the network stays a
function of its inputs only while the callback's verdict depends only on what it is given.
Nothing is read from outside. A compilation changes no record: whether it happens, and whether
a cache served it, is wall time only.

**Split networks.** A controller's store lives on its site, with the controller and the devices
it creates there. The merge carries what the records carry: digests and sizes in the
controller's journal and the digest references in the table; no bytes cross sites.

**What a controller with the grant can do**: run code it chose, within the embedder's admission,
its bounds and the device limits (fuel, memory, its device count), on its own site, with the
imports the host links for every device and no grant of its own (no `infra`). **What it cannot
do**: run anything the admission refused, read or use another controller's components, keep
more bytes than its bounds, make a compiled artifact stand for other bytes, or reach anything
outside the network.

### A change feed that wakes a controller

`wasmnet:infra/changes.wait(selector, since, deadline)` (package 0.1.2) is an async function:
it returns at once if the caller's view has a change after `since` to a device matching
`selector`, and otherwise waits until one is made or virtual time reaches `deadline`, then
returns the view's latest version. A controller calls it between two reconciles instead of
sleeping for its period (the `replicas` app does with `wake = true`), so it sees a stopped
device, an exit or a crash in the same instant.

It is served by the core (`InfraEnd::wait`, a future): a change wakes the waiting task through
its waker in the processing context the change is made in (a derived event applying, an
operator event, a device's app exit, which the table folds in as it is journalled), and the
executor polls the controller in that event's next round. So the wake is at the same position
in every run, and the same in a split network, where everything in a controller's view
changes on its own site ([sites.md](sites.md)). The deadline is an ordinary timer, cancelled
when the call returns early or is dropped. A stepped controller cannot await: it keeps polling
`watch` from its `poll`.

**Split networks.** A controller works in a split (multi-site) network on its own site: its
devices and their cables stay there. A creation cabled to a device of another site fails the
split run when it applies (`Error::Refused`, deterministic), and WAN links are never created
while a network runs ([sites.md](sites.md#in-world-controllers)).

**Devices it creates are numbered by creator.** Every device has a number in event keys and
record tags; a device created while the network runs gets its creator's next number
([event-order.md](event-order.md#devices-created-while-the-network-runs)), so its uid and the
event order do not depend on what other creators did. With one creator the numbers are the
devices' indices.

### A new config in place

`apply` with a new spec recreates a device: it loses its frames in flight, its learned state,
its connections, and its cables come back under new names (`-2`). When only the config changed
(the same component, options and cables), the device may take the new config in place instead:

- A device that can exports `wasmnet:reconfigure/reconfigure`
  ([wit/reconfigure/reconfigure.wit](../../wit/reconfigure/reconfigure.wit)): one function,
  `reconfigure(now, config)`, given the device's whole new config. A package of its own, so the
  worlds of devices that take commands do not change.
- When the request applies to a running device with that export, the network calls it (a
  control call in the device's event loop, followed by a `poll` at that instant) instead of
  recreating it. The device answers `ok` (it runs on with the new config; `wasi:config/store`
  serves the new config from then on), `restart(why)` (this change needs a restart: the
  network recreates it, as before) or `invalid(why)` (a bad config: nothing changes).
- What the controller sees: on `ok`, a follow-up request records it at the same instant
  (`device-reconfigured` on the device, a `modified` change, generation + 1, the new spec); on
  `restart`, the recreation (`device-removed`, `device-added`, generation + 1); on `invalid`,
  `infra-failed {verb: apply}` with the device's reason, the device's `message`, and the old
  spec back in the table.
- A device without the export, or one that is stopped, is recreated, exactly as before.

The switch takes a new `aging` or `max-entries` in place (it keeps its table and counters;
journalled as `reconfigured`); a new `ports` or `mtu` needs a restart. A changed `blocks` or
`delays` replaces the switch's blocks and delays in place, and an unchanged one keeps those its
commands set ([configuration.md](configuration.md#switch)).

## Commands into a running device

Some changes belong inside a device, not in the topology: a router's routes, for example.
Recreating the device for them (`apply` with a new spec, or a stop and an add) loses its frames
in flight, forgets its neighbours, rewires its links under new names (`-2`) and splits its
captures. A device that can change in place exports `wasmnet:control/commands`
([wit/control/control.wit](../../wit/control/control.wit)): one sync function,
`invoke(now, command, argument) -> result<string, string>`. The router does: `route-add`,
`route-replace`, `route-remove` and `routes`, in its configuration's own route syntax
([wit/router/router.wit](../../wit/router/router.wit) has their semantics).

The wasmtime host finds the export when it instantiates a device and reports it as the optional
export `wasmnet:control/commands` (`wasmnet_core::commands::COMMANDS_EXPORT`). Neither the
host nor the sim core reads a command or its answer. Three ways in, all through the same
control call (`CommandCall`), which runs inside the device's event loop at the current
instant and is followed by a `poll` of the device at that instant:

- **Between runs**: `Network::command(device, command, argument)` answers the device's
  `ok` text or its refusal (`None`: the device takes no commands), like `Network::counters`.
- **Operator events** (embedder surface, unstable): `Op::Control { device, call }` or
  `Op::ControlNamed { device, call }` with `call = DeviceCommand::new(command, argument)
  .into_control()`, at any placement. `add_op` refuses a device that takes no commands; the
  device's refusal becomes the op's state (`OpState::Failed` with its message).
- **Controllers**: `wasmnet:infra/devices.control(request-id, name, command, argument)`, below.

**Why one generic interface, not a router interface.** The operator path and the infra verb
carry a command without knowing the device: a router-specific export would need a
router-specific verb in `wasmnet:infra` and a host that knows routers, and every new device
with commands would add both again. With one export, a device adds commands as it adds
configuration keys, without a change to any package. The price is that commands are text:
the device checks them, as it checks its configuration, and answers a malformed one with an
error instead of trapping.

**`devices.control`.** A controller may send commands only to the devices it created (another
owner's device, the network's own devices and the caller itself are `denied`), and only while
the device is running or about to be (`invalid` otherwise). It follows the rules of every
mutation: it validates and records (`infra-control {name, command}` on the caller), and queues
a derived event at the caller's position, after anything still queued for that device (so an
`apply` and a `control` in one poll reach the new device). When the event applies the command
runs in the device. The answer is not returned by the call: a refusal (the device's error, a
device that stopped meanwhile or takes no commands) is journalled on the caller as
`infra-failed {verb: control, name, message}`, at the instant and in the processing context
the device gave it, and shown as the device's `message`; what the command did is in the
device's own journal (`route-added`). A retry with the same request id and arguments is
answered from the record and not sent again; without a request id, every call sends the
command, so commands should be idempotent (the router's are). In a split network it reaches
the controller's own devices, which are on its site.

**Reading the answer: `devices.control-answer(request-id)`** (0.1.2). A controller that sent a
command with a request id reads its answer by that id: `none` until the command has run, then
the device's `ok` text or its refusal (or why it never reached the device), with the instant
it came. A read by request id, rather than the answer on the device's record, because the
`device` record cannot grow a field without breaking the package, because several commands to
one device can be in flight at once, and because a router's `tunnels` or `routes` listing is
an answer to one question, not a property of the device. Bounds: the host keeps the answers to
the last 256 commands each caller sent with a request id (an older id is `not-found`), each at
most 64 KiB (cut at a character boundary). An answer is a controller's own: no other caller
reads it. It is available from the instant the command runs, which is the derived event's own
instant (so not within the poll that sent it), the same on every replay and, since the device
is on the caller's site, in a split network. Every answer, `ok` or not, is also a `modified`
change of the device (its `message` the refusal, or none), so a controller waiting on
`changes.wait` wakes when it comes. This is new for `ok` answers: before 0.1.2 an answer that
was not a refusal left the table as it was, so a controller that sends commands now sees one
more change, and one more resource version, per command. The `infra-script` fixture reads
answers (`answer <request-id>`) and makes a step depend on one (`when=<id>~<text>`, `!<text>`,
or `when=<id>.<key>=<value>` for a line of `<key> <value>` pairs):
[crates/wasmnet-host/tests/infra_verbs.rs](../../crates/wasmnet-host/tests/infra_verbs.rs) adds a
route to a router only when its `routes` answer lacks it, and
[crates/wasmnet-host/tests/tunnel.rs](../../crates/wasmnet-host/tests/tunnel.rs) routes over a
tunnel once its `tunnels` answer says `state up`. The fixture also takes commands of its own
(`set <variable> <value>`, `variables`): a `{<variable>}` in a `control` step's argument is
filled in when the step runs, which is how a test hands one controller what another learnt.

The package went from `wasmnet:infra@0.1.0` to `0.1.1` (`devices.control`) and to `0.1.2`
(`changes.wait`, `devices.control-answer`, `devices.wire`, `devices.unwire`, the spec keys `args`,
`env` and `memory`, the cable key `impair`): additions, so a component built against an earlier `0.1` still links (wasmtime matches `0.1.x` imports
semver-compatibly).

The `infra-script` test fixture ([components/infra-script](../../components/infra-script)) is
a controller with a script: a stepped device with no ports that makes `apply`, `control`,
`start`, `stop`, `remove` and `logs` calls at set virtual times, which
[crates/wasmnet-host/tests/routes.rs](../../crates/wasmnet-host/tests/routes.rs) uses to change
the routes of a router it created while traffic crosses it, and
[crates/wasmnet-host/tests/infra_verbs.rs](../../crates/wasmnet-host/tests/infra_verbs.rs) to
create devices with arguments and environment, read a failed device's output and stop its
devices with it.

**Not covered yet.** Commands to a device of another site (a controller's own devices are on its
site; a timed `Op::Control` is applied by the device's site, [sites.md](sites.md)). In-place
configs on the router (its routes change through commands). A limit on tables, or on what a
device allocates outside its linear memory. The router's port forwards and allow rules take
the same `commands` export ([nat.md](nat.md)), with no change to the host, the core or `wasmnet:infra`.
