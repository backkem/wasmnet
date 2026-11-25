# Dynamic topology and in-world controllers

A network is usually built up front with the builder API: devices, links, scripted link
changes. Two mechanisms change it while it runs, both deterministically: topology operator
events placed by the caller, and requests from in-world controllers through `wasmnet:infra`.
A third changes a device in place: commands into its `wasmnet:control/commands` export
([below](#commands-into-a-running-device)), such as a router's routes.

## Topology changes are operator events the network applies

`wasmnet_core::Op` has topology variants: `AddDevice`, `StopDevice`, `StartDevice`,
`RemoveDevice`, `Wire`, `Unwire`, `SetLink` and `ImpairNamed` (a link's impairments,
[links.md](links.md)), plus name-resolved writes (`StdinNamed`, `ControlNamed`) and extension
ops. They name devices and links by name and are resolved when they apply, so an op can refer
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
`device-started`, `device-removed`, `device-crashed`, `link-added`, `link-removed`,
`link-changed`).

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
shows it as `crashed`; `start` runs it again. A trap anywhere else still fails the whole
network.

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
`crashed`), any other fails the network; a limit too small for the device to start fails its
creation (`failed`). The browser backend neither enforces nor measures it. Every device's
memory is measured either way: `DeviceCost::memory` (now, 0 once stopped) and `peak_memory`,
deterministic, read with `Network::costs` or `cost_of` during and after a run.

**A crash is not a stop.** A device that traps (a fault, its fuel or its memory) is `crashed`,
with the trap's first line as its `message`; one an operator or its controller stopped is
`stopped` with no `message`, and one stopped with its owner (a cascade) is `stopped` with
`stopped with its owner ...`. Since 0.1.2 a stop clears the device's `message` (before, a
stopped device could still show the message of an earlier refused request), which is the one
change to existing tables: `get`, `list` and `watch` show it, the journal does not change.

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
journalled as `reconfigured`); a new `ports` or `mtu` needs a restart.

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
answers (`answer <request-id>`) and makes a step depend on one (`when=<id>~<text>`, `!<text>`):
[crates/wasmnet-host/tests/infra_verbs.rs](../../crates/wasmnet-host/tests/infra_verbs.rs) adds a
route to a router only when its `routes` answer lacks it.

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
