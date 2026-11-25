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
  index. Its cables are connected in the same op, before it first runs, like a cable plugged in
  before power-on.
- **Stop.** The device's store is dropped and its links go down, so their far ends see the
  carrier drop. Its name, ports and links stay.
- **Start.** A fresh instance of the same component and config in the same slot; the links its
  stop took down come back up. The network must know the device's catalog name: a device added
  by an op has it, one built with `Network::device*` needs `Network::set_device_component`. The
  new instance must declare the same ports.
- **Remove.** Stopped if running, every link unwired, the name free for a new device.
- **Seeds.** A device instantiated again under a name draws fresh numbers, as a rebooted host
  would. The first instance under a name uses the network seed; the instance after `n` earlier
  ones uses `derive_seed(seed, name, "incarnation-n")` as its root seed.
- **Links.** `Wire` connects two free ports (up at once, or down until a stopped end starts).
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
resource version) and `logs`. Every function is sync and never yields; a controller polls a
watch on its own period. Specs are deterministic CBOR: the device's component, config and
options plus the cables to plug in. Calls are idempotent by name and by request id.

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
resource version is the ordinal of a change in this table. A mutation never changes the world
inside the call: it validates, records what was asked, journals `infra-<verb>` on the caller
when something changed, and queues a derived event with an ordinary causal key in the caller's
own processing context, at `now` (a graceful stop at `now + grace`; never before a request
already queued for the same device), like a frame sent with zero latency. The network
applies it like a topology op in that event's processing context. A refusal is journalled as
`infra-failed` on the caller and shown on the device, never the network's failure.

**Determinism.** The world stays a function of how the embedder built the network, its
operator events and its seed: a rerun runs the controller again, which makes the same calls at
the same positions. A device's uid is a digest of the derived event that creates it (for other
devices, of their name and the ordinal of the change that added them), so reruns, and runs that
share the history up to that event ([event-order.md](event-order.md)), agree on it.

**A controller's device crashes alone.** A trap in a device that a controller created stops
only that device (its links go down), journals `device-crashed` with a one-line message, and
shows it as `crashed`; `start` runs it again. A trap anywhere else still fails the whole
network.

In a split (multi-site) network every mutation answers `denied` once a remote device exists;
reads work as usual ([sites.md](sites.md)).

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
runs in the device. The answer is not returned to the caller: a refusal (the device's error, a
device that stopped meanwhile or takes no commands) is journalled on the caller as
`infra-failed {verb: control, name, message}`, at the instant and in the processing context
the device gave it, and shown as the device's `message`; what the command did is in the
device's own journal (`route-added`). A retry with the same request id and arguments is
answered from the record and not sent again; without a request id, every call sends the
command, so commands should be idempotent (the router's are). In a split network it is
`denied`, like every mutation.

The package went from `wasmnet:infra@0.1.0` to `0.1.1`: an addition, so a component built
against 0.1.0 still links (wasmtime matches `0.1.x` imports semver-compatibly).

The `infra-script` test fixture ([components/infra-script](../../components/infra-script)) is
a controller with a script: a stepped device with no ports that makes `apply`, `control`,
`start`, `stop` and `remove` calls at set virtual times, which
[crates/wasmnet-host/tests/routes.rs](../../crates/wasmnet-host/tests/routes.rs) uses to change
the routes of a router it created while traffic crosses it.

**Not covered yet.** Commands in a split network (operator events and infra mutations are
refused there; the site-sync format would have to carry a command and its answer). Changing a
device's configuration in place through infra (`apply` with a new spec still recreates it),
and `wire` and `unwire` verbs for controllers. A NAT or a packet filter would take its rules
through the same `commands` export, with no change to the host, the core or `wasmnet:infra`.
