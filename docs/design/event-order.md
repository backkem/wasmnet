# The event order and operator events

wasmnet-core keeps one discrete-event queue per network. Frame deliveries, guest timers, stepped
devices' poll deadlines, scripted link changes and operator events all share it. The guarantee:
the order of that queue depends only on the network, its seed and what happened before, so the
same run gives the same order every time, and a network split across sites computes the same
order on each of them ([sites.md](sites.md)). This note explains the key that orders the queue
and how changes from outside the simulation (operator events) enter it without disturbing that
order. The code is [crates/wasmnet-core/src/clock.rs](../../crates/wasmnet-core/src/clock.rs) and
[crates/wasmnet-core/src/exec.rs](../../crates/wasmnet-core/src/exec.rs).

The executor pops one event at a time, and only when every device is idle; each event is
processed to quiescence (every device activity it causes at that instant) before the next
([async-under-virtual-time.md](async-under-virtual-time.md)). Below, a **run** means one
execution of a network from its start; two runs of the same network "share a history up to an
event" when every event before it happened identically in both.

## A causal, partition-invariant key

A queue keyed by `(time, seq)`, with one global insertion counter `seq`, gives a total and
deterministic order, but it cannot survive splitting a network across processes: each part
would count only its own insertions. `EventKey` says the same thing in terms every part can
compute locally:

```text
K(e) = (at, origin, [K(cause) if origin = popped], slot, round, device, idx)
```

compared lexicographically, one `KeyLevel` per nesting step:

| field | meaning |
|---|---|
| `at` | the event's virtual time |
| `origin` | `Origin`: `setup` < `init` < `popped` < `control` < `operator`, the context it was queued in |
| `K(cause)` | for `popped`: the key of the event being processed when this one was queued |
| `slot` | `setup`: the setup step (creating device `i` is step `i`; a scripted link change gets the number of devices created so far plus its own index among link changes); `control`: the device; `operator`: the operator event's index; otherwise 0 |
| `round` | the executor's round within the cause (1-based; 0 is the dispatch of the cause itself) |
| `device` | the device whose activity queued it (`HOST_DEVICE` for the simulator itself) |
| `idx` | how many events this `(cause, round, device)` queued before this one |

`init` is the executor's first round, before any event fired; `control` is a control call
between runs (`Network::counters`, `Network::control`). Within one event the executor polls
devices round by round, in device order, until a round finds no work. That makes `K` equal to
the insertion order of a single global counter (the two give byte-identical runs), while it
depends only on the history of the devices involved.

Keys nest, so they are truncated to `KEY_DEPTH` (32) levels. At the cut, `(device, counter)`,
where `counter` is the creating device's lifetime insertion count, stands in for the rest. The
order stays total and partition-invariant at any depth.

Every output record (a journal entry, a frame-log record, a pcap record of a WAN link, a link
transition) is stamped with a `Tag`: the processing context (`Ctx`) it was made in and its
position in that context. Merging the records of the parts of a split network by tag gives
exactly the unsplit order. A causal digest (`wasmnet_core::Digest`,
[crates/wasmnet-core/src/digest.rs](../../crates/wasmnet-core/src/digest.rs)) hashes a key
(`digest::event`) or a tag (`digest::record`), so it names one occurrence by its causal history
alone: the same in every rerun, on every site, and in every run that shares its history up to
that occurrence.

## Event boundaries and stoppable runs

An **event boundary** (`Boundary`) is a point where every store is idle and the next event has
not fired. Its ordinal (`Boundary::events`) counts the events popped so far, operator events
excluded. A run stops only at a boundary, and control calls and new operator events are made
between runs, so they too happen at boundaries. `Network::run_stoppable` checks a stop
condition at every boundary and returns `Step::Stopped` where it holds. Resuming pops the next
event directly, because that boundary's rounds already ran, so a run that stopped any number of
times (with nothing changed at the stops) is byte-identical to one that never stopped.

## Operator events

An operator event (`Op`, placed with `Network::add_op`) is a change made from outside the
simulation: a link going up or down, a new latency, an injected frame, a control call into a
device, bytes on a device's stdin, an extension's op, or a topology change
([topology-and-infra.md](topology-and-infra.md)). It is queued like any other event, under a
key chosen by its `Placement`:

- **Before an event** (`Placement::Before(K)`): every key level carries a *pre* number, 0 for
  every event the simulation queues itself. The n-th operator event anchored before K gets K's
  key with `pre = n` on its first level (`EventKey::pre`). The pre number is the last
  tie-break, ranked `(pre == 0, pre)`, so the operator event sorts after everything that sorts
  before K, before K itself, and after earlier operator events anchored there. When its key
  comes up and the next queued event is not its anchor (K was never queued in this run, or was
  removed again, as a cancelled timer is), it is not applied and its state is
  `OpState::Unreached`.
- **Start of an instant** (`Placement::StartOf(t)`): a `setup` key at `t` with slot
  `2^40 + n`, after every device and scripted link change of the network's setup, so it sorts
  before every event queued while the network runs at `t`.
- **End of an instant** (`Placement::EndOf(t)`): an `operator` key at `t`, which sorts after
  every other origin at that instant.

A timed placement in the past is refused (`Error::Refused`). Events an operator event causes
carry its key as their cause, so they sort after it and stay distinct from its anchor's own
consequences. Existing keys keep their order (their pre number is 0), so placing nothing
changes nothing. `Network::op_states` reports each operator event as `Pending`, `Applied`,
`Unreached` or `Failed` (the device or the topology refused it).

**Frame rules** (`Network::set_frame_rule`: drop, replace or delay one transmission,
`FrameAction`) are not queued at all: they are keyed by the transmission's causal digest and
applied at `wire.transmit` whenever that transmission happens. A rule therefore carries over to
any run that shares the history up to that transmission. A **transmit hook**
(`Network::set_transmit_hook`) sees every transmission on a wired port, with the matching rule
if there is one, and may return a verdict of its own, which applies only when no rule matched.
A hook must be deterministic for a run to replay; a caller that records every verdict that
changed a frame as a frame rule can replay the run without the hook.

A split (multi-site) network refuses operator events: `add_op` returns `Error::Refused` once
the network has a remote device, because the site-sync wire format carries no pre number.
