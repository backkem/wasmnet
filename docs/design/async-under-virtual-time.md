# Async components under virtual time

wasmnet runs every device in its own wasmtime store and advances one virtual clock for all of
them. The guarantee: with the same components, topology and seed, every device gets the same
calls, in the same order, at the same virtual instants, on every run and every machine. That
holds for stepped devices (a switch, a router) and for async ones (a node: the netstack and its
apps composed into one component). This note explains the executor behind the guarantee, how the
`wasmnet:link` contract ([wit/link/link.wit](../../wit/link/link.wit)) is shaped for it, and the
rules an async device follows to keep it.

## The executor

Each device is an **actor**: one future that owns the device's store and keeps **one
`run_concurrent` alive for the device's whole life** (`DeviceActor` in
[crates/wasmnet-host/src/actor.rs](../../crates/wasmnet-host/src/actor.rs)). Every host call
into the device (`start`, `receive`, `link-state`, `poll`, an app's `run`, a control call such
as `counters`) is started as a concurrent call from inside that event loop, never with
`call_async`: `call_async` drives the store only until its own call returns, so background
tasks (timers, a netstack's driver) would run late. In-flight calls are polled in start order.

The executor (`Executor` in [crates/wasmnet-core/src/exec.rs](../../crates/wasmnet-core/src/exec.rs))
alternates two phases:

```text
  ┌─► rounds: poll every woken actor, in device order, until a round polls nobody
  │   pop exactly one event (key order), move `now` to its time, dispatch it:
  │     wake a timer, or put a frame, a poll or a link change into a device's inbox
  └───────────────────────────────────────────────────────────────────────────────┘
```

Guest timers (virtual `wasi:clocks` waits, p2 and p3), frame deliveries, stepped devices' poll
deadlines and scripted link changes share that one queue (`VirtualClock`), ordered by virtual
time and then by a causal key ([event-order.md](event-order.md)). Same-instant events are
therefore processed one at a time, each to quiescence. Nothing in the simulation path reads a
real clock, starts a thread or uses an async runtime's timer.

A run ends in one of three ways:

- **Quiescent** (`Outcome::Quiescent`): nothing is queued, every store is idle and no host call
  is outstanding. `parked` names devices whose guest tasks are still alive (a netstack driver
  waiting for frames); `daemons` names apps' `run` calls that never returned (servers). Neither
  is an error.
- **At a deadline** (`Outcome::Deadline`, from `run_until`). Resumable: stopping at a deadline
  and running on gives the same result as one run.
- **With an error**: `Error::Deadlock` (nothing queued, every store idle, yet a host call is
  still outstanding, such as a `start` that never returns), `Error::Trap` (a device trapped,
  running out of fuel included), `Error::Runaway` (one device polled more than
  `Guard::max_polls_per_instant` times in one instant) or `Error::MissedWake` (with
  `Guard::paranoid`, an extra poll of every busy actor found work after the executor had seen
  them all idle). A network that failed refuses to run again (`Error::Halted`).

The guards in `Guard` are deterministic. Fuel is per virtual instant: a store's fuel is set to
its budget the first time its actor runs at a new instant, so a compute loop traps with
`OutOfFuel` at the same instant on every run. Each device reports the most it used in one
instant (`DeviceCost::peak_fuel`), which is what to size its budget by
([runtime-and-extensions.md](runtime-and-extensions.md#costs)). The poll cap counts polls, not
time. Neither depends on the wall clock.

A **control call** (`Network::counters`, `Network::control`) is queued into a live device's
inbox between runs. The executor then settles the current instant (rounds only, no event is
popped), so virtual time does not move.

A **paused** actor (`Op::PauseDevice`, [topology-and-infra.md](topology-and-infra.md#pause-and-resume))
keeps its store and is skipped by the rounds, its wake kept for later. When one of its timers
or its poll deadline is popped, the executor holds the event, under the key it was popped with,
instead of waking the actor (a timer's key names the device whose poll set it); a frame for it
is dropped at its port. At the resume the held events are queued again under those keys: being
earlier than the current instant, they pop next, one at a time and in their order, before
anything else still queued, while `now` stays where it is. So a guest's overdue timers come due
at the resume instant, each processed to quiescence. A paused device is never a deadlock: its
outstanding calls wait for its resume.

## Push in, push out

- `wire.transmit(port, frame)` is a **sync import that only enqueues**. The peer gets the frame
  at `now + latency` as its own, later `receive` call, never re-entrantly. A frame on an unwired
  or down port, or with a payload over the link MTU, is dropped and counted: a link drops
  instead of applying backpressure, like a NIC ring.
- `device.receive(now, port, frame)` is a **sync export**. In an async device it only enqueues
  the frame and wakes a task; it must not block.
- `device.poll(now) -> option<instant>` is for **stepped devices**: it advances their timers
  and returns the next deadline. Async devices keep time through virtual `wasi:clocks` and
  answer `none`.
- Async devices also export `lifecycle.start: async func()`. It spawns their long-lived tasks
  (`wit_bindgen::spawn_local`) and returns. A `start` that never returns is a deadlock, which
  keeps the set of outstanding host calls meaningful.

The call order for one device: `ports()` once, when the device is created and before anything
is wired; then `start()` for an async device; then the queued commands in order, which for a
device wired before the run are `link-state(up)` for each wired port and then `poll(now)`.
Commands that arrive while `start` is running wait until it returns. After every `receive` or
`link-state` the actor asks for a `poll` at the same instant (`VirtualClock::poll_by`); after a
`poll` it replaces the device's deadline with the answer (`VirtualClock::set_poll`).

There is no `stream<frame>` on the link: each frame is one sync call in each direction. A guest
whose task is woken from another export call (an async device woken by `receive`) needs
wit-bindgen's `async-spawn` and `inter-task-wakeup` features, as
[components/reflector/Cargo.toml](../../components/reflector/Cargo.toml) shows.

## Rules for an async device

Several component instances share one store in a composed node. While one of them sits in a
blocking builtin (dropping a pending wit-bindgen future is a blocking `subtask.cancel`), wasmtime
may run a sibling instance, which can call the device's sync exports. A wake that finds no
registered waker is lost until some unrelated timer fires: the run stays deterministic, but
it is wrong. Five rules prevent that:

1. **Wakes are level-triggered.** A wake sets a flag that the task clears at the start of a
   pass and checks again before it parks.
2. **Register the waker at the start of every poll**, never only when parking, and never take
   it out on wake.
3. **Hold no borrow across an import call or a future drop.** Collect frames and log records
   first and hand them to the host after the borrow ends.
4. **Never cancel timers in the hot path.** Arm a new `wait-until` only when no armed one fires
   at or before the new deadline; a stale timer only costs one spurious pass.
5. **Diagnostics go through the sync `wasmnet:link/log` import**, never `eprintln!`, whose
   write is a yield point in an async component.

[netstack.md](netstack.md) shows how the netstack applies them, and how it counts wakes that
were served late or not at all, so tests can assert that none were lost.
