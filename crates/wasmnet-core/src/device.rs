//! The executor's side of a device: its command inbox and what the host still awaits from it.
//!
//! A runtime backend turns each [`Command`] into an export call on the device (inside the
//! device's live event loop) and reports in-flight calls and live guest tasks through
//! [`Status`]. Both are runtime-agnostic, so the executor and the network never see the runtime.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Waker};

use crate::clock::Nanos;
use crate::ext::ControlCall;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Work for a device, queued by the executor or the network and turned into export calls.
#[derive(Debug)]
pub enum Command {
    Receive {
        port: u32,
        frame: Vec<u8>,
    },
    Poll,
    LinkState {
        port: u32,
        up: bool,
    },
    /// A control call (`counters`), answered into the shared slot. Never schedules a poll.
    Counters(CountersReply),
    /// A control call into one of the device's optional exports, answered into the call's own
    /// slot. Followed by a poll at the same instant when [`ControlCall::may_reschedule`].
    Control(Box<dyn ControlCall>),
    /// Bytes for the device's stdin (an [`crate::Op::Stdin`]): the backend appends them to the
    /// stdin it serves the guest ([`crate::InputQueue`] natively) and wakes a pending read.
    /// Never an export call.
    Stdin(Vec<u8>),
}

/// Where a `counters` control call puts its answer.
pub type CountersReply = Arc<Mutex<Option<Vec<(String, u64)>>>>;

/// What a device cost in a run: reports and regression gates only, never behaviour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceCost {
    /// Wasm fuel consumed (the backend's metering; 0 without one). Deterministic.
    pub fuel: u64,
    /// The most fuel the device consumed in one virtual instant: everything its guest ran at
    /// that instant, over every actor poll, command, timer and task at it, which is what has to
    /// fit in its fuel per instant (`DeviceOptions::fuel_per_instant`). 0 without metering, and
    /// from a backend that reports fuel without its instant ([`CostMeter::add_fuel`]).
    /// Deterministic.
    pub peak_fuel: u64,
    /// The instant of [`peak_fuel`](Self::peak_fuel): the first one, if several instants
    /// consumed as much. 0 while `peak_fuel` is 0.
    pub peak_fuel_at: Nanos,
    /// Commands delivered (`receive`, `poll`, `link-state`, control calls). Deterministic.
    pub calls: u64,
    /// Actor polls. Deterministic.
    pub polls: u64,
    /// Of those, polls with no command waiting (woken by the runtime or a timer, not by work
    /// for the device). Deterministic.
    pub idle_polls: u64,
    /// Wall time inside the actor's polls, when the runtime gave the executor a wall clock.
    /// Not deterministic: reports only.
    pub wall_ns: u64,
    /// The device's linear memory now, in bytes, all its instances together (the netstack and
    /// the apps of a composed node alike), as the backend saw it grow (0 with a backend that
    /// does not measure it, and once the device stopped). Deterministic.
    pub memory: u64,
    /// The most it had at once since it was instantiated. Deterministic.
    pub peak_memory: u64,
}

/// A device's cost, shared by the executor (calls, polls, wall) and the backend (fuel).
#[derive(Clone, Default)]
pub struct CostMeter {
    inner: Arc<Mutex<MeterState>>,
}

#[derive(Default)]
struct MeterState {
    cost: DeviceCost,
    /// The instant fuel was last reported at, and the fuel reported at it so far.
    instant: Option<(Nanos, u64)>,
}

impl CostMeter {
    /// Adds fuel the backend saw consumed, without saying at which instant: it counts in
    /// [`DeviceCost::fuel`] only.
    pub fn add_fuel(&self, fuel: u64) {
        let mut m = lock(&self.inner);
        m.cost.fuel = m.cost.fuel.saturating_add(fuel);
    }

    /// Adds fuel the backend saw consumed at virtual instant `at`, under that instant's budget.
    /// A backend reports an instant's fuel in as many parts as it likes, and may report the
    /// last part at its next look, after time moved on, as long as it names the instant the
    /// fuel was consumed at; instants are reported in order. The parts of one instant add up
    /// in [`DeviceCost::peak_fuel`].
    pub fn add_fuel_at(&self, at: Nanos, fuel: u64) {
        let mut m = lock(&self.inner);
        m.cost.fuel = m.cost.fuel.saturating_add(fuel);
        let sum = match m.instant {
            Some((t, sum)) if t == at => sum.saturating_add(fuel),
            _ => fuel,
        };
        m.instant = Some((at, sum));
        if sum > m.cost.peak_fuel {
            m.cost.peak_fuel = sum;
            m.cost.peak_fuel_at = at;
        }
    }

    /// The device's linear memory is now `bytes` (the backend measures it as it grows, and
    /// reports 0 when the instance is dropped).
    pub fn set_memory(&self, bytes: u64) {
        let mut m = lock(&self.inner);
        m.cost.memory = bytes;
        m.cost.peak_memory = m.cost.peak_memory.max(bytes);
    }

    pub(crate) fn add_call(&self) {
        lock(&self.inner).cost.calls += 1;
    }

    pub(crate) fn add_poll(&self, wall_ns: u64, idle: bool) {
        let c = &mut lock(&self.inner).cost;
        c.polls += 1;
        c.idle_polls += u64::from(idle);
        c.wall_ns += wall_ns;
    }

    /// The cost so far.
    pub fn get(&self) -> DeviceCost {
        lock(&self.inner).cost
    }
}

/// A device's pending commands, shared between the executor and the actor.
#[derive(Clone, Default)]
pub struct Inbox {
    inner: Arc<Mutex<InboxState>>,
    cost: CostMeter,
}

#[derive(Default)]
struct InboxState {
    commands: VecDeque<Command>,
    waker: Option<Waker>,
}

impl Inbox {
    /// Queues `command` and wakes the actor.
    pub fn push(&self, command: Command) {
        let waker = {
            let mut s = lock(&self.inner);
            s.commands.push_back(command);
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Takes the next command, or registers `cx`'s waker for the next push.
    pub fn poll_pop(&self, cx: &mut Context<'_>) -> Option<Command> {
        let mut s = lock(&self.inner);
        let command = s.commands.pop_front();
        if command.is_none() {
            s.waker = Some(cx.waker().clone());
        } else {
            self.cost.add_call();
        }
        command
    }

    /// No command is waiting.
    pub fn is_empty(&self) -> bool {
        lock(&self.inner).commands.is_empty()
    }

    /// The device's cost meter (the backend adds its fuel here).
    pub fn cost(&self) -> &CostMeter {
        &self.cost
    }
}

/// What the host is still waiting for in a device: in-flight export calls and live guest tasks.
#[derive(Clone, Default)]
pub struct Status {
    inner: Arc<Mutex<StatusState>>,
}

#[derive(Default)]
struct StatusState {
    next_call: u64,
    /// In-flight calls: name and whether it is a daemon call.
    outstanding: BTreeMap<u64, (String, bool)>,
    guest_tasks_alive: bool,
    /// The message of a fault a host import raised, for the crash record ([`Status::set_fault`]).
    fault: Option<String>,
}

/// What a device is still busy with when the network looks at it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Snapshot {
    /// In-flight calls the host waits for (not daemons), in start order.
    pub outstanding: Vec<String>,
    /// In-flight daemon calls (apps' `run`), in start order.
    pub daemons: Vec<String>,
    /// Guest tasks are alive in the store.
    pub alive: bool,
}

impl Status {
    /// Records the start of a call. A `daemon` call may legitimately never finish.
    pub fn begin(&self, what: String, daemon: bool) -> u64 {
        let mut s = lock(&self.inner);
        let id = s.next_call;
        s.next_call += 1;
        s.outstanding.insert(id, (what, daemon));
        id
    }

    pub fn end(&self, id: u64) {
        lock(&self.inner).outstanding.remove(&id);
    }

    /// A host import is faulting the device with `message` (it returns a trap right after). The
    /// crash is then journalled with this message rather than the runtime's own trap text, so
    /// it reads the same on every backend. A later fault replaces an earlier one.
    pub fn set_fault(&self, message: impl Into<String>) {
        lock(&self.inner).fault = Some(message.into());
    }

    /// The message [`set_fault`](Self::set_fault) left, taken.
    pub(crate) fn take_fault(&self) -> Option<String> {
        lock(&self.inner).fault.take()
    }

    pub fn set_guest_tasks_alive(&self, alive: bool) {
        lock(&self.inner).guest_tasks_alive = alive;
    }

    /// Nothing in flight and no live guest tasks: nothing in the store can become ready, so
    /// there is no wake to miss.
    pub fn is_quiet(&self) -> bool {
        let s = lock(&self.inner);
        s.outstanding.is_empty() && !s.guest_tasks_alive
    }

    pub fn snapshot(&self) -> Snapshot {
        let s = lock(&self.inner);
        let (daemons, outstanding): (Vec<_>, Vec<_>) =
            s.outstanding.values().partition(|(_, daemon)| *daemon);
        Snapshot {
            outstanding: outstanding.into_iter().map(|(w, _)| w.clone()).collect(),
            daemons: daemons.into_iter().map(|(w, _)| w.clone()).collect(),
            alive: s.guest_tasks_alive,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_peak_adds_up_one_instant_and_keeps_the_first_of_equals() {
        let m = CostMeter::default();
        assert_eq!((m.get().peak_fuel, m.get().peak_fuel_at), (0, 0));
        // Instant 10 in three parts (as a backend reports at each look), then 20 and 30.
        m.add_fuel_at(10, 40);
        m.add_fuel_at(10, 0);
        m.add_fuel_at(10, 60);
        m.add_fuel_at(20, 99);
        m.add_fuel_at(30, 100);
        let c = m.get();
        assert_eq!(c.fuel, 299);
        assert_eq!(
            (c.peak_fuel, c.peak_fuel_at),
            (100, 10),
            "the first of equals"
        );
        m.add_fuel_at(30, 1);
        assert_eq!((m.get().peak_fuel, m.get().peak_fuel_at), (101, 30));
        // Fuel without an instant counts in the total only.
        m.add_fuel(1_000);
        assert_eq!((m.get().fuel, m.get().peak_fuel), (1_300, 101));
    }
}
