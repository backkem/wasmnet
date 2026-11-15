//! The executor's side of a device: its command inbox and what the host still awaits from it.
//!
//! A runtime backend turns each [`Command`] into an export call on the device (inside the
//! device's live event loop) and reports in-flight calls and live guest tasks through
//! [`Status`]. Both are runtime-agnostic, so the executor and the network never see the runtime.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Waker};

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
pub struct DeviceCost {
    /// Wasm fuel consumed (the backend's metering; 0 without one). Deterministic.
    pub fuel: u64,
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
}

/// A device's cost, shared by the executor (calls, polls, wall) and the backend (fuel).
#[derive(Clone, Default)]
pub struct CostMeter {
    inner: Arc<Mutex<DeviceCost>>,
}

impl CostMeter {
    /// Adds fuel the backend saw consumed.
    pub fn add_fuel(&self, fuel: u64) {
        lock(&self.inner).fuel += fuel;
    }

    pub(crate) fn add_call(&self) {
        lock(&self.inner).calls += 1;
    }

    pub(crate) fn add_poll(&self, wall_ns: u64, idle: bool) {
        let mut c = lock(&self.inner);
        c.polls += 1;
        c.idle_polls += u64::from(idle);
        c.wall_ns += wall_ns;
    }

    /// The cost so far.
    pub fn get(&self) -> DeviceCost {
        *lock(&self.inner)
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
}

/// What a device is still busy with when the network looks at it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
