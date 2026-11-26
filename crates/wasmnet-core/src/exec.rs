//! Single-threaded, deterministic executors driven by virtual time
//! (`docs/design/async-under-virtual-time.md`).
//!
//! * [`block_on`] drives **one** future (a `wasi:cli/run` command): poll it, and when it is idle,
//!   fire the next timer.
//! * [`Executor`] drives **many** device actors, one per store. It runs in rounds: phase 1 polls
//!   every woken actor, in device-number order, until a full round wakes nobody. Only then does phase 2
//!   pop **exactly one** event, advance virtual time to it and dispatch it (wake a timer, or hand
//!   a frame or poll to a device's inbox). Same-instant events are therefore each processed to
//!   quiescence, in key order (`docs/design/event-order.md`).
//!
//! There is no tokio runtime, no real timer and no thread in the simulation path.

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use crate::clock::{Event, EventKey, Nanos, Origin, VirtualClock};
use crate::device::{Command, Inbox, Status};
use crate::link::Panel;
use crate::{Error, Fault, Guard, Outcome};

/// A waker that only records that it fired.
struct WokenFlag(AtomicBool);

impl WokenFlag {
    fn new(woken: bool) -> Arc<Self> {
        Arc::new(Self(AtomicBool::new(woken)))
    }

    fn take(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }

    fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Wake for WokenFlag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// [`block_on`]'s future was still pending with no event left to advance to: it can never
/// finish (a deadlock).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("stalled at t={at}ns: the future is pending and no timer is left to fire")]
#[non_exhaustive]
pub struct Stalled {
    /// The virtual time it stalled at.
    pub at: Nanos,
}

/// Runs `fut` to completion, firing the next timer whenever the future is idle.
///
/// Fails with [`Stalled`] if the future is pending and no event is left to advance to (a
/// deadlock). Only timers are expected here; any other event kind is dropped.
pub fn block_on<F: Future>(clock: &VirtualClock, fut: F) -> Result<F::Output, Stalled> {
    let flag = WokenFlag::new(false);
    let waker = Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        flag.take();
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return Ok(out);
        }
        // Woken during the poll (e.g. a yield): there is more work at the current instant.
        if flag.is_set() {
            continue;
        }
        match clock.pop(None) {
            Some((_, Event::Timer(w))) => w.wake(),
            Some(_) => {}
            None => return Err(Stalled { at: clock.now() }),
        }
    }
}

/// The future that owns one device's store for the device's whole life (see
/// [`crate::Runtime::instantiate`]).
pub type ActorFuture = Pin<Box<dyn Future<Output = Result<(), Fault>>>>;

struct Slot {
    name: String,
    /// Its number in event keys and record tags (`docs/design/event-order.md`): its index for a
    /// device the network was built with, its creator's next number for a device created while
    /// the network runs.
    number: u32,
    /// `None` once the actor finished (it never should) or failed.
    future: Option<ActorFuture>,
    flag: Arc<WokenFlag>,
    waker: Waker,
    inbox: Inbox,
    status: Status,
    polls_this_instant: u32,
    /// Stopped or removed by an operator event: never polled, never counted as parked, a daemon
    /// or outstanding.
    stopped: bool,
    /// A trap stops this device instead of failing the network (a device an in-world controller
    /// created, or one whose options say so): the network is told ([`Flow::Crashed`]).
    contain: bool,
    /// Paused by an operator event: its store is kept but never polled; its timers and poll
    /// deadline are held in `held` as they come due, frames for it are dropped at its ports.
    paused: bool,
    /// Its events that came due while it was paused, with the keys they were popped with.
    held: Vec<(EventKey, Event)>,
    /// Frames that reached its ports while it was paused (dropped there).
    paused_drops: u64,
}

/// How a run returned to the network: done, stopped, or at an operator event that only the
/// network can apply (dynamic topology, `docs/design/topology-and-infra.md`). The network
/// applies it in the event's own processing context and calls the run again, which goes on
/// exactly where it was.
#[derive(Debug)]
pub(crate) enum Flow<T> {
    Done(T),
    /// Operator event `op` (slot index) is network op `network` (the network's table).
    Network {
        op: usize,
        network: usize,
    },
    /// Derived request `n` of an in-world controller fired (`wasmnet:infra`): the network
    /// applies it.
    Derived(usize),
    /// Device `.0` trapped and was contained (`Slot::contain`): the network stops it as crashed,
    /// with the trap's message `.1`.
    Crashed(usize, String),
}

#[cfg(test)]
impl<T> Flow<T> {
    /// The result of a run that met no network op (the executor's own tests).
    fn done(self) -> T {
        match self {
            Flow::Done(t) => t,
            Flow::Network { .. } | Flow::Derived(_) | Flow::Crashed(..) => {
                panic!("a network op in an executor test")
            }
        }
    }
}

/// Counters for reports and benchmarks. They do not affect behaviour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Actor polls (phase 1), excluding paranoid re-polls.
    pub actor_polls: u64,
    /// Events popped from the queue (phase 2), operator events excluded: the ordinal `e` of
    /// the current event boundary.
    pub events: u64,
    /// Operator events popped (applied or unreached).
    pub operator_events: u64,
}

/// An event boundary (`docs/design/event-order.md`): every store is idle and the next event
/// has not fired. The only place a world stops, a control call runs or an operator event is
/// placed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Boundary {
    /// Events popped so far (operator events excluded): the boundary's ordinal `e`.
    pub events: u64,
    pub now: Nanos,
    /// The key of the next queued event, if any.
    pub next: Option<EventKey>,
}

/// How a stoppable run returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// The stop condition held at this boundary. Resumable.
    Stopped(Boundary),
    /// The run ended as an ordinary run would have.
    Done(Outcome),
}

/// A change to the world that the sim core applies itself, as an operator event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreOp {
    /// Carrier change of a whole link (like a scripted link change).
    LinkState { link: usize, up: bool },
    /// A link's one-way latency, for frames transmitted from then on.
    Latency { link: usize, ns: Nanos },
    /// A link's impairments, for frames transmitted from then on (one direction or both).
    Impair {
        link: usize,
        from: Option<usize>,
        impairments: crate::link::Impairments,
    },
    /// A frame transmitted on `(device, port)` as if the device had sent it.
    Inject {
        device: usize,
        port: u32,
        bytes: Vec<u8>,
    },
    /// A control call into one of a device's optional exports (an extension's write or probe),
    /// at this position.
    Control {
        device: usize,
        call: crate::ext::Control,
    },
    /// Bytes typed into a device's stdin, served by its backend.
    Stdin { device: usize, bytes: Vec<u8> },
    /// An op the network applies itself (dynamic topology and name-resolved writes): the index
    /// into the network's table.
    Network(usize),
}

/// What became of an operator event.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpState {
    /// Not popped yet.
    Pending,
    /// Applied at this instant, at the boundary with this ordinal.
    Applied { at: Nanos, events: u64 },
    /// Its anchor event never occurred in this branch (reported, never applied somewhere
    /// else).
    Unreached { at: Nanos },
    /// Applied, but the device refused it (a control call it answered with an error).
    Failed {
        at: Nanos,
        events: u64,
        message: String,
    },
}

struct OpSlot {
    op: CoreOp,
    /// For an op anchored before an event: that event's key.
    anchor: Option<EventKey>,
    state: OpState,
    /// A control call's answer slot (the device answers in the op's own rounds).
    reply: Option<Arc<dyn crate::ext::ControlAnswer>>,
}

/// The multi-actor executor behind [`crate::Network`].
pub(crate) struct Executor {
    clock: VirtualClock,
    panel: Panel,
    guard: Guard,
    actors: Vec<Slot>,
    /// Actor indices by number: the order phase-1 rounds poll them in.
    order: Vec<usize>,
    /// The instant whose per-actor poll counts are being tallied.
    instant: Nanos,
    stats: Stats,
    /// The first round (before any event fired) has run.
    initialised: bool,
    /// Phase-1 rounds in the current processing context.
    round: u32,
    /// Operator events, by index.
    ops: Vec<OpSlot>,
    /// A stoppable run returned at a boundary and nothing has touched the world since: resuming
    /// pops the next event directly, exactly as an uninterrupted run would.
    at_boundary: bool,
    /// A network op just fired; the run returns it to the network before the event's rounds.
    network_pending: Option<(usize, usize)>,
    /// A derived request just fired; the run returns it to the network before the event's rounds.
    derived_pending: Option<usize>,
    /// Contained traps not yet handed to the network, in the order they happened.
    crashed: std::collections::VecDeque<(usize, String)>,
    /// A wall clock (ns) for per-device cost reports; `None`: no wall times.
    wall: Option<fn() -> u64>,
    /// How many actors are paused.
    paused: usize,
}

impl Executor {
    pub(crate) fn new(clock: VirtualClock, panel: Panel, guard: Guard) -> Self {
        Self {
            instant: clock.now(),
            clock,
            panel,
            guard,
            actors: Vec::new(),
            order: Vec::new(),
            stats: Stats::default(),
            initialised: false,
            round: 0,
            ops: Vec::new(),
            at_boundary: false,
            network_pending: None,
            derived_pending: None,
            crashed: std::collections::VecDeque::new(),
            wall: None,
            paused: 0,
        }
    }

    /// Gives the executor a wall clock (ns) for per-device cost reports.
    pub(crate) fn set_wall_clock(&mut self, wall: fn() -> u64) {
        self.wall = Some(wall);
    }

    /// Every device's cost so far, in device order (stopped devices included).
    pub(crate) fn costs(&self) -> Vec<(String, crate::DeviceCost)> {
        self.actors
            .iter()
            .map(|s| (s.name.clone(), s.inbox.cost().get()))
            .collect()
    }

    pub(crate) fn stats(&self) -> Stats {
        self.stats
    }

    /// Something outside a run touched the world (a command, a control call, a new device):
    /// the next run must settle the current instant before popping.
    pub(crate) fn touched(&mut self) {
        self.at_boundary = false;
    }

    /// Registers operator event `op` (queued separately by the caller under its key) and
    /// returns its index.
    pub(crate) fn add_op(&mut self, op: CoreOp, anchor: Option<EventKey>) -> usize {
        self.ops.push(OpSlot {
            op,
            anchor,
            state: OpState::Pending,
            reply: None,
        });
        self.ops.len() - 1
    }

    /// The states of every operator event, by index.
    pub(crate) fn op_states(&self) -> Vec<OpState> {
        self.ops
            .iter()
            .map(|o| {
                let refused = o.reply.as_ref().and_then(|r| r.refusal());
                match (&o.state, refused) {
                    (OpState::Applied { at, events }, Some(message)) => OpState::Failed {
                        at: *at,
                        events: *events,
                        message,
                    },
                    (s, _) => s.clone(),
                }
            })
            .collect()
    }

    /// How many operator events are anchored before `anchor` so far.
    pub(crate) fn ops_before(&self, anchor: &EventKey) -> u32 {
        self.ops
            .iter()
            .filter(|o| o.anchor.as_ref() == Some(anchor))
            .count() as u32
    }

    /// Runs like [`run`](Self::run) with no deadline, but checks `stop` at every event boundary
    /// (the current one included) and returns there when it holds. Resuming after a stop pops
    /// the next event directly, so a run that stopped any number of times is identical to one
    /// that never stopped.
    pub(crate) fn run_stoppable(
        &mut self,
        until: Option<Nanos>,
        stop: &mut dyn FnMut(&Boundary) -> bool,
    ) -> Result<Flow<Step>, Error> {
        loop {
            if let Some((op, network)) = self.network_pending.take() {
                return Ok(Flow::Network { op, network });
            }
            if let Some(n) = self.derived_pending.take() {
                return Ok(Flow::Derived(n));
            }
            if !self.at_boundary {
                self.ensure_initialised();
                self.run_round()?;
                // A contained trap: the network stops the device, then this boundary settles again.
                if let Some((i, message)) = self.crashed.pop_front() {
                    return Ok(Flow::Crashed(i, message));
                }
                if self.guard.paranoid {
                    self.paranoid_round()?;
                }
                self.at_boundary = true;
            }
            let b = Boundary {
                events: self.stats.events,
                now: self.clock.now(),
                next: self.clock.next_key(),
            };
            if stop(&b) {
                return Ok(Flow::Done(Step::Stopped(b)));
            }
            match self.clock.pop(until) {
                Some((key, event)) => {
                    self.at_boundary = false;
                    self.dispatch(key, event);
                }
                None => return self.finish(until, true).map(|o| Flow::Done(Step::Done(o))),
            }
        }
    }

    /// Something outside the executor woke an actor since the last run (a browser's JS
    /// between two runs): the next run starts with a round even at the same
    /// boundary, so that wake is served at this instant, not lost.
    pub(crate) fn woken_outside(&mut self) {
        self.at_boundary = false;
    }

    /// Adds an actor with `number`. It starts out woken, so its first poll happens in the next
    /// round.
    pub(crate) fn add(
        &mut self,
        name: &str,
        number: u32,
        inbox: Inbox,
        status: Status,
        future: ActorFuture,
    ) {
        self.at_boundary = false;
        let flag = WokenFlag::new(true);
        self.push(Slot {
            name: name.to_owned(),
            number,
            future: Some(future),
            waker: Waker::from(flag.clone()),
            flag,
            inbox,
            status,
            polls_this_instant: 0,
            stopped: false,
            contain: false,
            paused: false,
            held: Vec::new(),
            paused_drops: 0,
        });
    }

    /// Adds a placeholder for a device that runs on another site: it keeps device indices the
    /// same on every site, and it is never polled.
    pub(crate) fn add_remote(&mut self, name: &str, number: u32, inbox: Inbox, status: Status) {
        let flag = WokenFlag::new(false);
        self.push(Slot {
            name: name.to_owned(),
            number,
            future: None,
            waker: Waker::from(flag.clone()),
            flag,
            inbox,
            status,
            polls_this_instant: 0,
            stopped: false,
            contain: false,
            paused: false,
            held: Vec::new(),
            paused_drops: 0,
        });
    }

    /// Appends `slot`, keeping the poll order sorted by number.
    fn push(&mut self, slot: Slot) {
        let i = self.actors.len();
        let at = self
            .order
            .partition_point(|&j| self.actors[j].number <= slot.number);
        self.actors.push(slot);
        self.order.insert(at, i);
    }

    /// Enters the first round's context (`init`) if no round has run yet.
    fn ensure_initialised(&mut self) {
        if !self.initialised {
            self.initialised = true;
            self.clock.set_ctx(Origin::Init, None, 0);
            self.round = 0;
        }
    }

    /// Runs until quiescence, an error, or until the next event lies after `until`.
    pub(crate) fn run(&mut self, until: Option<Nanos>) -> Result<Flow<Outcome>, Error> {
        self.run_inner(until, true)
    }

    /// Runs every event *before* `horizon` (all of them for `None`) without moving the clock to
    /// the horizon: one site-sync window. While events remain it returns
    /// `Deadline { at: now, .. }`.
    pub(crate) fn run_before(&mut self, horizon: Option<Nanos>) -> Result<Flow<Outcome>, Error> {
        match horizon {
            Some(0) => {
                self.ensure_initialised();
                self.run_round()?;
                self.finish(Some(0), false).map(Flow::Done)
            }
            h => self.run_inner(h.map(|h| h - 1), false),
        }
    }

    fn run_inner(&mut self, until: Option<Nanos>, advance: bool) -> Result<Flow<Outcome>, Error> {
        self.at_boundary = false;
        loop {
            if let Some((op, network)) = self.network_pending.take() {
                return Ok(Flow::Network { op, network });
            }
            if let Some(n) = self.derived_pending.take() {
                return Ok(Flow::Derived(n));
            }
            self.ensure_initialised();
            self.run_round()?;
            // A contained trap: the network stops the device, then this instant settles again.
            if let Some((i, message)) = self.crashed.pop_front() {
                return Ok(Flow::Crashed(i, message));
            }
            if self.guard.paranoid {
                self.paranoid_round()?;
            }
            match self.clock.pop(until) {
                Some((key, event)) => self.dispatch(key, event),
                None => return self.finish(until, advance).map(Flow::Done),
            }
        }
    }

    // ---- dynamic topology: what the network asks of the executor ------------------------------

    /// Stops actor `i`: its store is dropped, and it is never polled or counted again.
    pub(crate) fn stop_actor(&mut self, i: usize) {
        let slot = &mut self.actors[i];
        slot.future = None;
        slot.stopped = true;
        slot.flag.take();
        self.unpause(i);
    }

    /// Actor `i` is no longer paused: what it held is dropped (its store is gone).
    fn unpause(&mut self, i: usize) {
        let slot = &mut self.actors[i];
        if std::mem::take(&mut slot.paused) {
            self.paused -= 1;
        }
        slot.held.clear();
        slot.paused_drops = 0;
    }

    /// Pauses actor `i`: its store is kept, it is not polled until
    /// [`resume_actor`](Self::resume_actor), and what comes due for it meanwhile is held.
    pub(crate) fn pause_actor(&mut self, i: usize) {
        if !std::mem::replace(&mut self.actors[i].paused, true) {
            self.paused += 1;
        }
    }

    /// Resumes actor `i`: its held timers and poll deadline are queued again under the keys
    /// they came due with (so they fire next, in their order, at the current instant), and it
    /// is polled again. Returns how many were held and how many frames were dropped at its
    /// ports meanwhile.
    pub(crate) fn resume_actor(&mut self, i: usize) -> (usize, u64) {
        self.at_boundary = false;
        let slot = &mut self.actors[i];
        if std::mem::take(&mut slot.paused) {
            self.paused -= 1;
        }
        let held = std::mem::take(&mut slot.held);
        let drops = std::mem::take(&mut slot.paused_drops);
        let n = held.len();
        for (key, event) in held {
            self.clock.requeue(key, event);
        }
        (n, drops)
    }

    /// The actor whose number is `number`, if any.
    fn by_number(&self, number: u32) -> Option<usize> {
        let at = self
            .order
            .partition_point(|&j| self.actors[j].number < number);
        self.order
            .get(at)
            .copied()
            .filter(|&j| self.actors[j].number == number)
    }

    /// Gives slot `i` a new actor (a stopped device started again, with the same index).
    pub(crate) fn restart_actor(
        &mut self,
        i: usize,
        inbox: Inbox,
        status: Status,
        future: ActorFuture,
    ) {
        self.at_boundary = false;
        let flag = WokenFlag::new(true);
        let slot = &mut self.actors[i];
        slot.future = Some(future);
        slot.waker = Waker::from(flag.clone());
        slot.flag = flag;
        slot.inbox = inbox;
        slot.status = status;
        slot.stopped = false;
    }

    /// Whether a trap of actor `i` stops only it instead of failing the network.
    pub(crate) fn set_contain(&mut self, i: usize, on: bool) {
        self.actors[i].contain = on;
    }

    /// The one rule for a fault of actor `i`, whatever raised it (its guest, its fuel or
    /// memory, a host import, an operator event): a contained actor stops alone (`Ok(true)`:
    /// the caller tells the network), any other fails the network with [`Error::Trap`].
    pub(crate) fn fault(&mut self, i: usize, error: Fault) -> Result<bool, Error> {
        let slot = &mut self.actors[i];
        slot.future = None;
        if slot.contain {
            // A crash of this device alone: never polled again.
            slot.stopped = true;
            slot.flag.take();
            self.unpause(i);
            return Ok(true);
        }
        Err(Error::Trap {
            device: slot.name.clone(),
            at: self.clock.now(),
            detail: error.detail,
            message: error.message,
        })
    }

    /// Contained traps not yet handed to the network (one from a control call's settle).
    pub(crate) fn take_crashed(&mut self) -> Vec<(usize, String)> {
        self.crashed.drain(..).collect()
    }

    /// Marks operator event `i` as refused (the device or the topology said no).
    pub(crate) fn fail_op(&mut self, i: usize, message: String) {
        if let OpState::Applied { at, events } = self.ops[i].state {
            self.ops[i].state = OpState::Failed {
                at,
                events,
                message,
            };
        }
    }

    /// Leaves operator event `i` to another site of a split network: pending here, as an op at
    /// another site's device that was never queued.
    pub(crate) fn leave_op(&mut self, i: usize) {
        self.ops[i].state = OpState::Pending;
    }

    /// Gives operator event `i` a reply slot (a name-resolved control call, answered in its
    /// rounds).
    pub(crate) fn set_op_reply(&mut self, i: usize, reply: Arc<dyn crate::ext::ControlAnswer>) {
        self.ops[i].reply = Some(reply);
    }

    /// Runs the current instant to idle without popping any event: used for control calls
    /// (`counters`) queued between runs. Virtual time does not move.
    pub(crate) fn settle(&mut self, slot: u64) -> Result<(), Error> {
        self.at_boundary = false;
        self.ensure_initialised();
        self.clock.set_ctx(Origin::Control, None, slot);
        self.round = 0;
        self.run_round()?;
        if self.guard.paranoid {
            self.paranoid_round()?;
        }
        Ok(())
    }

    /// Phase 1: polls woken actors in number order until a full round polls nobody.
    fn run_round(&mut self) -> Result<(), Error> {
        loop {
            let mut polled_any = false;
            self.round += 1;
            for k in 0..self.order.len() {
                let i = self.order[k];
                // A paused actor keeps its wake for when it resumes.
                if self.actors[i].stopped || self.actors[i].paused || !self.actors[i].flag.take() {
                    continue;
                }
                polled_any = true;
                self.clock.set_actor(self.round, self.actors[i].number);
                self.stats.actor_polls += 1;
                let slot = &mut self.actors[i];
                slot.polls_this_instant += 1;
                if slot.polls_this_instant > self.guard.max_polls_per_instant {
                    return Err(Error::Runaway {
                        device: slot.name.clone(),
                        at: self.clock.now(),
                        polls: self.guard.max_polls_per_instant,
                    });
                }
                self.poll_actor(i)?;
            }
            if !polled_any {
                return Ok(());
            }
        }
    }

    /// The debug "paranoid round": once everyone looks idle, poll every live actor
    /// once more. If that wakes anything or queues anything, a wake was missed (a wasmtime or
    /// actor bug that would otherwise show up as early quiescence or a false deadlock).
    fn paranoid_round(&mut self) -> Result<(), Error> {
        let queued = self.clock.pending_events();
        for k in 0..self.order.len() {
            let i = self.order[k];
            // A quiet actor (no command, nothing in flight, no live guest task) has no wake to
            // miss: polling it would only cost time (most of a stepped device's polls).
            let slot = &self.actors[i];
            if slot.stopped || slot.paused || (slot.inbox.is_empty() && slot.status.is_quiet()) {
                continue;
            }
            self.poll_actor(i)?;
            if self.actors[i].flag.is_set() || self.clock.pending_events() != queued {
                return Err(Error::MissedWake {
                    device: self.actors[i].name.clone(),
                    at: self.clock.now(),
                });
            }
        }
        Ok(())
    }

    fn poll_actor(&mut self, i: usize) -> Result<(), Error> {
        let slot = &mut self.actors[i];
        let Some(future) = slot.future.as_mut() else {
            return Ok(());
        };
        let mut cx = Context::from_waker(&slot.waker);
        let idle = slot.inbox.is_empty();
        let started = self.wall.map(|w| w());
        let polled = future.as_mut().poll(&mut cx);
        let wall_ns = match (self.wall, started) {
            (Some(w), Some(s)) => w().saturating_sub(s),
            _ => 0,
        };
        slot.inbox.cost().add_poll(wall_ns, idle);
        let mut error = match polled {
            Poll::Pending => return Ok(()),
            Poll::Ready(Ok(())) => Fault::new("device actor exited"),
            Poll::Ready(Err(e)) => e,
        };
        // A host import that faulted the device said why, in words every backend shares.
        if let Some(message) = self.actors[i].status.take_fault() {
            error.message = message;
        }
        let message = error.message.clone();
        if self.fault(i, error)? {
            // The network is told: it stops the device as crashed.
            self.crashed.push_back((i, message));
        }
        Ok(())
    }

    /// Phase 2: one event, at its instant.
    fn dispatch(&mut self, key: EventKey, event: Event) {
        let at = key.at();
        // Records made while dispatching (the inbound pcap tap, a link transition) sort before
        // the device polls that follow (round 0).
        let operator = matches!(event, Event::Operator(_) | Event::Derived(_));
        // Only while a device is paused can a timer or poll deadline be held (under its key).
        let key_kept = (self.paused > 0 && matches!(event, Event::Timer(_) | Event::Poll(_)))
            .then(|| key.clone());
        self.clock.set_ctx(Origin::Popped, Some(key), 0);
        self.round = 0;
        if operator {
            self.stats.operator_events += 1;
        } else {
            self.stats.events += 1;
        }
        if at != self.instant {
            self.instant = at;
            for slot in &mut self.actors {
                slot.polls_this_instant = 0;
            }
        }
        match event {
            Event::Timer(waker) => {
                // A paused device's timer (its key names the device whose poll set it) is held
                // until it resumes.
                let owner = key_kept
                    .as_ref()
                    .and_then(|k| self.by_number(k.levels[0].device))
                    .filter(|&i| self.actors[i].paused);
                match (owner, key_kept) {
                    (Some(i), Some(key)) => self.actors[i].held.push((key, Event::Timer(waker))),
                    _ => waker.wake(),
                }
            }
            Event::Poll(device) if self.actors[device].paused => {
                if let Some(key) = key_kept {
                    self.actors[device].held.push((key, Event::Poll(device)));
                }
            }
            Event::Poll(device) => self.actors[device].inbox.push(Command::Poll),
            Event::Deliver(d) => {
                if self.panel.arrive(&self.clock, at, &d) {
                    let slot = &mut self.actors[d.device];
                    if slot.paused {
                        // It reached the port; a sleeping device takes nothing in.
                        slot.paused_drops += 1;
                    } else {
                        slot.inbox.push(Command::Receive {
                            port: d.port,
                            frame: d.frame,
                        });
                    }
                }
            }
            Event::LinkState { link, up } => {
                for (device, port) in self
                    .panel
                    .set_up(&self.clock, at, link, up)
                    .into_iter()
                    .flatten()
                {
                    self.actors[device]
                        .inbox
                        .push(Command::LinkState { port, up });
                }
            }
            Event::Operator(i) => self.apply_op(i, at),
            // Applied by the network before this event's rounds (the run returns it).
            Event::Derived(n) => self.derived_pending = Some(n),
        }
    }

    /// An operator event fired. An anchored one applies only if its anchor is the
    /// very next event; otherwise the anchor never occurred in this branch.
    fn apply_op(&mut self, i: usize, at: Nanos) {
        let Some(slot) = self.ops.get(i) else {
            return;
        };
        if let Some(anchor) = &slot.anchor
            && self.clock.next_key().as_ref() != Some(anchor)
        {
            self.ops[i].state = OpState::Unreached { at };
            return;
        }
        let events = self.stats.events;
        match slot.op.clone() {
            CoreOp::LinkState { link, up } => {
                for (device, port) in self
                    .panel
                    .set_up(&self.clock, at, link, up)
                    .into_iter()
                    .flatten()
                {
                    self.actors[device]
                        .inbox
                        .push(Command::LinkState { port, up });
                }
            }
            CoreOp::Latency { link, ns } => self.panel.set_latency(link, ns),
            CoreOp::Impair {
                link,
                from,
                impairments,
            } => self.panel.set_impairments(link, from, impairments),
            CoreOp::Inject {
                device,
                port,
                bytes,
            } => self.panel.transmit(&self.clock, device, port, bytes),
            CoreOp::Control { device, .. } if self.actors[device].paused => {
                self.ops[i].state = OpState::Failed {
                    at,
                    events,
                    message: format!("`{}` is paused", self.actors[device].name),
                };
                return;
            }
            CoreOp::Control { device, call } => {
                // Served by the device's event loop in this event's rounds; the answer (the
                // device's own refusal, if any) is kept for `op_states`.
                let call = call.call();
                let reply = call.answer();
                self.actors[device].inbox.push(Command::Control(call));
                self.ops[i].reply = Some(reply);
            }
            CoreOp::Stdin { device, bytes } => {
                self.actors[device].inbox.push(Command::Stdin(bytes));
            }
            // Applied by the network before this event's rounds (the run returns it).
            CoreOp::Network(j) => self.network_pending = Some((i, j)),
        }
        self.ops[i].state = OpState::Applied { at, events };
    }

    /// Nothing left to pop (or nothing before `until`): decide the end state.
    fn finish(&mut self, until: Option<Nanos>, advance: bool) -> Result<Outcome, Error> {
        let pending_events = self.clock.pending_events();
        if let Some(at) = until.filter(|_| pending_events > 0) {
            if !advance {
                let at = self.clock.now();
                return Ok(Outcome::Deadline { at, pending_events });
            }
            self.clock.advance_to(at);
            return Ok(Outcome::Deadline { at, pending_events });
        }
        let at = self.clock.now();
        let mut outstanding = Vec::new();
        let mut parked = Vec::new();
        let mut daemons = Vec::new();
        for slot in self.actors.iter().filter(|s| !s.stopped) {
            let s = slot.status.snapshot();
            // A paused device waits for its resume, not for a call: never a deadlock.
            if !slot.paused {
                outstanding.extend(s.outstanding.into_iter().map(|c| (slot.name.clone(), c)));
            }
            daemons.extend(s.daemons.into_iter().map(|c| format!("{}: {c}", slot.name)));
            if s.alive {
                parked.push(slot.name.clone());
            }
        }
        if outstanding.is_empty() {
            Ok(Outcome::Quiescent {
                at,
                parked,
                daemons,
            })
        } else {
            Err(Error::Deadlock { at, outstanding })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn idle_future_advances_virtual_time() {
        let clock = VirtualClock::new(Duration::ZERO);
        let c = clock.clone();
        let t = block_on(&clock, async move {
            c.sleep_for(5_000).await;
            c.sleep_for(7).await;
            c.now()
        });
        assert_eq!(t, Ok(5_007));
    }

    #[test]
    fn pending_without_events_is_a_deadlock() {
        let clock = VirtualClock::new(Duration::ZERO);
        assert_eq!(
            block_on(&clock, std::future::pending::<()>()),
            Err(Stalled { at: 0 })
        );
    }

    // ---- multi-actor executor, with plain Rust futures standing in for device stores ----

    use std::future::poll_fn;
    use std::sync::Mutex;

    fn executor(guard: Guard) -> (VirtualClock, Executor) {
        let clock = VirtualClock::new(Duration::ZERO);
        let exec = Executor::new(clock.clone(), Panel::default(), guard);
        (clock, exec)
    }

    fn add(
        exec: &mut Executor,
        name: &str,
        status: Status,
        fut: impl Future<Output = Result<(), Fault>> + 'static,
    ) {
        let number = exec.actors.len() as u32;
        exec.add(name, number, Inbox::default(), status, Box::pin(fut));
    }

    /// An actor that logs `name@t` after each of its sleeps, then idles forever.
    fn sleeper(
        clock: &VirtualClock,
        log: &Arc<Mutex<Vec<String>>>,
        name: &'static str,
        sleeps: &'static [Nanos],
    ) -> impl Future<Output = Result<(), Fault>> + 'static {
        let (clock, log) = (clock.clone(), log.clone());
        async move {
            for &ns in sleeps {
                clock.sleep_for(ns).await;
                log.lock().unwrap().push(format!("{name}@{}", clock.now()));
            }
            std::future::pending().await
        }
    }

    #[test]
    fn actors_share_one_timeline_and_quiesce() {
        let (clock, mut exec) = executor(Guard::default().paranoid(true));
        let log = Arc::new(Mutex::new(Vec::new()));
        add(
            &mut exec,
            "a",
            Status::default(),
            sleeper(&clock, &log, "a", &[10, 10]),
        );
        add(
            &mut exec,
            "b",
            Status::default(),
            sleeper(&clock, &log, "b", &[20, 5]),
        );
        let mid = exec.run(Some(15)).unwrap().done();
        assert_eq!(
            mid,
            Outcome::Deadline {
                at: 15,
                pending_events: 2
            }
        );
        assert_eq!(clock.now(), 15);
        let end = exec.run(None).unwrap().done();
        assert_eq!(
            end,
            Outcome::Quiescent {
                at: 25,
                parked: vec![],
                daemons: vec![],
            }
        );
        // Same instant (t=20): b registered its timer at t=0, before a did at t=10.
        assert_eq!(*log.lock().unwrap(), ["a@10", "b@20", "a@20", "b@25"]);
        assert_eq!(exec.stats().events, 4);
    }

    #[test]
    fn settle_runs_woken_actors_without_advancing_time() {
        // Control calls (`Network::counters`) settle the current instant: woken actors run, but no
        // queued event fires and virtual time stays put.
        let (clock, mut exec) = executor(Guard::default().paranoid(true));
        let log = Arc::new(Mutex::new(Vec::new()));
        add(
            &mut exec,
            "a",
            Status::default(),
            sleeper(&clock, &log, "a", &[10]),
        );
        exec.settle(0).unwrap();
        assert_eq!((clock.now(), clock.pending_events()), (0, 1));
        assert!(log.lock().unwrap().is_empty());
        assert_eq!(exec.stats().events, 0);
        let end = exec.run(None).unwrap().done();
        assert_eq!(
            end,
            Outcome::Quiescent {
                at: 10,
                parked: vec![],
                daemons: vec![],
            }
        );
    }

    /// A run that stops at boundaries and resumes is identical to one that never stopped,
    /// and a boundary's ordinal counts events.
    #[test]
    fn stopping_and_resuming_changes_nothing() {
        let run = |stops: &[u64]| {
            let (clock, mut exec) = executor(Guard::default().paranoid(true));
            let log = Arc::new(Mutex::new(Vec::new()));
            add(
                &mut exec,
                "a",
                Status::default(),
                sleeper(&clock, &log, "a", &[10, 10]),
            );
            add(
                &mut exec,
                "b",
                Status::default(),
                sleeper(&clock, &log, "b", &[20, 5]),
            );
            let mut seen = Vec::new();
            for &n in stops {
                match exec
                    .run_stoppable(None, &mut |b| b.events >= n)
                    .unwrap()
                    .done()
                {
                    Step::Stopped(b) => seen.push((b.events, b.now)),
                    Step::Done(_) => panic!("ended before e={n}"),
                }
            }
            let end = exec.run_stoppable(None, &mut |_| false).unwrap().done();
            let log = log.lock().unwrap().clone();
            (log, end, seen, exec.stats())
        };
        let (plain, end, _, stats) = run(&[]);
        let (stopped, end2, seen, stats2) = run(&[0, 1, 1, 3]);
        assert_eq!(plain, stopped);
        assert_eq!(end, end2);
        assert_eq!(stats, stats2);
        assert_eq!(seen, [(0, 0), (1, 10), (1, 10), (3, 20)]);
    }

    #[test]
    fn a_self_waking_actor_is_a_runaway() {
        let guard = Guard::default().max_polls_per_instant(100);
        let (_, mut exec) = executor(guard);
        let spin = poll_fn(|cx| {
            cx.waker().wake_by_ref();
            Poll::Pending
        });
        add(&mut exec, "spin", Status::default(), spin);
        let err = exec.run(None).unwrap_err();
        assert!(
            matches!(&err, Error::Runaway { device, at: 0, polls: 100 } if device == "spin"),
            "{err}"
        );
    }

    #[test]
    fn a_failing_actor_is_a_trap() {
        let (clock, mut exec) = executor(Guard::default());
        let c = clock.clone();
        add(&mut exec, "crash", Status::default(), async move {
            c.sleep_for(7).await;
            Err(Fault::with_detail("unreachable", 42u8))
        });
        let err = exec.run(None).unwrap_err();
        assert!(
            matches!(&err, Error::Trap { device, at: 7, detail: Some(d), message } if device == "crash" && message == "unreachable" && d.downcast_ref::<u8>() == Some(&42)),
            "{err}"
        );
    }

    #[test]
    fn an_outstanding_call_with_nothing_queued_is_a_deadlock() {
        let (_, mut exec) = executor(Guard::default());
        let status = Status::default();
        status.begin("start".to_owned(), false);
        add(&mut exec, "stuck", status, std::future::pending());
        let err = exec.run(None).unwrap_err();
        assert!(
            matches!(&err, Error::Deadlock { at: 0, outstanding } if outstanding == &[("stuck".to_owned(), "start".to_owned())]),
            "{err}"
        );
    }

    #[test]
    fn a_daemon_call_that_never_finishes_is_parked_not_a_deadlock() {
        // An app's `run` (a server) is a daemon call: still in flight at the end, reported, and
        // never a deadlock. Ordinary calls beside it still are.
        let (_, mut exec) = executor(Guard::default());
        let status = Status::default();
        status.begin("app-udp-echo-server.run".to_owned(), true);
        add(&mut exec, "server", status, std::future::pending());
        assert_eq!(
            exec.run(None).unwrap().done(),
            Outcome::Quiescent {
                at: 0,
                parked: vec![],
                daemons: vec!["server: app-udp-echo-server.run".to_owned()],
            }
        );
        let (_, mut exec) = executor(Guard::default());
        let status = Status::default();
        status.begin("app-udp-echo-server.run".to_owned(), true);
        status.begin("receive(p0)".to_owned(), false);
        add(&mut exec, "server", status, std::future::pending());
        let err = exec.run(None).unwrap_err();
        assert!(
            matches!(&err, Error::Deadlock { outstanding, .. } if outstanding == &[("server".to_owned(), "receive(p0)".to_owned())]),
            "{err}"
        );
    }

    #[test]
    fn the_paranoid_round_catches_a_missed_wake() {
        let (_, mut exec) = executor(Guard::default().paranoid(true));
        // Idle on its first poll without registering anything, then finds work on the next one.
        // It has a call in flight: a quiet actor (nothing in flight, no live guest task) has no
        // wake to miss and is not re-polled.
        let mut polls = 0;
        let status = Status::default();
        status.begin("receive".into(), false);
        add(
            &mut exec,
            "flaky",
            status,
            poll_fn(move |cx| {
                polls += 1;
                if polls > 1 {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }),
        );
        let err = exec.run(None).unwrap_err();
        assert!(
            matches!(&err, Error::MissedWake { device, at: 0 } if device == "flaky"),
            "{err}"
        );
    }
}
