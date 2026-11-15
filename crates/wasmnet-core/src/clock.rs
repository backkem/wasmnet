//! Virtual time and the simulation's one discrete-event queue.
//!
//! Nothing in here reads a real clock. Every future happening is an [`Event`] keyed by an
//! [`EventKey`]: guest timers (`wasi:clocks` waits and host [`Sleep`]s), frame deliveries and
//! device poll deadlines all share one total order. The executor ([`crate::exec`]) pops **one**
//! event at a time, and only when every device is idle.
//!
//! ## The event order: a causal, partition-invariant key
//!
//! A queue keyed by `(time, seq)` with one global insertion counter `seq` cannot survive
//! splitting a network across instances (sites): each part would count only its own
//! insertions. The key says the same thing in a way every part computes locally
//! (`docs/design/event-order.md`, `docs/design/sites.md`):
//!
//! ```text
//! K(e) = (at, origin, [K(cause) if origin = popped], slot, round, device, idx)
//! ```
//!
//! * `origin`: `setup` (queued while the network was built; `slot` = the setup step: the device
//!   index while creating a device, then `devices + action index` for scripted link changes),
//!   `init` (the executor's first round, before any event fired), `popped` (while the event
//!   `cause` was being processed), or `control` (a control call between runs, `slot` = device).
//! * `round`: the executor's phase-1 round within that processing (1-based; 0 is the dispatch
//!   itself), `device`: the index of the device being polled ([`HOST_DEVICE`] for the host),
//!   `idx`: how many events were already queued in this `(cause, round, device)`.
//!
//! Events fire in key order, each to quiescence, and within one event the executor polls
//! devices round by round in index order. So this order is exactly the insertion order of a
//! single queue with a global counter (the two give byte-identical runs), but it depends only on
//! the history of the devices involved: every part of a split network computes the same key for
//! the same event.
//!
//! Keys nest (a key holds its cause's key) and are truncated to [`KEY_DEPTH`] levels; at the
//! cut, `(device, counter)` (the creator device's lifetime insertion counter, unique per event)
//! stands in for the rest. The order stays total and partition-invariant at any depth.
//!
//! Every output record (journal entry, frame, pcap tap of a split link, link transition) is
//! stamped with a [`Tag`] (the processing context and a position in it), so the records of the
//! parts of a split network merge back into exactly the unsplit order.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// Virtual time in nanoseconds since the simulation started.
pub type Nanos = u64;

/// Index of a device within its network.
pub(crate) type DeviceIdx = usize;

/// Levels kept in an [`EventKey`]: the event plus `KEY_DEPTH - 1` causes. The deepest tie seen
/// in practice is 21 levels (two identical HTTP flows).
pub const KEY_DEPTH: usize = 32;

/// The `device` of host-made insertions (scripted link changes) and host-made records.
pub const HOST_DEVICE: u32 = u32::MAX;

/// How an event or record came to be (see `docs/design/event-order.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    Setup,
    Init,
    Popped,
    Control,
    /// An operator event placed at the end of an instant: after every event of that
    /// instant, before the next instant. Never on the site-sync wire (split networks refuse ops).
    Operator,
}

impl Origin {
    /// The wire code (`docs/design/sites.md`).
    pub fn code(self) -> u8 {
        match self {
            Origin::Setup => 0,
            Origin::Init => 1,
            Origin::Popped => 2,
            Origin::Control => 3,
            Origin::Operator => 4,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Origin::Setup,
            1 => Origin::Init,
            2 => Origin::Popped,
            3 => Origin::Control,
            4 => Origin::Operator,
            _ => return None,
        })
    }
}

/// One level of an [`EventKey`]: an event and the context it was queued in.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyLevel {
    pub at: Nanos,
    pub origin: Origin,
    pub slot: u64,
    pub round: u32,
    pub device: u32,
    pub idx: u32,
    /// The creator device's lifetime insertion counter (the tie-break at the truncation depth).
    pub counter: u64,
    /// The *pre* number (`docs/design/event-order.md`): 0 for every event the simulation
    /// queues itself. The n-th operator event anchored before event K has K's key with
    /// `pre = n` on its first level, so it sorts after everything that sorts before K, and
    /// before K (in `n` order).
    pub pre: u32,
}

/// The pre number as a sort key: anchored operator events (`pre ≥ 1`, in order) before their
/// anchor (`pre = 0`).
fn pre_rank(pre: u32) -> (bool, u32) {
    (pre == 0, pre)
}

/// The partition-invariant queue key (see `docs/design/event-order.md`). `levels[0]` is the event itself,
/// `levels[i + 1]` the event that was being processed when `levels[i]` was queued.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventKey {
    pub levels: Vec<KeyLevel>,
}

/// Compares the keys `a[i..]` and `b[i..]` (see `docs/design/event-order.md`).
fn cmp_levels(a: &[KeyLevel], b: &[KeyLevel], i: usize) -> Ordering {
    let (x, y) = (&a[i], &b[i]);
    let o = x.at.cmp(&y.at).then(x.origin.cmp(&y.origin));
    if o != Ordering::Equal {
        return o;
    }
    if x.origin == Origin::Popped {
        if i + 1 < a.len() && i + 1 < b.len() {
            let o = cmp_levels(a, b, i + 1);
            if o != Ordering::Equal {
                return o;
            }
        } else {
            // The truncation depth: `(device, counter)` names the event uniquely.
            return (x.device, x.counter, pre_rank(x.pre)).cmp(&(
                y.device,
                y.counter,
                pre_rank(y.pre),
            ));
        }
    }
    // The pre number is the last tie-break: pre keys sort right before their anchor.
    (x.slot, x.round, x.device, x.idx, pre_rank(x.pre)).cmp(&(
        y.slot,
        y.round,
        y.device,
        y.idx,
        pre_rank(y.pre),
    ))
}

impl EventKey {
    /// The event's virtual time.
    pub fn at(&self) -> Nanos {
        self.levels[0].at
    }
}

impl Ord for EventKey {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_levels(&self.levels, &other.levels, 0)
    }
}

impl PartialOrd for EventKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The processing context: what the simulation is doing right now.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ctx {
    pub origin: Origin,
    /// The event being processed (`origin = popped`).
    pub cause: Option<EventKey>,
    pub slot: u64,
    pub round: u32,
    pub device: u32,
}

impl Ord for Ctx {
    fn cmp(&self, other: &Self) -> Ordering {
        self.origin
            .cmp(&other.origin)
            .then_with(|| match (&self.cause, &other.cause) {
                (Some(a), Some(b)) => a.cmp(b),
                (a, b) => a.is_some().cmp(&b.is_some()),
            })
            .then_with(|| {
                (self.slot, self.round, self.device).cmp(&(other.slot, other.round, other.device))
            })
    }
}

impl PartialOrd for Ctx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Where an output record sits in the global processing order: its context and its position
/// within it. Merging the records of all parts of a split network by `Tag` reproduces the unsplit
/// order.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tag {
    pub ctx: Ctx,
    pub n: u64,
}

/// A frame in flight on a link, delivered to `(device, port)` when its event fires.
#[derive(Debug)]
pub(crate) struct Delivery {
    /// The link it travels on and the index (0 or 1) of the receiving end, for the pcap tap.
    pub(crate) link: usize,
    pub(crate) to_end: usize,
    /// The link's generation at transmit time. If the link went down since, its generation moved
    /// on and the frame is lost instead of delivered.
    pub(crate) generation: u64,
    /// Index of this frame in the sending part's frame log.
    pub(crate) frame_id: usize,
    /// The frame came from another part of a split network (its record is in that part's log).
    pub(crate) remote: bool,
    pub(crate) device: DeviceIdx,
    pub(crate) port: u32,
    pub(crate) frame: Vec<u8>,
}

/// Something that happens at a virtual instant.
pub(crate) enum Event {
    /// A guest `wait-for`/`wait-until` (p2 or p3) or a host [`Sleep`] reached its deadline.
    Timer(Waker),
    /// A frame arrives at a device port.
    Deliver(Delivery),
    /// A stepped device's `poll` deadline.
    Poll(DeviceIdx),
    /// A scripted carrier change of a whole link (both ends).
    LinkState { link: usize, up: bool },
    /// Operator event `n` of the network, at the key it was placed at.
    Operator(usize),
    /// Derived request `n` of an in-world controller (`wasmnet:infra`), queued in
    /// the caller's processing context.
    Derived(usize),
}

/// The simulation clock and event queue: one per network (or command runner).
///
/// Cloning is cheap and yields a handle to the same clock. It is `Send + Sync` only because
/// runtimes require that of host state and host futures; the simulation is single-threaded.
#[derive(Clone)]
pub struct VirtualClock {
    inner: Arc<Mutex<State>>,
}

struct State {
    now: Nanos,
    wall_epoch: Duration,
    queue: BTreeMap<EventKey, Event>,
    /// The one pending `Poll` event per device, so a new deadline replaces the old one.
    polls: BTreeMap<DeviceIdx, EventKey>,
    ctx: Ctx,
    /// Events queued in the current context.
    ctx_idx: u32,
    /// Records stamped in the current context.
    ctx_records: u64,
    /// Lifetime insertion counter per creator device.
    counters: BTreeMap<u32, u64>,
}

impl State {
    fn next_key(&mut self, at: Nanos) -> EventKey {
        let at = at.max(self.now);
        let counter = self.counters.entry(self.ctx.device).or_insert(0);
        let level = KeyLevel {
            at,
            origin: self.ctx.origin,
            slot: self.ctx.slot,
            round: self.ctx.round,
            device: self.ctx.device,
            idx: self.ctx_idx,
            counter: *counter,
            pre: 0,
        };
        *counter += 1;
        self.ctx_idx += 1;
        let mut levels = Vec::with_capacity(KEY_DEPTH);
        levels.push(level);
        if let Some(cause) = &self.ctx.cause {
            levels.extend(cause.levels.iter().take(KEY_DEPTH - 1).cloned());
        }
        EventKey { levels }
    }

    fn insert(&mut self, at: Nanos, event: Event) -> EventKey {
        let key = self.next_key(at);
        self.queue.insert(key.clone(), event);
        key
    }

    fn reset_ctx(&mut self, ctx: Ctx) {
        self.ctx = ctx;
        self.ctx_idx = 0;
        self.ctx_records = 0;
    }
}

impl VirtualClock {
    /// A clock at virtual time 0 whose wall clock reads `wall_epoch` (since the Unix epoch).
    pub fn new(wall_epoch: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                now: 0,
                wall_epoch,
                queue: BTreeMap::new(),
                polls: BTreeMap::new(),
                ctx: Ctx {
                    origin: Origin::Setup,
                    cause: None,
                    slot: 0,
                    round: 0,
                    device: HOST_DEVICE,
                },
                ctx_idx: 0,
                ctx_records: 0,
                counters: BTreeMap::new(),
            })),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // Poisoning only means a panic elsewhere; the state itself stays consistent.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Current virtual monotonic time.
    pub fn now(&self) -> Nanos {
        self.state().now
    }

    /// Current virtual wall-clock time, as a duration since the Unix epoch.
    pub fn wall_now(&self) -> Duration {
        let s = self.state();
        s.wall_epoch + Duration::from_nanos(s.now)
    }

    /// Number of queued events (timers, deliveries and poll deadlines).
    pub fn pending_events(&self) -> usize {
        self.state().queue.len()
    }

    /// The time of the earliest queued event.
    pub fn next_event_time(&self) -> Option<Nanos> {
        self.state().queue.first_key_value().map(|(k, _)| k.at())
    }

    /// A future that completes once virtual time reaches `deadline`.
    pub fn sleep_until(&self, deadline: Nanos) -> Sleep {
        Sleep {
            clock: self.clone(),
            deadline,
            key: None,
        }
    }

    /// A future that completes `duration` nanoseconds of virtual time from now.
    pub fn sleep_for(&self, duration: Nanos) -> Sleep {
        self.sleep_until(self.now().saturating_add(duration))
    }

    /// Enters a new processing context (`round` 0, the host as device).
    pub(crate) fn set_ctx(&self, origin: Origin, cause: Option<EventKey>, slot: u64) {
        self.state().reset_ctx(Ctx {
            origin,
            cause,
            slot,
            round: 0,
            device: HOST_DEVICE,
        });
    }

    /// A setup context: building device (or scripted action) `slot`, made by `device`.
    pub(crate) fn set_setup(&self, slot: u64, device: u32) {
        self.state().reset_ctx(Ctx {
            origin: Origin::Setup,
            cause: None,
            slot,
            round: 0,
            device,
        });
    }

    /// The executor is about to poll `device` in phase-1 round `round`.
    pub(crate) fn set_actor(&self, round: u32, device: u32) {
        let mut s = self.state();
        if (s.ctx.round, s.ctx.device) != (round, device) {
            s.ctx.round = round;
            s.ctx.device = device;
            s.ctx_idx = 0;
            s.ctx_records = 0;
        }
    }

    /// Stamps one output record with the current context.
    pub(crate) fn tag(&self) -> Tag {
        let mut s = self.state();
        let n = s.ctx_records;
        s.ctx_records += 1;
        Tag {
            ctx: s.ctx.clone(),
            n,
        }
    }

    /// Queues a frame delivery at `at` (clamped to now).
    pub(crate) fn schedule_delivery(&self, at: Nanos, delivery: Delivery) {
        self.state().insert(at, Event::Deliver(delivery));
    }

    /// The key a delivery at `at` gets, for a frame that leaves for another part: computed
    /// exactly as if it were queued here, so the receiver queues it under the same key.
    pub(crate) fn remote_key(&self, at: Nanos) -> EventKey {
        self.state().next_key(at)
    }

    /// Queues a delivery that arrived from another part under the sender's key.
    pub(crate) fn schedule_remote_delivery(&self, key: EventKey, delivery: Delivery) {
        let mut s = self.state();
        assert!(
            key.at() >= s.now,
            "lockstep violation: a frame due at t={} arrived at t={}",
            key.at(),
            s.now
        );
        s.queue.insert(key, Event::Deliver(delivery));
    }

    /// Queues a carrier change of `link` at `at` (clamped to now).
    pub(crate) fn schedule_link_state(&self, at: Nanos, link: usize, up: bool) {
        self.state().insert(at, Event::LinkState { link, up });
    }

    /// Replaces `device`'s poll deadline with `at` (`None` cancels it). For runtime backends:
    /// after a device's `poll` returns its next deadline.
    pub fn set_poll(&self, device: DeviceIdx, at: Option<Nanos>) {
        let mut s = self.state();
        if let Some(old) = s.polls.remove(&device) {
            s.queue.remove(&old);
        }
        if let Some(at) = at {
            let key = s.insert(at, Event::Poll(device));
            s.polls.insert(device, key);
        }
    }

    /// Makes sure `device` is polled no later than `at`: keeps an earlier-or-equal deadline,
    /// otherwise replaces it. A fresh entry at the current instant sorts after every event
    /// already queued for it, so a burst of same-instant deliveries is followed by one poll.
    /// For runtime backends: after a device's `receive` or `link-state`.
    pub fn poll_by(&self, device: DeviceIdx, at: Nanos) {
        let current = self.state().polls.get(&device).map(EventKey::at);
        if current.is_none_or(|t| t > at) {
            self.set_poll(device, Some(at));
        }
    }

    /// Pops the earliest event and advances `now` to its time. Returns `None` if the queue is
    /// empty or the earliest event lies after `limit`.
    pub(crate) fn pop(&self, limit: Option<Nanos>) -> Option<(EventKey, Event)> {
        let mut s = self.state();
        let (key, _) = s.queue.first_key_value()?;
        let at = key.at();
        if limit.is_some_and(|l| at > l) {
            return None;
        }
        let (key, event) = s.queue.pop_first()?;
        if let Event::Poll(device) = event
            && s.polls.get(&device) == Some(&key)
        {
            s.polls.remove(&device);
        }
        s.now = s.now.max(at);
        Some((key, event))
    }

    /// Moves time forward to `t` without firing anything (stopping at a run deadline).
    pub(crate) fn advance_to(&self, t: Nanos) {
        let mut s = self.state();
        s.now = s.now.max(t);
    }

    /// The key of the earliest queued event: the event right after the current boundary.
    pub fn next_key(&self) -> Option<EventKey> {
        self.state().queue.first_key_value().map(|(k, _)| k.clone())
    }

    /// The tag the next record stamped in the current context will get, without taking it.
    pub(crate) fn peek_tag(&self) -> Tag {
        let s = self.state();
        Tag {
            ctx: s.ctx.clone(),
            n: s.ctx_records,
        }
    }

    /// Queues derived request `n` (`wasmnet:infra`) at `at` (clamped to now) in the
    /// current processing context, like a frame transmitted with zero latency.
    pub(crate) fn schedule_derived(&self, at: Nanos, n: usize) -> EventKey {
        self.state().insert(at, Event::Derived(n))
    }

    /// The key the next event queued at `at` in the current context will get (nothing is
    /// queued and no counter moves).
    pub(crate) fn peek_key(&self, at: Nanos) -> EventKey {
        let mut s = self.state();
        let device = s.ctx.device;
        let (idx, counter) = (s.ctx_idx, s.counters.get(&device).copied());
        let key = s.next_key(at);
        s.ctx_idx = idx;
        match counter {
            Some(c) => s.counters.insert(device, c),
            None => s.counters.remove(&device),
        };
        key
    }

    /// Queues operator event `op` under `key`. Returns false if the key is taken.
    pub(crate) fn schedule_op(&self, key: EventKey, op: usize) -> bool {
        let mut s = self.state();
        if s.queue.contains_key(&key) {
            return false;
        }
        s.queue.insert(key, Event::Operator(op));
        true
    }
}

impl EventKey {
    /// The key of the `n`-th (from 1) operator event anchored immediately before `self`.
    pub fn pre(&self, n: u32) -> EventKey {
        let mut k = self.clone();
        k.levels[0].pre = n.max(1);
        k
    }

    /// The anchor of a pre key (the key itself for an ordinary event).
    pub fn anchor(&self) -> EventKey {
        let mut k = self.clone();
        k.levels[0].pre = 0;
        k
    }

    /// The key of an operator event at the start of instant `at` (before every event of that
    /// instant), in setup slot `slot` (after the network's devices and scripted actions).
    pub fn operator_at(at: Nanos, slot: u64) -> EventKey {
        Self::single(at, Origin::Setup, slot)
    }

    /// The key of an operator event at the end of instant `at` (after every event of that
    /// instant), number `slot` among the network's operator events.
    pub fn operator_after(at: Nanos, slot: u64) -> EventKey {
        Self::single(at, Origin::Operator, slot)
    }

    fn single(at: Nanos, origin: Origin, slot: u64) -> EventKey {
        EventKey {
            levels: vec![KeyLevel {
                at,
                origin,
                slot,
                round: 0,
                device: HOST_DEVICE,
                idx: 0,
                counter: 0,
                pre: 0,
            }],
        }
    }
}

/// Future returned by [`VirtualClock::sleep_until`]. Dropping it cancels the timer.
pub struct Sleep {
    clock: VirtualClock,
    deadline: Nanos,
    key: Option<EventKey>,
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        let mut s = this.clock.state();
        let waker = Event::Timer(cx.waker().clone());
        match &this.key {
            // Never registered: a deadline that has already passed completes at once.
            None if s.now >= this.deadline => return Poll::Ready(()),
            None => this.key = Some(s.insert(this.deadline, waker)),
            // Registered: complete only once *our* event has fired. Checking `now >= deadline`
            // instead would let a spurious poll overtake same-instant events queued earlier.
            Some(key) => match s.queue.get_mut(key) {
                Some(slot) => *slot = waker,
                None => {
                    this.key = None;
                    return Poll::Ready(());
                }
            },
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.clock.state().queue.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::task::Wake;

    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, AtomicOrdering::SeqCst);
        }
    }

    fn fire_next(clock: &VirtualClock) -> Option<Nanos> {
        let (key, event) = clock.pop(None)?;
        if let Event::Timer(w) = event {
            w.wake();
        }
        Some(key.at())
    }

    #[test]
    fn timers_fire_in_deadline_order_and_cancel_on_drop() {
        let clock = VirtualClock::new(Duration::from_secs(100));
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);

        let mut late = Box::pin(clock.sleep_until(300));
        let mut early = Box::pin(clock.sleep_until(100));
        let mut cancelled = Box::pin(clock.sleep_until(50));
        for s in [&mut late, &mut early, &mut cancelled] {
            assert!(s.as_mut().poll(&mut cx).is_pending());
        }
        drop(cancelled);
        assert_eq!(clock.pending_events(), 2);

        assert_eq!(fire_next(&clock), Some(100));
        assert!(early.as_mut().poll(&mut cx).is_ready());
        assert!(late.as_mut().poll(&mut cx).is_pending());
        assert_eq!(fire_next(&clock), Some(300));
        assert!(late.as_mut().poll(&mut cx).is_ready());
        assert_eq!(fire_next(&clock), None);
        assert_eq!(
            clock.wall_now(),
            Duration::from_secs(100) + Duration::from_nanos(300)
        );
        assert_eq!(count.0.load(AtomicOrdering::SeqCst), 2);
    }

    fn delivery(port: u32) -> Delivery {
        Delivery {
            link: 0,
            to_end: 1,
            generation: 0,
            frame_id: 0,
            remote: false,
            device: 7,
            port,
            frame: vec![],
        }
    }

    fn drain(clock: &VirtualClock) -> Vec<(Nanos, String)> {
        std::iter::from_fn(|| clock.pop(None))
            .map(|(key, e)| {
                let what = match e {
                    Event::Timer(_) => "timer".to_owned(),
                    Event::Deliver(d) => format!("deliver p{}", d.port),
                    Event::Poll(d) => format!("poll d{d}"),
                    Event::LinkState { link, up } => format!("link {link} up={up}"),
                    Event::Operator(n) => format!("op {n}"),
                    Event::Derived(n) => format!("derived {n}"),
                };
                (key.at(), what)
            })
            .collect()
    }

    #[test]
    fn deliveries_and_polls_share_one_order() {
        let clock = VirtualClock::new(Duration::ZERO);
        clock.schedule_delivery(20, delivery(1));
        clock.set_poll(3, Some(10));
        clock.schedule_delivery(10, delivery(2));
        // Replacing a deadline drops the old event and takes a new place in the order.
        clock.set_poll(4, Some(5));
        clock.set_poll(4, Some(20));
        // poll_by keeps an earlier deadline and replaces a later one.
        clock.poll_by(3, 15);
        clock.poll_by(4, 10);
        assert_eq!(
            drain(&clock),
            [
                (10, "poll d3".to_owned()),
                (10, "deliver p2".to_owned()),
                (10, "poll d4".to_owned()),
                (20, "deliver p1".to_owned()),
            ]
        );
        assert_eq!(clock.now(), 20);
        // Popped deadlines are forgotten, so the next poll_by schedules afresh (clamped to now).
        clock.poll_by(3, 0);
        assert_eq!(drain(&clock), [(20, "poll d3".to_owned())]);
    }

    #[test]
    fn pop_respects_the_limit() {
        let clock = VirtualClock::new(Duration::ZERO);
        clock.schedule_delivery(50, delivery(0));
        assert!(clock.pop(Some(49)).is_none());
        assert_eq!(clock.now(), 0);
        clock.advance_to(49);
        assert_eq!(clock.now(), 49);
        assert!(clock.pop(Some(50)).is_some());
        assert_eq!(clock.now(), 50);
    }

    /// Keys sort like insertion order: within a context by `idx`, across contexts by setup
    /// slot, then the init round, then events by their cause.
    #[test]
    fn key_order_follows_insertion_order() {
        let clock = VirtualClock::new(Duration::ZERO);
        clock.set_setup(0, 0);
        let a = clock.remote_key(10);
        let b = clock.remote_key(10);
        clock.set_setup(1, 1);
        let c = clock.remote_key(10);
        clock.set_ctx(Origin::Init, None, 0);
        clock.set_actor(1, 1);
        let d = clock.remote_key(10);
        clock.set_actor(2, 0);
        let e = clock.remote_key(10);
        clock.set_ctx(Origin::Popped, Some(a.clone()), 0);
        clock.set_actor(1, 1);
        let f = clock.remote_key(10);
        let early = clock.remote_key(5);
        let keys = [early, a, b, c, d, e, f];
        for w in keys.windows(2) {
            assert!(w[0] < w[1], "{:?} < {:?}", w[0].levels[0], w[1].levels[0]);
        }
    }

    /// Operator keys anchored before an event sort after everything before it, before it, and
    /// among themselves in placement order. Start- and end-of-instant keys bracket
    /// the instant.
    #[test]
    fn pre_keys_sort_right_before_their_anchor() {
        let clock = VirtualClock::new(Duration::ZERO);
        clock.set_ctx(Origin::Init, None, 0);
        clock.set_actor(1, 0);
        let a = clock.remote_key(10);
        let b = clock.remote_key(10);
        clock.set_ctx(Origin::Popped, Some(b.clone()), 0);
        clock.set_actor(1, 1);
        let c = clock.remote_key(10);
        let keys = [
            EventKey::operator_at(10, 1 << 40),
            a.clone(),
            b.pre(1),
            b.pre(2),
            b.clone(),
            c,
            EventKey::operator_after(10, 0),
            EventKey::operator_at(11, 1 << 40),
        ];
        for w in keys.windows(2) {
            assert!(w[0] < w[1], "{:?} < {:?}", w[0].levels[0], w[1].levels[0]);
        }
        assert_eq!(b.pre(2).anchor(), b);
        // An event caused by an op sorts after the anchor, and is distinct from one caused by it.
        clock.set_ctx(Origin::Popped, Some(b.pre(1)), 0);
        clock.set_actor(1, 1);
        let by_op = clock.remote_key(10);
        assert!(by_op > b && by_op != a);
    }

    /// Two chains that tie at every level up to the truncation depth are told apart by the
    /// creator's `(device, counter)`.
    #[test]
    fn deep_ties_are_broken_by_the_creator_counter() {
        let level = |device, counter| KeyLevel {
            at: 7,
            origin: Origin::Popped,
            slot: 0,
            round: 1,
            device,
            idx: 0,
            counter,
            pre: 0,
        };
        let a = EventKey {
            levels: (0..KEY_DEPTH as u64).map(|i| level(1, 10 + i)).collect(),
        };
        let mut b = a.clone();
        b.levels[KEY_DEPTH - 1].counter += 1;
        assert!(a < b);
        b.levels[KEY_DEPTH - 1].device = 0;
        assert!(b < a);
    }
}
