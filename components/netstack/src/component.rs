//! wit-bindgen glue and the driver task: exports `wasmnet:link/{device,lifecycle,counters}`,
//! `wasi:sockets@0.3.0/{types,ip-name-lookup}`, `wasmnet:sockets-ext/*` and `state` (world
//! `wasmnet:netstack/netstack`) over [`crate::Stack`], through `export_netstack!` (this crate's
//! own cdylib with the feature `export`, or an embedder's), and the driver's half of
//! [`crate::debug`].
//!
//! Every comment tagged `rule N` refers to the five netstack driver rules in the crate docs
//! (`docs/design/async-under-virtual-time.md`). In short: wakes are level-triggered (1), the
//! waker is registered at the start of every driver poll (2), no `RefCell` borrow is held across
//! an import call or a future drop (3), pending timers are never cancelled in the hot path (4),
//! and diagnostics only go through the sync `wasmnet:link/log` import (5).
//!
//! Sockets: every `udp-socket` method runs in the calling app's component-model
//! task, inside this instance. Sync methods change the stack and wake the driver. The async
//! `send`/`receive` try once and, if they cannot finish yet (no datagram; tx buffer full), park on
//! `SOCKETS`, which the driver fires after every pass. They never spawn.
//!
//! TCP: `tcp-socket.listen`, `send` and `receive` are *sync* functions that hand
//! back streams and futures, so the work behind them runs as **jobs inside the driver task**:
//! an accept loop per listener and two byte pumps per connection. A sync
//! export only queues the job (`spawn_job`) and wakes the driver; it never spawns a task. The
//! driver polls every job on every pass, so a job waits on smoltcp state without registering a
//! waker (`state`); its stream and future operations register in the driver task's waitable
//! set, and their completion wakes the driver. `connect` is async: it parks on `SOCKETS`.

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};

use wasip3::clocks::monotonic_clock;
use wasmnet_wire::MacAddr;
use wit_bindgen::{FutureReader, FutureWriter, StreamReader, StreamResult, StreamWriter};

use crate::names::LookupError;
use crate::tcp::{Accept, KeepAlive, RecvStep, TcpNet, TcpSockets};
use crate::udp::{Family, Send, SockError, SocketId};
use crate::{Config, Level, Note, Output, Stack};

wit_bindgen::generate!({
    world: "wasmnet:netstack/netstack",
    path: [
        "../../wit/deps/clocks",
        "../../wit/deps/sockets",
        "../../wit/deps/config",
        "../../wit/link",
        "../../wit/sockets-ext",
        "../../wit/netstack",
    ],
    generate_all,
    // The export macro is public (`netstack::export_netstack!`), so an embedder exports the
    // world from its own component. The macro carries the exports' half of the
    // world's type section; without an invocation the component only sees the imports.
    pub_export_macro: true,
    export_macro_name: "export_netstack",
    default_bindings_module: "netstack::component",
    with: {
        // Not covered by any WASI binding crate: generate our own bindings for the vendored WIT.
        "wasi:config/store@0.2.0-rc.1": generate,
        // `wasi:sockets/types` uses `duration` from here; share wasip3's (types only).
        "wasi:clocks/types@0.3.0": wasip3::clocks::types,
    },
});

use exports::wasi::sockets::ip_name_lookup;
use exports::wasi::sockets::types::{
    self as sockets, ErrorCode, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress,
    Ipv6SocketAddress,
};
use exports::wasmnet::link::{counters, device, lifecycle};
use exports::wasmnet::sockets_ext::tcp as sockets_ext;
use exports::wasmnet::sockets_ext::udp as sockets_ext_udp;
use exports::wasmnet::sockets_ext::{interfaces as sockets_ext_if, multicast as sockets_ext_mc};
use wasi::config::store;
use wasmnet::link::log;
use wasmnet::link::types::PortInfo;
use wasmnet::link::wire;

/// The node's state. Created on first use (normally `ports()`), from `wasi:config`.
struct Node {
    config: Config,
    /// Port 0's MAC (`macs[0]`), for the log lines.
    mac: MacAddr,
    /// Every port's MAC, port 0 first: configured, or drawn from the seeded `wasi:random` in
    /// port order (a node with one port draws exactly what it always did).
    macs: Vec<MacAddr>,
    /// Built by `start()`, or by `state.restore` on a paused node.
    stack: Option<Stack>,
    /// The seeds `start()` drew (a paused node draws them too, so its `wasi:random` stream
    /// stands where the saved node's did).
    seeds: (u64, u16),
    /// Frames delivered while there is no stack: before `start()`, and on a node that starts
    /// paused, until its restore. They are handed to the stack when it exists. At most
    /// [`EARLY_FRAMES`] are kept; a paused node on a busy link drops the rest, like a NIC whose
    /// receive ring is full.
    early: Vec<(u32, Vec<u8>)>,
    /// Frames dropped because `early` was full.
    early_dropped: u64,
}

/// The most frames kept for a stack that does not exist yet.
const EARLY_FRAMES: usize = 1024;

/// Driver bookkeeping, shared between the driver task and the sync exports.
#[derive(Default)]
struct Driver {
    /// Rule 1: set by every wake, cleared at the start of a pass, re-checked before parking.
    woken: Cell<bool>,
    /// Rule 2: the driver's waker, replaced at the start of every poll and never taken.
    waker: RefCell<Option<Waker>>,
    /// The driver task is inside its poll (so a wake now comes from a re-entered export).
    in_poll: Cell<bool>,
    polls: Cell<u64>,
    passes: Cell<u64>,
    rewakes: Cell<u64>,
    reentrant_wakes: Cell<u64>,
    /// Export calls that entered the instance while the driver was inside its poll.
    reentrant_calls: Cell<u64>,
    /// The earliest instant of a wake not yet served by a pass.
    kick_at: Cell<Option<u64>>,
    /// Wakes first served at a later instant than their own: lost wakes. Must stay 0.
    late_wakes: Cell<u64>,
    timers_armed: Cell<u64>,
    timers_fired: Cell<u64>,
    timers_cancelled: Cell<u64>,
    /// TCP jobs (accept loops, pumps, future writes) queued so far.
    jobs: Cell<u64>,
    /// The deadlines of the armed `wait-until`s (device time), as of the driver's last park:
    /// what a snapshot saves.
    armed: RefCell<Vec<u64>>,
    /// Set by a restore: the driver drops its timers and arms these instead.
    rearm: RefCell<Option<Vec<u64>>>,
}

/// A "wake everyone who waits" signal for socket calls parked on the driver's progress.
///
/// Waiters are keyed so that a parked call that is dropped (an app cancels its `receive`, for
/// example after its own timeout) removes its waker. Waking the waker of a task that already
/// exited would trap inside wit-bindgen's inter-task wakeup.
#[derive(Default)]
struct Notify {
    next: Cell<u64>,
    waiters: RefCell<BTreeMap<u64, Waker>>,
}

impl Notify {
    /// Wakes every waiter, in the order they parked. No borrow is held while waking (rule 3).
    fn notify(&self) {
        let waiters = std::mem::take(&mut *self.waiters.borrow_mut());
        for (_, w) in waiters {
            w.wake();
        }
    }
}

thread_local! {
    // A component instance is single-threaded, so these are the instance's state.
    static NODE: RefCell<Option<Node>> = const { RefCell::new(None) };
    static DRIVER: Driver = Driver::default();
    /// Fired by the driver after every pass.
    static SOCKETS: Notify = Notify::default();
    /// TCP jobs queued by sync exports, taken by the driver at its next pass.
    static JOBS: RefCell<Vec<Job>> = const { RefCell::new(Vec::new()) };
    /// Set by a job that changed smoltcp state: the stack must be polled again this instant.
    static PROGRESS: Cell<bool> = const { Cell::new(false) };
    /// The device clock minus the host's: set by a restore, so the node's
    /// clock reads the saved instant at the moment of the restore.
    static SHIFT: Cell<i64> = const { Cell::new(0) };
    /// Restored sockets not handed back yet (`state.reclaim-*`): TCP and UDP ids.
    static UNCLAIMED: RefCell<(BTreeSet<SocketId>, BTreeSet<SocketId>)> =
        const { RefCell::new((BTreeSet::new(), BTreeSet::new())) };
}

/// A TCP job: an accept loop, a byte pump or a future write, run inside the driver task.
type Job = Pin<Box<dyn Future<Output = ()>>>;

/// Queues `job` for the driver and wakes it. Safe to call from a sync export: nothing is
/// spawned, the driver task polls the job.
fn spawn_job(job: impl Future<Output = ()> + 'static) {
    bump(|d| &d.jobs);
    JOBS.with(|j| j.borrow_mut().push(Box::pin(job)));
    wake_driver();
}

/// A job changed smoltcp state (queued bytes, FIN, consumed bytes): poll the stack again.
fn progress() {
    PROGRESS.with(|p| p.set(true));
}

/// A socket call parked until `attempt` answers. The attempt runs in the caller's task; it must
/// not call imports while it holds the stack (rule 3).
struct Parked<F> {
    attempt: F,
    key: Option<u64>,
}

impl<F> Unpin for Parked<F> {}

impl<T, F: FnMut() -> Option<T>> Future for Parked<F> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        if let Some(out) = (self.attempt)() {
            return Poll::Ready(out);
        }
        let key = *self.key.get_or_insert_with(|| {
            SOCKETS.with(|n| {
                let k = n.next.get();
                n.next.set(k + 1);
                k
            })
        });
        SOCKETS.with(|n| n.waiters.borrow_mut().insert(key, cx.waker().clone()));
        Poll::Pending
    }
}

impl<F> Drop for Parked<F> {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            SOCKETS.with(|n| n.waiters.borrow_mut().remove(&key));
        }
    }
}

fn parked<T>(attempt: impl FnMut() -> Option<T>) -> Parked<impl FnMut() -> Option<T>> {
    Parked { attempt, key: None }
}

/// The device's clock: the host's virtual clock plus [`SHIFT`] (zero unless restored). A sync
/// host call: it never yields.
pub(crate) fn device_now() -> u64 {
    let host = i128::from(monotonic_clock::now());
    (host + i128::from(SHIFT.with(Cell::get))).clamp(0, i128::from(u64::MAX)) as u64
}

/// A device instant on the host's clock.
fn host_time(t: u64) -> u64 {
    (i128::from(t) - i128::from(SHIFT.with(Cell::get))).clamp(0, i128::from(u64::MAX)) as u64
}

fn bump(counter: impl Fn(&Driver) -> &Cell<u64>) {
    DRIVER.with(|d| {
        let c = counter(d);
        c.set(c.get() + 1);
    });
}

fn level(l: Level) -> log::Level {
    match l {
        Level::Debug => log::Level::Debug,
        Level::Info => log::Level::Info,
        Level::Warn => log::Level::Warn,
    }
}

/// Reads the config and picks the MAC. Calls imports, so it runs with no borrow held (rule 3).
/// An invalid config is a configuration error: it is logged, then the device traps.
fn create() -> Node {
    // A config store that cannot be read is a configuration error too (as in the router): an
    // empty config would silently run a node with none of its settings.
    let pairs = store::get_all().unwrap_or_else(|e| {
        log::log(
            log::Level::Error,
            &format!("netstack: wasi:config get-all: {e:?}"),
        );
        panic!("netstack: wasi:config get-all failed")
    });
    let config = Config::from_pairs(pairs).unwrap_or_else(|e| {
        log::log(log::Level::Error, &e.to_string());
        panic!("netstack: {e}")
    });
    let macs: Vec<MacAddr> = config
        .ports()
        .iter()
        .map(|p| {
            p.mac.unwrap_or_else(|| {
                MacAddr::local_from_seed(wasip3::random::random::get_random_u64())
            })
        })
        .collect();
    Node {
        config,
        mac: macs[0],
        macs,
        stack: None,
        seeds: (0, 0),
        early: Vec::new(),
        early_dropped: 0,
    }
}

/// Runs `f` on the node, creating it first if needed. `f` must not call any import (rule 3).
fn with_node<R>(f: impl FnOnce(&mut Node) -> R) -> R {
    if NODE.with(|n| n.borrow().is_none()) {
        let created = create();
        NODE.with(|n| {
            n.borrow_mut().get_or_insert(created);
        });
    }
    NODE.with(|n| f(n.borrow_mut().as_mut().expect("node created above")))
}

/// Runs `f` on the started stack. `f` must not call any import (rule 3).
fn with_stack<R>(f: impl FnOnce(&mut Stack) -> R) -> Result<R, ErrorCode> {
    with_node(|n| n.stack.as_mut().map(f))
        .ok_or_else(|| ErrorCode::Other(Some("the netstack has not started".to_owned())))
}

/// Counts an export call that entered while the driver is suspended inside its poll (a
/// sibling re-entering us during a blocking builtin). Diagnostics only.
fn note_entry() {
    DRIVER.with(|d| {
        if d.in_poll.get() {
            d.reentrant_calls.set(d.reentrant_calls.get() + 1);
        }
    });
}

/// Rule 1 (level-triggered wake): set the flag, then wake the driver's current waker. The waker
/// is cloned out first, so no borrow is held while it runs (rule 3).
pub(crate) fn wake_driver() {
    // An import, so before any borrow (rule 3). A sync host call: it never yields.
    let now = device_now();
    let waker = DRIVER.with(|d| {
        d.woken.set(true);
        d.kick_at
            .set(Some(d.kick_at.get().map_or(now, |k| k.min(now))));
        if d.in_poll.get() {
            // The driver is suspended inside a blocking builtin and a sibling task re-entered
            // one of our exports. Rules 1 and 2 make this wake count anyway.
            d.reentrant_wakes.set(d.reentrant_wakes.get() + 1);
        }
        d.waker.borrow().clone()
    });
    if let Some(w) = waker {
        w.wake();
    }
}

/// Hands one poll's output to the host: frames, then logs and events, in order.
fn emit(out: Output) {
    for (port, frame) in &out.frames {
        wire::transmit(*port, frame);
    }
    emit_notes(out.notes);
}

fn emit_notes(notes: Vec<Note>) {
    for note in notes {
        match note {
            Note::Log(l, line) => log::log(level(l), &line),
            Note::Event(e) => log::event(e.kind, &e.fields),
        }
    }
}

type Timer = Pin<Box<dyn Future<Output = ()>>>;

/// The most job-and-stack rounds in one driver poll. Past it, the driver yields through the
/// usual path (rule 1 brings it back at the same instant if anything is left).
const MAX_ROUNDS: u32 = 256;

/// The one long-lived driver task (spawned by `start`).
///
/// Each poll runs passes until nothing is left at this instant. A pass polls the stack at the
/// current virtual time, transmits what it produced, wakes the socket calls parked on its
/// progress, and makes sure a virtual `wait-until` is pending at or before the stack's next
/// wakeup. The task never finishes: once nothing is pending it parks until a frame or a socket
/// call arrives, and the host reports the node as parked.
async fn driver() {
    let churn = with_node(|n| n.config.timer_churn_ns);
    let mut timers: Vec<(u64, Timer)> = Vec::new();
    // TCP jobs: accept loops and byte pumps. Owned here, never borrowed by an export.
    let mut jobs: Vec<Job> = Vec::new();
    poll_fn(|cx| {
        bump(|d| &d.polls);
        // Rule 2: register first, so a wake during this very poll (a sibling re-entering
        // `receive` or a socket call while we are suspended in a blocking builtin) finds a waker.
        DRIVER.with(|d| {
            *d.waker.borrow_mut() = Some(cx.waker().clone());
            d.in_poll.set(true);
        });
        // A paused node does nothing until its restore, which wakes us.
        if with_node(|n| n.stack.is_none()) {
            DRIVER.with(|d| {
                d.woken.set(false);
                d.kick_at.set(None);
                d.in_poll.set(false);
            });
            return Poll::<()>::Pending;
        }
        // A restore replaces the timers with the saved node's (their deadlines in device time).
        if let Some(rearm) = DRIVER.with(|d| d.rearm.borrow_mut().take()) {
            timers.clear();
            for t in rearm {
                timers.push((t, Box::pin(monotonic_clock::wait_until(host_time(t)))));
            }
        }
        // Passes in this poll that re-ran only because jobs and the stack fed each other.
        let mut rounds = 0u32;
        loop {
            bump(|d| &d.passes);
            // Rule 1: clear before the pass; anything that arrives during it sets it again.
            DRIVER.with(|d| d.woken.set(false));
            let now = device_now();
            // Every wake must be served by a pass at its own instant. A later one means the
            // wake was lost (or delayed) and something else woke us: count it (tests assert 0).
            DRIVER.with(|d| {
                if d.kick_at.take().is_some_and(|k| k < now) {
                    d.late_wakes.set(d.late_wakes.get() + 1);
                }
            });
            // TCP jobs first: they move bytes between the apps' streams and smoltcp. They
            // borrow the stack only inside short closures (rule 3); a job's stream or future
            // operation registers this task's waker. Exports may queue new jobs meanwhile.
            let queued = JOBS.with(|j| std::mem::take(&mut *j.borrow_mut()));
            jobs.extend(queued);
            PROGRESS.with(|p| p.set(false));
            if !jobs.is_empty() {
                jobs.retain_mut(|job| job.as_mut().poll(cx).is_pending());
            }
            let moved =
                PROGRESS.with(|p| p.replace(false)) || JOBS.with(|j| !j.borrow().is_empty());
            // Rule 3: the stack is borrowed only inside this closure, which calls no import.
            let (out, next) = with_node(|n| {
                let stack = n.stack.as_mut().expect("the driver starts after the stack");
                let out = stack.poll(now);
                (out, stack.next_wakeup(now))
            });
            let active = out.active;
            emit(out);
            // Socket calls parked on our progress re-check now (datagrams arrived, tx drained,
            // a connection completed).
            SOCKETS.with(Notify::notify);
            // The pumps look at their sockets again whenever the stack moved, until neither side
            // has anything left at this instant.
            let more = moved || (active && !jobs.is_empty());
            if more && rounds < MAX_ROUNDS {
                rounds += 1;
                continue;
            }
            if more {
                // Still busy after MAX_ROUNDS: come back at this instant through the executor
                // (a visible self-wake, bounded by the host's poll cap) instead of spinning.
                cx.waker().wake_by_ref();
            }

            match (churn, next) {
                // Stress mode (`driver.timer-churn`): break rule 4 on
                // purpose. Every pass cancels the pending timer (a blocking `subtask.cancel`,
                // during which sibling apps may re-enter our exports) and arms a fresh one.
                (Some(period), _) => {
                    let t = next.map_or(now + period, |t| t.min(now + period));
                    // Retire the timers that already fired (dropping those cancels nothing).
                    let armed = timers.len();
                    timers.retain_mut(|(_, timer)| timer.as_mut().poll(cx).is_pending());
                    DRIVER.with(|d| {
                        d.timers_fired
                            .set(d.timers_fired.get() + (armed - timers.len()) as u64)
                    });
                    DRIVER.with(|d| {
                        d.timers_cancelled
                            .set(d.timers_cancelled.get() + timers.len() as u64)
                    });
                    timers.clear();
                    bump(|d| &d.timers_armed);
                    timers.push((t, Box::pin(monotonic_clock::wait_until(host_time(t)))));
                }
                // Rule 4: arm a new timer only if none fires at or before `t`. A stale one
                // just fires later and costs one spurious pass.
                (None, Some(t)) if !timers.iter().any(|(at, _)| *at <= t) => {
                    bump(|d| &d.timers_armed);
                    timers.push((t, Box::pin(monotonic_clock::wait_until(host_time(t)))));
                }
                (None, Some(_)) => {}
                // Fully idle (not the hot path): drop the stale timers, so the run's end is not
                // stretched to the last of them. No borrow is held here (rule 3), and a wake
                // during the cancel is caught by the flag (rule 1).
                (None, None) if !timers.is_empty() => {
                    DRIVER.with(|d| {
                        d.timers_cancelled
                            .set(d.timers_cancelled.get() + timers.len() as u64)
                    });
                    timers.clear();
                }
                (None, None) => {}
            }
            let armed = timers.len();
            timers.retain_mut(|(_, timer)| timer.as_mut().poll(cx).is_pending());
            if timers.len() != armed {
                DRIVER.with(|d| {
                    d.timers_fired
                        .set(d.timers_fired.get() + (armed - timers.len()) as u64)
                });
                continue;
            }
            // Rule 1: something happened while we were suspended in an import. Go again.
            if DRIVER.with(|d| d.woken.get()) {
                bump(|d| &d.rewakes);
                continue;
            }
            DRIVER.with(|d| {
                *d.armed.borrow_mut() = timers.iter().map(|(t, _)| *t).collect();
                d.in_poll.set(false);
            });
            return Poll::<()>::Pending;
        }
    })
    .await
}

/// The type every export is implemented on: what `export_netstack!` names.
pub struct Component;

impl device::Guest for Component {
    fn ports() -> Vec<PortInfo> {
        with_node(|n| {
            n.config
                .ports()
                .iter()
                .zip(&n.macs)
                .enumerate()
                .map(|(i, (p, mac))| PortInfo {
                    id: i as u32,
                    name: crate::stack::port_name(i),
                    mac: Some(mac.octets().to_vec()),
                    mtu: u32::from(p.mtu),
                })
                .collect()
        })
    }

    /// Push in: enqueue and wake, nothing else. Never spawns.
    fn receive(_now: u64, port: u32, frame: Vec<u8>) {
        note_entry();
        if port as usize >= with_node(|n| n.macs.len()) {
            return;
        }
        with_node(|n| match n.stack.as_mut() {
            Some(stack) => stack.receive_on(port as usize, frame),
            None if n.early.len() < EARLY_FRAMES => n.early.push((port, frame)),
            None => n.early_dropped += 1,
        });
        wake_driver();
    }

    /// An async node keeps time through `wasi:clocks`: never a deadline here.
    fn poll(_now: u64) -> Option<u64> {
        None
    }

    fn link_state(_now: u64, port: u32, up: bool) {
        note_entry();
        if port as usize >= with_node(|n| n.macs.len()) {
            return;
        }
        with_node(|n| {
            if let Some(stack) = n.stack.as_mut() {
                stack.link_state_on(port as usize, up);
            }
        });
        log::log(
            log::Level::Debug,
            &format!(
                "{} carrier {}",
                crate::stack::port_name(port as usize),
                if up { "up" } else { "down" }
            ),
        );
    }
}

impl lifecycle::Guest for Component {
    async fn start() {
        // Imports first, with no borrow held (rule 3).
        let now = device_now();
        let random_seed = wasip3::random::random::get_random_u64();
        let ident_seed = (wasip3::random::random::get_random_u64() >> 48) as u16;
        let line = with_node(|n| {
            n.seeds = (random_seed, ident_seed);
            if n.config.paused {
                // Built by `state.restore`; until then silent.
                return format!("netstack eth0: mac {}: paused until a restore", n.mac);
            }
            let mut stack = Stack::with_macs(&n.config, &n.macs, random_seed, ident_seed, now);
            for (port, frame) in n.early.drain(..) {
                stack.receive_on(port as usize, frame);
            }
            let line = stack.describe();
            n.stack = Some(stack);
            line
        });
        log::log(log::Level::Info, &line);
        wit_bindgen::spawn_local(driver());
    }
}

impl counters::Guest for Component {
    fn counters() -> Vec<(String, u64)> {
        all_counters()
    }
}

/// The `counters` export's answer (also `crate::debug::counters`): the stack's, then the
/// driver's, then each port's (`eth<N>.<name>`, only on a node with several ports).
pub(crate) fn all_counters() -> Vec<(String, u64)> {
    let mut out = with_node(|n| n.stack.as_ref().map(Stack::counters).unwrap_or_default());
    DRIVER.with(|d| {
        for (name, cell) in [
            ("driver-polls", &d.polls),
            ("driver-passes", &d.passes),
            ("driver-rewakes", &d.rewakes),
            ("driver-reentrant-calls", &d.reentrant_calls),
            ("driver-reentrant-wakes", &d.reentrant_wakes),
            ("driver-late-wakes", &d.late_wakes),
        ] {
            out.push((name.to_owned(), cell.get()));
        }
        // A wake that no pass has served yet. Read between runs, it must be 0: the
        // executor only stops once every woken task ran.
        out.push((
            "driver-unserved-wakes".to_owned(),
            u64::from(d.kick_at.get().is_some()),
        ));
        for (name, cell) in [
            ("timers-armed", &d.timers_armed),
            ("timers-fired", &d.timers_fired),
            ("timers-cancelled", &d.timers_cancelled),
            ("driver-jobs", &d.jobs),
        ] {
            out.push((name.to_owned(), cell.get()));
        }
    });
    // Each port's own counters last, on a node with several ports only.
    out.extend(with_node(|n| {
        n.stack
            .as_ref()
            .map(Stack::port_counters)
            .unwrap_or_default()
    }));
    out
}

/// `crate::debug::with_stack`: the started stack, read only. `f` must not call any import
/// (rule 3).
pub(crate) fn debug_with_stack<R>(f: impl FnOnce(&Stack) -> R) -> Option<R> {
    with_node(|n| n.stack.as_ref().map(f))
}

// ---------------------------------------------------------------------------------------------
// wasi:sockets

fn error_code(e: SockError) -> ErrorCode {
    match e {
        SockError::InvalidArgument => ErrorCode::InvalidArgument,
        SockError::InvalidState => ErrorCode::InvalidState,
        SockError::AddressInUse => ErrorCode::AddressInUse,
        SockError::AddressNotBindable => ErrorCode::AddressNotBindable,
        SockError::RemoteUnreachable => ErrorCode::RemoteUnreachable,
        SockError::DatagramTooLarge => ErrorCode::DatagramTooLarge,
        SockError::ConnectionRefused => ErrorCode::ConnectionRefused,
        SockError::ConnectionReset => ErrorCode::ConnectionReset,
        SockError::ConnectionBroken => ErrorCode::ConnectionBroken,
        SockError::Timeout => ErrorCode::Timeout,
    }
}

fn family(f: IpAddressFamily) -> Family {
    match f {
        IpAddressFamily::Ipv4 => Family::Ipv4,
        IpAddressFamily::Ipv6 => Family::Ipv6,
    }
}

fn wit_family(f: Family) -> IpAddressFamily {
    match f {
        Family::Ipv4 => IpAddressFamily::Ipv4,
        Family::Ipv6 => IpAddressFamily::Ipv6,
    }
}

fn to_std(a: IpSocketAddress) -> SocketAddr {
    match a {
        IpSocketAddress::Ipv4(v4) => {
            let (a, b, c, d) = v4.address;
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), v4.port))
        }
        IpSocketAddress::Ipv6(v6) => {
            let (a, b, c, d, e, f, g, h) = v6.address;
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(a, b, c, d, e, f, g, h),
                v6.port,
                v6.flow_info,
                v6.scope_id,
            ))
        }
    }
}

fn to_wit(a: SocketAddr) -> IpSocketAddress {
    match a {
        SocketAddr::V4(v4) => {
            let [a, b, c, d] = v4.ip().octets();
            IpSocketAddress::Ipv4(Ipv4SocketAddress {
                port: v4.port(),
                address: (a, b, c, d),
            })
        }
        SocketAddr::V6(v6) => {
            let [a, b, c, d, e, f, g, h] = v6.ip().segments();
            IpSocketAddress::Ipv6(Ipv6SocketAddress {
                port: v6.port(),
                flow_info: v6.flowinfo(),
                address: (a, b, c, d, e, f, g, h),
                scope_id: v6.scope_id(),
            })
        }
    }
}

fn wit_ip(a: IpAddr) -> ip_name_lookup::IpAddress {
    match a {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            ip_name_lookup::IpAddress::Ipv4((a, b, c, d))
        }
        IpAddr::V6(v6) => {
            let [a, b, c, d, e, f, g, h] = v6.segments();
            ip_name_lookup::IpAddress::Ipv6((a, b, c, d, e, f, g, h))
        }
    }
}

/// Runs a UDP table operation on the started stack (rule 3: no import inside).
fn udp<R>(
    f: impl FnOnce(&mut crate::udp::UdpSockets, &mut crate::udp::Net<'_>) -> Result<R, SockError>,
) -> Result<R, ErrorCode> {
    note_entry();
    with_stack(|s| {
        let (udp, mut net) = s.udp();
        f(udp, &mut net)
    })?
    .map_err(error_code)
}

/// The `udp-socket` resource: a handle on the stack's UDP table.
pub struct Udp {
    id: SocketId,
}

impl Drop for Udp {
    fn drop(&mut self) {
        note_entry();
        // Imports first (rule 3), then the table, then wake the driver so a lingering socket's
        // deadline is scheduled.
        let now = device_now();
        let id = self.id;
        let _ = with_stack(|s| {
            let (udp, net) = s.udp();
            udp.close(id, now, net.sockets);
        });
        wake_driver();
    }
}

impl sockets::GuestUdpSocket for Udp {
    fn create(address_family: IpAddressFamily) -> Result<sockets::UdpSocket, ErrorCode> {
        let id = udp(|udp, _| Ok(udp.create(family(address_family))))?;
        Ok(sockets::UdpSocket::new(Udp { id }))
    }

    fn bind(&self, local_address: IpSocketAddress) -> Result<(), ErrorCode> {
        let id = self.id;
        let bound = udp(|udp, net| udp.bind(id, to_std(local_address), net))?;
        log::log(
            log::Level::Debug,
            &format!("udp socket {id} bound to {bound}"),
        );
        wake_driver();
        Ok(())
    }

    fn connect(&self, remote_address: IpSocketAddress) -> Result<(), ErrorCode> {
        let id = self.id;
        udp(|udp, net| udp.connect(id, to_std(remote_address), net))?;
        wake_driver();
        Ok(())
    }

    fn disconnect(&self) -> Result<(), ErrorCode> {
        let id = self.id;
        udp(|udp, _| udp.disconnect(id))
    }

    async fn send(
        &self,
        data: Vec<u8>,
        remote_address: Option<IpSocketAddress>,
    ) -> Result<(), ErrorCode> {
        let (id, to) = (self.id, remote_address.map(to_std));
        let sent = parked(|| match udp(|udp, net| udp.send(id, &data, to, net)) {
            Ok(Send::WouldBlock) => None,
            Ok(Send::Queued) => Some(Ok(())),
            Err(e) => Some(Err(e)),
        })
        .await;
        if sent.is_ok() {
            // The datagram leaves at the driver's next pass, at this instant.
            wake_driver();
        }
        sent
    }

    async fn receive(&self) -> Result<(Vec<u8>, IpSocketAddress), ErrorCode> {
        let id = self.id;
        parked(|| match udp(|udp, net| udp.receive(id, net)) {
            Ok(None) => None,
            Ok(Some((data, from))) => Some(Ok((data, to_wit(from)))),
            Err(e) => Some(Err(e)),
        })
        .await
    }

    fn get_local_address(&self) -> Result<IpSocketAddress, ErrorCode> {
        let id = self.id;
        udp(|udp, _| udp.local_address(id)).map(to_wit)
    }

    fn get_remote_address(&self) -> Result<IpSocketAddress, ErrorCode> {
        let id = self.id;
        udp(|udp, _| udp.remote_address(id)).map(to_wit)
    }

    fn get_address_family(&self) -> IpAddressFamily {
        let id = self.id;
        udp(|udp, _| udp.family(id)).map_or(IpAddressFamily::Ipv4, wit_family)
    }

    fn get_unicast_hop_limit(&self) -> Result<u8, ErrorCode> {
        let id = self.id;
        udp(|udp, net| udp.unicast_hop_limit(id, net.hop_limit))
    }

    fn set_unicast_hop_limit(&self, value: u8) -> Result<(), ErrorCode> {
        let id = self.id;
        udp(|udp, net| udp.set_unicast_hop_limit(id, value, net))
    }

    fn get_receive_buffer_size(&self) -> Result<u64, ErrorCode> {
        let id = self.id;
        udp(|udp, _| udp.buffer_size(id, true))
    }

    fn set_receive_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        let id = self.id;
        udp(|udp, net| udp.set_buffer_size(id, true, value, net))
    }

    fn get_send_buffer_size(&self) -> Result<u64, ErrorCode> {
        let id = self.id;
        udp(|udp, _| udp.buffer_size(id, false))
    }

    fn set_send_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        let id = self.id;
        udp(|udp, net| udp.set_buffer_size(id, false, value, net))
    }
}

// ---------------------------------------------------------------------------------------------
// wasi:sockets TCP

/// Runs a TCP table operation on the started stack (rule 3: no import inside).
fn tcp<R>(
    f: impl FnOnce(&mut TcpSockets, &mut TcpNet<'_>) -> Result<R, SockError>,
) -> Result<R, ErrorCode> {
    note_entry();
    with_stack(|s| {
        let (tcp, mut net) = s.tcp();
        f(tcp, &mut net)
    })?
    .map_err(error_code)
}

/// Like [`tcp`], for the driver's jobs: `None` only if the stack is gone (never, once started).
fn with_tcp<R>(f: impl FnOnce(&mut TcpSockets, &mut TcpNet<'_>) -> R) -> Option<R> {
    with_node(|n| {
        n.stack.as_mut().map(|s| {
            let (tcp, mut net) = s.tcp();
            f(tcp, &mut net)
        })
    })
}

/// Resolves once `f` answers. It registers **no** waker: only the driver polls jobs, it polls
/// every job on every pass, and smoltcp state only changes in a driver pass or in an export
/// that wakes the driver.
fn state<T>(
    mut f: impl FnMut(&mut TcpSockets, &mut TcpNet<'_>) -> Option<T>,
) -> impl Future<Output = T> {
    poll_fn(move |_| match with_tcp(&mut f).flatten() {
        Some(v) => Poll::Ready(v),
        None => Poll::Pending,
    })
}

enum Either<A, B> {
    Op(A),
    Check(B),
}

/// Runs a stream or future operation `op` until it completes, or until `check` (polled while
/// `op` is pending, without a waker, like [`state`]) answers. In that case `op` is dropped,
/// which cancels it: a blocking builtin, so nothing may be borrowed here (rule 3).
async fn unless<F: Future, T>(op: F, mut check: impl FnMut() -> Option<T>) -> Either<F::Output, T> {
    let mut op = pin!(op);
    poll_fn(|cx| {
        if let Poll::Ready(v) = op.as_mut().poll(cx) {
            return Poll::Ready(Either::Op(v));
        }
        match check() {
            Some(t) => Poll::Ready(Either::Check(t)),
            None => Poll::Pending,
        }
    })
    .await
}

/// A job that only delivers `result` to a future the app holds (an error answer to a call that
/// could not start, or a pump's final result).
async fn resolve(done: FutureWriter<Result<(), ErrorCode>>, result: Result<(), ErrorCode>) {
    let _ = done.write(result).await;
}

/// The job behind `send`: the app's stream → smoltcp's transmit buffer. It reads at most the
/// free space, so every chunk fits, and the app's writer stays blocked while the buffer is full
/// (backpressure). A dropped writer is the FIN; the future resolves once every byte was
/// acknowledged, or with `connection-reset` if the connection was reset (or aborted) first.
async fn pump_send(
    id: SocketId,
    mut data: StreamReader<u8>,
    done: FutureWriter<Result<(), ErrorCode>>,
) {
    let result = loop {
        let room = match state(|t, net| t.send_room(id, net.sockets)).await {
            Ok(n) => n,
            Err(e) => break Err(e),
        };
        let read = data.read(Vec::with_capacity(room));
        let checked = unless(read, || {
            with_tcp(|t, net| t.send_check(id, net.sockets)).flatten()
        })
        .await;
        match checked {
            Either::Op((StreamResult::Complete(_), chunk)) => {
                if chunk.is_empty() {
                    continue;
                }
                match with_tcp(|t, net| t.send(id, &chunk, net.sockets)) {
                    Some(Ok(())) => progress(),
                    Some(Err(e)) => break Err(e),
                    None => break Err(SockError::InvalidState),
                }
            }
            // The app closed its end: FIN after the queued data, then wait until it is acked.
            Either::Op((StreamResult::Dropped, _)) => {
                with_tcp(|t, net| t.finish_send(id, net.sockets));
                progress();
                break state(|t, net| t.send_flushed(id, net.sockets)).await;
            }
            Either::Op((StreamResult::Cancelled, _)) => {}
            Either::Check(e) => break Err(e),
        }
    };
    // The app's next write sees its stream dropped.
    drop(data);
    let now = device_now();
    with_tcp(|t, net| t.job_done(id, now, net.sockets));
    progress();
    let _ = done.write(result.map_err(error_code)).await;
}

/// The job behind `receive`: smoltcp's receive buffer → the app's stream. Bytes leave smoltcp
/// only once the app took them, so the advertised window follows the app's reading speed. The
/// stream ends after the peer's FIN (future `ok`) or a reset (`connection-reset`). A dropped
/// stream is `SHUT_RD`: the rest is discarded, and the future still reports how the peer's
/// direction ended.
async fn pump_recv(
    id: SocketId,
    mut tx: StreamWriter<u8>,
    done: FutureWriter<Result<(), ErrorCode>>,
) {
    let result = loop {
        let buf = match state(|t, net| t.recv_step(id, net.sockets)).await {
            RecvStep::Data(buf) => buf,
            RecvStep::End(r) => break r,
        };
        let write = tx.write(buf);
        let checked = unless(write, || {
            with_tcp(|t, net| t.recv_check(id, net.sockets)).flatten()
        })
        .await;
        match checked {
            Either::Op((StreamResult::Complete(n), _)) => {
                with_tcp(|t, net| t.consume(id, n, net.sockets));
                progress();
            }
            Either::Op((StreamResult::Dropped, _)) => {
                with_tcp(|t, net| t.shutdown_read(id, net.sockets));
                progress();
                break state(|t, net| t.recv_end(id, net.sockets)).await;
            }
            Either::Op((StreamResult::Cancelled, _)) => {}
            Either::Check(e) => break Err(e),
        }
    };
    with_tcp(|t, _| t.recv_finished(id, result));
    // End of stream for the app (EOF, or the error the future reports).
    drop(tx);
    let now = device_now();
    with_tcp(|t, net| t.job_done(id, now, net.sockets));
    progress();
    let _ = done.write(result.map_err(error_code)).await;
}

/// The job behind `listen`: hands established connections to the app, one per stream item, in
/// the order their handshakes completed. Ends when the app drops the stream or the socket.
async fn accept_loop(listener: SocketId, mut tx: StreamWriter<sockets::TcpSocket>) {
    loop {
        let id = match state(|t, net| t.accept(listener, net.sockets)).await {
            Accept::Conn(id) => id,
            Accept::Closed => break,
        };
        let socket = sockets::TcpSocket::new(Tcp { id });
        let checked = unless(tx.write_one(socket), || {
            with_tcp(|t, _| t.listener_closed(listener)).flatten()
        })
        .await;
        match checked {
            Either::Op(None) => {
                with_tcp(|t, _| t.delivered(listener));
                progress();
            }
            // The app dropped the accept stream: this connection is closed with its resource.
            Either::Op(Some(socket)) => {
                drop(socket);
                with_tcp(|t, _| t.stop_listening(listener));
                break;
            }
            Either::Check(()) => break,
        }
    }
    drop(tx);
    let now = device_now();
    with_tcp(|t, net| t.job_done(listener, now, net.sockets));
    progress();
}

/// The `tcp-socket` resource: a handle on the stack's TCP table.
pub struct Tcp {
    id: SocketId,
}

impl Drop for Tcp {
    fn drop(&mut self) {
        // Imports first (rule 3), then the table, then wake the driver: a FIN or an orphan's
        // deadline may be due.
        let now = device_now();
        let id = self.id;
        let _ = with_stack(|s| {
            let (tcp, net) = s.tcp();
            tcp.close(id, now, net.sockets);
        });
        wake_driver();
    }
}

impl Tcp {
    fn keep_alive(&self, change: KeepAlive) -> Result<(), ErrorCode> {
        let id = self.id;
        tcp(|t, net| t.set_keep_alive(id, change, net.hop_limit, net.sockets))?;
        wake_driver();
        Ok(())
    }
}

impl sockets::GuestTcpSocket for Tcp {
    fn create(address_family: IpAddressFamily) -> Result<sockets::TcpSocket, ErrorCode> {
        let id = tcp(|t, _| Ok(t.create(family(address_family))))?;
        Ok(sockets::TcpSocket::new(Tcp { id }))
    }

    fn bind(&self, local_address: IpSocketAddress) -> Result<(), ErrorCode> {
        let id = self.id;
        let bound = tcp(|t, net| t.bind(id, to_std(local_address), net))?;
        log::log(
            log::Level::Debug,
            &format!("tcp socket {id} bound to {bound}"),
        );
        Ok(())
    }

    async fn connect(&self, remote_address: IpSocketAddress) -> Result<(), ErrorCode> {
        let (id, remote) = (self.id, to_std(remote_address));
        let now = device_now();
        tcp(|t, net| t.connect(id, remote, now, net))?;
        // The SYN leaves at the driver's next pass, at this instant.
        wake_driver();
        parked(|| {
            let now = device_now();
            with_tcp(|t, net| t.connect_poll(id, now, net.sockets)).flatten()
        })
        .await
        .map_err(error_code)
    }

    fn listen(&self) -> Result<StreamReader<sockets::TcpSocket>, ErrorCode> {
        let id = self.id;
        let local = tcp(|t, net| t.listen(id, net))?;
        log::log(
            log::Level::Debug,
            &format!("tcp socket {id} listening on {local}"),
        );
        let (tx, rx) = wit_stream::new::<sockets::TcpSocket>();
        with_tcp(|t, _| t.job_started(id));
        spawn_job(accept_loop(id, tx));
        Ok(rx)
    }

    fn send(&self, data: StreamReader<u8>) -> FutureReader<Result<(), ErrorCode>> {
        let id = self.id;
        let (done, reader) = wit_future::new(|| Err(ErrorCode::ConnectionAborted));
        match tcp(|t, _| t.start_send(id)) {
            Ok(()) => {
                with_tcp(|t, _| t.job_started(id));
                spawn_job(pump_send(id, data, done));
            }
            Err(e) => {
                drop(data);
                spawn_job(resolve(done, Err(e)));
            }
        }
        reader
    }

    fn receive(&self) -> (StreamReader<u8>, FutureReader<Result<(), ErrorCode>>) {
        let id = self.id;
        let (tx, rx) = wit_stream::new::<u8>();
        let (done, reader) = wit_future::new(|| Err(ErrorCode::ConnectionAborted));
        match tcp(|t, _| t.start_recv(id)) {
            Ok(()) => {
                with_tcp(|t, _| t.job_started(id));
                spawn_job(pump_recv(id, tx, done));
            }
            Err(e) => {
                drop(tx);
                spawn_job(resolve(done, Err(e)));
            }
        }
        (rx, reader)
    }

    fn get_local_address(&self) -> Result<IpSocketAddress, ErrorCode> {
        let id = self.id;
        tcp(|t, _| t.local_address(id)).map(to_wit)
    }

    fn get_remote_address(&self) -> Result<IpSocketAddress, ErrorCode> {
        let id = self.id;
        tcp(|t, _| t.remote_address(id)).map(to_wit)
    }

    fn get_is_listening(&self) -> bool {
        let id = self.id;
        tcp(|t, _| Ok(t.is_listening(id))).unwrap_or(false)
    }

    fn get_address_family(&self) -> IpAddressFamily {
        let id = self.id;
        tcp(|t, _| t.family(id)).map_or(IpAddressFamily::Ipv4, wit_family)
    }

    fn set_listen_backlog_size(&self, value: u64) -> Result<(), ErrorCode> {
        let id = self.id;
        tcp(|t, _| t.set_backlog(id, value))?;
        // A listener re-arms to the new size at the driver's next pass.
        wake_driver();
        Ok(())
    }

    fn get_keep_alive_enabled(&self) -> Result<bool, ErrorCode> {
        let id = self.id;
        tcp(|t, _| t.options(id)).map(|o| o.keep_alive)
    }

    fn set_keep_alive_enabled(&self, value: bool) -> Result<(), ErrorCode> {
        self.keep_alive(KeepAlive::Enabled(value))
    }

    fn get_keep_alive_idle_time(&self) -> Result<u64, ErrorCode> {
        let id = self.id;
        tcp(|t, _| t.options(id)).map(|o| o.keep_idle_ns)
    }

    fn set_keep_alive_idle_time(&self, value: u64) -> Result<(), ErrorCode> {
        self.keep_alive(KeepAlive::Idle(value))
    }

    fn get_keep_alive_interval(&self) -> Result<u64, ErrorCode> {
        let id = self.id;
        tcp(|t, _| t.options(id)).map(|o| o.keep_interval_ns)
    }

    fn set_keep_alive_interval(&self, value: u64) -> Result<(), ErrorCode> {
        self.keep_alive(KeepAlive::Interval(value))
    }

    fn get_keep_alive_count(&self) -> Result<u32, ErrorCode> {
        let id = self.id;
        tcp(|t, _| t.options(id)).map(|o| o.keep_count)
    }

    fn set_keep_alive_count(&self, value: u32) -> Result<(), ErrorCode> {
        self.keep_alive(KeepAlive::Count(u64::from(value)))
    }

    fn get_hop_limit(&self) -> Result<u8, ErrorCode> {
        let id = self.id;
        tcp(|t, net| Ok(t.options(id)?.hop_limit.unwrap_or(net.hop_limit)))
    }

    fn set_hop_limit(&self, value: u8) -> Result<(), ErrorCode> {
        let id = self.id;
        tcp(|t, net| t.set_hop_limit(id, value, net.hop_limit, net.sockets))
    }

    fn get_receive_buffer_size(&self) -> Result<u64, ErrorCode> {
        let id = self.id;
        tcp(|t, net| t.buffer_size(id, true, net.sockets))
    }

    fn set_receive_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        let id = self.id;
        tcp(|t, _| t.set_buffer_size(id, true, value))
    }

    fn get_send_buffer_size(&self) -> Result<u64, ErrorCode> {
        let id = self.id;
        tcp(|t, net| t.buffer_size(id, false, net.sockets))
    }

    fn set_send_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        let id = self.id;
        tcp(|t, _| t.set_buffer_size(id, false, value))
    }
}

impl sockets::Guest for Component {
    type TcpSocket = Tcp;
    type UdpSocket = Udp;
}

// ---------------------------------------------------------------------------------------------
// wasmnet:sockets-ext/tcp: freestanding functions on our own `tcp-socket`.

impl sockets_ext::Guest for Component {
    fn abort(socket: sockets::TcpSocketBorrow<'_>) {
        let id = socket.get::<Tcp>().id;
        let _ = tcp(|t, net| {
            t.abort(id, net.sockets);
            Ok(())
        });
        // The RST leaves at the driver's next pass; the pumps end there too.
        wake_driver();
    }

    fn set_no_delay(socket: sockets::TcpSocketBorrow<'_>, value: bool) -> Result<(), ErrorCode> {
        let id = socket.get::<Tcp>().id;
        tcp(|t, net| t.set_no_delay(id, value, net.hop_limit, net.sockets))?;
        wake_driver();
        Ok(())
    }

    fn get_no_delay(socket: sockets::TcpSocketBorrow<'_>) -> Result<bool, ErrorCode> {
        let id = socket.get::<Tcp>().id;
        tcp(|t, _| t.options(id)).map(|o| o.no_delay)
    }
}

// ---------------------------------------------------------------------------------------------
// wasmnet:sockets-ext/udp: the ICMP errors about a UDP socket's datagrams.

impl sockets_ext_udp::Guest for Component {
    fn set_recv_errors(socket: sockets::UdpSocketBorrow<'_>, value: bool) -> Result<(), ErrorCode> {
        let id = socket.get::<Udp>().id;
        udp(|u, _| u.set_recv_errors(id, value))
    }

    fn get_recv_errors(socket: sockets::UdpSocketBorrow<'_>) -> Result<bool, ErrorCode> {
        let id = socket.get::<Udp>().id;
        udp(|u, _| u.recv_errors(id))
    }

    async fn receive_error(
        socket: sockets::UdpSocketBorrow<'_>,
    ) -> Result<sockets_ext_udp::IcmpError, ErrorCode> {
        let id = socket.get::<Udp>().id;
        // Parks on the driver like `receive`: the stack queues errors in its passes.
        parked(|| match udp(|u, _| u.take_error(id)) {
            Ok(None) => None,
            Ok(Some(e)) => Some(Ok(sockets_ext_udp::IcmpError {
                reporter: wit_ip(e.from),
                destination: to_wit(SocketAddr::new(e.orig_dst, e.dport)),
                icmp_type: e.icmp_type,
                icmp_code: e.code,
            })),
            Err(e) => Some(Err(e)),
        })
        .await
    }
}

// ---------------------------------------------------------------------------------------------
// wasmnet:sockets-ext/multicast and /interfaces.

fn std_ip(a: ip_name_lookup::IpAddress) -> IpAddr {
    match a {
        ip_name_lookup::IpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        ip_name_lookup::IpAddress::Ipv6((a, b, c, d, e, f, g, h)) => {
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
        }
    }
}

impl sockets_ext_mc::Guest for Component {
    fn join_multicast_group(
        socket: sockets::UdpSocketBorrow<'_>,
        group: sockets_ext_mc::IpAddress,
        interface: u32,
    ) -> Result<(), ErrorCode> {
        let id = socket.get::<Udp>().id;
        udp(|u, _| u.join(id, std_ip(group), interface))?;
        // The interface joins (and its report leaves) at the driver's next pass, now.
        wake_driver();
        Ok(())
    }

    fn leave_multicast_group(
        socket: sockets::UdpSocketBorrow<'_>,
        group: sockets_ext_mc::IpAddress,
        interface: u32,
    ) -> Result<(), ErrorCode> {
        let id = socket.get::<Udp>().id;
        udp(|u, _| u.leave(id, std_ip(group), interface))?;
        wake_driver();
        Ok(())
    }

    fn set_multicast_hop_limit(
        socket: sockets::UdpSocketBorrow<'_>,
        value: u8,
    ) -> Result<(), ErrorCode> {
        let id = socket.get::<Udp>().id;
        udp(|u, _| u.set_multicast_hop_limit(id, value))
    }

    fn get_multicast_hop_limit(socket: sockets::UdpSocketBorrow<'_>) -> Result<u8, ErrorCode> {
        let id = socket.get::<Udp>().id;
        udp(|u, net| u.multicast_hop_limit(id, net.multicast_hop_limit))
    }

    fn set_multicast_loopback(
        socket: sockets::UdpSocketBorrow<'_>,
        value: bool,
    ) -> Result<(), ErrorCode> {
        let id = socket.get::<Udp>().id;
        udp(|u, _| u.set_multicast_loopback(id, value))
    }

    fn get_multicast_loopback(socket: sockets::UdpSocketBorrow<'_>) -> Result<bool, ErrorCode> {
        let id = socket.get::<Udp>().id;
        udp(|u, _| u.multicast_loopback(id))
    }

    fn set_multicast_interface(
        socket: sockets::UdpSocketBorrow<'_>,
        interface: u32,
    ) -> Result<(), ErrorCode> {
        let id = socket.get::<Udp>().id;
        udp(|u, _| u.set_multicast_interface(id, interface))
    }

    fn get_multicast_interface(socket: sockets::UdpSocketBorrow<'_>) -> Result<u32, ErrorCode> {
        let id = socket.get::<Udp>().id;
        udp(|u, _| u.multicast_interface(id))
    }
}

impl sockets_ext_if::Guest for Component {
    fn list_interfaces() -> Vec<sockets_ext_if::NetworkInterface> {
        note_entry();
        with_stack(|s| s.interfaces())
            .unwrap_or_default()
            .into_iter()
            .map(|i| sockets_ext_if::NetworkInterface {
                index: i.index,
                name: i.name,
                hardware_address: Some(i.mac.octets().to_vec()),
                addresses: i
                    .addresses
                    .into_iter()
                    .map(|(a, p)| sockets_ext_if::InterfaceAddress {
                        address: wit_ip(a),
                        prefix_length: p,
                    })
                    .collect(),
                mtu: u32::from(i.mtu),
                up: i.up,
                multicast: true,
            })
            .collect()
    }
}

/// A pending DNS lookup that the app may drop (its own timeout): dropping it forgets the
/// lookup and closes its socket. No import is called with the stack borrowed (rule 3).
struct LookupGuard {
    id: Option<crate::resolver::LookupId>,
}

impl Drop for LookupGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let now = device_now();
            let _ = with_stack(|s| s.lookup_cancel(id, now));
            wake_driver();
        }
    }
}

impl ip_name_lookup::Guest for Component {
    /// Literals and the `hosts.<name>` table answer at once; other names are looked up in DNS:
    /// the lookup runs in the driver's passes and this call parks until it ends.
    async fn resolve_addresses(
        name: String,
    ) -> Result<Vec<ip_name_lookup::IpAddress>, ip_name_lookup::ErrorCode> {
        note_entry();
        let now = device_now();
        let (start, notes) = with_stack(|s| s.lookup_start(&name, now))
            .map_err(|_| ip_name_lookup::ErrorCode::Other(Some("not started".to_owned())))?;
        emit_notes(notes);
        let resolved = match start {
            crate::resolver::Start::Done(r) => r,
            crate::resolver::Start::Pending(id) => {
                // The queries leave at the driver's next pass, at this instant.
                wake_driver();
                let mut guard = LookupGuard { id: Some(id) };
                let r = parked(|| with_stack(|s| s.lookup_take(id)).ok().flatten()).await;
                guard.id = None;
                r
            }
        };
        match resolved {
            Ok(addrs) => Ok(addrs.into_iter().map(wit_ip).collect()),
            Err(LookupError::InvalidArgument) => Err(ip_name_lookup::ErrorCode::InvalidArgument),
            Err(LookupError::NameUnresolvable) => Err(ip_name_lookup::ErrorCode::NameUnresolvable),
            Err(LookupError::TemporaryFailure) => {
                Err(ip_name_lookup::ErrorCode::TemporaryResolverFailure)
            }
            Err(LookupError::PermanentFailure) => {
                Err(ip_name_lookup::ErrorCode::PermanentResolverFailure)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// wasmnet:sockets-ext/icmp: ICMP echo sockets, Linux's ping sockets.

use exports::wasmnet::sockets_ext::icmp as sockets_ext_icmp;

/// Runs an ICMP table operation on the started stack (rule 3: no import inside).
fn icmp<R>(
    f: impl FnOnce(&mut crate::icmp::IcmpSockets, &mut crate::udp::Net<'_>) -> Result<R, SockError>,
) -> Result<R, ErrorCode> {
    note_entry();
    with_stack(|s| {
        let (icmp, mut net) = s.icmp();
        f(icmp, &mut net)
    })?
    .map_err(error_code)
}

/// The `icmp-socket` resource: a handle on the stack's ICMP table.
pub struct Icmp {
    id: crate::icmp::SocketId,
}

impl Drop for Icmp {
    fn drop(&mut self) {
        note_entry();
        let id = self.id;
        let _ = with_stack(|s| {
            let (icmp, net) = s.icmp();
            icmp.close(id, net.sockets);
        });
        wake_driver();
    }
}

impl sockets_ext_icmp::Guest for Component {
    type IcmpSocket = Icmp;
}

impl sockets_ext_icmp::GuestIcmpSocket for Icmp {
    fn create(address_family: IpAddressFamily) -> Result<sockets_ext_icmp::IcmpSocket, ErrorCode> {
        let id = icmp(|t, _| Ok(t.create(family(address_family))))?;
        Ok(sockets_ext_icmp::IcmpSocket::new(Icmp { id }))
    }

    fn bind(
        &self,
        local_address: sockets_ext_icmp::IpAddress,
        identifier: u16,
    ) -> Result<(), ErrorCode> {
        let id = self.id;
        let ident = icmp(|t, net| t.bind(id, std_ip(local_address), identifier, net))?;
        log::log(
            log::Level::Debug,
            &format!("icmp socket {id} bound, identifier {ident}"),
        );
        Ok(())
    }

    fn connect(&self, remote_address: sockets_ext_icmp::IpAddress) -> Result<(), ErrorCode> {
        let id = self.id;
        icmp(|t, net| t.connect(id, std_ip(remote_address), net))
    }

    fn disconnect(&self) -> Result<(), ErrorCode> {
        let id = self.id;
        icmp(|t, _| t.disconnect(id))
    }

    async fn send(
        &self,
        data: Vec<u8>,
        remote_address: Option<sockets_ext_icmp::IpAddress>,
    ) -> Result<(), ErrorCode> {
        let (id, to) = (self.id, remote_address.map(std_ip));
        let sent = parked(|| match icmp(|t, net| t.send(id, &data, to, net)) {
            Ok(Send::WouldBlock) => None,
            Ok(Send::Queued) => Some(Ok(())),
            Err(e) => Some(Err(e)),
        })
        .await;
        if sent.is_ok() {
            // The request leaves at the driver's next pass, at this instant.
            wake_driver();
        }
        sent
    }

    async fn receive(&self) -> Result<(Vec<u8>, sockets_ext_icmp::IpAddress), ErrorCode> {
        let id = self.id;
        parked(|| match icmp(|t, net| t.receive(id, net)) {
            Ok(None) => None,
            Ok(Some((data, from))) => Some(Ok((data, wit_ip(from)))),
            Err(e) => Some(Err(e)),
        })
        .await
    }

    async fn receive_datagram(&self) -> Result<sockets_ext_icmp::IcmpDatagram, ErrorCode> {
        let id = self.id;
        parked(|| match icmp(|t, net| t.receive_datagram(id, net)) {
            Ok(None) => None,
            Ok(Some((data, from, hop_limit))) => Some(Ok(sockets_ext_icmp::IcmpDatagram {
                data,
                remote_address: wit_ip(from),
                hop_limit,
            })),
            Err(e) => Some(Err(e)),
        })
        .await
    }

    fn get_local_address(&self) -> Result<sockets_ext_icmp::IpAddress, ErrorCode> {
        let id = self.id;
        icmp(|t, _| t.local_address(id)).map(wit_ip)
    }

    fn get_identifier(&self) -> Result<u16, ErrorCode> {
        let id = self.id;
        icmp(|t, _| t.identifier(id))
    }

    fn get_remote_address(&self) -> Result<sockets_ext_icmp::IpAddress, ErrorCode> {
        let id = self.id;
        icmp(|t, _| t.remote_address(id)).map(wit_ip)
    }

    fn get_address_family(&self) -> IpAddressFamily {
        let id = self.id;
        icmp(|t, _| t.family(id)).map_or(IpAddressFamily::Ipv4, wit_family)
    }

    fn get_unicast_hop_limit(&self) -> Result<u8, ErrorCode> {
        let id = self.id;
        icmp(|t, net| t.unicast_hop_limit(id, net.hop_limit))
    }

    fn set_unicast_hop_limit(&self, value: u8) -> Result<(), ErrorCode> {
        let id = self.id;
        icmp(|t, _| t.set_unicast_hop_limit(id, value))
    }

    fn set_recv_errors(&self, value: bool) -> Result<(), ErrorCode> {
        let id = self.id;
        icmp(|t, _| t.set_recv_errors(id, value))
    }

    fn get_recv_errors(&self) -> Result<bool, ErrorCode> {
        let id = self.id;
        icmp(|t, _| t.recv_errors(id))
    }

    async fn receive_error(&self) -> Result<sockets_ext_icmp::IcmpError, ErrorCode> {
        let id = self.id;
        // Parks on the driver like `receive`: the stack queues errors in its passes.
        parked(|| match icmp(|t, _| t.take_error(id)) {
            Ok(None) => None,
            Ok(Some(e)) => Some(Ok(sockets_ext_icmp::IcmpError {
                reporter: wit_ip(e.from),
                destination: wit_ip(e.orig_dst),
                sequence: e.dport,
                icmp_type: e.icmp_type,
                icmp_code: e.code,
            })),
            Err(e) => Some(Err(e)),
        })
        .await
    }
}

// ---------------------------------------------------------------------------------------------
// wasmnet:netstack/state: quiescent save and restore. The stack's
// part is `crate::snapshot`; the node's part (the device instant, the driver's counters and
// timers) is here. Control calls: no import is called while the node is borrowed (rule 3).

use exports::wasmnet::netstack::state as ns_state;

const NODE_MAGIC: &[u8; 6] = b"NSNODE";
const NODE_VERSION: u8 = 1;

/// The driver's counters, in the order a state stores them.
fn driver_counters(d: &Driver) -> [&Cell<u64>; 10] {
    [
        &d.polls,
        &d.passes,
        &d.rewakes,
        &d.reentrant_wakes,
        &d.reentrant_calls,
        &d.late_wakes,
        &d.timers_armed,
        &d.timers_fired,
        &d.timers_cancelled,
        &d.jobs,
    ]
}

fn save_node() -> Result<Vec<u8>, String> {
    let now = device_now();
    let busy = DRIVER.with(|d| d.in_poll.get() || d.woken.get() || d.kick_at.get().is_some())
        || JOBS.with(|j| !j.borrow().is_empty());
    if busy {
        return Err("the netstack's driver has work pending at this instant".into());
    }
    let stack = with_node(|n| match &n.stack {
        Some(s) => s.save(),
        None if n.config.paused => Err("the netstack is paused (not restored yet)".into()),
        None => Err("the netstack has not started".into()),
    })?;
    let mut w = crate::snapshot::W::default();
    w.0.extend_from_slice(NODE_MAGIC);
    w.u8(NODE_VERSION);
    w.u64(now);
    DRIVER.with(|d| {
        for c in driver_counters(d) {
            w.u64(c.get());
        }
        let armed = d.armed.borrow();
        w.count(armed.len());
        for t in armed.iter() {
            w.u64(*t);
        }
    });
    w.bytes(&stack);
    Ok(w.0)
}

fn restore_node(bytes: &[u8]) -> Result<(), String> {
    let host_now = monotonic_clock::now();
    let mut r = crate::snapshot::R::new(bytes);
    let magic: Vec<u8> = (0..NODE_MAGIC.len())
        .map(|_| r.u8())
        .collect::<Result<_, _>>()?;
    if magic != NODE_MAGIC {
        return Err("not a netstack node state".into());
    }
    let version = r.u8()?;
    if version != NODE_VERSION {
        return Err(format!(
            "netstack node state version {version}, expected {NODE_VERSION}"
        ));
    }
    let saved_at = r.u64()?;
    let mut counters = [0u64; 10];
    for c in &mut counters {
        *c = r.u64()?;
    }
    let mut armed = Vec::new();
    for _ in 0..r.count()? {
        armed.push(r.u64()?);
    }
    let stack_bytes = r.bytes()?;
    r.end()?;
    let line = with_node(|n| {
        if !n.config.paused || n.stack.is_some() {
            return Err(
                "a netstack state restores onto a paused node only (`snapshot.paused`)".to_owned(),
            );
        }
        let (seed, ident) = n.seeds;
        let mut stack = Stack::with_macs(&n.config, &n.macs, seed, ident, saved_at);
        stack.restore(&stack_bytes)?;
        for (port, frame) in n.early.drain(..) {
            stack.receive_on(port as usize, frame);
        }
        let dropped = match std::mem::take(&mut n.early_dropped) {
            0 => String::new(),
            d => format!("; {d} frames arrived while paused and were dropped"),
        };
        let line = format!(
            "{} (restored at device instant {saved_at} ns{dropped})",
            stack.describe()
        );
        let (tcp, udp) = (stack.tcp().0.ids(), stack.udp().0.ids());
        UNCLAIMED.with(|u| {
            let mut u = u.borrow_mut();
            u.0 = tcp.into_iter().collect();
            u.1 = udp.into_iter().collect();
        });
        n.stack = Some(stack);
        Ok(line)
    })?;
    // The device's clock reads the saved instant now, and runs on from there.
    let shift = i128::from(saved_at) - i128::from(host_now);
    SHIFT.with(|s| s.set(shift.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64));
    DRIVER.with(|d| {
        for (c, v) in driver_counters(d).into_iter().zip(counters) {
            c.set(v);
        }
        *d.rearm.borrow_mut() = Some(armed);
    });
    log::log(log::Level::Info, &line);
    wake_driver();
    Ok(())
}

fn unclaimed(tcp: bool, id: SocketId) -> Result<(), String> {
    UNCLAIMED.with(|u| {
        let mut u = u.borrow_mut();
        let set = if tcp { &mut u.0 } else { &mut u.1 };
        if set.remove(&id) {
            Ok(())
        } else {
            Err(format!(
                "no restored {} socket {id} to reclaim",
                if tcp { "TCP" } else { "UDP" }
            ))
        }
    })
}

impl ns_state::Guest for Component {
    fn paused() -> bool {
        with_node(|n| n.config.paused && n.stack.is_none())
    }

    fn save() -> Result<Vec<u8>, String> {
        note_entry();
        save_node()
    }

    fn restore(state: Vec<u8>) -> Result<(), String> {
        note_entry();
        restore_node(&state)
    }

    fn tcp_id(socket: sockets::TcpSocketBorrow<'_>) -> u32 {
        socket.get::<Tcp>().id
    }

    fn udp_id(socket: sockets::UdpSocketBorrow<'_>) -> u32 {
        socket.get::<Udp>().id
    }

    fn reclaim_tcp(id: u32) -> Result<sockets::TcpSocket, String> {
        let listener = with_tcp(|t, _| t.listeners().contains(&id)).unwrap_or(false);
        if listener {
            return Err(format!("TCP socket {id} listens: reclaim it as a listener"));
        }
        unclaimed(true, id)?;
        Ok(sockets::TcpSocket::new(Tcp { id }))
    }

    fn reclaim_udp(id: u32) -> Result<sockets::UdpSocket, String> {
        unclaimed(false, id)?;
        Ok(sockets::UdpSocket::new(Udp { id }))
    }

    fn reclaim_listener(
        id: u32,
    ) -> Result<(sockets::TcpSocket, StreamReader<sockets::TcpSocket>), String> {
        let listener = with_tcp(|t, _| t.listeners().contains(&id)).unwrap_or(false);
        if !listener {
            return Err(format!("TCP socket {id} is not a restored listener"));
        }
        unclaimed(true, id)?;
        // What `listen` does after arming: the accept loop, as a driver job.
        let (tx, rx) = wit_stream::new::<sockets::TcpSocket>();
        with_tcp(|t, _| t.job_started(id));
        spawn_job(accept_loop(id, tx));
        Ok((sockets::TcpSocket::new(Tcp { id }), rx))
    }
}

// The plain netstack component (`netstack.wasm`). An embedder builds without `export` and
// invokes `netstack::export_netstack!` itself.
#[cfg(all(feature = "export", target_family = "wasm"))]
export_netstack!(Component with_types_in self);
