//! The JavaScript backend of the simulator: [`JsRuntime`] implements [`wasmnet_core::Runtime`] over
//! a [`JsHost`], and [`Registry`] is the per-device state the JavaScript side reaches through the
//! device-side exports (`wire.transmit`, `log`, clocks, entropy, config, timers, async call
//! completions).
//!
//! **Re-entrancy.** An actor calls into JavaScript (`receive`), the guest calls an import, and the
//! import calls back into this crate (`transmit`) while the actor is still being polled. So
//! nothing here holds a `RefCell` borrow across a [`JsHost`] call, and the actor keeps its own
//! state in the future rather than in the registry.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use wasmnet_core::{
    Command, DeviceConfig, DeviceContext, DeviceInstance, Fault, Inbox, JournalEnd, Level, Nanos,
    OutputCapture, Record, Result as SimResult, Runtime, SimRng, Sleep, Status, VirtualClock, Wire,
    derive_seed,
};

use crate::host::{CallEnd, JsHost};

/// Entropy streams, seeded like the native host's, so a device draws the same numbers from the
/// same seed on both backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Entropy {
    /// `wasi:random/random` (seed stream `random`).
    Secure,
    /// `wasi:random/insecure` (seed stream `insecure`).
    Insecure,
}

struct DeviceState {
    clock: VirtualClock,
    wire: Wire,
    journal: JournalEnd,
    config: DeviceConfig,
    stdout: OutputCapture,
    stderr: OutputCapture,
    secure: SimRng,
    insecure: SimRng,
    insecure_seed: (u64, u64),
    /// The actor's waker, for completions and timers that arrive from JavaScript between polls.
    waker: Option<Waker>,
    completions: VecDeque<(u32, CallEnd)>,
    new_timers: Vec<(u32, Nanos)>,
}

#[derive(Default)]
struct Inner {
    /// The network's clock (also every device's).
    clock: Option<VirtualClock>,
    devices: BTreeMap<u32, DeviceState>,
    next_timer: u32,
    /// Something reached an actor from JavaScript since the last [`Registry::take_dirty`].
    dirty: bool,
    /// Calls for devices that do not exist: counted, never fatal.
    orphans: u64,
}

/// Per-device state shared between the actors and the device-side exports. Cheap to clone.
///
/// Every method borrows the state only for its own duration and never calls JavaScript, so any
/// of them may be called at any time, also from inside a [`JsHost`] call.
#[derive(Clone, Default)]
pub struct Registry {
    inner: Rc<RefCell<Inner>>,
}

impl Registry {
    fn with_device<T>(&self, dev: u32, f: impl FnOnce(&mut DeviceState) -> T) -> Option<T> {
        let mut inner = self.inner.borrow_mut();
        match inner.devices.get_mut(&dev) {
            Some(d) => Some(f(d)),
            None => {
                inner.orphans += 1;
                None
            }
        }
    }

    /// Wakes the device's actor (outside the executor: the next step polls it).
    fn wake(&self, dev: u32) {
        let waker = {
            let mut inner = self.inner.borrow_mut();
            inner.dirty = true;
            inner.devices.get_mut(&dev).and_then(|d| d.waker.clone())
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Uses `clock` for [`now`](Self::now) and [`wall_now_ns`](Self::wall_now_ns).
    pub(crate) fn set_clock(&self, clock: VirtualClock) {
        self.inner.borrow_mut().clock = Some(clock);
    }

    /// Forgets device `dev` (its instantiation failed).
    pub(crate) fn remove(&self, dev: u32) {
        self.inner.borrow_mut().devices.remove(&dev);
    }

    /// Forgets every device (their network is gone).
    pub(crate) fn clear(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.devices.clear();
        inner.clock = None;
    }

    /// `wasmnet:link/wire.transmit`: only enqueues (the frame arrives at now + latency).
    pub fn transmit(&self, dev: u32, port: u32, frame: Vec<u8>) {
        if let Some(wire) = self.with_device(dev, |d| d.wire.clone()) {
            wire.transmit(port, frame);
        }
    }

    /// `wasmnet:link/log.log`, stamped with virtual time.
    pub fn log(&self, dev: u32, level: Level, message: String) {
        if let Some((journal, now)) = self.with_device(dev, |d| (d.journal.clone(), d.clock.now()))
        {
            journal.log(now, level, message);
        }
    }

    /// `wasmnet:link/log.event`, stamped with virtual time.
    pub fn event(&self, dev: u32, kind: String, fields: Vec<(String, String)>) {
        if let Some((journal, now)) = self.with_device(dev, |d| (d.journal.clone(), d.clock.now()))
        {
            journal.event(now, kind, fields);
        }
    }

    /// Bytes the guest wrote to stdout (`stderr = false`) or stderr.
    pub fn output(&self, dev: u32, stderr: bool, bytes: &[u8]) {
        if let Some(capture) = self.with_device(dev, |d| {
            if stderr {
                d.stderr.clone()
            } else {
                d.stdout.clone()
            }
        }) {
            capture.append(bytes);
        }
    }

    /// `wasi:config/store.get`: the device's value for `key`.
    pub fn config_get(&self, dev: u32, key: &str) -> Option<String> {
        self.with_device(dev, |d| d.config.get(key).cloned())
            .flatten()
    }

    /// `wasi:config/store.get-all`: the device's whole config, sorted by key.
    pub fn config(&self, dev: u32) -> Option<DeviceConfig> {
        self.with_device(dev, |d| d.config.clone())
    }

    /// The next 64 random bits of the device's `which` stream (0 for an unknown device).
    pub fn random_u64(&self, dev: u32, which: Entropy) -> u64 {
        self.with_device(dev, |d| match which {
            Entropy::Secure => d.secure.next_u64(),
            Entropy::Insecure => d.insecure.next_u64(),
        })
        .unwrap_or(0)
    }

    /// Fills `buf` from the device's `which` stream (little-endian u64 chunks, like `SimRng`).
    pub fn random_fill(&self, dev: u32, which: Entropy, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.random_u64(dev, which).to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    /// `wasi:random/insecure-seed`.
    pub fn insecure_seed(&self, dev: u32) -> (u64, u64) {
        self.with_device(dev, |d| d.insecure_seed)
            .unwrap_or_default()
    }

    /// A virtual timer for the device at `at`: [`JsHost::timer_fire`] reports it with the id
    /// returned here. It enters the event queue at the actor's next poll.
    pub fn timer(&self, dev: u32, at: Nanos) -> u32 {
        let id = {
            let mut inner = self.inner.borrow_mut();
            let id = inner.next_timer;
            inner.next_timer = inner.next_timer.wrapping_add(1);
            if let Some(d) = inner.devices.get_mut(&dev) {
                d.new_timers.push((id, at));
            } else {
                inner.orphans += 1;
            }
            id
        };
        self.wake(dev);
        id
    }

    /// An async export call (`start`, an app's `run`) ended.
    pub fn call_done(&self, dev: u32, call: u32, end: CallEnd) {
        self.with_device(dev, |d| d.completions.push_back((call, end)));
        self.wake(dev);
    }

    /// Whether anything reached an actor from JavaScript since the last call (then the network
    /// must run a round at the current instant before time may move).
    pub fn take_dirty(&self) -> bool {
        std::mem::take(&mut self.inner.borrow_mut().dirty)
    }

    /// Current virtual time (0 before the network exists).
    pub fn now(&self) -> Nanos {
        self.inner
            .borrow()
            .clock
            .as_ref()
            .map_or(0, VirtualClock::now)
    }

    /// The wall clock (the network's epoch plus virtual time), in ns since the Unix epoch.
    pub fn wall_now_ns(&self) -> u64 {
        self.inner.borrow().clock.as_ref().map_or(0, |c| {
            u64::try_from(c.wall_now().as_nanos()).unwrap_or(u64::MAX)
        })
    }

    /// Calls for unknown devices so far.
    pub fn orphans(&self) -> u64 {
        self.inner.borrow().orphans
    }
}

/// The JavaScript backend: devices are JavaScript objects behind `H`.
pub struct JsRuntime<H> {
    host: H,
    registry: Registry,
}

impl<H: JsHost + Clone + Unpin + 'static> JsRuntime<H> {
    pub fn new(host: H) -> Self {
        Self {
            host,
            registry: Registry::default(),
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn host(&self) -> &H {
        &self.host
    }
}

impl<H: JsHost + Clone + Unpin + 'static> Runtime for JsRuntime<H> {
    /// The component's key; JavaScript maps it to a transpiled module.
    type Component = str;

    fn instantiate(&self, ctx: DeviceContext, component: &str) -> SimResult<DeviceInstance> {
        let dev = u32::try_from(ctx.index).map_err(|_| wasmnet_core::Error::Runtime {
            message: format!("too many devices for `{}`", ctx.name),
            detail: None,
        })?;
        let seed = |stream| derive_seed(ctx.seed, &ctx.name, stream);
        let mut seed_rng = SimRng::from_seed(seed("insecure-seed"));
        let insecure_seed = (seed_rng.next_u64(), seed_rng.next_u64());
        {
            // Registered before JavaScript instantiates, so imports used meanwhile are served.
            let mut inner = self.registry.inner.borrow_mut();
            inner.clock.get_or_insert_with(|| ctx.clock.clone());
            inner.devices.insert(
                dev,
                DeviceState {
                    clock: ctx.clock.clone(),
                    wire: ctx.wire.clone(),
                    journal: ctx.journal.clone(),
                    config: ctx.config.clone(),
                    stdout: ctx.stdout.clone(),
                    stderr: ctx.stderr.clone(),
                    secure: SimRng::from_seed(seed("random")),
                    insecure: SimRng::from_seed(seed("insecure")),
                    insecure_seed,
                    waker: None,
                    completions: VecDeque::new(),
                    new_timers: Vec::new(),
                },
            );
        }
        let instance = match self
            .host
            .instantiate(dev, &ctx.name, component, &ctx.config)
        {
            Ok(i) => i,
            Err(message) => {
                self.registry.remove(dev);
                return Err(wasmnet_core::Error::Runtime {
                    message: format!("component `{component}` for `{}`: {message}", ctx.name),
                    detail: None,
                });
            }
        };
        let actor = Actor {
            host: self.host.clone(),
            registry: self.registry.clone(),
            dev,
            clock: ctx.clock,
            journal: ctx.journal,
            inbox: ctx.inbox,
            status: ctx.status,
            lifecycle: instance.lifecycle,
            apps: instance.apps.clone(),
            started: false,
            initialised: !instance.lifecycle,
            apps_started: false,
            next_call: 0,
            calls: BTreeMap::new(),
            timers: Vec::new(),
        };
        // No optional exports are served: control calls never reach these devices.
        Ok(DeviceInstance::new(instance.ports, Box::pin(actor))
            .has_counters(instance.counters)
            .apps(instance.apps))
    }
}

enum CallKind {
    Start,
    App(String),
}

/// One device's actor: `start()` first, then the apps' `run`s as daemons, then inbox commands as
/// sync JavaScript calls; plus the device's virtual timers.
struct Actor<H> {
    host: H,
    registry: Registry,
    dev: u32,
    clock: VirtualClock,
    journal: JournalEnd,
    inbox: Inbox,
    status: Status,
    lifecycle: bool,
    apps: Vec<String>,
    started: bool,
    initialised: bool,
    apps_started: bool,
    next_call: u32,
    /// In-flight async calls: JavaScript call id -> (status id, kind).
    calls: BTreeMap<u32, (u64, CallKind)>,
    timers: Vec<(u32, Pin<Box<Sleep>>)>,
}

impl<H: JsHost> Actor<H> {
    fn begin(&mut self, kind: CallKind, what: String) -> u32 {
        let call = self.next_call;
        self.next_call += 1;
        // Every async call is a daemon: JavaScript runs it on promises, between the network's
        // steps, so "outstanding with nothing queued" is not a deadlock here.
        let id = self.status.begin(what, true);
        self.calls.insert(call, (id, kind));
        call
    }

    /// Journals an app's end the way the native host does (a log line and an `app-exit` event).
    fn app_exit(&self, name: &str, ok: bool) {
        let status = if ok { "ok" } else { "error" };
        let now = self.clock.now();
        self.journal.push(
            now,
            Record::Log {
                level: Level::Info,
                message: format!("app {name} exited: {status}"),
            },
        );
        self.journal.push(
            now,
            Record::Event {
                kind: "app-exit".to_owned(),
                fields: vec![
                    ("app".to_owned(), name.to_owned()),
                    ("status".to_owned(), status.to_owned()),
                ],
            },
        );
    }

    /// One pass over everything the actor can do now. `Ok(true)` if anything happened.
    fn pass(&mut self, cx: &mut Context<'_>) -> Result<bool, Fault> {
        let mut progress = false;
        let trap = |m: String| Fault::new(m);

        if self.lifecycle && !self.started {
            self.started = true;
            let call = self.begin(CallKind::Start, "start".to_owned());
            self.host.start(self.dev, call).map_err(trap)?;
            progress = true;
        }

        // Completions and new timers that JavaScript reported since the last poll.
        let (done, new_timers) = self
            .registry
            .with_device(self.dev, |d| {
                d.waker = Some(cx.waker().clone());
                (
                    std::mem::take(&mut d.completions),
                    std::mem::take(&mut d.new_timers),
                )
            })
            .unwrap_or_default();
        for (call, end) in done {
            progress = true;
            let Some((id, kind)) = self.calls.remove(&call) else {
                continue;
            };
            self.status.end(id);
            if let CallEnd::Trap(message) = end {
                return Err(trap(message));
            }
            match kind {
                CallKind::Start => self.initialised = true,
                CallKind::App(name) => self.app_exit(&name, end == CallEnd::Ok),
            }
        }
        for (id, at) in new_timers {
            self.timers.push((id, Box::pin(self.clock.sleep_until(at))));
        }
        let mut i = 0;
        while i < self.timers.len() {
            if self.timers[i].1.as_mut().poll(cx).is_ready() {
                let (id, _) = self.timers.remove(i);
                self.host.timer_fire(id);
                progress = true;
            } else {
                i += 1;
            }
        }

        if self.initialised && !self.apps_started {
            self.apps_started = true;
            for (n, name) in self.apps.clone().into_iter().enumerate() {
                let call = self.begin(CallKind::App(name.clone()), format!("app-{name}.run"));
                let n = u32::try_from(n).map_err(|_| trap("too many apps".to_owned()))?;
                self.host.run_app(self.dev, n, call).map_err(trap)?;
            }
            progress = true;
        }

        while self.initialised
            && let Some(command) = self.inbox.poll_pop(cx)
        {
            progress = true;
            let now = self.clock.now();
            let idx = self.dev as usize;
            match command {
                Command::Receive { port, frame } => {
                    self.host
                        .receive(self.dev, port, now, &frame)
                        .map_err(trap)?;
                    self.clock.poll_by(idx, now);
                }
                Command::LinkState { port, up } => {
                    self.host
                        .link_state(self.dev, port, up, now)
                        .map_err(trap)?;
                    self.clock.poll_by(idx, now);
                }
                Command::Poll => {
                    let next = self.host.poll(self.dev, now).map_err(trap)?;
                    self.clock.set_poll(idx, next.map(|t| t.max(now)));
                }
                Command::Counters(reply) => {
                    let values = self.host.counters(self.dev).map_err(trap)?;
                    *reply
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(values);
                }
                // This backend reports no optional exports, so the network sends none; refuse
                // one anyway rather than leave its caller waiting.
                Command::Control(call) => {
                    let reschedule = call.may_reschedule();
                    call.unsupported();
                    if reschedule {
                        self.clock.poll_by(idx, now);
                    }
                }
                // Only operator events write stdin, and this crate's network API makes none.
                Command::Stdin(_) => {}
            }
        }
        Ok(progress)
    }
}

impl<H: JsHost + Unpin> Future for Actor<H> {
    type Output = Result<(), Fault>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            match this.pass(cx) {
                Ok(true) => continue,
                Ok(false) => break,
                Err(fault) => return Poll::Ready(Err(fault)),
            }
        }
        this.status
            .set_guest_tasks_alive(!this.timers.is_empty() || !this.calls.is_empty());
        Poll::Pending
    }
}
