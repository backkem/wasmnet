//! The JavaScript backend of the simulator: [`JsRuntime`] implements [`wasmnet_core::Runtime`] over
//! a [`JsHost`], and [`Registry`] is the per-device state the JavaScript side reaches through the
//! device-side exports (`wire.transmit`, `log`, clocks, entropy, config, arguments and
//! environment, `wasmnet:infra`, timers, async call completions).
//!
//! Everything a device is served comes from the sim core, as on the wasmtime backend: its
//! entropy ([`DeviceEntropy`]), its `argv` ([`wasmnet_core::argv`]), its `wasmnet:infra` calls
//! ([`Calls`]), the answers of its control calls ([`wasmnet_core::CommandCall`],
//! [`wasmnet_core::ReconfigureCall`], every one an export call by name) and its `app-exit`
//! records ([`JournalEnd::app_exit`]). This module only routes.
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

use wasmnet_core::ext::ControlCall;
use wasmnet_core::infra::Calls;
use wasmnet_core::{
    COMMANDS_EXPORT, Command, DeviceConfig, DeviceContext, DeviceEntropy, DeviceInstance, Fault,
    Inbox, InfraEnd, InputQueue, JournalEnd, Level, MemoryBudget, Nanos, OutputCapture,
    RECONFIGURE_EXPORT, Result as SimResult, Runtime, Sleep, Status, VirtualClock, Wire,
};

use crate::codec::Value;
use crate::host::{CallEnd, JsHost};
use crate::infra::{self, Reply};

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
    /// Which instantiation of the device this is (a stopped device that starts again is a new
    /// one): calls of an older instance's guest, still settling in JavaScript, never reach it.
    generation: u64,
    clock: VirtualClock,
    wire: Wire,
    journal: JournalEnd,
    /// What `wasi:config/store` serves (a reconfiguration the device took replaces it).
    config: DeviceConfig,
    /// `wasi:cli/environment`.
    argv: Vec<String>,
    env: Vec<(String, String)>,
    /// `wasmnet:infra`, if the network granted it.
    infra: Option<InfraEnd>,
    /// The servers of the portable interfaces the network's extensions gave it.
    servers: Vec<(String, std::sync::Arc<dyn wasmnet_core::ImportServer>)>,
    /// Where a server's fault leaves its message (the crash record).
    status: wasmnet_core::Status,
    stdout: OutputCapture,
    stderr: OutputCapture,
    entropy: DeviceEntropy,
    /// Its stdin: what `Op::Stdin` wrote and the guest has not read yet.
    stdin: InputQueue,
    /// The actor's waker, for completions and timers that arrive from JavaScript between polls.
    waker: Option<Waker>,
    completions: VecDeque<(u32, CallEnd)>,
    new_timers: Vec<(u32, Nanos)>,
    new_waits: Vec<(u32, infra::Wait)>,
}

#[derive(Default)]
struct Inner {
    /// The network's clock (also every device's).
    clock: Option<VirtualClock>,
    devices: BTreeMap<u32, DeviceState>,
    next_timer: u32,
    next_wait: u32,
    next_generation: u64,
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

    /// Forgets device `dev` if it is still instantiation `generation` (its actor is gone: the
    /// device stopped, crashed or was removed). Calls for it are orphans from then on.
    /// Answers whether it was (a newer instance of the device may have replaced it already).
    fn retire(&self, dev: u32, generation: u64) -> bool {
        let mut inner = self.inner.borrow_mut();
        let current = inner
            .devices
            .get(&dev)
            .is_some_and(|d| d.generation == generation);
        if current {
            inner.devices.remove(&dev);
        }
        current
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

    /// `wasi:cli/environment.get-arguments`: `argv`, the device's name first (empty for an
    /// unknown device).
    pub fn args(&self, dev: u32) -> Vec<String> {
        self.with_device(dev, |d| d.argv.clone())
            .unwrap_or_default()
    }

    /// The device's stdin read now: everything queued, empty when nothing is (then
    /// [`JsHost::stdin_ready`] says when more comes).
    pub fn stdin(&self, dev: u32) -> Vec<u8> {
        self.with_device(dev, |d| d.stdin.take(usize::MAX))
            .unwrap_or_default()
    }

    /// `wasi:cli/environment.get-environment`, in order.
    pub fn env(&self, dev: u32) -> Vec<(String, String)> {
        self.with_device(dev, |d| d.env.clone()).unwrap_or_default()
    }

    /// One call of a portable interface the device imports (`interface#function`, the
    /// function by its component-model name), served by the server the network's extensions
    /// gave the device ([`wasmnet_core::DeviceExt::serve`]), at once. A fault leaves its
    /// message for the device's crash record and comes back as [`Reply::Failed`], which
    /// JavaScript raises as a trap.
    pub fn import(&self, dev: u32, call: &str, args: Vec<Value>) -> Reply {
        use wasmnet_core::Served;
        let Some((interface, function)) = call.split_once('#') else {
            return Reply::Failed(format!("not `interface#function`: {call}"));
        };
        let found = self.with_device(dev, |d| {
            let server = d
                .servers
                .iter()
                .find(|(i, _)| i == interface)
                .map(|(_, s)| s.clone());
            (server, d.status.clone())
        });
        let Some((server, status)) = found else {
            return Reply::Failed(format!("no device {dev}"));
        };
        // The server is called outside the registry: it may journal, or reach other state.
        let served = match server {
            Some(server) => server.call(interface, function, args),
            None => Served::Fault(format!(
                "{interface} is not served to this device (no extension gave it a server)"
            )),
        };
        match served {
            Served::Ok(v) => Reply::Value(v),
            Served::Err(v) => Reply::Error(v),
            Served::Fault(message) => {
                status.set_fault(message.clone());
                Reply::Failed(message)
            }
        }
    }

    /// The device dropped its handle `handle` to `interface#resource`.
    pub fn import_drop(&self, dev: u32, resource: &str, handle: u32) {
        let Some((interface, res)) = resource.split_once('#') else {
            return;
        };
        let server = self
            .with_device(dev, |d| {
                d.servers
                    .iter()
                    .find(|(i, _)| i == interface)
                    .map(|(_, s)| s.clone())
            })
            .flatten();
        if let Some(server) = server {
            server.drop_resource(interface, res, handle);
        }
    }

    /// One `wasmnet:infra` call of the device (`devices.apply`, ...; [`infra::FUNCTIONS`]),
    /// served by the sim core from its grant. Calls only record and queue, so this never runs
    /// a device.
    pub fn infra(&self, dev: u32, function: &str, args: &[Value]) -> Reply {
        match self.with_device(dev, |d| d.infra.clone()) {
            Some(end) => infra::serve(Calls::new(end.as_ref()), function, args),
            None => Reply::Failed(format!("no device {dev}")),
        }
    }

    /// A waiting `wasmnet:infra` call of the device (`changes.wait`, `changes.wait-any`;
    /// [`infra::WAITS`]): a wait id, whose answer [`JsHost::wait_done`] delivers (during a later
    /// step), or the answer at once. Wakes the device.
    pub fn infra_wait(&self, dev: u32, function: &str, args: &[Value]) -> Result<u32, Reply> {
        let Some(end) = self.with_device(dev, |d| d.infra.clone()) else {
            return Err(Reply::Failed(format!("no device {dev}")));
        };
        let wait = infra::start_wait(Calls::new(end.as_ref()), function, args)?;
        let id = {
            let mut inner = self.inner.borrow_mut();
            let id = inner.next_wait;
            inner.next_wait = inner.next_wait.wrapping_add(1);
            if let Some(d) = inner.devices.get_mut(&dev) {
                d.new_waits.push((id, wait));
            }
            id
        };
        self.wake(dev);
        Ok(id)
    }

    /// The next 64 random bits of the device's `which` stream (0 for an unknown device).
    pub fn random_u64(&self, dev: u32, which: Entropy) -> u64 {
        self.with_device(dev, |d| match which {
            Entropy::Secure => d.entropy.secure.next_u64(),
            Entropy::Insecure => d.entropy.insecure.next_u64(),
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

    /// `wasi:random/insecure-seed`, as the guest receives it.
    pub fn insecure_seed(&self, dev: u32) -> (u64, u64) {
        self.with_device(dev, |d| d.entropy.insecure_seed)
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
    /// The import names of the components controllers supplied, by digest: parsed by the core
    /// when they were compiled, for the grant check at instantiation.
    supplied: RefCell<BTreeMap<String, Vec<String>>>,
}

impl<H: JsHost + Clone + Unpin + 'static> JsRuntime<H> {
    pub fn new(host: H) -> Self {
        Self {
            host,
            registry: Registry::default(),
            supplied: RefCell::default(),
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    /// Forgets every device and supplied component (its network was dropped): what the runtime
    /// still holds afterwards is its few empty maps.
    pub(crate) fn forget(&self) {
        self.registry.clear();
        self.supplied.borrow_mut().clear();
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
        // The core's rule, as on wasmtime: a component that imports `wasmnet:infra` is refused
        // for a device without the grant, before JavaScript instantiates anything. JavaScript
        // reports the component's imports if it knows them.
        let known = self.supplied.borrow().get(component).cloned();
        if let Some(imports) = known.or_else(|| self.host.imports(component)) {
            wasmnet_core::infra::require_grant(&ctx.name, &imports, ctx.infra.is_some())
                .map_err(wasmnet_core::Error::Refused)?;
        }
        let generation;
        {
            // Registered before JavaScript instantiates, so imports used meanwhile are served.
            let mut inner = self.registry.inner.borrow_mut();
            inner.clock.get_or_insert_with(|| ctx.clock.clone());
            generation = inner.next_generation;
            inner.next_generation += 1;
            inner.devices.insert(
                dev,
                DeviceState {
                    clock: ctx.clock.clone(),
                    wire: ctx.wire.clone(),
                    journal: ctx.journal.clone(),
                    config: ctx.config.clone(),
                    argv: wasmnet_core::argv(&ctx.name, &ctx.args),
                    env: ctx.env.clone(),
                    infra: ctx.infra.clone(),
                    servers: ctx
                        .ext
                        .servers()
                        .map(|(i, s)| (i.to_owned(), s.clone()))
                        .collect(),
                    status: ctx.status.clone(),
                    stdout: ctx.stdout.clone(),
                    stderr: ctx.stderr.clone(),
                    entropy: DeviceEntropy::new(ctx.seed, &ctx.name),
                    stdin: InputQueue::new(),
                    waker: None,
                    completions: VecDeque::new(),
                    new_timers: Vec::new(),
                    new_waits: Vec::new(),
                    generation,
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
        // Its memory at the start: counted, and a limit too small for it fails the creation, as
        // natively.
        let mut memory = MemoryBudget::new(ctx.memory, ctx.inbox.cost().clone());
        if let Some(total) = self.host.memory(dev)
            && let Err(message) = memory.observe(total)
        {
            self.registry.remove(dev);
            self.host.release(dev);
            return Err(wasmnet_core::Error::Runtime {
                message,
                detail: None,
            });
        }
        // Every interface it exports, by name without a version, sorted: what control calls reach
        // by name (as the wasmtime backend reports them).
        let mut exports: Vec<String> = instance
            .exports
            .iter()
            .map(|e| wasmnet_core::export::unversioned(e).to_owned())
            .collect();
        if instance.commands {
            exports.push(COMMANDS_EXPORT.to_owned());
        }
        if instance.reconfigure {
            exports.push(RECONFIGURE_EXPORT.to_owned());
        }
        exports.sort();
        exports.dedup();
        let actor = Actor {
            memory,
            host: self.host.clone(),
            registry: self.registry.clone(),
            dev,
            generation,
            clock: ctx.clock,
            journal: ctx.journal,
            inbox: ctx.inbox,
            status: ctx.status,
            lifecycle: instance.lifecycle,
            exports: exports.clone(),
            apps: instance.apps.clone(),
            started: false,
            initialised: !instance.lifecycle,
            apps_started: false,
            next_call: 0,
            calls: BTreeMap::new(),
            timers: Vec::new(),
            waits: Vec::new(),
        };
        Ok(DeviceInstance::new(instance.ports, Box::pin(actor))
            .has_counters(instance.counters)
            .exports(exports)
            .apps(instance.apps))
    }

    /// Supplied bytes, as the core judged them on every backend: a component
    /// ([`wasmnet_core::component_imports`]) that imports only what the page serves (`served`),
    /// which JavaScript then turns into something it instantiates ([`JsHost::compile`]: an
    /// embedder's hook, or a pre-transpiled component with that digest). Its key is the digest.
    fn compile_supplied(&self, digest: &str, bytes: &[u8]) -> Result<String, String> {
        use wasmnet_core::supply::{not_compiled, not_linked};
        let imports =
            wasmnet_core::component_imports(bytes).map_err(|why| not_compiled(digest, &why))?;
        let served = served();
        if let Some(name) = imports.iter().find(|name| !served.allows(name)) {
            return Err(not_linked(
                digest,
                &format!("it imports `{name}`, which this host does not serve"),
            ));
        }
        self.host
            .compile(digest, bytes)
            .map_err(|why| not_compiled(digest, &why))?;
        self.supplied
            .borrow_mut()
            .insert(digest.to_owned(), imports);
        Ok(digest.to_owned())
    }
}

enum CallKind {
    Start,
    App(String),
}

/// One device's actor: `start()` first, then the apps' `run`s as daemons, then inbox commands as
/// sync JavaScript calls; plus the device's virtual timers and `changes.wait`s.
struct Actor<H: JsHost> {
    host: H,
    registry: Registry,
    dev: u32,
    /// Its instantiation of the device ([`DeviceState::generation`]).
    generation: u64,
    clock: VirtualClock,
    journal: JournalEnd,
    inbox: Inbox,
    status: Status,
    lifecycle: bool,
    /// The interfaces it exports, by name without a version (control calls reach them by name).
    exports: Vec<String>,
    apps: Vec<String>,
    started: bool,
    initialised: bool,
    apps_started: bool,
    next_call: u32,
    /// In-flight async calls: JavaScript call id -> (status id, kind).
    calls: BTreeMap<u32, (u64, CallKind)>,
    timers: Vec<(u32, Pin<Box<Sleep>>)>,
    waits: Vec<(u32, infra::Wait)>,
    /// Its linear memory: measured after every poll ([`JsHost::memory`]), bounded by the core.
    memory: MemoryBudget,
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

    /// Serves one control call with the device's export, the way the wasmtime backend does:
    /// a command or a reconfiguration through JavaScript, any other kind refused as
    /// unsupported. The answer goes into the call's own slot.
    /// A control call into one of the device's exports, by name ([`ControlCall::invocation`]):
    /// commands, configuration changes in place and any other export, one way. A trap is the
    /// device's fault; a call it has no export for is refused by the call's own words.
    fn control(&mut self, call: Box<dyn ControlCall>, now: Nanos) -> Result<(), Fault> {
        let Some(invocation) = call.invocation(now) else {
            call.unsupported();
            return Ok(());
        };
        if !self.exports.contains(&invocation.interface) {
            call.unsupported();
            return Ok(());
        }
        let Some(answer) = self
            .host
            .export(self.dev, now, &invocation)
            .map_err(Fault::new)?
        else {
            call.unsupported();
            return Ok(());
        };
        // What its `wasi:config/store` serves, which the call may replace (a configuration
        // taken in place). Taken out of the registry for the call: `invoked` reaches the core
        // (the device table), never JavaScript or the registry.
        let mut served = self
            .registry
            .with_device(self.dev, |d| std::mem::take(&mut d.config))
            .unwrap_or_default();
        call.invoked(answer, &mut served);
        self.registry.with_device(self.dev, |d| d.config = served);
        Ok(())
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

        // Completions, new timers and new waits that JavaScript reported since the last poll.
        let (done, new_timers, new_waits) = self
            .registry
            .with_device(self.dev, |d| {
                d.waker = Some(cx.waker().clone());
                (
                    std::mem::take(&mut d.completions),
                    std::mem::take(&mut d.new_timers),
                    std::mem::take(&mut d.new_waits),
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
                CallKind::App(name) => {
                    self.journal
                        .app_exit(self.clock.now(), &name, end == CallEnd::Ok);
                }
            }
        }
        for (id, at) in new_timers {
            self.timers.push((id, Box::pin(self.clock.sleep_until(at))));
        }
        for (id, wait) in new_waits {
            self.waits.push((id, wait));
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
        let mut i = 0;
        while i < self.waits.len() {
            if let Poll::Ready(reply) = self.waits[i].1.as_mut().poll(cx) {
                let (id, _) = self.waits.remove(i);
                self.host.wait_done(id, &reply);
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
                Command::Control(call) => {
                    let reschedule = call.may_reschedule();
                    self.control(call, now)?;
                    // The call may move a stepped device's deadline: let it say so.
                    if reschedule {
                        self.clock.poll_by(idx, now);
                    }
                }
                // The bytes wait in the device's queue (the core's, as natively) until its guest
                // reads them; JavaScript hears that there is something to read.
                Command::Stdin(bytes) => {
                    self.registry
                        .with_device(self.dev, |d| d.stdin.push(&bytes));
                    self.host.stdin_ready(self.dev);
                }
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
        // What its memories hold now (grown by this poll's calls, or by work JavaScript ran since
        // the last one): counted, and the device's fault if that passed its limit. The growth
        // happened already: jco grows memories itself, so this is as close as the page gets.
        if let Some(total) = this.host.memory(this.dev)
            && let Err(message) = this.memory.observe(total)
        {
            return Poll::Ready(Err(Fault::new(message)));
        }
        this.status.set_guest_tasks_alive(
            !this.timers.is_empty() || !this.calls.is_empty() || !this.waits.is_empty(),
        );
        Poll::Pending
    }
}

impl<H: JsHost> Drop for Actor<H> {
    /// The device's instance is gone (it stopped, crashed or was removed, or the network was
    /// dropped): what its guest still calls is an orphan from now on, and JavaScript lets go of
    /// the instance.
    fn drop(&mut self) {
        if self.registry.retire(self.dev, self.generation) {
            self.host.release(self.dev);
        }
    }
}

/// What the page links for every device (`web/src/network.ts`: the kit's WASI, `wasi:config`,
/// `wasmnet:link`, `wasmnet:infra`): a supplied component that imports anything else does not
/// link here.
fn served() -> wasmnet_core::ImportPolicy {
    wasmnet_core::ImportPolicy::devices().and(["wasmnet:infra/*"])
}
