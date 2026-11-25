//! Deterministic WASI: wasmtime-wasi for stdio/args, our clock and RNG for everything else.
//!
//! * `now`/`resolution` (p2 + p3, monotonic + wall) and all `wasi:random` interfaces are
//!   served through `WasiCtxBuilder` hooks backed by [`VirtualClock`] and the sim core's
//!   [`DeviceEntropy`].
//! * Waits are *not* hookable in wasmtime-wasi (49 and 50): p2 `subscribe-duration`/`subscribe-instant`
//!   and p3 `wait-for`/`wait-until` sleep on real tokio time. We therefore shadow the whole
//!   `wasi:clocks/monotonic-clock` interface (p2 and p3) with versions whose waits are
//!   [`VirtualClock`] timers.
//! * Network and filesystem: `wasi:sockets/*` and `wasi:filesystem/*` (p2 and p3) are **not
//!   linked at all**, so a component that imports them fails to instantiate. A plain std
//!   wasip2 guest does not import them unless it reaches `std::fs`/`std::net`. An import
//!   audit can reject such components before they ever get here.
//! * `wasmnet:link/{wire,log}` and `wasi:config/store` are linked for every store. Outside a
//!   network frames and log records go nowhere and the config is empty.
//! * stdout and stderr are captured ([`OutputPipe`]); a network device can have their lines
//!   journalled with virtual timestamps. stdin is the device's `Op::Stdin` operator events
//!   ([`InputPipe`]).
//! * Host extensions ([`crate::HostExtension`]) add their own imports to the same linker
//!   and keep per-store state in [`HostState`].

use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::time::Duration;

use wasmtime::component::{Accessor, HasData, HasSelf, Linker, Resource, ResourceTable};
use wasmtime_wasi::cli::{WasiCli, WasiCliView};
use wasmtime_wasi::clocks::{HostMonotonicClock, HostWallClock, WasiClocks, WasiClocksView};
use wasmtime_wasi::p2::bindings as p2;
use wasmtime_wasi::p2::bindings::clocks::monotonic_clock as p2_mono;
use wasmtime_wasi::p2::{DynPollable, Pollable, subscribe};
use wasmtime_wasi::p3::bindings::clocks::monotonic_clock as p3_mono;
use wasmtime_wasi::random::{WasiRandom, WasiRandomView};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::bindings::CountedAsyncDevice;
use wasmnet_core::{
    DeviceConfig, DeviceEntropy, JournalEnd, Nanos, OutputCapture, VirtualClock, Wire, derive_seed,
};

use crate::stdio::{InputPipe, OutputPipe};

/// Per-store state for one component instance (a network device or a command).
///
/// Opaque, except for what a [`crate::HostExtension`] needs to serve its imports: the store's
/// resource table, typed per-store extension state, the device name, virtual time and seeds.
pub struct HostState {
    ctx: WasiCtx,
    table: ResourceTable,
    pub(crate) clock: VirtualClock,
    /// The network's root seed (per-device seeds derive from it and the device name).
    sim_seed: u64,
    /// The device (or command) name.
    name: String,
    /// Set for network devices: where `wasmnet:link/wire.transmit` goes.
    pub(crate) wire: Option<Wire>,
    /// Set for network devices: where `wasmnet:link/log` records go.
    pub(crate) journal: Option<JournalEnd>,
    /// Served read-only through `wasi:config/store` (empty for plain commands).
    pub(crate) config: DeviceConfig,
    /// Per-store state of host extensions, by type.
    extensions: BTreeMap<TypeId, Box<dyn Any + Send>>,
    /// `wasmnet:infra`: the network's device table, for a device granted it; `None`
    /// refuses every call.
    pub(crate) infra: Option<wasmnet_core::InfraEnd>,
    /// The guest's stdin: `Op::Stdin` operator events land here.
    pub(crate) stdin: wasmnet_core::InputQueue,
    /// The device's memory, measured and (with [`wasmnet_core::DeviceOptions::memory`])
    /// bounded; `None` for a command.
    pub(crate) memory: Option<MemoryBudget>,
}

/// A device's linear memory, all its memories together: the sim core's [`wasmnet_core::MemoryBudget`]
/// (measured for its cost report and, with a limit, bounded), told of every growth before it
/// happens, so a growth past the limit traps at the growing instruction, the same every run.
pub(crate) struct MemoryBudget(wasmnet_core::MemoryBudget);

impl MemoryBudget {
    pub(crate) fn new(limit: Option<u64>, meter: wasmnet_core::CostMeter) -> Self {
        Self(wasmnet_core::MemoryBudget::new(limit, meter))
    }
}

impl wasmtime::ResourceLimiter for MemoryBudget {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let grow = desired.saturating_sub(current) as u64;
        self.0
            .growing(grow)
            .map_err(|e| wasmtime::format_err!("{e}"))?;
        Ok(true)
    }

    fn memory_grow_failed(&mut self, _error: wasmtime::Error) -> wasmtime::Result<()> {
        self.0.grow_failed();
        Ok(())
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(true)
    }
}

impl HostState {
    /// The store's resource table (for an extension's resources).
    pub fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    /// Stores per-store state of a host extension (one value per type), replacing any earlier
    /// value of the same type. Normally called from [`crate::HostExtension::init_store`].
    pub fn insert_extension<T: Any + Send>(&mut self, value: T) {
        self.extensions.insert(TypeId::of::<T>(), Box::new(value));
    }

    /// The extension state of type `T`, if one was inserted.
    pub fn extension<T: Any + Send>(&self) -> Option<&T> {
        self.extensions.get(&TypeId::of::<T>())?.downcast_ref()
    }

    /// The extension state of type `T`, mutably.
    pub fn extension_mut<T: Any + Send>(&mut self) -> Option<&mut T> {
        self.extensions.get_mut(&TypeId::of::<T>())?.downcast_mut()
    }

    /// The extension state of type `T` and the resource table at once (a host function that
    /// creates or looks up resources usually needs both).
    pub fn extension_and_table<T: Any + Send>(&mut self) -> Option<(&mut T, &mut ResourceTable)> {
        let ext = self
            .extensions
            .get_mut(&TypeId::of::<T>())?
            .downcast_mut()?;
        Some((ext, &mut self.table))
    }

    /// The device's name in the network (or the command's name).
    pub fn device_name(&self) -> &str {
        &self.name
    }

    /// Current virtual time in nanoseconds. Never a real clock.
    pub fn now(&self) -> Nanos {
        self.clock.now()
    }

    /// The store's virtual clock (the network's, or the command's).
    pub fn clock(&self) -> &VirtualClock {
        &self.clock
    }

    /// A seed for `stream`, derived from the network seed and this device's name (the same
    /// derivation as the device's `wasi:random`): deterministic per network, seed and device.
    pub fn seed(&self, stream: &str) -> u64 {
        derive_seed(self.sim_seed, &self.name, stream)
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl HostState {
    /// A store's state: `argv[0]` is `component`, then `args`; `env` is its environment, in
    /// order (`wasi:cli/environment`, p2 and p3). The guest's stdout and stderr go to the given captures (which may
    /// journal their lines, [`wasmnet_core::Record::Output`]).
    pub(crate) fn new(
        clock: &VirtualClock,
        sim_seed: u64,
        component: &str,
        args: &[&str],
        env: &[(String, String)],
        stdout: OutputCapture,
        stderr: OutputCapture,
    ) -> Self {
        let entropy = DeviceEntropy::new(sim_seed, component);
        let insecure_seed = entropy.insecure_seed_u128();

        let stdin = wasmnet_core::InputQueue::new();
        let mut b = WasiCtxBuilder::new();
        b.args(&wasmnet_core::argv(component, args))
            .envs(env)
            .stdin(InputPipe(stdin.clone()))
            .stdout(OutputPipe(stdout))
            .stderr(OutputPipe(stderr))
            .wall_clock(VirtualWallClock(clock.clone()))
            .monotonic_clock(VirtualMonotonicClock(clock.clone()))
            .secure_random(entropy.secure)
            .insecure_random(entropy.insecure)
            .insecure_random_seed(insecure_seed);
        Self {
            ctx: b.build(),
            table: ResourceTable::new(),
            clock: clock.clone(),
            sim_seed,
            name: component.to_owned(),
            wire: None,
            journal: None,
            config: DeviceConfig::new(),
            extensions: BTreeMap::new(),
            infra: None,
            stdin,
            memory: None,
        }
    }
}

/// [`HasData`] for `wasi:io` (p2), whose host traits are implemented on the resource table.
struct WasiIo;

impl HasData for WasiIo {
    type Data<'a> = &'a mut ResourceTable;
}

/// Links the deterministic WASI subset (p2 + p3), `wasi:config/store` and `wasmnet:link`.
///
/// Linked: `wasi:io` (p2), `wasi:cli/*`, `wasi:clocks/*` (monotonic waits on virtual time) and
/// `wasi:random/*`. Deliberately **not** linked: `wasi:sockets/*` and `wasi:filesystem/*`.
pub(crate) fn add_to_linker(linker: &mut Linker<HostState>) -> wasmtime::Result<()> {
    fn table(s: &mut HostState) -> &mut ResourceTable {
        &mut s.table
    }
    let l = linker;
    // ---- WASI 0.2 ----
    p2::io::error::add_to_linker::<_, WasiIo>(l, table)?;
    p2::io::poll::add_to_linker::<_, WasiIo>(l, table)?;
    p2::io::streams::add_to_linker::<_, WasiIo>(l, table)?;
    p2::clocks::wall_clock::add_to_linker::<_, WasiClocks>(l, HostState::clocks)?;
    p2_mono::add_to_linker::<_, VirtualClocks>(l, VirtualClocks::view)?;
    p2::random::random::add_to_linker::<_, WasiRandom>(l, HostState::random)?;
    p2::random::insecure::add_to_linker::<_, WasiRandom>(l, HostState::random)?;
    p2::random::insecure_seed::add_to_linker::<_, WasiRandom>(l, HostState::random)?;
    p2::cli::exit::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    p2::cli::environment::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    p2::cli::stdin::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    p2::cli::stdout::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    p2::cli::stderr::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    p2::cli::terminal_input::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    p2::cli::terminal_output::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    p2::cli::terminal_stdin::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    p2::cli::terminal_stdout::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    p2::cli::terminal_stderr::add_to_linker::<_, WasiCli>(l, HostState::cli)?;
    // ---- WASI 0.3 ---- (the stock clocks, then our monotonic clock over them)
    wasmtime_wasi::p3::cli::add_to_linker(l)?;
    wasmtime_wasi::p3::clocks::add_to_linker(l)?;
    wasmtime_wasi::p3::random::add_to_linker(l)?;
    l.allow_shadowing(true);
    p3_mono::add_to_linker::<_, VirtualClocks>(l, VirtualClocks::view)?;
    l.allow_shadowing(false);
    // ---- wasmnet:link and wasi:config (one bindgen world covers both) ----
    CountedAsyncDevice::add_to_linker::<_, HasSelf<HostState>>(l, |s| s)?;
    // ---- wasmnet:infra (in-world controllers): every store; refused unless granted -----------
    crate::infra::add_to_linker(l)?;
    Ok(())
}

/// Monotonic clock for `WasiCtxBuilder`: virtual nanoseconds, 1 ns resolution.
struct VirtualMonotonicClock(VirtualClock);

impl HostMonotonicClock for VirtualMonotonicClock {
    fn resolution(&self) -> u64 {
        1
    }

    fn now(&self) -> u64 {
        self.0.now()
    }
}

/// Wall clock for `WasiCtxBuilder`: the configured epoch plus virtual time.
struct VirtualWallClock(VirtualClock);

impl HostWallClock for VirtualWallClock {
    fn resolution(&self) -> Duration {
        Duration::from_nanos(1)
    }

    fn now(&self) -> Duration {
        self.0.wall_now()
    }
}

/// [`HasData`] marker for our `wasi:clocks/monotonic-clock` implementations.
struct VirtualClocks;

impl VirtualClocks {
    fn view(state: &mut HostState) -> VirtualClocksView<'_> {
        VirtualClocksView {
            clock: &state.clock,
            table: &mut state.table,
        }
    }
}

impl HasData for VirtualClocks {
    type Data<'a> = VirtualClocksView<'a>;
}

struct VirtualClocksView<'a> {
    clock: &'a VirtualClock,
    table: &'a mut ResourceTable,
}

// ---- WASI 0.2: pollables backed by virtual timers ----

/// A `wasi:io/poll.pollable` that becomes ready when virtual time reaches `deadline`.
struct VirtualDeadline {
    clock: VirtualClock,
    deadline: Nanos,
}

#[async_trait::async_trait]
impl Pollable for VirtualDeadline {
    async fn ready(&mut self) {
        self.clock.sleep_until(self.deadline).await;
    }
}

impl VirtualClocksView<'_> {
    fn subscribe_at(&mut self, deadline: Nanos) -> wasmtime::Result<Resource<DynPollable>> {
        let pollable = self.table.push(VirtualDeadline {
            clock: self.clock.clone(),
            deadline,
        })?;
        subscribe(self.table, pollable)
    }
}

impl p2_mono::Host for VirtualClocksView<'_> {
    fn now(&mut self) -> wasmtime::Result<p2_mono::Instant> {
        Ok(self.clock.now())
    }

    fn resolution(&mut self) -> wasmtime::Result<p2_mono::Duration> {
        Ok(1)
    }

    fn subscribe_instant(
        &mut self,
        when: p2_mono::Instant,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        self.subscribe_at(when)
    }

    fn subscribe_duration(
        &mut self,
        duration: p2_mono::Duration,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        let deadline = self.clock.now().saturating_add(duration);
        self.subscribe_at(deadline)
    }
}

// ---- WASI 0.3: async waits backed by virtual timers ----

impl p3_mono::Host for VirtualClocksView<'_> {
    fn now(&mut self) -> wasmtime::Result<p3_mono::Mark> {
        Ok(self.clock.now())
    }

    fn get_resolution(&mut self) -> wasmtime::Result<p3_mono::Duration> {
        Ok(1)
    }
}

impl<U> p3_mono::HostWithStore<U> for VirtualClocks {
    async fn wait_until(store: &Accessor<U, Self>, when: p3_mono::Mark) -> wasmtime::Result<()> {
        let clock = store.with(|mut view| view.get().clock.clone());
        clock.sleep_until(when).await;
        Ok(())
    }

    async fn wait_for(
        store: &Accessor<U, Self>,
        how_long: p3_mono::Duration,
    ) -> wasmtime::Result<()> {
        let clock = store.with(|mut view| view.get().clock.clone());
        clock.sleep_for(how_long).await;
        Ok(())
    }
}
