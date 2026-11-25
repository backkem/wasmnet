//! wasmnet-host: the Wasmtime embedder that runs wasmnet components deterministically.
//!
//! Same components, same topology and same seed give byte-identical pcaps and journals, on
//! every run and every machine.
//!
//! # A network in a few lines
//!
//! Two nodes on a switch; the client fetches `http://web/` one millisecond in. The components
//! are built by `cargo xtask build` into `target/wasm32-wasip2/release/`.
//!
//! ```no_run
//! use wasmnet_host::{DeviceConfig, Host, Network, Outcome, Record};
//!
//! /// A device config from `key = value` pairs.
//! fn config(pairs: &[(&str, &str)]) -> DeviceConfig {
//!     pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let host = Host::new()?;
//! let built = "target/wasm32-wasip2/release";
//! let switch = host.load(format!("{built}/switch.wasm"))?;
//! let server = host.load(format!("{built}/node-http-server.wasm"))?;
//! let client = host.load(format!("{built}/node-http-get.wasm"))?;
//!
//! let mut network = Network::new(&host, 42); // the seed
//! let sw = network.device_with_config("sw", &switch, config(&[("ports", "4")]))?;
//! let web = network.device_with_config(
//!     "web",
//!     &server,
//!     config(&[("ipv4", "10.0.0.1/24"), ("app.http-server.listen", "0.0.0.0:80")]),
//! )?;
//! let cli = network.device_with_config(
//!     "cli",
//!     &client,
//!     config(&[
//!         ("ipv4", "10.0.0.2/24"),
//!         ("hosts.web", "10.0.0.1"),
//!         ("app.http-get.url", "http://web/"),
//!         ("app.http-get.start", "1ms"),
//!     ]),
//! )?;
//! let uplink = network.link(web.port(0), sw.port(1))?.latency(150_000).id(); // ns
//! network.link(cli.port(0), sw.port(2))?.latency(100_000);
//! network.schedule_link_state(uplink, 50_000_000, false); // carrier loss at t = 50 ms
//!
//! if let Outcome::Quiescent { at, daemons, .. } = network.run_until_quiescent()? {
//!     println!("quiet at {at} ns; still serving: {daemons:?}");
//! }
//! for entry in network.journal() {
//!     if let Record::Event { kind, .. } = &entry.record {
//!         println!("{:>12} ns {} {kind}", entry.at, entry.device);
//!     }
//! }
//! let pcap: Vec<u8> = network.pcap(uplink); // pcap-ng: open it in Wireshark
//! # let _ = pcap;
//! # Ok(()) }
//! ```
//!
//! The full version, which writes every link's capture to disk, is `examples/http.rs`
//! (`cargo run -p wasmnet-host --example http`). The design notes in `docs/design/` explain
//! the rest; start with `docs/README.md`. Every config key is in
//! `docs/design/configuration.md`, the extension points in
//! `docs/design/runtime-and-extensions.md`.
//!
//! # What is here
//!
//! * [`Host`]: engines + linker, built once and shared. The linker serves deterministic WASI
//!   (virtual clocks, seeded random, captured stdio; no sockets, no filesystem),
//!   `wasi:config/store`, `wasmnet:link` and `wasmnet:infra`. An optional compile cache
//!   ([`Host::with_cache_dir`]) keeps precompiled components on disk.
//! * [`Network`]: a virtual network, the sim core's [`sim::Network`] with [`Host`] as its
//!   runtime: one type, every method of the sim core's network, one error type. Devices are
//!   component instances (one `Store` each) that
//!   export `wasmnet:link/device` and get a key/value config through `wasi:config/store`.
//!   Links are point-to-point with a one-way latency, an MTU and a carrier that can be scripted
//!   up/down. Each link has a pcap-ng tap and every transmission lands in a frame log. Devices'
//!   `wasmnet:link/log` records land in a journal stamped with virtual time. A composed node
//!   (netstack + apps) also exports one `app-<name>` per app: the host starts each app's
//!   `run` after `start` as a daemon call, and journals `app-exit` when one returns. A
//!   multi-actor executor runs every store on one thread and advances virtual time only when
//!   no store has work left at the current instant
//!   (`docs/design/async-under-virtual-time.md`).
//! * [`Sim`]: runs one `wasi:cli/run` command (p2 or p3) under a virtual clock.
//! * [`DeviceOptions`]: a device's own fuel budget per instant, its stdout/stderr lines in the
//!   journal ([`Record::Output`], [`Network::stdout`]), and its `wasmnet:infra` grant.
//! * [`HostExtension`]: extra host capabilities linked into every store
//!   (`Host::with_extension`), with per-store state in [`HostState`]; its rules and hook order
//!   are in `docs/design/runtime-and-extensions.md`.
//! * The sim core ([`sim`]) for operator events, dynamic topology, multi-site runs and
//!   extensions: all of them are methods of the same [`Network`].
//!
//! Module map (all private; their items are re-exported here): `runtime` ([`Host`] as the sim core's [`sim::Runtime`]: instantiating a device), `actor`
//! (one long-lived `run_concurrent` per device store), `glue` (the `wasmnet:link` and
//! `wasi:config/store` imports), `command` ([`Sim`], the command runner), `wasi` (the
//! deterministic WASI linker, [`HostState`]), `stdio` (captured, optionally journalled
//! stdout/stderr, and stdin), `infra` (`wasmnet:infra`), `extension` ([`HostExtension`],
//! [`ControlHandler`]), `cache` ([`CompileCache`]). Virtual time, the event queue, the
//! executors, the patch panel, the journal, the seeded PRNG and pcap live in the sim core
//! ([`sim`]).
//!
//! Errors: one [`Error`] for the whole library, the sim core's (re-exported here). A wasmtime
//! failure is an [`Error::Runtime`] whose message is wasmtime's report; the original
//! `wasmtime::Error` (which does not implement `std::error::Error`) rides along as its detail,
//! read with [`wasmtime_error`], and [`wasmtime_trap`] finds the trap code behind a failure.

#![deny(unsafe_code)]

mod actor;
mod cache;
mod command;
mod control;
mod extension;
mod glue;
mod infra;
mod reconfigure;
mod runtime;
mod stdio;
mod wasi;

/// The network journal (re-exported from the sim core).
pub mod journal {
    pub use wasmnet_core::journal::*;
}

/// A small pcap-ng reader for tests and tools (re-exported from the sim core).
pub mod pcap {
    pub use wasmnet_core::pcap::*;
}

use std::path::Path;

use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine};

pub use cache::{CacheStats, CompileCache, default_cache_dir};
/// The compile cache's default budget, default place and pruning.
pub mod compile_cache {
    pub use crate::cache::{MAX_CACHE_BYTES, default_cache_dir, prune_dir};
}
pub use command::{CommandOutput, Sim};
pub use extension::{ControlFuture, ControlHandler, HostExtension};

/// A virtual network of wasmtime component instances (one store each), links between their
/// ports, and one virtual clock: the sim core's [`sim::Network`] with [`Host`] as its runtime.
/// Same components, same topology and same seed give byte-identical pcaps.
///
/// ```no_run
/// # fn main() -> wasmnet_host::Result<()> {
/// use wasmnet_host::{DeviceConfig, Host, Network};
/// let host = Host::new()?;
/// let blaster = host.load("blaster.wasm")?;
/// let reflector = host.load("reflector.wasm")?;
///
/// let mut network = Network::new(&host, 42);
/// let config = DeviceConfig::from([("count".to_owned(), "3".to_owned())]);
/// let a = network.device_with_config("blaster", &blaster, config)?;
/// let b = network.device("reflector", &reflector)?;
/// let link = network.link(a.port(0), b.port(0))?.latency(250_000).id();
/// network.schedule_link_state(link, 1_500_000, false); // carrier loss at t = 1.5 ms
/// network.run_until_quiescent()?;
/// let pcap: Vec<u8> = network.pcap(link);
/// # Ok(()) }
/// ```
pub type Network<'h> = wasmnet_core::Network<'h, Host>;

/// Nanoseconds of a process-wide monotonic wall clock, for
/// [`Network::set_wall_clock`](sim::Network::set_wall_clock): device costs then include wall
/// time. Cost reports only, never behaviour.
pub fn wall_clock_ns() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos() as u64
}

/// The runtime-agnostic simulation core this host runs on.
pub use wasmnet_core as sim;
pub use wasmnet_core::{
    DEFAULT_WALL_EPOCH, DeviceConfig, DeviceId, DeviceOptions, DropReason, Error, FrameFate,
    FrameRecord, Guard, JournalEntry, Level, LinkId, LinkInfo, LinkMut, LinkStats, LinkTransition,
    Nanos, Outcome, PortInfo, PortRef, Record, Result, SimConfig, SimRng, Sleep, Stats, Stream,
    VirtualClock, derive_seed,
};
/// The wasmtime this host is built on, at the exact version and with the features it pins: an
/// embedder names `wasmtime::component::Component` (what [`Host::load`] returns),
/// `wasmtime::component::Linker` (a [`HostExtension`]'s) and `wasmtime::Error` through this
/// re-export, and needs no wasmtime of its own in its manifest.
pub use wasmtime;

pub use wasi::HostState;

/// Host bindings for `wasmnet:link@0.1.0` (world `counted-async-device`, a superset of every
/// world), including its `wasi:config/store` import (vendored WIT in `wit/deps/config`).
///
/// Every export is called with `call_concurrent` from inside the device's live event loop.
pub(crate) mod bindings {
    wasmtime::component::bindgen!({
        path: ["../../wit/deps/config", "../../wit/link"],
        world: "wasmnet:link/counted-async-device",
        exports: { default: async | store },
    });
}

/// A wasmtime error as this library's [`Error`]: a [`Error::Runtime`] whose message is
/// wasmtime's full report and whose detail is the original error ([`wasmtime_error`]).
pub(crate) fn runtime_error(e: wasmtime::Error) -> Error {
    Error::Runtime {
        message: format!("wasmtime: {e:?}"),
        detail: Some(wasmnet_core::Detail::new(e)),
    }
}

/// The wasmtime error an [`Error::Runtime`] carries (compiling, linking or instantiating a
/// component failed, or a command trapped), if it carries one.
pub fn wasmtime_error(error: &Error) -> Option<&wasmtime::Error> {
    match error {
        Error::Runtime { detail, .. } => detail.as_ref()?.downcast_ref(),
        _ => None,
    }
}

/// The wasmtime trap behind an error, if there is one: a device's trap ([`Error::Trap`]), or
/// one raised while a component was being created or run as a command ([`Error::Runtime`]).
pub fn wasmtime_trap(error: &Error) -> Option<wasmtime::Trap> {
    match error {
        Error::Trap { detail, .. } => detail.as_ref()?.downcast_ref().copied(),
        _ => wasmtime_error(error)?.downcast_ref().copied(),
    }
}

/// Engine plus a linker with deterministic WASI and `wasmnet:link` (plus any
/// [`HostExtension`]s). Expensive to build; share it.
pub struct Host {
    engine: Engine,
    linker: Linker<HostState>,
    /// Whether the main engine meters fuel (the per-instant fuel guard).
    fuel: bool,
    /// The engine and linker of components loaded with
    /// [`load_unmetered`](Host::load_unmetered), if the host was built with one.
    unmetered: Option<(Engine, Linker<HostState>)>,
    /// Precompiled components on disk, if enabled.
    cache: Option<cache::CompileCache>,
    /// Extra host capabilities, in the order they were added.
    extensions: Vec<Box<dyn HostExtension>>,
}

/// How a [`Host`] is built ([`Host::builder`]): its extensions, whether it meters fuel, and
/// whether it has a second engine without fuel.
#[derive(Default)]
pub struct HostBuilder {
    extensions: Vec<Box<dyn HostExtension>>,
    no_fuel: bool,
    unmetered_engine: bool,
}

impl HostBuilder {
    /// Adds a host capability; extensions are linked in the order they are added, and their
    /// engine hooks run for every engine the host builds.
    pub fn extension(mut self, extension: impl HostExtension) -> Self {
        self.extensions.push(Box::new(extension));
        self
    }

    /// Adds several host capabilities, in order ([`extension`](Self::extension)).
    pub fn extensions(mut self, extensions: Vec<Box<dyn HostExtension>>) -> Self {
        self.extensions.extend(extensions);
        self
    }

    /// Whether the host meters Wasm fuel (on by default). Off, there is no per-instant fuel
    /// budget, so no runaway guard against a device that never yields, and the cost meters
    /// report no fuel; a network that never exhausts its budget runs the same. For measuring
    /// what metering costs.
    pub fn fuel(mut self, on: bool) -> Self {
        self.no_fuel = !on;
        self
    }

    /// Also builds a second engine without fuel metering, for components whose guard is not
    /// wasmtime fuel (an interpreter with its own instruction budget), loaded with
    /// [`Host::load_unmetered`]. Embedder surface, unstable.
    pub fn unmetered_engine(mut self, on: bool) -> Self {
        self.unmetered_engine = on;
        self
    }

    /// Builds the engines and links the extensions.
    pub fn build(self) -> Result<Host> {
        let fuel = !self.no_fuel;
        let (engine, linker) = Host::build_engine(fuel, &self.extensions)?;
        // A host without fuel needs no second engine: its one engine is unmetered already.
        let unmetered = (fuel && self.unmetered_engine)
            .then(|| Host::build_engine(false, &self.extensions))
            .transpose()?;
        let mut host = Host {
            engine,
            linker,
            fuel,
            unmetered,
            cache: None,
            extensions: Vec::new(),
        };
        for extension in self.extensions {
            host = host.link_extension(extension)?;
        }
        Ok(host)
    }
}

impl Host {
    /// A host with the component model, component-model-async and fuel metering, and no
    /// extensions. [`builder`](Self::builder) sets up anything else.
    pub fn new() -> Result<Self> {
        Self::builder().build()
    }

    /// A host's builder: extensions, fuel metering, a second engine without fuel.
    pub fn builder() -> HostBuilder {
        HostBuilder::default()
    }

    /// [`new`](Self::new), with `extensions` added in order ([`with_extension`](
    /// Self::with_extension)); their engine hooks ([`HostExtension::configure_engine`],
    /// [`HostExtension::engine_built`]) run for every engine the host builds.
    pub fn with_extensions(extensions: Vec<Box<dyn HostExtension>>) -> Result<Self> {
        Self::builder().extensions(extensions).build()
    }

    /// One engine (fuel metered or not) and its linker.
    fn build_engine(
        fuel: bool,
        extensions: &[Box<dyn HostExtension>],
    ) -> Result<(Engine, Linker<HostState>)> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.wasm_component_model_async(true);
        config.consume_fuel(fuel);
        // Branch hints (a component may mark its slow paths cold): layout only, never
        // semantics.
        config.wasm_branch_hinting(true);
        for e in extensions {
            e.configure_engine(&mut config);
        }
        let engine = Engine::new(&config).map_err(runtime_error)?;
        for e in extensions {
            e.engine_built(&engine);
        }
        let mut linker = Linker::new(&engine);
        wasi::add_to_linker(&mut linker).map_err(runtime_error)?;
        Ok((engine, linker))
    }

    /// Adds a host capability to every store this host creates from now on: its imports are
    /// linked here, and [`HostExtension::init_store`] runs for each new device or command
    /// store. An extension may not shadow an import the host already serves. Its engine
    /// hooks do not run (the engines exist already): give such an extension to
    /// [`with_extensions`](Self::with_extensions).
    pub fn with_extension(self, extension: impl HostExtension) -> Result<Self> {
        self.link_extension(Box::new(extension))
    }

    fn link_extension(mut self, extension: Box<dyn HostExtension>) -> Result<Self> {
        extension.add_to_linker(&mut self.linker).map_err(|e| {
            runtime_error(e.context(format!("linking host extension `{}`", extension.name())))
        })?;
        if let Some((_, linker)) = &mut self.unmetered {
            extension.add_to_linker(linker).map_err(|e| {
                runtime_error(e.context(format!("linking host extension `{}`", extension.name())))
            })?;
        }
        self.extensions.push(extension);
        Ok(self)
    }

    /// The names of the added extensions, in order.
    pub fn extensions(&self) -> Vec<&str> {
        self.extensions.iter().map(|e| e.name()).collect()
    }

    /// The added extensions, in order.
    pub(crate) fn extension_hooks(&self) -> &[Box<dyn HostExtension>] {
        &self.extensions
    }

    /// Lets every extension set up a new store's state.
    pub(crate) fn init_store(&self, state: &mut HostState) -> Result<()> {
        for e in &self.extensions {
            e.init_store(state).map_err(|err| {
                runtime_error(err.context(format!("host extension `{}`", e.name())))
            })?;
        }
        Ok(())
    }

    /// Lets every extension take a network device's handles into its store's state.
    pub(crate) fn init_device(
        &self,
        state: &mut HostState,
        device: &wasmnet_core::DeviceContext,
    ) -> Result<()> {
        for e in &self.extensions {
            e.init_device(state, device).map_err(|err| {
                runtime_error(err.context(format!("host extension `{}`", e.name())))
            })?;
        }
        Ok(())
    }

    /// Tells every extension about a new store.
    pub(crate) fn store_created(&self, store: &mut wasmtime::Store<HostState>) {
        for e in &self.extensions {
            e.store_created(store);
        }
    }

    /// Keeps compiled components in `dir` (created on first use) and loads them from there on
    /// later runs, keyed by the component's bytes and the engine's configuration.
    /// Runs are unaffected: only the wall-clock cost of [`load`](Self::load) changes.
    /// [`default_cache_dir`] is the platform's per-user place for it.
    pub fn with_cache_dir(self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.with_compile_cache(CompileCache::new(dir))
    }

    /// [`with_cache_dir`](Self::with_cache_dir) with a cache set up by the caller (its size
    /// budget, [`CompileCache::with_budget`]).
    pub fn with_compile_cache(mut self, cache: CompileCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// How [`load`](Self::load) used the compile cache so far (`None` without a cache).
    pub fn cache_stats(&self) -> Option<CacheStats> {
        self.cache.as_ref().map(cache::CompileCache::stats)
    }

    /// The underlying engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Compiles a component from a `.wasm` file, or loads it precompiled from the cache
    /// ([`with_cache_dir`](Self::with_cache_dir)).
    pub fn load(&self, path: impl AsRef<Path>) -> Result<Component> {
        match &self.cache {
            Some(cache) => cache.load(&self.engine, path.as_ref()),
            None => Component::from_file(&self.engine, path).map_err(runtime_error),
        }
    }

    /// Compiles a component for the unmetered engine: it runs without wasmtime fuel, so
    /// without the per-instant fuel guard and the fuel cost meter. For components whose guard
    /// is not wasmtime fuel (for example an interpreter with its own instruction budget). Like
    /// [`load`](Self::load) when fuel is off altogether. Refused unless the host was built with
    /// [`HostBuilder::unmetered_engine`]. Embedder surface, unstable.
    pub fn load_unmetered(&self, path: impl AsRef<Path>) -> Result<Component> {
        let Some((engine, _)) = &self.unmetered else {
            if !self.fuel {
                return self.load(path);
            }
            return Err(Error::Refused(
                "this host has no unmetered engine (HostBuilder::unmetered_engine)".to_owned(),
            ));
        };
        match &self.cache {
            Some(cache) => cache.load(engine, path.as_ref()),
            None => Component::from_file(engine, path).map_err(runtime_error),
        }
    }

    /// The linker for `component`'s engine, and whether that engine meters fuel.
    pub(crate) fn linker_for(&self, component: &Component) -> (&Linker<HostState>, bool) {
        match &self.unmetered {
            Some((engine, linker)) if Engine::same(component.engine(), engine) => (linker, false),
            _ => (&self.linker, self.fuel),
        }
    }

    /// The component's import names (instances and functions), sorted.
    pub fn imports(&self, component: &Component) -> Vec<String> {
        let ty = component.component_type();
        let mut names: Vec<String> = ty
            .imports(component.engine())
            .map(|(name, _)| name.to_owned())
            .collect();
        names.sort();
        names
    }

    /// The component's export names, sorted.
    pub fn exports(&self, component: &Component) -> Vec<String> {
        let ty = component.component_type();
        let mut names: Vec<String> = ty
            .exports(component.engine())
            .map(|(name, _)| name.to_owned())
            .collect();
        names.sort();
        names
    }

    /// Starts a command simulation with its own virtual clock.
    pub fn sim(&self, config: SimConfig) -> Sim<'_> {
        Sim::new(self, config)
    }
}
