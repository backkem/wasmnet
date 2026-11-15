//! Host extensions: extra host capabilities linked into every device's linker, the registration
//! point for every capability an embedder serves beyond the core's.
//!
//! Embedder surface, unstable: public for embedders, and it may change between versions
//! without notice.
//!
//! wasmnet-host serves a fixed, deterministic import set (WASI subset, `wasi:config`,
//! `wasmnet:link`, `wasmnet:infra`). Some consumers need more capabilities that only a host can
//! provide, for example a JIT import through which the host instantiates a guest-supplied core
//! module on host-owned memory. A [`HostExtension`] adds such imports without wasmnet-host
//! knowing what they are, and may also serve control calls into an optional export
//! ([`HostExtension::instance_ready`], [`ControlHandler`]), take the network's per-device
//! handles ([`HostExtension::init_device`]) and register the network extensions it serves
//! ([`HostExtension::install`]):
//!
//! ```no_run
//! use wasmnet_host::{Host, HostExtension, HostState};
//! use wasmtime::component::Linker;
//!
//! struct Jit;
//! struct JitState { engines: u32 }
//!
//! impl HostExtension for Jit {
//!     fn name(&self) -> &str { "example:host/jit" }
//!     fn add_to_linker(&self, linker: &mut Linker<HostState>) -> wasmtime::Result<()> {
//!         // bindgen!-generated `add_to_linker::<HostState, D>(linker, |s| ...)`, whose host
//!         // functions reach their state through `HostState::extension_and_table::<JitState>()`.
//!         # let _ = linker;
//!         Ok(())
//!     }
//!     fn init_store(&self, state: &mut HostState) -> wasmtime::Result<()> {
//!         state.insert_extension(JitState { engines: 0 });
//!         Ok(())
//!     }
//! }
//!
//! # fn main() -> wasmnet_host::Result<()> {
//! let host = Host::new()?.with_extension(Jit)?;
//! # Ok(()) }
//! ```
//!
//! Rules (the host's invariants still hold):
//! * **Deterministic.** Anything a guest can observe through the extension must be a pure
//!   function of its inputs, virtual time ([`HostState::now`]) and seeds ([`HostState::seed`]).
//!   No wall clock, threads or ambient I/O may leak into results (wall-clock-only effects such as
//!   compile caching are fine).
//! * **No shadowing.** An extension may only add imports; linking one that wasmnet-host already
//!   serves is an error.
//! * **No networking.** Packets still only cross the network as Ethernet frames on its links.
//! * **Opt-in by import.** A component that does not import the extension's interfaces never
//!   sees it. One that does fails to instantiate on a host without it (wasmtime names the
//!   missing import), so an import audit can keep such imports out of the components that a
//!   plain host runs.
//! * Extension state lives in the device's store ([`HostState::insert_extension`]), so it is
//!   created and dropped with the device and never shared between devices.

use std::future::Future;
use std::pin::Pin;

use wasmnet_core::DeviceContext;
use wasmnet_core::ext::ControlCall;
use wasmtime::component::{Accessor, Instance, InstancePre, Linker};
use wasmtime::{Config, Engine, Store};

use crate::Host;
use crate::wasi::HostState;

/// A host capability added to every store's linker (see `docs/design/runtime-and-extensions.md`).
/// Embedder surface, unstable: the hooks may change between versions without notice.
///
/// Every hook but [`name`](Self::name) and [`add_to_linker`](Self::add_to_linker) has a default
/// that does nothing; they run in the order the extensions were added.
pub trait HostExtension: Send + Sync + 'static {
    /// A short name for diagnostics, conventionally the WIT interface it serves.
    fn name(&self) -> &str;

    /// Adds the extension's host functions to the linker. Called once per engine, by
    /// [`crate::Host::with_extension`] or [`crate::Host::with_extensions`].
    fn add_to_linker(&self, linker: &mut Linker<HostState>) -> wasmtime::Result<()>;

    /// Engine settings, before an engine is built. Only extensions given to
    /// [`crate::Host::with_extensions`] get this call; they must change nothing a guest can
    /// observe (code layout, profiling, interruption for sampling).
    fn configure_engine(&self, config: &mut Config) {
        let _ = config;
    }

    /// An engine was built (with [`configure_engine`](Self::configure_engine)'s settings). Only
    /// for extensions given to [`crate::Host::with_extensions`].
    fn engine_built(&self, engine: &Engine) {
        let _ = engine;
    }

    /// Called for every new store (network device or [`crate::Sim`] command) before its
    /// component is instantiated, in the order the extensions were added. Typically inserts the
    /// extension's per-store state with [`HostState::insert_extension`].
    fn init_store(&self, state: &mut HostState) -> wasmtime::Result<()> {
        let _ = state;
        Ok(())
    }

    /// Called for a network device's store after every extension's
    /// [`init_store`](Self::init_store): copy the device's handles from the network's extensions
    /// ([`DeviceContext::ext`]) into the store's state.
    fn init_device(&self, state: &mut HostState, device: &DeviceContext) -> wasmtime::Result<()> {
        let _ = (state, device);
        Ok(())
    }

    /// A store was created (for a network device or a command), before anything runs in it.
    fn store_created(&self, store: &mut Store<HostState>) {
        let _ = store;
    }

    /// A network device was instantiated: look up the optional export the extension serves
    /// control calls for. `Some((export, handler))` reports `export` to the network
    /// ([`wasmnet_core::DeviceInstance::exports`]) and gives the device's actor the handler.
    fn instance_ready(
        &self,
        pre: &InstancePre<HostState>,
        store: &mut Store<HostState>,
        instance: &Instance,
    ) -> wasmtime::Result<Option<(String, Box<dyn ControlHandler>)>> {
        let _ = (pre, store, instance);
        Ok(None)
    }

    /// A network was created on this host ([`wasmnet_core::Runtime::install`]): register the
    /// network extensions and cable kinds the extension serves.
    fn install(&self, network: &mut wasmnet_core::Network<'_, Host>) {
        let _ = network;
    }
}

/// A control call's export call, inside the device's live event loop.
pub type ControlFuture<'a> = Pin<Box<dyn Future<Output = wasmtime::Result<()>> + 'a>>;

/// Serves the control calls of one optional export of one device (see
/// [`HostExtension::instance_ready`]). Embedder surface, unstable.
pub trait ControlHandler {
    /// The export call for `call` (which answers into the call's own slot), or `call` back if
    /// it is not for this handler.
    fn serve<'a>(
        &'a self,
        acc: &'a Accessor<HostState>,
        call: Box<dyn ControlCall>,
    ) -> Result<ControlFuture<'a>, Box<dyn ControlCall>>;
}
