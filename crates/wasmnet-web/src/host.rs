//! What the JavaScript side provides: one call per device export (the `wasmnet:link` device
//! contract, the lifecycle `start`, the apps' `run`, and the optional `wasmnet:control/commands`
//! and `wasmnet:reconfigure/reconfigure`), timer completion and `changes.wait` completion.
//!
//! Sync exports (`receive`, `link-state`, `poll`, `counters`, `invoke`, `reconfigure`) run to
//! completion inside the call. Async exports (`start`, an app's `run`) only *start* here:
//! JavaScript reports their end later through [`crate::Registry::call_done`], and resolves a
//! guest's virtual wait when it hears [`JsHost::timer_fire`] or [`JsHost::wait_done`].
//!
//! Every method may re-enter this crate through the [`crate::Registry`] (a guest that transmits
//! from inside `receive`, logs from inside `poll`, asks for a timer from inside `start`, calls
//! `wasmnet:infra` from inside `poll`). It must not re-enter the [`crate::Network`] that made
//! the call.

use wasmnet_core::{DeclaredPort, DeviceConfig, Nanos, Refusal};

/// A device JavaScript has instantiated: its `ports()` answer and what it exports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Instance {
    /// Its `ports()` answer, in its order.
    pub ports: Vec<DeclaredPort>,
    /// A composed node's apps (its `app-<name>` exports), by name, in start order.
    pub apps: Vec<String>,
    /// It exports `wasmnet:link/counters`.
    pub counters: bool,
    /// It exports `wasmnet:link/lifecycle` (an async node: `start()` runs first).
    pub lifecycle: bool,
    /// It exports `wasmnet:control/commands` (it takes commands: [`JsHost::invoke`]).
    pub commands: bool,
    /// It exports `wasmnet:reconfigure/reconfigure` (it takes a config in place:
    /// [`JsHost::reconfigure`]).
    pub reconfigure: bool,
}

/// Chainable setters, one per field: `Instance::default().ports(ports).counters(true)`.
impl Instance {
    /// Sets [`ports`](Self::ports).
    pub fn ports(mut self, ports: Vec<DeclaredPort>) -> Self {
        self.ports = ports;
        self
    }

    /// Sets [`apps`](Self::apps).
    pub fn apps(mut self, apps: Vec<String>) -> Self {
        self.apps = apps;
        self
    }

    /// Sets [`counters`](Self::counters).
    pub fn counters(mut self, on: bool) -> Self {
        self.counters = on;
        self
    }

    /// Sets [`lifecycle`](Self::lifecycle).
    pub fn lifecycle(mut self, on: bool) -> Self {
        self.lifecycle = on;
        self
    }

    /// Sets [`commands`](Self::commands).
    pub fn commands(mut self, on: bool) -> Self {
        self.commands = on;
        self
    }

    /// Sets [`reconfigure`](Self::reconfigure).
    pub fn reconfigure(mut self, on: bool) -> Self {
        self.reconfigure = on;
        self
    }
}

/// How an async export call ended.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallEnd {
    /// Returned (`start()` returned, or an app's `run` returned `ok`).
    Ok,
    /// An app's `run` returned `err`.
    Err,
    /// The guest trapped (or the JavaScript glue failed): a device crash.
    Trap(String),
}

/// The JavaScript side. `dev` is the device's index in the network (creation order). An `Err` is
/// a trap message: the device crashed, and the network fails at that instant.
pub trait JsHost {
    /// Instantiates `component` (a key JavaScript understands, such as the name of a transpiled
    /// module) as device `dev` called `name`, serving it `config` through `wasi:config/store`,
    /// and calls its `ports()`. The device's imports are already served while this runs.
    fn instantiate(
        &self,
        dev: u32,
        name: &str,
        component: &str,
        config: &DeviceConfig,
    ) -> Result<Instance, String>;
    /// `device.receive(now, port, frame)`.
    fn receive(&self, dev: u32, port: u32, now: Nanos, frame: &[u8]) -> Result<(), String>;
    /// `device.link-state(now, port, up)`.
    fn link_state(&self, dev: u32, port: u32, up: bool, now: Nanos) -> Result<(), String>;
    /// `device.poll(now)`: the device's next deadline.
    fn poll(&self, dev: u32, now: Nanos) -> Result<Option<Nanos>, String>;
    /// `counters.counters()`.
    fn counters(&self, dev: u32) -> Result<Vec<(String, u64)>, String>;
    /// Starts `lifecycle.start()`; its end is reported as call `call`.
    fn start(&self, dev: u32, call: u32) -> Result<(), String>;
    /// Starts app number `app`'s `run()` (its index in [`Instance::apps`]); its end is reported
    /// as call `call`.
    fn run_app(&self, dev: u32, app: u32, call: u32) -> Result<(), String>;
    /// Timer `timer` (from [`crate::Registry::timer`]) is due: resolve the guest's wait.
    fn timer_fire(&self, timer: u32);
    /// `commands.invoke(now, command, argument)` of a device whose [`Instance::commands`] is
    /// set: its answer, `ok` text or its refusal. The default: no device takes commands.
    fn invoke(
        &self,
        dev: u32,
        now: Nanos,
        command: &str,
        argument: &str,
    ) -> Result<Result<String, String>, String> {
        let _ = (dev, now, command, argument);
        Err("this host serves no wasmnet:control/commands".to_owned())
    }
    /// `reconfigure.reconfigure(now, config)` of a device whose [`Instance::reconfigure`] is
    /// set, with its whole new config: `ok`, or its refusal. The default: no device takes one.
    fn reconfigure(
        &self,
        dev: u32,
        now: Nanos,
        config: &DeviceConfig,
    ) -> Result<Result<(), Refusal>, String> {
        let _ = (dev, now, config);
        Err("this host serves no wasmnet:reconfigure".to_owned())
    }
    /// The waiting call `wait` (`changes.wait`, `changes.wait-any`; from
    /// [`crate::Registry::infra_wait`]) is answered with `reply`: resolve the guest's call. The
    /// default does nothing (a host whose devices never wait).
    fn wait_done(&self, wait: u32, reply: &crate::infra::Reply) {
        let _ = (wait, reply);
    }
    /// The import names of `component` (`wasmnet:infra/devices@0.1.2`, ...), if JavaScript knows
    /// them, asked before it is instantiated: the core refuses a component that imports
    /// `wasmnet:infra` for a device without the grant ([`wasmnet_core::infra::require_grant`]).
    /// The default: unknown, so nothing is refused here and every infra call of an ungranted
    /// device is `denied` instead.
    fn imports(&self, component: &str) -> Option<Vec<String>> {
        let _ = component;
        None
    }
    /// Device `dev`'s instance is gone (stopped, crashed, removed, or its network dropped):
    /// JavaScript drops it. A later instantiation of the same `dev` is a new instance. The
    /// default does nothing.
    fn release(&self, dev: u32) {
        let _ = dev;
    }
    /// Makes the component a controller supplied as `bytes` (with digest reference `digest`,
    /// `sha256:<hex>`) instantiable by its digest: [`JsHost::instantiate`] gets `digest` as its
    /// component from then on. The core has checked the digest, the embedder's admission and
    /// the component's imports already. May take its time (JSPI). The default refuses: a page
    /// that runs no supplied components.
    fn compile(&self, digest: &str, bytes: &[u8]) -> Result<(), String> {
        let _ = (digest, bytes);
        Err("this page runs no supplied components".to_owned())
    }
}
