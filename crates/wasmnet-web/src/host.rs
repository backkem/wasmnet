//! What the JavaScript side provides: one call per device export (the `wasmnet:link` device
//! contract, the lifecycle `start` and the apps' `run`), and timer completion.
//!
//! Sync exports (`receive`, `link-state`, `poll`, `counters`) run to completion inside the call.
//! Async exports (`start`, an app's `run`) only *start* here: JavaScript reports their end later
//! through [`crate::Registry::call_done`], and resolves a guest's virtual wait when it hears
//! [`JsHost::timer_fire`].
//!
//! Every method may re-enter this crate through the [`crate::Registry`] (a guest that transmits
//! from inside `receive`, logs from inside `poll`, asks for a timer from inside `start`). It must
//! not re-enter the [`crate::Network`] that made the call.

use wasmnet_core::{DeclaredPort, DeviceConfig, Nanos};

/// A device JavaScript has instantiated: its `ports()` answer and what it exports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Instance {
    /// Its `ports()` answer, in its order.
    pub ports: Vec<DeclaredPort>,
    /// A composed node's apps (its `app-<name>` exports), by name, in start order.
    pub apps: Vec<String>,
    /// It exports `wasmnet:link/counters`.
    pub counters: bool,
    /// It exports `wasmnet:link/lifecycle` (an async node: `start()` runs first).
    pub lifecycle: bool,
}

/// How an async export call ended.
#[derive(Clone, Debug, PartialEq, Eq)]
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
}
