//! The `wasmnet:link` and `wasi:config` host imports, served from the sim core's handles.
//!
//! * `wasmnet:link/wire.transmit` goes to the device's [`wasmnet_core::Wire`] (the patch
//!   panel); it only enqueues.
//! * `wasmnet:link/log` records go to the device's [`wasmnet_core::JournalEnd`], stamped with
//!   virtual time.
//! * `wasi:config/store` serves the device's [`wasmnet_core::DeviceConfig`] read-only, sorted by
//!   key.
//!
//! A store outside a network (a plain command) has no wires, journal or config: frames and
//! records go nowhere and the config is empty.

use wasmnet_core::Level;

use crate::bindings::wasi::config::store;
use crate::bindings::wasmnet::link::log as wit;
use crate::wasi::HostState;

impl crate::bindings::wasmnet::link::types::Host for HostState {}

impl crate::bindings::wasmnet::link::wire::Host for HostState {
    fn transmit(&mut self, port: u32, frame: Vec<u8>) {
        if let Some(w) = &self.wire {
            w.transmit(port, frame);
        }
    }
}

fn level(l: wit::Level) -> Level {
    match l {
        wit::Level::Trace => Level::Trace,
        wit::Level::Debug => Level::Debug,
        wit::Level::Info => Level::Info,
        wit::Level::Warn => Level::Warn,
        wit::Level::Error => Level::Error,
    }
}

impl wit::Host for HostState {
    fn log(&mut self, l: wit::Level, message: String) {
        if let Some(j) = &self.journal {
            j.log(self.clock.now(), level(l), message);
        }
    }

    fn event(&mut self, kind: String, fields: Vec<(String, String)>) {
        if let Some(j) = &self.journal {
            j.event(self.clock.now(), kind, fields);
        }
    }
}

impl store::Host for HostState {
    fn get(&mut self, key: String) -> Result<Option<String>, store::Error> {
        Ok(self.config.get(&key).cloned())
    }

    fn get_all(&mut self) -> Result<Vec<(String, String)>, store::Error> {
        Ok(self
            .config
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}
