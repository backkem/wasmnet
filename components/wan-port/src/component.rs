//! wit-bindgen glue: exports `wasmnet:link/device` over [`crate::WanPort`].

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::RefCell;

use crate::{ACCESS, Config, OVERHEAD, Sink, WAN, WanPort};

wit_bindgen::generate!({
    world: "wasmnet:link/stepped-device",
    path: ["../../wit/deps/config", "../../wit/link"],
    // Not covered by any WASI binding crate: generate our own bindings for the vendored WIT.
    with: { "wasi:config/store@0.2.0-rc.1": generate },
});

use exports::wasmnet::link::device::Guest;
use wasi::config::store;
use wasmnet::link::log::{self, Level};
use wasmnet::link::types::PortInfo;
use wasmnet::link::wire;

thread_local! {
    // A component instance is single-threaded, so this is the instance's state.
    static STATE: RefCell<Option<WanPort>> = const { RefCell::new(None) };
}

/// Builds the WAN port from its config. An invalid config is a configuration error: it is
/// logged, then the device traps.
fn create() -> WanPort {
    let config = Config::from_lookup(|key| store::get(key).ok().flatten()).unwrap_or_else(|e| {
        log::log(Level::Error, &e.to_string());
        panic!("wan-port: {e}")
    });
    let port = WanPort::new(config);
    log::log(Level::Info, &format!("wan-port: {}", port.describe()));
    port
}

/// Runs `f` on the WAN port, creating it on first use.
fn with<R>(f: impl FnOnce(&mut WanPort) -> R) -> R {
    STATE.with(|s| f(s.borrow_mut().get_or_insert_with(create)))
}

/// Frames go straight to `wire.transmit`, events to `log.event`. Both imports are sync and
/// never re-enter this device.
struct Host;

impl Sink for Host {
    fn transmit(&mut self, port: u32, frame: &[u8]) {
        wire::transmit(port, frame);
    }

    fn event(&mut self, kind: &str, fields: &[(String, String)]) {
        log::event(kind, fields);
    }
}

struct Component;

impl Guest for Component {
    fn ports() -> Vec<PortInfo> {
        with(|t| {
            let c = t.config();
            vec![
                PortInfo {
                    id: ACCESS,
                    name: "access".to_owned(),
                    mac: None,
                    mtu: c.mtu,
                },
                PortInfo {
                    id: WAN,
                    name: "wan".to_owned(),
                    mac: Some(c.mac.octets().to_vec()),
                    mtu: c.mtu + OVERHEAD + 4,
                },
            ]
        })
    }

    fn receive(_now: u64, port: u32, frame: Vec<u8>) {
        with(|t| t.receive(port, &frame, &mut Host));
    }

    fn poll(_now: u64) -> Option<u64> {
        None
    }

    fn link_state(_now: u64, port: u32, up: bool) {
        with(|t| t.link_state(port, up));
    }
}

export!(Component);
