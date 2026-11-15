//! wit-bindgen glue: exports `wasmnet:link/device` over [`crate::Reflector`].

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::RefCell;

use wasmnet_wire::MacAddr;

use crate::{PORT, Reflector, mac_from_config};

wit_bindgen::generate!({
    world: "wasmnet:link/stepped-device",
    path: ["../../wit/deps/config", "../../wit/link"],
    // Not covered by the `wasip2` crate: generate our own bindings for the vendored WIT.
    with: { "wasi:config/store@0.2.0-rc.1": generate },
});

use exports::wasmnet::link::device::Guest;
use wasi::config::store;
use wasmnet::link::log::{self, Level};
use wasmnet::link::types::PortInfo;
use wasmnet::link::wire;

thread_local! {
    // A component instance is single-threaded, so this is the instance's state.
    static STATE: RefCell<Option<Reflector>> = const { RefCell::new(None) };
}

/// Builds the reflector with the configured `mac`, or one from the seeded `wasi:random`.
/// An invalid config is a configuration error: it is logged, then the device traps.
fn create() -> Reflector {
    let mac = mac_from_config(store::get("mac").ok().flatten()).unwrap_or_else(|e| {
        log::log(Level::Error, &e);
        panic!("reflector: {e}")
    });
    let mac =
        mac.unwrap_or_else(|| MacAddr::local_from_seed(wasip2::random::random::get_random_u64()));
    Reflector::new(mac)
}

/// Runs `f` on the reflector, creating it on first use.
fn with<R>(f: impl FnOnce(&mut Reflector) -> R) -> R {
    STATE.with(|s| f(s.borrow_mut().get_or_insert_with(create)))
}

struct Component;

impl Guest for Component {
    fn ports() -> Vec<PortInfo> {
        vec![PortInfo {
            id: PORT,
            name: "eth0".to_owned(),
            mac: Some(with(|r| r.mac()).octets().to_vec()),
            mtu: 1500,
        }]
    }

    fn receive(_now: u64, port: u32, frame: Vec<u8>) {
        with(|r| r.receive(port, &frame, |port, echo| wire::transmit(port, &echo)));
    }

    fn poll(_now: u64) -> Option<u64> {
        None
    }

    fn link_state(_now: u64, _port: u32, _up: bool) {}
}

export!(Component);
