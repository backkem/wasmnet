//! wit-bindgen glue: exports `wasmnet:link/device` over [`crate::Blaster`].

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::RefCell;

use wasmnet_wire::MacAddr;

use crate::{Blaster, Config, PORT};

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
    static STATE: RefCell<Option<Blaster>> = const { RefCell::new(None) };
}

/// Builds the blaster from its config. The MAC comes from `mac` or else from the seeded
/// `wasi:random`. An invalid config is a configuration error: it is logged, then the device traps.
fn create() -> Blaster {
    let config = Config::from_lookup(|key| store::get(key).ok().flatten()).unwrap_or_else(|e| {
        log::log(Level::Error, &e.to_string());
        panic!("blaster: {e}")
    });
    let mac = config
        .mac
        .unwrap_or_else(|| MacAddr::local_from_seed(wasip2::random::random::get_random_u64()));
    Blaster::with_config(mac, config)
}

/// Runs `f` on the blaster, creating it on first use.
fn with<R>(f: impl FnOnce(&mut Blaster) -> R) -> R {
    STATE.with(|s| f(s.borrow_mut().get_or_insert_with(create)))
}

struct Component;

impl Guest for Component {
    fn ports() -> Vec<PortInfo> {
        vec![PortInfo {
            id: PORT,
            name: "eth0".to_owned(),
            mac: Some(with(|b| b.mac()).octets().to_vec()),
            mtu: 1500,
        }]
    }

    fn receive(now: u64, _port: u32, frame: Vec<u8>) {
        if let Some(echo) = with(|b| b.receive(now, &frame)) {
            let message = format!("echo seq={} rtt={}ns", echo.seq, echo.rtt);
            log::log(Level::Info, &message);
        }
    }

    fn poll(now: u64) -> Option<u64> {
        with(|b| b.poll(now, |port, frame| wire::transmit(port, &frame)))
    }

    fn link_state(_now: u64, _port: u32, _up: bool) {}
}

export!(Component);
