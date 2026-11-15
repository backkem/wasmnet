//! wit-bindgen glue: exports `wasmnet:link/device` and `wasmnet:link/counters` over
//! [`crate::Router`] (world `wasmnet:router/router`).

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::RefCell;

use crate::{Config, Event, Router, Sink};

wit_bindgen::generate!({
    world: "wasmnet:router/router",
    path: ["../../wit/deps/config", "../../wit/link", "../../wit/router"],
    // The world lives in its own package, so the `wasmnet:link` interfaces are dependencies.
    generate_all,
    // Not covered by any WASI binding crate: generate our own bindings for the vendored WIT.
    with: { "wasi:config/store@0.2.0-rc.1": generate },
});

use exports::wasmnet::link::{counters, device};
use wasi::config::store;
use wasmnet::link::log::{self, Level};
use wasmnet::link::types::PortInfo;
use wasmnet::link::wire;

thread_local! {
    // A component instance is single-threaded, so this is the instance's state.
    static STATE: RefCell<Option<Router>> = const { RefCell::new(None) };
}

/// Builds the router from its config. An invalid config is a configuration error: it is logged,
/// then the device traps.
fn create() -> Router {
    let pairs = store::get_all().unwrap_or_else(|e| {
        log::log(Level::Error, &format!("router: wasi:config get-all: {e:?}"));
        panic!("router: wasi:config get-all failed")
    });
    let config = Config::from_pairs(pairs).unwrap_or_else(|e| {
        log::log(Level::Error, &e.to_string());
        panic!("router: {e}")
    });
    let router = Router::new(config);
    for line in router.describe() {
        log::log(Level::Info, &line);
    }
    router
}

/// Runs `f` on the router, creating it on first use.
fn with<R>(f: impl FnOnce(&mut Router) -> R) -> R {
    STATE.with(|s| f(s.borrow_mut().get_or_insert_with(create)))
}

/// Frames go straight to `wire.transmit`, events to `log.event`. Both imports are sync and never
/// re-enter this device, so calling them while the router is borrowed is fine.
struct Host;

impl Sink for Host {
    fn transmit(&mut self, port: u32, frame: Vec<u8>) {
        wire::transmit(port, &frame);
    }

    fn event(&mut self, event: Event) {
        log::event(event.kind, &event.fields);
    }
}

struct Component;

impl device::Guest for Component {
    fn ports() -> Vec<PortInfo> {
        with(|r| {
            r.config()
                .ports
                .iter()
                .enumerate()
                .map(|(n, p)| PortInfo {
                    id: n as u32,
                    name: format!("p{n}"),
                    mac: Some(p.mac.octets().to_vec()),
                    mtu: u32::from(p.mtu),
                })
                .collect()
        })
    }

    fn receive(now: u64, port: u32, frame: Vec<u8>) {
        with(|r| r.receive(now, port, &frame, &mut Host));
    }

    fn poll(now: u64) -> Option<u64> {
        with(|r| r.poll(now, &mut Host))
    }

    fn link_state(now: u64, port: u32, up: bool) {
        with(|r| r.link_state(now, port, up, &mut Host));
    }
}

impl counters::Guest for Component {
    fn counters() -> Vec<(String, u64)> {
        with(|r| r.counter_list())
    }
}

export!(Component);
