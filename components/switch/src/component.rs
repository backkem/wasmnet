//! wit-bindgen glue: exports `wasmnet:link/device` and `wasmnet:reconfigure/reconfigure` over
//! [`crate::Switch`].

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::RefCell;

use crate::{Config, Event, Sink, Switch};

wit_bindgen::generate!({
    inline: "
        package wasmnet:switch-device;
        world switch {
            include wasmnet:link/stepped-device@0.1.0;
            export wasmnet:reconfigure/reconfigure@0.1.0;
        }
    ",
    path: ["../../wit/deps/config", "../../wit/link", "../../wit/reconfigure"],
    generate_all,
    // Not covered by any WASI binding crate: generate our own bindings for the vendored WIT.
    with: { "wasi:config/store@0.2.0-rc.1": generate },
});

use exports::wasmnet::link::device::Guest;
use exports::wasmnet::reconfigure::reconfigure::{self, Refusal};
use wasi::config::store;
use wasmnet::link::log::{self, Level};
use wasmnet::link::types::PortInfo;
use wasmnet::link::wire;

thread_local! {
    // A component instance is single-threaded, so this is the instance's state.
    static STATE: RefCell<Option<Switch>> = const { RefCell::new(None) };
}

/// Builds the switch from its config. An invalid config is a configuration error: it is
/// logged, then the device traps.
fn create() -> Switch {
    let config = Config::from_lookup(|key| store::get(key).ok().flatten()).unwrap_or_else(|e| {
        log::log(Level::Error, &e.to_string());
        panic!("switch: {e}")
    });
    let switch = Switch::new(config);
    log::log(Level::Info, &format!("switch: {}", switch.describe()));
    switch
}

/// Runs `f` on the switch, creating it on first use.
fn with<R>(f: impl FnOnce(&mut Switch) -> R) -> R {
    STATE.with(|s| f(s.borrow_mut().get_or_insert_with(create)))
}

/// Frames go straight to `wire.transmit`, events to `log.event`. Both imports are sync and
/// never re-enter this device, so calling them while the switch is borrowed is fine.
struct Host;

impl Sink for Host {
    fn transmit(&mut self, port: u32, frame: &[u8]) {
        wire::transmit(port, frame);
    }

    fn event(&mut self, event: Event) {
        log::event(event.kind(), &event.fields());
    }
}

struct Component;

impl Guest for Component {
    fn ports() -> Vec<PortInfo> {
        with(|sw| {
            let mtu = sw.config().mtu;
            (0..sw.config().ports)
                .map(|id| PortInfo {
                    id,
                    name: format!("p{id}"),
                    mac: None,
                    mtu,
                })
                .collect()
        })
    }

    fn receive(now: u64, port: u32, frame: Vec<u8>) {
        with(|sw| sw.receive(now, port, &frame, &mut Host));
    }

    fn poll(now: u64) -> Option<u64> {
        with(|sw| sw.poll(now, &mut Host))
    }

    fn link_state(now: u64, port: u32, up: bool) {
        with(|sw| sw.link_state(now, port, up, &mut Host));
    }
}

impl reconfigure::Guest for Component {
    /// A new aging time or table size in place; other ports or another MTU need a restart.
    fn reconfigure(_now: u64, config: Vec<(String, String)>) -> Result<(), Refusal> {
        let new = Config::from_lookup(|key| {
            config
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
        })
        .map_err(|e| Refusal::Invalid(e.to_string()))?;
        with(|sw| sw.reconfigure(new, &mut Host)).map_err(Refusal::Restart)
    }
}

export!(Component);
