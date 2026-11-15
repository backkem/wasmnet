//! wit-bindgen glue for the `async-device` variant (feature `async-device`).
//!
//! `start()` spawns a long-lived task that takes frames off an rx queue. Each frame gets its own
//! task, which waits [`ASYNC_DELAY_NS`] on virtual `wasi:clocks` and then transmits the echo.
//! `receive` only enqueues and wakes (see `docs/design/async-under-virtual-time.md`), and
//! `poll` always returns `none`.

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::task::{Poll, Waker};

use wasip3::clocks::monotonic_clock;
use wasmnet_wire::MacAddr;

use crate::{ASYNC_DELAY_NS, PORT, Reflector, mac_from_config};

wit_bindgen::generate!({
    world: "wasmnet:link/async-device",
    path: ["../../wit/deps/config", "../../wit/link"],
    // Not covered by the `wasip2` crate: generate our own bindings for the vendored WIT.
    with: { "wasi:config/store@0.2.0-rc.1": generate },
});

use exports::wasmnet::link::{device, lifecycle};
use wasi::config::store;
use wasmnet::link::log::{self, Level};
use wasmnet::link::types::PortInfo;
use wasmnet::link::wire;

struct State {
    reflector: Reflector,
    rx: VecDeque<(u32, Vec<u8>)>,
    rx_waker: Option<Waker>,
}

thread_local! {
    // A component instance is single-threaded, so this is the instance's state.
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

/// Builds the state with the configured `mac` (as the stepped variant does), or one from the
/// seeded `wasi:random`. An invalid config is a configuration error: it is logged, then the
/// device traps.
fn create() -> State {
    let mac = mac_from_config(store::get("mac").ok().flatten()).unwrap_or_else(|e| {
        log::log(Level::Error, &e);
        panic!("reflector: {e}")
    });
    let mac =
        mac.unwrap_or_else(|| MacAddr::local_from_seed(wasip2::random::random::get_random_u64()));
    State {
        reflector: Reflector::new(mac),
        rx: VecDeque::new(),
        rx_waker: None,
    }
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(s.borrow_mut().get_or_insert_with(create)))
}

async fn next_rx() -> (u32, Vec<u8>) {
    poll_fn(|cx| {
        with(|s| match s.rx.pop_front() {
            Some(item) => Poll::Ready(item),
            None => {
                s.rx_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
    })
    .await
}

async fn echo_loop() {
    loop {
        let (port, frame) = next_rx().await;
        wit_bindgen::spawn_local(async move {
            monotonic_clock::wait_for(ASYNC_DELAY_NS).await;
            with(|s| {
                s.reflector
                    .receive(port, &frame, |port, echo| wire::transmit(port, &echo))
            });
        });
    }
}

struct Component;

impl device::Guest for Component {
    fn ports() -> Vec<PortInfo> {
        vec![PortInfo {
            id: PORT,
            name: "eth0".to_owned(),
            mac: Some(with(|s| s.reflector.mac()).octets().to_vec()),
            mtu: 1500,
        }]
    }

    fn receive(_now: u64, port: u32, frame: Vec<u8>) {
        // Wake outside the borrow: the woken task runs later, but keep the rule simple.
        let waker = with(|s| {
            s.rx.push_back((port, frame));
            s.rx_waker.take()
        });
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn poll(_now: u64) -> Option<u64> {
        None
    }

    fn link_state(_now: u64, _port: u32, _up: bool) {}
}

impl lifecycle::Guest for Component {
    async fn start() {
        wit_bindgen::spawn_local(echo_loop());
    }
}

export!(Component);
