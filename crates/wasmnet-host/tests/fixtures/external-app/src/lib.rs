//! hello: a wasmnet app in a crate of its own. It sends one UDP datagram to an echo server,
//! waits for it to come back, and journals the round trip.
//!
//! Config (keys under `app.hello.`): `peer`, the echo server's socket address (`10.0.0.1:7`),
//! and `text`, what to send (default `hello`).

use std::net::SocketAddr;

use wasmnet_app_kit::wasip3::clocks::monotonic_clock;
use wasmnet_app_kit::wasip3::sockets::types::{IpAddressFamily, UdpSocket};
use wasmnet_app_kit::{app_pairs, to_std, to_wit};

// The bindings of world `wasmnet:app/app`: the modules `wasi`, `wasmnet` and `exports`, the
// `export!` macro and the `event` helper. No WIT files, no `wit_bindgen::generate!`.
wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};

/// The app's name: its config prefix (`app.hello.`) and its node export (`app-hello`).
const APP: &str = "hello";

async fn hello() -> Result<(), String> {
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let (mut peer, mut text) = (None, "hello".to_owned());
    for (key, value) in app_pairs(pairs, APP) {
        match key.as_str() {
            "peer" => peer = Some(value),
            "text" => text = value,
            other => return Err(format!("unknown key `{other}`")),
        }
    }
    let peer: SocketAddr = peer
        .ok_or("`peer` is required")?
        .parse()
        .map_err(|e| format!("peer: {e}"))?;

    // One millisecond of virtual time: the clock is the simulation's.
    monotonic_clock::wait_for(1_000_000).await;

    let family = if peer.is_ipv4() {
        IpAddressFamily::Ipv4
    } else {
        IpAddressFamily::Ipv6
    };
    let socket = UdpSocket::create(family).map_err(|e| format!("create: {e:?}"))?;
    socket
        .connect(to_wit(peer))
        .map_err(|e| format!("connect {peer}: {e:?}"))?;
    let sent_at = monotonic_clock::now();
    socket
        .send(text.clone().into_bytes(), None)
        .await
        .map_err(|e| format!("send: {e:?}"))?;
    event("hello-sent", &[("peer", peer.to_string())]);

    let (data, from) = socket
        .receive()
        .await
        .map_err(|e| format!("receive: {e:?}"))?;
    let rtt = monotonic_clock::now() - sent_at;
    event(
        "hello-echoed",
        &[
            ("from", to_std(from).to_string()),
            ("text", String::from_utf8_lossy(&data).into_owned()),
            ("rtt-ns", rtt.to_string()),
        ],
    );
    if data == text.as_bytes() {
        Ok(())
    } else {
        Err("the echo is not what was sent".to_owned())
    }
}

struct App;

impl exports::wasi::cli::run::Guest for App {
    async fn run() -> Result<(), ()> {
        hello().await.map_err(|e| {
            log::log(Level::Error, &format!("{APP}: {e}"));
        })
    }
}

export!(App);
