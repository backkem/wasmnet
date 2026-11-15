//! wit-bindgen glue: exports `wasi:cli/run@0.3.0` and serves UDP echo through the standard
//! `wasip3` socket bindings (world `wasmnet:app/app`).

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use wasip3::sockets::types::{IpAddressFamily, UdpSocket};

use crate::{APP, Config, app_pairs};

use wasmnet_app_kit::{to_std, to_wit};

wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};

async fn serve() -> Result<(), String> {
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let config = Config::from_pairs(app_pairs(pairs, APP)).map_err(|e| e.to_string())?;
    let family = if config.listen.is_ipv4() {
        IpAddressFamily::Ipv4
    } else {
        IpAddressFamily::Ipv6
    };
    let socket = UdpSocket::create(family).map_err(|e| format!("create: {e:?}"))?;
    socket
        .bind(to_wit(config.listen))
        .map_err(|e| format!("bind {}: {e:?}", config.listen))?;
    let local = socket
        .get_local_address()
        .map(to_std)
        .map_err(|e| format!("local address: {e:?}"))?;
    log::log(Level::Info, &format!("{APP}: listening on udp {local}"));
    log::event(
        "udp-echo-listening",
        &[("address".to_owned(), local.to_string())],
    );

    let mut echoed = 0u32;
    loop {
        let (data, from) = socket
            .receive()
            .await
            .map_err(|e| format!("receive: {e:?}"))?;
        let bytes = data.len();
        let peer = to_std(from);
        // Back to back: each `send` returns once the datagram is queued in the netstack. A
        // datagram that cannot be answered (a source the stack refuses to send to) is the
        // sender's problem, not a reason to stop serving.
        let mut refused = None;
        for _ in 0..config.copies {
            if let Err(e) = socket.send(data.clone(), Some(from)).await {
                refused = Some(e);
                break;
            }
        }
        if let Some(e) = refused {
            log::log(Level::Warn, &format!("{APP}: cannot answer {peer}: {e:?}"));
            continue;
        }
        log::log(
            Level::Info,
            &format!("{APP}: echoed {bytes} bytes to {peer}"),
        );
        log::event(
            "udp-echoed",
            &[
                ("peer".to_owned(), peer.to_string()),
                ("bytes".to_owned(), bytes.to_string()),
            ],
        );
        echoed += 1;
        if config.count == Some(echoed) {
            return Ok(());
        }
    }
}

struct App;

impl exports::wasi::cli::run::Guest for App {
    async fn run() -> Result<(), ()> {
        serve().await.map_err(|e| {
            log::log(Level::Error, &format!("{APP}: {e}"));
        })
    }
}

export!(App);
