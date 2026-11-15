//! wit-bindgen glue: exports `wasi:cli/run@0.3.0` and serves DNS through the standard `wasip3`
//! socket bindings (world `wasmnet:app/app`).

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use wasip3::sockets::types::{IpAddressFamily, UdpSocket};

use crate::{APP, Config, Server, app_pairs};

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
    let zones = config.zones.join(",");
    log::log(
        Level::Info,
        &format!(
            "{APP}: listening on udp {}, authoritative for {zones} ({} records)",
            config.listen,
            config.record_count()
        ),
    );
    log::event(
        "dns-server-listening",
        &[
            ("address".to_owned(), config.listen.to_string()),
            ("zones".to_owned(), zones),
            ("records".to_owned(), config.record_count().to_string()),
        ],
    );
    let server = Server::new(config);
    loop {
        let (data, from) = socket
            .receive()
            .await
            .map_err(|e| format!("receive: {e:?}"))?;
        let peer = to_std(from);
        let (reply, note) = server.answer(&peer.to_string(), &data);
        if let Some((kind, fields)) = &note {
            log::log(
                Level::Info,
                &format!(
                    "{APP}: {}",
                    fields
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            );
            log::event(kind, fields);
        }
        if let Some(reply) = reply
            && let Err(e) = socket.send(reply, Some(from)).await
        {
            log::log(Level::Warn, &format!("{APP}: send to {peer}: {e:?}"));
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
