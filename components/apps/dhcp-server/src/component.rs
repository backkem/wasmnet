//! wit-bindgen glue: exports `wasi:cli/run@0.3.0` and serves DHCP through the standard `wasip3`
//! socket bindings (world `wasmnet:app/app`).

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use wasip3::clocks::monotonic_clock;
use wasip3::sockets::types::{IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, UdpSocket};

use crate::{APP, Config, Server, app_pairs};

wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};

fn to_wit(a: SocketAddr) -> IpSocketAddress {
    let v4 = match a {
        SocketAddr::V4(v4) => v4,
        // The config only allows IPv4 (DHCPv4).
        SocketAddr::V6(_) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, a.port()),
    };
    let [a, b, c, d] = v4.ip().octets();
    IpSocketAddress::Ipv4(Ipv4SocketAddress {
        port: v4.port(),
        address: (a, b, c, d),
    })
}

fn from_wit(a: IpSocketAddress) -> String {
    match a {
        IpSocketAddress::Ipv4(v4) => {
            let (a, b, c, d) = v4.address;
            SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), v4.port).to_string()
        }
        IpSocketAddress::Ipv6(v6) => format!("[{:?}]:{}", v6.address, v6.port),
    }
}

async fn serve() -> Result<(), String> {
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let config = Config::from_pairs(app_pairs(pairs, APP)).map_err(|e| e.to_string())?;
    let socket = UdpSocket::create(IpAddressFamily::Ipv4).map_err(|e| format!("create: {e:?}"))?;
    socket
        .bind(to_wit(config.listen))
        .map_err(|e| format!("bind {}: {e:?}", config.listen))?;
    let pools: Vec<String> = config
        .pools
        .iter()
        .map(|p| {
            format!(
                "{} {}/{} {}-{}",
                p.name, p.network, p.prefix, p.first, p.last
            )
        })
        .collect();
    log::log(
        Level::Info,
        &format!(
            "{APP}: listening on udp {} as {}; pools {}",
            config.listen,
            config.server_id,
            pools.join(", ")
        ),
    );
    log::event(
        "dhcp-server-listening",
        &[
            ("address".to_owned(), config.listen.to_string()),
            ("pools".to_owned(), pools.join(",")),
        ],
    );
    let mut server = Server::new(config);
    loop {
        let (data, from) = socket
            .receive()
            .await
            .map_err(|e| format!("receive: {e:?}"))?;
        let now = monotonic_clock::now();
        let (reply, notes) = server.handle(now, &data);
        for (kind, fields) in &notes {
            log::log(
                Level::Info,
                &format!(
                    "{APP}: {kind} from {}: {}",
                    from_wit(from),
                    fields
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            );
            log::event(kind, fields);
        }
        if let Some(reply) = reply {
            // A send error (an unroutable relay, say) is logged; the server keeps serving.
            if let Err(e) = socket
                .send(reply.message.encode(), Some(to_wit(reply.to)))
                .await
            {
                log::log(Level::Warn, &format!("{APP}: send to {}: {e:?}", reply.to));
            }
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
