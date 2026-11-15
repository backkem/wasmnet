//! wit-bindgen glue: exports `wasi:cli/run@0.3.0`, and serves mDNS through the standard `wasip3`
//! socket bindings plus `wasmnet:sockets-ext/{multicast,interfaces}` (world `wasmnet:app/app`).
//!
//! One UDP socket per family, bound to port 5353 and joined to the family's group, and one task
//! that waits for the first of: a datagram on either socket, or the responder's next deadline.

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;

use wasip3::clocks::monotonic_clock;
use wasip3::sockets::types::{ErrorCode, IpAddress, IpAddressFamily, IpSocketAddress, UdpSocket};
use wasmnet_wire::dns::{MDNS_PORT, MDNS_V4, MDNS_V6};

use crate::{APP, Config, Dest, Note, Packet, Responder, app_pairs};

use wasmnet_app_kit::{to_std, to_wit};

wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};
use wasmnet::sockets_ext::{interfaces, multicast};

fn wit_ip(a: IpAddr) -> IpAddress {
    match a {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            IpAddress::Ipv4((a, b, c, d))
        }
        IpAddr::V6(v6) => {
            let [a, b, c, d, e, f, g, h] = v6.segments();
            IpAddress::Ipv6((a, b, c, d, e, f, g, h))
        }
    }
}

fn std_ip(a: IpAddress) -> IpAddr {
    match a {
        IpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        IpAddress::Ipv6((a, b, c, d, e, f, g, h)) => {
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
        }
    }
}

/// The node's addresses now (they can change: a DHCP lease).
fn addresses() -> Vec<IpAddr> {
    interfaces::list_interfaces()
        .into_iter()
        .flat_map(|i| i.addresses.into_iter().map(|a| std_ip(a.address)))
        .collect()
}

/// A socket bound to port 5353 of `family`, joined to its group: hop limit 255, loopback off.
fn open(v6: bool) -> Result<UdpSocket, String> {
    let (family, any, group) = if v6 {
        (
            IpAddressFamily::Ipv6,
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, MDNS_PORT)),
            IpAddr::V6(MDNS_V6),
        )
    } else {
        (
            IpAddressFamily::Ipv4,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)),
            IpAddr::V4(MDNS_V4),
        )
    };
    let err = |what: &str, e: ErrorCode| format!("{what} ({group}): {e:?}");
    let s = UdpSocket::create(family).map_err(|e| err("create", e))?;
    s.bind(to_wit(any)).map_err(|e| err("bind", e))?;
    multicast::join_multicast_group(&s, wit_ip(group), 1).map_err(|e| err("join", e))?;
    multicast::set_multicast_hop_limit(&s, 255).map_err(|e| err("hop limit", e))?;
    multicast::set_multicast_loopback(&s, false).map_err(|e| err("loopback", e))?;
    multicast::set_multicast_interface(&s, 1).map_err(|e| err("interface", e))?;
    // RFC 6762 §11: unicast answers too.
    s.set_unicast_hop_limit(255)
        .map_err(|e| err("unicast hop limit", e))?;
    Ok(s)
}

fn emit(notes: Vec<Note>) {
    for (kind, fields) in notes {
        log::log(
            Level::Info,
            &format!(
                "{APP}: {kind} {}",
                fields
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        );
        log::event(kind, &fields);
    }
}

type Recv<'a> = Pin<Box<dyn Future<Output = Result<(Vec<u8>, IpSocketAddress), ErrorCode>> + 'a>>;

enum Wake {
    Datagram(bool, Result<(Vec<u8>, IpSocketAddress), ErrorCode>),
    Timer,
}

async fn send_all(v4: Option<&UdpSocket>, v6: Option<&UdpSocket>, packets: Vec<Packet>) {
    for p in packets {
        let (socket, to) = match p.to {
            Dest::Group { v6: false } => (v4, SocketAddr::from((MDNS_V4, MDNS_PORT))),
            Dest::Group { v6: true } => (v6, SocketAddr::from((MDNS_V6, MDNS_PORT))),
            Dest::Unicast(a) => (if a.is_ipv4() { v4 } else { v6 }, a),
        };
        let Some(socket) = socket else { continue };
        if let Err(e) = socket.send(p.message.encode(), Some(to_wit(to))).await {
            log::log(Level::Warn, &format!("{APP}: send to {to}: {e:?}"));
        }
    }
}

async fn serve() -> Result<(), String> {
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let config = Config::from_pairs(app_pairs(pairs, APP)).map_err(|e| e.to_string())?;
    let v4 = if config.ipv4 {
        Some(open(false)?)
    } else {
        None
    };
    let v6 = if config.ipv6 { Some(open(true)?) } else { None };
    let t0 = monotonic_clock::now();
    let mut config = config;
    config.start_ns += t0;
    let mut r = Responder::new(config);
    log::log(
        Level::Info,
        &format!(
            "{APP}: claiming {} on {}",
            r.name,
            [(v4.is_some(), "224.0.0.251"), (v6.is_some(), "ff02::fb")]
                .iter()
                .filter(|(on, _)| *on)
                .map(|(_, g)| *g)
                .collect::<Vec<_>>()
                .join(" and ")
        ),
    );
    let mut r4: Option<Recv<'_>> = v4.as_ref().map(|s| Box::pin(s.receive()) as Recv<'_>);
    let mut r6: Option<Recv<'_>> = v6.as_ref().map(|s| Box::pin(s.receive()) as Recv<'_>);
    loop {
        let deadline = r.next_deadline();
        let mut timer = deadline.map(|t| Box::pin(monotonic_clock::wait_until(t)));
        let wake = poll_fn(|cx| {
            if let Some(f) = r4.as_mut()
                && let Poll::Ready(d) = f.as_mut().poll(cx)
            {
                return Poll::Ready(Wake::Datagram(false, d));
            }
            if let Some(f) = r6.as_mut()
                && let Poll::Ready(d) = f.as_mut().poll(cx)
            {
                return Poll::Ready(Wake::Datagram(true, d));
            }
            if let Some(t) = timer.as_mut()
                && t.as_mut().poll(cx).is_ready()
            {
                return Poll::Ready(Wake::Timer);
            }
            Poll::Pending
        })
        .await;
        // A pending timer is dropped here (cancelled); a fresh one is armed next round.
        drop(timer);
        let now = monotonic_clock::now();
        let (packets, notes) = match wake {
            Wake::Timer => r.tick(now, &addresses()),
            Wake::Datagram(is_v6, got) => {
                // Arm the next receive on that socket first.
                if is_v6 {
                    r6 = v6.as_ref().map(|s| Box::pin(s.receive()) as Recv<'_>);
                } else {
                    r4 = v4.as_ref().map(|s| Box::pin(s.receive()) as Recv<'_>);
                }
                let (data, from) = got.map_err(|e| format!("receive: {e:?}"))?;
                r.on_packet(now, to_std(from), is_v6, &data, &addresses())
            }
        };
        emit(notes);
        send_all(v4.as_ref(), v6.as_ref(), packets).await;
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
