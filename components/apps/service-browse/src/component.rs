//! wit-bindgen glue: exports `wasi:cli/run@0.3.0`, and browses over the standard `wasip3`
//! socket bindings plus `wasmnet:sockets-ext/multicast` (world `wasmnet:app/app`).
//!
//! One UDP socket per family, bound to port 5353 (or any port, when the node's responder holds
//! 5353) and joined to the family's group, and one task that waits for the first of: a
//! datagram on either socket, or the browser's next deadline. A fetch runs inline: datagrams
//! wait in their sockets meanwhile.

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;

use wasip3::clocks::monotonic_clock;
use wasip3::sockets::types::{
    ErrorCode, IpAddress, IpAddressFamily, IpSocketAddress, TcpSocket, UdpSocket,
};
use wasmnet_app_kit::mdns::{Browser, Event, Resolved};
use wasmnet_wire::dns::{MDNS_PORT, MDNS_V4, MDNS_V6, Message};
use wit_bindgen::StreamResult;

use crate::{APP, Config, Note, app_pairs, note, request, response};

use wasmnet_app_kit::{error_name, to_wit};

wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};
use wasmnet::sockets_ext::multicast;

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

/// A socket of `family` joined to its group: port 5353 if it is free, else any port. Hop limit
/// 255 (RFC 6762 §11), loopback off.
fn open(v6: bool) -> Result<UdpSocket, String> {
    let (family, any, group) = if v6 {
        (
            IpAddressFamily::Ipv6,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(MDNS_V6),
        )
    } else {
        (
            IpAddressFamily::Ipv4,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(MDNS_V4),
        )
    };
    let err = |what: &str, e: ErrorCode| format!("{what} ({group}): {e:?}");
    let mut s = UdpSocket::create(family).map_err(|e| err("create", e))?;
    if let Err(e) = s.bind(to_wit(SocketAddr::new(any, MDNS_PORT))) {
        if !matches!(e, ErrorCode::AddressInUse) {
            return Err(err("bind", e));
        }
        log::log(
            Level::Info,
            &format!("{APP}: port 5353 ({group}) is taken; querying from another port"),
        );
        s = UdpSocket::create(family).map_err(|e| err("create", e))?;
        s.bind(to_wit(SocketAddr::new(any, 0)))
            .map_err(|e| err("bind", e))?;
    }
    multicast::join_multicast_group(&s, wit_ip(group), 1).map_err(|e| err("join", e))?;
    multicast::set_multicast_hop_limit(&s, 255).map_err(|e| err("hop limit", e))?;
    multicast::set_multicast_loopback(&s, false).map_err(|e| err("loopback", e))?;
    multicast::set_multicast_interface(&s, 1).map_err(|e| err("interface", e))?;
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

async fn send_queries(v4: Option<&UdpSocket>, v6: Option<&UdpSocket>, queries: Vec<Message>) {
    for q in queries {
        let bytes = q.encode();
        for (socket, to) in [
            (v4, SocketAddr::from((MDNS_V4, MDNS_PORT))),
            (v6, SocketAddr::from((MDNS_V6, MDNS_PORT))),
        ] {
            let Some(socket) = socket else { continue };
            if let Err(e) = socket.send(bytes.clone(), Some(to_wit(to))).await {
                log::log(Level::Warn, &format!("{APP}: send to {to}: {e:?}"));
            }
        }
    }
}

/// `GET <path>` from the instance's first address and port, read to the server's close.
async fn fetch(r: &Resolved, path: &str) -> Note {
    let kv = |k: &str, v: String| (k.to_owned(), v);
    let failed = |address: String, error: String| {
        (
            "dnssd-fetch-failed",
            vec![
                kv("instance", r.instance.clone()),
                kv("address", address),
                kv("error", error),
            ],
        )
    };
    let Some(ip) = r.addresses.first().copied() else {
        return failed(String::new(), "no address".into());
    };
    let peer = SocketAddr::new(ip, r.port);
    let family = if ip.is_ipv4() {
        IpAddressFamily::Ipv4
    } else {
        IpAddressFamily::Ipv6
    };
    let socket = match TcpSocket::create(family) {
        Ok(s) => s,
        Err(e) => return failed(peer.to_string(), error_name(&format!("{e:?}"))),
    };
    if let Err(e) = socket.connect(to_wit(peer)).await {
        return failed(peer.to_string(), error_name(&format!("{e:?}")));
    }
    let (mut rx, rx_done) = socket.receive();
    let (mut tx, tx_reader) = wasip3::wit_stream::new::<u8>();
    let send_done = socket.send(tx_reader);
    if !tx.write_all(request(r, path)).await.is_empty() {
        return failed(
            peer.to_string(),
            "closed before the request was sent".into(),
        );
    }
    drop(tx);
    let mut got = Vec::new();
    loop {
        let (status, chunk) = rx.read(Vec::with_capacity(4096)).await;
        match status {
            StreamResult::Complete(_) => got.extend_from_slice(&chunk),
            StreamResult::Dropped => break,
            StreamResult::Cancelled => {}
        }
        if got.len() > 1 << 20 {
            break;
        }
    }
    let _ = send_done.await;
    let _ = rx_done.await;
    drop(rx);
    drop(socket);
    match response(&got) {
        Some((status, body)) => (
            "dnssd-fetched",
            vec![
                kv("instance", r.instance.clone()),
                kv("address", ip.to_string()),
                kv("port", r.port.to_string()),
                kv("status", status.to_string()),
                kv("body-bytes", body.to_string()),
            ],
        ),
        None => failed(peer.to_string(), "no HTTP response".into()),
    }
}

type Recv<'a> = Pin<Box<dyn Future<Output = Result<(Vec<u8>, IpSocketAddress), ErrorCode>> + 'a>>;

enum Wake {
    Datagram(bool, Result<(Vec<u8>, IpSocketAddress), ErrorCode>),
    Timer,
}

async fn serve() -> Result<(), String> {
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let config = Config::from_pairs(app_pairs(pairs, APP)).map_err(|e| e.to_string())?;
    if config.start_ns > 0 {
        monotonic_clock::wait_for(config.start_ns).await;
    }
    let v4 = if config.ipv4 {
        Some(open(false)?)
    } else {
        None
    };
    let v6 = if config.ipv6 { Some(open(true)?) } else { None };
    let mut browser = Browser::new(config.seed());
    let now = monotonic_clock::now();
    for t in &config.types {
        browser.browse(now, t);
    }
    log::log(
        Level::Info,
        &format!("{APP}: browsing {}", config.types.join(",")),
    );
    let mut fetched = false;
    let mut r4: Option<Recv<'_>> = v4.as_ref().map(|s| Box::pin(s.receive()) as Recv<'_>);
    let mut r6: Option<Recv<'_>> = v6.as_ref().map(|s| Box::pin(s.receive()) as Recv<'_>);
    loop {
        let deadline = browser.next_deadline();
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
        let (queries, events) = match wake {
            Wake::Timer => browser.tick(now),
            Wake::Datagram(is_v6, got) => {
                if is_v6 {
                    r6 = v6.as_ref().map(|s| Box::pin(s.receive()) as Recv<'_>);
                } else {
                    r4 = v4.as_ref().map(|s| Box::pin(s.receive()) as Recv<'_>);
                }
                let (data, _from) = got.map_err(|e| format!("receive: {e:?}"))?;
                (Vec::new(), browser.on_message(now, &data))
            }
        };
        let mut to_fetch = None;
        for e in &events {
            match e {
                Event::Found { name, instance, .. } if config.wants(instance) => {
                    browser.resolve(now, name);
                }
                Event::Removed { name, .. } => browser.stop_resolving(name),
                Event::Resolved(r) => {
                    let wanted = config
                        .fetch
                        .as_deref()
                        .is_some_and(|f| f.eq_ignore_ascii_case(&r.instance));
                    if wanted && !fetched {
                        fetched = true;
                        to_fetch = Some(r.clone());
                    }
                }
                _ => {}
            }
        }
        emit(events.iter().map(note).collect());
        send_queries(v4.as_ref(), v6.as_ref(), queries).await;
        if let Some(r) = to_fetch {
            let n = fetch(&r, &config.fetch_path).await;
            emit(vec![n]);
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
