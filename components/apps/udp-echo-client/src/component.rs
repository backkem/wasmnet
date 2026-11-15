//! wit-bindgen glue: exports `wasi:cli/run@0.3.0` and runs the echo exchange through the standard
//! `wasip3` socket, name-lookup and clock bindings (world `wasmnet:app/app`).

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::pin;
use std::task::Poll;

use wasip3::clocks::monotonic_clock;
use wasip3::sockets::ip_name_lookup::{self, IpAddress};
use wasip3::sockets::types::{IpAddressFamily, UdpSocket};

use crate::{APP, Config, Reply, Stats, app_pairs, classify, fmt_ms, payload};

use wasmnet_app_kit::{to_std, to_wit};

wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};

fn ip(a: IpAddress) -> IpAddr {
    match a {
        IpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        IpAddress::Ipv6((a, b, c, d, e, f, g, h)) => {
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
        }
    }
}

enum First<A, B> {
    Left(A),
    Right(B),
}

/// Polls `a` then `b` until one finishes; the other is dropped (cancelled). `a` wins a tie.
async fn first<A: Future, B: Future>(a: A, b: B) -> First<A::Output, B::Output> {
    let (mut a, mut b) = (pin!(a), pin!(b));
    poll_fn(|cx| {
        if let Poll::Ready(x) = a.as_mut().poll(cx) {
            return Poll::Ready(First::Left(x));
        }
        if let Poll::Ready(y) = b.as_mut().poll(cx) {
            return Poll::Ready(First::Right(y));
        }
        Poll::Pending
    })
    .await
}

/// Runs the exchange. `Ok(true)` when every datagram was echoed.
async fn client() -> Result<bool, String> {
    let t0 = monotonic_clock::now();
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let c = Config::from_pairs(app_pairs(pairs, APP)).map_err(|e| e.to_string())?;
    if c.start_ns > 0 {
        monotonic_clock::wait_until(t0 + c.start_ns).await;
    }
    let addrs = ip_name_lookup::resolve_addresses(c.target.clone())
        .await
        .map_err(|e| format!("resolve {}: {e:?}", c.target))?;
    let server = addrs
        .into_iter()
        .map(ip)
        .next()
        .ok_or_else(|| format!("resolve {}: no address", c.target))?;
    let peer = SocketAddr::new(server, c.port);
    let family = if server.is_ipv4() {
        IpAddressFamily::Ipv4
    } else {
        IpAddressFamily::Ipv6
    };
    let socket = UdpSocket::create(family).map_err(|e| format!("create: {e:?}"))?;
    // Connected: `receive` only returns datagrams from the server.
    socket
        .connect(to_wit(peer))
        .map_err(|e| format!("connect {peer}: {e:?}"))?;
    let local = socket
        .get_local_address()
        .map(to_std)
        .map_err(|e| format!("local address: {e:?}"))?;
    log::log(
        Level::Info,
        &format!(
            "UDP-ECHO {} ({peer}) from {local}: {} datagrams of {} bytes",
            c.target, c.count, c.size
        ),
    );
    event(
        "udp-echo-start",
        &[
            ("target", c.target.clone()),
            ("peer", peer.to_string()),
            ("local", local.to_string()),
            ("count", c.count.to_string()),
            ("size", c.size.to_string()),
        ],
    );

    let mut stats = Stats::default();
    for seq in 1..=c.count {
        let due = t0 + c.due(seq);
        if monotonic_clock::now() < due {
            monotonic_clock::wait_until(due).await;
        }
        let sent_at = monotonic_clock::now();
        socket
            .send(payload(seq, c.size), None)
            .await
            .map_err(|e| format!("send seq={seq}: {e:?}"))?;
        stats.transmitted += 1;
        event(
            "udp-echo-request",
            &[("seq", seq.to_string()), ("bytes", c.size.to_string())],
        );
        let deadline = sent_at + c.timeout_ns;
        loop {
            match first(socket.receive(), monotonic_clock::wait_until(deadline)).await {
                First::Left(Ok((data, from))) => match classify(&data, seq, c.size) {
                    Reply::Echo => {
                        let rtt = monotonic_clock::now() - sent_at;
                        stats.rtts.push(rtt);
                        let from = to_std(from);
                        log::log(
                            Level::Info,
                            &format!(
                                "{} bytes from {from}: seq={seq} time={}",
                                data.len(),
                                fmt_ms(rtt)
                            ),
                        );
                        event(
                            "udp-echo-reply",
                            &[
                                ("seq", seq.to_string()),
                                ("from", from.to_string()),
                                ("bytes", data.len().to_string()),
                                ("rtt-ns", rtt.to_string()),
                            ],
                        );
                        break;
                    }
                    Reply::Late(old) => log::log(
                        Level::Info,
                        &format!("late echo of seq={old} (it already timed out)"),
                    ),
                    Reply::Garbled => log::log(
                        Level::Warn,
                        &format!(
                            "unexpected {}-byte datagram while waiting for seq={seq}",
                            data.len()
                        ),
                    ),
                },
                First::Left(Err(e)) => return Err(format!("receive seq={seq}: {e:?}")),
                First::Right(()) => {
                    let waited = monotonic_clock::now() - sent_at;
                    log::log(Level::Info, &format!("Request timeout for seq={seq}"));
                    event(
                        "udp-echo-timeout",
                        &[("seq", seq.to_string()), ("waited-ns", waited.to_string())],
                    );
                    break;
                }
            }
        }
    }

    let summary = match stats.rtt() {
        Some((min, avg, max)) => format!(
            ", rtt min/avg/max = {}/{}/{}",
            fmt_ms(min),
            fmt_ms(avg),
            fmt_ms(max)
        ),
        None => String::new(),
    };
    log::log(
        Level::Info,
        &format!(
            "--- {} udp-echo statistics --- {} datagrams transmitted, {} received, {}% loss{summary}",
            c.target,
            stats.transmitted,
            stats.received(),
            stats.loss_pct()
        ),
    );
    log::event("udp-echo-done", &stats.fields());
    Ok(stats.received() == c.count)
}

struct App;

impl exports::wasi::cli::run::Guest for App {
    async fn run() -> Result<(), ()> {
        match client().await {
            Ok(true) => Ok(()),
            Ok(false) => Err(()),
            Err(e) => {
                log::log(Level::Error, &format!("{APP}: {e}"));
                Err(())
            }
        }
    }
}

export!(App);
