//! wit-bindgen glue: exports `wasi:cli/run@0.3.0` and traces through the standard `wasip3`
//! socket, name-lookup and clock bindings plus `wasmnet:sockets-ext/udp` (world
//! `wasmnet:app/app`).

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::pin;
use std::task::Poll;

use wasip3::clocks::monotonic_clock;
use wasip3::sockets::ip_name_lookup::{self, IpAddress};
use wasip3::sockets::types::{IpAddressFamily, UdpSocket};

use crate::{APP, Config, Outcome, Probe, app_pairs, hop_line, packet_bytes, payload};

use wasmnet_app_kit::{to_std, to_wit};

wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};
use wasmnet::sockets_ext::udp as ext;

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

/// Traces one target. `seq` numbers probes across the whole run (their destination ports).
/// `Ok(true)` when the target was reached.
async fn trace(c: &Config, name: &str, seq: &mut u32) -> Result<bool, String> {
    let addrs = ip_name_lookup::resolve_addresses(name.to_owned())
        .await
        .map_err(|e| format!("resolve {name}: {e:?}"))?;
    let target = addrs
        .into_iter()
        .map(ip)
        .next()
        .ok_or_else(|| format!("resolve {name}: no address"))?;
    let v6 = target.is_ipv6();
    let (family, any) = if v6 {
        (IpAddressFamily::Ipv6, SocketAddr::from(([0u16; 8], 0)))
    } else {
        (IpAddressFamily::Ipv4, SocketAddr::from(([0u8; 4], 0)))
    };
    let socket = UdpSocket::create(family).map_err(|e| format!("create: {e:?}"))?;
    socket
        .bind(to_wit(any))
        .map_err(|e| format!("bind: {e:?}"))?;
    ext::set_recv_errors(&socket, true).map_err(|e| format!("recv-errors: {e:?}"))?;
    let bytes = packet_bytes(v6, c.size);
    log::log(
        Level::Info,
        &format!(
            "traceroute to {name} ({target}), {} hops max, {bytes} byte packets",
            c.max_hops
        ),
    );
    event(
        "traceroute-start",
        &[
            ("target", name.to_owned()),
            ("address", target.to_string()),
            ("max-hops", c.max_hops.to_string()),
            ("queries", c.queries.to_string()),
            ("packet-bytes", bytes.to_string()),
        ],
    );

    let mut path: Vec<String> = Vec::new();
    let mut reached = false;
    for ttl in 1..=c.max_hops {
        socket
            .set_unicast_hop_limit(ttl)
            .map_err(|e| format!("hop limit {ttl}: {e:?}"))?;
        let mut probes = Vec::new();
        for query in 1..=c.queries {
            let port = c.probe_port(*seq);
            *seq += 1;
            let dst = SocketAddr::new(target, port);
            let sent = monotonic_clock::now();
            socket
                .send(payload(c.size), Some(to_wit(dst)))
                .await
                .map_err(|e| format!("send to {dst}: {e:?}"))?;
            let deadline = sent + c.wait_ns;
            let probe = loop {
                match first(
                    ext::receive_error(&socket),
                    monotonic_clock::wait_until(deadline),
                )
                .await
                {
                    First::Left(Ok(err)) => {
                        if to_std(err.destination) != dst {
                            // A late answer to an earlier probe: not this one.
                            continue;
                        }
                        let from = ip(err.reporter);
                        break Probe {
                            outcome: Outcome::of(v6, err.icmp_type, err.icmp_code, from, target),
                            from: Some(from),
                            rtt_ns: monotonic_clock::now() - sent,
                        };
                    }
                    First::Left(Err(e)) => return Err(format!("receive-error: {e:?}")),
                    First::Right(()) => {
                        break Probe {
                            outcome: Outcome::Timeout,
                            from: None,
                            rtt_ns: c.wait_ns,
                        };
                    }
                }
            };
            event(
                "traceroute-probe",
                &[
                    ("target", name.to_owned()),
                    ("ttl", ttl.to_string()),
                    ("probe", query.to_string()),
                    ("port", port.to_string()),
                    ("result", probe.outcome.name().to_owned()),
                    ("from", probe.from.map_or("*".to_owned(), |f| f.to_string())),
                    ("rtt-ns", probe.rtt_ns.to_string()),
                ],
            );
            probes.push(probe);
        }
        let line = hop_line(ttl, &probes);
        let hop = probes
            .iter()
            .find_map(|p| p.from)
            .map_or("*".to_owned(), |f| f.to_string());
        log::log(Level::Info, &line);
        event(
            "traceroute-hop",
            &[
                ("target", name.to_owned()),
                ("ttl", ttl.to_string()),
                ("from", hop.clone()),
                ("line", line),
            ],
        );
        path.push(hop);
        if probes.iter().any(|p| p.outcome.ends_trace()) {
            reached = probes.iter().any(|p| p.outcome == Outcome::Reached);
            break;
        }
    }
    event(
        "traceroute-done",
        &[
            ("target", name.to_owned()),
            ("hops", path.len().to_string()),
            ("reached", reached.to_string()),
            ("path", path.join(",")),
        ],
    );
    Ok(reached)
}

/// Traces every target in turn. `Ok(true)` when all were reached.
async fn run_all() -> Result<bool, String> {
    let t0 = monotonic_clock::now();
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let c = Config::from_pairs(app_pairs(pairs, APP)).map_err(|e| e.to_string())?;
    if c.start_ns > 0 {
        monotonic_clock::wait_until(t0 + c.start_ns).await;
    }
    let mut seq = 0;
    let mut all = true;
    for (i, name) in c.targets.iter().enumerate() {
        if i > 0 && c.gap_ns > 0 {
            monotonic_clock::wait_for(c.gap_ns).await;
        }
        all &= trace(&c, name, &mut seq).await?;
    }
    Ok(all)
}

struct App;

impl exports::wasi::cli::run::Guest for App {
    async fn run() -> Result<(), ()> {
        match run_all().await {
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
