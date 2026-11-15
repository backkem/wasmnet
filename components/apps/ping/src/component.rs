//! wit-bindgen glue: exports `wasi:cli/run@0.3.0` and pings through the standard `wasip3`
//! name-lookup and clock bindings plus `wasmnet:sockets-ext/icmp` (world `wasmnet:app/app`).

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::{Pin, pin};
use std::task::Poll;

use wasip3::clocks::monotonic_clock;
use wasip3::sockets::ip_name_lookup::{self, IpAddress};
use wasip3::sockets::types::IpAddressFamily;

use crate::{APP, Session, Stats, app_pairs, echo_request, error_name, fmt_ms, packet_bytes};

wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};
use wasmnet::sockets_ext::icmp::IcmpSocket;

fn ip(a: IpAddress) -> IpAddr {
    match a {
        IpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        IpAddress::Ipv6((a, b, c, d, e, f, g, h)) => {
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
        }
    }
}

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

enum Woke<R, E> {
    Reply(R),
    Error(E),
    Time,
}

/// Polls `reply`, `error` and `timer` until one finishes; the others are dropped (cancelled),
/// which loses nothing on the socket. A reply wins a tie, then an error.
async fn first<A: Future, B: Future, C: Future<Output = ()>>(
    reply: A,
    error: B,
    timer: C,
) -> Woke<A::Output, B::Output> {
    let (mut a, mut b, mut c) = (pin!(reply), pin!(error), pin!(timer));
    poll_fn(|cx| {
        if let Poll::Ready(x) = a.as_mut().poll(cx) {
            return Poll::Ready(Woke::Reply(x));
        }
        if let Poll::Ready(y) = b.as_mut().poll(cx) {
            return Poll::Ready(Woke::Error(y));
        }
        if let Poll::Ready(()) = c.as_mut().poll(cx) {
            return Poll::Ready(Woke::Time);
        }
        Poll::Pending
    })
    .await
}

/// Runs one session from `t0` on. `Ok(true)` when at least one reply came back.
async fn session(s: Session, t0: u64) -> Result<bool, String> {
    if s.start_ns > 0 {
        monotonic_clock::wait_until(t0 + s.start_ns).await;
    }
    let name = &s.name;
    let target = ip_name_lookup::resolve_addresses(s.target.clone())
        .await
        .map_err(|e| format!("{name}: resolve {}: {e:?}", s.target))?
        .into_iter()
        .map(ip)
        .next()
        .ok_or_else(|| format!("{name}: resolve {}: no address", s.target))?;
    let v6 = target.is_ipv6();
    let (family, any) = if v6 {
        (IpAddressFamily::Ipv6, IpAddr::from([0u16; 8]))
    } else {
        (IpAddressFamily::Ipv4, IpAddr::from([0u8; 4]))
    };
    let socket = IcmpSocket::create(family).map_err(|e| format!("{name}: socket: {e:?}"))?;
    socket
        .bind(wit_ip(any), 0)
        .map_err(|e| format!("{name}: bind: {e:?}"))?;
    socket
        .set_recv_errors(true)
        .map_err(|e| format!("{name}: recv-errors: {e:?}"))?;
    if let Some(ttl) = s.ttl {
        socket
            .set_unicast_hop_limit(ttl)
            .map_err(|e| format!("{name}: ttl {ttl}: {e:?}"))?;
    }
    let id = socket
        .get_identifier()
        .map_err(|e| format!("{name}: identifier: {e:?}"))?;
    log::log(
        Level::Info,
        &format!(
            "PING {} ({target}) {}({}) bytes of data.",
            s.target,
            s.size,
            packet_bytes(v6, s.size)
        ),
    );
    let base = |seq: Option<u16>| {
        let mut f = vec![("session", name.clone()), ("target", s.target.clone())];
        if let Some(seq) = seq {
            f.push(("seq", seq.to_string()));
        }
        f
    };
    let mut start = base(None);
    start.extend([
        ("address", target.to_string()),
        ("id", id.to_string()),
        ("count", s.count.to_string()),
        ("size", s.size.to_string()),
    ]);
    event("ping-start", &start);

    let mut stats = Stats::default();
    // Requests waiting for an answer: sequence number -> (sent at, deadline).
    let mut waiting: BTreeMap<u16, (u64, u64)> = BTreeMap::new();
    // Requests answered, for duplicates (several hosts answer a group): sequence -> sent at.
    let mut answered: BTreeMap<u16, u64> = BTreeMap::new();
    let mut next_seq: u16 = 1;
    let mut next_at = monotonic_clock::now();
    loop {
        let now = monotonic_clock::now();
        // Expire before sending, so a timeout and a send at the same instant read in order.
        let overdue: Vec<u16> = waiting
            .iter()
            .filter(|(_, (_, deadline))| *deadline <= now)
            .map(|(&seq, _)| seq)
            .collect();
        for seq in overdue {
            waiting.remove(&seq);
            event("ping-timeout", &base(Some(seq)));
            log::log(Level::Info, &format!("Request timeout for icmp_seq={seq}"));
        }
        while next_seq <= s.count && next_at <= now {
            let seq = next_seq;
            socket
                .send(echo_request(v6, seq, s.size), Some(wit_ip(target)))
                .await
                .map_err(|e| format!("{name}: send icmp_seq={seq}: {e:?}"))?;
            let sent = monotonic_clock::now();
            stats.transmitted += 1;
            waiting.insert(seq, (sent, sent.saturating_add(s.timeout_ns)));
            next_seq += 1;
            next_at = next_at.saturating_add(s.interval_ns);
        }
        if next_seq > s.count && waiting.is_empty() {
            break;
        }
        let send_due = (next_seq <= s.count).then_some(next_at);
        let wake = waiting
            .values()
            .map(|(_, deadline)| *deadline)
            .chain(send_due)
            .min()
            .unwrap_or(now);
        match first(
            socket.receive_datagram(),
            socket.receive_error(),
            monotonic_clock::wait_until(wake),
        )
        .await
        {
            Woke::Reply(Ok(datagram)) => {
                let now = monotonic_clock::now();
                let (reply, from, hops) = (
                    datagram.data,
                    ip(datagram.remote_address),
                    datagram.hop_limit,
                );
                let Some(seq) = crate::reply_seq(&reply) else {
                    continue;
                };
                let (sent, dup) = match waiting.remove(&seq) {
                    Some((sent, _)) => {
                        answered.insert(seq, sent);
                        stats.received += 1;
                        stats.rtts.push(now - sent);
                        (sent, false)
                    }
                    None => match answered.get(&seq) {
                        Some(&sent) => (sent, true),
                        // Too late: it timed out already.
                        None => continue,
                    },
                };
                let rtt = now - sent;
                let mut f = base(None);
                f.extend([
                    ("from", from.to_string()),
                    ("seq", seq.to_string()),
                    ("bytes", reply.len().to_string()),
                    ("rtt-ns", rtt.to_string()),
                    ("dup", dup.to_string()),
                ]);
                if let Some(h) = hops {
                    f.push(("hop-limit", h.to_string()));
                }
                event("ping-reply", &f);
                let ttl = hops.map_or(String::new(), |h| format!(" ttl={h}"));
                log::log(
                    Level::Info,
                    &format!(
                        "{} bytes from {from}: icmp_seq={seq}{ttl} time={}{}",
                        reply.len(),
                        fmt_ms(rtt),
                        if dup { " (DUP!)" } else { "" }
                    ),
                );
            }
            Woke::Error(Ok(e)) => {
                if waiting.remove(&e.sequence).is_none() {
                    continue;
                }
                stats.errors += 1;
                let from = ip(e.reporter);
                let (error, text) = error_name(v6, e.icmp_type, e.icmp_code);
                let mut f = base(None);
                f.extend([
                    ("from", from.to_string()),
                    ("seq", e.sequence.to_string()),
                    ("error", error.to_owned()),
                    ("icmp-type", e.icmp_type.to_string()),
                    ("icmp-code", e.icmp_code.to_string()),
                ]);
                event("ping-error", &f);
                log::log(
                    Level::Info,
                    &format!("From {from} icmp_seq={} {text}", e.sequence),
                );
            }
            Woke::Reply(Err(e)) => return Err(format!("{name}: receive: {e:?}")),
            Woke::Error(Err(e)) => return Err(format!("{name}: receive-error: {e:?}")),
            Woke::Time => {}
        }
    }
    drop(socket);
    for line in stats.lines(&s.target) {
        log::log(Level::Info, &line);
    }
    let mut done = base(None);
    done.extend([
        ("transmitted", stats.transmitted.to_string()),
        ("received", stats.received.to_string()),
        ("errors", stats.errors.to_string()),
        ("loss-pct", stats.loss_pct().to_string()),
    ]);
    event("ping-done", &done);
    Ok(stats.received > 0)
}

type Job = Pin<Box<dyn Future<Output = Result<bool, String>>>>;

/// Runs every session concurrently in this one task. `Ok(true)` when all got a reply.
async fn run_all() -> Result<bool, String> {
    let t0 = monotonic_clock::now();
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let all = crate::sessions(app_pairs(pairs, APP)).map_err(|e| e.to_string())?;
    let mut jobs: Vec<Option<Job>> = all
        .into_iter()
        .map(|s| Some(Box::pin(session(s, t0)) as Job))
        .collect();
    let mut ok = true;
    let mut failure = None;
    poll_fn(|cx| {
        for slot in &mut jobs {
            if let Some(job) = slot
                && let Poll::Ready(r) = job.as_mut().poll(cx)
            {
                *slot = None;
                match r {
                    Ok(replied) => ok &= replied,
                    Err(e) => {
                        log::log(Level::Error, &format!("{APP}: {e}"));
                        failure.get_or_insert(e);
                    }
                }
            }
        }
        if jobs.iter().all(Option::is_none) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    match failure {
        Some(e) => Err(e),
        None => Ok(ok),
    }
}

struct App;

impl exports::wasi::cli::run::Guest for App {
    async fn run() -> Result<(), ()> {
        match run_all().await {
            Ok(true) => Ok(()),
            Ok(false) => Err(()),
            Err(_) => Err(()),
        }
    }
}

export!(App);
