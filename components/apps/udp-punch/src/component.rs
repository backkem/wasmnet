//! wit-bindgen glue: exports `wasi:cli/run@0.3.0` and runs the rendezvous server or a peer
//! through the standard `wasip3` socket and clock bindings (world `wasmnet:app/app`).

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::pin;
use std::task::Poll;

use wasip3::clocks::monotonic_clock;
use wasip3::sockets::types::{IpAddressFamily, UdpSocket};

use crate::{APP, Config, Message, Peer, Registry, app_pairs};

use wasmnet_app_kit::{to_std, to_wit};

wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};

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

fn socket(local: SocketAddr) -> Result<UdpSocket, String> {
    let family = if local.is_ipv4() {
        IpAddressFamily::Ipv4
    } else {
        IpAddressFamily::Ipv6
    };
    let s = UdpSocket::create(family).map_err(|e| format!("create: {e:?}"))?;
    s.bind(to_wit(local))
        .map_err(|e| format!("bind {local}: {e:?}"))?;
    Ok(s)
}

async fn send(s: &UdpSocket, to: SocketAddr, m: &Message) -> Result<(), String> {
    s.send(m.encode(), Some(to_wit(to)))
        .await
        .map_err(|e| format!("send to {to}: {e:?}"))
}

async fn rendezvous(listen: SocketAddr) -> Result<(), String> {
    let s = socket(listen)?;
    log::log(Level::Info, &format!("{APP}: rendezvous on udp {listen}"));
    let mut registry = Registry::default();
    loop {
        let (data, from) = s.receive().await.map_err(|e| format!("receive: {e:?}"))?;
        let from = to_std(from);
        let Some(Message::Reg(name)) = Message::parse(&data) else {
            continue;
        };
        let (news, answers) = registry.register(&name, from);
        if news {
            event(
                "punch-registered",
                &[("name", name.clone()), ("endpoint", from.to_string())],
            );
        }
        for (to, m) in answers {
            // A peer the stack cannot reach right now is the peer's problem.
            if let Err(e) = send(&s, to, &m).await {
                log::log(Level::Warn, &format!("{APP}: {e}"));
            }
        }
    }
}

/// Runs a peer. `Ok(true)` when it heard the other peer.
async fn peer(c: Peer) -> Result<bool, String> {
    let t0 = monotonic_clock::now();
    let s = socket(c.local)?;
    if c.start_ns > 0 {
        monotonic_clock::wait_until(t0 + c.start_ns).await;
    }
    // Register until the server names the other peer.
    let mut other = None;
    'register: for _ in 0..c.register_tries {
        send(&s, c.server, &Message::Reg(c.name.clone())).await?;
        let deadline = monotonic_clock::now() + c.interval_ns;
        loop {
            match first(s.receive(), monotonic_clock::wait_until(deadline)).await {
                First::Left(Ok((data, from))) => {
                    if to_std(from) == c.server
                        && let Some(Message::PeerAt(name, at)) = Message::parse(&data)
                    {
                        other = Some((name, at));
                        break 'register;
                    }
                }
                First::Left(Err(e)) => return Err(format!("receive: {e:?}")),
                First::Right(()) => break,
            }
        }
    }
    let Some((other, advertised)) = other else {
        event(
            "punch-done",
            &[
                ("name", c.name.clone()),
                ("result", "no-peer".to_owned()),
                ("advertised", String::new()),
                ("heard-from", String::new()),
                ("sent", "0".to_owned()),
                ("received", "0".to_owned()),
            ],
        );
        return Ok(false);
    };
    event(
        "punch-peer",
        &[
            ("name", c.name.clone()),
            ("peer", other.clone()),
            ("endpoint", advertised.to_string()),
        ],
    );
    let mut targets = vec![advertised];
    let mut heard: Option<SocketAddr> = None;
    let (mut sent, mut received) = (0u32, 0u32);
    let round0 = monotonic_clock::now();
    for n in 1..=c.tries {
        for to in targets.clone() {
            send(&s, to, &Message::Punch(c.name.clone(), n)).await?;
            sent += 1;
        }
        let deadline = round0 + u64::from(n) * c.interval_ns;
        loop {
            match first(s.receive(), monotonic_clock::wait_until(deadline)).await {
                First::Left(Ok((data, from))) => {
                    let from = to_std(from);
                    if from == c.server {
                        continue;
                    }
                    let (kind, punch) = match Message::parse(&data) {
                        Some(Message::Punch(name, _)) if name == other => ("punch", true),
                        Some(Message::Ack(name)) if name == other => ("ack", false),
                        _ => continue,
                    };
                    received += 1;
                    if heard.is_none() {
                        heard = Some(from);
                        event(
                            "punch-heard",
                            &[
                                ("name", c.name.clone()),
                                ("from", from.to_string()),
                                ("message", kind.to_owned()),
                            ],
                        );
                    }
                    if !targets.contains(&from) {
                        targets.push(from);
                    }
                    if punch {
                        send(&s, from, &Message::Ack(c.name.clone())).await?;
                        sent += 1;
                    }
                }
                First::Left(Err(e)) => return Err(format!("receive: {e:?}")),
                First::Right(()) => break,
            }
        }
    }
    let result = if heard.is_some() {
        "connected"
    } else {
        "failed"
    };
    log::log(
        Level::Info,
        &format!(
            "{APP}: {} {result} ({sent} sent, {received} received)",
            c.name
        ),
    );
    event(
        "punch-done",
        &[
            ("name", c.name.clone()),
            ("result", result.to_owned()),
            ("advertised", advertised.to_string()),
            (
                "heard-from",
                heard.map(|h| h.to_string()).unwrap_or_default(),
            ),
            ("sent", sent.to_string()),
            ("received", received.to_string()),
        ],
    );
    Ok(heard.is_some())
}

async fn main() -> Result<bool, String> {
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    match Config::from_pairs(app_pairs(pairs, APP)).map_err(|e| e.to_string())? {
        Config::Rendezvous { listen } => rendezvous(listen).await.map(|()| true),
        Config::Peer(p) => peer(p).await,
    }
}

struct App;

impl exports::wasi::cli::run::Guest for App {
    async fn run() -> Result<(), ()> {
        match main().await {
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
