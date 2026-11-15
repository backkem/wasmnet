//! End to end: UDP echo between two composed nodes across a switch.
//!
//! `udp-echo-client` → `wasi:sockets` UDP → netstack → switch → netstack → `udp-echo-server`,
//! and the echo back.
//!
//! * Every datagram the client sends is echoed: the client's app exits `ok`, and the capture
//!   holds exactly one UDP datagram each way per request.
//! * Round trips are exact in virtual time: the first pays for ARP, the rest are twice the
//!   link latencies.
//! * A datagram to a closed port is never echoed: the client times out and exits with an error.
//! * The same seed gives the same bytes on every link.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{built, config, datagrams_from, events, field, transcript};
use wasmnet_host::{FrameRecord, JournalEntry, Network, PortRef};

const US: u64 = 1_000;

struct Run {
    journal: Vec<JournalEntry>,
    pcaps: Vec<Vec<u8>>,
    client: PortRef,
    server: PortRef,
    frames: Vec<FrameRecord>,
}

/// A client sending `count` datagrams to `port` of the server, both on one switch.
fn echo(seed: u64, port: &str, count: &str) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "4")]))
        .unwrap();
    let server = network
        .device_with_config(
            "server",
            &b.load("node-udp-echo-server"),
            config(&[
                ("mac", "02:00:00:00:00:01"),
                ("ipv4", "10.0.0.1/24"),
                ("app.udp-echo-server.listen", "0.0.0.0:7"),
            ]),
        )
        .unwrap();
    let client = network
        .device_with_config(
            "client",
            &b.load("node-udp-echo-client"),
            config(&[
                ("mac", "02:00:00:00:00:02"),
                ("ipv4", "10.0.0.2/24"),
                ("hosts.server", "10.0.0.1"),
                ("app.udp-echo-client.target", "server"),
                ("app.udp-echo-client.port", port),
                ("app.udp-echo-client.count", count),
                ("app.udp-echo-client.interval", "10ms"),
                ("app.udp-echo-client.timeout", "20ms"),
                ("app.udp-echo-client.start", "1ms"),
            ]),
        )
        .unwrap();
    network
        .link(server.port(0), sw.port(1))
        .unwrap()
        .latency(150 * US);
    network
        .link(client.port(0), sw.port(2))
        .unwrap()
        .latency(100 * US);
    network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    Run {
        journal: network.journal(),
        pcaps: support::pcaps(&network),
        client: client.port(0),
        server: server.port(0),
        frames: network.frames(),
    }
}

#[test]
fn every_datagram_is_echoed() {
    let run = echo(42, "7", "3");
    let log = transcript(&run.journal);

    let replies = events(&run.journal, "client", "udp-echo-reply");
    assert_eq!(replies.len(), 3, "three echoes\n{log}");
    for (i, r) in replies.iter().enumerate() {
        assert_eq!(field(r, "seq"), (i + 1).to_string(), "{log}");
        assert_eq!(field(r, "from"), "10.0.0.1:7", "{log}");
    }
    // The first round trip includes ARP (one round trip of 500 us more); later ones do not.
    assert_eq!(field(&replies[0], "rtt-ns"), "1000000", "{log}");
    assert_eq!(field(&replies[1], "rtt-ns"), "500000", "{log}");
    assert_eq!(field(&replies[2], "rtt-ns"), "500000", "{log}");

    let echoed = events(&run.journal, "server", "udp-echoed");
    assert_eq!(echoed.len(), 3, "the server echoed each datagram\n{log}");

    let done = events(&run.journal, "client", "udp-echo-done");
    assert_eq!(done.len(), 1, "{log}");
    assert_eq!(field(&done[0], "transmitted"), "3");
    assert_eq!(field(&done[0], "received"), "3");
    assert_eq!(field(&done[0], "loss-pct"), "0");

    let exit = events(&run.journal, "client", "app-exit");
    assert_eq!(exit.len(), 1, "{log}");
    assert_eq!(field(&exit[0], "app"), "udp-echo-client");
    assert_eq!(field(&exit[0], "status"), "ok", "{log}");

    // On the wire: three datagrams each way, each echo carrying its request's bytes back.
    let out = datagrams_from(&run.frames, run.client);
    let back = datagrams_from(&run.frames, run.server);
    assert_eq!(out.len(), 3);
    assert_eq!(back.len(), 3);
    for (q, a) in out.iter().zip(&back) {
        assert_eq!(q.dst_port, 7);
        assert_eq!(a.src_port, 7);
        assert_eq!(
            a.dst_port, q.src_port,
            "the echo returns to the sender's port"
        );
        assert_eq!(q.payload, a.payload, "the echo is the request");
        assert_eq!(q.payload.len(), 32);
    }
}

#[test]
fn a_closed_port_is_never_echoed() {
    let run = echo(42, "9", "1");
    let log = transcript(&run.journal);

    assert!(events(&run.journal, "client", "udp-echo-reply").is_empty());
    let timeout = events(&run.journal, "client", "udp-echo-timeout");
    assert_eq!(timeout.len(), 1, "{log}");
    assert_eq!(field(&timeout[0], "waited-ns"), "20000000");
    let exit = events(&run.journal, "client", "app-exit");
    assert_eq!(field(&exit[0], "status"), "error", "{log}");
    assert!(events(&run.journal, "server", "udp-echoed").is_empty());
    assert!(datagrams_from(&run.frames, run.server).is_empty());
}

#[test]
fn the_same_seed_gives_the_same_bytes() {
    let (a, b) = (echo(42, "7", "3"), echo(42, "7", "3"));
    assert_eq!(
        a.pcaps, b.pcaps,
        "seed=42: the captures differ between runs"
    );
    assert_eq!(a.journal, b.journal, "seed=42: the journals differ");

    let other = echo(7, "7", "3");
    assert_eq!(
        events(&other.journal, "client", "udp-echo-reply").len(),
        3,
        "seed=7"
    );
}
