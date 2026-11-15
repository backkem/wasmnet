//! End to end: the diagnostic tools, `ping` and `traceroute`, across real routers.
//!
//! `ping` opens an ICMP echo socket on its node's netstack; `traceroute` sends UDP probes with a
//! rising TTL and reads the ICMP errors the routers send back. Neither knows the network is
//! simulated.
//!
//! * A ping across a router is answered every time, and the reply's hop limit shows the one
//!   router it crossed (64 at the sender, 63 on arrival).
//! * A ping whose TTL is 1 dies at the router, which says so with an ICMP time exceeded.
//! * A traceroute across two routers names each hop in order and reaches the server.
//! * The same seed gives the same bytes on every link.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{built, config, events, field, transcript};
use wasmnet_host::{JournalEntry, Network};

const US: u64 = 1_000;

struct Run {
    journal: Vec<JournalEntry>,
    pcaps: Vec<Vec<u8>>,
}

/// `probe` (a `node-ping` with `ping` config added) → `router` → `far` (an HTTP server, which
/// answers echo requests like any host).
fn ping_across_a_router(seed: u64, ping: &[(&str, &str)]) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let router = network
        .device_with_config(
            "router",
            &b.load("router"),
            config(&[
                ("mac", "02:00:00:00:a1:00"),
                ("port0.ipv4", "10.0.1.1/24"),
                ("port1.ipv4", "10.0.2.1/24"),
            ]),
        )
        .unwrap();
    let far = network
        .device_with_config(
            "far",
            &b.load("node-http-server"),
            config(&[
                ("mac", "02:00:00:00:02:10"),
                ("ipv4", "10.0.2.10/24"),
                ("ipv4-gateway", "10.0.2.1"),
            ]),
        )
        .unwrap();
    let mut probe_config = vec![
        ("mac", "02:00:00:00:01:10"),
        ("ipv4", "10.0.1.10/24"),
        ("ipv4-gateway", "10.0.1.1"),
        ("hosts.far", "10.0.2.10"),
        ("app.ping.target", "far"),
        ("app.ping.start", "1ms"),
    ];
    probe_config.extend_from_slice(ping);
    let probe = network
        .device_with_config("probe", &b.load("node-ping"), config(&probe_config))
        .unwrap();
    network
        .link(probe.port(0), router.port(0))
        .unwrap()
        .latency(100 * US);
    network
        .link(router.port(1), far.port(0))
        .unwrap()
        .latency(150 * US);
    network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    Run {
        journal: network.journal(),
        pcaps: support::pcaps(&network),
    }
}

#[test]
fn a_ping_across_a_router_is_answered() {
    let run = ping_across_a_router(
        42,
        &[("app.ping.count", "3"), ("app.ping.interval", "10ms")],
    );
    let log = transcript(&run.journal);

    let replies = events(&run.journal, "probe", "ping-reply");
    assert_eq!(replies.len(), 3, "{log}");
    for (i, r) in replies.iter().enumerate() {
        assert_eq!(field(r, "seq"), (i + 1).to_string(), "{log}");
        assert_eq!(field(r, "from"), "10.0.2.10");
        assert_eq!(
            field(r, "hop-limit"),
            "63",
            "one router decremented it\n{log}"
        );
    }
    // The first round trip also pays for ARP on both sides of the router.
    assert_eq!(
        field(&replies[1], "rtt-ns"),
        "500000",
        "2 x (100 + 150) us\n{log}"
    );
    assert_eq!(field(&replies[2], "rtt-ns"), "500000", "{log}");
    assert!(
        field(&replies[0], "rtt-ns").parse::<u64>().unwrap() > 500_000,
        "the first request waits for ARP\n{log}"
    );

    let done = events(&run.journal, "probe", "ping-done");
    assert_eq!(done.len(), 1, "{log}");
    assert_eq!(field(&done[0], "transmitted"), "3");
    assert_eq!(field(&done[0], "received"), "3");
    assert_eq!(field(&done[0], "loss-pct"), "0");
    let exit = events(&run.journal, "probe", "app-exit");
    assert_eq!(field(&exit[0], "status"), "ok", "{log}");
}

#[test]
fn a_ping_that_runs_out_of_ttl_hears_from_the_router() {
    let run = ping_across_a_router(42, &[("app.ping.count", "1"), ("app.ping.ttl", "1")]);
    let log = transcript(&run.journal);

    assert!(
        events(&run.journal, "probe", "ping-reply").is_empty(),
        "{log}"
    );
    let errors = events(&run.journal, "probe", "ping-error");
    assert_eq!(errors.len(), 1, "{log}");
    assert_eq!(field(&errors[0], "error"), "time-exceeded");
    assert_eq!(
        field(&errors[0], "from"),
        "10.0.1.1",
        "the router's near port\n{log}"
    );
    assert_eq!(field(&errors[0], "icmp-type"), "11");
    let sent = events(&run.journal, "router", "icmp-error-sent");
    assert_eq!(sent.len(), 1, "{log}");
    assert_eq!(field(&sent[0], "error"), "time-exceeded");
}

/// `probe` (traceroute) → `r1` → `r2` → `web`: three hops, the last the server itself.
fn traceroute(seed: u64) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let r1 = network
        .device_with_config(
            "r1",
            &b.load("router"),
            config(&[
                ("mac", "02:00:00:00:a1:00"),
                ("port0.ipv4", "10.0.1.1/24"),
                ("port1.ipv4", "10.0.12.1/24"),
                ("routes", "10.0.3.0/24 via 10.0.12.2"),
            ]),
        )
        .unwrap();
    let r2 = network
        .device_with_config(
            "r2",
            &b.load("router"),
            config(&[
                ("mac", "02:00:00:00:a2:00"),
                ("port0.ipv4", "10.0.12.2/24"),
                ("port1.ipv4", "10.0.3.1/24"),
                ("routes", "default via 10.0.12.1"),
            ]),
        )
        .unwrap();
    let web = network
        .device_with_config(
            "web",
            &b.load("node-http-server"),
            config(&[
                ("mac", "02:00:00:00:03:10"),
                ("ipv4", "10.0.3.10/24"),
                ("ipv4-gateway", "10.0.3.1"),
            ]),
        )
        .unwrap();
    let probe = network
        .device_with_config(
            "probe",
            &b.load("node-traceroute"),
            config(&[
                ("mac", "02:00:00:00:01:10"),
                ("ipv4", "10.0.1.10/24"),
                ("ipv4-gateway", "10.0.1.1"),
                ("hosts.web", "10.0.3.10"),
                ("app.traceroute.targets", "web"),
                ("app.traceroute.max-hops", "8"),
                ("app.traceroute.start", "1ms"),
            ]),
        )
        .unwrap();
    network
        .link(probe.port(0), r1.port(0))
        .unwrap()
        .latency(100 * US);
    network
        .link(r1.port(1), r2.port(0))
        .unwrap()
        .latency(200 * US);
    network
        .link(r2.port(1), web.port(0))
        .unwrap()
        .latency(150 * US);
    network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    Run {
        journal: network.journal(),
        pcaps: support::pcaps(&network),
    }
}

#[test]
fn a_traceroute_names_every_router_on_the_path() {
    let run = traceroute(42);
    let log = transcript(&run.journal);

    let hops = events(&run.journal, "probe", "traceroute-hop");
    let reporters: Vec<&str> = hops.iter().map(|h| field(h, "from")).collect();
    assert_eq!(reporters, ["10.0.1.1", "10.0.12.2", "10.0.3.10"], "{log}");
    for (i, h) in hops.iter().enumerate() {
        assert_eq!(field(h, "ttl"), (i + 1).to_string(), "{log}");
    }

    let done = events(&run.journal, "probe", "traceroute-done");
    assert_eq!(done.len(), 1, "{log}");
    assert_eq!(field(&done[0], "hops"), "3");
    assert_eq!(field(&done[0], "reached"), "true");
    assert_eq!(field(&done[0], "path"), "10.0.1.1,10.0.12.2,10.0.3.10");

    // Each router answered the probes that ran out of TTL at it.
    for router in ["r1", "r2"] {
        let sent = events(&run.journal, router, "icmp-error-sent");
        assert!(
            sent.iter().all(|e| field(e, "error") == "time-exceeded"),
            "{router}\n{log}"
        );
        assert_eq!(sent.len(), 3, "three probes die at {router}\n{log}");
    }
    let exit = events(&run.journal, "probe", "app-exit");
    assert_eq!(field(&exit[0], "status"), "ok", "{log}");
}

#[test]
fn the_same_seed_gives_the_same_bytes() {
    let (a, b) = (traceroute(42), traceroute(42));
    assert_eq!(
        a.pcaps, b.pcaps,
        "seed=42: the captures differ between runs"
    );
    assert_eq!(a.journal, b.journal, "seed=42: the journals differ");

    let ping = |seed| ping_across_a_router(seed, &[("app.ping.count", "3")]);
    let (a, b) = (ping(42), ping(42));
    assert_eq!(
        a.pcaps, b.pcaps,
        "seed=42: the ping captures differ between runs"
    );
    assert_eq!(a.journal, b.journal);
}
