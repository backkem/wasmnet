//! End to end: address translation on a router port, with real composed nodes.
//!
//! * A client behind the NAT fetches over HTTP from a server outside; the server sees the
//!   router's address, and the captures on both sides show the translation.
//! * The hole-punching matrix: two peers behind two NATs and a rendezvous server, for each
//!   mapping and filtering behaviour of RFC 4787 and for a symmetric NAT facing cone NATs.
//! * An inbound port forward, and hairpinning on and off.
//! * Traceroute and a port unreachable through the NAT.
//!
//! Every network runs at two seeds, twice: the reruns are byte-identical. The tests assert on
//! decoded packets and journals, not on capture hashes (TCP's timing is not what they test).
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use std::collections::BTreeMap;

use etherparse::{NetSlice, SlicedPacket};
use support::{built, config, events, field, transcript};
use wasmnet_host::{DeviceId, FrameRecord, JournalEntry, Network, PortRef};

const US: u64 = 1_000;

/// What a run leaves behind, for the checks and for the rerun comparison.
struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcaps: Vec<Vec<u8>>,
    counters: BTreeMap<String, BTreeMap<String, u64>>,
    ports: BTreeMap<String, DeviceId>,
}

impl Run {
    fn counter(&self, device: &str, name: &str) -> u64 {
        self.counters
            .get(device)
            .and_then(|c| c.get(name))
            .copied()
            .unwrap_or_else(|| panic!("{device} has no counter {name}"))
    }

    fn port(&self, device: &str, n: u32) -> PortRef {
        self.ports[device].port(n)
    }

    fn same_as(&self, other: &Run, label: &str) {
        assert_eq!(self.journal, other.journal, "{label}: journal");
        assert_eq!(self.frames, other.frames, "{label}: frames");
        assert_eq!(self.pcaps, other.pcaps, "{label}: pcaps");
    }
}

/// Runs `network` until it is quiet and collects what a check needs; `routers` are the devices
/// whose counters are read.
fn finish(mut network: Network, seed: u64, routers: &[&str]) -> Run {
    network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    let mut counters = BTreeMap::new();
    let mut ports = BTreeMap::new();
    for name in routers {
        let d = network.live_device(name).expect("the router");
        let c = network.counters(d).unwrap().expect("a router has counters");
        counters.insert((*name).to_owned(), c.into_iter().collect());
    }
    for d in network.devices() {
        ports.insert(network.device_name(d).to_owned(), d);
    }
    Run {
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        counters,
        ports,
    }
}

/// `(src, dst)` IPv4 addresses of an IPv4 frame.
fn addrs(frame: &[u8]) -> Option<(String, String)> {
    let p = SlicedPacket::from_ethernet(frame).ok()?;
    match p.net? {
        NetSlice::Ipv4(ip) => Some((
            ip.header().source_addr().to_string(),
            ip.header().destination_addr().to_string(),
        )),
        _ => None,
    }
}

/// The IPv4 `(src, dst)` pairs of every frame `port` transmitted.
fn sent(run: &Run, port: PortRef) -> Vec<(String, String)> {
    support::sent_by(&run.frames, port)
        .into_iter()
        .filter_map(|f| addrs(&f.bytes))
        .collect()
}

fn link(network: &mut Network, a: PortRef, b: PortRef) {
    network.link(a, b).unwrap().latency(100 * US);
}

// ---------------------------------------------------------------------------------------------
// HTTP through the NAT

fn http_run(seed: u64) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:01:10"),
                ("ipv4", "192.168.1.10/24"),
                ("ipv4-gateway", "192.168.1.1"),
                ("app.http-get.url", "http://203.0.113.80/big?n=20000"),
                ("app.http-get.start", "5ms"),
            ]),
        )
        .unwrap();
    let nat = network
        .device_with_config(
            "nat",
            &b.load("router"),
            config(&[
                ("mac", "02:00:00:00:fe:00"),
                ("port0.ipv4", "192.168.1.1/24"),
                ("port1.ipv4", "203.0.113.1/24"),
                ("port1.nat", "masquerade"),
            ]),
        )
        .unwrap();
    let server = network
        .device_with_config(
            "server",
            &b.load("node-http-server"),
            config(&[("mac", "02:00:00:00:02:80"), ("ipv4", "203.0.113.80/24")]),
        )
        .unwrap();
    link(&mut network, client.port(0), nat.port(0));
    link(&mut network, nat.port(1), server.port(0));
    finish(network, seed, &["nat"])
}

#[test]
fn a_client_behind_the_nat_fetches_from_outside() {
    for seed in [1, 2] {
        let label = format!("seed={seed}");
        let run = http_run(seed);
        let log = transcript(&run.journal);
        let done = events(&run.journal, "client", "http-get-done");
        assert_eq!(done.len(), 1, "{label}\n{log}");
        assert_eq!(field(&done[0], "status"), "200", "{label}");
        assert_eq!(field(&done[0], "body-bytes"), "20000", "{label}");
        // The server saw the router's address.
        let accepted = events(&run.journal, "server", "http-accepted");
        assert_eq!(accepted.len(), 1, "{label}");
        assert!(
            field(&accepted[0], "peer").starts_with("203.0.113.1:"),
            "{label}: {accepted:?}"
        );
        // The captures: inside, the client's own address; outside, only the router's.
        let inside = sent(&run, run.port("client", 0));
        assert!(!inside.is_empty());
        assert!(
            inside
                .iter()
                .all(|(s, d)| s == "192.168.1.10" && d == "203.0.113.80"),
            "{label}: {inside:?}"
        );
        let out = sent(&run, run.port("nat", 1));
        assert!(
            out.iter()
                .all(|(s, d)| s == "203.0.113.1" && d == "203.0.113.80"),
            "{label}: {out:?}"
        );
        let back = sent(&run, run.port("server", 0));
        assert!(back.iter().all(|(_, d)| d == "203.0.113.1"), "{label}");
        let to_client = sent(&run, run.port("nat", 0));
        assert!(
            to_client
                .iter()
                .all(|(s, d)| s == "203.0.113.80" && d == "192.168.1.10"),
            "{label}"
        );
        let created = events(&run.journal, "nat", "nat-mapping-created");
        assert_eq!(created.len(), 1, "{label}: one connection, one mapping");
        assert_eq!(field(&created[0], "proto"), "tcp");
        assert!(run.counter("nat", "nat-translated-out") > 0);
        assert!(run.counter("nat", "nat-translated-in") > 0);
        // The network ran until the mapping expired (transitory 240 s after the FINs).
        assert_eq!(run.counter("nat", "nat-mappings"), 0, "{label}");
        assert_eq!(events(&run.journal, "nat", "nat-mapping-expired").len(), 1);
        assert_eq!(run.counter("nat", "nat-no-mapping"), 0, "{label}");
        run.same_as(&http_run(seed), &label);
    }
}

// ---------------------------------------------------------------------------------------------
// The hole-punching matrix

/// One NAT's behaviours: `nat.mapping` and `nat.filtering`.
#[derive(Clone, Copy, Debug)]
struct Behaviour {
    mapping: &'static str,
    filtering: &'static str,
}

const EI: &str = "endpoint-independent";
const AD: &str = "address-dependent";
const APD: &str = "address-and-port-dependent";

fn punch_run(seed: u64, a: Behaviour, b: Behaviour) -> Run {
    let built = built();
    let mut network = Network::new(&built.host, seed);
    let router = built.load("router");
    let punch = built.load("node-udp-punch");
    let wan = network
        .device_with_config("wan", &built.load("switch"), config(&[("ports", "3")]))
        .unwrap();
    let rendezvous = network
        .device_with_config(
            "rendezvous",
            &punch,
            config(&[
                ("mac", "02:00:00:00:02:00"),
                ("ipv4", "203.0.113.100/24"),
                ("app.udp-punch.role", "rendezvous"),
            ]),
        )
        .unwrap();
    link(&mut network, rendezvous.port(0), wan.port(0));
    for (n, (name, side, outside, start)) in [
        ("a", a, "203.0.113.1/24", "10ms"),
        ("b", b, "203.0.113.2/24", "20ms"),
    ]
    .into_iter()
    .enumerate()
    {
        let nat = network
            .device_with_config(
                &format!("nat-{name}"),
                &router,
                config(&[
                    ("mac", &format!("02:00:00:00:f{n}:00")),
                    ("port0.ipv4", "192.168.1.1/24"),
                    ("port1.ipv4", outside),
                    ("port1.nat", "masquerade"),
                    ("nat.mapping", side.mapping),
                    ("nat.filtering", side.filtering),
                ]),
            )
            .unwrap();
        // Both homes use the same inside prefix and the same inside address.
        let peer = network
            .device_with_config(
                &format!("peer-{name}"),
                &punch,
                config(&[
                    ("mac", &format!("02:00:00:00:0{n}:10")),
                    ("ipv4", "192.168.1.10/24"),
                    ("ipv4-gateway", "192.168.1.1"),
                    ("app.udp-punch.role", "peer"),
                    ("app.udp-punch.name", name),
                    ("app.udp-punch.server", "203.0.113.100:3478"),
                    ("app.udp-punch.start", start),
                ]),
            )
            .unwrap();
        link(&mut network, peer.port(0), nat.port(0));
        link(&mut network, nat.port(1), wan.port(n as u32 + 1));
    }
    finish(network, seed, &["nat-a", "nat-b"])
}

/// What each peer concluded: `(a's result, b's result)`.
fn punch_results(run: &Run) -> (String, String) {
    let result = |peer: &str| {
        let done = events(&run.journal, peer, "punch-done");
        assert_eq!(done.len(), 1, "{peer}\n{}", transcript(&run.journal));
        field(&done[0], "result").to_owned()
    };
    (result("peer-a"), result("peer-b"))
}

#[test]
fn hole_punching_succeeds_or_fails_as_rfc_4787_predicts() {
    let same = |mapping, filtering| {
        let b = Behaviour { mapping, filtering };
        (b, b)
    };
    let symmetric = Behaviour {
        mapping: APD,
        filtering: APD,
    };
    let cone = |filtering| Behaviour {
        mapping: EI,
        filtering,
    };
    // (NAT A, NAT B, whether the peers connect). With endpoint-independent mapping, each peer
    // reaches the other at the endpoint the rendezvous saw: filtering only decides whether the
    // first punches are dropped. With address- or address-and-port-dependent mapping a punch
    // leaves from a new external port, which only endpoint-independent filtering on the far
    // side lets in; the far peer then answers that port (peer-reflexive), and its answer comes
    // from the endpoint the new mapping sent to. A symmetric NAT facing a cone NAT connects when
    // the cone filters by address (it sent to the symmetric NAT's address already), not when
    // it filters by address and port.
    let cases = [
        (same(EI, EI), true),
        (same(EI, AD), true),
        (same(EI, APD), true),
        (same(AD, EI), true),
        (same(AD, AD), false),
        (same(AD, APD), false),
        (same(APD, EI), true),
        (same(APD, AD), false),
        (same(APD, APD), false),
        ((symmetric, cone(EI)), true),
        ((symmetric, cone(AD)), true),
        ((symmetric, cone(APD)), false),
    ];
    let mut table = Vec::new();
    for ((a, b), connects) in cases {
        for seed in [1, 2] {
            let label = format!(
                "A {}/{}, B {}/{}, seed={seed}",
                a.mapping, a.filtering, b.mapping, b.filtering
            );
            let run = punch_run(seed, a, b);
            let log = transcript(&run.journal);
            // Both registered, from their NAT's outside address.
            let regs = events(&run.journal, "rendezvous", "punch-registered");
            assert_eq!(regs.len(), 2, "{label}\n{log}");
            assert!(
                field(&regs[0], "endpoint").starts_with("203.0.113.1:"),
                "{label}"
            );
            assert!(
                field(&regs[1], "endpoint").starts_with("203.0.113.2:"),
                "{label}"
            );
            let (ra, rb) = punch_results(&run);
            let want = if connects { "connected" } else { "failed" };
            assert_eq!((ra.as_str(), rb.as_str()), (want, want), "{label}\n{log}");
            if !connects {
                let filtered =
                    run.counter("nat-a", "nat-filtered") + run.counter("nat-b", "nat-filtered");
                assert!(filtered > 0, "{label}: a failure is the filters' doing");
            }
            // Endpoint-independent mapping: the punches leave from the registered endpoint.
            if a.mapping == EI && b.mapping == EI {
                for nat in ["nat-a", "nat-b"] {
                    assert_eq!(
                        events(&run.journal, nat, "nat-mapping-created").len(),
                        1,
                        "{label}: {nat} keeps one mapping"
                    );
                }
            }
            if seed == 1 {
                table.push(format!(
                    "{label}: a {ra}, b {rb}; filtered a={} b={}",
                    run.counter("nat-a", "nat-filtered"),
                    run.counter("nat-b", "nat-filtered")
                ));
            }
            run.same_as(&punch_run(seed, a, b), &label);
        }
    }
    println!("{}", table.join("\n"));
}

// ---------------------------------------------------------------------------------------------
// A port forward and hairpinning

fn forward_run(seed: u64, hairpin: bool) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let lan = network
        .device_with_config("lan", &b.load("switch"), config(&[("ports", "4")]))
        .unwrap();
    let nat = network
        .device_with_config(
            "nat",
            &b.load("router"),
            config(&[
                ("mac", "02:00:00:00:fe:00"),
                ("port0.ipv4", "192.168.1.1/24"),
                ("port1.ipv4", "203.0.113.1/24"),
                ("port1.nat", "masquerade"),
                (
                    "nat.forwards",
                    "tcp 8080 to 192.168.1.10:80, udp 7 to 192.168.1.30:7",
                ),
                ("nat.hairpin", if hairpin { "true" } else { "false" }),
            ]),
        )
        .unwrap();
    let web = network
        .device_with_config(
            "web",
            &b.load("node-http-server"),
            config(&[
                ("mac", "02:00:00:00:01:10"),
                ("ipv4", "192.168.1.10/24"),
                ("ipv4-gateway", "192.168.1.1"),
            ]),
        )
        .unwrap();
    let echo = network
        .device_with_config(
            "echo",
            &b.load("node-udp-echo-server"),
            config(&[
                ("mac", "02:00:00:00:01:30"),
                ("ipv4", "192.168.1.30/24"),
                ("ipv4-gateway", "192.168.1.1"),
            ]),
        )
        .unwrap();
    // Inside, a client of the forwarded echo service, through the outside address.
    let inside = network
        .device_with_config(
            "inside",
            &b.load("node-udp-echo-client"),
            config(&[
                ("mac", "02:00:00:00:01:20"),
                ("ipv4", "192.168.1.20/24"),
                ("ipv4-gateway", "192.168.1.1"),
                ("app.udp-echo-client.target", "203.0.113.1"),
                ("app.udp-echo-client.count", "3"),
                ("app.udp-echo-client.interval", "100ms"),
                ("app.udp-echo-client.timeout", "50ms"),
                ("app.udp-echo-client.start", "5ms"),
            ]),
        )
        .unwrap();
    // Outside, a client of the forwarded web server.
    let outside = network
        .device_with_config(
            "outside",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:02:50"),
                ("ipv4", "203.0.113.50/24"),
                ("app.http-get.url", "http://203.0.113.1:8080/big?n=3000"),
                ("app.http-get.start", "5ms"),
            ]),
        )
        .unwrap();
    link(&mut network, nat.port(0), lan.port(0));
    link(&mut network, web.port(0), lan.port(1));
    link(&mut network, echo.port(0), lan.port(2));
    link(&mut network, inside.port(0), lan.port(3));
    link(&mut network, nat.port(1), outside.port(0));
    finish(network, seed, &["nat"])
}

#[test]
fn a_port_forward_and_hairpinning_on_and_off() {
    for hairpin in [true, false] {
        for seed in [1, 2] {
            let label = format!("hairpin={hairpin}, seed={seed}");
            let run = forward_run(seed, hairpin);
            let log = transcript(&run.journal);
            // The outside reaches the forwarded web server; it sees the outside client.
            let done = events(&run.journal, "outside", "http-get-done");
            assert_eq!(done.len(), 1, "{label}\n{log}");
            assert_eq!(field(&done[0], "status"), "200", "{label}");
            let accepted = events(&run.journal, "web", "http-accepted");
            assert!(
                field(&accepted[0], "peer").starts_with("203.0.113.50:"),
                "{label}: {accepted:?}"
            );
            // Outside, only the outside address and the forwarded port.
            let out = support::segments_from(&run.frames, run.port("nat", 1));
            assert!(!out.is_empty(), "{label}");
            assert!(
                sent(&run, run.port("nat", 1))
                    .iter()
                    .all(|(s, _)| s == "203.0.113.1"),
                "{label}"
            );
            // The inside client of the outside address.
            let replies = events(&run.journal, "inside", "udp-echo-reply");
            let echoed = events(&run.journal, "echo", "udp-echoed");
            if hairpin {
                assert_eq!(replies.len(), 3, "{label}\n{log}");
                assert_eq!(field(&replies[0], "from"), "203.0.113.1:7", "{label}");
                // The echo server saw the client as the outside sees it.
                assert!(
                    echoed
                        .iter()
                        .all(|e| field(e, "peer").starts_with("203.0.113.1:")),
                    "{label}: {echoed:?}"
                );
                assert_eq!(run.counter("nat", "nat-hairpinned"), 6, "{label}");
            } else {
                assert!(replies.is_empty(), "{label}");
                assert!(echoed.is_empty(), "{label}");
                assert_eq!(
                    events(&run.journal, "inside", "udp-echo-timeout").len(),
                    3,
                    "{label}"
                );
                assert_eq!(run.counter("nat", "nat-hairpin-refused"), 3, "{label}");
                assert_eq!(run.counter("nat", "nat-hairpinned"), 0, "{label}");
            }
            assert_eq!(run.counter("nat", "nat-forwards"), 2, "{label}");
            run.same_as(&forward_run(seed, hairpin), &label);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Traceroute and a port unreachable

fn trace_run(seed: u64) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let client = network
        .device_with_config(
            "client",
            &b.load("node-traceroute"),
            config(&[
                ("mac", "02:00:00:00:01:10"),
                ("ipv4", "192.168.1.10/24"),
                ("ipv4-gateway", "192.168.1.1"),
                ("app.traceroute.target", "198.51.100.10"),
                ("app.traceroute.queries", "1"),
                ("app.traceroute.max-hops", "5"),
                ("app.traceroute.start", "5ms"),
            ]),
        )
        .unwrap();
    let nat = network
        .device_with_config(
            "nat",
            &b.load("router"),
            config(&[
                ("mac", "02:00:00:00:fe:00"),
                ("port0.ipv4", "192.168.1.1/24"),
                ("port1.ipv4", "203.0.113.1/24"),
                ("port1.nat", "masquerade"),
                ("routes", "default via 203.0.113.2"),
            ]),
        )
        .unwrap();
    let isp = network
        .device_with_config(
            "isp",
            &b.load("router"),
            config(&[
                ("mac", "02:00:00:00:fd:00"),
                ("port0.ipv4", "203.0.113.2/24"),
                ("port1.ipv4", "198.51.100.1/24"),
            ]),
        )
        .unwrap();
    let server = network
        .device_with_config(
            "server",
            &b.load("node-udp-echo-server"),
            config(&[
                ("mac", "02:00:00:00:03:10"),
                ("ipv4", "198.51.100.10/24"),
                ("ipv4-gateway", "198.51.100.1"),
            ]),
        )
        .unwrap();
    link(&mut network, client.port(0), nat.port(0));
    link(&mut network, nat.port(1), isp.port(0));
    link(&mut network, isp.port(1), server.port(0));
    finish(network, seed, &["nat"])
}

#[test]
fn traceroute_and_a_port_unreachable_through_the_nat() {
    for seed in [1, 2] {
        let label = format!("seed={seed}");
        let run = trace_run(seed);
        let log = transcript(&run.journal);
        let done = events(&run.journal, "client", "traceroute-done");
        assert_eq!(done.len(), 1, "{label}\n{log}");
        assert_eq!(field(&done[0], "reached"), "true", "{label}\n{log}");
        assert_eq!(
            field(&done[0], "path"),
            "192.168.1.1,203.0.113.2,198.51.100.10",
            "{label}"
        );
        let probes = events(&run.journal, "client", "traceroute-probe");
        let results: Vec<&str> = probes.iter().map(|p| field(p, "result")).collect();
        assert_eq!(
            results,
            ["time-exceeded", "time-exceeded", "reached"],
            "{label}"
        );
        // The ISP's time exceeded and the server's port unreachable were sent to the outside
        // address and reached the client translated.
        assert_eq!(
            run.counter("nat", "nat-icmp-errors-translated"),
            2,
            "{label}"
        );
        let to_nat = sent(&run, run.port("isp", 0));
        assert!(to_nat.iter().all(|(_, d)| d == "203.0.113.1"), "{label}");
        run.same_as(&trace_run(seed), &label);
    }
}
