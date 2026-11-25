//! End to end: tunnel ports on the router, between two homes behind NATs, with real composed
//! nodes.
//!
//! Each home is a NAT router (192.168.1.1 inside, 203.0.113.1 or .2 outside) with a box router
//! behind it (192.168.1.2; port 1 an IPv6 subnet, fd00:a::/64 or fd00:b::/64) and a node on that
//! subnet: `node-a` fetches over HTTP from `node-b`. On the Internet switch, `relay` is a router
//! with an address everyone reaches (203.0.113.50): it answers STUN Binding requests (its
//! `stun-server`), which tells each tunnel its reflexive endpoint, and in some tests it relays.
//!
//! The test plays both boxes' controllers through `Network::command`: it adds a tunnel and a
//! route over it on each box, reads each tunnel's reflexive endpoint from `tunnels`, and hands
//! it to the other box with `tunnel-peer`; the boxes punch through their NATs by themselves.
//!
//! Every network runs at two seeds, twice: the reruns are byte-identical. The tests assert on
//! decoded packets and journals; between the homes they decode every frame as ARP, STUN or
//! Geneve with an inner IPv6 packet.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use std::collections::BTreeMap;

use etherparse::{Ipv6Slice, NetSlice, SlicedPacket, TransportSlice};
use support::{built, config, events, field, transcript};
use wasmnet_det_cbor::Value;
use wasmnet_host::{
    DeviceConfig, DeviceId, DeviceOptions, FrameRecord, JournalEntry, LinkId, Network, PortRef, sim,
};

const US: u64 = 1_000;
const MS: u64 = 1_000_000;
const S: u64 = 1_000_000_000;

const EI: &str = "endpoint-independent";
const AD: &str = "address-dependent";
const APD: &str = "address-and-port-dependent";

/// One NAT's behaviour and any further keys.
#[derive(Clone, Debug)]
struct Nat {
    mapping: &'static str,
    filtering: &'static str,
    extra: Vec<(&'static str, &'static str)>,
}

fn nat(mapping: &'static str, filtering: &'static str) -> Nat {
    Nat {
        mapping,
        filtering,
        extra: Vec::new(),
    }
}

/// What a run varies.
#[derive(Clone, Debug)]
struct Setup {
    nats: [Nat; 2],
    /// Tunnel timers on the boxes.
    keepalive: &'static str,
    dead: &'static str,
    /// When `node-a` fetches, and what (`app.http-get.urls`), and what `node-b` serves.
    fetch_at: &'static str,
    urls: &'static str,
    interval: &'static str,
    listen: &'static str,
    /// Commands to a box (0 or 1) at an instant after the pairing (50 ms).
    commands: Vec<(u64, usize, &'static str, &'static str)>,
    /// Use the relay when the direct tunnel failed (the controller checks at 5 s).
    relay: bool,
    /// Home B's Internet cable is down over this interval.
    cut: Option<(u64, u64)>,
    end: u64,
    /// The direct tunnel's key at box A and at box B; with keys, the relay's tunnels are keyed
    /// too ([`RELAY_A`], [`RELAY_B`]).
    keys: Option<[&'static str; 2]>,
    /// Frames an attacker on the Internet switch sends (from the relay's cable), at instants.
    inject: Vec<(u64, Vec<u8>)>,
}

/// Tunnel keys: the direct tunnel's, another, and the relay's two pairs.
const KEY: &str = "5a17b0c3e8d24f6197a2c4e6f8091b3d5f7193b5d7f9e2c4a6b8d0f1e3c5a7b9";
const KEY2: &str = "0d1c2b3a49586776859a4b3c2d1e0f1f2e3d4c5b6a79887766554433221100ff";
const RELAY_A: &str = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0";
const RELAY_B: &str = "b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0";

impl Setup {
    fn new(a: Nat, b: Nat) -> Setup {
        Setup {
            nats: [a, b],
            keepalive: "25s",
            dead: "80s",
            fetch_at: "2s",
            urls: "http://[fd00:b::10]/big?n=20000",
            interval: "0s",
            listen: "[::]:80",
            commands: Vec::new(),
            relay: false,
            cut: None,
            end: 4 * S,
            keys: None,
            inject: Vec::new(),
        }
    }

    /// The same with the direct tunnel keyed with `KEY` at both ends.
    fn keyed(mut self) -> Setup {
        self.keys = Some([KEY, KEY]);
        self
    }

    /// ` key <k>` for box `i`'s direct tunnel, or nothing (no keys, or an empty one).
    fn key(&self, i: usize) -> String {
        match self.keys {
            Some(k) if !k[i].is_empty() => format!(" key {}", k[i]),
            _ => String::new(),
        }
    }
}

/// What a run leaves behind.
struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcaps: Vec<Vec<u8>>,
    /// The links between the NATs and the Internet switch.
    wan_links: Vec<LinkId>,
    /// `tunnels` of box-a, box-b and the relay at the end.
    listings: BTreeMap<String, String>,
    counters: BTreeMap<String, BTreeMap<String, u64>>,
    /// What each device cost (fuel), by name.
    costs: BTreeMap<String, wasmnet_host::sim::DeviceCost>,
}

impl Run {
    fn same_as(&self, other: &Run, label: &str) {
        assert_eq!(self.journal, other.journal, "{label}: journal");
        assert_eq!(self.frames, other.frames, "{label}: frames");
        assert_eq!(self.pcaps, other.pcaps, "{label}: pcaps");
    }

    fn counter(&self, device: &str, name: &str) -> u64 {
        self.counters[device]
            .get(name)
            .copied()
            .unwrap_or_else(|| panic!("{device} has no counter {name}"))
    }

    fn count(&self, device: &str, kind: &str) -> usize {
        events(&self.journal, device, kind).len()
    }

    fn fetched(&self) -> bool {
        let done = events(&self.journal, "node-a", "http-get-done");
        done.len() == 1
            && field(&done[0], "status") == "200"
            && field(&done[0], "body-bytes") == "20000"
    }
}

fn command(network: &mut Network, d: DeviceId, c: &str, a: &str) -> String {
    match network.command(d, c, a).unwrap() {
        Some(Ok(s)) => s,
        other => panic!("{c} {a}: {other:?}"),
    }
}

/// The value after `key` in a `tunnels` line.
fn value<'a>(line: &'a str, key: &str) -> &'a str {
    let words: Vec<&str> = line.split(' ').collect();
    let at = words.iter().position(|w| *w == key).expect(key);
    words[at + 1]
}

/// The `tunnels` line of tunnel `name`.
fn line<'a>(listing: &'a str, name: &str) -> &'a str {
    listing
        .lines()
        .find(|l| l.split(' ').next() == Some(name))
        .unwrap_or_else(|| panic!("no tunnel {name} in {listing}"))
}

fn link(network: &mut Network, a: PortRef, b: PortRef) -> LinkId {
    network.link(a, b).unwrap().latency(100 * US).id()
}

fn pairs(p: &[(&str, &str)]) -> DeviceConfig {
    config(p)
}

fn run(seed: u64, s: &Setup) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let router = b.load("router");
    let wan = network
        .device_with_config("wan", &b.load("switch"), pairs(&[("ports", "3")]))
        .unwrap();
    let relay = network
        .device_with_config(
            "relay",
            &router,
            pairs(&[
                ("mac", "02:00:00:00:05:00"),
                ("port0.ipv4", "203.0.113.50/24"),
                ("stun-server", "3478"),
            ]),
        )
        .unwrap();
    link(&mut network, relay.port(0), wan.port(0));
    let mut boxes = Vec::new();
    let mut wan_links = Vec::new();
    for (n, name) in ["a", "b"].into_iter().enumerate() {
        let spec = &s.nats[n];
        let outside = format!("203.0.113.{}/24", n + 1);
        let mac = format!("02:00:00:00:f{n}:00");
        let mut cfg = vec![
            ("mac", mac.as_str()),
            ("port0.ipv4", "192.168.1.1/24"),
            ("port1.ipv4", outside.as_str()),
            ("port1.nat", "masquerade"),
            ("nat.mapping", spec.mapping),
            ("nat.filtering", spec.filtering),
        ];
        cfg.extend(spec.extra.iter().copied());
        let natd = network
            .device_with_config(&format!("nat-{name}"), &router, pairs(&cfg))
            .unwrap();
        let subnet = format!("fd00:{name}::1/64");
        let boxr = network
            .device_with_config(
                &format!("box-{name}"),
                &router,
                pairs(&[
                    ("mac", &format!("02:00:00:00:b{n}:00")),
                    ("port0.ipv4", "192.168.1.2/24"),
                    ("port1.ipv6", &subnet),
                    ("port1.ipv6-link-local", "fe80::1"),
                    ("routes", "default via 192.168.1.1"),
                ]),
            )
            .unwrap();
        let mac = format!("02:00:00:00:0{n}:10");
        let addr = format!("fd00:{name}::10/64");
        let mut node = vec![
            ("mac", mac.as_str()),
            ("ipv6", addr.as_str()),
            ("ipv6-gateway", "fe80::1"),
        ];
        let node = if name == "a" {
            node.push(("app.http-get.urls", s.urls));
            node.push(("app.http-get.interval", s.interval));
            node.push(("app.http-get.start", s.fetch_at));
            network
                .device_with_config("node-a", &b.load("node-http-get"), pairs(&node))
                .unwrap()
        } else {
            node.push(("app.http-server.listen", s.listen));
            network
                .device_with_config("node-b", &b.load("node-http-server"), pairs(&node))
                .unwrap()
        };
        link(&mut network, node.port(0), boxr.port(1));
        link(&mut network, boxr.port(0), natd.port(0));
        let w = link(&mut network, natd.port(1), wan.port(n as u32 + 1));
        if let (Some((down, up)), "b") = (s.cut, name) {
            network.schedule_link_state(w, down, false);
            network.schedule_link_state(w, up, true);
        }
        wan_links.push(w);
        boxes.push(boxr);
    }

    // The controllers. At 1 ms each box gets its tunnel and a route over it; the tunnel asks the
    // relay for its reflexive endpoint.
    network.run_until(MS).unwrap();
    for (i, (me, other)) in [("a", "b"), ("b", "a")].into_iter().enumerate() {
        let spec = format!(
            "to-{other} id 7 local fd00:ff::{me}/128 reflector 203.0.113.50:3478 \
             keepalive {} dead {}{}",
            s.keepalive,
            s.dead,
            s.key(i)
        );
        assert_eq!(
            command(&mut network, boxes[i], "tunnel-add", &spec),
            "added"
        );
        let route = format!("fd00:{other}::/64 tunnel to-{other}");
        assert_eq!(
            command(&mut network, boxes[i], "route-add", &route),
            "added"
        );
        if s.relay {
            // A keyed relay tunnel listens on 4500, a keyless one on Geneve's 6081.
            let (port, key) = match s.keys {
                Some(_) => (4500, format!(" key {}", [RELAY_A, RELAY_B][i])),
                None => (6081, String::new()),
            };
            let spec = format!(
                "relay id {} local fd00:ff::{me}:1/128 peer 203.0.113.50:{port} keepalive {} dead {}{key}",
                8 + i,
                s.keepalive,
                s.dead
            );
            assert_eq!(
                command(&mut network, boxes[i], "tunnel-add", &spec),
                "added"
            );
        }
    }
    if s.relay {
        // The relay's ends: no candidates; each learns its peer from the first check.
        for (name, id, sub, key) in [("to-a", 8, "a", RELAY_A), ("to-b", 9, "b", RELAY_B)] {
            let key = s.keys.map_or_else(String::new, |_| format!(" key {key}"));
            let spec = format!(
                "{name} id {id} local fd00:ff::50:{id}/128 keepalive {} dead {}{key}",
                s.keepalive, s.dead
            );
            command(&mut network, relay, "tunnel-add", &spec);
            command(
                &mut network,
                relay,
                "route-add",
                &format!("fd00:{sub}::/64 tunnel {name}"),
            );
        }
    }
    for (at, frame) in &s.inject {
        network
            .add_op(
                sim::Op::inject(relay.port(0), frame.clone()),
                sim::Placement::StartOf(*at),
            )
            .unwrap();
    }
    // At 50 ms each controller has its tunnel's reflexive endpoint and hands it to the other.
    network.run_until(50 * MS).unwrap();
    let reflexive: Vec<String> = boxes
        .iter()
        .zip(["to-b", "to-a"])
        .map(|(d, t)| {
            let listing = command(&mut network, *d, "tunnels", "");
            value(line(&listing, t), "reflexive").to_owned()
        })
        .collect();
    for (i, t) in ["to-b", "to-a"].into_iter().enumerate() {
        let theirs = &reflexive[1 - i];
        assert_ne!(theirs, "-", "a reflexive endpoint by 50 ms");
        command(
            &mut network,
            boxes[i],
            "tunnel-peer",
            &format!("{t} {theirs}"),
        );
    }
    for (at, i, c, a) in &s.commands {
        network.run_until(*at).unwrap();
        command(&mut network, boxes[*i], c, a);
    }
    if s.relay {
        // At 5 s the controllers move each box's route to the relay if the direct tunnel failed.
        network.run_until(5 * S).unwrap();
        for (i, (t, other)) in [("to-b", "b"), ("to-a", "a")].into_iter().enumerate() {
            let listing = command(&mut network, boxes[i], "tunnels", "");
            if value(line(&listing, t), "state") == "failed" {
                let route = format!("fd00:{other}::/64 tunnel relay");
                assert_eq!(
                    command(&mut network, boxes[i], "route-replace", &route),
                    "replaced"
                );
            }
        }
    }
    network
        .run_until(s.end)
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));

    let mut listings = BTreeMap::new();
    let mut counters = BTreeMap::new();
    for (name, d) in [("box-a", boxes[0]), ("box-b", boxes[1]), ("relay", relay)] {
        listings.insert(name.to_owned(), command(&mut network, d, "tunnels", ""));
    }
    for name in ["box-a", "box-b", "relay", "nat-a", "nat-b"] {
        let d = network.live_device(name).unwrap();
        let c = network.counters(d).unwrap().unwrap();
        counters.insert(name.to_owned(), c.into_iter().collect());
    }
    Run {
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        wan_links,
        listings,
        counters,
        costs: network.costs().into_iter().collect(),
    }
}

/// What crossed between the homes and the Internet, decoded by this test's own reading of
/// STUN (RFC 8489) and Geneve (RFC 8926).
#[derive(Debug, Default, PartialEq, Eq)]
struct Wan {
    arp: usize,
    stun_requests: usize,
    stun_responses: usize,
    geneve: usize,
    /// ESP packets (RFC 4303 in UDP, RFC 3948): a keyed tunnel's data.
    esp: usize,
    /// STUN messages that carry MESSAGE-INTEGRITY-SHA256 (0x001C).
    signed: usize,
    /// Distinct outer UDP endpoints seen (address and port).
    endpoints: std::collections::BTreeSet<String>,
}

fn decode_wan(run: &Run) -> Wan {
    let mut w = Wan::default();
    for f in run
        .frames
        .iter()
        .filter(|f| run.wan_links.contains(&f.link))
    {
        if f.bytes.get(12..14) == Some(&[0x08, 0x06]) {
            w.arp += 1;
            continue;
        }
        let p = SlicedPacket::from_ethernet(&f.bytes).expect("an Ethernet frame");
        let Some(NetSlice::Ipv4(ip)) = p.net else {
            panic!("between the homes only IPv4: {:02x?}", f.bytes)
        };
        let Some(TransportSlice::Udp(u)) = p.transport else {
            panic!("between the homes only UDP: {:02x?}", f.bytes)
        };
        let h = ip.header();
        w.endpoints
            .insert(format!("{}:{}", h.source_addr(), u.source_port()));
        let d = u.payload();
        if d.len() >= 20 && d[4..8] == [0x21, 0x12, 0xa4, 0x42] {
            let len = usize::from(u16::from_be_bytes([d[2], d[3]]));
            assert_eq!(20 + len, d.len(), "a STUN length");
            match u16::from_be_bytes([d[0], d[1]]) {
                0x0001 => w.stun_requests += 1,
                0x0101 => w.stun_responses += 1,
                t => panic!("STUN type {t:#06x}"),
            }
            let mut at = 20;
            while at + 4 <= d.len() {
                let t = u16::from_be_bytes([d[at], d[at + 1]]);
                let l = usize::from(u16::from_be_bytes([d[at + 2], d[at + 3]]));
                if t == 0x001c {
                    w.signed += 1;
                }
                at += 4 + l.next_multiple_of(4);
            }
        } else if d[0] & 0x80 != 0 {
            // ESP: SPI (top bit set), sequence number, IV, then ciphertext and a 16-byte tag; the
            // encrypted part is a multiple of 4 bytes.
            assert!(
                d.len() >= 36 && (d.len() - 32).is_multiple_of(4),
                "an ESP length"
            );
            assert_eq!(
                d[8..12],
                [0; 4],
                "the IV is the zero-extended sequence number"
            );
            assert_eq!(d[12..16], d[4..8]);
            w.esp += 1;
        } else {
            assert_eq!(d[0], 0, "Geneve version 0, no options");
            assert_eq!(d[1], 0, "no O or C bit");
            assert_eq!(d[2..4], [0x86, 0xdd], "inner IPv6");
            assert_eq!(d[7], 0);
            let inner = Ipv6Slice::from_slice(&d[8..]).expect("an inner IPv6 packet");
            let src = inner.header().source_addr().segments();
            assert!(
                src[0] == 0xfd00 && [0xa, 0xb, 0xff].contains(&src[1]),
                "{src:x?}"
            );
            w.geneve += 1;
        }
    }
    w
}

/// Runs a setup at seeds 1 and 2, each twice, and hands each first run to `check`.
fn each_seed(s: &Setup, mut check: impl FnMut(&Run, &str)) {
    for seed in [1, 2] {
        let label = format!("seed={seed}");
        let r = run(seed, s);
        check(&r, &label);
        r.same_as(&run(seed, s), &label);
    }
}

#[test]
fn http_across_a_tunnel_punched_through_two_nats() {
    each_seed(&Setup::new(nat(EI, APD), nat(EI, APD)), |r, label| {
        let log = transcript(&r.journal);
        assert!(r.fetched(), "{label}\n{log}");
        for (d, peer) in [("box-a", "203.0.113.2:6081"), ("box-b", "203.0.113.1:6081")] {
            let up = events(&r.journal, d, "tunnel-up");
            assert_eq!(up.len(), 1, "{label} {d}\n{log}");
            assert_eq!(
                field(&up[0], "peer"),
                peer,
                "{label}: ports preserved by both NATs"
            );
            assert_eq!(r.count(d, "tunnel-reflexive"), 1);
        }
        let w = decode_wan(r);
        assert!(
            w.geneve > 20 && w.stun_requests > 2 && w.stun_responses > 2,
            "{label}: {w:?}"
        );
        // The endpoints between the homes: both NATs' and the relay's, nothing else.
        let want = ["203.0.113.1:6081", "203.0.113.2:6081", "203.0.113.50:3478"];
        assert_eq!(
            w.endpoints.iter().map(String::as_str).collect::<Vec<_>>(),
            want
        );
        assert!(r.counter("box-a", "tunnel-to-b-mss-clamped") >= 1);
        assert_eq!(r.counter("box-a", "tunnel-to-b-down-drops"), 0);
        assert_eq!(r.counter("relay", "stun-bindings-answered"), 2);
        let a = &r.listings["box-a"];
        assert!(a.starts_with("to-b id 7 udp 6081 local fd00:ff::a/128 state up peer 203.0.113.2:6081 reflexive 203.0.113.1:6081"), "{a}");
    });
}

#[test]
fn the_punching_matrix_holds() {
    // (NAT A, NAT B, whether the tunnel comes up), as RFC 4787 predicts and as
    // `tests/nat.rs` finds for the `udp-punch` fixture.
    let same = |m, f| (nat(m, f), nat(m, f));
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
        ((nat(APD, APD), nat(EI, EI)), true),
        ((nat(APD, APD), nat(EI, AD)), true),
        ((nat(APD, APD), nat(EI, APD)), false),
    ];
    let mut table = Vec::new();
    for ((a, b), connects) in cases {
        let s = Setup::new(a.clone(), b.clone());
        let name = format!(
            "A {}/{} B {}/{}",
            a.mapping, a.filtering, b.mapping, b.filtering
        );
        each_seed(&s, |r, label| {
            let up = (r.count("box-a", "tunnel-up"), r.count("box-b", "tunnel-up"));
            let want = usize::from(connects);
            assert_eq!(
                up,
                (want, want),
                "{name} {label}\n{}",
                transcript(&r.journal)
            );
            assert_eq!(r.fetched(), connects, "{name} {label}");
            if !connects {
                assert_eq!(r.count("box-a", "tunnel-failed"), 1, "{name} {label}");
                let filtered =
                    r.counter("nat-a", "nat-filtered") + r.counter("nat-b", "nat-filtered");
                assert!(filtered > 0, "{name} {label}: the filters' doing");
            }
            if label == "seed=1" {
                table.push(format!("{name}: up {up:?}"));
            }
        });
    }
    println!("{}", table.join("\n"));
}

#[test]
fn symmetric_nats_fail_and_a_relay_carries_the_fetch() {
    let symmetric = || nat(APD, APD);
    // Without the relay: no tunnel, no fetch.
    let mut s = Setup::new(symmetric(), symmetric());
    s.fetch_at = "6s";
    s.end = 8 * S;
    each_seed(&s, |r, label| {
        assert_eq!(r.count("box-a", "tunnel-failed"), 1, "{label}");
        assert!(!r.fetched(), "{label}");
        let error = events(&r.journal, "node-a", "http-get-error");
        assert!(
            field(&error[0], "error").contains("unreachable"),
            "{error:?}"
        );
    });
    // With it: the controllers move the routes at 5 s and the fetch at 6 s goes through it.
    s.relay = true;
    each_seed(&s, |r, label| {
        let log = transcript(&r.journal);
        assert!(r.fetched(), "{label}\n{log}");
        assert_eq!(
            r.count("box-a", "tunnel-failed"),
            1,
            "{label}: the direct tunnel"
        );
        for d in ["box-a", "box-b"] {
            let changed = events(&r.journal, d, "route-added");
            assert!(
                changed.iter().any(|f| field(f, "port") == "relay"),
                "{label} {d}"
            );
        }
        // The relay forwarded the fetch: its tunnels carried it both ways.
        for t in ["to-a", "to-b"] {
            assert!(
                r.counter("relay", &format!("tunnel-{t}-forwarded-out")) > 5,
                "{label} {t}"
            );
            assert_eq!(value(line(&r.listings["relay"], t), "state"), "up");
        }
        // Symmetric NATs gave the relay's ends new ports, learnt from the boxes' checks.
        let peer = value(line(&r.listings["relay"], "to-a"), "peer");
        assert!(
            peer.starts_with("203.0.113.1:") && peer != "203.0.113.1:6081",
            "{peer}"
        );
        decode_wan(r);
    });
}

#[test]
fn a_cut_takes_the_tunnel_down_and_it_heals() {
    let mut s = Setup::new(nat(EI, APD), nat(EI, APD));
    s.keepalive = "1s";
    s.dead = "3500ms";
    s.cut = Some((3 * S, 7 * S));
    s.fetch_at = "9s";
    s.end = 11 * S;
    each_seed(&s, |r, label| {
        let log = transcript(&r.journal);
        for d in ["box-a", "box-b"] {
            let down = events(&r.journal, d, "tunnel-down");
            assert_eq!(down.len(), 1, "{label} {d}\n{log}");
            let at = r
                .journal
                .iter()
                .find(|e| e.device == d && matches!(&e.record, wasmnet_host::Record::Event { kind, .. } if kind == "tunnel-down"))
                .map(|e| e.at)
                .unwrap();
            assert!(
                (5 * S..7 * S).contains(&at),
                "{label}: down 3.5 s after the last answer, at {at}"
            );
            assert_eq!(r.count(d, "tunnel-up"), 2, "{label} {d}");
        }
        assert!(r.fetched(), "{label}\n{log}");
    });
}

#[test]
fn a_nat_rebinding_moves_the_peer() {
    // Home B's NAT forgets idle UDP mappings after 3 s and allocates ports in sequence, so the
    // 5 s keepalives find a new mapping each time; home A's NAT lets in any port of an address
    // it sent to. Box A follows box B to each new endpoint.
    let mut b = nat(EI, AD);
    b.extra = vec![
        ("nat.port-allocation", "sequential"),
        ("conntrack.udp-timeout", "3s"),
    ];
    let mut s = Setup::new(nat(EI, AD), b);
    s.keepalive = "5s";
    s.dead = "20s";
    s.fetch_at = "12s";
    s.end = 14 * S;
    each_seed(&s, |r, label| {
        let log = transcript(&r.journal);
        let up = events(&r.journal, "box-a", "tunnel-up");
        assert_eq!(field(&up[0], "peer"), "203.0.113.2:1024", "{label}");
        let roamed = events(&r.journal, "box-a", "tunnel-roamed");
        assert!(!roamed.is_empty(), "{label}\n{log}");
        assert_eq!(field(&roamed[0], "from"), "203.0.113.2:1024");
        assert_eq!(field(&roamed[0], "to"), "203.0.113.2:1025");
        assert_eq!(
            r.count("box-a", "tunnel-down"),
            0,
            "{label}: roaming, not a reconnect"
        );
        assert!(r.count("nat-b", "nat-mapping-expired") >= 1, "{label}");
        assert!(r.fetched(), "{label}\n{log}");
    });
}

// ---------------------------------------------------------------------------------------------
// A tunnel added and removed while other traffic crosses the router

/// A client (10.0.1.10) fetches 1 MB from a server (10.0.2.80) through router `r`; `r`'s
/// third port faces `far` (203.0.113.9), a router with a tunnel end. With `tunnel`, `r` adds a
/// tunnel to `far` while the transfer runs, routes a prefix over it, and removes it again.
fn busy_run(seed: u64, tunnel: bool) -> (Vec<JournalEntry>, Vec<FrameRecord>, Network<'static>) {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let router = b.load("router");
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            pairs(&[
                ("mac", "02:00:00:00:01:10"),
                ("ipv4", "10.0.1.10/24"),
                ("ipv4-gateway", "10.0.1.1"),
                ("app.http-get.url", "http://10.0.2.80/big?n=1000000"),
                ("app.http-get.start", "5ms"),
            ]),
        )
        .unwrap();
    let r = network
        .device_with_config(
            "r",
            &router,
            pairs(&[
                ("mac", "02:00:00:00:fe:00"),
                ("port0.ipv4", "10.0.1.1/24"),
                ("port1.ipv4", "10.0.2.1/24"),
                ("port2.ipv4", "203.0.113.1/24"),
            ]),
        )
        .unwrap();
    let server = network
        .device_with_config(
            "server",
            &b.load("node-http-server"),
            pairs(&[
                ("mac", "02:00:00:00:02:80"),
                ("ipv4", "10.0.2.80/24"),
                ("ipv4-gateway", "10.0.2.1"),
            ]),
        )
        .unwrap();
    let far = network
        .device_with_config(
            "far",
            &router,
            pairs(&[
                ("mac", "02:00:00:00:fa:00"),
                ("port0.ipv4", "203.0.113.9/24"),
                ("tunnel.to-r.id", "5"),
                ("tunnel.to-r.local", "10.255.0.9/32"),
                ("tunnel.to-r.keepalive", "200ms"),
                ("tunnel.to-r.dead", "1s"),
                ("routes", "10.255.0.1/32 tunnel to-r"),
            ]),
        )
        .unwrap();
    link(&mut network, client.port(0), r.port(0));
    link(&mut network, r.port(1), server.port(0));
    link(&mut network, r.port(2), far.port(0));
    if tunnel {
        for (at, c, a) in [
            (
                7 * MS,
                "tunnel-add",
                "to-far id 5 local 10.255.0.1/32 peer 203.0.113.9:6081 keepalive 200ms dead 1s",
            ),
            (7 * MS, "route-add", "10.255.0.9/32 tunnel to-far"),
            (12 * MS, "tunnel-remove", "to-far"),
        ] {
            network.run_until(at).unwrap();
            command(&mut network, r, c, a);
        }
    }
    network.run_until(3 * S).unwrap();
    (network.journal(), network.frames(), network)
}

#[test]
fn a_tunnel_added_and_removed_beside_a_transfer_leaves_it_alone() {
    for seed in [1, 2] {
        let label = format!("seed={seed}");
        let (plain_journal, plain_frames, plain) = busy_run(seed, false);
        let (journal, frames, busy) = busy_run(seed, true);
        let done = events(&journal, "client", "http-get-done");
        assert_eq!(done.len(), 1, "{label}");
        assert_eq!(field(&done[0], "body-bytes"), "1000000");
        // The tunnel came up and went again while the transfer ran.
        let up = events(&journal, "r", "tunnel-up");
        assert_eq!(up.len(), 1, "{label}\n{}", transcript(&journal));
        assert_eq!(events(&journal, "r", "tunnel-removed").len(), 1);
        let transfer_done = journal
            .iter()
            .find(|e| e.device == "client" && matches!(&e.record, wasmnet_host::Record::Event { kind, .. } if kind == "http-get-done"))
            .unwrap()
            .at;
        assert!(
            transfer_done > 12 * MS,
            "{label}: the transfer spans the change ({transfer_done})"
        );
        // The client's and the server's links carried exactly the same frames at the same times,
        // and both nodes journalled exactly the same.
        let links = |n: &Network| -> Vec<LinkId> {
            let c = n.live_device("client").unwrap();
            let s = n.live_device("server").unwrap();
            n.links()
                .into_iter()
                .filter(|l| {
                    n.link_info(*l)
                        .ends
                        .iter()
                        .any(|e| e.device == c || e.device == s)
                })
                .collect()
        };
        let on = |frames: &[FrameRecord], ls: &[LinkId]| -> Vec<FrameRecord> {
            frames
                .iter()
                .filter(|f| ls.contains(&f.link))
                .cloned()
                .collect()
        };
        assert_eq!(
            on(&frames, &links(&busy)),
            on(&plain_frames, &links(&plain)),
            "{label}"
        );
        let of = |j: &[JournalEntry], d: &str| -> Vec<JournalEntry> {
            j.iter().filter(|e| e.device == d).cloned().collect()
        };
        for d in ["client", "server"] {
            assert_eq!(of(&journal, d), of(&plain_journal, d), "{label} {d}");
        }
        let (again, ..) = busy_run(seed, true);
        assert_eq!(journal, again, "{label}: rerun");
    }
}

// ---------------------------------------------------------------------------------------------
// The packet filter on a tunnel port

#[test]
fn allow_rules_on_a_tunnel_port_filter_what_crosses_it() {
    // node-a asks node-b on port 8080, then 80, then 8080 again, a second apart. At 1 s box B
    // lets in only TCP to port 80 from its tunnel, and box A only ICMPv6 from its own: the
    // second 8080 is dropped at box B, and the answers to node-a pass box A as a known flow.
    let mut s = Setup::new(nat(EI, APD), nat(EI, APD));
    s.fetch_at = "500ms";
    s.interval = "1s";
    s.urls = "http://[fd00:b::10]:8080/big?n=1000,http://[fd00:b::10]/big?n=20000,\
              http://[fd00:b::10]:8080/big?n=3000";
    s.listen = "[::]:80,[::]:8080";
    s.commands = vec![
        (S, 1, "allow-add", "to-a tcp dport 80"),
        (S, 0, "allow-add", "to-b icmpv6"),
    ];
    s.end = 6 * S;
    each_seed(&s, |r, label| {
        let log = transcript(&r.journal);
        let done: Vec<String> = events(&r.journal, "node-a", "http-get-done")
            .iter()
            .map(|f| format!("{} {}", field(f, "url"), field(f, "body-bytes")))
            .collect();
        assert_eq!(
            done,
            [
                "http://[fd00:b::10]:8080/big?n=1000 1000",
                "http://[fd00:b::10]/big?n=20000 20000"
            ],
            "{label}\n{log}"
        );
        // Box B dropped the third request's SYNs at its tunnel port, and said so.
        let drops = events(&r.journal, "box-b", "filter-drop");
        assert!(!drops.is_empty(), "{label}");
        assert_eq!(field(&drops[0], "port"), "to-a");
        assert!(field(&drops[0], "dst").ends_with(":8080"), "{drops:?}");
        assert!(r.counter("box-b", "filter-dropped") >= 1);
        // Box A let node-b's answers in only as a known flow.
        assert_eq!(r.counter("box-a", "filter-dropped"), 0, "{label}");
        assert!(r.counter("box-a", "filter-tracked") > 10, "{label}");
        let added = events(&r.journal, "box-b", "allow-added");
        assert_eq!(field(&added[0], "port"), "to-a");
        decode_wan(r);
    });
}

// ---------------------------------------------------------------------------------------------
// Controllers in the network drive the tunnel

/// A box router's spec for its controller: the router, its config, and its two cables (to the
/// home's NAT router and to the home's node).
fn box_spec(name: &str) -> Vec<u8> {
    let subnet = format!("fd00:{name}::1/64");
    let mac = format!("02:00:00:00:b{}:00", if name == "a" { 0 } else { 1 });
    let config: Vec<(Value, Value)> = [
        ("mac", mac.as_str()),
        ("port0.ipv4", "192.168.1.2/24"),
        ("port1.ipv6", subnet.as_str()),
        ("port1.ipv6-link-local", "fe80::1"),
        ("routes", "default via 192.168.1.1"),
    ]
    .into_iter()
    .map(|(k, v)| (Value::text(k), Value::text(v)))
    .collect();
    let cable = |port: u64, to: String| {
        Value::Map(vec![
            (Value::text("port"), Value::Uint(port)),
            (Value::text("to"), Value::text(&to)),
            (Value::text("latency"), Value::Uint(100 * US)),
        ])
    };
    Value::Map(vec![
        (Value::text("component"), Value::text("router")),
        (Value::text("config"), Value::Map(config)),
        (
            Value::text("wire"),
            Value::Array(vec![
                cable(0, format!("nat-{name}:0")),
                cable(1, format!("node-{name}:0")),
            ]),
        ),
    ])
    .encode()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The controller's script for box `me` (whose peer is box `other`): create the box router, add
/// the tunnel, read its reflexive endpoint (`tunnels`), give the tunnel the peer's endpoint once
/// the embedder has set it (`{peer}`), and route over the tunnel once `tunnels` says it is up.
fn controller_steps(me: &str, other: &str) -> Vec<(String, String)> {
    let mut steps = signaling_steps(me, other);
    // Ask every 10 ms from 45 ms on whether the tunnel is up; route over it once it is.
    for k in 0..10 {
        let at = 45 + 10 * k;
        steps.push(format!("{at}ms id=up-{k} control box-{me} tunnels"));
        steps.push(format!(
            "{}ms when=up-{k}.state=up control box-{me} route-add fd00:{other}::/64 tunnel to-{other}",
            at + 5
        ));
    }
    numbered(steps)
}

/// A script's steps as config keys (`step.<n>`).
fn numbered(steps: Vec<String>) -> Vec<(String, String)> {
    steps
        .into_iter()
        .enumerate()
        .map(|(k, s)| (format!("step.{k}"), s))
        .collect()
}

/// What both kinds of controller do first: create the box router, add the tunnel (`keepalive`
/// 1 s, `dead` 3.5 s), read its reflexive endpoint (`tunnels`, once) and give the tunnel the
/// peer's endpoint once the embedder has set it (`{peer}`).
fn signaling_steps(me: &str, other: &str) -> Vec<String> {
    keyed_signaling_steps(me, other, "")
}

/// [`signaling_steps`] with `more` after the tunnel's settings (` key <hex>`).
fn keyed_signaling_steps(me: &str, other: &str, more: &str) -> Vec<String> {
    vec![
        format!("0ms apply box-{me} {}", hex(&box_spec(me))),
        format!(
            "10ms id=add control box-{me} tunnel-add to-{other} id 7 local fd00:ff::{me}/128 \
             reflector 203.0.113.50:3478 keepalive 1s dead 3500ms{more}"
        ),
        format!("40ms id=reflexive control box-{me} tunnels"),
        "41ms answer reflexive".to_owned(),
        format!("50ms id=peer control box-{me} tunnel-peer to-{other} {{peer}}"),
    ]
}

/// The script of a controller that follows its box's events instead of asking: when the
/// tunnel to the other box comes up it routes the other's prefix over it, and when it goes down
/// it takes that route away again (`routes-replace` with the whole static table each time), with
/// no `tunnels` command after the one that reads the reflexive endpoint.
fn event_steps(me: &str, other: &str) -> Vec<(String, String)> {
    let mut config = numbered(signaling_steps(me, other));
    config.push((
        "on.0".to_owned(),
        format!(
            "box-{me} tunnel-up tunnel=to-{other} : control box-{me} routes-replace \
             default via 192.168.1.1, fd00:{other}::/64 tunnel to-{other}"
        ),
    ));
    config.push((
        "on.1".to_owned(),
        format!(
            "box-{me} tunnel-down tunnel=to-{other} : control box-{me} routes-replace \
             default via 192.168.1.1"
        ),
    ));
    config
}

/// The value after `reflexive` in the text an `answer` step journalled.
fn reflexive_from(journal: &[JournalEntry], controller: &str) -> String {
    let answers = events(journal, controller, "infra-script");
    let answer = answers
        .iter()
        .find(|f| field(f, "verb") == "answer" && field(f, "name") == "reflexive")
        .unwrap_or_else(|| panic!("{controller} read no answer"));
    assert_eq!(field(answer, "result"), "ok");
    value(field(answer, "text"), "reflexive").to_owned()
}

/// What a run with controllers varies.
struct Controlled {
    /// Each controller's config, for box `me` with peer `other`.
    script: fn(&str, &str) -> Vec<(String, String)>,
    /// Home B's Internet cable is down over this interval.
    cut: Option<(u64, u64)>,
    /// When `node-a` fetches, and (interval, count) to fetch again.
    fetch_at: &'static str,
    repeat: Option<(&'static str, &'static str)>,
    end: u64,
}

/// Controllers that ask `tunnels` on a period.
const POLLING: Controlled = Controlled {
    script: controller_steps,
    cut: None,
    fetch_at: "2s",
    repeat: None,
    end: 4 * S,
};

fn controlled_run(seed: u64, plan: &Controlled) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let router = b.load("router");
    let resolver_router = router.clone();
    network.set_component_resolver(Box::new(move |name, instantiate| match name {
        "router" => instantiate(&resolver_router),
        other => Err(sim::Error::Refused(format!("no component {other}"))),
    }));
    network.set_infra_catalog(vec!["router".to_owned()]);
    let wan = network
        .device_with_config("wan", &b.load("switch"), pairs(&[("ports", "3")]))
        .unwrap();
    let relay = network
        .device_with_config(
            "relay",
            &router,
            pairs(&[
                ("mac", "02:00:00:00:05:00"),
                ("port0.ipv4", "203.0.113.50/24"),
                ("stun-server", "3478"),
            ]),
        )
        .unwrap();
    link(&mut network, relay.port(0), wan.port(0));
    let mut wan_links = Vec::new();
    let mut controllers = Vec::new();
    for (n, (me, other)) in [("a", "b"), ("b", "a")].into_iter().enumerate() {
        let outside = format!("203.0.113.{}/24", n + 1);
        let mac = format!("02:00:00:00:f{n}:00");
        let natd = network
            .device_with_config(
                &format!("nat-{me}"),
                &router,
                pairs(&[
                    ("mac", &mac),
                    ("port0.ipv4", "192.168.1.1/24"),
                    ("port1.ipv4", &outside),
                    ("port1.nat", "masquerade"),
                ]),
            )
            .unwrap();
        let w = link(&mut network, natd.port(1), wan.port(n as u32 + 1));
        if let (Some((down, up)), "b") = (plan.cut, me) {
            network.schedule_link_state(w, down, false);
            network.schedule_link_state(w, up, true);
        }
        wan_links.push(w);
        let mac = format!("02:00:00:00:0{n}:10");
        let addr = format!("fd00:{me}::10/64");
        let mut node = vec![
            ("mac", mac.as_str()),
            ("ipv6", addr.as_str()),
            ("ipv6-gateway", "fe80::1"),
        ];
        let component = if me == "a" {
            node.push(("app.http-get.url", "http://[fd00:b::10]/big?n=20000"));
            node.push(("app.http-get.start", plan.fetch_at));
            if let Some((interval, n)) = plan.repeat {
                node.push(("app.http-get.interval", interval));
                node.push(("app.http-get.repeat", n));
            }
            "node-http-get"
        } else {
            node.push(("app.http-server.listen", "[::]:80"));
            "node-http-server"
        };
        network
            .device_with_config(&format!("node-{me}"), &b.load(component), pairs(&node))
            .unwrap();
        let config = (plan.script)(me, other);
        let script: Vec<(&str, &str)> = config
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let ctl = network
            .device_with_options(
                &format!("ctl-{me}"),
                &b.load("infra_script"),
                pairs(&script),
                DeviceOptions::default().infra(true),
            )
            .unwrap();
        controllers.push(ctl);
    }
    // At 45 ms each controller has read its tunnel's reflexive endpoint. The embedder carries
    // it to the other box's controller, as its own replicated state would: here, the test
    // reads it from one controller's journal and sets it on the other with a command.
    network.run_until(45 * MS).unwrap();
    let journal = network.journal();
    let endpoints = [
        reflexive_from(&journal, "ctl-a"),
        reflexive_from(&journal, "ctl-b"),
    ];
    for (i, ctl) in controllers.iter().enumerate() {
        let peer = &endpoints[1 - i];
        assert_eq!(
            command(&mut network, *ctl, "set", &format!("peer {peer}")),
            "set"
        );
    }
    network
        .run_until(plan.end)
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    let mut listings = BTreeMap::new();
    let mut counters = BTreeMap::new();
    for name in ["box-a", "box-b"] {
        let d = network.live_device(name).unwrap();
        listings.insert(name.to_owned(), command(&mut network, d, "tunnels", ""));
        let c = network.counters(d).unwrap().unwrap();
        counters.insert(name.to_owned(), c.into_iter().collect());
    }
    Run {
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        wan_links,
        listings,
        counters,
        costs: network.costs().into_iter().collect(),
    }
}

#[test]
fn controllers_in_the_network_drive_a_tunnel_end_to_end() {
    for seed in [1, 2] {
        let label = format!("seed={seed}");
        let r = controlled_run(seed, &POLLING);
        let log = transcript(&r.journal);
        assert!(r.fetched(), "{label}\n{log}");
        for (ctl, me, tunnel, theirs) in [
            ("ctl-a", "box-a", "to-b", "203.0.113.2:6081"),
            ("ctl-b", "box-b", "to-a", "203.0.113.1:6081"),
        ] {
            // The controller was told the other side's endpoint and gave it to its tunnel.
            let set = events(&r.journal, ctl, "infra-script-set");
            assert_eq!(field(&set[0], "value"), theirs, "{label}");
            let steps = events(&r.journal, ctl, "infra-script");
            let result = |id: &str| -> Vec<String> {
                steps
                    .iter()
                    .filter(|f| field(f, "name") == me && field(f, "step") == id)
                    .map(|f| field(f, "result").to_owned())
                    .collect()
            };
            assert_eq!(
                result("4"),
                ["ok"],
                "{label}: tunnel-peer with {{peer}} filled in"
            );
            // It routed over the tunnel once it was up, not before: at 45 ms the tunnel had
            // no peer yet.
            let routes: Vec<String> = (0..10)
                .map(|k| result(&(6 + 2 * k).to_string()).concat())
                .collect();
            let first = routes
                .iter()
                .position(|r| r == "ok")
                .expect("a route step ran");
            assert_eq!(routes[0], "skipped", "{label}: {routes:?}");
            assert!(
                routes[first..].iter().all(|r| r == "ok"),
                "{label}: {routes:?}"
            );
            let added = events(&r.journal, me, "route-added");
            assert_eq!(added.len(), 1, "{label}: later route-adds change nothing");
            assert_eq!(field(&added[0], "port"), tunnel);
        }
        decode_wan(&r);
        r.same_as(&controlled_run(seed, &POLLING), &label);
    }
}

/// When each `kind` event of `device` was journalled.
fn times(journal: &[JournalEntry], device: &str, kind: &str) -> Vec<u64> {
    journal
        .iter()
        .filter(|e| e.device == device)
        .filter(|e| matches!(&e.record, wasmnet_host::Record::Event { kind: k, .. } if k == kind))
        .map(|e| e.at)
        .collect()
}

#[test]
fn controllers_follow_the_tunnel_s_events_through_a_cut_and_heal() {
    // Home B's Internet cable is cut from 3 s to 7 s. Each box's tunnel goes down 3.5 s after
    // the last answer and up again after the heal; each controller routes over the tunnel when
    // `tunnel-up` comes and takes the route away when `tunnel-down` comes, in the same instant,
    // and asks `tunnels` only once (for the reflexive endpoint). The fetch at 9 s goes through.
    let plan = Controlled {
        script: event_steps,
        cut: Some((3 * S, 7 * S)),
        fetch_at: "9s",
        repeat: None,
        end: 11 * S,
    };
    for seed in [1, 2] {
        let label = format!("seed={seed}");
        let r = controlled_run(seed, &plan);
        let log = transcript(&r.journal);
        assert!(r.fetched(), "{label}\n{log}");
        for (ctl, me, tunnel, other) in [
            ("ctl-a", "box-a", "to-b", "b"),
            ("ctl-b", "box-b", "to-a", "a"),
        ] {
            let up = times(&r.journal, me, "tunnel-up");
            let down = times(&r.journal, me, "tunnel-down");
            assert_eq!((up.len(), down.len()), (2, 1), "{label} {me}\n{log}");
            assert!((5 * S..7 * S).contains(&down[0]), "{label}: {down:?}");
            // One reaction per event, in the instant of the event.
            let reactions = events(&r.journal, ctl, "infra-script")
                .into_iter()
                .filter(|f| field(f, "step").starts_with("on."))
                .collect::<Vec<_>>();
            let seen: Vec<(&str, &str)> = reactions
                .iter()
                .map(|f| (field(f, "event"), field(f, "result")))
                .collect();
            assert_eq!(
                seen,
                [
                    ("tunnel-up", "ok"),
                    ("tunnel-down", "ok"),
                    ("tunnel-up", "ok")
                ],
                "{label} {ctl}"
            );
            let reacted = times(&r.journal, ctl, "infra-script")
                .into_iter()
                .zip(events(&r.journal, ctl, "infra-script"))
                .filter(|(_, f)| field(f, "step").starts_with("on."))
                .map(|(at, _)| at)
                .collect::<Vec<_>>();
            assert_eq!(reacted, [up[0], down[0], up[1]], "{label} {ctl}");
            // The routes followed: added at each up, removed at the down, at those instants.
            let prefix = format!("fd00:{other}::/64");
            let added: Vec<u64> = r
                .journal
                .iter()
                .filter(|e| e.device == me)
                .filter(|e| {
                    matches!(&e.record, wasmnet_host::Record::Event { kind, fields }
                    if kind == "route-added"
                        && fields.iter().any(|(k, v)| k == "prefix" && *v == prefix))
                })
                .map(|e| e.at)
                .collect();
            assert_eq!(added, [up[0], up[1]], "{label} {me}");
            assert_eq!(times(&r.journal, me, "route-removed"), [down[0]], "{label}");
            let removed = &events(&r.journal, me, "route-removed")[0];
            assert_eq!(field(removed, "port"), tunnel);
            // No polling: one `tunnels` command, for the reflexive endpoint.
            let asked = events(&r.journal, ctl, "infra-control")
                .into_iter()
                .filter(|f| field(f, "command") == "tunnels")
                .count();
            assert_eq!(asked, 1, "{label} {ctl}");
        }
        decode_wan(&r);
        r.same_as(&controlled_run(seed, &plan), &label);
    }
}

// ---------------------------------------------------------------------------------------------
// A keyless tunnel's bytes do not change

/// The SHA-256 of every link's capture of a run, in link order.
fn capture_digest(r: &Run) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    for p in &r.pcaps {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_keyless_tunnel_s_captures_are_unchanged() {
    // Pinned before tunnels could have keys: a keyless tunnel puts the same bytes on every
    // link as it did then (the NATs, the punching, Geneve, the fetch), at two seeds.
    for (seed, want) in [
        (
            1,
            "7688e0536cef171c45c0647c578dbc775f32cf9cb010b19ec334846b0e6ebfb2",
        ),
        (
            2,
            "bdd51798df53f055b4ba16ef0e22eaf97c68b7903b3981321b9b65224e874dcf",
        ),
    ] {
        let r = run(seed, &Setup::new(nat(EI, APD), nat(EI, APD)));
        assert!(r.fetched());
        assert_eq!(capture_digest(&r), want, "seed={seed}");
    }
}

// ---------------------------------------------------------------------------------------------
// Keyed tunnels: ESP in UDP, signed checks

/// The reasons box `d`'s tunnel journalled for refusing something (`tunnel-auth-failed`).
fn refusals(r: &Run, d: &str) -> Vec<String> {
    events(&r.journal, d, "tunnel-auth-failed")
        .iter()
        .map(|f| field(f, "reason").to_owned())
        .collect()
}

/// When each `kind` event of device `d` was journalled.
fn instants(r: &Run, d: &str, kind: &str) -> Vec<u64> {
    r.journal
        .iter()
        .filter(|e| e.device == d)
        .filter(|e| matches!(&e.record, wasmnet_host::Record::Event { kind: k, .. } if k == kind))
        .map(|e| e.at)
        .collect()
}

#[test]
fn http_across_a_keyed_tunnel_punched_through_two_nats() {
    each_seed(
        &Setup::new(nat(EI, APD), nat(EI, APD)).keyed(),
        |r, label| {
            let log = transcript(&r.journal);
            assert!(r.fetched(), "{label}\n{log}");
            for (d, t, peer) in [
                ("box-a", "to-b", "203.0.113.2:4500"),
                ("box-b", "to-a", "203.0.113.1:4500"),
            ] {
                let up = events(&r.journal, d, "tunnel-up");
                assert_eq!(up.len(), 1, "{label} {d}\n{log}");
                assert_eq!(field(&up[0], "peer"), peer, "{label}");
                assert_eq!(
                    r.counter(d, &format!("tunnel-{t}-auth-failed")),
                    0,
                    "{label}"
                );
                assert!(refusals(r, d).is_empty(), "{label} {d}");
            }
            // Between the homes: ESP and signed STUN, never Geneve.
            let w = decode_wan(r);
            assert_eq!(w.geneve, 0, "{label}: no cleartext");
            assert!(w.esp > 20, "{label}: {w:?}");
            assert!(w.signed > 2, "{label}: {w:?}");
            let want = ["203.0.113.1:4500", "203.0.113.2:4500", "203.0.113.50:3478"];
            assert_eq!(
                w.endpoints.iter().map(String::as_str).collect::<Vec<_>>(),
                want
            );
            // The default keyed MTU (1438) is what the MSS clamp follows.
            assert!(r.counter("box-a", "tunnel-to-b-mss-clamped") >= 1);
            let a = &r.listings["box-a"];
            assert!(a.contains("udp 4500") && a.contains(" key "), "{a}");
            assert!(!a.contains(&KEY[..16]), "a listing never shows the key");
        },
    );
}

#[test]
fn a_wrong_key_or_a_keyless_end_never_comes_up_and_says_why() {
    for (keys, a_says, b_says) in [
        ([KEY, KEY2], "integrity", "integrity"),
        ([KEY, ""], "unsigned", "keyed-peer"),
    ] {
        let mut s = Setup::new(nat(EI, APD), nat(EI, APD));
        s.keys = Some(keys);
        each_seed(&s, |r, label| {
            let log = transcript(&r.journal);
            assert!(!r.fetched(), "{label}");
            for d in ["box-a", "box-b"] {
                assert_eq!(r.count(d, "tunnel-up"), 0, "{label} {d}\n{log}");
            }
            assert!(
                refusals(r, "box-a").contains(&a_says.to_owned()),
                "{label}\n{log}"
            );
            assert!(
                refusals(r, "box-b").contains(&b_says.to_owned()),
                "{label}\n{log}"
            );
            assert!(r.counter("box-b", "tunnel-to-a-auth-failed") > 0);
        });
    }
}

#[test]
fn symmetric_nats_fail_and_a_keyed_relay_carries_the_fetch() {
    let mut s = Setup::new(nat(APD, APD), nat(APD, APD)).keyed();
    s.fetch_at = "6s";
    s.end = 8 * S;
    s.relay = true;
    each_seed(&s, |r, label| {
        let log = transcript(&r.journal);
        assert!(r.fetched(), "{label}\n{log}");
        assert_eq!(r.count("box-a", "tunnel-failed"), 1, "{label}");
        for t in ["to-a", "to-b"] {
            assert!(r.counter("relay", &format!("tunnel-{t}-forwarded-out")) > 5);
            assert_eq!(value(line(&r.listings["relay"], t), "state"), "up");
            assert_eq!(r.counter("relay", &format!("tunnel-{t}-auth-failed")), 0);
        }
        let w = decode_wan(r);
        assert_eq!(w.geneve, 0, "{label}");
        assert!(w.esp > 20, "{label}: {w:?}");
    });
}

/// `frame` (Ethernet, IPv4, UDP) as the attacker sends it: from its own MAC, and from
/// `from` (address and port) if given, with the IPv4 header checksum recomputed and the UDP
/// checksum left out (0, allowed over IPv4).
fn forged(frame: &[u8], from: Option<([u8; 4], u16)>) -> Vec<u8> {
    let mut f = frame.to_vec();
    f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0x66, 0]);
    let ihl = usize::from(f[14] & 0x0f) * 4;
    if let Some((ip, port)) = from {
        f[26..30].copy_from_slice(&ip);
        f[14 + ihl..16 + ihl].copy_from_slice(&port.to_be_bytes());
    }
    f[14 + ihl + 6..14 + ihl + 8].copy_from_slice(&[0, 0]);
    f[24..26].copy_from_slice(&[0, 0]);
    let mut sum: u32 = f[14..14 + ihl]
        .chunks(2)
        .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    f[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    f
}

/// Where the UDP payload of an Ethernet/IPv4/UDP frame starts.
fn udp_start(f: &[u8]) -> usize {
    14 + usize::from(f[14] & 0x0f) * 4 + 8
}

/// A Binding request with `USERNAME` 7 and nothing else, in place of `check`'s payload.
fn unsigned_check(check: &[u8]) -> Vec<u8> {
    let start = udp_start(check);
    let mut f = check[..start].to_vec();
    let mut stun = check[start..start + 20].to_vec();
    stun[2..4].copy_from_slice(&8u16.to_be_bytes());
    stun.extend_from_slice(&[0, 6, 0, 1, b'7', 0, 0, 0]);
    f.extend_from_slice(&stun);
    let ip_len = (f.len() - 14) as u16;
    f[16..18].copy_from_slice(&ip_len.to_be_bytes());
    let udp_len = (8 + stun.len()) as u16;
    f[start - 4..start - 2].copy_from_slice(&udp_len.to_be_bytes());
    f
}

#[test]
fn an_attacker_cannot_inject_roam_or_bring_up_a_keyed_tunnel() {
    // Endpoint-independent NATs, so what the attacker sends from its own address reaches box
    // B. Node A fetches at 2 s and again at 4 s; at 3 s the attacker, on the Internet switch,
    // replays one of box A's ESP packets as it was and from its own address, replays one of A's
    // signed checks from its own address, sends a check without a key and one whose integrity
    // does not check (a captured check with one byte of its transaction id changed).
    let mut base = Setup::new(nat(EI, EI), nat(EI, EI)).keyed();
    base.urls = "http://[fd00:b::10]/big?n=20000,http://[fd00:b::10]/big?n=20000";
    base.interval = "2s";
    base.end = 6 * S;
    const EVIL: ([u8; 4], u16) = ([203, 0, 113, 66], 4500);
    for seed in [1, 2] {
        let label = format!("seed={seed}");
        let first = run(seed, &base);
        let from_a = |f: &&FrameRecord| {
            f.link == first.wan_links[0]
                && f.sent_at < 3 * S
                && f.bytes.len() > 42
                && f.bytes[12..14] == [0x08, 0x00]
                && f.bytes[23] == 17
                && f.bytes[26..30] == [203, 0, 113, 1]
                && f.bytes[30..34] == [203, 0, 113, 2]
        };
        let esp = first
            .frames
            .iter()
            .filter(from_a)
            .find(|f| f.bytes[udp_start(&f.bytes)] & 0x80 != 0)
            .expect("an ESP packet from A")
            .bytes
            .clone();
        let check = first
            .frames
            .iter()
            .filter(from_a)
            .find(|f| f.bytes[udp_start(&f.bytes)..][..2] == [0x00, 0x01])
            .expect("a check from A")
            .bytes
            .clone();
        let mut bad_integrity = forged(&check, Some(EVIL));
        let tx = udp_start(&bad_integrity) + 12;
        bad_integrity[tx] ^= 0xff;
        let mut s = base.clone();
        s.inject = vec![
            (3 * S, forged(&esp, None)),
            (3 * S + MS, forged(&esp, Some(EVIL))),
            (3 * S + 2 * MS, forged(&check, Some(EVIL))),
            (3 * S + 3 * MS, forged(&unsigned_check(&check), Some(EVIL))),
            (3 * S + 4 * MS, bad_integrity),
        ];
        let r = run(seed, &s);
        let log = transcript(&r.journal);
        let done = events(&r.journal, "node-a", "http-get-done");
        assert_eq!(done.len(), 2, "{label}: both fetches\n{log}");
        assert!(done.iter().all(|f| field(f, "status") == "200"));
        for d in ["box-a", "box-b"] {
            assert_eq!(r.count(d, "tunnel-up"), 1, "{label} {d}");
            assert_eq!(r.count(d, "tunnel-roamed"), 0, "{label} {d}\n{log}");
            assert_eq!(r.count(d, "tunnel-down"), 0, "{label} {d}");
        }
        let said = refusals(&r, "box-b");
        for reason in ["replayed", "unsigned", "integrity"] {
            assert!(
                said.contains(&reason.to_owned()),
                "{label}: {said:?}\n{log}"
            );
        }
        assert!(r.counter("box-b", "tunnel-to-a-replayed") >= 3, "{label}");
        let peer = value(line(&r.listings["box-b"], "to-a"), "peer");
        assert_eq!(peer, "203.0.113.1:4500", "{label}: the peer never moved");
        // Box B answered nothing to the attacker.
        let to_evil = r
            .frames
            .iter()
            .filter(|f| f.bytes.len() > 34 && f.bytes[12..14] == [0x08, 0x00])
            .filter(|f| f.bytes[30..34] == [203, 0, 113, 66])
            .count();
        assert_eq!(to_evil, 0, "{label}");
        r.same_as(&run(seed, &s), &label);
    }
}

/// The controllers of keyed boxes: as [`event_steps`] for `tunnel-up`, with the key in
/// `tunnel-add`, and a new key at 3 s. Box A's controller replaces its key on a timer; box B's
/// controller replaces it when its box first refuses a check under a key it does not have
/// (`tunnel-auth-failed`), which is how it learns that its peer moved on. Both set the new key
/// through `devices.control` (`tunnel-key`).
fn rekeying_steps(me: &str, other: &str) -> Vec<(String, String)> {
    let mut steps = keyed_signaling_steps(me, other, &format!(" key {KEY}"));
    if me == "a" {
        steps.push(format!("3s id=rekey control box-a tunnel-key to-b {KEY2}"));
    }
    let mut config = numbered(steps);
    config.push((
        "on.0".to_owned(),
        format!(
            "box-{me} tunnel-up tunnel=to-{other} : control box-{me} routes-replace \
             default via 192.168.1.1, fd00:{other}::/64 tunnel to-{other}"
        ),
    ));
    if me == "b" {
        config.push((
            "on.1".to_owned(),
            format!("box-b tunnel-auth-failed tunnel=to-a : control box-b tunnel-key to-a {KEY2}"),
        ));
    }
    config
}

#[test]
fn controllers_replace_a_live_tunnel_s_key_without_taking_it_down() {
    // Node A fetches every 500 ms from 2 s to 4.5 s, across the replacement at 3 s.
    let plan = Controlled {
        script: rekeying_steps,
        cut: None,
        fetch_at: "2s",
        repeat: Some(("500ms", "6")),
        end: 6 * S,
    };
    for seed in [1, 2] {
        let label = format!("seed={seed}");
        let r = controlled_run(seed, &plan);
        let log = transcript(&r.journal);
        let done = events(&r.journal, "node-a", "http-get-done");
        assert_eq!(done.len(), 6, "{label}\n{log}");
        assert!(done.iter().all(|f| field(f, "status") == "200"), "{label}");
        for d in ["box-a", "box-b"] {
            assert_eq!(r.count(d, "tunnel-up"), 1, "{label} {d}");
            assert_eq!(r.count(d, "tunnel-down"), 0, "{label} {d}\n{log}");
            assert_eq!(r.count(d, "tunnel-key-replaced"), 1, "{label} {d}\n{log}");
            assert_eq!(r.count(d, "tunnel-key-confirmed"), 1, "{label} {d}\n{log}");
            assert!(!r.listings[d].contains(&KEY2[..16]), "{d}");
        }
        // Box A changed its key at 3 s; box B refused A's first check under the new key, and
        // its controller replaced B's key in that same instant.
        assert_eq!(
            instants(&r, "box-a", "tunnel-key-replaced"),
            [3 * S],
            "{label}"
        );
        let refused = instants(&r, "box-b", "tunnel-auth-failed");
        assert_eq!(refused.len(), 1, "{label}\n{log}");
        assert_eq!(
            instants(&r, "box-b", "tunnel-key-replaced"),
            refused,
            "{label}"
        );
        assert_eq!(refusals(&r, "box-b"), ["integrity"], "{label}");
        let rule: Vec<_> = events(&r.journal, "ctl-b", "infra-script")
            .into_iter()
            .filter(|f| field(f, "step") == "on.1")
            .collect();
        assert_eq!(rule.len(), 1, "{label}");
        assert_eq!(field(&rule[0], "result"), "ok");
        decode_wan(&r);
        r.same_as(&controlled_run(seed, &plan), &label);
    }
}

#[test]
fn what_the_cryptography_costs() {
    // One 1 MB fetch through box B, keyless and keyed: its fuel, per tunnel packet, and the
    // most it used in one instant (a device's default budget is 50 M per instant).
    let mut plain = Setup::new(nat(EI, APD), nat(EI, APD));
    plain.urls = "http://[fd00:b::10]/big?n=1000000";
    plain.end = 6 * S;
    let keyed = plain.clone().keyed();
    let mut rows = Vec::new();
    let mut per = Vec::new();
    for (name, s) in [("keyless", &plain), ("keyed", &keyed)] {
        let r = run(1, s);
        let done = events(&r.journal, "node-a", "http-get-done");
        assert_eq!(field(&done[0], "body-bytes"), "1000000", "{name}");
        let c = &r.costs["box-b"];
        let packets = r.counter("box-b", "tunnel-to-a-tx-packets")
            + r.counter("box-b", "tunnel-to-a-rx-packets");
        let checks = r.counter("box-b", "tunnel-to-a-checks-sent")
            + r.counter("box-b", "tunnel-to-a-requests-received");
        per.push((c.fuel, packets));
        rows.push(format!(
            "{name}: box-b fuel {} for {packets} tunnel packets and {checks} checks; \
             peak {} in one instant",
            c.fuel, c.peak_fuel
        ));
        assert!(
            c.peak_fuel < 50_000_000,
            "{name}: within the default budget"
        );
    }
    let ((f0, p0), (f1, p1)) = (per[0], per[1]);
    rows.push(format!(
        "box-b fuel per tunnel packet: keyless {}, keyed {}",
        f0 / p0.max(1),
        f1 / p1.max(1)
    ));
    println!("{}", rows.join("\n"));
    assert!(f1 > f0, "encryption costs something");
}
