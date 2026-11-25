//! End to end: tunnel ports over an outer IPv6 path, with real composed nodes.
//!
//! ```text
//! node-a ── box-a ── fw-a ── isp ── fw-b ── box-b ── node-b
//!                             │
//!                           stun (a STUN server, 2001:db8:f2::50)
//! ```
//!
//! Every link outside the homes is IPv6 only: the boxes (2001:db8:a0::2, 2001:db8:b0::2) sit
//! behind their homes' routers (`fw-a`, `fw-b`), which route to `isp`; there is no translation.
//! With `firewall`, each home router's outside port lets in only ICMPv6 and the flows its home
//! started (a stateful packet filter), so the two boxes punch through as they do through NATs
//! that filter. Inside, each home is IPv6 (fd00:a::/64, fd00:b::/64) or IPv4 (10.1.0.0/24,
//! 10.2.0.0/24): all four combinations of inner and outer family are covered with this file and
//! `tests/tunnel.rs` (outer IPv4), keyless and keyed. `node-a` fetches from `node-b` over HTTP.
//!
//! Every network runs at two seeds, twice: the reruns are byte-identical. Needs `wac` and
//! `wasm-tools` on `PATH` (see `support`).

mod support;

use std::collections::BTreeMap;

use support::{built, config, events, field, transcript};
use wasmnet_host::{DeviceConfig, DeviceId, FrameRecord, JournalEntry, LinkId, Network, PortRef};

const US: u64 = 1_000;
const S: u64 = 1_000_000_000;
const MS: u64 = 1_000_000;

const KEY: &str = "3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b";

/// What a run varies.
#[derive(Clone, Copy, Debug)]
struct Setup {
    /// The homes' inner family.
    inner_v6: bool,
    keyed: bool,
    /// The home routers filter their outside ports (only ICMPv6 and their own flows come in).
    firewall: bool,
    /// Box A also has an IPv4 address, and its tunnel an IPv4 candidate it cannot reach.
    mixed: bool,
}

struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcaps: Vec<Vec<u8>>,
    /// The links between the homes and `isp`.
    outside: Vec<LinkId>,
    /// The links between each box and its node.
    inside: Vec<LinkId>,
    listings: BTreeMap<String, String>,
    counters: BTreeMap<String, BTreeMap<String, u64>>,
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

    fn fetched(&self) -> bool {
        let done = events(&self.journal, "node-a", "http-get-done");
        done.len() == 1
            && field(&done[0], "status") == "200"
            && field(&done[0], "body-bytes") == "20000"
    }
}

fn pairs(p: &[(&str, &str)]) -> DeviceConfig {
    config(p)
}

fn link(network: &mut Network, a: PortRef, b: PortRef) -> LinkId {
    network.link(a, b).unwrap().latency(100 * US).id()
}

fn command(network: &mut Network, d: DeviceId, c: &str, a: &str) -> String {
    match network.command(d, c, a).unwrap() {
        Some(Ok(s)) => s,
        other => panic!("{c} {a}: {other:?}"),
    }
}

fn run(seed: u64, s: Setup) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let router = b.load("router");
    let isp = network
        .device_with_config(
            "isp",
            &router,
            pairs(&[
                ("mac", "02:00:00:00:e0:00"),
                ("port0.ipv6", "2001:db8:f0::1/64"),
                ("port0.ipv6-link-local", "fe80::1"),
                ("port1.ipv6", "2001:db8:f1::1/64"),
                ("port1.ipv6-link-local", "fe80::1"),
                ("port2.ipv6", "2001:db8:f2::1/64"),
                ("port2.ipv6-link-local", "fe80::1"),
                (
                    "routes",
                    "2001:db8:a0::/64 via 2001:db8:f0::2, 2001:db8:b0::/64 via 2001:db8:f1::2",
                ),
            ]),
        )
        .unwrap();
    let stun = network
        .device_with_config(
            "stun",
            &router,
            pairs(&[
                ("mac", "02:00:00:00:e5:00"),
                ("port0.ipv6", "2001:db8:f2::50/64"),
                ("port0.ipv6-link-local", "fe80::50"),
                ("routes", "default via 2001:db8:f2::1"),
                ("stun-server", "3478"),
            ]),
        )
        .unwrap();
    link(&mut network, stun.port(0), isp.port(2));
    let mut boxes = Vec::new();
    let (mut outside, mut inside) = (Vec::new(), Vec::new());
    for (n, (me, other)) in [("a", "b"), ("b", "a")].into_iter().enumerate() {
        let home = format!("2001:db8:{me}0::");
        let mut fw = vec![
            ("mac".to_owned(), format!("02:00:00:00:f{n}:00")),
            ("port0.ipv6".to_owned(), format!("{home}1/64")),
            ("port0.ipv6-link-local".to_owned(), "fe80::1".to_owned()),
            ("port1.ipv6".to_owned(), format!("2001:db8:f{n}::2/64")),
            ("port1.ipv6-link-local".to_owned(), "fe80::2".to_owned()),
            ("routes".to_owned(), format!("default via 2001:db8:f{n}::1")),
        ];
        if s.firewall {
            fw.push(("port1.allow".to_owned(), "icmpv6".to_owned()));
        }
        let fw: Vec<(&str, &str)> = fw.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let fwd = network
            .device_with_config(&format!("fw-{me}"), &router, pairs(&fw))
            .unwrap();
        outside.push(link(&mut network, fwd.port(1), isp.port(n as u32)));
        let mut bx = vec![
            ("mac".to_owned(), format!("02:00:00:00:b{n}:00")),
            ("port0.ipv6".to_owned(), format!("{home}2/64")),
            ("port0.ipv6-link-local".to_owned(), "fe80::2".to_owned()),
            ("routes".to_owned(), format!("default via {home}1")),
        ];
        if s.inner_v6 {
            bx.push(("port1.ipv6".to_owned(), format!("fd00:{me}::1/64")));
            bx.push(("port1.ipv6-link-local".to_owned(), "fe80::1".to_owned()));
        } else {
            bx.push(("port1.ipv4".to_owned(), format!("10.{}.0.1/24", n + 1)));
        }
        if s.mixed && me == "a" {
            bx.push(("port0.ipv4".to_owned(), "192.0.2.2/24".to_owned()));
        }
        let bx: Vec<(&str, &str)> = bx.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let boxd = network
            .device_with_config(&format!("box-{me}"), &router, pairs(&bx))
            .unwrap();
        link(&mut network, boxd.port(0), fwd.port(0));
        let mac = format!("02:00:00:00:0{n}:10");
        let (addr, gw_key, gw) = if s.inner_v6 {
            (
                format!("fd00:{me}::10/64"),
                "ipv6-gateway",
                "fe80::1".to_owned(),
            )
        } else {
            (
                format!("10.{}.0.10/24", n + 1),
                "ipv4-gateway",
                format!("10.{}.0.1", n + 1),
            )
        };
        let family = if s.inner_v6 { "ipv6" } else { "ipv4" };
        let mut node = vec![
            ("mac", mac.as_str()),
            (family, addr.as_str()),
            (gw_key, gw.as_str()),
        ];
        let url = if s.inner_v6 {
            "http://[fd00:b::10]/big?n=20000"
        } else {
            "http://10.2.0.10/big?n=20000"
        };
        let noded = if me == "a" {
            node.push(("app.http-get.url", url));
            node.push(("app.http-get.start", "2s"));
            network
                .device_with_config("node-a", &b.load("node-http-get"), pairs(&node))
                .unwrap()
        } else {
            let listen = if s.inner_v6 { "[::]:80" } else { "0.0.0.0:80" };
            node.push(("app.http-server.listen", listen));
            network
                .device_with_config("node-b", &b.load("node-http-server"), pairs(&node))
                .unwrap()
        };
        inside.push(link(&mut network, noded.port(0), boxd.port(1)));
        boxes.push((boxd, me, other));
    }
    network.run_until(MS).unwrap();
    let port = if s.keyed { 4500 } else { 6081 };
    for (d, me, other) in boxes.clone() {
        let mut peers = format!("[2001:db8:{other}0::2]:{port}");
        if s.mixed && me == "a" {
            // An IPv4 candidate box A has no route to: probed in vain, counted.
            peers = format!("198.51.100.2:{port},{peers}");
        }
        let key = if s.keyed {
            format!(" key {KEY}")
        } else {
            String::new()
        };
        let spec = format!(
            "to-{other} id 7 local fd00:ff::{me}/128 peer {peers} \
             reflector [2001:db8:f2::50]:3478 keepalive 1s dead 3500ms{key}"
        );
        assert_eq!(command(&mut network, d, "tunnel-add", &spec), "added");
        let prefix = if s.inner_v6 {
            format!("fd00:{other}::/64")
        } else {
            format!("10.{}.0.0/24", if other == "a" { 1 } else { 2 })
        };
        assert_eq!(
            command(
                &mut network,
                d,
                "route-add",
                &format!("{prefix} tunnel to-{other}")
            ),
            "added"
        );
    }
    network
        .run_until(4 * S)
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    let mut listings = BTreeMap::new();
    let mut counters = BTreeMap::new();
    for (d, me, _) in &boxes {
        listings.insert(
            format!("box-{me}"),
            command(&mut network, *d, "tunnels", ""),
        );
    }
    for name in ["box-a", "box-b", "fw-a", "fw-b", "stun"] {
        let d = network.live_device(name).unwrap();
        let c = network.counters(d).unwrap().unwrap();
        counters.insert(name.to_owned(), c.into_iter().collect());
    }
    Run {
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        outside,
        inside,
        listings,
        counters,
    }
}

/// What crossed the outside links, decoded by this test's own reading of IPv6, UDP, STUN,
/// Geneve and ESP.
#[derive(Debug, Default)]
struct Outside {
    ndp: usize,
    stun: usize,
    geneve: usize,
    esp: usize,
    /// The inner protocol types Geneve carried.
    inner: std::collections::BTreeSet<u16>,
}

fn decode_outside(r: &Run) -> Outside {
    let mut o = Outside::default();
    for f in r.frames.iter().filter(|f| r.outside.contains(&f.link)) {
        let b = &f.bytes;
        assert_eq!(b[12..14], [0x86, 0xdd], "only IPv6 outside: {b:02x?}");
        let next = b[14 + 6];
        if next == 58 {
            o.ndp += 1;
            continue;
        }
        assert_eq!(next, 17, "UDP or ICMPv6 outside: {b:02x?}");
        let u = &b[14 + 40..];
        assert_ne!(u[6..8], [0, 0], "a UDP checksum");
        let d = &u[8..];
        if d.len() >= 20 && d[4..8] == [0x21, 0x12, 0xa4, 0x42] {
            o.stun += 1;
        } else if d[0] & 0x80 != 0 {
            o.esp += 1;
        } else {
            assert_eq!(d[0], 0, "Geneve version 0");
            o.inner.insert(u16::from_be_bytes([d[2], d[3]]));
            o.geneve += 1;
        }
    }
    o
}

/// The MSS of the first SYN-ACK... of the first SYN that reached node B, as the box let it in.
fn syn_mss(r: &Run, v6: bool) -> u16 {
    let link = r.inside[1];
    let (ip, proto_at) = if v6 { (40, 6) } else { (20, 9) };
    let f = r
        .frames
        .iter()
        .filter(|f| f.link == link)
        .find(|f| {
            let b = &f.bytes;
            let ethertype = if v6 { [0x86, 0xdd] } else { [0x08, 0x00] };
            b.len() > 14 + ip + 24
                && b[12..14] == ethertype
                && b[14 + proto_at] == 6
                && b[14 + ip + 13] == 0x02
        })
        .expect("a SYN to node B");
    let opts = &f.bytes[14 + ip + 20..];
    assert_eq!(opts[..2], [2, 4], "MSS first");
    u16::from_be_bytes([opts[2], opts[3]])
}

fn each_seed(s: Setup, mut check: impl FnMut(&Run, &str)) {
    for seed in [1, 2] {
        let label = format!("seed={seed} {s:?}");
        let r = run(seed, s);
        check(&r, &label);
        r.same_as(&run(seed, s), &label);
    }
}

#[test]
fn http_over_an_ipv6_outer_path_for_both_inner_families_keyless_and_keyed() {
    for keyed in [false, true] {
        for inner_v6 in [true, false] {
            let s = Setup {
                inner_v6,
                keyed,
                firewall: false,
                mixed: false,
            };
            each_seed(s, |r, label| {
                let log = transcript(&r.journal);
                assert!(r.fetched(), "{label}\n{log}");
                let port = if keyed { 4500 } else { 6081 };
                for (d, peer) in [("box-a", "b"), ("box-b", "a")] {
                    let up = events(&r.journal, d, "tunnel-up");
                    assert_eq!(up.len(), 1, "{label} {d}\n{log}");
                    assert_eq!(
                        field(&up[0], "peer"),
                        format!("[2001:db8:{peer}0::2]:{port}"),
                        "{label}"
                    );
                    // No translation: the reflexive endpoint is the box's own address.
                    let me = if d == "box-a" { "a" } else { "b" };
                    let refl = events(&r.journal, d, "tunnel-reflexive");
                    assert_eq!(
                        field(&refl[0], "endpoint"),
                        format!("[2001:db8:{me}0::2]:{port}"),
                        "{label}"
                    );
                }
                let o = decode_outside(r);
                assert!(o.stun > 2 && o.ndp > 0, "{label}: {o:?}");
                if keyed {
                    assert_eq!(o.geneve, 0, "{label}");
                    assert!(o.esp > 10, "{label}: {o:?}");
                } else {
                    assert_eq!(o.esp, 0, "{label}");
                    assert!(o.geneve > 10, "{label}: {o:?}");
                    let want = if inner_v6 { 0x86dd } else { 0x0800 };
                    assert_eq!(o.inner.iter().copied().collect::<Vec<_>>(), [want]);
                }
                // The clamp follows the MTU over outer IPv6: 1444 keyless, 1418 keyed, minus
                // the inner headers.
                let mtu = if keyed { 1418 } else { 1444 };
                let want = mtu - if inner_v6 { 60 } else { 40 };
                assert_eq!(syn_mss(r, inner_v6), want, "{label}");
                assert!(r.counter("box-b", "tunnel-to-a-mss-clamped") >= 1);
                assert_eq!(r.counter("stun", "stun-bindings-answered"), 2, "{label}");
            });
        }
    }
}

#[test]
fn two_stateful_firewalls_are_punched_through_over_ipv6() {
    for keyed in [false, true] {
        let s = Setup {
            inner_v6: true,
            keyed,
            firewall: true,
            mixed: false,
        };
        each_seed(s, |r, label| {
            let log = transcript(&r.journal);
            assert!(r.fetched(), "{label}\n{log}");
            // Each home router let the other box's datagrams in as part of a flow its own box
            // started; nothing else got through.
            for fw in ["fw-a", "fw-b"] {
                assert!(r.counter(fw, "filter-tracked") >= 1, "{label} {fw}");
            }
            decode_outside(r);
        });
    }
}

#[test]
fn a_tunnel_whose_candidates_mix_families_comes_up_over_the_one_that_works() {
    let s = Setup {
        inner_v6: true,
        keyed: false,
        firewall: false,
        mixed: true,
    };
    each_seed(s, |r, label| {
        let log = transcript(&r.journal);
        assert!(r.fetched(), "{label}\n{log}");
        let up = events(&r.journal, "box-a", "tunnel-up");
        assert_eq!(field(&up[0], "peer"), "[2001:db8:b0::2]:6081", "{label}");
        // The IPv4 candidate stays a candidate; its checks never left (no route).
        let a = &r.listings["box-a"];
        assert!(
            a.contains("candidates 198.51.100.2:6081,[2001:db8:b0::2]:6081"),
            "{label}: {a}"
        );
        assert!(
            r.counter("box-a", "tunnel-to-b-outer-drops") >= 1,
            "{label}"
        );
        // The MTU is IPv6's: the clamp says so.
        assert_eq!(syn_mss(r, true), 1444 - 60, "{label}");
    });
}
