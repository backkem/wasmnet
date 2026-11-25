//! Tunnel ports, frame by frame through the whole router.
//!
//! Port 0 (10.0.1.1/24) faces the peer's endpoint, 10.0.1.20:6081 (host P); port 1 (10.0.2.1/24,
//! fd00:2::1/64) has host B (10.0.2.10). The tunnel `to-b` (id 7, transit fd00:ff::a/128)
//! carries fd00:b::/64 and 10.9.0.0/16.

use std::net::SocketAddr;

use proptest::prelude::*;

use super::*;
use crate::tunnel::{geneve, stun};

const P_MAC: u8 = 0x20;
const PEER: &str = "10.0.1.20";

/// Router-emitted frames only go to the two cabled ports.
fn cabled_only(tx: &[(u32, Vec<u8>)]) {
    assert!(tx.iter().all(|(p, _)| *p < 2), "a frame to a tunnel port");
}

/// A UDP datagram with its checksum, from `src:sport` (host `from`) to the router.
fn udp_in(from: u8, src: &str, sport: u16, dst: &str, dport: u16, payload: &[u8]) -> Vec<u8> {
    let d = wire::udp_v4(v4(src), v4(dst), sport, dport, payload);
    let p = wire::ipv4(v4(src), v4(dst), PROTO_UDP, 64, 9, &d);
    wire::eth_frame(RTR0, mac(from), ETHERTYPE_IPV4, &p)
}

/// The reference decoding of an outer frame: IPv4 (header checksum checked), UDP (checksum
/// checked), and the payload: `(src, dst, sport, dport, payload)`.
fn outer(frame: &[u8]) -> (Ipv4Addr, Ipv4Addr, u16, u16, Vec<u8>) {
    let ip = &frame[14..];
    let h = Ipv4HeaderSlice::from_slice(ip).unwrap();
    assert_eq!(h.protocol().0, PROTO_UDP);
    assert_eq!(wire::checksum(h.slice()), 0);
    let u = &ip[20..usize::from(h.total_len())];
    let len = usize::from(u16::from_be_bytes([u[4], u[5]]));
    assert_eq!(len, u.len());
    let ps = wire::pseudo_v4(h.source_addr(), h.destination_addr(), PROTO_UDP, len);
    assert_eq!(wire::finish(wire::sum16(u, ps)), 0, "UDP checksum");
    (
        h.source_addr(),
        h.destination_addr(),
        u16::from_be_bytes([u[0], u[1]]),
        u16::from_be_bytes([u[2], u[3]]),
        u[8..].to_vec(),
    )
}

/// A router with tunnel `to-b` up: P known by ARP, its check answered.
fn tunnel_up(extra: &[(&str, &str)]) -> (Router, Out) {
    let (mut r, mut out) = router(extra);
    r.receive(
        0,
        0,
        &arp_frame(1, P_MAC, PEER, MacAddr::ZERO, "10.0.1.1"),
        &mut out,
    );
    out.take();
    let cmd = |r: &mut Router, out: &mut Out, c: &str, a: &str| r.command(MS, c, a, out);
    assert_eq!(
        cmd(
            &mut r,
            &mut out,
            "tunnel-add",
            "to-b id 7 local fd00:ff::a/128 peer 10.0.1.20:6081"
        )
        .as_deref(),
        Ok("added")
    );
    assert_eq!(
        cmd(&mut r, &mut out, "route-add", "fd00:b::/64 tunnel to-b").as_deref(),
        Ok("added")
    );
    assert_eq!(
        cmd(&mut r, &mut out, "route-add", "10.9.0.0/16 tunnel to-b").as_deref(),
        Ok("added")
    );
    assert_eq!(r.poll(MS, &mut out), Some(MS + 100 * MS));
    let tx = out.take();
    cabled_only(&tx);
    assert_eq!(tx.len(), 1, "one check");
    let (src, dst, sport, dport, payload) = outer(&tx[0].1);
    assert_eq!(
        (src, dst, sport, dport),
        (v4("10.0.1.1"), v4(PEER), 6081, 6081)
    );
    let stun::Message::Request { txid, username } = stun::parse(&payload).unwrap() else {
        panic!("a Binding request")
    };
    assert_eq!(username.as_deref(), Some("7"));
    let answer = stun::success(&txid, SocketAddr::from(([10, 0, 1, 1], 6081)));
    r.receive(
        2 * MS,
        0,
        &udp_in(P_MAC, PEER, 6081, "10.0.1.1", 6081, &answer),
        &mut out,
    );
    assert_eq!(out.event("tunnel-up").get("peer"), Some("10.0.1.20:6081"));
    out.take();
    (r, out)
}

#[test]
fn packets_routed_to_a_tunnel_leave_in_geneve_and_come_back_out() {
    let (mut r, mut out) = tunnel_up(&[]);
    // IPv6 from B to fd00:b::10: one hop less, in Geneve, to the peer.
    let inner6 = wire::ipv6(
        v6("fd00:2::10"),
        v6("fd00:b::10"),
        PROTO_UDP,
        64,
        &udp(1, 2, b"six"),
    );
    r.receive(
        3 * MS,
        1,
        &wire::eth_frame(RTR1, mac(B_MAC), ETHERTYPE_IPV6, &inner6),
        &mut out,
    );
    let tx = out.take();
    cabled_only(&tx);
    let (src, dst, sport, dport, payload) = outer(&tx[0].1);
    assert_eq!(
        (src, dst, sport, dport),
        (v4("10.0.1.1"), v4(PEER), 6081, 6081)
    );
    assert_eq!(payload[..8], [0, 0, 0x86, 0xdd, 0, 0, 7, 0]);
    let mut want = inner6.clone();
    want[7] -= 1;
    assert_eq!(payload[8..], want[..]);
    // IPv4 from B to 10.9.1.1.
    r.receive(
        4 * MS,
        1,
        &frame_v4(
            B_MAC,
            RTR1,
            "10.0.2.10",
            "10.9.1.1",
            PROTO_UDP,
            64,
            false,
            &udp(1, 2, b"four"),
        ),
        &mut out,
    );
    let tx = out.take();
    let (.., payload) = outer(&tx[0].1);
    assert_eq!(payload[..8], [0, 0, 0x08, 0x00, 0, 0, 7, 0]);
    let inner4 = &payload[8..];
    assert_eq!(inner4[8], 63, "TTL decremented");
    assert_eq!(wire::checksum(&inner4[..20]), 0);
    assert_eq!(&inner4[12..20], &[10, 0, 2, 10, 10, 9, 1, 1]);

    // From the tunnel: IPv4 to B leaves port 1 with one hop less.
    r.receive(
        5 * MS,
        1,
        &arp_frame(1, B_MAC, "10.0.2.10", MacAddr::ZERO, "10.0.2.1"),
        &mut out,
    );
    out.take();
    let to_b = wire::ipv4(
        v4("10.9.1.1"),
        v4("10.0.2.10"),
        PROTO_UDP,
        64,
        3,
        &udp(2, 1, b"back"),
    );
    let d = geneve::encap(7, &to_b);
    r.receive(
        6 * MS,
        0,
        &udp_in(P_MAC, PEER, 6081, "10.0.1.1", 6081, &d),
        &mut out,
    );
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    assert_eq!(tx[0].0, 1);
    assert_eq!(ip4(&tx[0].1)[12..20], [10, 9, 1, 1, 10, 0, 2, 10]);
    assert_eq!(ttl_of(&tx[0].1), 63);
    // An echo request to the tunnel's transit address is answered back through the tunnel.
    let echo = wire::icmpv6(
        v6("fd00:b::10"),
        v6("fd00:ff::a"),
        128,
        0,
        [0, 1, 0, 1],
        b"hi",
    );
    let ping = wire::ipv6(v6("fd00:b::10"), v6("fd00:ff::a"), PROTO_ICMPV6, 64, &echo);
    r.receive(
        7 * MS,
        0,
        &udp_in(
            P_MAC,
            PEER,
            6081,
            "10.0.1.1",
            6081,
            &geneve::encap(7, &ping),
        ),
        &mut out,
    );
    let tx = out.take();
    let (.., payload) = outer(&tx[0].1);
    let reply = &payload[8..];
    assert_eq!(reply[40], 129, "an echo reply");
    assert_eq!(&reply[8..24], &v6("fd00:ff::a").octets());
    assert_eq!(counter(&r, "tunnel-to-b-rx-packets"), Some(2));
    assert_eq!(counter(&r, "tunnel-to-b-tx-packets"), Some(3));
    assert_eq!(counter(&r, "tunnel-to-b-up"), Some(1));
    // Packets for the wrong id are not this tunnel's.
    r.receive(
        8 * MS,
        0,
        &udp_in(
            P_MAC,
            PEER,
            6081,
            "10.0.1.1",
            6081,
            &geneve::encap(8, &to_b),
        ),
        &mut out,
    );
    assert!(out.take().is_empty());
    assert_eq!(counter(&r, "tunnel-unknown-id"), Some(1));
    // No cabled port counters for the tunnel.
    assert_eq!(counter(&r, "p2-rx-frames"), None);
}

#[test]
fn a_syn_into_the_tunnel_is_clamped_and_the_mtu_holds() {
    let (mut r, mut out) = tunnel_up(&[]);
    let mut seg = vec![
        0x30, 0x39, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x60, 0x02, 0xff, 0xff, 0, 0, 0, 0,
    ];
    seg.extend_from_slice(&[2, 4, 0x05, 0xa0]);
    let ps = wire::pseudo_v6(v6("fd00:2::10"), v6("fd00:b::10"), PROTO_TCP, seg.len());
    let c = wire::finish(wire::sum16(&seg, ps));
    seg[16..18].copy_from_slice(&c.to_be_bytes());
    let syn = wire::ipv6(v6("fd00:2::10"), v6("fd00:b::10"), PROTO_TCP, 64, &seg);
    r.receive(
        3 * MS,
        1,
        &wire::eth_frame(RTR1, mac(B_MAC), ETHERTYPE_IPV6, &syn),
        &mut out,
    );
    let tx = out.take();
    let (.., payload) = outer(&tx[0].1);
    let tcp = &payload[8 + 40..];
    assert_eq!(&tcp[20..24], &[2, 4, 0x05, 0x7c], "MSS 1464 - 60 = 1404");
    let ps = wire::pseudo_v6(v6("fd00:2::10"), v6("fd00:b::10"), PROTO_TCP, tcp.len());
    assert_eq!(wire::finish(wire::sum16(tcp, ps)), 0);
    assert_eq!(counter(&r, "tunnel-to-b-mss-clamped"), Some(1));
    // A packet above the tunnel MTU (1464) gets Packet Too Big, not a fragment.
    let big = wire::ipv6(
        v6("fd00:2::10"),
        v6("fd00:b::10"),
        PROTO_UDP,
        64,
        &udp(1, 2, &[0; 1460]),
    );
    r.receive(
        4 * MS,
        1,
        &wire::eth_frame(RTR1, mac(B_MAC), ETHERTYPE_IPV6, &big),
        &mut out,
    );
    assert_eq!(
        out.event("forward-drop").get("reason"),
        Some("packet-too-big")
    );
    assert_eq!(out.event("forward-drop").get("port"), Some("1"));
    cabled_only(&out.take());
}

#[test]
fn routes_name_tunnels_and_survive_the_removal_of_another() {
    let (mut r, mut out) = router(&[]);
    let mut cmd = |c: &str, a: &str| r.command(MS, c, a, &mut out);
    for (name, id) in [("a", 1), ("b", 2), ("c", 3)] {
        let spec = format!("{name} id {id} local fd00:ff::{id}/128");
        assert_eq!(cmd("tunnel-add", &spec).as_deref(), Ok("added"));
        assert_eq!(cmd("tunnel-add", &spec).as_deref(), Ok("unchanged"));
        let route = format!("fd00:{name}::/64 tunnel {name}");
        assert_eq!(cmd("route-add", &route).as_deref(), Ok("added"));
    }
    assert!(
        cmd("tunnel-add", "a id 9 local fd00:ff::1/128")
            .unwrap_err()
            .contains("other settings")
    );
    assert!(
        cmd("tunnel-add", "d id 2 local fd00:ff::4/128")
            .unwrap_err()
            .contains("id 2")
    );
    assert!(
        cmd("route-add", "fd00:e::/64 tunnel e")
            .unwrap_err()
            .contains("no tunnel `e`")
    );
    assert!(cmd("route-add", "fd00:e::/64 tunnel a port 0").is_err());
    assert!(
        cmd("route-remove", "fd00:ff::1/128")
            .unwrap_err()
            .contains("connected to tunnel a")
    );
    assert_eq!(cmd("tunnel-remove", "a").as_deref(), Ok("removed"));
    assert_eq!(cmd("tunnel-remove", "a").as_deref(), Ok("absent"));
    // A new tunnel takes the free port; b's and c's routes still name b and c.
    assert_eq!(
        cmd("tunnel-add", "d id 4 local fd00:ff::4/128").as_deref(),
        Ok("added")
    );
    let routes = cmd("routes", "").unwrap();
    assert!(!routes.contains("tunnel a"), "{routes}");
    for line in [
        "fd00:b::/64 tunnel b (static)",
        "fd00:c::/64 tunnel c (static)",
        "fd00:ff::4/128 tunnel d (connected)",
    ] {
        assert!(routes.lines().any(|l| l == line), "{line} in\n{routes}");
    }
    let kinds = out.kinds();
    assert!(kinds.contains(&"tunnel-removed") && kinds.contains(&"route-removed"));
    let removed = out.event("route-removed");
    assert_eq!(removed.get("port"), Some("a"));
    assert_eq!(out.event("tunnel-removed").get("routes"), Some("1"));
    // Routing still reaches b and c over their own ports.
    assert_eq!(port_for(&r, "fd00:b::1"), Some(3));
    assert_eq!(port_for(&r, "fd00:c::1"), Some(4));
    assert_eq!(port_for(&r, "fd00:ff::4"), Some(2));
    assert_eq!(port_for(&r, "fd00:a::1"), None);
    // The listing is by name.
    let listing = r.command(MS, "tunnels", "", &mut out).unwrap();
    let names: Vec<&str> = listing
        .lines()
        .map(|l| l.split(' ').next().unwrap())
        .collect();
    assert_eq!(names, ["b", "c", "d"]);
    assert!(listing.starts_with(
        "b id 2 udp 6081 local fd00:ff::2/128 state idle peer - reflexive - candidates -"
    ));
}

#[test]
fn tunnels_and_routes_from_the_config() {
    let (r, _) = router(&[
        ("tunnel.to-b.id", "7"),
        ("tunnel.to-b.local", "fd00:ff::a/128"),
        ("tunnel.to-b.peer", "10.0.1.20:6081"),
        ("tunnel.relay.id", "8"),
        ("tunnel.relay.local", "10.255.0.1/32"),
        ("routes", "fd00:b::/64 tunnel to-b,10.9.0.0/16 tunnel relay"),
        ("stun-server", "3478"),
    ]);
    // By name: `relay` is port 2, `to-b` port 3.
    assert_eq!(port_for(&r, "fd00:b::1"), Some(3));
    assert_eq!(port_for(&r, "10.9.0.1"), Some(2));
    assert_eq!(port_for(&r, "10.255.0.1"), Some(2));
    assert!(
        r.describe()
            .iter()
            .any(|l| l == "  route fd00:b::/64 tunnel to-b (static)")
    );
    for bad in [
        vec![("tunnel.to-b.id", "7")],
        vec![
            ("tunnel.To-b.id", "7"),
            ("tunnel.To-b.local", "fd00:ff::a/128"),
        ],
        vec![("routes", "fd00:b::/64 tunnel nope")],
        vec![
            ("tunnel.a.id", "7"),
            ("tunnel.a.local", "fd00:ff::a/128"),
            ("tunnel.b.id", "7"),
            ("tunnel.b.local", "fd00:ff::b/128"),
        ],
    ] {
        let mut pairs = vec![("port0.ipv4", "10.0.1.1/24")];
        pairs.extend(bad.clone());
        assert!(Config::from_pairs(pairs).is_err(), "{bad:?}");
    }
}

#[test]
fn routes_replace_names_tunnels_and_keeps_their_connected_routes() {
    let tunnels = [
        ("tunnel.to-b.id", "7"),
        ("tunnel.to-b.local", "fd00:ff::a/128"),
        ("tunnel.to-b.peer", "10.0.1.20:6081"),
        ("tunnel.relay.id", "8"),
        ("tunnel.relay.local", "10.255.0.1/32"),
    ];
    let (mut r, mut out) = router(&tunnels);
    let wanted = "fd00:b::/64 tunnel to-b\n10.9.0.0/16 tunnel relay\n10.0.3.0/24 via 10.0.2.2";
    assert_eq!(
        r.command(0, "routes-replace", wanted, &mut out).as_deref(),
        Ok("added 3, removed 0, kept 0")
    );
    assert_eq!(out.event("route-added").get("port"), Some("to-b"));
    assert_eq!(port_for(&r, "fd00:b::1"), Some(3));
    assert_eq!(port_for(&r, "10.9.0.1"), Some(2));
    // The same table as a router started with these routes; its answer reads back unchanged.
    let table = r.command(0, "routes", "", &mut out).unwrap();
    let mut started = tunnels.to_vec();
    let listed = wanted.replace('\n', ",");
    started.push(("routes", listed.as_str()));
    let (mut s, mut out2) = router(&started);
    assert_eq!(s.command(0, "routes", "", &mut out2).unwrap(), table);
    out.take();
    assert_eq!(
        r.command(0, "routes-replace", &table, &mut out).as_deref(),
        Ok("unchanged")
    );
    // A tunnel's transit prefix is connected: not the command's to set.
    let e = r
        .command(0, "routes-replace", "10.255.0.1/32 tunnel to-b", &mut out)
        .unwrap_err();
    assert!(e.contains("connected"), "{e}");
    // Clearing leaves the tunnels' connected routes.
    assert_eq!(
        r.command(0, "routes-replace", "", &mut out).as_deref(),
        Ok("added 0, removed 3, kept 0")
    );
    assert_eq!(port_for(&r, "10.255.0.1"), Some(2));
    assert_eq!(port_for(&r, "fd00:b::1"), None);
}

#[test]
fn binding_requests_are_answered_and_unknown_ids_are_not() {
    let (mut r, mut out) = router(&[("stun-server", "3478")]);
    r.receive(
        0,
        0,
        &arp_frame(1, P_MAC, PEER, MacAddr::ZERO, "10.0.1.1"),
        &mut out,
    );
    out.take();
    let tx_id = [9; 12];
    let req = stun::request(&tx_id, None);
    r.receive(
        MS,
        0,
        &udp_in(P_MAC, PEER, 40000, "10.0.1.1", 3478, &req),
        &mut out,
    );
    let tx = out.take();
    cabled_only(&tx);
    let (src, dst, sport, dport, payload) = outer(&tx[0].1);
    assert_eq!(
        (src, dst, sport, dport),
        (v4("10.0.1.1"), v4(PEER), 3478, 40000)
    );
    assert_eq!(
        stun::parse(&payload),
        Ok(stun::Message::Success {
            txid: tx_id,
            mapped: Some(SocketAddr::from(([10, 0, 1, 20], 40000)))
        })
    );
    // The answer leaves from the address asked, here port 1's, through port 0.
    r.receive(
        2 * MS,
        0,
        &udp_in(P_MAC, PEER, 40000, "10.0.2.1", 3478, &req),
        &mut out,
    );
    let (src, ..) = outer(&out.take()[0].1);
    assert_eq!(src, v4("10.0.2.1"));
    // A check for a tunnel this router does not have: no answer.
    r.receive(
        3 * MS,
        0,
        &udp_in(
            P_MAC,
            PEER,
            40000,
            "10.0.1.1",
            3478,
            &stun::request(&tx_id, Some("7")),
        ),
        &mut out,
    );
    assert!(out.take().is_empty());
    assert_eq!(counter(&r, "tunnel-unknown-id"), Some(1));
    assert_eq!(counter(&r, "stun-bindings-answered"), Some(2));
    // Other UDP to the router is still a port unreachable.
    r.receive(
        4 * MS,
        0,
        &udp_in(P_MAC, PEER, 40000, "10.0.1.1", 6081, b"x"),
        &mut out,
    );
    let tx = out.take();
    assert_eq!(ip4(&tx[0].1)[20], 3, "destination unreachable");
}

#[test]
fn a_router_without_tunnels_lists_no_tunnel_counters() {
    let (r, _) = router(&[]);
    assert!(
        r.counter_list()
            .iter()
            .all(|(k, _)| !k.starts_with("tunnel") && !k.starts_with("stun"))
    );
}

proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 512,
        rng_seed: proptest::test_runner::RngSeed::Fixed(6081),
        failure_persistence: None,
        ..proptest::test_runner::Config::default()
    })]

    /// Whatever arrives on a tunnel's UDP port, the router never panics and only sends valid
    /// frames to cabled ports.
    #[test]
    fn arbitrary_datagrams_on_the_tunnel_port_never_trap(
        payloads in proptest::collection::vec(
            prop_oneof![
                proptest::collection::vec(any::<u8>(), 0..80),
                // Geneve-looking, for id 7, with an arbitrary inner packet.
                proptest::collection::vec(any::<u8>(), 0..80).prop_map(|b| geneve::encap(7, &b)),
                // STUN-looking: a valid header and arbitrary attributes.
                proptest::collection::vec(any::<u8>(), 0..40).prop_map(|b| {
                    let mut m = stun::request(&[7; 12], Some("7"));
                    m.extend_from_slice(&b);
                    let len = (m.len() - 20) as u16;
                    m[2..4].copy_from_slice(&len.to_be_bytes());
                    m
                }),
            ],
            1..8,
        ),
        dport in prop_oneof![Just(6081u16), Just(3478)],
    ) {
        let (mut r, mut out) = tunnel_up(&[("stun-server", "3478")]);
        for (n, p) in payloads.iter().enumerate() {
            let now = 10 * MS + n as u64 * MS;
            r.receive(now, 0, &udp_in(P_MAC, PEER, 6081, "10.0.1.1", dport, p), &mut out);
            r.poll(now, &mut out);
        }
        cabled_only(&out.take());
    }
}

#[test]
fn on_a_translating_router_the_tunnel_port_comes_before_translation() {
    // Port 0 is the outside: the tunnel's datagrams reach the router itself, not the NAT table
    // (which has no mapping for them), and its own outer packets leave untranslated.
    let (mut r, mut out) = tunnel_up(&[("port0.nat", "masquerade")]);
    let inner = wire::ipv6(
        v6("fd00:2::10"),
        v6("fd00:b::10"),
        PROTO_UDP,
        64,
        &udp(1, 2, b"x"),
    );
    r.receive(
        3 * MS,
        1,
        &wire::eth_frame(RTR1, mac(B_MAC), ETHERTYPE_IPV6, &inner),
        &mut out,
    );
    let (src, _, sport, ..) = outer(&out.take()[0].1);
    assert_eq!((src, sport), (v4("10.0.1.1"), 6081));
    let echo = wire::icmpv6(
        v6("fd00:b::10"),
        v6("fd00:ff::a"),
        128,
        0,
        [0, 1, 0, 1],
        b"hi",
    );
    let ping = wire::ipv6(v6("fd00:b::10"), v6("fd00:ff::a"), PROTO_ICMPV6, 64, &echo);
    let d = geneve::encap(7, &ping);
    r.receive(
        4 * MS,
        0,
        &udp_in(P_MAC, PEER, 6081, "10.0.1.1", 6081, &d),
        &mut out,
    );
    assert_eq!(
        out.take().len(),
        1,
        "the echo reply, back through the tunnel"
    );
    assert_eq!(counter(&r, "nat-no-mapping"), Some(0));
    assert_eq!(counter(&r, "nat-mappings"), Some(0));
}

/// A TCP segment from `src:sport` to `dst:dport` with `flags`, as an IPv6 packet.
fn tcp6(src: &str, sport: u16, dst: &str, dport: u16, flags: u8) -> Vec<u8> {
    let ps = wire::pseudo_v6(v6(src), v6(dst), PROTO_TCP, 20);
    let seg = wire::tcp_segment(sport, dport, 1, 0, flags, ps);
    wire::ipv6(v6(src), v6(dst), PROTO_TCP, 64, &seg)
}

#[test]
fn allow_rules_name_a_tunnel_and_keep_state() {
    let (mut r, mut out) = tunnel_up(&[]);
    let cmd = |r: &mut Router, out: &mut Out, c: &str, a: &str| r.command(MS, c, a, out);
    assert_eq!(
        cmd(&mut r, &mut out, "allow-add", "to-b tcp dport 80").as_deref(),
        Ok("added")
    );
    assert_eq!(out.event("allow-added").get("port"), Some("to-b"));
    assert!(cmd(&mut r, &mut out, "allow-add", "nope tcp").is_err());
    assert_eq!(
        cmd(&mut r, &mut out, "rules", "").as_deref(),
        Ok("to-b tcp dport 80")
    );
    out.take();
    // B's host learnt by ARP, so what passes reaches it.
    let from_tunnel = |r: &mut Router, out: &mut Out, now: u64, p: &[u8]| {
        let d = geneve::encap(7, p);
        r.receive(
            now,
            0,
            &udp_in(P_MAC, PEER, 6081, "10.0.1.1", 6081, &d),
            out,
        );
        out.take()
    };
    // Inbound through the tunnel: TCP to port 80 passes, to port 22 does not.
    let ok = from_tunnel(
        &mut r,
        &mut out,
        3 * MS,
        &tcp6("fd00:b::10", 4000, "fd00:2::10", 80, 0x02),
    );
    assert!(!ok.is_empty(), "to port 80: B's neighbour is asked for");
    assert_eq!(counter(&r, "filter-dropped"), Some(0));
    let no = from_tunnel(
        &mut r,
        &mut out,
        4 * MS,
        &tcp6("fd00:b::10", 4001, "fd00:2::10", 22, 0x02),
    );
    assert!(no.is_empty());
    assert_eq!(counter(&r, "filter-dropped"), Some(1));
    // A flow B opened through the tunnel gets its answers back through it without a rule.
    let syn = tcp6("fd00:2::10", 5000, "fd00:b::10", 443, 0x02);
    r.receive(
        5 * MS,
        1,
        &wire::eth_frame(RTR1, mac(B_MAC), ETHERTYPE_IPV6, &syn),
        &mut out,
    );
    out.take();
    let back = from_tunnel(
        &mut r,
        &mut out,
        6 * MS,
        &tcp6("fd00:b::10", 443, "fd00:2::10", 5000, 0x12),
    );
    // It waits behind B's neighbour solicitation like the SYN to port 80: passed, not dropped.
    assert!(back.is_empty());
    assert_eq!(
        counter(&r, "filter-dropped"),
        Some(1),
        "the answer to a flow from inside passes"
    );
    assert_eq!(counter(&r, "filter-tracked"), Some(1));
    // Removing the tunnel takes its rules; a new tunnel in its place starts with none.
    assert_eq!(
        cmd(&mut r, &mut out, "tunnel-remove", "to-b").as_deref(),
        Ok("removed")
    );
    assert_eq!(cmd(&mut r, &mut out, "rules", "").as_deref(), Ok(""));
}

#[test]
fn allow_rules_for_a_tunnel_from_the_config() {
    let (mut r, mut out) = router(&[
        ("tunnel.to-b.id", "7"),
        ("tunnel.to-b.local", "fd00:ff::a/128"),
        ("tunnel.to-b.allow", "tcp dport 80,icmpv6"),
        ("port1.allow", "udp"),
    ]);
    assert_eq!(
        r.command(MS, "rules", "", &mut out).as_deref(),
        Ok("1 udp\nto-b tcp dport 80\nto-b icmpv6")
    );
    let mut bad = vec![
        ("port0.ipv4", "10.0.1.1/24"),
        ("tunnel.to-b.id", "7"),
        ("tunnel.to-b.local", "fd00:ff::a/128"),
    ];
    bad.push(("tunnel.to-b.allow", "tcp dport"));
    assert!(Config::from_pairs(bad).is_err());
}
