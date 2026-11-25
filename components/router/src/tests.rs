//! Router behaviour, frame by frame: the frames a host would send in, the frames and events that
//! come out. Every frame the router emits is checked for valid lengths and checksums.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{Ethernet2HeaderSlice, Ipv4HeaderSlice, Ipv6HeaderSlice};
use wasmnet_wire::MacAddr;

use crate::wire::{
    self, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP,
    PROTO_UDP,
};
use crate::{Config, Event, Router, Sink};

const MS: u64 = 1_000_000;
const S: u64 = 1_000_000_000;

#[derive(Default)]
struct Out {
    tx: Vec<(u32, Vec<u8>)>,
    events: Vec<Event>,
}

impl Sink for Out {
    fn transmit(&mut self, port: u32, frame: Vec<u8>) {
        check(&frame);
        self.tx.push((port, frame));
    }

    fn event(&mut self, event: Event) {
        self.events.push(event);
    }
}

impl Out {
    fn kinds(&self) -> Vec<&str> {
        self.events.iter().map(|e| e.kind).collect()
    }

    fn event(&self, kind: &str) -> &Event {
        self.events
            .iter()
            .find(|e| e.kind == kind)
            .unwrap_or_else(|| panic!("no {kind} in {:?}", self.kinds()))
    }

    fn take(&mut self) -> Vec<(u32, Vec<u8>)> {
        self.events.clear();
        std::mem::take(&mut self.tx)
    }
}

/// Every emitted frame: at least 60 bytes, a valid IP header checksum and a valid ICMP / TCP
/// checksum.
fn check(frame: &[u8]) {
    assert!(frame.len() >= 60, "short frame");
    let eth = Ethernet2HeaderSlice::from_slice(frame).unwrap();
    let p = &frame[14..];
    match eth.ether_type().0 {
        ETHERTYPE_IPV4 => {
            let h = Ipv4HeaderSlice::from_slice(p).unwrap();
            assert_eq!(wire::checksum(h.slice()), 0, "IPv4 header checksum");
            let total = usize::from(h.total_len());
            let body = &p[h.slice().len()..total];
            match h.protocol().0 {
                PROTO_ICMP => assert_eq!(wire::checksum(body), 0, "ICMP checksum"),
                PROTO_TCP => {
                    let ps = wire::pseudo_v4(h.source_addr(), h.destination_addr(), 6, body.len());
                    assert_eq!(wire::finish(wire::sum16(body, ps)), 0, "TCP checksum");
                }
                _ => {}
            }
        }
        ETHERTYPE_IPV6 => {
            let h = Ipv6HeaderSlice::from_slice(p).unwrap();
            let body = &p[40..40 + usize::from(h.payload_length())];
            if matches!(h.next_header().0, PROTO_ICMPV6 | PROTO_TCP) {
                let ps = wire::pseudo_v6(
                    h.source_addr(),
                    h.destination_addr(),
                    h.next_header().0,
                    body.len(),
                );
                assert_eq!(
                    wire::finish(wire::sum16(body, ps)),
                    0,
                    "ICMPv6/TCP checksum"
                );
            }
        }
        ETHERTYPE_ARP => assert_eq!(&p[..6], &[0, 1, 8, 0, 6, 4]),
        t => panic!("unexpected ethertype {t:#06x}"),
    }
}

fn mac(n: u8) -> MacAddr {
    MacAddr([2, 0, 0, 0, 0, n])
}

const RTR0: MacAddr = MacAddr([2, 0, 0, 0, 1, 0]);
const RTR1: MacAddr = MacAddr([2, 0, 0, 0, 1, 1]);
/// A host on port 0 (10.0.1.10) and one on port 1 (10.0.2.10).
const A_MAC: u8 = 0x0a;
const B_MAC: u8 = 0x0b;

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn config(extra: &[(&str, &str)]) -> Config {
    let mut pairs = vec![
        ("port0.mac", "02:00:00:00:01:00"),
        ("port0.ipv4", "10.0.1.1/24"),
        ("port0.ipv6", "fd00:1::1/64"),
        ("port0.ipv6-link-local", "fe80::1"),
        ("port1.mac", "02:00:00:00:01:01"),
        ("port1.ipv4", "10.0.2.1/24"),
        ("port1.ipv6", "fd00:2::1/64"),
        ("port1.ipv6-link-local", "fe80::1"),
        ("port1.mtu", "1400"),
    ];
    pairs.extend_from_slice(extra);
    Config::from_pairs(pairs.iter().map(|(k, v)| (*k, *v))).unwrap()
}

fn router(extra: &[(&str, &str)]) -> (Router, Out) {
    let mut r = Router::new(config(extra));
    let mut out = Out::default();
    r.link_state(0, 0, true, &mut out);
    r.link_state(0, 1, true, &mut out);
    out.take();
    (r, out)
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]); // no checksum (IPv4 allows it)
    u.extend_from_slice(payload);
    u
}

/// An IPv4 frame from host `from` (MAC) to the router's port-0 MAC.
#[allow(clippy::too_many_arguments)]
fn frame_v4(
    from: u8,
    to_mac: MacAddr,
    src: &str,
    dst: &str,
    proto: u8,
    ttl: u8,
    df: bool,
    body: &[u8],
) -> Vec<u8> {
    let mut p = wire::ipv4(v4(src), v4(dst), proto, ttl, 7, body);
    if df {
        p[6] |= 0x40;
        p[10] = 0;
        p[11] = 0;
        let c = wire::checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
    }
    wire::eth_frame(to_mac, mac(from), ETHERTYPE_IPV4, &p)
}

fn frame_v6(
    from: u8,
    to_mac: MacAddr,
    src: &str,
    dst: &str,
    next: u8,
    hops: u8,
    body: &[u8],
) -> Vec<u8> {
    let p = wire::ipv6(v6(src), v6(dst), next, hops, body);
    wire::eth_frame(to_mac, mac(from), ETHERTYPE_IPV6, &p)
}

fn arp_frame(op: u16, from: u8, sender: &str, target_mac: MacAddr, target: &str) -> Vec<u8> {
    let dst = if op == 1 {
        MacAddr::BROADCAST
    } else {
        target_mac
    };
    let a = wire::arp(op, mac(from), v4(sender), target_mac, v4(target));
    wire::eth_frame(dst, mac(from), ETHERTYPE_ARP, &a)
}

fn ip4(frame: &[u8]) -> &[u8] {
    &frame[14..]
}

fn ttl_of(frame: &[u8]) -> u8 {
    frame[14 + 8]
}

fn dst_mac(frame: &[u8]) -> MacAddr {
    MacAddr::from_slice(&frame[..6]).unwrap()
}

/// Resolves host B behind port 1 by answering the router's ARP request.
fn learn_b(r: &mut Router, out: &mut Out, now: u64) {
    r.receive(
        now,
        1,
        &arp_frame(2, B_MAC, "10.0.2.10", RTR1, "10.0.2.1"),
        out,
    );
}

#[test]
fn answers_arp_for_its_port_address_and_learns_the_asker() {
    let (mut r, mut out) = router(&[]);
    r.receive(
        0,
        0,
        &arp_frame(1, A_MAC, "10.0.1.10", MacAddr::ZERO, "10.0.1.1"),
        &mut out,
    );
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    let (port, f) = &tx[0];
    assert_eq!(*port, 0);
    assert_eq!(dst_mac(f), mac(A_MAC));
    assert_eq!(&f[20..22], &[0, 2], "an ARP reply");
    assert_eq!(&f[22..28], &RTR0.octets());
    // The port-1 address is not answered on port 0 (no proxy ARP).
    r.receive(
        0,
        0,
        &arp_frame(1, A_MAC, "10.0.1.10", MacAddr::ZERO, "10.0.2.1"),
        &mut out,
    );
    assert!(out.take().is_empty());
    // The asker was learned: a reply to it needs no ARP.
    r.receive(
        MS,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.0.1.1",
            PROTO_ICMP,
            64,
            false,
            &wire::icmpv4(8, 0, [0, 1, 0, 1], b"ping"),
        ),
        &mut out,
    );
    let tx = out.take();
    assert_eq!(tx.len(), 1, "echo reply straight away");
    assert_eq!(dst_mac(&tx[0].1), mac(A_MAC));
    assert_eq!(r.counters.echo_replies, 1);
}

#[test]
fn forwards_after_arp_with_the_ttl_decremented() {
    let (mut r, mut out) = router(&[]);
    let f = frame_v4(
        A_MAC,
        RTR0,
        "10.0.1.10",
        "10.0.2.10",
        PROTO_UDP,
        64,
        true,
        &udp(49152, 7, b"hi"),
    );
    r.receive(0, 0, &f, &mut out);
    // Routed and decremented, then queued behind an ARP request on port 1 (broadcast, from the
    // port-1 address).
    assert_eq!(out.kinds(), vec!["route-lookup", "ttl-decrement"]);
    let lookup = out.event("route-lookup");
    assert_eq!(lookup.get("result"), Some("connected"));
    assert_eq!(lookup.get("prefix"), Some("10.0.2.0/24"));
    assert_eq!(lookup.get("port"), Some("1"));
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    assert_eq!((tx[0].0, dst_mac(&tx[0].1)), (1, MacAddr::BROADCAST));
    assert_eq!(&tx[0].1[28..32], &[10, 0, 2, 1]);
    assert_eq!(&tx[0].1[38..42], &[10, 0, 2, 10]);
    assert_eq!(r.poll(0, &mut out), Some(S), "a retry is scheduled");

    learn_b(&mut r, &mut out, 400_000);
    assert_eq!(out.kinds(), vec!["arp-resolved"]);
    let resolved = out.event("arp-resolved");
    assert_eq!(resolved.get("after-ns"), Some("400000"));
    assert_eq!(resolved.get("queued"), Some("1"));
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    let (port, fwd) = &tx[0];
    assert_eq!(*port, 1);
    assert_eq!(dst_mac(fwd), mac(B_MAC));
    assert_eq!(&fwd[6..12], &RTR1.octets(), "source MAC rewritten");
    assert_eq!(ttl_of(fwd), 63);
    assert_eq!(&ip4(fwd)[20..30], &ip4(&f)[20..30], "payload untouched");
    assert_eq!(r.poll(400_000, &mut out), None, "nothing pending");

    // The next packet goes straight out; the ttl-decrement event was reported once per flow.
    r.receive(MS, 0, &f, &mut out);
    assert_eq!(out.take().len(), 1);
    assert_eq!(r.counters.forwarded_v4, 2);
    assert_eq!(r.port_counters(0).unwrap().forwarded_in, 2);
    assert_eq!(r.port_counters(1).unwrap().forwarded_out, 2);
}

#[test]
fn ttl_decrement_is_traced_once_per_flow_by_default() {
    let (mut r, mut out) = router(&[]);
    learn_b(&mut r, &mut out, 0);
    r.receive(
        0,
        1,
        &arp_frame(1, B_MAC, "10.0.2.10", MacAddr::ZERO, "10.0.2.1"),
        &mut out,
    );
    out.take();
    let f = frame_v4(
        A_MAC,
        RTR0,
        "10.0.1.10",
        "10.0.2.10",
        PROTO_UDP,
        9,
        false,
        &udp(49152, 7, b"x"),
    );
    r.receive(0, 0, &f, &mut out);
    let e = out.event("ttl-decrement");
    assert_eq!(e.get("src"), Some("10.0.1.10:49152"));
    assert_eq!(e.get("dst"), Some("10.0.2.10:7"));
    assert_eq!((e.get("ttl-in"), e.get("ttl-out")), (Some("9"), Some("8")));
    assert_eq!(
        (e.get("from-port"), e.get("to-port")),
        (Some("0"), Some("1"))
    );
    out.take();
    r.receive(0, 0, &f, &mut out);
    assert!(out.events.is_empty(), "same flow: no second event");
    let (mut all, mut out) = router(&[
        ("trace.ttl-decrement", "all"),
        ("trace.route-lookup", "all"),
    ]);
    learn_b(&mut all, &mut out, 0);
    all.receive(
        0,
        1,
        &arp_frame(1, B_MAC, "10.0.2.10", MacAddr::ZERO, "10.0.2.1"),
        &mut out,
    );
    for _ in 0..2 {
        out.take();
        all.receive(0, 0, &f, &mut out);
        assert_eq!(out.kinds(), vec!["route-lookup", "ttl-decrement"]);
    }
}

#[test]
fn ttl_expiry_draws_time_exceeded_from_the_ingress_address() {
    let (mut r, mut out) = router(&[]);
    r.receive(
        0,
        0,
        &arp_frame(1, A_MAC, "10.0.1.10", MacAddr::ZERO, "10.0.1.1"),
        &mut out,
    );
    out.take();
    let probe = frame_v4(
        A_MAC,
        RTR0,
        "10.0.1.10",
        "10.0.3.10",
        PROTO_UDP,
        1,
        false,
        &udp(49152, 33434, &[0; 24]),
    );
    r.receive(MS, 0, &probe, &mut out);
    let e = out.event("icmp-error-sent").clone();
    assert_eq!(e.get("error"), Some("time-exceeded"));
    assert_eq!(e.get("from"), Some("10.0.1.1"));
    assert_eq!(e.get("to"), Some("10.0.1.10"));
    assert_eq!(e.get("about"), Some("10.0.3.10:33434"));
    assert_eq!(
        out.event("forward-drop").get("reason"),
        Some("ttl-exceeded")
    );
    // Expiry comes before the route lookup: the only lookup is the error's way back.
    let lookups: Vec<_> = out
        .events
        .iter()
        .filter(|e| e.kind == "route-lookup")
        .collect();
    assert_eq!(lookups.len(), 1);
    assert_eq!(lookups[0].get("dst"), Some("10.0.1.10"));
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    let icmp = &ip4(&tx[0].1)[20..];
    assert_eq!((icmp[0], icmp[1]), (11, 0));
    // The whole offending datagram is quoted, as received (TTL 1).
    let quoted = &icmp[8..];
    assert_eq!(quoted, &ip4(&probe)[..20 + 8 + 24]);
    assert_eq!(quoted[8], 1);
}

#[test]
fn no_route_is_net_unreachable_and_errors_about_errors_are_suppressed() {
    let (mut r, mut out) = router(&[]);
    r.receive(
        0,
        0,
        &arp_frame(1, A_MAC, "10.0.1.10", MacAddr::ZERO, "10.0.1.1"),
        &mut out,
    );
    out.take();
    let syn = wire::tcp_segment(
        49152,
        80,
        1000,
        0,
        wire::TCP_SYN,
        wire::pseudo_v4(v4("10.0.1.10"), v4("10.99.0.1"), 6, 20),
    );
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.99.0.1",
            PROTO_TCP,
            64,
            true,
            &syn,
        ),
        &mut out,
    );
    assert_eq!(out.event("route-lookup").get("result"), Some("no-route"));
    let e = out.event("icmp-error-sent");
    assert_eq!(
        (e.get("error"), e.get("icmp-type"), e.get("icmp-code")),
        (Some("net-unreachable"), Some("3"), Some("0"))
    );
    assert_eq!(e.get("about"), Some("10.99.0.1:80"));
    assert_eq!(e.get("proto"), Some("tcp"));
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    assert_eq!(&ip4(&tx[0].1)[20..22], &[3, 0]);
    // An ICMP error that cannot be routed draws no error about itself.
    let err = wire::icmpv4(3, 3, [0; 4], &[0x45; 28]);
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.99.0.1",
            PROTO_ICMP,
            64,
            false,
            &err,
        ),
        &mut out,
    );
    assert!(out.events.iter().all(|e| e.kind != "icmp-error-sent"));
    assert!(out.take().is_empty());
    assert_eq!(r.counters.icmp_errors_suppressed, 1);
    // Group destinations are never forwarded, and never answered.
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            MacAddr::BROADCAST,
            "10.0.1.10",
            "10.0.2.255",
            PROTO_UDP,
            64,
            false,
            &udp(1, 2, b""),
        ),
        &mut out,
    );
    assert!(out.take().is_empty());
    assert_eq!(r.counters.not_forwarded, 1);
}

#[test]
fn an_unresolvable_neighbor_draws_host_unreachable_after_three_tries() {
    let (mut r, mut out) = router(&[]);
    r.receive(
        0,
        1,
        &arp_frame(1, B_MAC, "10.0.2.10", MacAddr::ZERO, "10.0.2.1"),
        &mut out,
    );
    out.take();
    let f = |n: u16| {
        frame_v4(
            B_MAC,
            RTR1,
            "10.0.2.10",
            "10.0.1.99",
            PROTO_UDP,
            64,
            false,
            &udp(n, 80, b"syn"),
        )
    };
    r.receive(0, 1, &f(1), &mut out);
    r.receive(400 * MS, 1, &f(2), &mut out);
    let arps = |tx: &[(u32, Vec<u8>)]| tx.iter().filter(|(_, f)| f[12..14] == [8, 6]).count();
    assert_eq!(arps(&out.take()), 1, "one request, the second packet waits");
    let mut t = 0;
    let mut requests = 1;
    while let Some(next) = r.poll(t, &mut out) {
        t = next;
        requests += arps(&out.tx);
        if out.events.iter().any(|e| e.kind == "arp-failed") {
            break;
        }
        out.take();
    }
    assert_eq!(t, 3 * S, "requests at 0, 1 s and 2 s; given up at 3 s");
    assert_eq!(requests, 3);
    let failed = out.event("arp-failed");
    assert_eq!(
        (failed.get("attempts"), failed.get("dropped")),
        (Some("3"), Some("2"))
    );
    let unreachable: Vec<_> = out
        .events
        .iter()
        .filter(|e| e.kind == "icmp-error-sent")
        .collect();
    assert_eq!(
        unreachable.len(),
        2,
        "one host unreachable per queued packet"
    );
    assert_eq!(unreachable[0].get("error"), Some("host-unreachable"));
    assert_eq!(unreachable[0].get("from"), Some("10.0.2.1"));
    let drops: Vec<_> = out
        .events
        .iter()
        .filter(|e| e.kind == "forward-drop")
        .collect();
    assert_eq!(drops[0].get("reason"), Some("neighbor-unreachable"));
    let tx = out.take();
    assert_eq!(tx.len(), 2);
    assert!(
        tx.iter().all(|(p, f)| *p == 1
            && dst_mac(f) == mac(B_MAC)
            && ip4(f)[20] == 3
            && ip4(f)[21] == 1)
    );
    assert_eq!(r.poll(t, &mut out), None);
}

#[test]
fn local_traffic_ping_udp_tcp_and_other_protocols() {
    let (mut r, mut out) = router(&[]);
    r.receive(
        0,
        0,
        &arp_frame(1, A_MAC, "10.0.1.10", MacAddr::ZERO, "10.0.1.1"),
        &mut out,
    );
    out.take();
    // Ping the far port's address: answered from that address.
    let echo = wire::icmpv4(8, 0, [0x12, 0x34, 0, 1], b"abcdefgh");
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.0.2.1",
            PROTO_ICMP,
            64,
            false,
            &echo,
        ),
        &mut out,
    );
    let tx = out.take();
    let reply = ip4(&tx[0].1);
    assert_eq!(&reply[12..16], &[10, 0, 2, 1]);
    assert_eq!(reply[8], 64, "the router's own TTL");
    assert_eq!(&reply[20..22], &[0, 0]);
    assert_eq!(&reply[24..36], &echo[4..16]);
    // UDP: port unreachable.
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.0.1.1",
            PROTO_UDP,
            64,
            false,
            &udp(5000, 53, b"q"),
        ),
        &mut out,
    );
    assert_eq!(
        out.event("icmp-error-sent").get("error"),
        Some("port-unreachable")
    );
    assert_eq!(&ip4(&out.take()[0].1)[20..22], &[3, 3]);
    // TCP SYN: RST,ACK acknowledging the SYN.
    let syn = wire::tcp_segment(
        40000,
        22,
        7,
        0,
        wire::TCP_SYN,
        wire::pseudo_v4(v4("10.0.1.10"), v4("10.0.1.1"), 6, 20),
    );
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.0.1.1",
            PROTO_TCP,
            64,
            true,
            &syn,
        ),
        &mut out,
    );
    let tx = out.take();
    let rst = &ip4(&tx[0].1)[20..];
    assert_eq!(&rst[0..4], &[0, 22, 0x9c, 0x40]);
    assert_eq!(u32::from_be_bytes(rst[8..12].try_into().unwrap()), 8);
    assert_eq!(rst[13], wire::TCP_RST | wire::TCP_ACK);
    // GRE (47): protocol unreachable.
    r.receive(
        0,
        0,
        &frame_v4(A_MAC, RTR0, "10.0.1.10", "10.0.1.1", 47, 64, false, &[0; 8]),
        &mut out,
    );
    assert_eq!(
        out.event("icmp-error-sent").get("error"),
        Some("protocol-unreachable")
    );
    assert_eq!(r.counters.local_v4, 4);
}

#[test]
fn mtu_df_gets_frag_needed_and_non_df_is_dropped() {
    let (mut r, mut out) = router(&[]);
    r.receive(
        0,
        0,
        &arp_frame(1, A_MAC, "10.0.1.10", MacAddr::ZERO, "10.0.1.1"),
        &mut out,
    );
    out.take();
    let big = udp(1, 2, &[0; 1400]); // 1428 + 20 > port 1's MTU of 1400
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.0.2.10",
            PROTO_UDP,
            64,
            true,
            &big,
        ),
        &mut out,
    );
    assert_eq!(
        out.event("icmp-error-sent").get("error"),
        Some("frag-needed")
    );
    let tx = out.take();
    let icmp = &ip4(&tx[0].1)[20..];
    assert_eq!((icmp[0], icmp[1]), (3, 4));
    assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), 1400, "next-hop MTU");
    assert_eq!(ip4(&tx[0].1).len(), 576, "the quote is capped at 576 bytes");
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.0.2.10",
            PROTO_UDP,
            64,
            false,
            &big,
        ),
        &mut out,
    );
    assert_eq!(
        out.event("forward-drop").get("reason"),
        Some("fragmentation-unsupported")
    );
    assert!(out.take().is_empty());
}

#[test]
fn l2_filter_bad_checksums_and_down_ports() {
    let (mut r, mut out) = router(&[]);
    // Unknown unicast flooded by a switch: not for us.
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            mac(0x77),
            "10.0.1.10",
            "10.0.2.10",
            PROTO_UDP,
            64,
            false,
            &udp(1, 2, b""),
        ),
        &mut out,
    );
    assert_eq!(r.counters.l2_filtered, 1);
    let mut bad = frame_v4(
        A_MAC,
        RTR0,
        "10.0.1.10",
        "10.0.2.10",
        PROTO_UDP,
        64,
        false,
        &udp(1, 2, b""),
    );
    bad[14 + 10] ^= 0xff;
    r.receive(0, 0, &bad, &mut out);
    assert_eq!(r.counters.bad_checksum, 1);
    assert_eq!(
        out.event("forward-drop").get("reason"),
        Some("bad-checksum")
    );
    r.receive(0, 0, &[0u8; 10], &mut out);
    assert_eq!(r.counters.malformed, 1);
    assert!(out.take().is_empty());
    // A packet waiting for ARP on a port that goes down is dropped with it.
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.0.2.10",
            PROTO_UDP,
            64,
            false,
            &udp(1, 2, b""),
        ),
        &mut out,
    );
    r.link_state(MS, 1, false, &mut out);
    assert_eq!(out.event("port-down").get("port"), Some("1"));
    assert_eq!(r.counters.neighbor_drops, 1);
    assert_eq!(r.poll(MS, &mut out), None);
    out.take();
    // Now the route's port is down: net unreachable.
    r.receive(
        2 * MS,
        0,
        &arp_frame(1, A_MAC, "10.0.1.10", MacAddr::ZERO, "10.0.1.1"),
        &mut out,
    );
    out.take();
    r.receive(
        2 * MS,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.0.2.10",
            PROTO_UDP,
            64,
            false,
            &udp(1, 2, b""),
        ),
        &mut out,
    );
    assert_eq!(out.event("forward-drop").get("reason"), Some("port-down"));
    r.receive(
        2 * MS,
        1,
        &arp_frame(1, B_MAC, "10.0.2.10", MacAddr::ZERO, "10.0.2.1"),
        &mut out,
    );
    assert_eq!(r.counters.rx_port_down, 1);
}

#[test]
fn static_routes_use_the_gateway_as_next_hop() {
    let (mut r, mut out) = router(&[("routes", "10.0.3.0/24 via 10.0.2.2,default via 10.0.1.254")]);
    r.receive(
        0,
        0,
        &arp_frame(1, A_MAC, "10.0.1.10", MacAddr::ZERO, "10.0.1.1"),
        &mut out,
    );
    out.take();
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.0.3.10",
            PROTO_UDP,
            64,
            false,
            &udp(1, 2, b""),
        ),
        &mut out,
    );
    let e = out.event("route-lookup");
    assert_eq!(
        (e.get("result"), e.get("via"), e.get("prefix")),
        (Some("static"), Some("10.0.2.2"), Some("10.0.3.0/24"))
    );
    let tx = out.take();
    assert_eq!(
        &tx[0].1[38..42],
        &[10, 0, 2, 2],
        "ARP for the gateway, not the destination"
    );
    r.receive(
        0,
        0,
        &frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "192.0.2.1",
            PROTO_UDP,
            64,
            false,
            &udp(1, 2, b""),
        ),
        &mut out,
    );
    assert_eq!(out.event("route-lookup").get("prefix"), Some("0.0.0.0/0"));
    assert_eq!(r.routes().len(), 6, "4 connected + 2 static");
}

// ---- IPv6 ---------------------------------------------------------------------------------

fn ns_frame(from: u8, src: &str, target: &str) -> Vec<u8> {
    let (src, target) = (v6(src), v6(target));
    let group = wire::solicited_node(target);
    let mut body = target.octets().to_vec();
    body.extend_from_slice(&wire::ll_option(1, mac(from)));
    let icmp = wire::icmpv6(src, group, 135, 0, [0; 4], &body);
    wire::eth_frame(
        wire::multicast_mac(group),
        mac(from),
        ETHERTYPE_IPV6,
        &wire::ipv6(src, group, 58, 255, &icmp),
    )
}

fn na_frame(from: u8, to: MacAddr, target: &str, dst: &str) -> Vec<u8> {
    let (target, dst) = (v6(target), v6(dst));
    let mut body = target.octets().to_vec();
    body.extend_from_slice(&wire::ll_option(2, mac(from)));
    let icmp = wire::icmpv6(target, dst, 136, 0, [0x60, 0, 0, 0], &body);
    wire::eth_frame(
        to,
        mac(from),
        ETHERTYPE_IPV6,
        &wire::ipv6(target, dst, 58, 255, &icmp),
    )
}

#[test]
fn ndp_answers_solicitations_and_learns_the_solicitor() {
    let (mut r, mut out) = router(&[]);
    r.receive(0, 0, &ns_frame(A_MAC, "fe80::a", "fe80::1"), &mut out);
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    let na = &tx[0].1;
    assert_eq!(dst_mac(na), mac(A_MAC));
    let ip = &na[14..];
    assert_eq!(ip[7], 255, "NDP hop limit");
    assert_eq!(&ip[24..40], &v6("fe80::a").octets());
    let icmp = &ip[40..];
    assert_eq!(
        (icmp[0], icmp[4]),
        (136, 0xe0),
        "NA with router, solicited, override"
    );
    assert_eq!(&icmp[8..24], &v6("fe80::1").octets());
    assert_eq!(wire::find_ll_option(&icmp[24..], 2), Some(RTR0));
    // Not ours: silence. Not for this port's groups: filtered at L2.
    r.receive(0, 0, &ns_frame(A_MAC, "fe80::a", "fd00:1::99"), &mut out);
    assert!(out.take().is_empty());
    assert_eq!(r.counters.l2_filtered, 1);
    // The solicitor was learned: ping6 is answered at once, from the global address.
    let echo = wire::icmpv6(v6("fe80::a"), v6("fe80::1"), 128, 0, [0, 1, 0, 1], b"x");
    r.receive(
        0,
        0,
        &frame_v6(A_MAC, RTR0, "fe80::a", "fe80::1", 58, 64, &echo),
        &mut out,
    );
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    assert_eq!(tx[0].1[14 + 40], 129);
}

#[test]
fn forwards_ipv6_after_ndp_and_reports_errors() {
    let (mut r, mut out) = router(&[]);
    r.receive(0, 0, &ns_frame(A_MAC, "fd00:1::a", "fe80::1"), &mut out);
    out.take();
    let body = udp(49152, 33434, &[0; 8]);
    let f = frame_v6(A_MAC, RTR0, "fd00:1::a", "fd00:2::b", PROTO_UDP, 64, &body);
    r.receive(0, 0, &f, &mut out);
    let tx = out.take();
    assert_eq!(tx.len(), 1, "a Neighbor Solicitation");
    let ns = &tx[0].1;
    assert_eq!(dst_mac(ns).to_string(), "33:33:ff:00:00:0b");
    assert_eq!(
        &ns[14 + 8..14 + 24],
        &v6("fe80::1").octets(),
        "from the port's link-local address"
    );
    r.receive(
        300_000,
        1,
        &na_frame(B_MAC, RTR1, "fd00:2::b", "fe80::1"),
        &mut out,
    );
    assert_eq!(out.event("ndp-resolved").get("after-ns"), Some("300000"));
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    assert_eq!(tx[0].1[14 + 7], 63, "hop limit decremented");
    assert_eq!(dst_mac(&tx[0].1), mac(B_MAC));

    // Hop limit 1: time exceeded from the ingress port's global address.
    r.receive(
        MS,
        0,
        &frame_v6(A_MAC, RTR0, "fd00:1::a", "fd00:2::b", PROTO_UDP, 1, &body),
        &mut out,
    );
    let e = out.event("icmp-error-sent");
    assert_eq!(
        (e.get("error"), e.get("from")),
        (Some("time-exceeded"), Some("fd00:1::1"))
    );
    let tx = out.take();
    assert_eq!(&tx[0].1[14 + 40..14 + 42], &[3, 0]);
    // No route: destination unreachable code 0.
    r.receive(
        MS,
        0,
        &frame_v6(A_MAC, RTR0, "fd00:1::a", "fd00:99::1", PROTO_UDP, 64, &body),
        &mut out,
    );
    assert_eq!(
        out.event("icmp-error-sent").get("error"),
        Some("net-unreachable")
    );
    out.take();
    // Too big for port 1 (MTU 1400): packet too big with the MTU.
    let big = udp(1, 2, &[0; 1400]);
    r.receive(
        MS,
        0,
        &frame_v6(A_MAC, RTR0, "fd00:1::a", "fd00:2::b", PROTO_UDP, 64, &big),
        &mut out,
    );
    assert_eq!(
        out.event("icmp-error-sent").get("error"),
        Some("packet-too-big")
    );
    let tx = out.take();
    let icmp = &tx[0].1[14 + 40..];
    assert_eq!(icmp[0], 2);
    assert_eq!(u32::from_be_bytes(icmp[4..8].try_into().unwrap()), 1400);
    assert_eq!(
        tx[0].1.len() - 14,
        1280,
        "the quote is capped at the minimum MTU"
    );
    // A link-local source must not be forwarded.
    r.receive(
        MS,
        0,
        &frame_v6(A_MAC, RTR0, "fe80::a", "fd00:2::b", PROTO_UDP, 64, &body),
        &mut out,
    );
    assert_eq!(
        out.event("icmp-error-sent").get("error"),
        Some("beyond-scope")
    );
    assert_eq!(out.take()[0].1[14 + 8..14 + 24], v6("fe80::1").octets());
    // A ping to the other port's global address.
    let echo = wire::icmpv6(
        v6("fd00:1::a"),
        v6("fd00:2::1"),
        128,
        0,
        [0, 9, 0, 1],
        b"abc",
    );
    r.receive(
        MS,
        0,
        &frame_v6(A_MAC, RTR0, "fd00:1::a", "fd00:2::1", 58, 64, &echo),
        &mut out,
    );
    let tx = out.take();
    assert_eq!(&tx[0].1[14 + 8..14 + 24], &v6("fd00:2::1").octets());
    assert_eq!(tx[0].1[14 + 40], 129);
    assert_eq!(r.counters.forwarded_v6, 1);
}

#[test]
fn ipv6_neighbor_failure_is_address_unreachable() {
    let (mut r, mut out) = router(&[("neighbor.attempts", "2"), ("neighbor.retry", "500ms")]);
    r.receive(0, 0, &ns_frame(A_MAC, "fd00:1::a", "fe80::1"), &mut out);
    out.take();
    r.receive(
        0,
        0,
        &frame_v6(
            A_MAC,
            RTR0,
            "fd00:1::a",
            "fd00:2::99",
            PROTO_TCP,
            64,
            &[0; 20],
        ),
        &mut out,
    );
    assert_eq!(r.poll(0, &mut out), Some(500 * MS));
    assert_eq!(r.poll(500 * MS, &mut out), Some(S));
    out.take();
    assert_eq!(r.poll(S, &mut out), None);
    assert_eq!(out.event("ndp-failed").get("attempts"), Some("2"));
    assert_eq!(
        out.event("icmp-error-sent").get("error"),
        Some("host-unreachable")
    );
    let tx = out.take();
    assert_eq!(&tx[0].1[14 + 40..14 + 42], &[1, 3]);
}

#[test]
fn router_advertisements_only_when_enabled() {
    let (_, out) = router(&[]);
    assert!(out.tx.is_empty());
    let mut r = Router::new(config(&[("port0.ra", "true")]));
    let mut out = Out::default();
    r.link_state(0, 0, true, &mut out);
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    let ra = &tx[0].1;
    assert_eq!(dst_mac(ra).to_string(), "33:33:00:00:00:01");
    let icmp = &ra[14 + 40..];
    assert_eq!(icmp[0], 134);
    assert_eq!(
        u16::from_be_bytes([icmp[6], icmp[7]]),
        1800,
        "router lifetime"
    );
    // Answer a Router Solicitation (hop limit 255) with another one.
    let rs = wire::icmpv6(v6("fe80::a"), v6("ff02::2"), 133, 0, [0; 4], &[]);
    let f = wire::eth_frame(
        MacAddr([0x33, 0x33, 0, 0, 0, 2]),
        mac(A_MAC),
        ETHERTYPE_IPV6,
        &wire::ipv6(v6("fe80::a"), v6("ff02::2"), 58, 255, &rs),
    );
    r.receive(MS, 0, &f, &mut out);
    assert_eq!(out.take().len(), 1);
    assert_eq!(r.counters.ra_sent, 2);
}

#[test]
fn counters_are_listed_per_port() {
    let (r, _) = router(&[]);
    let list = r.counter_list();
    let names: Vec<&str> = list.iter().map(|(k, _)| k.as_str()).collect();
    assert!(names.contains(&"forwarded-v4") && names.contains(&"p1-tx-frames"));
    assert_eq!(list.iter().find(|(k, _)| k == "routes").unwrap().1, 4);
    assert!(
        !names.contains(&"routes-added"),
        "listed only once a command changed the table"
    );
    let _ = IpAddr::V4(v4("10.0.0.1"));
}

// ---- commands ----

fn counter(r: &Router, name: &str) -> Option<u64> {
    r.counter_list()
        .into_iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
}

fn port_for(r: &Router, ip: &str) -> Option<u32> {
    r.routes()
        .lookup(ip.parse().unwrap())
        .map(|route| route.port)
}

#[test]
fn commands_change_static_routes_and_are_idempotent() {
    let (mut r, mut out) = router(&[]);
    let cmd = |r: &mut Router, out: &mut Out, c: &str, a: &str| r.command(MS, c, a, out);

    assert_eq!(
        cmd(&mut r, &mut out, "route-add", "10.0.3.0/24 via 10.0.2.2").as_deref(),
        Ok("added")
    );
    let e = out.event("route-added");
    assert_eq!(
        (e.get("prefix"), e.get("via"), e.get("port")),
        (Some("10.0.3.0/24"), Some("10.0.2.2"), Some("1"))
    );
    assert_eq!(port_for(&r, "10.0.3.9"), Some(1));
    out.take();
    // The same route again changes nothing; another route for the prefix needs a replace.
    assert_eq!(
        cmd(&mut r, &mut out, "route-add", " 10.0.3.0/24  via 10.0.2.2 ").as_deref(),
        Ok("unchanged")
    );
    let taken = cmd(&mut r, &mut out, "route-add", "10.0.3.0/24 via 10.0.1.9").unwrap_err();
    assert!(taken.contains("route-replace"), "{taken}");
    assert!(out.events.is_empty(), "no event for a no-op or a refusal");
    assert_eq!(
        cmd(
            &mut r,
            &mut out,
            "route-replace",
            "10.0.3.0/24 via 10.0.1.9"
        )
        .as_deref(),
        Ok("replaced")
    );
    assert_eq!(out.kinds(), ["route-removed", "route-added"]);
    assert_eq!(out.events[0].get("via"), Some("10.0.2.2"));
    assert_eq!(out.events[1].get("port"), Some("0"));
    assert_eq!(port_for(&r, "10.0.3.9"), Some(0));
    assert_eq!(
        cmd(
            &mut r,
            &mut out,
            "route-replace",
            "10.0.3.0/24 via 10.0.1.9"
        )
        .as_deref(),
        Ok("unchanged")
    );
    assert_eq!(
        cmd(&mut r, &mut out, "route-replace", "default via fd00:2::fe").as_deref(),
        Ok("added")
    );
    assert_eq!(port_for(&r, "2001:db8::1"), Some(1));
    out.take();

    // Connected routes are not the commands' to change.
    for (c, a) in [
        ("route-add", "10.0.1.0/24 via 10.0.2.2"),
        ("route-replace", "fd00:2::/64 port 0"),
        ("route-remove", "10.0.2.0/24"),
    ] {
        let e = cmd(&mut r, &mut out, c, a).unwrap_err();
        assert!(e.contains("connected"), "{c} {a}: {e}");
    }
    // A removal by prefix, or of exactly this route; nothing to remove is fine.
    let other = cmd(&mut r, &mut out, "route-remove", "10.0.3.0/24 via 10.0.2.2").unwrap_err();
    assert!(other.contains("not"), "{other}");
    assert_eq!(
        cmd(
            &mut r,
            &mut out,
            "route-remove",
            "10.0.3.0/24 via 10.0.1.9 port 0"
        )
        .as_deref(),
        Ok("removed")
    );
    assert_eq!(out.kinds(), ["route-removed"]);
    assert_eq!(
        cmd(&mut r, &mut out, "route-remove", "10.0.3.0/24").as_deref(),
        Ok("absent")
    );
    assert_eq!(
        cmd(&mut r, &mut out, "route-remove", "::/0").as_deref(),
        Ok("removed")
    );
    assert_eq!(port_for(&r, "10.0.3.9"), None);
    out.take();

    // Malformed commands are refused, never trapped on.
    for (c, a) in [
        ("route-add", ""),
        ("route-add", "10.0.3.1/24 via 10.0.2.2"),
        ("route-add", "10.0.3.0/24 via 10.0.9.2"),
        ("route-add", "10.0.3.0/24 port 7"),
        ("route-add", "default"),
        ("route-remove", ""),
        ("route-remove", "default"),
        ("route-remove", "10.0.3.1/24"),
        ("route-remove", "somewhere"),
        ("routes", "all"),
        ("route-flush", ""),
    ] {
        assert!(cmd(&mut r, &mut out, c, a).is_err(), "{c} {a:?}");
    }
    assert!(out.events.is_empty() && out.tx.is_empty());

    // The table, and the counters of the changes.
    let table = cmd(&mut r, &mut out, "routes", "").unwrap();
    assert_eq!(
        table.lines().collect::<Vec<_>>(),
        [
            "10.0.1.0/24 port 0 (connected)",
            "fd00:1::/64 port 0 (connected)",
            "10.0.2.0/24 port 1 (connected)",
            "fd00:2::/64 port 1 (connected)",
        ]
    );
    assert_eq!(counter(&r, "routes"), Some(4));
    assert_eq!(counter(&r, "routes-added"), Some(3));
    assert_eq!(counter(&r, "routes-removed"), Some(3));
}

#[test]
fn a_route_change_keeps_queued_packets_and_known_neighbors() {
    const C_MAC: u8 = 0x0c;
    const D_MAC: u8 = 0x0d;
    let (mut r, mut out) = router(&[("routes", "10.0.3.0/24 via 10.0.2.2")]);
    // 10.0.2.3 asks for the router, so the router knows it.
    r.receive(
        0,
        1,
        &arp_frame(1, C_MAC, "10.0.2.3", MacAddr::ZERO, "10.0.2.1"),
        &mut out,
    );
    out.take();
    let packet = frame_v4(
        A_MAC,
        RTR0,
        "10.0.1.10",
        "10.0.3.10",
        PROTO_UDP,
        64,
        false,
        &udp(1, 2, b"x"),
    );
    // Routed to 10.0.2.2, which is not known yet: queued behind an ARP request.
    r.receive(MS, 0, &packet, &mut out);
    assert_eq!(out.event("route-lookup").get("via"), Some("10.0.2.2"));
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    assert_eq!(dst_mac(&tx[0].1), MacAddr::BROADCAST);
    assert_eq!(&tx[0].1[38..42], &[10, 0, 2, 2]);

    // The route moves to the known 10.0.2.3: nothing is sent for the change itself.
    assert_eq!(
        r.command(
            2 * MS,
            "route-replace",
            "10.0.3.0/24 via 10.0.2.3",
            &mut out
        )
        .as_deref(),
        Ok("replaced")
    );
    assert!(out.take().is_empty());
    // The next packet goes straight to it, without an ARP request, and its lookup is traced
    // again with the new route.
    r.receive(3 * MS, 0, &packet, &mut out);
    assert_eq!(out.event("route-lookup").get("via"), Some("10.0.2.3"));
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    assert_eq!((tx[0].0, dst_mac(&tx[0].1)), (1, mac(C_MAC)));
    assert_eq!(r.counters.arp_requests, 1, "only the one for 10.0.2.2");
    // The packet queued for 10.0.2.2 still waits for it, and leaves when it answers.
    r.receive(
        4 * MS,
        1,
        &arp_frame(2, D_MAC, "10.0.2.2", RTR1, "10.0.2.1"),
        &mut out,
    );
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    assert_eq!(dst_mac(&tx[0].1), mac(D_MAC));
    assert_eq!(counter(&r, "neighbor-drops"), Some(0));
}

// ---- DHCP relay agent ----

use wasmnet_wire::dhcp;

/// A DHCP message from client `B_MAC` (or a server reply), as a UDP payload.
fn dhcp_msg(op: u8, kind: dhcp::MessageType, giaddr: &str, yiaddr: &str, flags: u16) -> Vec<u8> {
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac(B_MAC).octets());
    let mut m = dhcp::Message {
        op,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: 0xabcd_0001,
        secs: 0,
        flags,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: v4(yiaddr),
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: v4(giaddr),
        chaddr,
        options: Vec::new(),
    };
    m.set_option(dhcp::opt::MESSAGE_TYPE, &[kind.to_u8()]);
    m.encode()
}

fn udp_of(frame: &[u8]) -> (u16, u16, &[u8]) {
    let ip = ip4(frame);
    let u = &ip[20..];
    (
        u16::from_be_bytes([u[0], u[1]]),
        u16::from_be_bytes([u[2], u[3]]),
        &u[8..],
    )
}

#[test]
fn relays_dhcp_between_a_client_port_and_a_server() {
    let (mut r, mut out) = router(&[("port1.dhcp-relay", "10.0.1.2")]);
    assert!(
        r.counter_list()
            .iter()
            .any(|(k, _)| k == "dhcp-relayed-to-server")
    );
    // A DISCOVER broadcast from 0.0.0.0 on port 1.
    let discover = dhcp_msg(1, dhcp::MessageType::Discover, "0.0.0.0", "0.0.0.0", 0);
    let f = frame_v4(
        B_MAC,
        MacAddr::BROADCAST,
        "0.0.0.0",
        "255.255.255.255",
        PROTO_UDP,
        64,
        false,
        &udp(68, 67, &discover),
    );
    r.receive(0, 1, &f, &mut out);
    // The server is not resolved yet: an ARP request on port 0, the message queued.
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    assert_eq!(&tx[0].1[12..14], &[8, 6]);
    r.receive(
        1,
        0,
        &arp_frame(2, A_MAC, "10.0.1.2", RTR0, "10.0.1.1"),
        &mut out,
    );
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    let (port, f) = &tx[0];
    assert_eq!(*port, 0);
    assert_eq!(dst_mac(f), mac(A_MAC));
    let ip = ip4(f);
    assert_eq!(
        &ip[12..16],
        &[10, 0, 1, 1],
        "from the egress port's address"
    );
    assert_eq!(&ip[16..20], &[10, 0, 1, 2]);
    let (sport, dport, payload) = udp_of(f);
    assert_eq!((sport, dport), (67, 67));
    let m = dhcp::Message::parse(payload).unwrap();
    assert_eq!((m.hops, m.giaddr), (1, v4("10.0.2.1")));
    assert_eq!(m.xid, 0xabcd_0001);
    // The UDP checksum verifies.
    let u = &ip[20..];
    let ps = wire::pseudo_v4(v4("10.0.1.1"), v4("10.0.1.2"), PROTO_UDP, u.len());
    assert_eq!(wire::finish(wire::sum16(u, ps)), 0);

    // The OFFER comes back to giaddr:67 and goes to the client unicast (no broadcast flag), at
    // its MAC, from giaddr, to port 68.
    let offer = dhcp_msg(2, dhcp::MessageType::Offer, "10.0.2.1", "10.0.2.100", 0);
    let f = frame_v4(
        A_MAC,
        RTR0,
        "10.0.1.2",
        "10.0.2.1",
        PROTO_UDP,
        64,
        false,
        &udp(67, 67, &offer),
    );
    r.receive(2, 0, &f, &mut out);
    let e = out.event("dhcp-relayed").clone();
    assert_eq!(e.get("direction"), Some("to-client"));
    assert_eq!(e.get("type"), Some("offer"));
    let tx = out.take();
    assert_eq!(tx.len(), 1);
    let (port, f) = &tx[0];
    assert_eq!((*port, dst_mac(f)), (1, mac(B_MAC)));
    assert_eq!(&ip4(f)[12..20], &[10, 0, 2, 1, 10, 0, 2, 100]);
    let (sport, dport, payload) = udp_of(f);
    assert_eq!((sport, dport), (67, 68));
    assert_eq!(payload, &offer[..]);

    // With the broadcast flag (or a NAK, which has no yiaddr): broadcast.
    let nak = dhcp_msg(2, dhcp::MessageType::Nak, "10.0.2.1", "0.0.0.0", 0);
    let f = frame_v4(
        A_MAC,
        RTR0,
        "10.0.1.2",
        "10.0.2.1",
        PROTO_UDP,
        64,
        false,
        &udp(67, 67, &nak),
    );
    r.receive(3, 0, &f, &mut out);
    let tx = out.take();
    assert_eq!(dst_mac(&tx[0].1), MacAddr::BROADCAST);
    assert_eq!(&ip4(&tx[0].1)[16..20], &[255, 255, 255, 255]);

    // Too many hops: dropped.
    let mut looped = discover.clone();
    looped[dhcp::offset::HOPS] = 16;
    let f = frame_v4(
        B_MAC,
        MacAddr::BROADCAST,
        "0.0.0.0",
        "255.255.255.255",
        PROTO_UDP,
        64,
        false,
        &udp(68, 67, &looped),
    );
    r.receive(4, 1, &f, &mut out);
    assert!(out.take().is_empty());
    let c: std::collections::BTreeMap<String, u64> = r.counter_list().into_iter().collect();
    assert_eq!(
        (
            c["dhcp-relayed-to-server"],
            c["dhcp-relayed-to-client"],
            c["dhcp-relay-dropped"]
        ),
        (1, 2, 1)
    );
}

#[test]
fn without_a_relay_dhcp_broadcasts_stay_on_their_link() {
    let (mut r, mut out) = router(&[]);
    assert!(!r.counter_list().iter().any(|(k, _)| k.starts_with("dhcp")));
    let discover = dhcp_msg(1, dhcp::MessageType::Discover, "0.0.0.0", "0.0.0.0", 0);
    let f = frame_v4(
        B_MAC,
        MacAddr::BROADCAST,
        "0.0.0.0",
        "255.255.255.255",
        PROTO_UDP,
        64,
        false,
        &udp(68, 67, &discover),
    );
    r.receive(0, 1, &f, &mut out);
    assert!(out.take().is_empty(), "no forwarding, no ICMP");
    // A relay port ignores a broadcast on another port.
    let (mut r, mut out) = router(&[("port1.dhcp-relay", "10.0.1.2")]);
    r.receive(0, 0, &f, &mut out);
    assert!(out.take().is_empty());
}

#[test]
fn a_relay_needs_an_ipv4_port_and_server_addresses() {
    let parse = |pairs: &[(&str, &str)]| {
        Config::from_pairs(pairs.iter().map(|(k, v)| (*k, *v)))
            .map(|c| c.ports[0].dhcp_relay.clone())
            .map_err(|e| e.to_string())
    };
    assert_eq!(
        parse(&[
            ("port0.ipv4", "10.0.2.1/24"),
            ("port0.dhcp-relay", "10.0.1.2, 10.0.1.3")
        ]),
        Ok(vec![v4("10.0.1.2"), v4("10.0.1.3")])
    );
    let err = parse(&[
        ("port0.ipv6", "fd00::1/64"),
        ("port0.dhcp-relay", "10.0.1.2"),
    ])
    .unwrap_err();
    assert!(err.contains("needs port0.ipv4"), "{err}");
    let err = parse(&[
        ("port0.ipv4", "10.0.2.1/24"),
        ("port0.dhcp-relay", "0.0.0.0"),
    ])
    .unwrap_err();
    assert!(err.contains("dhcp-relay"), "{err}");
}

mod nat;
