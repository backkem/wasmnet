//! Address translation and the packet filter, frame by frame through the whole router.
//!
//! Port 0 (10.0.1.1/24) is the inside with hosts A (10.0.1.10) and C (10.0.1.20); port 1
//! (10.0.2.1/24, `nat = masquerade`) is the outside with host B (10.0.2.10).

use proptest::prelude::*;

use super::*;

const C_MAC: u8 = 0x0c;
const OUT: &str = "10.0.2.1";

/// A UDP datagram from `src:sport` to `dst:dport` in a frame from host `from`, with its checksum.
#[allow(clippy::too_many_arguments)]
fn udp_frame(
    from: u8,
    to_mac: MacAddr,
    src: &str,
    sport: u16,
    dst: &str,
    dport: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let d = wire::udp_v4(v4(src), v4(dst), sport, dport, payload);
    let p = wire::ipv4(v4(src), v4(dst), PROTO_UDP, ttl, 7, &d);
    wire::eth_frame(to_mac, mac(from), ETHERTYPE_IPV4, &p)
}

fn tcp_frame(
    from: u8,
    to_mac: MacAddr,
    src: &str,
    sport: u16,
    dst: &str,
    dport: u16,
    flags: u8,
) -> Vec<u8> {
    let pseudo = wire::pseudo_v4(v4(src), v4(dst), PROTO_TCP, 20);
    let s = wire::tcp_segment(sport, dport, 100, 1, flags, pseudo);
    let p = wire::ipv4(v4(src), v4(dst), PROTO_TCP, 64, 8, &s);
    wire::eth_frame(to_mac, mac(from), ETHERTYPE_IPV4, &p)
}

/// A UDP frame's addresses, ports and payload; its UDP checksum must verify (or be zero).
fn udp4(frame: &[u8]) -> (Ipv4Addr, u16, Ipv4Addr, u16, Vec<u8>) {
    let ip = ip4(frame);
    let h = Ipv4HeaderSlice::from_slice(ip).unwrap();
    assert_eq!(h.protocol().0, PROTO_UDP);
    let u = &ip[h.slice().len()..usize::from(h.total_len())];
    if u[6..8] != [0, 0] {
        let ps = wire::pseudo_v4(h.source_addr(), h.destination_addr(), PROTO_UDP, u.len());
        assert_eq!(wire::finish(wire::sum16(u, ps)), 0, "UDP checksum");
    }
    (
        h.source_addr(),
        u16::from_be_bytes([u[0], u[1]]),
        h.destination_addr(),
        u16::from_be_bytes([u[2], u[3]]),
        u[8..].to_vec(),
    )
}

fn learn(r: &mut Router, out: &mut Out, from: u8, ip: &str, port: u32, rtr: &str) {
    r.receive(0, port, &arp_frame(1, from, ip, MacAddr::ZERO, rtr), out);
    out.take();
}

/// A router translating on port 1, with A, C and B known.
fn nat_router(extra: &[(&str, &str)]) -> (Router, Out) {
    let mut pairs = vec![("port1.nat", "masquerade")];
    pairs.extend_from_slice(extra);
    let (mut r, mut out) = router(&pairs);
    learn(&mut r, &mut out, A_MAC, "10.0.1.10", 0, "10.0.1.1");
    learn(&mut r, &mut out, C_MAC, "10.0.1.20", 0, "10.0.1.1");
    learn_b(&mut r, &mut out, 0);
    out.take();
    (r, out)
}

fn one(out: &mut Out) -> (u32, Vec<u8>) {
    let mut tx = out.take();
    assert_eq!(tx.len(), 1, "one frame out");
    tx.remove(0)
}

#[test]
fn udp_leaves_with_the_outside_address_and_its_answer_comes_back() {
    let (mut r, mut out) = nat_router(&[]);
    r.receive(
        MS,
        0,
        &udp_frame(
            A_MAC,
            RTR0,
            "10.0.1.10",
            4000,
            "10.0.2.10",
            53,
            64,
            b"query",
        ),
        &mut out,
    );
    let created = out.event("nat-mapping-created").clone();
    assert_eq!(created.get("internal"), Some("10.0.1.10:4000"));
    assert_eq!(
        created.get("external"),
        Some("10.0.2.1:4000"),
        "the port is preserved"
    );
    assert_eq!(created.get("remote"), Some("any"));
    let (port, f) = one(&mut out);
    assert_eq!((port, dst_mac(&f)), (1, mac(B_MAC)));
    assert_eq!(ttl_of(&f), 63);
    assert_eq!(
        udp4(&f),
        (v4(OUT), 4000, v4("10.0.2.10"), 53, b"query".to_vec())
    );
    // B answers the router's address; A gets it.
    r.receive(
        2 * MS,
        1,
        &udp_frame(B_MAC, RTR1, "10.0.2.10", 53, OUT, 4000, 64, b"answer"),
        &mut out,
    );
    let (port, f) = one(&mut out);
    assert_eq!((port, dst_mac(&f)), (0, mac(A_MAC)));
    assert_eq!(
        udp4(&f),
        (
            v4("10.0.2.10"),
            53,
            v4("10.0.1.10"),
            4000,
            b"answer".to_vec()
        )
    );
    assert_eq!(counter(&r, "nat-translated-out"), Some(1));
    assert_eq!(counter(&r, "nat-translated-in"), Some(1));
    assert_eq!(counter(&r, "nat-mappings"), Some(1));
    // Another inside host on the same port gets the next port of the range.
    r.receive(
        3 * MS,
        0,
        &udp_frame(C_MAC, RTR0, "10.0.1.20", 4000, "10.0.2.10", 53, 64, b"q"),
        &mut out,
    );
    let (_, f) = one(&mut out);
    assert_eq!(udp4(&f).1, 1024);
}

#[test]
fn unsolicited_and_filtered_packets_are_dropped_without_an_answer() {
    let (mut r, mut out) = nat_router(&[]);
    r.receive(
        MS,
        1,
        &udp_frame(B_MAC, RTR1, "10.0.2.10", 53, OUT, 5555, 64, b"x"),
        &mut out,
    );
    assert!(out.take().is_empty(), "no port unreachable, nothing");
    assert_eq!(counter(&r, "nat-no-mapping"), Some(1));
    r.receive(
        MS,
        1,
        &tcp_frame(B_MAC, RTR1, "10.0.2.10", 1, OUT, 22, wire::TCP_SYN),
        &mut out,
    );
    assert!(out.take().is_empty(), "no RST for an unsolicited SYN");
    // A mapping toward B:53; B from another port is filtered (address-and-port-dependent).
    r.receive(
        2 * MS,
        0,
        &udp_frame(A_MAC, RTR0, "10.0.1.10", 4000, "10.0.2.10", 53, 64, b"q"),
        &mut out,
    );
    out.take();
    r.receive(
        3 * MS,
        1,
        &udp_frame(B_MAC, RTR1, "10.0.2.10", 54, OUT, 4000, 64, b"x"),
        &mut out,
    );
    let ev = out.event("nat-filtered").clone();
    assert_eq!(ev.get("from"), Some("10.0.2.10:54"));
    assert_eq!(ev.get("internal"), Some("10.0.1.10:4000"));
    assert!(out.take().is_empty());
    assert_eq!(counter(&r, "nat-filtered"), Some(1));
    // Echo requests to the outside address are still the router's.
    r.receive(
        4 * MS,
        1,
        &frame_v4(
            B_MAC,
            RTR1,
            "10.0.2.10",
            OUT,
            PROTO_ICMP,
            64,
            false,
            &wire::icmpv4(8, 0, [0, 1, 0, 1], b"p"),
        ),
        &mut out,
    );
    let (port, f) = one(&mut out);
    assert_eq!((port, ip4(&f)[20]), (1, 0), "an echo reply");
}

#[test]
fn icmp_errors_are_translated_both_ways() {
    let (mut r, mut out) = nat_router(&[]);
    let probe = udp_frame(
        A_MAC,
        RTR0,
        "10.0.1.10",
        4000,
        "10.0.2.10",
        33434,
        64,
        b"probe",
    );
    r.receive(MS, 0, &probe, &mut out);
    let (_, sent) = one(&mut out);
    // B answers with a port unreachable quoting what it got (the translated packet).
    let quote = &ip4(&sent)[..20 + 8 + 5];
    let err = frame_v4(
        B_MAC,
        RTR1,
        "10.0.2.10",
        OUT,
        PROTO_ICMP,
        64,
        false,
        &wire::icmpv4(3, 3, [0; 4], quote),
    );
    r.receive(2 * MS, 1, &err, &mut out);
    let (port, f) = one(&mut out);
    assert_eq!(port, 0);
    let ip = ip4(&f);
    assert_eq!(&ip[16..20], &v4("10.0.1.10").octets(), "to the inside host");
    let inner = &ip[28..];
    assert_eq!(
        wire::checksum(&inner[..20]),
        0,
        "the quoted header's checksum"
    );
    assert_eq!(&inner[12..16], &v4("10.0.1.10").octets(), "quoted source");
    assert_eq!(&inner[20..22], &4000u16.to_be_bytes());
    let u = &inner[20..];
    let ps = wire::pseudo_v4(v4("10.0.1.10"), v4("10.0.2.10"), PROTO_UDP, u.len());
    assert_eq!(
        wire::finish(wire::sum16(u, ps)),
        0,
        "the quoted UDP checksum"
    );
    assert_eq!(counter(&r, "nat-icmp-errors-translated"), Some(1));
    // An error about another flow goes to the router itself (and nowhere).
    let mut other = quote.to_vec();
    other[20..22].copy_from_slice(&9999u16.to_be_bytes());
    let err = frame_v4(
        B_MAC,
        RTR1,
        "10.0.2.10",
        OUT,
        PROTO_ICMP,
        64,
        false,
        &wire::icmpv4(3, 3, [0; 4], &other),
    );
    r.receive(3 * MS, 1, &err, &mut out);
    assert!(out.take().is_empty());

    // The other way: a forward to C, and C's port unreachable about B's datagram.
    r.command(
        4 * MS,
        "forward-add",
        "udp 7000 to 10.0.1.20:7000",
        &mut out,
    )
    .unwrap();
    out.take();
    r.receive(
        5 * MS,
        1,
        &udp_frame(B_MAC, RTR1, "10.0.2.10", 6000, OUT, 7000, 64, b"hi"),
        &mut out,
    );
    let (port, inside) = one(&mut out);
    assert_eq!(port, 0);
    assert_eq!(
        udp4(&inside),
        (v4("10.0.2.10"), 6000, v4("10.0.1.20"), 7000, b"hi".to_vec())
    );
    let quote = &ip4(&inside)[..30];
    let err = frame_v4(
        C_MAC,
        RTR0,
        "10.0.1.20",
        "10.0.2.10",
        PROTO_ICMP,
        64,
        false,
        &wire::icmpv4(3, 3, [0; 4], quote),
    );
    r.receive(6 * MS, 0, &err, &mut out);
    let (port, f) = one(&mut out);
    assert_eq!(port, 1);
    let ip = ip4(&f);
    assert_eq!(&ip[12..16], &v4(OUT).octets(), "from the outside address");
    let inner = &ip[28..];
    assert_eq!(&inner[16..20], &v4(OUT).octets(), "quoted destination");
    assert_eq!(&inner[22..24], &7000u16.to_be_bytes());
    assert_eq!(wire::checksum(&inner[..20]), 0);
    // An inside host's error about nothing translated is dropped, not leaked.
    let stray = wire::ipv4(
        v4("10.0.2.10"),
        v4("10.0.1.20"),
        PROTO_UDP,
        64,
        1,
        &wire::udp_v4(v4("10.0.2.10"), v4("10.0.1.20"), 1, 2, b""),
    );
    let err = frame_v4(
        C_MAC,
        RTR0,
        "10.0.1.20",
        "10.0.2.10",
        PROTO_ICMP,
        64,
        false,
        &wire::icmpv4(3, 3, [0; 4], &stray[..28]),
    );
    r.receive(7 * MS, 0, &err, &mut out);
    assert_eq!(
        out.event("forward-drop").get("reason"),
        Some("nat-no-mapping")
    );
    assert!(out.take().is_empty());
}

#[test]
fn time_exceeded_from_beyond_reaches_the_traceroute_behind_the_nat() {
    let (mut r, mut out) = nat_router(&[]);
    // TTL 1 at the NAT itself: the router's own error, from its inside address.
    r.receive(
        MS,
        0,
        &udp_frame(A_MAC, RTR0, "10.0.1.10", 50000, "10.0.9.9", 33434, 1, b""),
        &mut out,
    );
    let (port, f) = one(&mut out);
    assert_eq!((port, ip4(&f)[20]), (0, 11));
    assert_eq!(&ip4(&f)[12..16], &v4("10.0.1.1").octets());
    // TTL 2 through the NAT (to B as the next router), and B's time exceeded comes back.
    r.command(MS, "route-add", "10.0.9.0/24 via 10.0.2.10", &mut out)
        .unwrap();
    out.take();
    r.receive(
        2 * MS,
        0,
        &udp_frame(A_MAC, RTR0, "10.0.1.10", 50000, "10.0.9.9", 33435, 2, b""),
        &mut out,
    );
    let (_, sent) = one(&mut out);
    assert_eq!(ttl_of(&sent), 1);
    let quote = &ip4(&sent)[..28];
    let err = frame_v4(
        B_MAC,
        RTR1,
        "10.0.2.10",
        OUT,
        PROTO_ICMP,
        64,
        false,
        &wire::icmpv4(11, 0, [0; 4], quote),
    );
    r.receive(3 * MS, 1, &err, &mut out);
    let (port, f) = one(&mut out);
    assert_eq!(port, 0);
    assert_eq!(
        (ip4(&f)[20], &ip4(&f)[12..16]),
        (11, &v4("10.0.2.10").octets()[..])
    );
    assert_eq!(&ip4(&f)[28 + 12..28 + 16], &v4("10.0.1.10").octets());
}

#[test]
fn echo_identifiers_are_translated() {
    let (mut r, mut out) = nat_router(&[
        ("nat.port-allocation", "sequential"),
        ("nat.port-range", "2000-2001"),
    ]);
    let ping = frame_v4(
        A_MAC,
        RTR0,
        "10.0.1.10",
        "10.0.2.10",
        PROTO_ICMP,
        64,
        false,
        &wire::icmpv4(8, 0, [0, 77, 0, 1], b"abc"),
    );
    r.receive(MS, 0, &ping, &mut out);
    let (_, f) = one(&mut out);
    assert_eq!(&ip4(&f)[24..26], &2000u16.to_be_bytes(), "the identifier");
    let reply = frame_v4(
        B_MAC,
        RTR1,
        "10.0.2.10",
        OUT,
        PROTO_ICMP,
        64,
        false,
        &wire::icmpv4(0, 0, [7, 208, 0, 1], b"abc"),
    );
    r.receive(2 * MS, 1, &reply, &mut out);
    let (port, f) = one(&mut out);
    assert_eq!(port, 0);
    assert_eq!(&ip4(&f)[16..20], &v4("10.0.1.10").octets());
    assert_eq!(&ip4(&f)[24..26], &77u16.to_be_bytes());
    // The range holds two identifiers: a third mapping finds no port.
    for id in [78u8, 79] {
        let p = frame_v4(
            A_MAC,
            RTR0,
            "10.0.1.10",
            "10.0.2.10",
            PROTO_ICMP,
            64,
            false,
            &wire::icmpv4(8, 0, [0, id, 0, 1], b""),
        );
        r.receive(3 * MS, 0, &p, &mut out);
    }
    assert_eq!(out.take().len(), 1);
    assert_eq!(counter(&r, "nat-ports-exhausted"), Some(1));
}

#[test]
fn tcp_needs_a_syn_from_inside_and_mappings_expire() {
    let (mut r, mut out) = nat_router(&[]);
    r.receive(
        MS,
        0,
        &tcp_frame(
            A_MAC,
            RTR0,
            "10.0.1.10",
            40000,
            "10.0.2.10",
            80,
            wire::TCP_ACK,
        ),
        &mut out,
    );
    assert_eq!(
        out.event("forward-drop").get("reason"),
        Some("nat-no-mapping")
    );
    assert!(out.take().is_empty());
    assert_eq!(counter(&r, "nat-no-mapping"), Some(1));
    r.receive(
        2 * MS,
        0,
        &tcp_frame(
            A_MAC,
            RTR0,
            "10.0.1.10",
            40000,
            "10.0.2.10",
            80,
            wire::TCP_SYN,
        ),
        &mut out,
    );
    assert_eq!(out.take().len(), 1);
    // Only the SYN: transitory, 240 s. The poll deadline includes it.
    let deadline = r.poll(3 * MS, &mut out).unwrap();
    assert_eq!(deadline, 2 * MS + 240 * S);
    r.poll(deadline, &mut out);
    let ev = out.event("nat-mapping-expired");
    assert_eq!(ev.get("internal"), Some("10.0.1.10:40000"));
    assert_eq!(counter(&r, "nat-mappings"), Some(0));
    assert_eq!(
        r.poll(deadline + 1, &mut out),
        None,
        "nothing left to wait for"
    );
}

#[test]
fn port_forwards_and_hairpinning() {
    let (mut r, mut out) = nat_router(&[("nat.forwards", "udp 7 to 10.0.1.20:7")]);
    // From the outside, to the forward.
    r.receive(
        MS,
        1,
        &udp_frame(B_MAC, RTR1, "10.0.2.10", 3000, OUT, 7, 64, b"echo"),
        &mut out,
    );
    let (port, f) = one(&mut out);
    assert_eq!((port, dst_mac(&f)), (0, mac(C_MAC)));
    assert_eq!(udp4(&f).2, v4("10.0.1.20"));
    // C answers from port 7: it leaves through the forward.
    r.receive(
        2 * MS,
        0,
        &udp_frame(C_MAC, RTR0, "10.0.1.20", 7, "10.0.2.10", 3000, 64, b"echo"),
        &mut out,
    );
    let (port, f) = one(&mut out);
    assert_eq!(port, 1);
    assert_eq!(
        udp4(&f),
        (v4(OUT), 7, v4("10.0.2.10"), 3000, b"echo".to_vec())
    );
    // A, inside, sends to the outside address: hairpinned to C, from A's external endpoint.
    r.receive(
        3 * MS,
        0,
        &udp_frame(A_MAC, RTR0, "10.0.1.10", 4000, OUT, 7, 64, b"hair"),
        &mut out,
    );
    let (port, f) = one(&mut out);
    assert_eq!((port, dst_mac(&f)), (0, mac(C_MAC)));
    assert_eq!(
        udp4(&f),
        (v4(OUT), 4000, v4("10.0.1.20"), 7, b"hair".to_vec())
    );
    // C answers A's external endpoint: hairpinned back to A, from the forward.
    r.receive(
        4 * MS,
        0,
        &udp_frame(C_MAC, RTR0, "10.0.1.20", 7, OUT, 4000, 64, b"back"),
        &mut out,
    );
    let (port, f) = one(&mut out);
    assert_eq!((port, dst_mac(&f)), (0, mac(A_MAC)));
    assert_eq!(
        udp4(&f),
        (v4(OUT), 7, v4("10.0.1.10"), 4000, b"back".to_vec())
    );
    assert_eq!(counter(&r, "nat-hairpinned"), Some(2));
    // A port nobody maps is the router's own: a port unreachable from it.
    r.receive(
        5 * MS,
        0,
        &udp_frame(A_MAC, RTR0, "10.0.1.10", 4000, OUT, 9, 64, b""),
        &mut out,
    );
    let (_, f) = one(&mut out);
    assert_eq!(ip4(&f)[20], 3);

    let (mut r, mut out) = nat_router(&[
        ("nat.forwards", "udp 7 to 10.0.1.20:7"),
        ("nat.hairpin", "false"),
    ]);
    r.receive(
        MS,
        0,
        &udp_frame(A_MAC, RTR0, "10.0.1.10", 4000, OUT, 7, 64, b"hair"),
        &mut out,
    );
    assert_eq!(
        out.event("forward-drop").get("reason"),
        Some("nat-hairpin-refused")
    );
    assert!(out.take().is_empty());
    assert_eq!(counter(&r, "nat-hairpin-refused"), Some(1));
}

#[test]
fn an_unreachable_next_hop_reports_the_packet_as_it_came_in() {
    let mut pairs = vec![("port1.nat", "masquerade")];
    pairs.push(("neighbor.attempts", "1"));
    let (mut r, mut out) = router(&pairs);
    learn(&mut r, &mut out, A_MAC, "10.0.1.10", 0, "10.0.1.1");
    r.receive(
        MS,
        0,
        &udp_frame(A_MAC, RTR0, "10.0.1.10", 4000, "10.0.2.99", 53, 64, b"q"),
        &mut out,
    );
    out.take();
    r.poll(MS + S, &mut out);
    let tx = out.take();
    let (port, f) = tx.iter().find(|(_, f)| f[12..14] == [8, 0]).unwrap();
    assert_eq!(*port, 0);
    assert_eq!((ip4(f)[20], ip4(f)[21]), (3, 1), "host unreachable");
    assert_eq!(
        &ip4(f)[28 + 12..28 + 16],
        &v4("10.0.1.10").octets(),
        "the quote's source"
    );
}

#[test]
fn malformed_and_fragmented_packets_are_dropped_and_counted() {
    let (mut r, mut out) = nat_router(&[]);
    // 4 bytes of UDP: ports but no length or checksum.
    let short = wire::ipv4(
        v4("10.0.1.10"),
        v4("10.0.2.10"),
        PROTO_UDP,
        64,
        1,
        &[0x0f, 0xa0, 0, 53],
    );
    r.receive(
        MS,
        0,
        &wire::eth_frame(RTR0, mac(A_MAC), ETHERTYPE_IPV4, &short),
        &mut out,
    );
    assert_eq!(
        out.event("forward-drop").get("reason"),
        Some("nat-malformed")
    );
    assert!(out.take().is_empty());
    let mut frag = wire::ipv4(
        v4("10.0.1.10"),
        v4("10.0.2.10"),
        PROTO_UDP,
        64,
        1,
        &wire::udp_v4(v4("10.0.1.10"), v4("10.0.2.10"), 1, 2, b"x"),
    );
    frag[6] = 0x20; // more fragments
    frag[10..12].copy_from_slice(&[0, 0]);
    let c = wire::checksum(&frag[..20]);
    frag[10..12].copy_from_slice(&c.to_be_bytes());
    r.receive(
        MS,
        0,
        &wire::eth_frame(RTR0, mac(A_MAC), ETHERTYPE_IPV4, &frag),
        &mut out,
    );
    assert_eq!(
        out.event("forward-drop").get("reason"),
        Some("nat-fragment")
    );
    assert!(out.take().is_empty());
    // GRE is not translated.
    let gre = wire::ipv4(v4("10.0.1.10"), v4("10.0.2.10"), 47, 64, 1, &[0; 8]);
    r.receive(
        MS,
        0,
        &wire::eth_frame(RTR0, mac(A_MAC), ETHERTYPE_IPV4, &gre),
        &mut out,
    );
    assert_eq!(
        out.event("forward-drop").get("reason"),
        Some("nat-unsupported")
    );
    for (name, n) in [
        ("nat-malformed", 1),
        ("nat-fragments", 1),
        ("nat-unsupported", 1),
    ] {
        assert_eq!(counter(&r, name), Some(n), "{name}");
    }
}

#[test]
fn routers_without_translation_or_rules_list_no_new_counters() {
    let (r, _) = router(&[]);
    assert!(
        !r.counter_list()
            .iter()
            .any(|(k, _)| k.starts_with("nat-") || k.starts_with("filter-"))
    );
    let (r, _) = nat_router(&[]);
    assert!(r.counter_list().iter().any(|(k, _)| k == "nat-mappings"));
    assert!(
        !r.counter_list()
            .iter()
            .any(|(k, _)| k.starts_with("filter-"))
    );
}

#[test]
fn config_checks() {
    let bad = |pairs: &[(&str, &str)]| {
        let mut all = vec![("port0.ipv4", "10.0.1.1/24"), ("port1.ipv4", "10.0.2.1/24")];
        all.extend_from_slice(pairs);
        Config::from_pairs(all.iter().map(|(k, v)| (*k, *v))).is_err()
    };
    assert!(!bad(&[
        ("port1.nat", "masquerade"),
        ("nat.mapping", "address-dependent")
    ]));
    assert!(
        bad(&[("nat.mapping", "address-dependent")]),
        "nat.* needs a nat port"
    );
    assert!(bad(&[("port1.nat", "yes")]));
    assert!(bad(&[("port2.nat", "masquerade")]), "a nat port needs ipv4");
    assert!(bad(&[
        ("port1.nat", "masquerade"),
        ("nat.filtering", "full-cone")
    ]));
    assert!(bad(&[
        ("port1.nat", "masquerade"),
        ("nat.port-range", "9-8")
    ]));
    assert!(bad(&[
        ("port1.nat", "masquerade"),
        ("nat.forwards", "tcp 80 to 10.0.1.10:80 port 0")
    ]));
    assert!(bad(&[
        ("port1.nat", "masquerade"),
        (
            "nat.forwards",
            "tcp 80 to 10.0.1.10:80, tcp 80 to 10.0.1.11:80"
        )
    ]));
    assert!(bad(&[("port1.allow", "tcp dport 99999")]));
    assert!(bad(&[("conntrack.udp-timeout", "0s")]));
    assert!(!bad(&[
        ("port1.allow", "tcp to 10.0.1.0/24 dport 80, icmp"),
        ("conntrack.max-entries", "16")
    ]));
}

// ---- the filter ----

fn v6_udp(from: u8, to: MacAddr, src: &str, sport: u16, dst: &str, dport: u16) -> Vec<u8> {
    let (s, d) = (v6(src), v6(dst));
    let mut u = udp(sport, dport, b"six");
    let c = wire::finish(wire::sum16(&u, wire::pseudo_v6(s, d, PROTO_UDP, u.len())));
    u[6..8].copy_from_slice(&c.to_be_bytes());
    frame_v6(from, to, src, dst, PROTO_UDP, 64, &u)
}

#[test]
fn the_filter_allows_by_rule_and_lets_answers_back() {
    let (mut r, mut out) = router(&[(
        "port1.allow",
        "tcp to 10.0.1.10/32 dport 80, udp to fd00:1::10/128 dport 53",
    )]);
    learn(&mut r, &mut out, A_MAC, "10.0.1.10", 0, "10.0.1.1");
    learn_b(&mut r, &mut out, 0);
    // From the outside: TCP to A:80 passes, to A:22 does not (journalled once).
    r.receive(
        MS,
        1,
        &tcp_frame(
            B_MAC,
            RTR1,
            "10.0.2.10",
            5000,
            "10.0.1.10",
            80,
            wire::TCP_SYN,
        ),
        &mut out,
    );
    assert_eq!(one(&mut out).0, 0);
    r.receive(
        MS,
        1,
        &tcp_frame(
            B_MAC,
            RTR1,
            "10.0.2.10",
            5000,
            "10.0.1.10",
            22,
            wire::TCP_SYN,
        ),
        &mut out,
    );
    let ev = out.event("filter-drop").clone();
    assert_eq!(ev.get("dst"), Some("10.0.1.10:22"));
    assert_eq!(ev.get("port"), Some("1"));
    assert!(out.take().is_empty());
    // A's answer to B (port 0 has no rules) and A's own new flow, whose answer comes back.
    r.receive(
        2 * MS,
        0,
        &tcp_frame(
            A_MAC,
            RTR0,
            "10.0.1.10",
            80,
            "10.0.2.10",
            5000,
            wire::TCP_SYN | wire::TCP_ACK,
        ),
        &mut out,
    );
    assert_eq!(one(&mut out).0, 1);
    r.receive(
        3 * MS,
        0,
        &udp_frame(A_MAC, RTR0, "10.0.1.10", 6000, "10.0.2.10", 7, 64, b"x"),
        &mut out,
    );
    assert_eq!(one(&mut out).0, 1);
    r.receive(
        4 * MS,
        1,
        &udp_frame(B_MAC, RTR1, "10.0.2.10", 7, "10.0.1.10", 6000, 64, b"x"),
        &mut out,
    );
    assert_eq!(one(&mut out).0, 0, "return traffic");
    r.receive(
        5 * MS,
        1,
        &udp_frame(B_MAC, RTR1, "10.0.2.10", 7, "10.0.1.10", 6001, 64, b"x"),
        &mut out,
    );
    assert!(out.take().is_empty(), "not a known flow");
    // IPv6: the UDP rule. NDP first so the router knows A's IPv6 neighbor... it asks.
    r.receive(
        6 * MS,
        1,
        &v6_udp(B_MAC, RTR1, "fd00:2::10", 1000, "fd00:1::10", 53),
        &mut out,
    );
    let tx = out.take();
    assert!(
        tx.iter().any(|(p, f)| *p == 0 && f[12..14] == [0x86, 0xdd]),
        "a solicitation for A"
    );
    r.receive(
        6 * MS,
        1,
        &v6_udp(B_MAC, RTR1, "fd00:2::10", 1000, "fd00:1::10", 54),
        &mut out,
    );
    assert_eq!(out.event("filter-drop").get("dst"), Some("[fd00:1::10]:54"));
    assert!(out.take().is_empty());
    assert_eq!(counter(&r, "filter-dropped"), Some(3));
    assert_eq!(counter(&r, "filter-rules"), Some(2));
    // Traffic to the router itself is not filtered.
    r.receive(
        7 * MS,
        1,
        &frame_v4(
            B_MAC,
            RTR1,
            "10.0.2.10",
            "10.0.2.1",
            PROTO_ICMP,
            64,
            false,
            &wire::icmpv4(8, 0, [0, 1, 0, 1], b"p"),
        ),
        &mut out,
    );
    assert_eq!(one(&mut out).0, 1);
}

#[test]
fn commands_change_forwards_and_rules() {
    let (mut r, mut out) = nat_router(&[]);
    assert_eq!(
        r.command(0, "forward-add", "tcp 8080 to 10.0.1.10:80", &mut out),
        Ok("added".into())
    );
    assert_eq!(out.event("nat-forward-added").get("external"), Some("8080"));
    assert_eq!(
        r.command(0, "forward-add", "tcp 8080 to 10.0.1.10:80", &mut out),
        Ok("unchanged".into())
    );
    assert!(
        r.command(0, "forward-add", "tcp 8080 to 10.0.1.11:80", &mut out)
            .is_err()
    );
    assert_eq!(
        r.command(0, "forwards", "", &mut out),
        Ok("tcp 8080 to 10.0.1.10:80 port 1".into())
    );
    assert!(
        r.command(0, "forward-remove", "tcp 8080 to 10.0.1.11:80", &mut out)
            .is_err(),
        "not that forward"
    );
    assert_eq!(
        r.command(0, "forward-remove", "tcp 8080", &mut out),
        Ok("removed".into())
    );
    assert_eq!(
        r.command(0, "forward-remove", "tcp 8080 port 1", &mut out),
        Ok("absent".into())
    );
    assert!(
        r.command(0, "forward-add", "tcp 1 to 10.0.1.10:1 port 0", &mut out)
            .is_err()
    );

    assert_eq!(r.command(0, "rules", "", &mut out), Ok(String::new()));
    assert_eq!(
        r.command(0, "allow-add", "1 tcp dport 80", &mut out),
        Ok("added".into())
    );
    assert_eq!(out.event("allow-added").get("rule"), Some("tcp dport 80"));
    assert_eq!(
        r.command(0, "allow-add", "1 tcp dport 80", &mut out),
        Ok("unchanged".into())
    );
    assert!(r.command(0, "allow-add", "5 tcp", &mut out).is_err());
    assert!(r.command(0, "allow-add", "1 tcp dport", &mut out).is_err());
    assert_eq!(
        r.command(0, "rules", "", &mut out),
        Ok("1 tcp dport 80".into())
    );
    assert_eq!(
        r.command(0, "allow-remove", "1 tcp dport 80", &mut out),
        Ok("removed".into())
    );
    assert_eq!(
        r.command(0, "allow-remove", "1 tcp dport 80", &mut out),
        Ok("absent".into())
    );
    // A mapping listing.
    r.receive(
        MS,
        0,
        &udp_frame(A_MAC, RTR0, "10.0.1.10", 4000, "10.0.2.10", 53, 64, b"q"),
        &mut out,
    );
    assert_eq!(
        r.command(MS, "mappings", "", &mut out),
        Ok("udp 10.0.1.10:4000 -> 10.0.2.1:4000 port 1 remote any\n  session 10.0.2.10:53".into())
    );
    // Without translation, the NAT commands are refused.
    let (mut plain, mut out) = router(&[]);
    assert!(
        plain
            .command(0, "forward-add", "tcp 1 to 10.0.1.10:1", &mut out)
            .is_err()
    );
    assert!(plain.command(0, "mappings", "", &mut out).is_err());
}

proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 256,
        rng_seed: proptest::test_runner::RngSeed::Fixed(5508),
        failure_persistence: None,
        ..proptest::test_runner::Config::default()
    })]

    /// Out through the NAT and back is the identity on payloads and inside endpoints, with
    /// every checksum valid on both sides, for any ports and payloads.
    #[test]
    fn out_and_back_is_the_identity(
        sport in 1u16..,
        dport in 1u16..,
        out_payload in proptest::collection::vec(any::<u8>(), 0..200),
        back_payload in proptest::collection::vec(any::<u8>(), 0..200),
        tcp in any::<bool>(),
    ) {
        let (mut r, mut out) = nat_router(&[]);
        let send = if tcp {
            let pseudo = wire::pseudo_v4(v4("10.0.1.10"), v4("10.0.2.10"), PROTO_TCP, 20 + out_payload.len());
            let mut s = wire::tcp_segment(sport, dport, 1, 0, wire::TCP_SYN, 0);
            s.extend_from_slice(&out_payload);
            s[16..18].copy_from_slice(&[0, 0]);
            let c = wire::finish(wire::sum16(&s, pseudo));
            s[16..18].copy_from_slice(&c.to_be_bytes());
            wire::eth_frame(RTR0, mac(A_MAC), ETHERTYPE_IPV4, &wire::ipv4(v4("10.0.1.10"), v4("10.0.2.10"), PROTO_TCP, 64, 1, &s))
        } else {
            udp_frame(A_MAC, RTR0, "10.0.1.10", sport, "10.0.2.10", dport, 64, &out_payload)
        };
        r.receive(MS, 0, &send, &mut out);
        let tx = out.take();
        prop_assert_eq!(tx.len(), 1);
        let sent = unpadded(&tx[0].1);
        prop_assert_eq!(&sent[12..16], &v4(OUT).octets());
        prop_assert_eq!(&sent[20 + if tcp { 20 } else { 8 }..], &out_payload[..]);
        let ext = u16::from_be_bytes([sent[20], sent[21]]);
        let back = if tcp {
            let pseudo = wire::pseudo_v4(v4("10.0.2.10"), v4(OUT), PROTO_TCP, 20 + back_payload.len());
            let mut s = wire::tcp_segment(dport, ext, 9, 2, wire::TCP_SYN | wire::TCP_ACK, 0);
            s.extend_from_slice(&back_payload);
            s[16..18].copy_from_slice(&[0, 0]);
            let c = wire::finish(wire::sum16(&s, pseudo));
            s[16..18].copy_from_slice(&c.to_be_bytes());
            wire::eth_frame(RTR1, mac(B_MAC), ETHERTYPE_IPV4, &wire::ipv4(v4("10.0.2.10"), v4(OUT), PROTO_TCP, 64, 2, &s))
        } else {
            udp_frame(B_MAC, RTR1, "10.0.2.10", dport, OUT, ext, 64, &back_payload)
        };
        r.receive(2 * MS, 1, &back, &mut out);
        let tx = out.take();
        prop_assert_eq!(tx.len(), 1);
        prop_assert_eq!(tx[0].0, 0);
        let got = unpadded(&tx[0].1);
        prop_assert_eq!(&got[16..20], &v4("10.0.1.10").octets());
        prop_assert_eq!(&got[22..24], &sport.to_be_bytes());
        let l4 = &got[20..];
        prop_assert_eq!(&l4[if tcp { 20 } else { 8 }..], &back_payload[..]);
        let ps = wire::pseudo_v4(v4("10.0.2.10"), v4("10.0.1.10"), if tcp { PROTO_TCP } else { PROTO_UDP }, l4.len());
        prop_assert_eq!(wire::finish(wire::sum16(l4, ps)), 0, "transport checksum");
    }

    /// Any bytes at all, in through either port of a translating, filtering router: never a
    /// trap.
    #[test]
    fn junk_never_traps(
        port in 0u32..2,
        ethertype in prop_oneof![Just(0x0800u16), Just(0x86dd), any::<u16>()],
        body in proptest::collection::vec(any::<u8>(), 0..120),
        ver_ihl in prop_oneof![Just(0x45u8), any::<u8>()],
        proto in prop_oneof![Just(1u8), Just(6), Just(17), any::<u8>()],
    ) {
        let (mut r, _) = nat_router(&[("port1.allow", "udp dport 1-100"), ("nat.forwards", "udp 7 to 10.0.1.20:7")]);
        let mut p = body;
        if p.len() >= 20 && ethertype == 0x0800 {
            p[0] = ver_ihl;
            p[9] = proto;
            let len = p.len() as u16;
            p[2..4].copy_from_slice(&len.to_be_bytes());
            p[16..20].copy_from_slice(&v4(OUT).octets());
            p[10..12].copy_from_slice(&[0, 0]);
            let h = usize::from(p[0] & 0x0f) * 4;
            if h >= 20 && h <= p.len() {
                let c = wire::checksum(&p[..h]);
                p[10..12].copy_from_slice(&c.to_be_bytes());
            }
        }
        let to = if port == 0 { RTR0 } else { RTR1 };
        let mut f = Vec::new();
        f.extend_from_slice(&to.octets());
        f.extend_from_slice(&mac(B_MAC).octets());
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(&p);
        r.receive(MS, port, &f, &mut Quiet);
        r.poll(MS, &mut Quiet);
    }
}

/// A sink that keeps nothing and checks nothing (junk may be forwarded as junk).
struct Quiet;

impl Sink for Quiet {
    fn transmit(&mut self, _port: u32, _frame: Vec<u8>) {}
    fn event(&mut self, _event: Event) {}
}

/// A frame's IPv4 packet without the Ethernet padding.
fn unpadded(frame: &[u8]) -> Vec<u8> {
    let ip = ip4(frame);
    ip[..usize::from(u16::from_be_bytes([ip[2], ip[3]]))].to_vec()
}
