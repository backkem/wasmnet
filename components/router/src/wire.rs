//! Byte-level helpers: Internet checksums, the TTL decrement with an incremental checksum update
//! (RFC 1624), and builders for the frames the router originates (ARP, NDP, ICMP, TCP RST).
//!
//! Parsing uses etherparse (in `router.rs`); building is a few explicit byte writes, which keeps
//! every header field visible and the checksums in one place.

use std::net::{Ipv4Addr, Ipv6Addr};

use wasmnet_wire::MacAddr;

pub const ETH_HEADER: usize = 14;
/// Frames shorter than this (without FCS) are zero-padded, like a real NIC does.
pub const MIN_FRAME: usize = 60;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

/// Adds `data` as big-endian 16-bit words to a running one's-complement sum. (A `u32` holds
/// the sum of any packet up to 64 KiB without folding.)
pub fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        acc += u32::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        acc += u32::from(*last) << 8;
    }
    acc
}

/// Folds a running sum and complements it: the checksum field's value.
pub fn finish(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The Internet checksum of `data`.
pub fn checksum(data: &[u8]) -> u16 {
    finish(sum16(data, 0))
}

/// The IPv4 pseudo-header sum for TCP/UDP.
pub fn pseudo_v4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> u32 {
    let acc = sum16(&src.octets(), 0);
    let acc = sum16(&dst.octets(), acc);
    acc + u32::from(proto) + len as u32
}

/// The IPv6 pseudo-header sum (RFC 8200 §8.1).
pub fn pseudo_v6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, len: usize) -> u32 {
    let acc = sum16(&src.octets(), 0);
    let acc = sum16(&dst.octets(), acc);
    acc + (len as u32 >> 16) + (len as u32 & 0xffff) + u32::from(next)
}

/// An Ethernet II frame, zero-padded to [`MIN_FRAME`].
pub fn eth_frame(dst: MacAddr, src: MacAddr, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity((ETH_HEADER + payload.len()).max(MIN_FRAME));
    f.extend_from_slice(&dst.octets());
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    if f.len() < MIN_FRAME {
        f.resize(MIN_FRAME, 0);
    }
    f
}

/// An ARP packet (Ethernet / IPv4): `op` 1 = request, 2 = reply.
pub fn arp(
    op: u16,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);
    p.extend_from_slice(&op.to_be_bytes());
    p.extend_from_slice(&sender_mac.octets());
    p.extend_from_slice(&sender_ip.octets());
    p.extend_from_slice(&target_mac.octets());
    p.extend_from_slice(&target_ip.octets());
    p
}

/// An IPv4 packet with a 20-byte header (no options, DF clear) and its header checksum.
pub fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, ttl: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0, 0, ttl, proto, 0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let c = checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// A UDP datagram (header and payload) with its checksum over the IPv4 pseudo-header (for the
/// DHCP relay).
pub fn udp_v4(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut d = Vec::with_capacity(len);
    d.extend_from_slice(&sport.to_be_bytes());
    d.extend_from_slice(&dport.to_be_bytes());
    d.extend_from_slice(&(len as u16).to_be_bytes());
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(payload);
    let c = match finish(sum16(&d, pseudo_v4(src, dst, PROTO_UDP, len))) {
        // RFC 768: a computed zero is sent as all ones (zero means "no checksum").
        0 => 0xffff,
        c => c,
    };
    d[6..8].copy_from_slice(&c.to_be_bytes());
    d
}

/// An IPv6 packet (no extension headers).
pub fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, hop_limit: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(40 + payload.len());
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    p.extend_from_slice(&[next, hop_limit]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

/// An ICMPv4 message: type, code, the 4 "rest of header" bytes and the body, checksummed.
pub fn icmpv4(icmp_type: u8, code: u8, rest: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + body.len());
    m.extend_from_slice(&[icmp_type, code, 0, 0]);
    m.extend_from_slice(&rest);
    m.extend_from_slice(body);
    let c = checksum(&m);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    m
}

/// An ICMPv6 message, checksummed over the IPv6 pseudo-header.
pub fn icmpv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    icmp_type: u8,
    code: u8,
    rest: [u8; 4],
    body: &[u8],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + body.len());
    m.extend_from_slice(&[icmp_type, code, 0, 0]);
    m.extend_from_slice(&rest);
    m.extend_from_slice(body);
    let c = finish(sum16(&m, pseudo_v6(src, dst, PROTO_ICMPV6, m.len())));
    m[2..4].copy_from_slice(&c.to_be_bytes());
    m
}

/// A TCP header-only segment (20 bytes, no options) with its checksum computed over `pseudo`.
pub fn tcp_segment(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, pseudo: u32) -> Vec<u8> {
    let mut s = Vec::with_capacity(20);
    s.extend_from_slice(&sport.to_be_bytes());
    s.extend_from_slice(&dport.to_be_bytes());
    s.extend_from_slice(&seq.to_be_bytes());
    s.extend_from_slice(&ack.to_be_bytes());
    s.extend_from_slice(&[5 << 4, flags, 0, 0, 0, 0, 0, 0]);
    let c = finish(sum16(&s, pseudo));
    s[16..18].copy_from_slice(&c.to_be_bytes());
    s
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// The RST that answers `segment` (a TCP header plus payload) when no socket wants it
/// (RFC 9293 §3.10.7.1): `(seq, ack, flags)`.
pub fn rst_for(segment: &[u8]) -> Option<(u32, u32, u8)> {
    let flags = *segment.get(13)?;
    if flags & TCP_RST != 0 {
        return None;
    }
    let seq = u32::from_be_bytes(segment.get(4..8)?.try_into().ok()?);
    let ack = u32::from_be_bytes(segment.get(8..12)?.try_into().ok()?);
    if flags & TCP_ACK != 0 {
        return Some((ack, 0, TCP_RST));
    }
    let data_off = usize::from(segment.get(12)? >> 4) * 4;
    let mut len = segment.len().saturating_sub(data_off) as u32;
    if flags & TCP_SYN != 0 {
        len += 1;
    }
    if flags & TCP_FIN != 0 {
        len += 1;
    }
    Some((0, seq.wrapping_add(len), TCP_RST | TCP_ACK))
}

/// Decrements an IPv4 packet's TTL by one and patches its header checksum incrementally
/// (RFC 1624 eqn. 3: `HC' = ~(~HC + ~m + m')`, with `m` the TTL/protocol word).
/// The caller made sure the TTL is above 1.
pub fn decrement_ttl_v4(packet: &mut [u8]) {
    let old = u16::from_be_bytes([packet[8], packet[9]]);
    packet[8] -= 1;
    let new = u16::from_be_bytes([packet[8], packet[9]]);
    let hc = u16::from_be_bytes([packet[10], packet[11]]);
    let mut acc = u32::from(!hc) + u32::from(!old) + u32::from(new);
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    packet[10..12].copy_from_slice(&(!(acc as u16)).to_be_bytes());
}

/// `ff02::1:ffXX:XXXX`, the solicited-node group of `a` (RFC 4291 §2.7.1).
pub fn solicited_node(a: Ipv6Addr) -> Ipv6Addr {
    let o = a.octets();
    Ipv6Addr::from([
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, o[13], o[14], o[15],
    ])
}

/// The Ethernet group address of an IPv6 multicast address (`33:33:` + its low 32 bits).
pub fn multicast_mac(a: Ipv6Addr) -> MacAddr {
    let o = a.octets();
    MacAddr([0x33, 0x33, o[12], o[13], o[14], o[15]])
}

/// An NDP link-layer address option: `kind` 1 = source, 2 = target.
pub fn ll_option(kind: u8, mac: MacAddr) -> [u8; 8] {
    let m = mac.octets();
    [kind, 1, m[0], m[1], m[2], m[3], m[4], m[5]]
}

/// The link-layer address in an NDP option list (`kind` 1 = source, 2 = target), if present.
pub fn find_ll_option(mut options: &[u8], kind: u8) -> Option<MacAddr> {
    while options.len() >= 2 {
        let len = usize::from(options[1]) * 8;
        if len == 0 || len > options.len() {
            return None;
        }
        if options[0] == kind && len >= 8 {
            return MacAddr::from_slice(&options[2..8]);
        }
        options = &options[len..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn checksum_of_a_known_header() {
        // A real IPv4 header (Wikipedia's "IPv4 header checksum" example).
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&header), 0xb861);
        let built = ipv4(
            "192.168.0.1".parse().unwrap(),
            "192.168.0.199".parse().unwrap(),
            17,
            64,
            0,
            &[0; 0x73 - 20],
        );
        assert_eq!(checksum(&built[..20]), 0, "a valid header sums to zero");
    }

    #[test]
    fn frames_are_padded() {
        let f = eth_frame(
            MacAddr::BROADCAST,
            MacAddr([2, 0, 0, 0, 0, 1]),
            0x0806,
            &[1; 28],
        );
        assert_eq!(f.len(), 60);
        assert_eq!(&f[12..14], &[0x08, 0x06]);
    }

    #[test]
    fn icmpv6_checksum_verifies_with_etherparse() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "ff02::1:ff00:10".parse().unwrap();
        let m = icmpv6(src, dst, 135, 0, [0; 4], &[0xfd; 16]);
        let ty = etherparse::Icmpv6Type::NeighborSolicitation;
        let want = ty
            .calc_checksum(src.octets(), dst.octets(), &m[8..])
            .unwrap();
        assert_eq!(u16::from_be_bytes([m[2], m[3]]), want);
        assert_eq!(finish(sum16(&m, pseudo_v6(src, dst, 58, m.len()))), 0);
    }

    #[test]
    fn rst_answers() {
        // A SYN with seq 100 → RST,ACK ack 101; an ACK segment with ack 7 → RST seq 7.
        let syn = tcp_segment(1, 2, 100, 0, TCP_SYN, 0);
        assert_eq!(rst_for(&syn), Some((0, 101, TCP_RST | TCP_ACK)));
        let ack = tcp_segment(1, 2, 100, 7, TCP_ACK, 0);
        assert_eq!(rst_for(&ack), Some((7, 0, TCP_RST)));
        let rst = tcp_segment(1, 2, 100, 7, TCP_RST, 0);
        assert_eq!(rst_for(&rst), None, "never answer an RST");
    }

    #[test]
    fn ndp_helpers() {
        let a: Ipv6Addr = "fd00:1::10".parse().unwrap();
        assert_eq!(
            solicited_node(a),
            "ff02::1:ff00:10".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            multicast_mac(solicited_node(a)).to_string(),
            "33:33:ff:00:00:10"
        );
        let mac = MacAddr([2, 0, 0, 0, 0, 9]);
        let mut opts = vec![5, 1, 0, 0, 0, 0, 5, 220]; // an MTU option first
        opts.extend_from_slice(&ll_option(1, mac));
        assert_eq!(find_ll_option(&opts, 1), Some(mac));
        assert_eq!(find_ll_option(&opts, 2), None);
        assert_eq!(
            find_ll_option(&[1, 0, 1, 2], 1),
            None,
            "a zero length ends the walk"
        );
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 1024,
            rng_seed: proptest::test_runner::RngSeed::Fixed(1624),
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]

        /// The incremental update always equals a full recomputation (RFC 1624 fixed RFC 1141's
        /// -0 corner case; this would catch it).
        #[test]
        fn ttl_decrement_keeps_the_checksum_valid(
            ttl in 2u8..=255,
            proto in any::<u8>(),
            id in any::<u16>(),
            src in any::<u32>(),
            dst in any::<u32>(),
            tos in any::<u8>(),
            len in 0usize..64,
        ) {
            let mut p = ipv4(Ipv4Addr::from(src), Ipv4Addr::from(dst), proto, ttl, id, &vec![0xab; len]);
            p[1] = tos;
            p[10..12].copy_from_slice(&[0, 0]);
            let c = checksum(&p[..20]);
            p[10..12].copy_from_slice(&c.to_be_bytes());
            decrement_ttl_v4(&mut p);
            prop_assert_eq!(p[8], ttl - 1);
            prop_assert_eq!(checksum(&p[..20]), 0);
            let mut fresh = p[..20].to_vec();
            fresh[10] = 0;
            fresh[11] = 0;
            let full = checksum(&fresh);
            prop_assert_eq!(u16::from_be_bytes([p[10], p[11]]), full);
        }
    }
}
