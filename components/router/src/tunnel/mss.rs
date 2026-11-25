//! TCP MSS clamping: a SYN that crosses a tunnel gets its maximum segment size lowered to what
//! fits the tunnel's MTU, so neither end sends a segment the tunnel must refuse.
//!
//! Routers do this at tunnels because path MTU discovery is fragile; here it is needed: the
//! netstack's TCP does not react to ICMPv6 Packet Too Big or ICMP fragmentation needed, so a
//! connection whose segments are too big for the tunnel stalls on retransmissions.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::wire::{self, PROTO_TCP};

/// IPv6 header (no extension headers) plus a TCP header without options.
const V6_HEADERS: u16 = 60;
/// IPv4 header without options plus a TCP header without options.
const V4_HEADERS: u16 = 40;

/// Lowers the MSS option of a TCP SYN in IP packet `p` to `mtu` minus the IP and TCP headers,
/// and recomputes the TCP checksum. IPv6 packets whose TCP header follows the fixed header and
/// IPv4 packets that are not fragments; anything else, a SYN without an MSS option and one
/// whose MSS is small enough already are left as they are. Returns whether `p` changed.
pub fn clamp(p: &mut [u8], mtu: u16) -> bool {
    let (tcp_at, end, max) = match p.first().map(|b| b >> 4) {
        Some(6) if p.len() >= 40 && p[6] == PROTO_TCP => {
            let end = 40 + usize::from(u16::from_be_bytes([p[4], p[5]]));
            (40, end, mtu.saturating_sub(V6_HEADERS))
        }
        Some(4) if p.len() >= 20 && p[9] == PROTO_TCP => {
            let fragment = p[6] & 0x20 != 0 || u16::from_be_bytes([p[6] & 0x1f, p[7]]) != 0;
            if fragment {
                return false;
            }
            let end = usize::from(u16::from_be_bytes([p[2], p[3]]));
            (
                usize::from(p[0] & 0xf) * 4,
                end,
                mtu.saturating_sub(V4_HEADERS),
            )
        }
        _ => return false,
    };
    if end > p.len() || tcp_at + 20 > end {
        return false;
    }
    let (ip, tcp) = p[..end].split_at_mut(tcp_at);
    if tcp[13] & 0x02 == 0 {
        return false;
    }
    let options_end = (usize::from(tcp[12] >> 4) * 4).min(tcp.len());
    let mut i = 20;
    let mut at = None;
    while i < options_end {
        match tcp[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let Some(&len) = tcp.get(i + 1) else { break };
                let len = usize::from(len);
                if len < 2 || i + len > options_end {
                    break;
                }
                if kind == 2 && len == 4 {
                    at = Some(i + 2);
                    break;
                }
                i += len;
            }
        }
    }
    let Some(at) = at else { return false };
    if u16::from_be_bytes([tcp[at], tcp[at + 1]]) <= max {
        return false;
    }
    tcp[at..at + 2].copy_from_slice(&max.to_be_bytes());
    tcp[16..18].copy_from_slice(&[0, 0]);
    let pseudo = if ip[0] >> 4 == 6 {
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap_or([0; 16]));
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap_or([0; 16]));
        wire::pseudo_v6(src, dst, PROTO_TCP, tcp.len())
    } else {
        let src = Ipv4Addr::from(<[u8; 4]>::try_from(&ip[12..16]).unwrap_or([0; 4]));
        let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&ip[16..20]).unwrap_or([0; 4]));
        wire::pseudo_v4(src, dst, PROTO_TCP, tcp.len())
    };
    let c = wire::finish(wire::sum16(tcp, pseudo));
    tcp[16..18].copy_from_slice(&c.to_be_bytes());
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A TCP segment with `options`, its checksum filled in, inside an IPv6 or IPv4 packet.
    fn syn(v6: bool, flags: u8, options: &[u8]) -> Vec<u8> {
        let mut tcp = vec![0x30, 0x39, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0];
        tcp.push((((20 + options.len()) / 4) << 4) as u8);
        tcp.extend_from_slice(&[flags, 0xff, 0xff, 0, 0, 0, 0]);
        tcp.extend_from_slice(options);
        if v6 {
            let (s, d) = ("fd00:a::10".parse().unwrap(), "fd00:b::10".parse().unwrap());
            let c = wire::finish(wire::sum16(
                &tcp,
                wire::pseudo_v6(s, d, PROTO_TCP, tcp.len()),
            ));
            tcp[16..18].copy_from_slice(&c.to_be_bytes());
            wire::ipv6(s, d, PROTO_TCP, 64, &tcp)
        } else {
            let (s, d) = ("10.0.1.10".parse().unwrap(), "10.0.2.10".parse().unwrap());
            let c = wire::finish(wire::sum16(
                &tcp,
                wire::pseudo_v4(s, d, PROTO_TCP, tcp.len()),
            ));
            tcp[16..18].copy_from_slice(&c.to_be_bytes());
            wire::ipv4(s, d, PROTO_TCP, 64, 1, &tcp)
        }
    }

    fn mss_and_checksum_ok(p: &[u8]) -> (u16, bool) {
        let (at, pseudo) = if p[0] >> 4 == 6 {
            let s = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap());
            let d = Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap());
            (40, wire::pseudo_v6(s, d, PROTO_TCP, p.len() - 40))
        } else {
            let s = Ipv4Addr::from(<[u8; 4]>::try_from(&p[12..16]).unwrap());
            let d = Ipv4Addr::from(<[u8; 4]>::try_from(&p[16..20]).unwrap());
            (20, wire::pseudo_v4(s, d, PROTO_TCP, p.len() - 20))
        };
        let tcp = &p[at..];
        let i = tcp[20..].windows(2).position(|w| w == [2, 4]).unwrap() + 20;
        (
            u16::from_be_bytes([tcp[i + 2], tcp[i + 3]]),
            wire::finish(wire::sum16(tcp, pseudo)) == 0,
        )
    }

    #[test]
    fn a_syn_is_clamped_to_the_tunnel_mtu() {
        // MSS 1440 (an IPv6 host on a 1500-byte link) through a 1464-byte tunnel: 1404.
        let mut p = syn(true, 0x02, &[2, 4, 0x05, 0xa0, 1, 1, 4, 2]);
        assert!(clamp(&mut p, 1464));
        assert_eq!(mss_and_checksum_ok(&p), (1404, true));
        // Again: nothing to do.
        assert!(!clamp(&mut p, 1464));
        // IPv4, MSS 1460, after a NOP (the option at an odd offset): 1424.
        let mut p = syn(false, 0x12, &[1, 2, 4, 0x05, 0xb4, 1, 1, 1]);
        assert!(clamp(&mut p, 1464));
        assert_eq!(mss_and_checksum_ok(&p), (1424, true));
    }

    #[test]
    fn other_segments_are_left_alone() {
        // Not a SYN.
        let mut p = syn(true, 0x10, &[2, 4, 0x05, 0xa0]);
        assert!(!clamp(&mut p, 1280));
        // A SYN without an MSS option.
        let mut p = syn(true, 0x02, &[1, 1, 4, 2]);
        assert!(!clamp(&mut p, 1280));
        // A small MSS.
        let mut p = syn(true, 0x02, &[2, 4, 0x02, 0x00]);
        assert!(!clamp(&mut p, 1464));
        // A malformed option list ends the search.
        let mut p = syn(true, 0x02, &[3, 0, 2, 4, 0x05, 0xa0, 0, 0]);
        assert!(!clamp(&mut p, 1280));
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 1024,
            rng_seed: proptest::test_runner::RngSeed::Fixed(879),
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]

        #[test]
        fn arbitrary_packets_never_panic(mut d in proptest::collection::vec(any::<u8>(), 0..120), mtu in any::<u16>()) {
            let _ = clamp(&mut d, mtu);
        }

        #[test]
        fn clamped_syns_keep_a_valid_checksum(v6 in any::<bool>(), mss in 1000u16..9000, mtu in 1280u16..1500) {
            let [hi, lo] = mss.to_be_bytes();
            let mut p = syn(v6, 0x02, &[2, 4, hi, lo]);
            let changed = clamp(&mut p, mtu);
            let (got, ok) = mss_and_checksum_ok(&p);
            prop_assert!(ok);
            let max = mtu - if v6 { 60 } else { 40 };
            prop_assert_eq!(got, mss.min(max));
            prop_assert_eq!(changed, mss > max);
        }
    }
}
