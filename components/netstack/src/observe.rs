//! Classifies frames the netstack sends or receives, for diagnostics and timing only.
//!
//! smoltcp keeps its neighbor cache and multicast timers private, and its ICMP socket does not
//! say when a queued echo request actually left. So the netstack watches its own frames:
//!
//! * an outgoing ARP request or Neighbor Solicitation starts a resolution, and the matching
//!   incoming ARP packet or Neighbor Advertisement ends it (`arp-resolved` / `ndp-resolved`);
//! * an incoming IGMP or MLD query opens the multicast polling window ([`crate::mcast`]);
//! * an incoming ICMP error is reported (`icmp-error-received`), fails a TCP connect still in
//!   SYN-SENT ([`crate::tcp`]), lowers a TCP connection's send MSS when it is a "fragmentation
//!   needed" or "packet too big" (path MTU discovery, [`crate::tcp::TcpSockets::path_mtu`]),
//!   and is queued for a UDP socket that asked for its errors
//!   (`wasmnet:sockets-ext/udp`, [`crate::udp`]). smoltcp itself ignores ICMP errors for TCP and
//!   UDP sockets.
//!
//! The parser is a few bounds-checked byte reads. It never panics, and anything it does not
//! recognise is [`Observed::Other`]. It never changes what smoltcp does with the frame.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wasmnet_wire::MacAddr;

/// What a frame is, as far as the netstack's diagnostics care.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    Arp {
        reply: bool,
        sender_mac: MacAddr,
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    },
    NeighborSolicit {
        target: Ipv6Addr,
    },
    /// `mac` is the target link-layer address option, or else the Ethernet source.
    NeighborAdvert {
        target: Ipv6Addr,
        mac: MacAddr,
    },
    Echo {
        reply: bool,
        src: IpAddr,
        dst: IpAddr,
        ident: u16,
        seq: u16,
        /// The IPv4 TTL or IPv6 hop limit it travelled with (a ping's `ttl=`).
        hop_limit: u8,
    },
    /// An IGMP membership query or an MLD query, with its maximum response delay.
    MulticastQuery {
        max_resp_ns: u64,
    },
    /// An ICMP error: ICMPv4 destination unreachable / time exceeded / parameter problem,
    /// ICMPv6 types 1 to 4, with what its quoted header says about the packet it is about.
    IcmpError(IcmpError),
    Other,
}

/// An ICMP error and the packet it reports on (from its quoted header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpError {
    pub v6: bool,
    /// Who reported it (the router or host that sent the ICMP message).
    pub from: IpAddr,
    /// The ICMP message's own destination (it must be one of our addresses to count).
    pub to: IpAddr,
    pub icmp_type: u8,
    pub code: u8,
    /// The quoted packet: its protocol, addresses and (TCP/UDP) ports. For a quoted ICMP echo
    /// request `sport` is its identifier and `dport` its sequence number; 0
    /// otherwise.
    pub proto: u8,
    pub orig_src: IpAddr,
    pub orig_dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    /// The quoted TCP segment's sequence number (0 if the quote is not TCP or too short).
    pub seq: u32,
    /// The MTU a "fragmentation needed" (ICMPv4 type 3 code 4) or "packet too big" (ICMPv6
    /// type 2) reports for the next hop; 0 for any other error, or when the router sent none.
    pub mtu: u32,
}

impl IcmpError {
    /// A stable name, the same for both families where they mean the same (as the router's
    /// `icmp-error-sent`).
    pub fn name(&self) -> &'static str {
        match (self.v6, self.icmp_type, self.code) {
            (false, 11, _) | (true, 3, _) => "time-exceeded",
            (false, 3, 0) | (true, 1, 0) => "net-unreachable",
            (false, 3, 1) | (true, 1, 3) => "host-unreachable",
            (false, 3, 2) => "protocol-unreachable",
            (false, 3, 3) | (true, 1, 4) => "port-unreachable",
            (false, 3, 4) => "frag-needed",
            (false, 3, 9 | 10 | 13) | (true, 1, 1) => "admin-prohibited",
            (true, 1, 2) => "beyond-scope",
            (true, 2, _) => "packet-too-big",
            (false, 12, _) | (true, 4, _) => "parameter-problem",
            _ => "unreachable",
        }
    }

    /// Whether it means "this destination cannot be reached" (a connect in SYN-SENT gives up,
    /// like Linux's `tcp_v4_err`): destination unreachable except fragmentation needed, and
    /// time exceeded. Packet too big and parameter problems do not.
    pub fn is_hard(&self) -> bool {
        match (self.v6, self.icmp_type) {
            (false, 3) => self.code != 4,
            (false, 11) | (true, 1) | (true, 3) => true,
            _ => false,
        }
    }
}

/// The quoted packet inside an ICMP error body (after the 8-byte ICMP header).
fn quoted(v6: bool, inner: &[u8]) -> Option<(u8, IpAddr, IpAddr, u16, u16, u32)> {
    let (proto, src, dst, l4): (u8, IpAddr, IpAddr, usize) = if v6 {
        (
            *inner.get(6)?,
            v6_at(inner, 8)?.into(),
            v6_at(inner, 24)?.into(),
            40,
        )
    } else {
        let ihl = usize::from(inner.first()? & 0x0f) * 4;
        (
            *inner.get(9)?,
            v4_at(inner, 12)?.into(),
            v4_at(inner, 16)?.into(),
            ihl,
        )
    };
    let (sport, dport) = match proto {
        6 | 17 => (u16_at(inner, l4)?, u16_at(inner, l4 + 2)?),
        // An echo request (ICMPv4 type 8, ICMPv6 type 128): identifier and sequence number.
        1 | 58 if inner.get(l4) == Some(&if v6 { 128 } else { 8 }) => {
            (u16_at(inner, l4 + 4)?, u16_at(inner, l4 + 6)?)
        }
        _ => (0, 0),
    };
    // A TCP quote carries the sequence number in its first 8 bytes, the least a router quotes.
    let seq = if proto == 6 {
        inner
            .get(l4 + 4..l4 + 8)
            .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    } else {
        0
    };
    Some((proto, src, dst, sport, dport, seq))
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn v4_at(b: &[u8], at: usize) -> Option<Ipv4Addr> {
    let o: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
    Some(Ipv4Addr::from(o))
}

fn v6_at(b: &[u8], at: usize) -> Option<Ipv6Addr> {
    let o: [u8; 16] = b.get(at..at + 16)?.try_into().ok()?;
    Some(Ipv6Addr::from(o))
}

/// The ones'-complement sum of `parts` (each padded to a whole 16-bit word), folded: `0xffff`
/// over a header or message that carries its correct Internet checksum.
fn sum(parts: &[&[u8]]) -> u16 {
    let mut s: u32 = 0;
    for part in parts {
        for w in part.chunks(2) {
            s += u32::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]));
            s = (s & 0xffff) + (s >> 16);
        }
    }
    s as u16
}

const MS: u64 = 1_000_000;

/// Classifies one Ethernet frame (no FCS, no 802.1Q tag; padding is fine).
pub fn observe(frame: &[u8]) -> Observed {
    parse(frame).unwrap_or(Observed::Other)
}

fn parse(frame: &[u8]) -> Option<Observed> {
    let eth_src = MacAddr::from_slice(frame.get(6..12)?)?;
    let payload = frame.get(14..)?;
    match u16_at(frame, 12)? {
        0x0806 => arp(payload),
        0x0800 => ipv4(payload),
        0x86dd => ipv6(payload, eth_src),
        _ => None,
    }
}

fn arp(p: &[u8]) -> Option<Observed> {
    // Ethernet (1) / IPv4 (0x0800), 6-byte and 4-byte addresses.
    if u16_at(p, 0)? != 1 || u16_at(p, 2)? != 0x0800 || p.get(4..6)? != [6, 4] {
        return None;
    }
    let reply = match u16_at(p, 6)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    Some(Observed::Arp {
        reply,
        sender_mac: MacAddr::from_slice(p.get(8..14)?)?,
        sender_ip: v4_at(p, 14)?,
        target_ip: v4_at(p, 24)?,
    })
}

fn ipv4(p: &[u8]) -> Option<Observed> {
    let ihl = usize::from(p.first()? & 0x0f) * 4;
    if p.first()? >> 4 != 4 || ihl < 20 {
        return None;
    }
    // Ignore Ethernet padding: the datagram ends at the total length.
    let total = usize::from(u16_at(p, 2)?).min(p.len());
    let (src, dst) = (v4_at(p, 12)?, v4_at(p, 16)?);
    let body = p.get(ihl..total)?;
    match *p.get(9)? {
        1 if matches!(body.first(), Some(3 | 11 | 12)) => {
            // Acted on only when smoltcp would accept it too: a valid IPv4 header and ICMP
            // checksum (RFC 791, RFC 792).
            if sum(&[p.get(..ihl)?]) != 0xffff || sum(&[body]) != 0xffff {
                return None;
            }
            let (proto, orig_src, orig_dst, sport, dport, seq) = quoted(false, body.get(8..)?)?;
            // RFC 1191: the next-hop MTU in the low 16 bits of the unused word.
            let mtu = if body[0] == 3 && *body.get(1)? == 4 {
                u32::from(u16_at(body, 6)?)
            } else {
                0
            };
            Some(Observed::IcmpError(IcmpError {
                v6: false,
                from: src.into(),
                to: dst.into(),
                icmp_type: body[0],
                code: *body.get(1)?,
                proto,
                orig_src,
                orig_dst,
                sport,
                dport,
                seq,
                mtu,
            }))
        }
        1 => {
            let t = *body.first()?;
            (t == 0 || t == 8).then_some(())?;
            Some(Observed::Echo {
                reply: t == 0,
                src: src.into(),
                dst: dst.into(),
                ident: u16_at(body, 4)?,
                seq: u16_at(body, 6)?,
                hop_limit: *p.get(8)?,
            })
        }
        2 if *body.first()? == 0x11 => {
            // Max Resp Time in 1/10 s. 0 is IGMPv1, which means 10 s (RFC 2236 §4). IGMPv3
            // (longer than 8 bytes) uses a floating-point code from 128 on.
            let code = u64::from(*body.get(1)?);
            let tenths = match code {
                0 => 100,
                c if c >= 128 && body.len() > 8 => (c & 0x0f | 0x10) << ((c >> 4 & 0x07) + 3),
                c => c,
            };
            Some(Observed::MulticastQuery {
                max_resp_ns: tenths * 100 * MS,
            })
        }
        _ => None,
    }
}

fn ipv6(p: &[u8], eth_src: MacAddr) -> Option<Observed> {
    if p.first()? >> 4 != 6 {
        return None;
    }
    let (src, dst) = (v6_at(p, 8)?, v6_at(p, 24)?);
    let end = (40 + usize::from(u16_at(p, 4)?)).min(p.len());
    let mut next = *p.get(6)?;
    let mut at = 40;
    // Skip hop-by-hop (MLD carries a Router Alert), routing and destination options headers.
    while matches!(next, 0 | 43 | 60) {
        next = *p.get(at)?;
        at += (usize::from(*p.get(at + 1)?) + 1) * 8;
    }
    if next != 58 {
        return None;
    }
    let icmp = p.get(at..end)?;
    match *icmp.first()? {
        t @ 1..=4 => {
            // Acted on only with a valid ICMPv6 checksum over the pseudo-header (RFC 4443 §2.3).
            let len = u32::try_from(icmp.len()).ok()?.to_be_bytes();
            let pseudo = [
                &src.octets()[..],
                &dst.octets()[..],
                &len[..],
                &[0, 0, 0, 58][..],
            ];
            if sum(&[&pseudo[..], &[icmp]].concat()) != 0xffff {
                return None;
            }
            let (proto, orig_src, orig_dst, sport, dport, seq) = quoted(true, icmp.get(8..)?)?;
            // RFC 4443: a packet too big carries the MTU in its second word.
            let mtu = if t == 2 {
                u32::from_be_bytes(icmp.get(4..8)?.try_into().ok()?)
            } else {
                0
            };
            Some(Observed::IcmpError(IcmpError {
                v6: true,
                from: src.into(),
                to: dst.into(),
                icmp_type: t,
                code: *icmp.get(1)?,
                proto,
                orig_src,
                orig_dst,
                sport,
                dport,
                seq,
                mtu,
            }))
        }
        t @ (128 | 129) => Some(Observed::Echo {
            reply: t == 129,
            src: src.into(),
            dst: dst.into(),
            ident: u16_at(icmp, 4)?,
            seq: u16_at(icmp, 6)?,
            hop_limit: *p.get(7)?,
        }),
        130 => {
            // MLDv1 Maximum Response Delay in ms; MLDv2 codes from 32768 are floating point.
            let code = u64::from(u16_at(icmp, 4)?);
            let ms = if code >= 32_768 && icmp.len() > 24 {
                (code & 0x0fff | 0x1000) << ((code >> 12 & 0x07) + 3)
            } else {
                code
            };
            Some(Observed::MulticastQuery {
                max_resp_ns: ms * MS,
            })
        }
        135 => Some(Observed::NeighborSolicit {
            target: v6_at(icmp, 8)?,
        }),
        136 => {
            let target = v6_at(icmp, 8)?;
            // Options from byte 24: type, length in units of 8 bytes, value.
            let mut mac = eth_src;
            let mut o = 24;
            while let (Some(&kind), Some(&len)) = (icmp.get(o), icmp.get(o + 1)) {
                if len == 0 {
                    break;
                }
                if kind == 2
                    && let Some(m) = icmp.get(o + 2..o + 8).and_then(MacAddr::from_slice)
                {
                    mac = m;
                }
                o += usize::from(len) * 8;
            }
            Some(Observed::NeighborAdvert { target, mac })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 6] = [2, 0, 0, 0, 0, 1];

    fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&A);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        p.extend_from_slice(&[next, 255]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn arp_request_padded_to_60_bytes() {
        let mut p = vec![0, 1, 8, 0, 6, 4, 0, 1];
        p.extend_from_slice(&A);
        p.extend_from_slice(&[10, 0, 0, 1]);
        p.extend_from_slice(&[0; 6]);
        p.extend_from_slice(&[10, 0, 0, 2]);
        let mut f = eth(0x0806, &p);
        f.resize(60, 0);
        assert_eq!(
            observe(&f),
            Observed::Arp {
                reply: false,
                sender_mac: MacAddr::new(A),
                sender_ip: Ipv4Addr::new(10, 0, 0, 1),
                target_ip: Ipv4Addr::new(10, 0, 0, 2),
            }
        );
    }

    #[test]
    fn icmpv4_echo_and_igmp_query() {
        let mut ip = vec![
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        ip.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 7]);
        let mut f = eth(0x0800, &ip);
        f.resize(60, 0xee);
        assert_eq!(
            observe(&f),
            Observed::Echo {
                reply: false,
                src: Ipv4Addr::new(10, 0, 0, 1).into(),
                dst: Ipv4Addr::new(10, 0, 0, 2).into(),
                ident: 0x1234,
                seq: 7,
                hop_limit: 64,
            }
        );
        let mut ip = vec![
            0x45, 0, 0, 28, 0, 0, 0, 0, 1, 2, 0, 0, 10, 0, 0, 1, 224, 0, 0, 1,
        ];
        ip.extend_from_slice(&[0x11, 100, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            observe(&eth(0x0800, &ip)),
            Observed::MulticastQuery {
                max_resp_ns: 10_000 * MS
            }
        );
    }

    #[test]
    fn ndp_echo6_and_mld_query_behind_hop_by_hop() {
        let (a, b): (Ipv6Addr, Ipv6Addr) = ("fe80::1".parse().unwrap(), "fe80::2".parse().unwrap());
        let mut na = vec![136, 0, 0, 0, 0x60, 0, 0, 0];
        na.extend_from_slice(&b.octets());
        na.extend_from_slice(&[2, 1, 2, 0, 0, 0, 0, 9]);
        assert_eq!(
            observe(&eth(0x86dd, &ipv6_packet(b, a, 58, &na))),
            Observed::NeighborAdvert {
                target: b,
                mac: MacAddr::new([2, 0, 0, 0, 0, 9])
            }
        );
        let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
        ns.extend_from_slice(&b.octets());
        assert_eq!(
            observe(&eth(0x86dd, &ipv6_packet(a, b, 58, &ns))),
            Observed::NeighborSolicit { target: b }
        );
        let echo = [129, 0, 0, 0, 0, 5, 0, 2];
        assert_eq!(
            observe(&eth(0x86dd, &ipv6_packet(b, a, 58, &echo))),
            Observed::Echo {
                reply: true,
                src: b.into(),
                dst: a.into(),
                ident: 5,
                seq: 2,
                hop_limit: 255,
            }
        );
        // Hop-by-hop (Router Alert) then an MLDv1 query, max delay 2500 ms.
        let mut hbh = vec![58, 0, 5, 2, 0, 0, 1, 0];
        hbh.extend_from_slice(&[130, 0, 0, 0, 0x09, 0xc4, 0, 0]);
        hbh.extend_from_slice(&[0; 16]);
        assert_eq!(
            observe(&eth(0x86dd, &ipv6_packet(a, b, 0, &hbh))),
            Observed::MulticastQuery {
                max_resp_ns: 2_500 * MS
            }
        );
    }

    #[test]
    fn icmp_errors_and_their_quoted_headers() {
        // Time exceeded from 10.0.1.1 about UDP 10.0.1.10:49152 -> 10.0.3.10:33434.
        let mut quote = vec![
            0x45, 0, 0, 36, 0, 0, 0, 0, 1, 17, 0, 0, 10, 0, 1, 10, 10, 0, 3, 10,
        ];
        quote.extend_from_slice(&[0xc0, 0x00, 0x82, 0x9a, 0, 16, 0, 0]);
        let mut ip = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 1, 1, 10, 0, 1, 10,
        ];
        ip.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]);
        ip.extend_from_slice(&quote);
        let total = ip.len() as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        let c = !sum(&[&ip[20..]]);
        ip[22..24].copy_from_slice(&c.to_be_bytes());
        let c = !sum(&[&ip[..20]]);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        let Observed::IcmpError(e) = observe(&eth(0x0800, &ip)) else {
            panic!("not an ICMP error")
        };
        // A bad header or ICMP checksum: smoltcp drops it, so it is not acted on either.
        for at in [11, 23] {
            let mut bad = ip.clone();
            bad[at] ^= 1;
            assert_eq!(observe(&eth(0x0800, &bad)), Observed::Other, "{at}");
        }
        assert_eq!((e.v6, e.icmp_type, e.code, e.proto), (false, 11, 0, 17));
        assert_eq!(e.from, IpAddr::from([10, 0, 1, 1]));
        assert_eq!(
            (e.orig_src, e.orig_dst),
            (IpAddr::from([10, 0, 1, 10]), IpAddr::from([10, 0, 3, 10]))
        );
        assert_eq!((e.sport, e.dport), (49152, 33434));
        assert_eq!(e.name(), "time-exceeded");
        assert!(e.is_hard());
        // ICMPv6 destination unreachable (address unreachable) about TCP.
        let (r, a, b): (Ipv6Addr, Ipv6Addr, Ipv6Addr) = (
            "fd00:2::1".parse().unwrap(),
            "fd00:2::20".parse().unwrap(),
            "fd00:1::99".parse().unwrap(),
        );
        let mut inner = ipv6_packet(a, b, 6, &[0xc0, 0x01, 0, 80, 0, 0, 0, 0]);
        let mut icmp = vec![1, 3, 0, 0, 0, 0, 0, 0];
        icmp.append(&mut inner);
        let len = (icmp.len() as u32).to_be_bytes();
        let c = !sum(&[
            &r.octets()[..],
            &a.octets()[..],
            &len[..],
            &[0, 0, 0, 58],
            &icmp,
        ]);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let mut bad = icmp.clone();
        bad[1] = 4;
        assert_eq!(
            observe(&eth(0x86dd, &ipv6_packet(r, a, 58, &bad))),
            Observed::Other
        );
        let Observed::IcmpError(e) = observe(&eth(0x86dd, &ipv6_packet(r, a, 58, &icmp))) else {
            panic!("not an ICMPv6 error")
        };
        assert_eq!((e.v6, e.proto, e.sport, e.dport), (true, 6, 49153, 80));
        assert_eq!(e.name(), "host-unreachable");
        let too_big = IcmpError { icmp_type: 2, ..e };
        assert!(!too_big.is_hard());
    }

    #[test]
    fn truncations_never_panic() {
        let mut ip = vec![
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        ip.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 7]);
        let f = eth(0x0800, &ip);
        for n in 0..f.len() {
            assert_eq!(observe(&f[..n]), Observed::Other, "{n}");
        }
        // A hop-by-hop length that runs off the end.
        let bad = ipv6_packet(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 0, &[58, 200]);
        assert_eq!(observe(&eth(0x86dd, &bad)), Observed::Other);
    }
}
