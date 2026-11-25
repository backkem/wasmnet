//! Connection tracking, shared by address translation ([`crate::nat`]) and the packet filter
//! ([`crate::filter`]): a packet's flow tuple, a connection's TCP state and its idle timeout.
//!
//! * [`Tuple`]: what identifies a packet's flow, for IPv4 and IPv6: protocol, addresses, ports
//!   (TCP, UDP) or the echo identifier (ICMP, ICMPv6), and for an ICMP error the flow of the
//!   packet it quotes.
//! * [`Track`]: one connection's last activity and TCP state, and its deadline under
//!   [`Timeouts`]: UDP 300 s (RFC 4787 REQ-5), TCP established 7440 s and transitory 240 s
//!   (RFC 5382 REQ-5), ICMP echo 60 s (RFC 5508 REQ-1). A TCP connection is established once
//!   both sides sent a SYN, and transitory before that and after a FIN or an RST.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::Ipv6Slice;

use crate::wire::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, TCP_FIN, TCP_RST, TCP_SYN};

const S: u64 = 1_000_000_000;

/// Idle timeouts in virtual nanoseconds (`conntrack.*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    pub udp: u64,
    pub tcp_established: u64,
    pub tcp_transitory: u64,
    pub icmp: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            udp: 300 * S,
            tcp_established: 7440 * S,
            tcp_transitory: 240 * S,
            icmp: 60 * S,
        }
    }
}

/// One connection's state: when it last saw a packet, and for TCP which side sent a SYN or a
/// FIN and whether an RST went by. Side 0 and side 1 are the two directions (the inside and
/// the outside for a NAT session, the original and the reply direction for a filter flow).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Track {
    pub last: u64,
    syn: [bool; 2],
    fin: [bool; 2],
    rst: bool,
}

impl Track {
    pub fn new(now: u64) -> Self {
        Self {
            last: now,
            ..Self::default()
        }
    }

    /// A packet from `side` (0 or 1) at `now`; `flags` are its TCP flags, if it is TCP.
    pub fn seen(&mut self, now: u64, side: usize, flags: Option<u8>) {
        self.last = self.last.max(now);
        if let Some(f) = flags {
            let side = side.min(1);
            self.syn[side] |= f & TCP_SYN != 0;
            self.fin[side] |= f & TCP_FIN != 0;
            self.rst |= f & TCP_RST != 0;
        }
    }

    /// Both sides sent a SYN, and neither a FIN nor an RST went by.
    pub fn established(&self) -> bool {
        self.syn[0] && self.syn[1] && !self.fin[0] && !self.fin[1] && !self.rst
    }

    /// When this connection expires, for a flow of protocol `proto` (an IP protocol number).
    pub fn deadline(&self, proto: u8, t: &Timeouts) -> u64 {
        let idle = match proto {
            PROTO_TCP if self.established() => t.tcp_established,
            PROTO_TCP => t.tcp_transitory,
            PROTO_UDP => t.udp,
            _ => t.icmp,
        };
        self.last.saturating_add(idle)
    }

    /// The TCP state's name, for listings: `established`, `opening` or `closing`.
    pub fn tcp_state(&self) -> &'static str {
        if self.established() {
            "established"
        } else if self.fin[0] || self.fin[1] || self.rst {
            "closing"
        } else {
            "opening"
        }
    }
}

/// A flow's key: protocol, source address and port, destination address and port. For ICMP
/// echo the identifier sits in the requester's port (an echo request is `(id, 0)`, a reply
/// `(0, id)`), so a reply's reversed key is its request's key.
pub type FlowKey = (u8, IpAddr, u16, IpAddr, u16);

/// The key of the opposite direction.
pub fn reverse((p, a, ap, b, bp): FlowKey) -> FlowKey {
    (p, b, bp, a, ap)
}

/// What kind of packet a [`Tuple`] describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// TCP or UDP with its ports, an ICMP echo request or reply, or another protocol.
    Plain,
    /// An ICMP or ICMPv6 error, with the flow of the packet it quotes (as that packet was sent).
    Error(FlowKey),
    /// A fragment: no transport header to read (ports are zero).
    Fragment,
}

/// A packet's flow, as connection tracking sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tuple {
    pub key: FlowKey,
    /// Whether the key holds TCP/UDP ports.
    pub ports: bool,
    /// TCP flags, for TCP.
    pub flags: Option<u8>,
    pub kind: Kind,
}

impl Tuple {
    pub fn proto(&self) -> u8 {
        self.key.0
    }

    pub fn src(&self) -> IpAddr {
        self.key.1
    }

    pub fn dst(&self) -> IpAddr {
        self.key.3
    }

    pub fn dport(&self) -> Option<u16> {
        self.ports.then_some(self.key.4)
    }
}

/// The tuple of an IPv4 or IPv6 packet (starting at its IP header; the router has already
/// checked its lengths). `None` when the transport header it needs is truncated.
pub fn tuple(packet: &[u8]) -> Option<Tuple> {
    match packet.first()? >> 4 {
        4 => tuple_v4(packet, false),
        6 => tuple_v6(packet, false),
        _ => None,
    }
}

fn v4_addrs(p: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let a = p.get(12..20)?;
    Some((
        IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])),
        IpAddr::V4(Ipv4Addr::new(a[4], a[5], a[6], a[7])),
    ))
}

/// `quoted`: the packet is the quote inside an ICMP error, so it may be truncated after its
/// first 8 transport bytes, and an error inside it is not looked into.
fn tuple_v4(p: &[u8], quoted: bool) -> Option<Tuple> {
    let ihl = usize::from(*p.first()? & 0x0f) * 4;
    let (src, dst) = v4_addrs(p)?;
    let proto = *p.get(9)?;
    let frag = p.get(6..8)?;
    let fragment = frag[0] & 0x20 != 0 || u16::from_be_bytes([frag[0] & 0x1f, frag[1]]) != 0;
    let l4 = p.get(ihl..)?;
    if fragment {
        return Some(Tuple {
            key: (proto, src, 0, dst, 0),
            ports: false,
            flags: None,
            kind: Kind::Fragment,
        });
    }
    transport(
        proto,
        src,
        dst,
        l4,
        quoted,
        PROTO_ICMP,
        (8, 0),
        &[3, 4, 5, 11, 12],
    )
}

fn tuple_v6(p: &[u8], quoted: bool) -> Option<Tuple> {
    let (src, dst) = (
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(p.get(8..24)?).ok()?)),
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(p.get(24..40)?).ok()?)),
    );
    let (proto, fragmented, l4) = if quoted {
        // A quote may be cut anywhere: read only a transport header right after the fixed one.
        (*p.get(6)?, false, p.get(40..)?)
    } else {
        let s = Ipv6Slice::from_slice(p).ok()?;
        let up = s.payload();
        (up.ip_number.0, up.fragmented, up.payload)
    };
    if fragmented {
        return Some(Tuple {
            key: (proto, src, 0, dst, 0),
            ports: false,
            flags: None,
            kind: Kind::Fragment,
        });
    }
    transport(
        proto,
        src,
        dst,
        l4,
        quoted,
        PROTO_ICMPV6,
        (128, 129),
        &[1, 2, 3, 4],
    )
}

/// The transport part of a tuple. `icmp`: the ICMP protocol number of the family, `echo`: its
/// echo request and reply types, `errors`: its error types.
#[allow(clippy::too_many_arguments)]
fn transport(
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    l4: &[u8],
    quoted: bool,
    icmp: u8,
    echo: (u8, u8),
    errors: &[u8],
) -> Option<Tuple> {
    let word = |at: usize| -> Option<u16> {
        let b = l4.get(at..at + 2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    };
    let plain = |key, ports, flags| {
        Some(Tuple {
            key,
            ports,
            flags,
            kind: Kind::Plain,
        })
    };
    match proto {
        PROTO_TCP | PROTO_UDP => {
            let (sport, dport) = (word(0)?, word(2)?);
            let flags = if proto == PROTO_TCP {
                // A quote carries only 8 bytes of the segment: no flags to read.
                if quoted { None } else { Some(*l4.get(13)?) }
            } else {
                None
            };
            plain((proto, src, sport, dst, dport), true, flags)
        }
        p if p == icmp => {
            let t = *l4.first()?;
            if t == echo.0 {
                plain((proto, src, word(4)?, dst, 0), false, None)
            } else if t == echo.1 {
                plain((proto, src, 0, dst, word(4)?), false, None)
            } else if errors.contains(&t) && !quoted {
                let inner = l4.get(8..)?;
                let quoted_tuple = if icmp == PROTO_ICMP {
                    tuple_v4(inner, true)?
                } else {
                    tuple_v6(inner, true)?
                };
                Some(Tuple {
                    key: (proto, src, 0, dst, 0),
                    ports: false,
                    flags: None,
                    kind: Kind::Error(quoted_tuple.key),
                })
            } else {
                plain((proto, src, 0, dst, 0), false, None)
            }
        }
        _ => plain((proto, src, 0, dst, 0), false, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{self, TCP_ACK};

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn tcp_state_and_deadlines() {
        let t = Timeouts::default();
        let mut c = Track::new(0);
        c.seen(0, 0, Some(TCP_SYN));
        assert!(!c.established());
        assert_eq!(c.deadline(PROTO_TCP, &t), 240 * S);
        c.seen(S, 1, Some(TCP_SYN | TCP_ACK));
        assert!(c.established());
        assert_eq!(c.deadline(PROTO_TCP, &t), S + 7440 * S);
        c.seen(2 * S, 0, Some(TCP_FIN | TCP_ACK));
        assert_eq!(c.tcp_state(), "closing");
        assert_eq!(c.deadline(PROTO_TCP, &t), 2 * S + 240 * S);
        let mut u = Track::new(5);
        u.seen(7, 1, None);
        assert_eq!(u.deadline(PROTO_UDP, &t), 7 + 300 * S);
        assert_eq!(u.deadline(PROTO_ICMP, &t), 7 + 60 * S);
    }

    #[test]
    fn tuples_of_transport_echo_and_errors() {
        let (a, b) = (v4("10.0.1.10"), v4("10.0.2.10"));
        let udp = wire::ipv4(a, b, PROTO_UDP, 64, 1, &wire::udp_v4(a, b, 4000, 53, b"q"));
        let t = tuple(&udp).unwrap();
        assert_eq!(t.key, (PROTO_UDP, a.into(), 4000, b.into(), 53));
        assert_eq!(t.dport(), Some(53));
        let echo = wire::ipv4(
            a,
            b,
            PROTO_ICMP,
            64,
            2,
            &wire::icmpv4(8, 0, [0, 9, 0, 1], b""),
        );
        let reply = wire::ipv4(
            b,
            a,
            PROTO_ICMP,
            64,
            3,
            &wire::icmpv4(0, 0, [0, 9, 0, 1], b""),
        );
        let (req, rep) = (tuple(&echo).unwrap(), tuple(&reply).unwrap());
        assert_eq!(reverse(rep.key), req.key, "a reply reverses to its request");
        let err = wire::ipv4(
            b,
            a,
            PROTO_ICMP,
            64,
            4,
            &wire::icmpv4(3, 3, [0; 4], &udp[..28]),
        );
        assert_eq!(tuple(&err).unwrap().kind, Kind::Error(t.key));
        let mut frag = udp.clone();
        frag[6] = 0x20;
        assert_eq!(tuple(&frag).unwrap().kind, Kind::Fragment);
        assert_eq!(tuple(&udp[..22]), None, "truncated ports");
        let v6a: Ipv6Addr = "fd00:1::10".parse().unwrap();
        let v6b: Ipv6Addr = "fd00:2::10".parse().unwrap();
        let seg = wire::tcp_segment(5000, 80, 1, 0, TCP_SYN, 0);
        let p6 = wire::ipv6(v6a, v6b, PROTO_TCP, 64, &seg);
        let t6 = tuple(&p6).unwrap();
        assert_eq!(t6.key, (PROTO_TCP, v6a.into(), 5000, v6b.into(), 80));
        assert_eq!(t6.flags, Some(TCP_SYN));
    }
}
