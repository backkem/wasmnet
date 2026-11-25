//! Static routes and the route lookup: which port a packet to a destination leaves by.
//!
//! The netstack is a host, not a router: it never forwards between its ports. The table only
//! picks the outgoing port for what the node itself sends. It holds, in this order:
//!
//! 1. a **connected route** per address of every port (its prefix, on-link; every port's IPv6
//!    link-local address brings `fe80::/64`), as the addresses are right now (a DHCP lease adds
//!    and removes its own);
//! 2. the **static routes** of the `routes` key, in the order listed, then the default routes of
//!    the gateway keys (`ipv4-gateway`, `port<N>.ipv6-gateway`, ...), port by port;
//! 3. the **default route of each DHCP lease** that names a router, port by port.
//!
//! The lookup is a longest-prefix match ([`longest_match`]); among routes of the same length the
//! first in that order wins, so a connected route beats a static one and the lowest port wins a
//! tie between ports. The next hop inside the chosen port is smoltcp's: each port's smoltcp
//! interface holds that port's static routes and DHCP default, and sends on-link what lies in one
//! of its own prefixes.

use std::net::IpAddr;

use crate::config::{Cidr, PortConfig};

/// The most items `routes` may list.
pub const MAX_ROUTES: usize = 32;

/// One static route: `dst/prefix` via the next hop `via`, out of `port`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticRoute {
    /// The prefix's network address (no host bits set).
    pub dst: IpAddr,
    pub prefix: u8,
    /// The next hop: a unicast address of the destination's family.
    pub via: IpAddr,
    /// The port it leaves by (0 is `eth0`).
    pub port: usize,
}

impl StaticRoute {
    /// The route as the config writes it: `10.0.3.0/24 via 10.0.2.2 port 1`.
    pub fn describe(&self) -> String {
        let dst = if self.prefix == 0 {
            "default".to_owned()
        } else {
            format!("{}/{}", self.dst, self.prefix)
        };
        format!("{dst} via {} port {}", self.via, self.port)
    }
}

/// Whether `ip` lies inside `net/prefix` (always false across families).
pub fn contains(net: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix.min(32)))
            };
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix.min(128)))
            };
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

/// `ip` with every bit past `prefix` cleared.
pub fn network(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix.min(32)))
            };
            IpAddr::from((u32::from(a) & mask).to_be_bytes())
        }
        IpAddr::V6(a) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix.min(128)))
            };
            IpAddr::from((u128::from(a) & mask).to_be_bytes())
        }
    }
}

/// The longest-prefix match: the port of the first candidate `(network, prefix, port)` with the
/// longest prefix that contains `dst`, or `None` if none does.
pub fn longest_match(
    candidates: impl IntoIterator<Item = (IpAddr, u8, usize)>,
    dst: IpAddr,
) -> Option<usize> {
    let mut best: Option<(u8, usize)> = None;
    for (net, prefix, port) in candidates {
        if contains(net, prefix, dst) && best.is_none_or(|(len, _)| prefix > len) {
            best = Some((prefix, port));
        }
    }
    best.map(|(_, port)| port)
}

fn is_link_local_v6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80)
}

fn unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => !(a.is_unspecified() || a.is_multicast() || a.is_broadcast()),
        IpAddr::V6(a) => !(a.is_unspecified() || a.is_multicast()),
    }
}

/// The static prefixes of a port (DHCP's are not known before the lease).
fn prefixes(p: &PortConfig) -> impl Iterator<Item = (IpAddr, u8)> {
    let v4 = p
        .ipv4
        .map(|Cidr { addr, prefix }| (IpAddr::V4(addr), prefix));
    let v6 = p
        .ipv6
        .map(|Cidr { addr, prefix }| (IpAddr::V6(addr), prefix));
    v4.into_iter().chain(v6)
}

/// Parses one item of `routes` against the ports:
///
/// ```text
/// <prefix> via <next-hop> [port <n>]
/// default via <next-hop> [port <n>]
/// ```
///
/// `default` is `0.0.0.0/0` or `::/0` by the family of the next hop. The prefix has no host
/// bits set. The next hop is a unicast address of the prefix's family. Without `port`, the next
/// hop must lie inside a port's static prefix (the lowest such port), unless the node has a
/// single port; a link-local next hop on a node with several ports needs `port`. A route inside
/// a static prefix of its own port is refused: smoltcp sends on-link what lies in one of the
/// port's prefixes, so the route would never be used.
pub fn parse_route(text: &str, ports: &[PortConfig]) -> Result<StaticRoute, String> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let syntax = || {
        "a route like `10.0.3.0/24 via 10.0.2.2`, `default via 10.0.2.2` or \
         `fd00:3::/64 via fe80::2 port 1`"
            .to_owned()
    };
    let (dest, rest) = words.split_first().ok_or_else(syntax)?;
    let mut via: Option<IpAddr> = None;
    let mut port: Option<usize> = None;
    let mut it = rest.iter();
    while let Some(word) = it.next() {
        let value = it.next().ok_or_else(syntax)?;
        match *word {
            "via" if via.is_none() => via = Some(value.parse().map_err(|_| syntax())?),
            "port" if port.is_none() => {
                let n: usize = value
                    .parse()
                    .ok()
                    .filter(|_| value == &"0" || !value.starts_with('0'))
                    .ok_or_else(syntax)?;
                if n >= ports.len() {
                    return Err(format!("port {n} does not exist"));
                }
                port = Some(n);
            }
            _ => return Err(syntax()),
        }
    }
    let via = via.ok_or_else(|| {
        "a route needs `via <next-hop>` (the netstack has no on-link routes)".to_owned()
    })?;
    if !unicast(via) {
        return Err("the next hop must be a unicast address".to_owned());
    }
    let (dst, prefix) = match *dest {
        "default" => match via {
            IpAddr::V4(_) => (IpAddr::from([0u8; 4]), 0),
            IpAddr::V6(_) => (IpAddr::from([0u16; 8]), 0),
        },
        d => {
            let (a, l) = d.split_once('/').ok_or_else(syntax)?;
            let a: IpAddr = a.parse().map_err(|_| syntax())?;
            let max = if a.is_ipv4() { 32 } else { 128 };
            let l: u8 = l.parse().ok().filter(|l| *l <= max).ok_or_else(syntax)?;
            if network(a, l) != a {
                return Err(format!(
                    "{d}: host bits are set (use {}/{l})",
                    network(a, l)
                ));
            }
            (a, l)
        }
    };
    if dst.is_ipv4() != via.is_ipv4() {
        return Err("the next hop's family differs from the prefix's".to_owned());
    }
    let port = match port {
        Some(p) => p,
        None if ports.len() == 1 => 0,
        None if is_link_local_v6(via) => {
            return Err("a link-local next hop needs `port <n>`".to_owned());
        }
        None => ports
            .iter()
            .position(|p| prefixes(p).any(|(n, l)| contains(n, l, via)))
            .ok_or_else(|| {
                format!("next hop {via} is not inside any port's prefix (name its `port <n>`)")
            })?,
    };
    if let Some((n, l)) = prefixes(&ports[port]).find(|&(n, l)| l <= prefix && contains(n, l, dst))
    {
        return Err(format!(
            "it lies inside port {port}'s own prefix {}/{l}, which is on-link",
            network(n, l)
        ));
    }
    Ok(StaticRoute {
        dst,
        prefix,
        via,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn port(v4: Option<&str>, v6: Option<&str>) -> PortConfig {
        let cidr4 = v4.map(|s| {
            let (a, l) = s.split_once('/').unwrap();
            Cidr {
                addr: a.parse().unwrap(),
                prefix: l.parse().unwrap(),
            }
        });
        let cidr6 = v6.map(|s| {
            let (a, l) = s.split_once('/').unwrap();
            Cidr {
                addr: a.parse().unwrap(),
                prefix: l.parse().unwrap(),
            }
        });
        PortConfig {
            ipv4: cidr4,
            ipv6: cidr6,
            ..PortConfig::default()
        }
    }

    #[test]
    fn routes_parse_like_the_routers() {
        let ports = [
            port(Some("10.0.1.5/24"), Some("fd00:1::5/64")),
            port(Some("10.0.2.5/24"), None),
        ];
        let r = parse_route("10.0.3.0/24 via 10.0.2.2", &ports).unwrap();
        assert_eq!(
            (r.dst, r.prefix, r.via, r.port),
            (ip("10.0.3.0"), 24, ip("10.0.2.2"), 1)
        );
        assert_eq!(r.describe(), "10.0.3.0/24 via 10.0.2.2 port 1");
        let r = parse_route("default via 10.0.1.1", &ports).unwrap();
        assert_eq!((r.dst, r.prefix, r.port), (ip("0.0.0.0"), 0, 0));
        assert_eq!(r.describe(), "default via 10.0.1.1 port 0");
        let r = parse_route("fd00:3::/64 via fe80::2 port 1", &ports).unwrap();
        assert_eq!((r.prefix, r.port), (64, 1));
        let r = parse_route("default via fd00:1::1", &ports).unwrap();
        assert_eq!((r.dst, r.port), (ip("::"), 0));
        // A next hop outside every prefix with `port`: smoltcp still finds it (a gateway it
        // reaches by ARP or NDP on that link).
        assert_eq!(
            parse_route("10.9.0.0/16 via 192.168.7.1 port 1", &ports)
                .unwrap()
                .port,
            1
        );
        for (text, needle) in [
            ("", "a route like"),
            ("10.0.3.0/24", "needs `via"),
            ("10.0.3.0/24 port 1", "needs `via"),
            ("10.0.3.1/24 via 10.0.2.2", "host bits"),
            ("10.0.3.0/33 via 10.0.2.2", "a route like"),
            ("10.0.3.0/24 via fd00:1::1", "family"),
            ("10.0.3.0/24 via 10.0.2.2 port 2", "port 2 does not exist"),
            ("10.0.3.0/24 via 10.0.2.2 port 01", "a route like"),
            ("10.0.3.0/24 via 10.0.9.9", "not inside any port's prefix"),
            ("fd00:3::/64 via fe80::2", "link-local"),
            ("10.0.3.0/24 via 224.0.0.1", "unicast"),
            ("10.0.3.0/24 via 10.0.2.2 via 10.0.2.3", "a route like"),
            ("10.0.2.128/25 via 10.0.2.2", "own prefix"),
            ("default via 10.0.2.2 tunnel x", "a route like"),
        ] {
            let err = parse_route(text, &ports).unwrap_err();
            assert!(err.contains(needle), "{text:?}: {err}");
        }
        // One port: every next hop is on it, link-local or not.
        let one = [port(Some("10.0.1.5/24"), None)];
        assert_eq!(parse_route("fd00::/8 via fe80::1", &one).unwrap().port, 0);
        assert_eq!(
            parse_route("default via 192.168.0.1", &one).unwrap().port,
            0
        );
    }

    #[test]
    fn prefixes_contain_and_mask() {
        assert!(contains(ip("10.0.0.0"), 8, ip("10.255.0.1")));
        assert!(!contains(ip("10.0.0.0"), 8, ip("11.0.0.1")));
        assert!(contains(ip("0.0.0.0"), 0, ip("1.2.3.4")));
        assert!(!contains(ip("0.0.0.0"), 0, ip("::1")));
        assert!(contains(ip("fd00::"), 16, ip("fd00:ffff::1")));
        assert!(contains(ip("10.0.0.7"), 32, ip("10.0.0.7")));
        assert!(!contains(ip("10.0.0.7"), 32, ip("10.0.0.6")));
        assert_eq!(network(ip("10.1.2.3"), 12), ip("10.0.0.0"));
        assert_eq!(network(ip("fd00:1:2::9"), 32), ip("fd00:1::"));
        assert_eq!(network(ip("1.2.3.4"), 0), ip("0.0.0.0"));
    }

    /// The reference: every candidate checked bit by bit, the longest one first in order.
    fn reference(cands: &[(IpAddr, u8, usize)], dst: IpAddr) -> Option<usize> {
        let bits = |a: IpAddr| -> Vec<bool> {
            let o: Vec<u8> = match a {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            o.iter()
                .flat_map(|b| (0..8).rev().map(move |i| b >> i & 1 == 1))
                .collect()
        };
        let mut best: Option<(u8, usize)> = None;
        for &(net, len, port) in cands {
            if net.is_ipv4() != dst.is_ipv4() {
                continue;
            }
            let (n, d) = (bits(net), bits(dst));
            if n[..usize::from(len)] == d[..usize::from(len)] && best.is_none_or(|(l, _)| len > l) {
                best = Some((len, port));
            }
        }
        best.map(|(_, p)| p)
    }

    #[test]
    fn longest_match_agrees_with_a_reference_under_random_routes() {
        // A small xorshift: the same tables on every run.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..400 {
            let v6 = round % 2 == 1;
            // Addresses from a small space, so prefixes nest and collide often.
            let addr = |r: u64| -> IpAddr {
                if v6 {
                    let hi = (r & 0xff) as u128;
                    IpAddr::from(
                        (0xfd00u128 << 112 | hi << 104 | u128::from(r >> 8 & 0xff)).to_be_bytes(),
                    )
                } else {
                    IpAddr::from(
                        ((10u32 << 24) | ((r & 0xff) as u32) << 16 | (r >> 8 & 0xff) as u32)
                            .to_be_bytes(),
                    )
                }
            };
            let n = (next() % 12) as usize;
            let cands: Vec<(IpAddr, u8, usize)> = (0..n)
                .map(|_| {
                    let r = next();
                    let max = if v6 { 128 } else { 32 };
                    let len = (r >> 20) as u8 % (max + 1);
                    let a = addr(r);
                    (network(a, len), len, (r >> 40) as usize % 4)
                })
                .collect();
            for _ in 0..20 {
                let dst = addr(next());
                assert_eq!(
                    longest_match(cands.iter().copied(), dst),
                    reference(&cands, dst),
                    "round {round}: {cands:?} to {dst}"
                );
            }
        }
    }
}
