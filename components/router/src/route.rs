//! The routing table: connected and static routes, longest-prefix match.
//!
//! Routes are kept per family in one map per prefix length (`len → masked prefix → route`), so a
//! lookup probes at most 33 (IPv4) or 129 (IPv6) maps from the longest length down, and the first
//! hit is the longest match. Inserting a second route for the same prefix keeps the first one:
//! connected routes are inserted before static ones, so they win ties (an administrative
//! distance of 0), and among static routes the first in the config wins. The table is tested
//! against a brute-force reference with proptest.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// A prefix: the address bits and the length. Host bits may be set until [`Prefix::masked`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Prefix {
    V4(u32, u8),
    V6(u128, u8),
}

fn mask4(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(len))
    }
}

fn mask6(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(len))
    }
}

impl Prefix {
    pub fn prefix_len(self) -> u8 {
        match self {
            Prefix::V4(_, l) | Prefix::V6(_, l) => l,
        }
    }

    /// The prefix with its host bits cleared.
    pub fn masked(self) -> Prefix {
        match self {
            Prefix::V4(a, l) => Prefix::V4(a & mask4(l), l),
            Prefix::V6(a, l) => Prefix::V6(a & mask6(l), l),
        }
    }

    /// No host bits set.
    pub fn is_canonical(self) -> bool {
        self.masked() == self
    }

    pub fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Prefix::V4(a, l), IpAddr::V4(ip)) => (u32::from(ip) ^ a) & mask4(l) == 0,
            (Prefix::V6(a, l), IpAddr::V6(ip)) => (u128::from(ip) ^ a) & mask6(l) == 0,
            _ => false,
        }
    }

    /// The IPv4 directed broadcast address of this prefix (`None` for /31, /32 and IPv6).
    pub fn broadcast(self) -> Option<Ipv4Addr> {
        match self {
            Prefix::V4(a, l) if l <= 30 => Some(Ipv4Addr::from(a | !mask4(l))),
            _ => None,
        }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Prefix::V4(a, l) => write!(f, "{}/{l}", Ipv4Addr::from(a)),
            Prefix::V6(a, l) => write!(f, "{}/{l}", Ipv6Addr::from(a)),
        }
    }
}

impl FromStr for Prefix {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        let (addr, len) = s.split_once('/').ok_or(())?;
        let len: u8 = len.parse().map_err(|_| ())?;
        match addr.parse::<IpAddr>().map_err(|_| ())? {
            IpAddr::V4(a) if len <= 32 => Ok(Prefix::V4(u32::from(a), len)),
            IpAddr::V6(a) if len <= 128 => Ok(Prefix::V6(u128::from(a), len)),
            _ => Err(()),
        }
    }
}

/// Where a route came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    /// A port's own prefix: the destination is on-link.
    Connected,
    /// From the config's `routes`.
    Static,
}

impl RouteKind {
    pub fn name(self) -> &'static str {
        match self {
            RouteKind::Connected => "connected",
            RouteKind::Static => "static",
        }
    }
}

/// One route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// Masked.
    pub prefix: Prefix,
    /// The next hop; `None`: the destination itself is on-link.
    pub via: Option<IpAddr>,
    pub port: u32,
    pub kind: RouteKind,
}

impl Route {
    /// The neighbor a packet for `dst` is handed to.
    pub fn next_hop(&self, dst: IpAddr) -> IpAddr {
        self.via.unwrap_or(dst)
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix)?;
        if let Some(v) = self.via {
            write!(f, " via {v}")?;
        }
        write!(f, " port {} ({})", self.port, self.kind.name())
    }
}

/// The routing table.
#[derive(Clone, Debug)]
pub struct RouteTable {
    v4: Vec<BTreeMap<u32, Route>>,
    v6: Vec<BTreeMap<u128, Route>>,
    /// Every route, in insertion order (for display and counters).
    order: Vec<Route>,
}

impl Default for RouteTable {
    fn default() -> Self {
        Self {
            v4: vec![BTreeMap::new(); 33],
            v6: vec![BTreeMap::new(); 129],
            order: Vec::new(),
        }
    }
}

impl RouteTable {
    /// Adds a route (its prefix is masked). Returns `false`, keeping the existing route, when
    /// one for the same prefix exists already.
    pub fn insert(&mut self, mut route: Route) -> bool {
        route.prefix = route.prefix.masked();
        let fresh = match route.prefix {
            Prefix::V4(a, l) => match self.v4[usize::from(l)].entry(a) {
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(route);
                    true
                }
                std::collections::btree_map::Entry::Occupied(_) => false,
            },
            Prefix::V6(a, l) => match self.v6[usize::from(l)].entry(a) {
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(route);
                    true
                }
                std::collections::btree_map::Entry::Occupied(_) => false,
            },
        };
        if fresh {
            self.order.push(route);
        }
        fresh
    }

    /// The longest-prefix match for `ip`.
    pub fn lookup(&self, ip: IpAddr) -> Option<&Route> {
        match ip {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                (0..=32u8)
                    .rev()
                    .find_map(|l| self.v4[usize::from(l)].get(&(a & mask4(l))))
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                (0..=128u8)
                    .rev()
                    .find_map(|l| self.v6[usize::from(l)].get(&(a & mask6(l))))
            }
        }
    }

    /// Every route, in insertion order.
    pub fn routes(&self) -> &[Route] {
        &self.order
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn route(prefix: &str, port: u32) -> Route {
        Route {
            prefix: prefix.parse().unwrap(),
            via: None,
            port,
            kind: RouteKind::Static,
        }
    }

    fn port_of(t: &RouteTable, ip: &str) -> Option<u32> {
        t.lookup(ip.parse().unwrap()).map(|r| r.port)
    }

    /// Table tests: the classic cases.
    #[test]
    fn longest_prefix_wins() {
        let mut t = RouteTable::default();
        for (p, port) in [
            ("0.0.0.0/0", 0),
            ("10.0.0.0/8", 1),
            ("10.0.1.0/24", 2),
            ("10.0.1.128/25", 3),
            ("10.0.1.200/32", 4),
            ("::/0", 5),
            ("fd00::/16", 6),
            ("fd00:1::/64", 7),
        ] {
            assert!(t.insert(route(p, port)));
        }
        let cases = [
            ("192.0.2.1", Some(0)),
            ("10.9.9.9", Some(1)),
            ("10.0.1.1", Some(2)),
            ("10.0.1.127", Some(2)),
            ("10.0.1.128", Some(3)),
            ("10.0.1.200", Some(4)),
            ("10.0.1.201", Some(3)),
            ("2001:db8::1", Some(5)),
            ("fd00:9::1", Some(6)),
            ("fd00:1::abcd", Some(7)),
        ];
        for (ip, want) in cases {
            assert_eq!(port_of(&t, ip), want, "{ip}");
        }
        assert_eq!(t.len(), 8);
    }

    #[test]
    fn no_default_means_no_route() {
        let mut t = RouteTable::default();
        t.insert(route("10.0.1.0/24", 0));
        assert_eq!(port_of(&t, "10.0.2.1"), None);
        assert_eq!(port_of(&t, "fd00::1"), None, "families never mix");
    }

    #[test]
    fn first_route_for_a_prefix_wins_and_prefixes_are_masked() {
        let mut t = RouteTable::default();
        assert!(t.insert(route("10.0.1.0/24", 0)));
        assert!(
            !t.insert(route("10.0.1.7/24", 1)),
            "same prefix once masked"
        );
        assert_eq!(port_of(&t, "10.0.1.9"), Some(0));
        assert_eq!(t.routes()[0].prefix.to_string(), "10.0.1.0/24");
    }

    #[test]
    fn prefix_helpers() {
        let p: Prefix = "10.0.1.1/24".parse().unwrap();
        assert!(!p.is_canonical());
        assert_eq!(p.masked().to_string(), "10.0.1.0/24");
        assert_eq!(p.broadcast(), Some("10.0.1.255".parse().unwrap()));
        assert_eq!("10.0.0.0/31".parse::<Prefix>().unwrap().broadcast(), None);
        assert!(p.contains("10.0.1.200".parse().unwrap()));
        assert!(!p.contains("10.0.2.1".parse().unwrap()));
        assert!("10.0.0.0/33".parse::<Prefix>().is_err());
        assert!("fd00::/129".parse::<Prefix>().is_err());
        assert!(
            "::/0"
                .parse::<Prefix>()
                .unwrap()
                .contains("fd00::1".parse().unwrap())
        );
    }

    /// The brute-force reference: scan every route (first one per masked prefix), keep the
    /// longest that contains the address.
    fn reference(routes: &[Route], ip: IpAddr) -> Option<u32> {
        let mut seen: Vec<Prefix> = Vec::new();
        let mut best: Option<(u8, u32)> = None;
        for r in routes {
            let p = r.prefix.masked();
            if seen.contains(&p) {
                continue;
            }
            seen.push(p);
            if p.contains(ip) && best.is_none_or(|(l, _)| p.prefix_len() > l) {
                best = Some((p.prefix_len(), r.port));
            }
        }
        best.map(|(_, port)| port)
    }

    /// Addresses clustered in a few /16s and /112s, so random prefixes overlap often.
    fn v4() -> impl Strategy<Value = u32> {
        (0u32..4, any::<u16>()).prop_map(|(net, host)| (10 << 24) | (net << 16) | u32::from(host))
    }

    fn v6() -> impl Strategy<Value = u128> {
        (0u128..4, any::<u16>())
            .prop_map(|(net, host)| (0xfd00 << 112) | (net << 16) | host as u128)
    }

    fn any_route() -> impl Strategy<Value = Route> {
        let p4 = (v4(), 0u8..=32).prop_map(|(a, l)| Prefix::V4(a, l));
        let p6 = (v6(), prop_oneof![0u8..=8, 96u8..=128]).prop_map(|(a, l)| Prefix::V6(a, l));
        (prop_oneof![p4, p6], 0u32..8).prop_map(|(prefix, port)| Route {
            prefix,
            via: None,
            port,
            kind: RouteKind::Static,
        })
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 512,
            // Deterministic like everything else here; no regression files (no filesystem).
            rng_seed: proptest::test_runner::RngSeed::Fixed(6),
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]

        #[test]
        fn lookup_matches_the_brute_force_reference(
            routes in prop::collection::vec(any_route(), 0..24),
            probes4 in prop::collection::vec(v4(), 1..16),
            probes6 in prop::collection::vec(v6(), 1..16),
        ) {
            let mut t = RouteTable::default();
            for r in &routes {
                t.insert(*r);
            }
            let ips = probes4
                .iter()
                .map(|&a| IpAddr::V4(Ipv4Addr::from(a)))
                .chain(probes6.iter().map(|&a| IpAddr::V6(Ipv6Addr::from(a))));
            for ip in ips {
                prop_assert_eq!(t.lookup(ip).map(|r| r.port), reference(&routes, ip), "{}", ip);
            }
        }
    }
}
