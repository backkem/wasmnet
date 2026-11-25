//! The router's configuration, read from `wasi:config/store` with `get-all`.
//!
//! Every key is optional except that at least one port must exist; unknown keys are errors, so
//! typos in a config fail loudly. Ports are flat dotted keys (`port0.ipv4 = "10.0.1.1/24"`) and
//! lists are comma-joined (`routes = "10.0.3.0/24 via 10.0.2.2,default via 10.0.1.254"`).
//!
//! | key | value | default |
//! |---|---|---|
//! | `ports` | number of ports, 1..=16 | one more than the highest `port<N>` |
//! | `mac` | base MAC; port N's default MAC is this with N added to the last octet | `02:52:00:00:00:00` |
//! | `port<N>.mac` | the port's unicast MAC | from `mac` |
//! | `port<N>.mtu` | IP MTU, 68..=9000 (1280.. if the port has IPv6); a frame is MTU + 14 bytes | `1500` |
//! | `port<N>.ipv4` | `10.0.1.1/24`: the port's address and its connected route | none |
//! | `port<N>.ipv6` | a global address with a prefix, `fd00:1::1/64`, and its connected route | none |
//! | `port<N>.ipv6-link-local` | `fe80::1` | EUI-64 from the port's MAC |
//! | `port<N>.ra` | `true`: send a Router Advertisement when the link comes up and answer Router Solicitations | `false` |
//! | `port<N>.dhcp-relay` | DHCP servers (IPv4, a list) to relay this port's DHCP client broadcasts to, as an RFC 1542 relay agent with the port's IPv4 address as `giaddr` | none |
//! | `routes` | static routes, a list (see [`StaticRoute`]) | none |
//! | `ttl` | TTL / hop limit of packets the router originates (ICMP, echo replies, RSTs) | `64` |
//! | `neighbor.retry` | time between ARP requests / Neighbor Solicitations for one neighbor | `1s` |
//! | `neighbor.attempts` | requests before a neighbor is unreachable, 1..=10 | `3` |
//! | `neighbor.queue` | packets queued per unresolved neighbor, 1..=256 (the oldest is dropped) | `16` |
//! | `neighbor.lifetime` | how long a learned neighbor is trusted (checked when used) | `300s` |
//! | `trace.route-lookup` | `route-lookup` events: `first` (once per destination), `all` or `none` | `first` |
//! | `trace.ttl-decrement` | `ttl-decrement` events: `first` (once per flow), `all` or `none` | `first` |
//!
//! Address translation and the filter (`docs/design/nat.md`), all optional:
//!
//! | key | value | default |
//! |---|---|---|
//! | `port<N>.nat` | `masquerade`: port N is an outside port (needs `port<N>.ipv4`) | none |
//! | `port<N>.allow` | allow rules for packets forwarded from port N, a list (see [`crate::filter::parse_rule`]) | none: everything |
//! | `nat.mapping`, `nat.filtering` | `endpoint-independent`, `address-dependent` or `address-and-port-dependent` | EIM, APDF |
//! | `nat.hairpin` | `true` or `false` | `true` |
//! | `nat.port-allocation` | `preserve` or `sequential` | `preserve` |
//! | `nat.port-range` | `<low>-<high>`, 1..=65535 | `1024-65535` |
//! | `nat.forwards` | port forwards, a list (see [`crate::nat::parse_forward`]) | none |
//! | `conntrack.udp-timeout`, `conntrack.tcp-established-timeout`, `conntrack.tcp-transitory-timeout`, `conntrack.icmp-timeout` | idle timeouts | `300s`, `7440s`, `240s`, `60s` |
//! | `conntrack.max-entries` | NAT sessions, and filter flows, 1..=65536 each | `4096` |
//! | `trace.nat-filtered`, `trace.filter-drop` | `first` (once per flow), `all` or `none` | `first` |
//!
//! Tunnel ports (`docs/design/tunnels.md`), all optional; a tunnel needs `id` and `local`:
//!
//! | key | value | default |
//! |---|---|---|
//! | `tunnel.<name>.<key>` | a tunnel's settings, the keys of [`crate::tunnel::Spec`] (at most 256 tunnels) | none |
//! | `stun-server` | a UDP port on which the router answers STUN Binding requests without a tunnel id | none |
//!
//! A route over a tunnel names it: `fd00:b::/64 tunnel to-b`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wasmnet_wire::{MacAddr, parse_duration};

use crate::filter::{Rule, parse_rule};
use crate::nat::{Allocation, Dependence, NatConfig, parse_forward};
use crate::route::Prefix;
use crate::track::Timeouts;
use crate::tunnel::{self, Spec as TunnelSpec};

/// Most ports a router may have.
pub const MAX_PORTS: u32 = 16;

/// A config value that could not be used. The component logs it and traps.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("config {key}={value:?}: expected {expected}")]
    Invalid {
        key: String,
        value: String,
        expected: String,
    },
    #[error("config {key}: unknown key")]
    Unknown { key: String },
    #[error("config: {0}")]
    Other(String),
}

/// How many `route-lookup` / `ttl-decrement` events to emit (they can be one per packet).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trace {
    /// `route-lookup`: once per destination address; `ttl-decrement`: once per flow (protocol,
    /// addresses and ports).
    First,
    All,
    None,
}

/// One port's addresses and link parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortConfig {
    pub mac: MacAddr,
    /// IP MTU.
    pub mtu: u16,
    pub ipv4: Option<(Ipv4Addr, u8)>,
    /// The global address and its prefix length.
    pub ipv6: Option<(Ipv6Addr, u8)>,
    pub link_local: Ipv6Addr,
    pub ra: bool,
    /// DHCP servers this port relays client broadcasts to (RFC 1542); empty: no relay.
    pub dhcp_relay: Vec<Ipv4Addr>,
    /// An outside port of address translation (`masquerade`).
    pub nat: bool,
    /// Allow rules for packets forwarded from this port; empty: everything.
    pub allow: Vec<Rule>,
}

/// A static route: `10.0.3.0/24 via 10.0.2.2`, `default via 10.0.2.2`,
/// `fd00:3::/64 via fe80::2 port 1` or `10.9.0.0/16 port 1` (on-link through port 1).
///
/// `default` means `0.0.0.0/0` or `::/0`, by the next hop's family. A next hop without `port`
/// must lie inside one of the ports' connected prefixes (that port is used); a link-local next
/// hop needs `port`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticRoute {
    pub prefix: Prefix,
    pub via: Option<IpAddr>,
    pub port: u32,
}

/// The neighbor (ARP / NDP) parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborConfig {
    pub retry_ns: u64,
    pub attempts: u32,
    pub queue: usize,
    pub lifetime_ns: u64,
}

/// The parsed configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub ports: Vec<PortConfig>,
    pub routes: Vec<StaticRoute>,
    pub ttl: u8,
    pub neighbor: NeighborConfig,
    pub trace_route_lookup: Trace,
    pub trace_ttl_decrement: Trace,
    /// Translation settings, when a port has `nat`.
    pub nat: Option<NatConfig>,
    /// Connection tracking's idle timeouts and table size (NAT sessions, filter flows).
    pub conntrack: Timeouts,
    pub conntrack_max: usize,
    pub trace_nat_filtered: Trace,
    pub trace_filter_drop: Trace,
    /// Tunnel ports from `tunnel.<name>.<key>`, by name: the first is port `ports.len()`, the
    /// next one after it, and so on (`docs/design/tunnels.md`).
    pub tunnels: Vec<(String, TunnelSpec)>,
    /// A UDP port on which the router answers STUN Binding requests without a tunnel id.
    pub stun_server: Option<u16>,
}

/// The default base MAC (`R` = 0x52).
pub const DEFAULT_MAC: MacAddr = MacAddr([0x02, 0x52, 0, 0, 0, 0]);

const PORT_KEYS: &[&str] = &[
    "mac",
    "mtu",
    "ipv4",
    "ipv6",
    "ipv6-link-local",
    "ra",
    "dhcp-relay",
    "nat",
    "allow",
];
/// Keys that only mean something when a port translates.
const NAT_KEYS: &[&str] = &[
    "nat.mapping",
    "nat.filtering",
    "nat.hairpin",
    "nat.port-allocation",
    "nat.port-range",
    "nat.forwards",
];
const TOP_KEYS: &[&str] = &[
    "ports",
    "mac",
    "routes",
    "ttl",
    "neighbor.retry",
    "neighbor.attempts",
    "neighbor.queue",
    "neighbor.lifetime",
    "trace.route-lookup",
    "trace.ttl-decrement",
    "nat.mapping",
    "nat.filtering",
    "nat.hairpin",
    "nat.port-allocation",
    "nat.port-range",
    "nat.forwards",
    "conntrack.udp-timeout",
    "conntrack.tcp-established-timeout",
    "conntrack.tcp-transitory-timeout",
    "conntrack.icmp-timeout",
    "conntrack.max-entries",
    "trace.nat-filtered",
    "trace.filter-drop",
    "stun-server",
];

/// The link-local address of `mac` (RFC 4291 modified EUI-64).
pub fn eui64_link_local(mac: MacAddr) -> Ipv6Addr {
    let m = mac.octets();
    Ipv6Addr::from([
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        m[0] ^ 0x02,
        m[1],
        m[2],
        0xff,
        0xfe,
        m[3],
        m[4],
        m[5],
    ])
}

pub fn is_link_local_v6(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

/// A unicast IPv4 address a host may use (not unspecified, multicast, broadcast or loopback).
pub fn usable_v4(a: Ipv4Addr) -> bool {
    !(a.is_unspecified() || a.is_multicast() || a.is_broadcast() || a.is_loopback())
}

/// A unicast IPv6 address (not unspecified, multicast or loopback).
pub fn usable_v6(a: Ipv6Addr) -> bool {
    !(a.is_unspecified() || a.is_multicast() || a.is_loopback())
}

fn cidr<A: std::str::FromStr>(text: &str, max: u8) -> Option<(A, u8)> {
    let (addr, prefix) = text.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= max).then_some(())?;
    Some((addr.parse().ok()?, prefix))
}

fn trace(v: &str) -> Option<Trace> {
    match v {
        "first" => Some(Trace::First),
        "all" => Some(Trace::All),
        "none" => Some(Trace::None),
        _ => None,
    }
}

struct Reader<'a> {
    map: &'a BTreeMap<String, String>,
}

impl Reader<'_> {
    fn get<T>(
        &self,
        key: &str,
        expected: &str,
        parse: impl Fn(&str) -> Option<T>,
    ) -> Result<Option<T>, ConfigError> {
        match self.map.get(key) {
            None => Ok(None),
            Some(value) => parse(value).map(Some).ok_or_else(|| ConfigError::Invalid {
                key: key.to_owned(),
                value: value.clone(),
                expected: expected.to_owned(),
            }),
        }
    }
}

fn int<T: std::str::FromStr + PartialOrd>(lo: T, hi: T) -> impl Fn(&str) -> Option<T> {
    move |v| v.parse::<T>().ok().filter(|n| *n >= lo && *n <= hi)
}

/// `port<N>.<key>` → `(N, key)`.
fn port_key(key: &str) -> Option<(u32, &str)> {
    let rest = key.strip_prefix("port")?;
    let (n, k) = rest.split_once('.')?;
    if n.is_empty() || (n.len() > 1 && n.starts_with('0')) {
        return None;
    }
    Some((n.parse().ok()?, k))
}

impl Config {
    /// Parses the device's whole config (`wasi:config/store.get-all`).
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let map: BTreeMap<String, String> = pairs
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        let r = Reader { map: &map };

        let mut highest: Option<u32> = None;
        let mut tunnel_pairs: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
        for (key, value) in &map {
            if TOP_KEYS.contains(&key.as_str()) {
                continue;
            }
            if let Some((name, k)) = key
                .strip_prefix("tunnel.")
                .and_then(|rest| rest.split_once('.'))
            {
                tunnel_pairs.entry(name).or_default().push((k, value));
                continue;
            }
            match port_key(key) {
                Some((n, k)) if n < MAX_PORTS && PORT_KEYS.contains(&k) => {
                    highest = Some(highest.map_or(n, |h| h.max(n)));
                }
                _ => return Err(ConfigError::Unknown { key: key.clone() }),
            }
        }
        let ports = r
            .get("ports", "an integer from 1 to 16", int(1u32, MAX_PORTS))?
            .or(highest.map(|h| h + 1))
            .ok_or_else(|| ConfigError::Other("a router needs at least one port".to_owned()))?;
        if let Some(h) = highest.filter(|&h| h >= ports) {
            return Err(ConfigError::Other(format!(
                "port{h} is configured, but `ports` = {ports}"
            )));
        }
        let base = r
            .get("mac", "a unicast MAC like 02:52:00:00:00:00", |v| {
                v.parse::<MacAddr>().ok().filter(|m| m.is_unicast())
            })?
            .unwrap_or(DEFAULT_MAC);

        let mut port_configs = Vec::new();
        for n in 0..ports {
            let key = |k: &str| format!("port{n}.{k}");
            let mac = r
                .get(&key("mac"), "a unicast MAC like 02:00:00:00:01:01", |v| {
                    v.parse::<MacAddr>().ok().filter(|m| m.is_unicast())
                })?
                .unwrap_or_else(|| {
                    let mut o = base.octets();
                    o[5] = o[5].wrapping_add(n as u8);
                    MacAddr(o)
                });
            let ipv4 = r.get(
                &key("ipv4"),
                "an address with a prefix like 10.0.1.1/24",
                |v| cidr::<Ipv4Addr>(v, 32).filter(|(a, _)| usable_v4(*a)),
            )?;
            let ipv6 = r.get(
                &key("ipv6"),
                "a global address with a prefix like fd00:1::1/64",
                |v| {
                    cidr::<Ipv6Addr>(v, 128).filter(|(a, _)| usable_v6(*a) && !is_link_local_v6(*a))
                },
            )?;
            let mtu_min = if ipv6.is_some() { 1280 } else { 68 };
            let mtu = r
                .get(
                    &key("mtu"),
                    &format!("an IP MTU from {mtu_min} to 9000"),
                    int(mtu_min, 9000u16),
                )?
                .unwrap_or(1500);
            let link_local = r
                .get(
                    &key("ipv6-link-local"),
                    "a link-local address like fe80::1",
                    |v| {
                        v.parse::<Ipv6Addr>()
                            .ok()
                            .filter(|a| is_link_local_v6(*a) && usable_v6(*a))
                    },
                )?
                .unwrap_or_else(|| eui64_link_local(mac));
            let ra = r
                .get(&key("ra"), "true or false", |v| v.parse::<bool>().ok())?
                .unwrap_or(false);
            if ra && ipv6.is_none() {
                return Err(ConfigError::Other(format!(
                    "port{n}.ra needs port{n}.ipv6 (the advertised prefix)"
                )));
            }
            let dhcp_relay = r
                .get(
                    &key("dhcp-relay"),
                    "DHCP server addresses like 10.0.1.2 (a list is fine)",
                    |v| {
                        v.split(',')
                            .map(|a| a.trim().parse::<Ipv4Addr>().ok().filter(|a| usable_v4(*a)))
                            .collect::<Option<Vec<_>>>()
                    },
                )?
                .unwrap_or_default();
            if !dhcp_relay.is_empty() && ipv4.is_none() {
                return Err(ConfigError::Other(format!(
                    "port{n}.dhcp-relay needs port{n}.ipv4 (it becomes the relayed giaddr)"
                )));
            }
            let nat = r
                .get(&key("nat"), "masquerade", |v| {
                    (v == "masquerade").then_some(true)
                })?
                .unwrap_or(false);
            if nat && ipv4.is_none() {
                return Err(ConfigError::Other(format!(
                    "port{n}.nat needs port{n}.ipv4 (the address it translates to)"
                )));
            }
            let allow = match map.get(&key("allow")) {
                None => Vec::new(),
                Some(list) => list
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(|t| {
                        parse_rule(t).map_err(|why| ConfigError::Invalid {
                            key: key("allow"),
                            value: t.to_owned(),
                            expected: why,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            };
            if allow.len() > crate::filter::MAX_RULES {
                return Err(ConfigError::Other(format!(
                    "port{n}.allow has more than {} rules",
                    crate::filter::MAX_RULES
                )));
            }
            port_configs.push(PortConfig {
                mac,
                mtu,
                ipv4,
                ipv6,
                link_local,
                ra,
                dhcp_relay,
                nat,
                allow,
            });
        }

        if tunnel_pairs.len() > tunnel::MAX_TUNNELS {
            return Err(ConfigError::Other(format!(
                "more than {} tunnels",
                tunnel::MAX_TUNNELS
            )));
        }
        let mut tunnels: Vec<(String, TunnelSpec)> = Vec::new();
        for (name, pairs) in tunnel_pairs {
            if !tunnel::valid_name(name) {
                return Err(ConfigError::Other(format!(
                    "tunnel.{name}: a tunnel name is a-z, 0-9 and -, 1 to 32 characters, \
                     starting with a letter"
                )));
            }
            let spec = TunnelSpec::from_pairs(pairs)
                .map_err(|why| ConfigError::Other(format!("tunnel.{name}: {why}")))?;
            if tunnels
                .iter()
                .any(|(_, s)| (s.udp, s.id) == (spec.udp, spec.id))
            {
                return Err(ConfigError::Other(format!(
                    "tunnel.{name}: another tunnel has id {} on udp {}",
                    spec.id, spec.udp
                )));
            }
            tunnels.push((name.to_owned(), spec));
        }
        let stun_server = r.get(
            "stun-server",
            "a UDP port from 1 to 65535",
            int(1u16, 65535),
        )?;
        let tunnel_port = |name: &str| {
            tunnels
                .iter()
                .position(|(n, _)| n == name)
                .map(|i| (port_configs.len() + i) as u32)
        };

        let mut routes = Vec::new();
        if let Some(list) = map.get("routes") {
            for text in list.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                let route = parse_route_with(text, &port_configs, tunnel_port).map_err(|why| {
                    ConfigError::Invalid {
                        key: "routes".to_owned(),
                        value: text.to_owned(),
                        expected: why,
                    }
                })?;
                routes.push(route);
            }
        }

        let ttl = r
            .get("ttl", "an integer from 1 to 255", int(1u8, 255))?
            .unwrap_or(64);
        let neighbor = NeighborConfig {
            retry_ns: r
                .get("neighbor.retry", "a duration above zero like 1s", |v| {
                    parse_duration(v).filter(|&ns| ns > 0)
                })?
                .unwrap_or(1_000_000_000),
            attempts: r
                .get(
                    "neighbor.attempts",
                    "an integer from 1 to 10",
                    int(1u32, 10),
                )?
                .unwrap_or(3),
            queue: r
                .get(
                    "neighbor.queue",
                    "an integer from 1 to 256",
                    int(1usize, 256),
                )?
                .unwrap_or(16),
            lifetime_ns: r
                .get(
                    "neighbor.lifetime",
                    "a duration above zero like 300s",
                    |v| parse_duration(v).filter(|&ns| ns > 0),
                )?
                .unwrap_or(300_000_000_000),
        };
        let trace_route_lookup = r
            .get("trace.route-lookup", "first, all or none", trace)?
            .unwrap_or(Trace::First);
        let trace_ttl_decrement = r
            .get("trace.ttl-decrement", "first, all or none", trace)?
            .unwrap_or(Trace::First);
        let timeout = |key: &str, default_s: u64| {
            r.get(key, "a duration above zero like 300s", |v| {
                parse_duration(v).filter(|&ns| ns > 0)
            })
            .map(|v| v.unwrap_or(default_s * 1_000_000_000))
        };
        let conntrack = Timeouts {
            udp: timeout("conntrack.udp-timeout", 300)?,
            tcp_established: timeout("conntrack.tcp-established-timeout", 7440)?,
            tcp_transitory: timeout("conntrack.tcp-transitory-timeout", 240)?,
            icmp: timeout("conntrack.icmp-timeout", 60)?,
        };
        let conntrack_max = r
            .get(
                "conntrack.max-entries",
                "an integer from 1 to 65536",
                int(1usize, 65536),
            )?
            .unwrap_or(4096);
        let trace_nat_filtered = r
            .get("trace.nat-filtered", "first, all or none", trace)?
            .unwrap_or(Trace::First);
        let trace_filter_drop = r
            .get("trace.filter-drop", "first, all or none", trace)?
            .unwrap_or(Trace::First);
        let nat_ports: Vec<u32> = port_configs
            .iter()
            .enumerate()
            .filter(|(_, p)| p.nat)
            .map(|(n, _)| n as u32)
            .collect();
        let nat = if nat_ports.is_empty() {
            if let Some(k) = NAT_KEYS.iter().find(|k| map.contains_key(**k)) {
                return Err(ConfigError::Other(format!(
                    "{k} needs a port that translates (port<N>.nat = masquerade)"
                )));
            }
            None
        } else {
            Some(nat_config(&r, &map, &nat_ports)?)
        };
        Ok(Self {
            ports: port_configs,
            routes,
            ttl,
            neighbor,
            trace_route_lookup,
            trace_ttl_decrement,
            nat,
            conntrack,
            conntrack_max,
            trace_nat_filtered,
            trace_filter_drop,
            tunnels,
            stun_server,
        })
    }
}

/// The `nat.*` keys, for a router whose ports `nat_ports` translate.
fn nat_config(
    r: &Reader<'_>,
    map: &BTreeMap<String, String>,
    nat_ports: &[u32],
) -> Result<NatConfig, ConfigError> {
    let behaviour = "endpoint-independent, address-dependent or address-and-port-dependent";
    let d = NatConfig::default();
    let mapping = r
        .get("nat.mapping", behaviour, Dependence::parse)?
        .unwrap_or(d.mapping);
    let filtering = r
        .get("nat.filtering", behaviour, Dependence::parse)?
        .unwrap_or(d.filtering);
    let hairpin = r
        .get("nat.hairpin", "true or false", |v| v.parse::<bool>().ok())?
        .unwrap_or(d.hairpin);
    let allocation = r
        .get(
            "nat.port-allocation",
            "preserve or sequential",
            |v| match v {
                "preserve" => Some(Allocation::Preserve),
                "sequential" => Some(Allocation::Sequential),
                _ => None,
            },
        )?
        .unwrap_or(d.allocation);
    let port_range = r
        .get(
            "nat.port-range",
            "a range like 1024-65535 (1..=65535, low first)",
            |v| {
                let (a, b) = v.split_once('-')?;
                let (a, b): (u16, u16) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
                (a >= 1 && a <= b).then_some((a, b))
            },
        )?
        .unwrap_or(d.port_range);
    let mut forwards: Vec<crate::nat::Forward> = Vec::new();
    if let Some(list) = map.get("nat.forwards") {
        for text in list.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            let invalid = |why: String| ConfigError::Invalid {
                key: "nat.forwards".to_owned(),
                value: text.to_owned(),
                expected: why,
            };
            let f = parse_forward(text, nat_ports).map_err(invalid)?;
            if forwards
                .iter()
                .any(|g| (g.proto, g.port, g.external) == (f.proto, f.port, f.external))
            {
                return Err(invalid("an external port forwarded only once".to_owned()));
            }
            if forwards
                .iter()
                .any(|g| (g.proto, g.port, g.internal) == (f.proto, f.port, f.internal))
            {
                return Err(invalid(
                    "one forward per inside endpoint and port".to_owned(),
                ));
            }
            forwards.push(f);
        }
    }
    if forwards.len() > crate::nat::MAX_FORWARDS {
        return Err(ConfigError::Other(format!(
            "nat.forwards has more than {} forwards",
            crate::nat::MAX_FORWARDS
        )));
    }
    Ok(NatConfig {
        mapping,
        filtering,
        hairpin,
        allocation,
        port_range,
        forwards,
    })
}

/// Parses one static route against the ports (see [`StaticRoute`]); it names no tunnel.
pub fn parse_route(text: &str, ports: &[PortConfig]) -> Result<StaticRoute, String> {
    parse_route_with(text, ports, |_| None)
}

/// Parses one static route against the ports and the tunnels: `tunnel(name)` is the port of
/// tunnel `name`, if there is one. A route over a tunnel is `<prefix> tunnel <name>`: on-link
/// through that tunnel port, with neither `via` nor `port`.
pub fn parse_route_with(
    text: &str,
    ports: &[PortConfig],
    tunnel: impl Fn(&str) -> Option<u32>,
) -> Result<StaticRoute, String> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let syntax = || {
        "a route like `10.0.3.0/24 via 10.0.2.2`, `default via 10.0.2.2`, \
         `fd00:3::/64 via fe80::2 port 1` or `10.9.0.0/16 port 1`"
            .to_owned()
    };
    let (dest, rest) = words.split_first().ok_or_else(syntax)?;
    let mut via: Option<IpAddr> = None;
    let mut port: Option<u32> = None;
    let mut over: Option<u32> = None;
    let mut it = rest.iter();
    while let Some(word) = it.next() {
        let value = it.next().ok_or_else(syntax)?;
        match *word {
            "via" if via.is_none() => {
                via = Some(value.parse().map_err(|_| syntax())?);
            }
            "port" if port.is_none() => {
                let n: u32 = value.parse().map_err(|_| syntax())?;
                if n as usize >= ports.len() {
                    return Err(format!("port {n} does not exist"));
                }
                port = Some(n);
            }
            "tunnel" if over.is_none() => {
                over = Some(tunnel(value).ok_or_else(|| format!("no tunnel `{value}`"))?);
            }
            _ => return Err(syntax()),
        }
    }
    if let Some(t) = over {
        if via.is_some() || port.is_some() {
            return Err("a route over a tunnel takes neither `via` nor `port`".to_owned());
        }
        if *dest == "default" {
            return Err("`default` needs `via`; over a tunnel write 0.0.0.0/0 or ::/0".to_owned());
        }
        let prefix: Prefix = dest.parse().map_err(|_| syntax())?;
        if !prefix.is_canonical() {
            return Err(format!(
                "{dest}: host bits are set (use {})",
                prefix.masked()
            ));
        }
        return Ok(StaticRoute {
            prefix,
            via: None,
            port: t,
        });
    }
    let prefix = match *dest {
        "default" => match via {
            Some(IpAddr::V4(_)) => Prefix::V4(0, 0),
            Some(IpAddr::V6(_)) => Prefix::V6(0, 0),
            None => return Err("`default` needs `via` (it names the family)".to_owned()),
        },
        d => {
            let p: Prefix = d.parse().map_err(|_| syntax())?;
            if !p.is_canonical() {
                return Err(format!("{d}: host bits are set (use {})", p.masked()));
            }
            p
        }
    };
    if via.is_none() && port.is_none() {
        return Err(syntax());
    }
    if let Some(v) = via {
        let same_family = matches!(
            (prefix, v),
            (Prefix::V4(..), IpAddr::V4(_)) | (Prefix::V6(..), IpAddr::V6(_))
        );
        if !same_family {
            return Err("the next hop's family differs from the prefix's".to_owned());
        }
        let usable = match v {
            IpAddr::V4(a) => usable_v4(a),
            IpAddr::V6(a) => usable_v6(a),
        };
        if !usable {
            return Err("the next hop must be a unicast address".to_owned());
        }
    }
    let port = match (port, via) {
        (Some(p), _) => p,
        (None, Some(IpAddr::V6(a))) if is_link_local_v6(a) => {
            return Err("a link-local next hop needs `port <n>`".to_owned());
        }
        (None, Some(v)) => connected_port(v, ports)
            .ok_or_else(|| format!("next hop {v} is not inside any port's prefix"))?,
        (None, None) => unreachable!("checked above"),
    };
    Ok(StaticRoute { prefix, via, port })
}

/// The port whose connected prefix contains `ip`, if any (the lowest port wins).
pub fn connected_port(ip: IpAddr, ports: &[PortConfig]) -> Option<u32> {
    ports
        .iter()
        .position(|p| {
            let v4 = p.ipv4.map(|(a, l)| Prefix::V4(u32::from(a), l));
            let v6 = p.ipv6.map(|(a, l)| Prefix::V6(u128::from(a), l));
            v4.into_iter().chain(v6).any(|pre| pre.contains(ip))
        })
        .map(|i| i as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_pairs(pairs.iter().map(|(k, v)| (*k, *v)))
    }

    fn two_ports() -> Vec<(&'static str, &'static str)> {
        vec![
            ("port0.ipv4", "10.0.1.1/24"),
            ("port0.ipv6", "fd00:1::1/64"),
            ("port0.ipv6-link-local", "fe80::1"),
            ("port1.ipv4", "10.0.2.1/24"),
            ("port1.ipv6", "fd00:2::1/64"),
        ]
    }

    #[test]
    fn ports_and_defaults() {
        let c = cfg(&two_ports()).unwrap();
        assert_eq!(c.ports.len(), 2);
        assert_eq!(c.ports[0].mac.to_string(), "02:52:00:00:00:00");
        assert_eq!(c.ports[1].mac.to_string(), "02:52:00:00:00:01");
        assert_eq!(c.ports[0].ipv4, Some(("10.0.1.1".parse().unwrap(), 24)));
        assert_eq!(
            c.ports[0].link_local,
            "fe80::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            c.ports[1].link_local,
            "fe80::52:ff:fe00:1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(c.ports[0].mtu, 1500);
        assert_eq!(c.ttl, 64);
        assert_eq!(c.neighbor.attempts, 3);
        assert_eq!(c.trace_route_lookup, Trace::First);
        // `ports` may add unconfigured ports, but not hide configured ones.
        let mut more = two_ports();
        more.push(("ports", "4"));
        assert_eq!(cfg(&more).unwrap().ports.len(), 4);
        let mut fewer = two_ports();
        fewer.push(("ports", "1"));
        assert!(matches!(cfg(&fewer), Err(ConfigError::Other(_))));
        assert!(matches!(cfg(&[]), Err(ConfigError::Other(_))));
    }

    #[test]
    fn rejects_unknown_and_bad_keys() {
        assert!(matches!(
            cfg(&[("port0.ip", "10.0.0.1/24")]),
            Err(ConfigError::Unknown { .. })
        ));
        assert!(matches!(
            cfg(&[("port00.ipv4", "10.0.0.1/24")]),
            Err(ConfigError::Unknown { .. })
        ));
        assert!(matches!(
            cfg(&[("port16.ipv4", "10.0.0.1/24")]),
            Err(ConfigError::Unknown { .. })
        ));
        assert!(matches!(
            cfg(&[("port0.ipv4", "10.0.0.1")]),
            Err(ConfigError::Invalid { .. })
        ));
        assert!(matches!(
            cfg(&[("port0.ipv6", "fe80::1/64")]),
            Err(ConfigError::Invalid { .. })
        ));
        assert!(matches!(
            cfg(&[("port0.ipv6", "fd00::1/64"), ("port0.mtu", "1000")]),
            Err(ConfigError::Invalid { .. })
        ));
        assert!(matches!(
            cfg(&[("port0.ra", "true")]),
            Err(ConfigError::Other(_))
        ));
        assert!(matches!(
            cfg(&[
                ("port0.ipv4", "10.0.0.1/24"),
                ("trace.ttl-decrement", "some")
            ]),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn routes() {
        let ports = cfg(&two_ports()).unwrap().ports;
        let r = |t: &str| parse_route(t, &ports);
        let v4 = |s: &str| s.parse::<Prefix>().unwrap();
        assert_eq!(
            r("10.0.3.0/24 via 10.0.2.2").unwrap(),
            StaticRoute {
                prefix: v4("10.0.3.0/24"),
                via: Some("10.0.2.2".parse().unwrap()),
                port: 1
            }
        );
        assert_eq!(
            r("default via 10.0.1.254").unwrap().prefix,
            Prefix::V4(0, 0)
        );
        assert_eq!(r("default via fd00:2::9").unwrap().prefix, Prefix::V6(0, 0));
        assert_eq!(r("fd00:3::/64 via fe80::2 port 1").unwrap().port, 1);
        assert_eq!(
            r("10.9.0.0/16 port 0").unwrap(),
            StaticRoute {
                prefix: v4("10.9.0.0/16"),
                via: None,
                port: 0
            }
        );
        for bad in [
            "",
            "10.0.3.0/24",
            "10.0.3.1/24 via 10.0.2.2",
            "10.0.3.0/24 via 10.0.9.2",
            "10.0.3.0/24 via fd00:2::2",
            "fd00:3::/64 via fe80::2",
            "default port 1",
            "10.0.3.0/24 port 7",
            "10.0.3.0/24 via 10.0.2.2 via 10.0.2.3",
            "10.0.3.0/24 via 255.255.255.255 port 1",
            "10.0.3.0/24 gateway 10.0.2.2",
        ] {
            assert!(r(bad).is_err(), "{bad:?} must be rejected");
        }
        let mut with_routes = two_ports();
        with_routes.push(("routes", "10.0.3.0/24 via 10.0.2.2,default via fd00:1::fe"));
        let c = cfg(&with_routes).unwrap();
        assert_eq!(c.routes.len(), 2);
        assert_eq!(c.routes[1].port, 0);
    }
}
