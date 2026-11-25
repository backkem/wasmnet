//! The netstack's configuration, read from `wasi:config/store`.
//!
//! Keys (every key is optional; unknown keys are an error, so typos fail loudly):
//!
//! | key | value | default |
//! |---|---|---|
//! | `mac` | unicast MAC `02:00:00:00:00:01` | derived from the seeded `wasi:random` |
//! | `mtu` | IP MTU, 1280..=9000 (the frame is MTU + 14 bytes) | `1500` |
//! | `ipv4` | `10.0.0.1/24` | none (no IPv4) |
//! | `ipv4-gateway` | `10.0.0.254` (needs `ipv4`) | none |
//! | `ipv6` | a global address `2001:db8::1/64` | none |
//! | `ipv6-link-local` | `fe80::1` (prefix /64) | EUI-64 from the MAC |
//! | `ipv6-gateway` | `fe80::1` | none |
//! | `hop-limit` | unicast TTL / hop limit, 1..=255 | `64` |
//! | `multicast-hop-limit` | TTL / hop limit for multicast destinations, 1..=255 | `1` |
//!
//! Name lookup and the driver:
//!
//! | key | value | default |
//! |---|---|---|
//! | `hosts.<name>` | static name resolution for `ip-name-lookup`: one address or a list (`10.0.0.1,fd00::1`); names are ASCII, matched case-insensitively | none |
//! | `driver.timer-churn` | a test key, a stress mode (a duration): every driver pass cancels its pending timer and arms a new one, at the stack's deadline or `now + churn` (driver rule 4, inverted on purpose) | off |
//! | `app.<app>.<key>` | an app's own config, read by the app and ignored here | |
//!
//! DHCP and DNS:
//!
//! | key | value | default |
//! |---|---|---|
//! | `ipv4` | also `dhcp`: no static IPv4; a DHCPv4 client (smoltcp's) leases the address, the default gateway and the DNS servers | |
//! | `hostname` | a host name sent in DHCP option 12 (with `ipv4 = "dhcp"`) | none |
//! | `dns` | DNS servers for `ip-name-lookup`, one address or a list; they replace the ones a DHCP lease names | the lease's |
//! | `resolver.timeout` | how long one DNS try waits for its answer | `5s` |
//! | `resolver.attempts` | rounds over the DNS server list, 1..=5 | `2` |
//!
//! Multicast and mDNS:
//!
//! | key | value | default |
//! |---|---|---|
//! | `resolver.mdns-timeout` | how long one mDNS query for a `.local` name waits | `1s` |
//! | `resolver.mdns-attempts` | mDNS queries before a `.local` name is unresolvable, 1..=5 | `3` |
//! | `multicast-hop-limit` | also the default of `wasmnet:sockets-ext/multicast` hop limits | `1` |
//!
//! TCP:
//!
//! | key | value | default |
//! |---|---|---|
//! | `tcp.congestion` | the congestion controller of every TCP connection: `reno`, or `none` (the whole send window at once) | `reno` |

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wasmnet_wire::{MacAddr, parse_duration};

/// A config value that could not be used. The component logs it and traps.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("config {key}={value:?}: expected {expected}")]
    Invalid {
        key: String,
        value: String,
        expected: &'static str,
    },
    #[error("config {key}: required ({expected})")]
    Missing { key: String, expected: &'static str },
    #[error("config {key}: unknown key")]
    Unknown { key: String },
}

/// An address with its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr<A> {
    pub addr: A,
    pub prefix: u8,
}

/// The parsed configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// `None`: derive one from the seeded RNG.
    pub mac: Option<MacAddr>,
    /// IP MTU (payload after the Ethernet header).
    pub mtu: u16,
    pub ipv4: Option<Cidr<Ipv4Addr>>,
    pub ipv4_gateway: Option<Ipv4Addr>,
    pub ipv6: Option<Cidr<Ipv6Addr>>,
    /// `None`: EUI-64 from the MAC.
    pub ipv6_link_local: Option<Ipv6Addr>,
    pub ipv6_gateway: Option<Ipv6Addr>,
    pub hop_limit: u8,
    pub multicast_hop_limit: u8,
    /// `hosts.<name>`: lowercase name to its addresses, in the configured order.
    pub hosts: BTreeMap<String, Vec<IpAddr>>,
    /// `driver.timer-churn`: the stress mode's re-arm period, if on.
    pub timer_churn_ns: Option<u64>,
    /// `ipv4 = "dhcp"`: lease the IPv4 configuration.
    pub dhcp: bool,
    /// `hostname`: DHCP option 12.
    pub hostname: Option<String>,
    /// `dns`: static DNS servers (they replace the lease's).
    pub dns: Vec<IpAddr>,
    pub resolver_timeout_ns: u64,
    pub resolver_attempts: u32,
    /// One-shot mDNS queries for `.local` names.
    pub mdns_timeout_ns: u64,
    pub mdns_attempts: u32,
    /// `tcp.congestion`: the congestion controller of every TCP connection.
    pub tcp_congestion: crate::tcp::Congestion,
    /// `snapshot.paused`: the node waits for a `wasmnet:netstack/state`
    /// restore before it does anything (set by an embedder that restores the stack before it
    /// starts).
    pub paused: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mac: None,
            mtu: 1500,
            ipv4: None,
            ipv4_gateway: None,
            ipv6: None,
            ipv6_link_local: None,
            ipv6_gateway: None,
            hop_limit: 64,
            multicast_hop_limit: 1,
            hosts: BTreeMap::new(),
            timer_churn_ns: None,
            dhcp: false,
            hostname: None,
            dns: Vec::new(),
            resolver_timeout_ns: crate::resolver::DEFAULT_TIMEOUT_NS,
            resolver_attempts: crate::resolver::DEFAULT_ATTEMPTS,
            mdns_timeout_ns: crate::resolver::DEFAULT_MDNS_TIMEOUT_NS,
            mdns_attempts: crate::resolver::DEFAULT_MDNS_ATTEMPTS,
            tcp_congestion: crate::tcp::Congestion::default(),
            paused: false,
        }
    }
}

const TOP_KEYS: &[&str] = &[
    "mac",
    "snapshot.paused",
    "mtu",
    "ipv4",
    "ipv4-gateway",
    "ipv6",
    "ipv6-link-local",
    "ipv6-gateway",
    "hop-limit",
    "multicast-hop-limit",
    "hostname",
    "dns",
    "resolver.timeout",
    "resolver.attempts",
    "resolver.mdns-timeout",
    "resolver.mdns-attempts",
    "tcp.congestion",
];
/// Keys under this prefix belong to the node's apps (`app.<app>.<key>`).
pub const APP_PREFIX: &str = "app.";

/// A host name for `hosts.<name>`: ASCII letters, digits, `-` and `.`, not starting or ending
/// with a dot.
pub fn is_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// The link-local address of `mac` (RFC 4291 modified EUI-64: flip the U/L bit, insert ff:fe).
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

fn is_link_local_v6(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

/// Parses `addr/prefix`.
fn cidr<A: std::str::FromStr>(text: &str, max_prefix: u8) -> Option<Cidr<A>> {
    let (addr, prefix) = text.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= max_prefix).then_some(())?;
    Some(Cidr {
        addr: addr.parse().ok()?,
        prefix,
    })
}

struct Reader<'a> {
    map: &'a BTreeMap<String, String>,
}

impl Reader<'_> {
    fn get<T>(
        &self,
        key: &str,
        expected: &'static str,
        parse: impl Fn(&str) -> Option<T>,
    ) -> Result<Option<T>, ConfigError> {
        match self.map.get(key) {
            None => Ok(None),
            Some(value) => parse(value).map(Some).ok_or_else(|| ConfigError::Invalid {
                key: key.to_owned(),
                value: value.clone(),
                expected,
            }),
        }
    }
}

fn int<T: std::str::FromStr + PartialOrd>(lo: T, hi: T) -> impl Fn(&str) -> Option<T> {
    move |v| v.parse::<T>().ok().filter(|n| *n >= lo && *n <= hi)
}

fn positive_duration(v: &str) -> Option<u64> {
    parse_duration(v).filter(|&ns| ns > 0)
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
        let d = Config::default();

        let mut hosts = BTreeMap::new();
        for (key, value) in &map {
            let unknown = || ConfigError::Unknown { key: key.clone() };
            if key.starts_with(APP_PREFIX) || key == "driver.timer-churn" {
                continue;
            }
            if let Some(name) = key.strip_prefix("hosts.") {
                let invalid = |expected| ConfigError::Invalid {
                    key: key.clone(),
                    value: value.clone(),
                    expected,
                };
                if !is_host_name(name) {
                    return Err(ConfigError::Invalid {
                        key: key.clone(),
                        value: name.to_owned(),
                        expected: "a host name of ASCII letters, digits, `-` and `.`",
                    });
                }
                let addrs = value
                    .split(',')
                    .map(|a| {
                        a.trim()
                            .parse::<IpAddr>()
                            .ok()
                            .filter(|a| !a.is_unspecified())
                    })
                    .collect::<Option<Vec<IpAddr>>>()
                    .ok_or_else(|| invalid("one IP address or a list like 10.0.0.1,fd00::1"))?;
                hosts.insert(name.to_ascii_lowercase(), addrs);
                continue;
            }
            if !TOP_KEYS.contains(&key.as_str()) {
                // `ping.*` is unknown too: ping is the `ping` app.
                return Err(unknown());
            }
        }

        let mac = r.get("mac", "a unicast MAC like 02:00:00:00:00:01", |v| {
            v.parse::<MacAddr>().ok().filter(|m| m.is_unicast())
        })?;
        let mtu = r
            .get("mtu", "an IP MTU from 1280 to 9000", int(1280u16, 9000))?
            .unwrap_or(d.mtu);
        let dhcp = map.get("ipv4").is_some_and(|v| v == "dhcp");
        let ipv4 = if dhcp {
            None
        } else {
            r.get(
                "ipv4",
                "an address with a prefix like 10.0.0.1/24, or dhcp",
                |v| {
                    cidr::<Ipv4Addr>(v, 32).filter(|c| {
                        !(c.addr.is_unspecified() || c.addr.is_multicast() || c.addr.is_broadcast())
                    })
                },
            )?
        };
        let hostname = r.get("hostname", "a host name like web or web.internal", |v| {
            wasmnet_wire::dns::valid_name(v).then(|| v.to_owned())
        })?;
        let dns = r
            .get(
                "dns",
                "one IP address or a list like 10.0.1.2,fd00:1::2",
                |v| {
                    v.split(',')
                        .map(|a| {
                            a.trim().parse::<IpAddr>().ok().filter(|a| {
                                !(a.is_unspecified() || a.is_multicast() || a.is_loopback())
                            })
                        })
                        .collect::<Option<Vec<IpAddr>>>()
                },
            )?
            .unwrap_or_default();
        let resolver_timeout_ns = r
            .get(
                "resolver.timeout",
                "a duration above zero like 5s",
                positive_duration,
            )?
            .unwrap_or(d.resolver_timeout_ns);
        let resolver_attempts = r
            .get("resolver.attempts", "an integer from 1 to 5", int(1u32, 5))?
            .unwrap_or(d.resolver_attempts);
        let mdns_timeout_ns = r
            .get(
                "resolver.mdns-timeout",
                "a duration above zero like 1s",
                positive_duration,
            )?
            .unwrap_or(d.mdns_timeout_ns);
        let mdns_attempts = r
            .get(
                "resolver.mdns-attempts",
                "an integer from 1 to 5",
                int(1u32, 5),
            )?
            .unwrap_or(d.mdns_attempts);
        let ipv4_gateway = r.get("ipv4-gateway", "a unicast IPv4 address", |v| {
            v.parse::<Ipv4Addr>()
                .ok()
                .filter(|a| !(a.is_unspecified() || a.is_multicast() || a.is_broadcast()))
        })?;
        if ipv4_gateway.is_some() && ipv4.is_none() {
            return Err(ConfigError::Missing {
                key: "ipv4".to_owned(),
                expected: "a static IPv4 address, because ipv4-gateway is set",
            });
        }
        let ipv6 = r.get(
            "ipv6",
            "a global unicast address with a prefix like 2001:db8::1/64",
            |v| {
                cidr::<Ipv6Addr>(v, 128).filter(|c| {
                    !(c.addr.is_unspecified()
                        || c.addr.is_multicast()
                        || c.addr.is_loopback()
                        || is_link_local_v6(c.addr))
                })
            },
        )?;
        let ipv6_link_local = r.get(
            "ipv6-link-local",
            "a link-local address like fe80::1",
            |v| v.parse::<Ipv6Addr>().ok().filter(|a| is_link_local_v6(*a)),
        )?;
        let ipv6_gateway = r.get("ipv6-gateway", "a unicast IPv6 address", |v| {
            v.parse::<Ipv6Addr>()
                .ok()
                .filter(|a| !(a.is_unspecified() || a.is_multicast()))
        })?;
        let hop_limit = r
            .get("hop-limit", "an integer from 1 to 255", int(1u8, 255))?
            .unwrap_or(d.hop_limit);
        let multicast_hop_limit = r
            .get(
                "multicast-hop-limit",
                "an integer from 1 to 255",
                int(1u8, 255),
            )?
            .unwrap_or(d.multicast_hop_limit);

        Ok(Self {
            mac,
            mtu,
            ipv4,
            ipv4_gateway,
            ipv6,
            ipv6_link_local,
            ipv6_gateway,
            hop_limit,
            multicast_hop_limit,
            hosts,
            timer_churn_ns: r.get(
                "driver.timer-churn",
                "a duration above zero like 1ms",
                positive_duration,
            )?,
            dhcp,
            hostname,
            dns,
            resolver_timeout_ns,
            resolver_attempts,
            mdns_timeout_ns,
            mdns_attempts,
            tcp_congestion: r
                .get(
                    "tcp.congestion",
                    "reno or none",
                    crate::tcp::Congestion::parse,
                )?
                .unwrap_or(d.tcp_congestion),
            paused: r
                .get("snapshot.paused", "true or false", |v| {
                    v.parse::<bool>().ok()
                })?
                .unwrap_or(false),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_pairs(pairs.iter().copied())
    }

    #[test]
    fn defaults_and_a_full_config() {
        assert_eq!(parse(&[]).unwrap(), Config::default());
        let c = parse(&[
            ("mac", "02:00:00:00:00:01"),
            ("mtu", "9000"),
            ("ipv4", "10.0.0.1/24"),
            ("ipv4-gateway", "10.0.0.254"),
            ("ipv6", "2001:db8::1/64"),
            ("ipv6-gateway", "fe80::1"),
            ("hop-limit", "32"),
            ("multicast-hop-limit", "255"),
        ])
        .unwrap();
        assert_eq!(c.mtu, 9000);
        assert_eq!(
            c.ipv4,
            Some(Cidr {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                prefix: 24
            })
        );
        assert_eq!(c.ipv6.unwrap().prefix, 64);
        assert_eq!((c.hop_limit, c.multicast_hop_limit), (32, 255));
    }

    #[test]
    fn tcp_congestion_names_a_controller() {
        use crate::tcp::Congestion;
        assert_eq!(parse(&[]).unwrap().tcp_congestion, Congestion::Reno);
        for (v, want) in [("reno", Congestion::Reno), ("none", Congestion::None)] {
            let c = parse(&[("tcp.congestion", v)]).unwrap();
            assert_eq!(c.tcp_congestion, want);
            assert_eq!(want.name(), v);
        }
        assert!(matches!(
            parse(&[("tcp.congestion", "Reno")]),
            Err(ConfigError::Invalid { .. })
        ));
        assert!(matches!(
            parse(&[("tcp.congestion", "cubic")]),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn eui64_flips_the_universal_local_bit() {
        let mac: MacAddr = "02:00:00:00:00:02".parse().unwrap();
        assert_eq!(
            eui64_link_local(mac),
            "fe80::ff:fe00:2".parse::<Ipv6Addr>().unwrap()
        );
        let mac: MacAddr = "00:1b:21:aa:bb:cc".parse().unwrap();
        assert_eq!(
            eui64_link_local(mac),
            "fe80::21b:21ff:feaa:bbcc".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn hosts_churn_and_app_keys() {
        let c = parse(&[
            ("hosts.Server", "10.0.0.1"),
            ("hosts.web.internal", "10.0.0.2, fd00::2"),
            ("driver.timer-churn", "1ms"),
            ("app.udp-echo-client.count", "3"),
            ("app.anything.goes", "here"),
        ])
        .unwrap();
        assert_eq!(
            c.hosts.into_iter().collect::<Vec<_>>(),
            [
                ("server".to_owned(), vec!["10.0.0.1".parse().unwrap()]),
                (
                    "web.internal".to_owned(),
                    vec!["10.0.0.2".parse().unwrap(), "fd00::2".parse().unwrap()]
                ),
            ]
        );
        assert_eq!(c.timer_churn_ns, Some(1_000_000));
        for (pairs, needle) in [
            (&[("hosts.a", "nope")][..], "hosts.a"),
            (&[("hosts.a", "0.0.0.0")][..], "hosts.a"),
            (&[("hosts.a_b", "10.0.0.1")][..], "host name"),
            (&[("hosts..a", "10.0.0.1")][..], "host name"),
            (&[("driver.timer-churn", "0")][..], "timer-churn"),
            (&[("driver.other", "1")][..], "unknown"),
        ] {
            let err = parse(pairs).unwrap_err().to_string();
            assert!(err.contains(needle), "{pairs:?}: {err}");
        }
    }

    #[test]
    fn dhcp_dns_and_resolver_keys() {
        let c = parse(&[
            ("ipv4", "dhcp"),
            ("hostname", "alice"),
            ("dns", "10.0.1.2, fd00:1::2"),
            ("resolver.timeout", "1s"),
            ("resolver.attempts", "3"),
        ])
        .unwrap();
        assert!(c.dhcp && c.ipv4.is_none());
        assert_eq!(c.hostname.as_deref(), Some("alice"));
        assert_eq!(c.dns.len(), 2);
        assert_eq!(
            (c.resolver_timeout_ns, c.resolver_attempts),
            (1_000_000_000, 3)
        );
        let d = parse(&[]).unwrap();
        assert!(!d.dhcp && d.dns.is_empty() && d.hostname.is_none());
        for (pairs, needle) in [
            (&[("ipv4", "dhcpv4")][..], "or dhcp"),
            (
                &[("ipv4", "dhcp"), ("ipv4-gateway", "10.0.0.1")][..],
                "static",
            ),
            (&[("dns", "10.0.0.1,nope")][..], "dns"),
            (&[("dns", "0.0.0.0")][..], "dns"),
            (&[("hostname", "a b")][..], "hostname"),
            (&[("resolver.attempts", "0")][..], "attempts"),
            (&[("resolver.retries", "1")][..], "unknown"),
        ] {
            let err = parse(pairs).unwrap_err().to_string();
            assert!(err.contains(needle), "{pairs:?}: {err}");
        }
    }

    #[test]
    fn rejects_bad_values_and_unknown_keys() {
        for (pairs, needle) in [
            (&[("mac", "01:00:5e:00:00:01")][..], "mac"),
            (&[("mtu", "1000")][..], "mtu"),
            (&[("ipv4", "10.0.0.1")][..], "ipv4"),
            (&[("ipv4", "10.0.0.1/33")][..], "ipv4"),
            (&[("ipv6", "fe80::1/64")][..], "ipv6"),
            (&[("ipv6-link-local", "2001:db8::1")][..], "ipv6-link-local"),
            (&[("ipv4-gateway", "10.0.0.1")][..], "ipv4"),
            (&[("colour", "red")][..], "colour"),
            // The old built-in pinger's keys are gone: ping is the `ping` app.
            (&[("ping.target", "10.0.0.2")][..], "unknown"),
            (&[("ping.x.target", "fe80::2")][..], "unknown"),
        ] {
            let err = parse(pairs).unwrap_err().to_string();
            assert!(err.contains(needle), "{pairs:?}: {err}");
        }
    }
}
