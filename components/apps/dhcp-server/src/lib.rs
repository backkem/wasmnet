//! dhcp-server: a DHCPv4 server (RFC 2131) as a wasmnet app. It hands out
//! addresses from per-subnet pools, with reservations, and serves remote subnets through RFC 1542
//! relay agents (the router's `port<N>.dhcp-relay`). It never returns: a daemon.
//!
//! # Config (`wasi:config`, keys under `app.dhcp-server.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `server-id` | this server's IPv4 address (option 54; also picks the on-link pool) | required |
//! | `listen` | the local socket address | `0.0.0.0:67` |
//! | `pool.<name>.subnet` | the pool's subnet, `10.0.2.0/24` (its mask is option 1) | required |
//! | `pool.<name>.range` | the dynamic addresses, `10.0.2.100-10.0.2.199` | required |
//! | `pool.<name>.router` | option 3 | none |
//! | `pool.<name>.dns` | option 6, one address or a list | none |
//! | `pool.<name>.domain` | option 15 | none |
//! | `pool.<name>.lease` | lease time (whole seconds, option 51) | `3600s` |
//! | `pool.<name>.reserve` | fixed addresses, a list of `mac=ip` (`02:00:00:00:01:10=10.0.1.10`) | none |
//!
//! # Behaviour
//!
//! * **Pool choice:** a relayed message (`giaddr` set) is served from the pool whose subnet holds
//!   `giaddr`; a renewing client's (`ciaddr` set) from the pool that holds `ciaddr`; anything
//!   else from the pool that holds `server-id` (the server's own subnet).
//! * **DISCOVER → OFFER:** the client's reservation, else its current lease or offer, else the
//!   address it asked for (option 50) if free, else the lowest free address of the range. An
//!   offer is held for [`OFFER_HOLD_NS`]. No free address: no answer (`dhcp-pool-exhausted`).
//! * **REQUEST → ACK / NAK:** selecting (option 54 names us: our offer must match, or NAK; it
//!   names another server: our offer is withdrawn, no answer), init-reboot (option 50, no
//!   `ciaddr`: ACK if the address is free or the client's, NAK if it belongs to someone else,
//!   lies outside the subnet, or is one the pool would not assign: outside `range` and not the
//!   client's reservation, or the subnet's network or broadcast address), renewing/rebinding
//!   (`ciaddr`: ACK if it is the client's lease, else NAK).
//! * **RELEASE** frees the lease, **DECLINE** parks the address for one lease time (only the
//!   address offered or leased to that client; any other DECLINE is `dhcp-ignored`), **INFORM**
//!   gets the pool's options without an address.
//! * **Where replies go** (RFC 2131 §4.1): to the relay (`giaddr:67`) when relayed; else unicast
//!   to `ciaddr:68` when the client has an address; else broadcast to `255.255.255.255:68`. A
//!   server on `wasi:sockets` cannot unicast to an unconfigured client (that takes a raw ARP
//!   entry), which RFC 2131 allows ("MAY ... broadcast").
//! * Leases expire lazily: an expired lease is only noticed when its address is wanted again,
//!   so an idle server keeps no timer.
//!
//! # Journal
//!
//! `dhcp-server-listening {address, pools}`; per message `dhcp-offer {mac, ip, pool, relay,
//! hostname}`, `dhcp-ack {mac, ip, hostname, lease-s, phase, relay}` (`phase`: `new`, `renew`,
//! `reboot`, `inform`), `dhcp-nak {mac, ip, reason}`, `dhcp-release {mac, ip}`, `dhcp-decline
//! {mac, ip}`, `dhcp-ignored {mac, type, reason}`, `dhcp-pool-exhausted {mac, pool}`.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
pub use wasmnet_app_kit::app_pairs;

use wasmnet_wire::dhcp::{self, Message, MessageType, opt};
use wasmnet_wire::{MacAddr, parse_duration};

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "dhcp-server";
/// How long an OFFER reserves its address for the client.
pub const OFFER_HOLD_NS: u64 = 60_000_000_000;
/// The default lease time.
pub const DEFAULT_LEASE_S: u32 = 3600;

/// A config value that cannot be used. The app logs it and exits with an error.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("config app.{APP}.{key}={value:?}: expected {expected}")]
    Invalid {
        key: String,
        value: String,
        expected: &'static str,
    },
    #[error("config app.{APP}.{key}: required ({expected})")]
    Missing { key: String, expected: &'static str },
    #[error("config app.{APP}.{key}: unknown key")]
    Unknown { key: String },
}

/// One address pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    pub name: String,
    pub network: Ipv4Addr,
    pub prefix: u8,
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    pub lease_s: u32,
    pub reserved: BTreeMap<MacAddr, Ipv4Addr>,
}

impl Pool {
    pub fn contains(&self, a: Ipv4Addr) -> bool {
        let mask = u32::from(dhcp::prefix_mask(self.prefix));
        u32::from(a) & mask == u32::from(self.network)
    }

    fn in_range(&self, a: Ipv4Addr) -> bool {
        (u32::from(self.first)..=u32::from(self.last)).contains(&u32::from(a))
    }

    /// Whether this pool could give `a` to `mac`: from `range`, or its reservation; never the
    /// subnet's network or broadcast address (subnets of /30 and wider).
    fn assignable(&self, a: Ipv4Addr, mac: MacAddr) -> bool {
        let mask = u32::from(dhcp::prefix_mask(self.prefix));
        let edge = self.prefix <= 30
            && (u32::from(a) == u32::from(self.network) || u32::from(a) | mask == u32::MAX);
        !edge && (self.in_range(a) || self.reserved.get(&mac) == Some(&a))
    }

    /// Options 1, 3, 6, 15 (and 51 when `lease`).
    fn options(&self, m: &mut Message, lease: bool) {
        m.set_option(opt::SUBNET_MASK, &dhcp::prefix_mask(self.prefix).octets());
        if let Some(r) = self.router {
            m.set_option(opt::ROUTER, &r.octets());
        }
        if !self.dns.is_empty() {
            let d: Vec<u8> = self.dns.iter().flat_map(|a| a.octets()).collect();
            m.set_option(opt::DNS_SERVERS, &d);
        }
        if let Some(d) = &self.domain {
            m.set_option(opt::DOMAIN_NAME, d.as_bytes());
        }
        if lease {
            m.set_option(opt::LEASE_TIME, &self.lease_s.to_be_bytes());
        }
    }
}

/// The parsed config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub server_id: Ipv4Addr,
    pub listen: SocketAddr,
    /// In name order.
    pub pools: Vec<Pool>,
}

fn cidr(v: &str) -> Option<(Ipv4Addr, u8)> {
    let (a, p) = v.split_once('/')?;
    let p: u8 = p.parse().ok().filter(|p| *p <= 32)?;
    Some((a.parse().ok()?, p))
}

fn addrs(v: &str) -> Option<Vec<Ipv4Addr>> {
    v.split(',').map(|a| a.trim().parse().ok()).collect()
}

const POOL_KEYS: &[&str] = &[
    "subnet", "range", "router", "dns", "domain", "lease", "reserve",
];

impl Config {
    /// Parses this app's pairs (prefix already stripped). Unknown keys are errors.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Self, ConfigError> {
        let mut server_id = None;
        let mut listen = SocketAddr::from(([0, 0, 0, 0], dhcp::SERVER_PORT));
        let mut raw: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for (key, value) in pairs {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            match key.as_str() {
                "server-id" => {
                    server_id = Some(
                        value
                            .parse::<Ipv4Addr>()
                            .map_err(|_| invalid("an IPv4 address"))?,
                    );
                }
                "listen" => {
                    listen = value
                        .parse()
                        .ok()
                        .filter(SocketAddr::is_ipv4)
                        .ok_or_else(|| invalid("an IPv4 socket address like 0.0.0.0:67"))?;
                }
                _ => match key.strip_prefix("pool.").and_then(|r| r.rsplit_once('.')) {
                    Some((name, k)) if !name.is_empty() && POOL_KEYS.contains(&k) => {
                        raw.entry(name.to_owned())
                            .or_default()
                            .insert(k.to_owned(), value);
                    }
                    _ => return Err(ConfigError::Unknown { key }),
                },
            }
        }
        let server_id = server_id.ok_or_else(|| ConfigError::Missing {
            key: "server-id".into(),
            expected: "this server's IPv4 address",
        })?;
        let mut pools = Vec::new();
        for (name, keys) in raw {
            let key = |k: &str| format!("pool.{name}.{k}");
            let get = |k: &str| keys.get(k).cloned();
            let invalid = |k: &str, expected| ConfigError::Invalid {
                key: key(k),
                value: get(k).unwrap_or_default(),
                expected,
            };
            let (network, prefix) = get("subnet")
                .ok_or_else(|| ConfigError::Missing {
                    key: key("subnet"),
                    expected: "a subnet like 10.0.2.0/24",
                })
                .and_then(|v| {
                    cidr(&v).ok_or_else(|| invalid("subnet", "a subnet like 10.0.2.0/24"))
                })?;
            let network = Ipv4Addr::from(u32::from(network) & u32::from(dhcp::prefix_mask(prefix)));
            let (first, last) = get("range")
                .ok_or_else(|| ConfigError::Missing {
                    key: key("range"),
                    expected: "a range like 10.0.2.100-10.0.2.199",
                })
                .and_then(|v| {
                    v.split_once('-')
                        .and_then(|(a, b)| Some((a.trim().parse().ok()?, b.trim().parse().ok()?)))
                        .ok_or_else(|| invalid("range", "a range like 10.0.2.100-10.0.2.199"))
                })?;
            let mut pool = Pool {
                name: name.clone(),
                network,
                prefix,
                first,
                last,
                router: None,
                dns: Vec::new(),
                domain: None,
                lease_s: DEFAULT_LEASE_S,
                reserved: BTreeMap::new(),
            };
            if !(pool.contains(first) && pool.contains(last) && first <= last) {
                return Err(invalid("range", "a non-empty range inside the subnet"));
            }
            if let Some(v) = get("router") {
                pool.router = Some(
                    v.parse()
                        .map_err(|_| invalid("router", "an IPv4 address"))?,
                );
            }
            if let Some(v) = get("dns") {
                pool.dns = addrs(&v).ok_or_else(|| invalid("dns", "IPv4 addresses"))?;
            }
            if let Some(v) = get("domain") {
                if !wasmnet_wire::dns::valid_name(&v) {
                    return Err(invalid("domain", "a domain name like internal"));
                }
                pool.domain = Some(v);
            }
            if let Some(v) = get("lease") {
                pool.lease_s = parse_duration(&v)
                    .filter(|ns| *ns >= 1_000_000_000 && ns % 1_000_000_000 == 0)
                    .and_then(|ns| u32::try_from(ns / 1_000_000_000).ok())
                    .ok_or_else(|| {
                        invalid("lease", "whole seconds, at least 1s, like 10s or 1h")
                    })?;
            }
            if let Some(v) = get("reserve") {
                for item in v.split(',') {
                    let (mac, ip) = item
                        .split_once('=')
                        .and_then(|(m, i)| {
                            Some((m.trim().parse::<MacAddr>().ok()?, i.trim().parse().ok()?))
                        })
                        .filter(|(_, ip)| pool.contains(*ip))
                        .ok_or_else(|| {
                            invalid("reserve", "a list of mac=ip, the ip inside the subnet")
                        })?;
                    pool.reserved.insert(mac, ip);
                }
            }
            pools.push(pool);
        }
        if pools.is_empty() {
            return Err(ConfigError::Missing {
                key: "pool.<name>.subnet".into(),
                expected: "at least one pool",
            });
        }
        Ok(Config {
            server_id,
            listen,
            pools,
        })
    }
}

/// A lease or an offer.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Lease {
    mac: MacAddr,
    expires: u64,
    bound: bool,
}

/// One reply to send, and the journal event that explains it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub to: SocketAddr,
    pub message: Message,
}

/// One journal event: kind and fields.
pub type Note = (&'static str, Vec<(String, String)>);

/// The server's state: leases per address.
#[derive(Debug)]
pub struct Server {
    pub config: Config,
    /// Per pool: address → lease (offered, bound or declined).
    leases: BTreeMap<Ipv4Addr, Lease>,
}

fn kv(k: &str, v: impl ToString) -> (String, String) {
    (k.to_owned(), v.to_string())
}

/// Declined addresses are parked under this MAC.
const DECLINED: MacAddr = MacAddr::ZERO;

impl Server {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            leases: BTreeMap::new(),
        }
    }

    fn pool_for(&self, m: &Message) -> Option<&Pool> {
        let key = if !m.giaddr.is_unspecified() {
            m.giaddr
        } else if !m.ciaddr.is_unspecified() {
            m.ciaddr
        } else {
            self.config.server_id
        };
        self.config.pools.iter().find(|p| p.contains(key))
    }

    /// Whether `ip` is usable for `mac` at `now`: in the pool, not the server or router, and
    /// free (or already the client's).
    fn free_for(&self, pool: &Pool, ip: Ipv4Addr, mac: MacAddr, now: u64) -> bool {
        let reserved_by_other = pool.reserved.iter().any(|(m, a)| *a == ip && *m != mac);
        let taken = self
            .leases
            .get(&ip)
            .is_some_and(|l| l.mac != mac && l.expires > now);
        pool.contains(ip)
            && ip != self.config.server_id
            && Some(ip) != pool.router
            && !reserved_by_other
            && !taken
    }

    /// The client's address in `pool`: reservation, current lease or offer, its wish, the lowest
    /// free one.
    fn choose(
        &self,
        pool: &Pool,
        mac: MacAddr,
        wish: Option<Ipv4Addr>,
        now: u64,
    ) -> Option<Ipv4Addr> {
        if let Some(&ip) = pool.reserved.get(&mac) {
            return Some(ip);
        }
        let current = self
            .leases
            .iter()
            .find(|(ip, l)| l.mac == mac && l.expires > now && pool.contains(**ip))
            .map(|(ip, _)| *ip);
        if current.is_some() {
            return current;
        }
        if let Some(w) = wish.filter(|w| pool.in_range(*w) && self.free_for(pool, *w, mac, now)) {
            return Some(w);
        }
        (u32::from(pool.first)..=u32::from(pool.last))
            .map(Ipv4Addr::from)
            .find(|ip| self.free_for(pool, *ip, mac, now))
    }

    /// Where a reply to `m` goes (RFC 2131 §4.1).
    fn destination(m: &Message, nak: bool) -> SocketAddr {
        if !m.giaddr.is_unspecified() {
            SocketAddr::V4(SocketAddrV4::new(m.giaddr, dhcp::SERVER_PORT))
        } else if !m.ciaddr.is_unspecified() && !nak {
            SocketAddr::V4(SocketAddrV4::new(m.ciaddr, dhcp::CLIENT_PORT))
        } else {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, dhcp::CLIENT_PORT))
        }
    }

    fn reply(&self, req: &Message, kind: MessageType, pool: &Pool, yiaddr: Ipv4Addr) -> Reply {
        let mut m = Message::reply_to(req, kind);
        m.yiaddr = yiaddr;
        m.set_option(opt::SERVER_ID, &self.config.server_id.octets());
        let lease =
            kind != MessageType::Nak && !(kind == MessageType::Ack && yiaddr.is_unspecified());
        if kind == MessageType::Ack && yiaddr.is_unspecified() {
            m.ciaddr = req.ciaddr; // INFORM
        }
        if kind != MessageType::Nak {
            pool.options(&mut m, lease);
        }
        Reply {
            to: Self::destination(req, kind == MessageType::Nak),
            message: m,
        }
    }

    fn nak(
        &self,
        req: &Message,
        mac: MacAddr,
        ip: Ipv4Addr,
        reason: &str,
        notes: &mut Vec<Note>,
    ) -> Option<Reply> {
        notes.push((
            "dhcp-nak",
            vec![kv("mac", mac), kv("ip", ip), kv("reason", reason)],
        ));
        let mut m = Message::reply_to(req, MessageType::Nak);
        m.set_option(opt::SERVER_ID, &self.config.server_id.octets());
        Some(Reply {
            to: Self::destination(req, true),
            message: m,
        })
    }

    /// Handles one datagram's payload at `now`. Returns the reply (if any) and journal notes.
    pub fn handle(&mut self, now: u64, payload: &[u8]) -> (Option<Reply>, Vec<Note>) {
        let mut notes = Vec::new();
        let reply = self.handle_inner(now, payload, &mut notes);
        (reply, notes)
    }

    fn handle_inner(&mut self, now: u64, payload: &[u8], notes: &mut Vec<Note>) -> Option<Reply> {
        let ignore = |notes: &mut Vec<Note>, mac: String, kind: &str, reason: &str| {
            notes.push((
                "dhcp-ignored",
                vec![kv("mac", mac), kv("type", kind), kv("reason", reason)],
            ));
            None
        };
        let Ok(m) = Message::parse(payload) else {
            return ignore(notes, String::new(), "", "malformed");
        };
        let kind = m.message_type();
        let kind_name = kind.map_or("bootp", MessageType::name);
        let (Some(mac), true) = (m.client_mac(), m.op == dhcp::BOOTREQUEST) else {
            return ignore(
                notes,
                String::new(),
                kind_name,
                "not a request from an Ethernet client",
            );
        };
        let Some(kind) = kind else {
            return ignore(
                notes,
                mac.to_string(),
                kind_name,
                "no message type (plain BOOTP)",
            );
        };
        let Some(pool) = self.pool_for(&m).cloned() else {
            return ignore(notes, mac.to_string(), kind_name, "no pool for this subnet");
        };
        let hostname = m.text_option(opt::HOSTNAME).unwrap_or_default();
        let relay = if m.giaddr.is_unspecified() {
            String::new()
        } else {
            m.giaddr.to_string()
        };
        match kind {
            MessageType::Discover => {
                let Some(ip) = self.choose(&pool, mac, m.addr_option(opt::REQUESTED_IP), now)
                else {
                    notes.push((
                        "dhcp-pool-exhausted",
                        vec![kv("mac", mac), kv("pool", &pool.name)],
                    ));
                    return None;
                };
                let held = self.leases.get(&ip).filter(|l| l.mac == mac && l.bound);
                let expires = match held {
                    Some(l) => l.expires.max(now + OFFER_HOLD_NS),
                    None => now + OFFER_HOLD_NS,
                };
                let bound = held.is_some();
                self.leases.insert(
                    ip,
                    Lease {
                        mac,
                        expires,
                        bound,
                    },
                );
                notes.push((
                    "dhcp-offer",
                    vec![
                        kv("mac", mac),
                        kv("ip", ip),
                        kv("pool", &pool.name),
                        kv("relay", relay),
                        kv("hostname", &hostname),
                    ],
                ));
                Some(self.reply(&m, MessageType::Offer, &pool, ip))
            }
            MessageType::Request => {
                let server = m.addr_option(opt::SERVER_ID);
                let wish = m.addr_option(opt::REQUESTED_IP);
                let (ip, how) = match (server, wish, m.ciaddr.is_unspecified()) {
                    // SELECTING: the client picked a server.
                    (Some(s), _, _) if s != self.config.server_id => {
                        self.leases.retain(|_, l| !(l.mac == mac && !l.bound));
                        return ignore(
                            notes,
                            mac.to_string(),
                            kind_name,
                            "another server was selected",
                        );
                    }
                    (Some(_), Some(ip), _) => {
                        let ours = self
                            .leases
                            .get(&ip)
                            .is_some_and(|l| l.mac == mac && l.expires > now);
                        if !ours {
                            return self.nak(&m, mac, ip, "not offered", notes);
                        }
                        (ip, "new")
                    }
                    // INIT-REBOOT: the client asks for its old address.
                    (None, Some(ip), true) => {
                        if !pool.contains(ip) {
                            return self.nak(&m, mac, ip, "wrong subnet", notes);
                        }
                        // RFC 2131 §4.3.2: an address this server would not assign (outside
                        // `range` and not the client's reservation, or the subnet's network or
                        // broadcast address) is incorrect: NAK.
                        if !pool.assignable(ip, mac) {
                            return self.nak(&m, mac, ip, "not assignable", notes);
                        }
                        if !self.free_for(&pool, ip, mac, now) {
                            return self.nak(&m, mac, ip, "in use", notes);
                        }
                        (ip, "reboot")
                    }
                    // RENEWING / REBINDING.
                    (None, _, false) => {
                        let ip = m.ciaddr;
                        let ours = self
                            .leases
                            .get(&ip)
                            .is_some_and(|l| l.mac == mac && l.bound && l.expires > now);
                        if !ours {
                            return self.nak(&m, mac, ip, "no lease", notes);
                        }
                        (ip, "renew")
                    }
                    _ => return ignore(notes, mac.to_string(), kind_name, "malformed request"),
                };
                self.leases.insert(
                    ip,
                    Lease {
                        mac,
                        expires: now + u64::from(pool.lease_s) * 1_000_000_000,
                        bound: true,
                    },
                );
                notes.push((
                    "dhcp-ack",
                    vec![
                        kv("mac", mac),
                        kv("ip", ip),
                        kv("hostname", &hostname),
                        kv("lease-s", pool.lease_s),
                        kv("phase", how),
                        kv("relay", relay),
                    ],
                ));
                Some(self.reply(&m, MessageType::Ack, &pool, ip))
            }
            MessageType::Release => {
                if self.leases.get(&m.ciaddr).is_some_and(|l| l.mac == mac) {
                    self.leases.remove(&m.ciaddr);
                }
                notes.push(("dhcp-release", vec![kv("mac", mac), kv("ip", m.ciaddr)]));
                None
            }
            MessageType::Decline => {
                if let Some(ip) = requested(&m) {
                    // RFC 2131 §4.3.3: a client declines the address this server offered or
                    // leased to it. A DECLINE for any other address (another client's, or one
                    // outside the pool) changes nothing.
                    let ours =
                        pool.contains(ip) && self.leases.get(&ip).is_some_and(|l| l.mac == mac);
                    if !ours {
                        return ignore(
                            notes,
                            mac.to_string(),
                            kind_name,
                            "declined an address not offered to it",
                        );
                    }
                    self.leases.insert(
                        ip,
                        Lease {
                            mac: DECLINED,
                            expires: now + u64::from(pool.lease_s) * 1_000_000_000,
                            bound: false,
                        },
                    );
                    notes.push(("dhcp-decline", vec![kv("mac", mac), kv("ip", ip)]));
                }
                None
            }
            MessageType::Inform => {
                notes.push((
                    "dhcp-ack",
                    vec![
                        kv("mac", mac),
                        kv("ip", m.ciaddr),
                        kv("hostname", &hostname),
                        kv("lease-s", ""),
                        kv("phase", "inform"),
                        kv("relay", relay),
                    ],
                ));
                Some(self.reply(&m, MessageType::Ack, &pool, Ipv4Addr::UNSPECIFIED))
            }
            MessageType::Offer | MessageType::Ack | MessageType::Nak => {
                ignore(notes, mac.to_string(), kind_name, "a server message")
            }
            _ => ignore(
                notes,
                mac.to_string(),
                kind_name,
                "a message type it does not serve",
            ),
        }
    }

    /// Addresses currently leased or offered (not expired) at `now`, for tests and logs.
    pub fn leased(&self, now: u64) -> Vec<(Ipv4Addr, MacAddr, bool)> {
        self.leases
            .iter()
            .filter(|(_, l)| l.expires > now && l.mac != DECLINED)
            .map(|(ip, l)| (*ip, l.mac, l.bound))
            .collect()
    }
}

fn requested(m: &Message) -> Option<Ipv4Addr> {
    m.addr_option(opt::REQUESTED_IP)
}

#[cfg(test)]
mod tests;
