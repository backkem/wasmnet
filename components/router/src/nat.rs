//! Address and port translation (NAT44 with port translation): the table of mappings and
//! sessions, port allocation, filtering, port forwards and expiry. RFC 4787 (UDP behaviours),
//! RFC 5382 (TCP), RFC 5508 (ICMP). The design is in `docs/design/nat.md`.
//!
//! This module only answers questions about endpoints: which external port an inside endpoint
//! leaves with ([`Nat::outbound`]), which inside endpoint an inbound packet is for and whether
//! filtering lets it in ([`Nat::inbound`]), and the lookups an ICMP error needs. The router
//! decides when to ask, and rewrites the bytes (`wire::rewrite_v4`).
//!
//! * A **mapping** binds an inside endpoint (address and port, or an ICMP echo identifier) to an
//!   external port on an outside port's address. [`Dependence`] (`nat.mapping`) says which
//!   outbound packets share one; every mapping has its own external port.
//! * A **session** is one remote endpoint a mapping talks to, with its idle timer and TCP state
//!   ([`Track`]). Filtering (`nat.filtering`) checks an inbound packet's source against them.
//!   A mapping expires with its last session (a forward never does).
//! * Allocation is deterministic: the inside port if it is free (`preserve`), else the next free
//!   port of the range after a per-protocol cursor.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv4Addr;

use crate::config::Trace;
use crate::track::{Timeouts, Track};
use crate::wire::{PROTO_ICMP, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_SYN};
use crate::{Event, Sink};

/// `first`-mode trace sets stop growing here.
const TRACE_CAP: usize = 4096;
/// The most forwards a router holds.
pub const MAX_FORWARDS: usize = 256;

/// An IPv4 address and a port (or an ICMP echo identifier).
pub type Endpoint = (Ipv4Addr, u16);

fn ep((a, p): Endpoint) -> String {
    format!("{a}:{p}")
}

fn kv(k: &str, v: impl ToString) -> (String, String) {
    (k.to_owned(), v.to_string())
}

/// A translated protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {
    Icmp,
    Tcp,
    Udp,
}

impl Proto {
    pub fn from_number(n: u8) -> Option<Self> {
        match n {
            PROTO_ICMP => Some(Self::Icmp),
            PROTO_TCP => Some(Self::Tcp),
            PROTO_UDP => Some(Self::Udp),
            _ => None,
        }
    }

    pub fn number(self) -> u8 {
        match self {
            Self::Icmp => PROTO_ICMP,
            Self::Tcp => PROTO_TCP,
            Self::Udp => PROTO_UDP,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// RFC 4787's three behaviours, for mapping (`nat.mapping`) and for filtering
/// (`nat.filtering`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dependence {
    /// Endpoint-independent: one mapping per inside endpoint / any remote may send.
    Endpoint,
    /// Address-dependent: per remote address / only addresses the mapping sent to.
    Address,
    /// Address-and-port-dependent: per remote endpoint / only endpoints the mapping sent to.
    AddressAndPort,
}

impl Dependence {
    pub fn parse(v: &str) -> Option<Self> {
        match v {
            "endpoint-independent" => Some(Self::Endpoint),
            "address-dependent" => Some(Self::Address),
            "address-and-port-dependent" => Some(Self::AddressAndPort),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint-independent",
            Self::Address => "address-dependent",
            Self::AddressAndPort => "address-and-port-dependent",
        }
    }
}

/// How external ports are chosen (`nat.port-allocation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allocation {
    /// The inside port when it is free, else the next free port of the range.
    Preserve,
    /// Always the next free port of the range.
    Sequential,
}

/// A port forward: `<proto> <external> to <addr>:<port> port <n>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Forward {
    pub proto: Proto,
    pub external: u16,
    pub internal: Endpoint,
    /// The outside router port it listens on.
    pub port: u32,
}

impl fmt::Display for Forward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} to {} port {}",
            self.proto,
            self.external,
            ep(self.internal),
            self.port
        )
    }
}

/// Parses a forward, `<proto> <external-port> to <addr>:<port> [port <n>]`, where `nat_ports`
/// are the router ports that translate (without `port`, the lowest one).
pub fn parse_forward(text: &str, nat_ports: &[u32]) -> Result<Forward, String> {
    let syntax = || {
        "a forward like `tcp 8080 to 192.168.1.10:80` or `udp 5000 to 192.168.1.20:5000 port 1`"
            .to_owned()
    };
    let words: Vec<&str> = text.split_whitespace().collect();
    let (proto, external, to, internal, rest) = match words.as_slice() {
        [p, e, t, i, rest @ ..] => (*p, *e, *t, *i, rest),
        _ => return Err(syntax()),
    };
    let proto = match proto {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        _ => return Err(format!("`{proto}`: a forward is `tcp` or `udp`")),
    };
    let external: u16 = external
        .parse()
        .ok()
        .filter(|&p| p > 0)
        .ok_or_else(|| format!("`{external}`: the external port is 1..=65535"))?;
    if to != "to" {
        return Err(syntax());
    }
    let internal: std::net::SocketAddrV4 = internal
        .parse()
        .map_err(|_| format!("`{internal}`: the inside endpoint is like 192.168.1.10:80"))?;
    let (a, p) = (*internal.ip(), internal.port());
    if p == 0 || !crate::config::usable_v4(a) {
        return Err(format!(
            "`{internal}`: the inside endpoint needs a unicast address and a port"
        ));
    }
    let port = match rest {
        [] => *nat_ports
            .first()
            .ok_or("no port translates: set port<N>.nat first")?,
        ["port", n] => {
            let n: u32 = n.parse().map_err(|_| syntax())?;
            if !nat_ports.contains(&n) {
                return Err(format!("port {n} does not translate (port{n}.nat)"));
            }
            n
        }
        _ => return Err(syntax()),
    };
    Ok(Forward {
        proto,
        external,
        internal: (a, p),
        port,
    })
}

/// The translation settings (`nat.*`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatConfig {
    pub mapping: Dependence,
    pub filtering: Dependence,
    pub hairpin: bool,
    pub allocation: Allocation,
    /// Inclusive, `low <= high`, `low >= 1`.
    pub port_range: (u16, u16),
    pub forwards: Vec<Forward>,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            mapping: Dependence::Endpoint,
            filtering: Dependence::AddressAndPort,
            hairpin: true,
            allocation: Allocation::Preserve,
            port_range: (1024, 65535),
            forwards: Vec::new(),
        }
    }
}

/// Why a packet was not translated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No mapping for it (inbound), or a TCP segment other than a SYN would need a new one.
    NoMapping,
    /// A mapping exists, but filtering refuses this remote.
    Filtered,
    /// The session table is full.
    TableFull,
    /// No external port is free.
    PortsExhausted,
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoMapping => "nat-no-mapping",
            Self::Filtered => "nat-filtered",
            Self::TableFull => "nat-table-full",
            Self::PortsExhausted => "nat-ports-exhausted",
        }
    }
}

/// One mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub proto: Proto,
    /// The outside router port.
    pub port: u32,
    pub external: Endpoint,
    pub internal: Endpoint,
    /// What the mapping depends on besides the inside endpoint (ADM: an address; APDM: an
    /// address and a port).
    pub remote: Option<(Ipv4Addr, Option<u16>)>,
    /// A port forward: never expires, accepts any remote.
    pub forward: bool,
    pub sessions: BTreeMap<Endpoint, Track>,
    pub created: u64,
}

/// The table's counters (`nat-*` in the router's counters).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NatCounters {
    pub mappings_created: u64,
    pub mappings_expired: u64,
    pub translated_out: u64,
    pub translated_in: u64,
    pub icmp_errors_translated: u64,
    pub hairpinned: u64,
    pub hairpin_refused: u64,
    pub filtered: u64,
    pub no_mapping: u64,
    pub table_full: u64,
    pub ports_exhausted: u64,
    pub fragments: u64,
    pub unsupported: u64,
    pub malformed: u64,
}

type IntKey = (Proto, u32, Endpoint, Option<Ipv4Addr>, Option<u16>);

/// The translation table.
pub struct Nat {
    cfg: NatConfig,
    /// Outside router ports and their addresses.
    addrs: BTreeMap<u32, Ipv4Addr>,
    timeouts: Timeouts,
    max_sessions: usize,
    trace_filtered: Trace,
    maps: BTreeMap<u64, Mapping>,
    by_ext: BTreeMap<(Proto, u32, u16), u64>,
    by_int: BTreeMap<IntKey, u64>,
    by_forward: BTreeMap<(Proto, u32, Endpoint), u64>,
    cursor: BTreeMap<(Proto, u32), u16>,
    next: u64,
    sessions: usize,
    /// No session expires before this (a lower bound; refreshes only push deadlines later).
    earliest: Option<u64>,
    traced: BTreeSet<(Proto, Endpoint, Endpoint)>,
    pub trace_suppressed: u64,
    pub counters: NatCounters,
}

impl Nat {
    /// A table for the outside ports `addrs`, with the configured forwards installed (the
    /// config parser made sure they do not collide).
    pub fn new(
        cfg: NatConfig,
        addrs: BTreeMap<u32, Ipv4Addr>,
        timeouts: Timeouts,
        max_sessions: usize,
        trace_filtered: Trace,
    ) -> Self {
        let forwards = cfg.forwards.clone();
        let mut nat = Self {
            cfg,
            addrs,
            timeouts,
            max_sessions,
            trace_filtered,
            maps: BTreeMap::new(),
            by_ext: BTreeMap::new(),
            by_int: BTreeMap::new(),
            by_forward: BTreeMap::new(),
            cursor: BTreeMap::new(),
            next: 0,
            sessions: 0,
            earliest: None,
            traced: BTreeSet::new(),
            trace_suppressed: 0,
            counters: NatCounters::default(),
        };
        nat.cfg.forwards.clear();
        for f in forwards {
            // Checked by the config parser; a collision here would only skip the forward.
            let _ = nat.install_forward(f, 0);
        }
        nat
    }

    pub fn config(&self) -> &NatConfig {
        &self.cfg
    }

    /// The outside router ports, lowest first.
    pub fn ports(&self) -> Vec<u32> {
        self.addrs.keys().copied().collect()
    }

    pub fn is_outside(&self, port: u32) -> bool {
        self.addrs.contains_key(&port)
    }

    /// The address of outside port `port`.
    pub fn addr(&self, port: u32) -> Option<Ipv4Addr> {
        self.addrs.get(&port).copied()
    }

    /// The outside port whose address is `a`.
    pub fn port_with_addr(&self, a: Ipv4Addr) -> Option<u32> {
        self.addrs.iter().find(|(_, x)| **x == a).map(|(p, _)| *p)
    }

    pub fn mappings(&self) -> impl Iterator<Item = &Mapping> {
        self.maps.values()
    }

    pub fn mapping_count(&self) -> usize {
        self.maps.len()
    }

    pub fn session_count(&self) -> usize {
        self.sessions
    }

    pub fn forwards(&self) -> &[Forward] {
        &self.cfg.forwards
    }

    fn int_key(&self, proto: Proto, port: u32, internal: Endpoint, remote: Endpoint) -> IntKey {
        let (ra, rp) = remote;
        match self.cfg.mapping {
            Dependence::Endpoint => (proto, port, internal, None, None),
            Dependence::Address => (proto, port, internal, Some(ra), None),
            Dependence::AddressAndPort => (proto, port, internal, Some(ra), Some(rp)),
        }
    }

    /// The mapping an outbound packet from `internal` to `remote` uses, if there is one: the
    /// inside endpoint's forward first, then the mapping its behaviour selects.
    fn outbound_id(
        &self,
        proto: Proto,
        port: u32,
        internal: Endpoint,
        remote: Endpoint,
    ) -> Option<u64> {
        self.by_forward
            .get(&(proto, port, internal))
            .or_else(|| {
                self.by_int
                    .get(&self.int_key(proto, port, internal, remote))
            })
            .copied()
    }

    fn note_deadline(&mut self, d: u64) {
        self.earliest = Some(self.earliest.map_or(d, |e| e.min(d)));
    }

    /// Refreshes (or adds) the session with `remote` of mapping `id`; `side` 0 is the inside.
    fn touch(
        &mut self,
        id: u64,
        remote: Endpoint,
        now: u64,
        side: usize,
        flags: Option<u8>,
    ) -> Result<(), Refusal> {
        let full = self.sessions >= self.max_sessions;
        let m = self.maps.get_mut(&id).ok_or(Refusal::NoMapping)?;
        let new = !m.sessions.contains_key(&remote);
        if new && full {
            return Err(Refusal::TableFull);
        }
        let t = m.sessions.entry(remote).or_insert_with(|| Track::new(now));
        t.seen(now, side, flags);
        let d = t.deadline(m.proto.number(), &self.timeouts);
        if new {
            self.sessions += 1;
        }
        self.note_deadline(d);
        Ok(())
    }

    fn free(&self, proto: Proto, port: u32, ext: u16) -> bool {
        ext != 0 && !self.by_ext.contains_key(&(proto, port, ext))
    }

    /// An external port for `internal`'s new mapping, or `None` when none is free.
    fn allocate(&mut self, proto: Proto, port: u32, want: u16) -> Option<u16> {
        if self.cfg.allocation == Allocation::Preserve && self.free(proto, port, want) {
            return Some(want);
        }
        let (lo, hi) = self.cfg.port_range;
        let span = u32::from(hi - lo) + 1;
        let start = self
            .cursor
            .get(&(proto, port))
            .copied()
            .filter(|c| (lo..=hi).contains(c))
            .unwrap_or(lo);
        for i in 0..span {
            let p = (u32::from(lo) + (u32::from(start - lo) + i) % span) as u16;
            if self.free(proto, port, p) {
                let next = if p == hi { lo } else { p + 1 };
                self.cursor.insert((proto, port), next);
                return Some(p);
            }
        }
        None
    }

    /// An outbound packet from `internal` to `remote` leaves through outside port `port` at
    /// `now`: its external port, creating a mapping if it needs one. `flags` are TCP's.
    /// A new TCP mapping needs a SYN (without ACK).
    #[allow(clippy::too_many_arguments)]
    pub fn outbound(
        &mut self,
        now: u64,
        port: u32,
        proto: Proto,
        internal: Endpoint,
        remote: Endpoint,
        flags: Option<u8>,
        out: &mut impl Sink,
    ) -> Result<u16, Refusal> {
        let r = self.outbound_inner(now, port, proto, internal, remote, flags, out);
        match r {
            Ok(_) => self.counters.translated_out += 1,
            Err(Refusal::TableFull) => self.counters.table_full += 1,
            Err(Refusal::PortsExhausted) => self.counters.ports_exhausted += 1,
            Err(Refusal::NoMapping) => self.counters.no_mapping += 1,
            Err(Refusal::Filtered) => self.counters.filtered += 1,
        }
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn outbound_inner(
        &mut self,
        now: u64,
        port: u32,
        proto: Proto,
        internal: Endpoint,
        remote: Endpoint,
        flags: Option<u8>,
        out: &mut impl Sink,
    ) -> Result<u16, Refusal> {
        let addr = self.addr(port).ok_or(Refusal::NoMapping)?;
        let id = match self.outbound_id(proto, port, internal, remote) {
            Some(id) => id,
            None => {
                if proto == Proto::Tcp && flags.is_some_and(|f| f & (TCP_SYN | TCP_ACK) != TCP_SYN)
                {
                    return Err(Refusal::NoMapping);
                }
                if self.sessions >= self.max_sessions {
                    return Err(Refusal::TableFull);
                }
                let ext = self
                    .allocate(proto, port, internal.1)
                    .ok_or(Refusal::PortsExhausted)?;
                let key = self.int_key(proto, port, internal, remote);
                let id = self.next;
                self.next += 1;
                let m = Mapping {
                    proto,
                    port,
                    external: (addr, ext),
                    internal,
                    remote: key.3.map(|a| (a, key.4)),
                    forward: false,
                    sessions: BTreeMap::new(),
                    created: now,
                };
                out.event(Event::new(
                    "nat-mapping-created",
                    vec![
                        kv("proto", proto),
                        kv("internal", ep(internal)),
                        kv("external", ep(m.external)),
                        kv("remote", remote_name(m.remote)),
                        kv("port", port),
                    ],
                ));
                self.counters.mappings_created += 1;
                self.maps.insert(id, m);
                self.by_ext.insert((proto, port, ext), id);
                self.by_int.insert(key, id);
                id
            }
        };
        self.touch(id, remote, now, 0, flags)?;
        Ok(self.maps[&id].external.1)
    }

    /// An inbound packet from `remote` to external port `ext` of outside port `port` at `now`:
    /// the inside endpoint it is for, if a mapping exists and its filtering lets `remote` in.
    #[allow(clippy::too_many_arguments)]
    pub fn inbound(
        &mut self,
        now: u64,
        port: u32,
        proto: Proto,
        ext: u16,
        remote: Endpoint,
        flags: Option<u8>,
        out: &mut impl Sink,
    ) -> Result<Endpoint, Refusal> {
        let Some(&id) = self.by_ext.get(&(proto, port, ext)) else {
            self.counters.no_mapping += 1;
            return Err(Refusal::NoMapping);
        };
        let m = &self.maps[&id];
        let allowed = m.forward
            || match self.cfg.filtering {
                Dependence::Endpoint => true,
                Dependence::Address => m.sessions.keys().any(|(a, _)| *a == remote.0),
                Dependence::AddressAndPort => m.sessions.contains_key(&remote),
            };
        if !allowed {
            self.counters.filtered += 1;
            let (external, internal) = (m.external, m.internal);
            self.trace_filtered(proto, remote, external, internal, out);
            return Err(Refusal::Filtered);
        }
        let internal = m.internal;
        self.touch(id, remote, now, 1, flags).inspect_err(|r| {
            if *r == Refusal::TableFull {
                self.counters.table_full += 1;
            }
        })?;
        self.counters.translated_in += 1;
        Ok(internal)
    }

    fn trace_filtered(
        &mut self,
        proto: Proto,
        remote: Endpoint,
        external: Endpoint,
        internal: Endpoint,
        out: &mut impl Sink,
    ) {
        let report = match self.trace_filtered {
            Trace::None => false,
            Trace::All => true,
            Trace::First => {
                let key = (proto, remote, external);
                if self.traced.contains(&key) {
                    false
                } else if self.traced.len() >= TRACE_CAP {
                    self.trace_suppressed += 1;
                    false
                } else {
                    self.traced.insert(key)
                }
            }
        };
        if report {
            out.event(Event::new(
                "nat-filtered",
                vec![
                    kv("proto", proto),
                    kv("from", ep(remote)),
                    kv("to", ep(external)),
                    kv("internal", ep(internal)),
                    kv("filtering", self.cfg.filtering.name()),
                ],
            ));
        }
    }

    /// The mapping behind external port `ext` of `port`, without touching it.
    pub fn peek(&self, proto: Proto, port: u32, ext: u16) -> Option<&Mapping> {
        self.by_ext
            .get(&(proto, port, ext))
            .map(|id| &self.maps[id])
    }

    /// For an ICMP error that came in about a packet sent from external port `ext` to `remote`:
    /// the inside endpoint that sent it, if the mapping exists and talked to `remote`.
    pub fn error_in(
        &self,
        port: u32,
        proto: Proto,
        ext: u16,
        remote: Endpoint,
    ) -> Option<Endpoint> {
        let m = self.peek(proto, port, ext)?;
        m.sessions.contains_key(&remote).then_some(m.internal)
    }

    /// For an ICMP error going out about a packet `remote` sent to `internal`: the external
    /// port `remote` sent it to, if the mapping exists and talked to `remote`.
    pub fn error_out(
        &self,
        port: u32,
        proto: Proto,
        internal: Endpoint,
        remote: Endpoint,
    ) -> Option<u16> {
        let m = &self.maps[&self.outbound_id(proto, port, internal, remote)?];
        m.sessions.contains_key(&remote).then_some(m.external.1)
    }

    /// The inside endpoint of external port `ext` (to undo a translation the router made).
    pub fn internal_of(&self, port: u32, proto: Proto, ext: u16) -> Option<Endpoint> {
        self.peek(proto, port, ext).map(|m| m.internal)
    }

    /// Ends every session idle past its timeout at `now`, and every mapping left without one
    /// (`nat-mapping-expired`).
    pub fn expire(&mut self, now: u64, out: &mut impl Sink) {
        if self.earliest.is_none_or(|e| e > now) {
            return;
        }
        let mut earliest: Option<u64> = None;
        let mut gone = Vec::new();
        for (&id, m) in self.maps.iter_mut() {
            let proto = m.proto.number();
            let before = m.sessions.len();
            m.sessions
                .retain(|_, t| t.deadline(proto, &self.timeouts) > now);
            self.sessions -= before - m.sessions.len();
            for t in m.sessions.values() {
                let d = t.deadline(proto, &self.timeouts);
                earliest = Some(earliest.map_or(d, |e| e.min(d)));
            }
            if m.sessions.is_empty() && !m.forward {
                gone.push(id);
            }
        }
        self.earliest = earliest;
        for id in gone {
            if let Some(m) = self.maps.remove(&id) {
                self.unindex(id, &m);
                self.counters.mappings_expired += 1;
                out.event(Event::new(
                    "nat-mapping-expired",
                    vec![
                        kv("proto", m.proto),
                        kv("internal", ep(m.internal)),
                        kv("external", ep(m.external)),
                        kv("remote", remote_name(m.remote)),
                        kv("lifetime-ns", now - m.created),
                    ],
                ));
            }
        }
    }

    fn unindex(&mut self, id: u64, m: &Mapping) {
        self.by_ext.remove(&(m.proto, m.port, m.external.1));
        self.by_int.retain(|_, v| *v != id);
        self.by_forward.retain(|_, v| *v != id);
    }

    /// The earliest moment a session may expire.
    pub fn next_deadline(&self) -> Option<u64> {
        self.earliest
    }

    fn install_forward(&mut self, f: Forward, now: u64) -> Result<(), String> {
        let addr = self
            .addr(f.port)
            .ok_or_else(|| format!("port {} does not translate", f.port))?;
        if let Some(m) = self.peek(f.proto, f.port, f.external) {
            return Err(if m.forward {
                format!(
                    "{} {} on port {} is forwarded already",
                    f.proto, f.external, f.port
                )
            } else {
                format!(
                    "{} {} on port {} is held by the mapping of {} (until it expires)",
                    f.proto,
                    f.external,
                    f.port,
                    ep(m.internal)
                )
            });
        }
        if self.by_forward.contains_key(&(f.proto, f.port, f.internal)) {
            return Err(format!(
                "{} {} has a forward on port {} already",
                f.proto,
                ep(f.internal),
                f.port
            ));
        }
        if self.cfg.forwards.len() >= MAX_FORWARDS {
            return Err(format!("at most {MAX_FORWARDS} forwards"));
        }
        let id = self.next;
        self.next += 1;
        self.maps.insert(
            id,
            Mapping {
                proto: f.proto,
                port: f.port,
                external: (addr, f.external),
                internal: f.internal,
                remote: None,
                forward: true,
                sessions: BTreeMap::new(),
                created: now,
            },
        );
        self.by_ext.insert((f.proto, f.port, f.external), id);
        self.by_forward.insert((f.proto, f.port, f.internal), id);
        self.cfg.forwards.push(f);
        Ok(())
    }

    /// Adds a forward: `Ok("added")`, `Ok("unchanged")` when it is there, an error when its
    /// external port (or its inside endpoint, on that port) is taken.
    pub fn add_forward(&mut self, f: Forward, now: u64) -> Result<&'static str, String> {
        if self.cfg.forwards.contains(&f) {
            return Ok("unchanged");
        }
        self.install_forward(f, now).map(|()| "added")
    }

    /// Removes the forward on `(proto, port, external)` (only if it is `exact`, when given),
    /// with its sessions: `Ok("removed")` or `Ok("absent")`.
    pub fn remove_forward(
        &mut self,
        proto: Proto,
        port: u32,
        external: u16,
        exact: Option<Forward>,
    ) -> Result<&'static str, String> {
        let Some(at) = self
            .cfg
            .forwards
            .iter()
            .position(|f| (f.proto, f.port, f.external) == (proto, port, external))
        else {
            return Ok("absent");
        };
        let f = self.cfg.forwards[at];
        if exact.is_some_and(|e| e != f) {
            return Err(format!("the forward of {proto} {external} is `{f}`"));
        }
        self.cfg.forwards.remove(at);
        if let Some(&id) = self.by_ext.get(&(proto, port, external))
            && let Some(m) = self.maps.remove(&id)
        {
            self.sessions -= m.sessions.len();
            self.unindex(id, &m);
        }
        Ok("removed")
    }

    /// Every mapping, one per line: `<proto> <internal> -> <external> [remote ...] (forward)`
    /// then its sessions.
    pub fn listing(&self) -> String {
        let mut lines = Vec::new();
        for m in self.maps.values() {
            let kind = if m.forward {
                "forward".to_owned()
            } else {
                format!("remote {}", remote_name(m.remote))
            };
            lines.push(format!(
                "{} {} -> {} port {} {kind}",
                m.proto,
                ep(m.internal),
                ep(m.external),
                m.port
            ));
            for (r, t) in &m.sessions {
                let state = if m.proto == Proto::Tcp {
                    format!(" {}", t.tcp_state())
                } else {
                    String::new()
                };
                lines.push(format!("  session {}{state}", ep(*r)));
            }
        }
        lines.join("\n")
    }
}

/// `any`, an address, or an endpoint: what a mapping depends on.
fn remote_name(r: Option<(Ipv4Addr, Option<u16>)>) -> String {
    match r {
        None => "any".to_owned(),
        Some((a, None)) => a.to_string(),
        Some((a, Some(p))) => format!("{a}:{p}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const S: u64 = 1_000_000_000;
    const WAN: u32 = 1;

    #[derive(Default)]
    struct Out(Vec<Event>);

    impl Sink for Out {
        fn transmit(&mut self, _port: u32, _frame: Vec<u8>) {}
        fn event(&mut self, event: Event) {
            self.0.push(event);
        }
    }

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn nat(mapping: Dependence, filtering: Dependence, allocation: Allocation) -> Nat {
        let cfg = NatConfig {
            mapping,
            filtering,
            allocation,
            port_range: (1024, 1031),
            ..NatConfig::default()
        };
        Nat::new(
            cfg,
            BTreeMap::from([(WAN, v4("203.0.113.1"))]),
            Timeouts::default(),
            64,
            Trace::All,
        )
    }

    #[test]
    fn port_preservation_and_sequential_allocation() {
        let mut out = Out::default();
        let mut n = nat(
            Dependence::Endpoint,
            Dependence::AddressAndPort,
            Allocation::Preserve,
        );
        let (a, b, r) = (v4("192.168.1.10"), v4("192.168.1.11"), v4("198.51.100.1"));
        let e1 = n
            .outbound(0, WAN, Proto::Udp, (a, 4000), (r, 53), None, &mut out)
            .unwrap();
        assert_eq!(e1, 4000, "preserved");
        // Another inside host with the same port: the next free port of the range.
        let e2 = n
            .outbound(0, WAN, Proto::Udp, (b, 4000), (r, 53), None, &mut out)
            .unwrap();
        assert_eq!(e2, 1024);
        // The same host to another remote: endpoint-independent, the same mapping.
        let e3 = n
            .outbound(0, WAN, Proto::Udp, (a, 4000), (r, 99), None, &mut out)
            .unwrap();
        assert_eq!(e3, 4000);
        assert_eq!(n.mapping_count(), 2);
        assert_eq!(n.session_count(), 3);
        let mut s = nat(
            Dependence::AddressAndPort,
            Dependence::AddressAndPort,
            Allocation::Sequential,
        );
        let ports: Vec<u16> = (0..3)
            .map(|q| {
                s.outbound(0, WAN, Proto::Udp, (a, 4000), (r, q), None, &mut out)
                    .unwrap()
            })
            .collect();
        assert_eq!(ports, [1024, 1025, 1026], "one mapping per remote endpoint");
    }

    #[test]
    fn filtering_kinds() {
        let mut out = Out::default();
        let (a, r, r2) = (v4("192.168.1.10"), v4("198.51.100.1"), v4("198.51.100.2"));
        for (f, same_addr, other_addr) in [
            (Dependence::Endpoint, true, true),
            (Dependence::Address, true, false),
            (Dependence::AddressAndPort, false, false),
        ] {
            let mut n = nat(Dependence::Endpoint, f, Allocation::Preserve);
            let e = n
                .outbound(0, WAN, Proto::Udp, (a, 5000), (r, 53), None, &mut out)
                .unwrap();
            assert_eq!(
                n.inbound(S, WAN, Proto::Udp, e, (r, 53), None, &mut out),
                Ok((a, 5000))
            );
            assert_eq!(
                n.inbound(S, WAN, Proto::Udp, e, (r, 54), None, &mut out)
                    .is_ok(),
                same_addr,
                "{f:?}: another port of the same remote"
            );
            assert_eq!(
                n.inbound(S, WAN, Proto::Udp, e, (r2, 53), None, &mut out)
                    .is_ok(),
                other_addr,
                "{f:?}: another remote"
            );
            assert_eq!(
                n.inbound(S, WAN, Proto::Udp, 9, (r, 53), None, &mut out),
                Err(Refusal::NoMapping)
            );
        }
    }

    #[test]
    fn tcp_needs_a_syn_and_expires_by_state() {
        let mut out = Out::default();
        let mut n = nat(
            Dependence::Endpoint,
            Dependence::AddressAndPort,
            Allocation::Preserve,
        );
        let (a, r) = (v4("192.168.1.10"), v4("198.51.100.1"));
        assert_eq!(
            n.outbound(
                0,
                WAN,
                Proto::Tcp,
                (a, 40000),
                (r, 80),
                Some(TCP_ACK),
                &mut out
            ),
            Err(Refusal::NoMapping)
        );
        let e = n
            .outbound(
                0,
                WAN,
                Proto::Tcp,
                (a, 40000),
                (r, 80),
                Some(TCP_SYN),
                &mut out,
            )
            .unwrap();
        n.inbound(
            S,
            WAN,
            Proto::Tcp,
            e,
            (r, 80),
            Some(TCP_SYN | TCP_ACK),
            &mut out,
        )
        .unwrap();
        // Established: 7440 s from the last packet.
        n.expire(S + 7439 * S, &mut out);
        assert_eq!(n.mapping_count(), 1);
        n.expire(S + 7440 * S, &mut out);
        assert_eq!(n.mapping_count(), 0);
        assert_eq!(out.0.last().unwrap().kind, "nat-mapping-expired");
    }

    #[test]
    fn forwards_accept_anyone_and_carry_the_replies() {
        let mut out = Out::default();
        let mut n = nat(
            Dependence::AddressAndPort,
            Dependence::AddressAndPort,
            Allocation::Preserve,
        );
        let f = parse_forward("tcp 8080 to 192.168.1.10:80", &[WAN]).unwrap();
        assert_eq!(n.add_forward(f, 0), Ok("added"));
        assert_eq!(n.add_forward(f, 0), Ok("unchanged"));
        let r = v4("198.51.100.7");
        assert_eq!(
            n.inbound(0, WAN, Proto::Tcp, 8080, (r, 5555), Some(TCP_SYN), &mut out),
            Ok((v4("192.168.1.10"), 80))
        );
        assert_eq!(
            n.outbound(
                0,
                WAN,
                Proto::Tcp,
                (v4("192.168.1.10"), 80),
                (r, 5555),
                Some(TCP_SYN | TCP_ACK),
                &mut out
            ),
            Ok(8080)
        );
        // Allocation never hands out a forwarded port.
        let e = n
            .outbound(
                0,
                WAN,
                Proto::Tcp,
                (v4("192.168.1.11"), 8080),
                (r, 1),
                Some(TCP_SYN),
                &mut out,
            )
            .unwrap();
        assert_ne!(e, 8080);
        n.expire(10_000 * S, &mut out);
        assert_eq!(n.forwards().len(), 1, "forwards never expire");
        assert_eq!(n.mapping_count(), 1);
        assert_eq!(n.remove_forward(Proto::Tcp, WAN, 8080, None), Ok("removed"));
        assert_eq!(n.remove_forward(Proto::Tcp, WAN, 8080, None), Ok("absent"));
        assert_eq!(n.session_count(), 0);
        for bad in [
            "icmp 1 to 192.168.1.10:1",
            "tcp 0 to 192.168.1.10:80",
            "tcp 80 192.168.1.10:80",
            "tcp 80 to 192.168.1.10",
            "tcp 80 to 0.0.0.0:80",
            "tcp 80 to 192.168.1.10:80 port 0",
        ] {
            assert!(parse_forward(bad, &[WAN]).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_full_table_refuses_new_sessions() {
        let mut out = Out::default();
        let mut n = Nat::new(
            NatConfig::default(),
            BTreeMap::from([(WAN, v4("203.0.113.1"))]),
            Timeouts::default(),
            2,
            Trace::All,
        );
        let (a, r) = (v4("192.168.1.10"), v4("198.51.100.1"));
        for p in 0..2 {
            n.outbound(0, WAN, Proto::Udp, (a, 100 + p), (r, 1), None, &mut out)
                .unwrap();
        }
        assert_eq!(
            n.outbound(0, WAN, Proto::Udp, (a, 200), (r, 1), None, &mut out),
            Err(Refusal::TableFull)
        );
        assert_eq!(
            n.outbound(0, WAN, Proto::Udp, (a, 100), (r, 2), None, &mut out),
            Err(Refusal::TableFull),
            "a new session of an existing mapping too"
        );
    }

    // -----------------------------------------------------------------------------------------
    // The table against a reference model.

    /// A model mapping: its key, external port and sessions (remote, last activity).
    type ModelMapping = (IntKey, u16, Vec<(Endpoint, u64)>);

    /// A reference model: a flat list of mappings, each with its key, external port and
    /// sessions with their last-activity times. Linear scans, no indexes, no allocation policy.
    struct Model {
        mapping: Dependence,
        filtering: Dependence,
        timeout: u64,
        maps: Vec<ModelMapping>,
    }

    impl Model {
        fn key(&self, internal: Endpoint, remote: Endpoint) -> IntKey {
            match self.mapping {
                Dependence::Endpoint => (Proto::Udp, WAN, internal, None, None),
                Dependence::Address => (Proto::Udp, WAN, internal, Some(remote.0), None),
                Dependence::AddressAndPort => {
                    (Proto::Udp, WAN, internal, Some(remote.0), Some(remote.1))
                }
            }
        }

        fn expire(&mut self, now: u64) {
            let t = self.timeout;
            for m in &mut self.maps {
                m.2.retain(|(_, last)| last + t > now);
            }
            self.maps.retain(|m| !m.2.is_empty());
        }

        /// The external port an existing mapping gives, or `None` when it needs a new one.
        fn outbound(&mut self, now: u64, internal: Endpoint, remote: Endpoint) -> Option<u16> {
            self.expire(now);
            let key = self.key(internal, remote);
            let m = self.maps.iter_mut().find(|m| m.0 == key)?;
            touch(&mut m.2, remote, now);
            Some(m.1)
        }

        fn inbound(&mut self, now: u64, ext: u16, remote: Endpoint) -> Option<Endpoint> {
            self.expire(now);
            let filtering = self.filtering;
            let m = self.maps.iter_mut().find(|m| m.1 == ext)?;
            let ok = match filtering {
                Dependence::Endpoint => true,
                Dependence::Address => m.2.iter().any(|(r, _)| r.0 == remote.0),
                Dependence::AddressAndPort => m.2.iter().any(|(r, _)| *r == remote),
            };
            if !ok {
                return None;
            }
            touch(&mut m.2, remote, now);
            Some(m.0.2)
        }
    }

    fn touch(sessions: &mut Vec<(Endpoint, u64)>, remote: Endpoint, now: u64) {
        match sessions.iter_mut().find(|(r, _)| *r == remote) {
            Some(s) => s.1 = now,
            None => sessions.push((remote, now)),
        }
    }

    #[derive(Clone, Debug)]
    enum Step {
        /// Inside host, its port, remote host, remote port, time advance (ms).
        Out(u8, u16, u8, u16, u64),
        /// Remote host, remote port, which external port (an index into those seen), advance.
        In(u8, u16, usize, u64),
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            (0u8..3, 1u16..4, 0u8..3, 1u16..3, 0u64..200_000)
                .prop_map(|(h, p, r, q, t)| Step::Out(h, p, r, q, t)),
            (0u8..3, 1u16..3, 0usize..8, 0u64..200_000)
                .prop_map(|(r, q, e, t)| Step::In(r, q, e, t)),
        ]
    }

    fn dependence() -> impl Strategy<Value = Dependence> {
        prop_oneof![
            Just(Dependence::Endpoint),
            Just(Dependence::Address),
            Just(Dependence::AddressAndPort),
        ]
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 256,
            rng_seed: proptest::test_runner::RngSeed::Fixed(4787),
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]

        /// Random outbound and inbound UDP packets with time passing: the table agrees with the
        /// model on which mapping each outbound packet uses, on every inbound accept or refusal
        /// and its inside endpoint (out and back is the identity), and on expiry; no two live
        /// mappings share an external port, and one mapping keeps its port while it lives.
        #[test]
        fn the_table_matches_a_reference_model(
            mapping in dependence(),
            filtering in dependence(),
            preserve in any::<bool>(),
            steps in proptest::collection::vec(step(), 1..120),
        ) {
            let allocation = if preserve { Allocation::Preserve } else { Allocation::Sequential };
            let mut n = Nat::new(
                NatConfig { mapping, filtering, allocation, port_range: (1024, 1100), ..NatConfig::default() },
                BTreeMap::from([(WAN, v4("203.0.113.1"))]),
                Timeouts { udp: 300 * S, ..Timeouts::default() },
                4096,
                Trace::None,
            );
            let mut model = Model { mapping, filtering, timeout: 300 * S, maps: Vec::new() };
            let mut out = Out::default();
            let mut now = 0u64;
            let mut seen: Vec<u16> = Vec::new();
            let host = |h: u8| Ipv4Addr::new(192, 168, 1, 10 + h);
            let remote = |r: u8| Ipv4Addr::new(198, 51, 100, 1 + r);
            for s in steps {
                match s {
                    Step::Out(h, p, r, q, dt) => {
                        now += dt * 1_000_000 * 10;
                        n.expire(now, &mut out);
                        let (i, rem) = ((host(h), p), (remote(r), q));
                        let want = model.outbound(now, i, rem);
                        let got = n.outbound(now, WAN, Proto::Udp, i, rem, None, &mut out).unwrap();
                        match want {
                            Some(e) => prop_assert_eq!(got, e, "an existing mapping keeps its port"),
                            None => {
                                prop_assert!(model.maps.iter().all(|m| m.1 != got), "a fresh port");
                                if preserve && model.maps.iter().all(|m| m.1 != p) {
                                    prop_assert_eq!(got, p, "preserved when free");
                                }
                                let key = model.key(i, rem);
                                model.maps.push((key, got, vec![(rem, now)]));
                            }
                        }
                        seen.push(got);
                    }
                    Step::In(r, q, e, dt) => {
                        now += dt * 1_000_000 * 10;
                        n.expire(now, &mut out);
                        let Some(&ext) = seen.get(e % seen.len().max(1)) else { continue };
                        let rem = (remote(r), q);
                        let want = model.inbound(now, ext, rem);
                        let got = n.inbound(now, WAN, Proto::Udp, ext, rem, None, &mut out).ok();
                        prop_assert_eq!(got, want);
                    }
                }
                prop_assert_eq!(n.mapping_count(), model.maps.len());
                let mut exts: Vec<u16> = n.mappings().map(|m| m.external.1).collect();
                exts.sort();
                exts.dedup();
                prop_assert_eq!(exts.len(), n.mapping_count(), "no shared external port");
                let sessions: usize = model.maps.iter().map(|m| m.2.len()).sum();
                prop_assert_eq!(n.session_count(), sessions);
            }
        }
    }
}
