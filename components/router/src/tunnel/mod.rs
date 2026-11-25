//! Tunnel ports: a router port without a cable whose packets cross the network inside UDP.
//!
//! Each tunnel is a point-to-point port with a transit address of its own and one peer
//! endpoint. A packet the router routes to it leaves as a [`geneve`] datagram, originated by the
//! router from its own IPv4 address on the egress port toward the peer's endpoint; a datagram
//! that arrives on the tunnel's UDP port with the tunnel's id is decapsulated and enters the
//! router as if it had arrived on the tunnel port. The design note is
//! `docs/design/tunnels.md`.
//!
//! This module is the tunnel itself, without a router: its settings ([`Spec`], from config or
//! a command), the [`stun`] checks that find and keep a peer, the state machine ([`Tunnel`]) and
//! [`mss`] clamping. It never sends anything itself: every method appends [`Action`]s the
//! router carries out.
//!
//! **Finding the peer.** A tunnel knows candidate endpoints (from its settings, from
//! `tunnel-peer` commands, and from checks it receives: peer-reflexive, as ICE learns them).
//! While it is not up it sends a check (a STUN Binding request whose `USERNAME` is the tunnel
//! id) to every candidate each `probe`, for at most `rounds` rounds. The first success response
//! (or data packet) with the tunnel's id brings it up, with the endpoint it came from as its
//! peer. Once up it sends a check to the peer every `keepalive`, which holds NAT mappings open;
//! any packet with its id from another endpoint moves the peer there (roaming, as after a NAT
//! rebinding); nothing heard from the peer for `dead` takes it down, and probing starts again.
//! A tunnel that runs out of rounds is `failed` until a new candidate arrives.
//!
//! **Its own address.** A Binding request without `USERNAME` to any tunnel port (or to a
//! router's `stun-server` port) is answered with the endpoint it came from, as a STUN server
//! does. A tunnel sends one to each of its `reflector`s until one answers, so a controller can
//! read the tunnel's reflexive endpoint and hand it to the peer's controller.

pub mod geneve;
pub mod mss;
pub mod stun;

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};

use wasmnet_wire::parse_duration;

use crate::Event;

/// Most tunnels one router has.
pub const MAX_TUNNELS: usize = 256;
/// Most candidates (and reflectors) per tunnel; peer-reflexive candidates beyond it are not
/// learnt.
pub const MAX_CANDIDATES: usize = 8;
/// The outer IPv4 header, UDP and Geneve: what a tunnel adds to every inner packet.
pub const OVERHEAD: u16 = 20 + 8 + geneve::HEADER as u16;
/// The default tunnel MTU: a 1500-byte path minus [`OVERHEAD`].
pub const DEFAULT_MTU: u16 = 1500 - OVERHEAD;

/// Check: a request to a candidate or the peer. Query: a request to a reflector.
const TX_CHECK: u8 = 1;
const TX_QUERY: u8 = 2;

/// A tunnel's settings: `tunnel.<name>.<key>` in the config, `tunnel-add <name> <key> <value>...`
/// as a command. Equal settings make `tunnel-add` idempotent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    /// The VNI and the STUN `USERNAME`, 1..=2^24-1; unique per UDP port.
    pub id: u32,
    /// The transit address and its prefix length; the prefix is the port's connected route.
    pub local: (IpAddr, u8),
    /// The local UDP port.
    pub udp: u16,
    /// Candidate endpoints of the peer.
    pub peers: Vec<SocketAddrV4>,
    /// Endpoints to ask for this tunnel's reflexive endpoint.
    pub reflectors: Vec<SocketAddrV4>,
    /// The tunnel port's IP MTU.
    pub mtu: u16,
    pub probe_ns: u64,
    pub rounds: u32,
    pub keepalive_ns: u64,
    pub dead_ns: u64,
    pub mss_clamp: bool,
}

/// The keys a spec takes, in the order a listing shows them.
pub const KEYS: &[&str] = &[
    "id",
    "local",
    "udp",
    "peer",
    "reflector",
    "mtu",
    "probe",
    "rounds",
    "keepalive",
    "dead",
    "mss-clamp",
];

/// A tunnel name: `a-z`, `0-9` and `-`, 1 to 32 characters, starting with a letter (so it never
/// reads as a port number where events name a port).
pub fn valid_name(n: &str) -> bool {
    (1..=32).contains(&n.len())
        && n.starts_with(|c: char| c.is_ascii_lowercase())
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn endpoints(key: &str, v: &str) -> Result<Vec<SocketAddrV4>, String> {
    let mut out: Vec<SocketAddrV4> = Vec::new();
    for item in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let e: SocketAddrV4 = item.parse().map_err(|_| {
            format!("{key}: `{item}` is not an IPv4 endpoint like 203.0.113.2:6081")
        })?;
        let ip = *e.ip();
        if e.port() == 0
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_broadcast()
            || ip.is_loopback()
        {
            return Err(format!("{key}: `{item}` is not a unicast endpoint"));
        }
        if !out.contains(&e) {
            out.push(e);
        }
    }
    if out.len() > MAX_CANDIDATES {
        return Err(format!("{key}: at most {MAX_CANDIDATES} endpoints"));
    }
    Ok(out)
}

impl Spec {
    /// The settings from `(key, value)` pairs; `id` and `local` are required, unknown keys,
    /// repeated keys and bad values are errors.
    pub fn from_pairs<'a>(
        pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Spec, String> {
        let mut seen = BTreeMap::new();
        for (k, v) in pairs {
            if !KEYS.contains(&k) {
                return Err(format!(
                    "unknown tunnel key `{k}` (keys: {})",
                    KEYS.join(", ")
                ));
            }
            if seen.insert(k, v.trim()).is_some() {
                return Err(format!("tunnel key `{k}` given twice"));
            }
        }
        let dur = |k: &str, default: u64| -> Result<u64, String> {
            match seen.get(k) {
                None => Ok(default),
                Some(v) => parse_duration(v)
                    .filter(|&n| n > 0)
                    .ok_or_else(|| format!("{k}: `{v}` is not a duration above zero")),
            }
        };
        let id = match seen.get("id") {
            None => return Err("a tunnel needs `id`".to_owned()),
            Some(v) => v
                .parse::<u32>()
                .ok()
                .filter(|n| (1..=geneve::MAX_VNI).contains(n))
                .ok_or_else(|| format!("id: `{v}` is not 1..={}", geneve::MAX_VNI))?,
        };
        let local = match seen.get("local") {
            None => return Err("a tunnel needs `local`".to_owned()),
            Some(v) => parse_local(v)?,
        };
        let udp = match seen.get("udp") {
            None => geneve::PORT,
            Some(v) => v
                .parse::<u16>()
                .ok()
                .filter(|&p| p != 0)
                .ok_or_else(|| format!("udp: `{v}` is not a port 1..=65535"))?,
        };
        let mtu = match seen.get("mtu") {
            None => DEFAULT_MTU,
            Some(v) => v
                .parse::<u16>()
                .ok()
                .filter(|m| (1280..=9000).contains(m))
                .ok_or_else(|| format!("mtu: `{v}` is not 1280..=9000"))?,
        };
        let rounds = match seen.get("rounds") {
            None => 20,
            Some(v) => v
                .parse::<u32>()
                .ok()
                .filter(|n| (1..=1000).contains(n))
                .ok_or_else(|| format!("rounds: `{v}` is not 1..=1000"))?,
        };
        let mss_clamp = match seen.get("mss-clamp").copied() {
            None | Some("true") => true,
            Some("false") => false,
            Some(v) => return Err(format!("mss-clamp: `{v}` is not true or false")),
        };
        let spec = Spec {
            id,
            local,
            udp,
            peers: endpoints("peer", seen.get("peer").copied().unwrap_or(""))?,
            reflectors: endpoints("reflector", seen.get("reflector").copied().unwrap_or(""))?,
            mtu,
            probe_ns: dur("probe", 100_000_000)?,
            rounds,
            keepalive_ns: dur("keepalive", 25_000_000_000)?,
            dead_ns: dur("dead", 80_000_000_000)?,
            mss_clamp,
        };
        if spec.dead_ns <= spec.keepalive_ns {
            return Err("dead must be longer than keepalive".to_owned());
        }
        Ok(spec)
    }

    /// `tunnel-add`'s argument after the name: `<key> <value>` pairs.
    pub fn from_words(words: &[&str]) -> Result<Spec, String> {
        if !words.len().is_multiple_of(2) {
            return Err("tunnel settings are `<key> <value>` pairs".to_owned());
        }
        Spec::from_pairs(words.chunks(2).map(|kv| (kv[0], kv[1])))
    }
}

fn parse_local(v: &str) -> Result<(IpAddr, u8), String> {
    let bad = || {
        format!("local: `{v}` is not a unicast address with a prefix length, like fd00:ff::a/128")
    };
    let (a, l) = v.split_once('/').ok_or_else(bad)?;
    let a: IpAddr = a.parse().map_err(|_| bad())?;
    let l: u8 = l.parse().map_err(|_| bad())?;
    let ok = match a {
        IpAddr::V4(x) => {
            l <= 32
                && !(x.is_unspecified() || x.is_multicast() || x.is_broadcast() || x.is_loopback())
        }
        IpAddr::V6(x) => {
            l <= 128
                && !(x.is_unspecified()
                    || x.is_multicast()
                    || x.is_loopback()
                    || (x.segments()[0] & 0xffc0) == 0xfe80)
        }
    };
    if ok { Ok((a, l)) } else { Err(bad()) }
}

/// Where a tunnel is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Nothing to probe: no candidate (and no reflector left to ask). It comes up when a peer
    /// probes it.
    Idle,
    Probing,
    Up,
    /// Probed every candidate for `rounds` rounds without an answer.
    Failed,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Idle => "idle",
            State::Probing => "probing",
            State::Up => "up",
            State::Failed => "failed",
        }
    }
}

/// Per tunnel, listed as `tunnel-<name>-<counter>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Inner packets sent and received, and their bytes.
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    /// Checks and reflector queries sent; requests received with this tunnel's id; success
    /// responses received for this tunnel.
    pub checks_sent: u64,
    pub requests_received: u64,
    pub responses_received: u64,
    /// Inner packets dropped because the tunnel was not up.
    pub down_drops: u64,
    /// Datagrams (data or checks) whose outer packet could not leave: no route to the peer, a
    /// port down, too big for the egress port.
    pub outer_drops: u64,
    pub roamed: u64,
    pub mss_clamped: u64,
}

/// What the router does for a tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send `datagram` from the tunnel's UDP port to `to`.
    Send {
        to: SocketAddrV4,
        datagram: Vec<u8>,
    },
    /// The tunnel port's carrier: up when the tunnel is.
    Carrier(bool),
    Event(Event),
}

/// One tunnel's state.
#[derive(Clone, Debug)]
pub struct Tunnel {
    pub name: String,
    pub spec: Spec,
    state: State,
    candidates: Vec<SocketAddrV4>,
    peer: Option<SocketAddrV4>,
    reflexive: Option<SocketAddrV4>,
    /// A reflector answered: stop asking.
    reflected: bool,
    seq: u64,
    rounds: u32,
    next: u64,
    last_rx: u64,
    since: u64,
    pub c: Counters,
}

fn ev(kind: &'static str, fields: Vec<(&str, String)>) -> Action {
    Action::Event(Event::new(
        kind,
        fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
    ))
}

fn ep(e: Option<SocketAddrV4>) -> String {
    e.map_or_else(|| "-".to_owned(), |e| e.to_string())
}

/// A transaction id: what it is (check or query), the tunnel id and a sequence number.
fn txid(kind: u8, id: u32, seq: u64) -> stun::TransactionId {
    let mut t = [0u8; 12];
    t[0] = kind;
    t[1..4].copy_from_slice(&id.to_be_bytes()[1..]);
    t[4..].copy_from_slice(&seq.to_be_bytes());
    t
}

/// What a received response's transaction id says: `(kind, tunnel id, seq)`.
pub fn parse_txid(t: &stun::TransactionId) -> (u8, u32, u64) {
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&t[4..]);
    (
        t[0],
        u32::from_be_bytes([0, t[1], t[2], t[3]]),
        u64::from_be_bytes(seq),
    )
}

impl Tunnel {
    /// A new tunnel at `now`; its first round is due at once.
    pub fn new(name: &str, spec: Spec, now: u64) -> Tunnel {
        let mut t = Tunnel {
            name: name.to_owned(),
            candidates: spec.peers.clone(),
            spec,
            state: State::Idle,
            peer: None,
            reflexive: None,
            reflected: false,
            seq: 0,
            rounds: 0,
            next: now,
            last_rx: now,
            since: now,
            c: Counters::default(),
        };
        if t.has_targets() {
            t.state = State::Probing;
        }
        t
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn peer(&self) -> Option<SocketAddrV4> {
        self.peer.filter(|_| self.state == State::Up)
    }

    pub fn reflexive(&self) -> Option<SocketAddrV4> {
        self.reflexive
    }

    pub fn candidates(&self) -> &[SocketAddrV4] {
        &self.candidates
    }

    fn has_targets(&self) -> bool {
        !self.candidates.is_empty() || (!self.reflected && !self.spec.reflectors.is_empty())
    }

    /// The next instant `poll` has work.
    pub fn deadline(&self) -> Option<u64> {
        match self.state {
            State::Up => Some(
                self.next
                    .min(self.last_rx.saturating_add(self.spec.dead_ns)),
            ),
            State::Probing => Some(self.next),
            State::Idle | State::Failed => None,
        }
    }

    fn check(&mut self, to: SocketAddrV4, out: &mut Vec<Action>) {
        self.seq += 1;
        self.c.checks_sent += 1;
        let t = txid(TX_CHECK, self.spec.id, self.seq);
        let datagram = stun::request(&t, Some(&self.spec.id.to_string()));
        out.push(Action::Send { to, datagram });
    }

    /// Timers: a probing round, a keepalive, or the peer gone silent.
    pub fn poll(&mut self, now: u64, out: &mut Vec<Action>) {
        if self.state == State::Up && now >= self.last_rx.saturating_add(self.spec.dead_ns) {
            out.push(ev(
                "tunnel-down",
                vec![
                    ("tunnel", self.name.clone()),
                    ("peer", ep(self.peer)),
                    ("silent-ns", (now - self.last_rx).to_string()),
                ],
            ));
            out.push(Action::Carrier(false));
            self.state = State::Probing;
            self.rounds = 0;
            self.reflected = false;
            self.next = now;
            self.since = now;
        }
        if now < self.next {
            return;
        }
        match self.state {
            State::Up => {
                if let Some(p) = self.peer {
                    self.check(p, out);
                }
                self.next = now + self.spec.keepalive_ns;
            }
            State::Probing => {
                if !self.has_targets() {
                    self.state = State::Idle;
                } else if self.rounds >= self.spec.rounds {
                    if self.candidates.is_empty() {
                        self.state = State::Idle;
                    } else {
                        self.state = State::Failed;
                        out.push(ev(
                            "tunnel-failed",
                            vec![
                                ("tunnel", self.name.clone()),
                                ("rounds", self.rounds.to_string()),
                                ("candidates", self.candidates.len().to_string()),
                            ],
                        ));
                    }
                } else {
                    self.rounds += 1;
                    if !self.reflected {
                        for r in self.spec.reflectors.clone() {
                            self.seq += 1;
                            self.c.checks_sent += 1;
                            let t = txid(TX_QUERY, self.spec.id, self.seq);
                            out.push(Action::Send {
                                to: r,
                                datagram: stun::request(&t, None),
                            });
                        }
                    }
                    for c in self.candidates.clone() {
                        self.check(c, out);
                    }
                    self.next = now + self.spec.probe_ns;
                }
            }
            State::Idle | State::Failed => {}
        }
    }

    /// Adds a candidate; `source` says where it came from (`command` or
    /// `peer-reflexive`). A tunnel that is idle or failed starts probing again at once.
    pub fn add_candidate(
        &mut self,
        now: u64,
        e: SocketAddrV4,
        source: &str,
        out: &mut Vec<Action>,
    ) -> bool {
        if self.candidates.contains(&e) || self.candidates.len() >= MAX_CANDIDATES {
            return false;
        }
        self.candidates.push(e);
        out.push(ev(
            "tunnel-candidate",
            vec![
                ("tunnel", self.name.clone()),
                ("endpoint", e.to_string()),
                ("source", source.to_owned()),
            ],
        ));
        match self.state {
            State::Idle | State::Failed => {
                self.state = State::Probing;
                self.rounds = 0;
                self.next = now;
                self.since = now;
            }
            // A new candidate is checked in the next round, or at once (a triggered check).
            State::Probing => self.next = now,
            State::Up => {}
        }
        true
    }

    /// Forgets a candidate. A tunnel that is up keeps its peer even so, but does not probe it
    /// again after going down unless it is heard from or given again.
    pub fn remove_candidate(&mut self, e: SocketAddrV4) -> bool {
        let before = self.candidates.len();
        self.candidates.retain(|c| *c != e);
        before != self.candidates.len()
    }

    /// A packet with this tunnel's id came from `from`: the peer is alive, or has moved, or
    /// the tunnel comes up.
    fn heard(&mut self, now: u64, from: SocketAddrV4, out: &mut Vec<Action>) {
        // The endpoint heard from is always a candidate, so a tunnel that goes down probes its
        // last peer again; at the bound it takes the oldest candidate's place.
        if !self.candidates.contains(&from) {
            if self.candidates.len() >= MAX_CANDIDATES {
                self.candidates.remove(0);
            }
            self.candidates.push(from);
        }
        self.last_rx = now;
        if self.state != State::Up {
            self.state = State::Up;
            self.peer = Some(from);
            self.next = now + self.spec.keepalive_ns;
            out.push(ev(
                "tunnel-up",
                vec![
                    ("tunnel", self.name.clone()),
                    ("peer", from.to_string()),
                    ("after-ns", (now - self.since).to_string()),
                ],
            ));
            out.push(Action::Carrier(true));
        } else if self.peer != Some(from) {
            out.push(ev(
                "tunnel-roamed",
                vec![
                    ("tunnel", self.name.clone()),
                    ("from", ep(self.peer)),
                    ("to", from.to_string()),
                ],
            ));
            self.peer = Some(from);
            self.c.roamed += 1;
        }
    }

    /// A check for this tunnel from `from`: answered with the endpoint it came from, learnt as a
    /// candidate, and once up, the peer follows it.
    pub fn on_request(
        &mut self,
        now: u64,
        from: SocketAddrV4,
        t: &stun::TransactionId,
        out: &mut Vec<Action>,
    ) {
        self.c.requests_received += 1;
        out.push(Action::Send {
            to: from,
            datagram: stun::success(t, SocketAddr::V4(from)),
        });
        if self.state == State::Up {
            self.heard(now, from, out);
        } else {
            self.add_candidate(now, from, "peer-reflexive", out);
        }
    }

    /// A success response for this tunnel: from a reflector (its reflexive endpoint) or from
    /// the peer (the tunnel is up).
    pub fn on_response(
        &mut self,
        now: u64,
        from: SocketAddrV4,
        t: &stun::TransactionId,
        mapped: Option<SocketAddr>,
        out: &mut Vec<Action>,
    ) {
        let (kind, _, seq) = parse_txid(t);
        if seq == 0 || seq > self.seq {
            return;
        }
        self.c.responses_received += 1;
        let mapped = match mapped {
            Some(SocketAddr::V4(m)) => Some(m),
            _ => None,
        };
        if let Some(m) = mapped
            && self.reflexive != Some(m)
        {
            self.reflexive = Some(m);
            out.push(ev(
                "tunnel-reflexive",
                vec![
                    ("tunnel", self.name.clone()),
                    ("endpoint", m.to_string()),
                    ("from", from.to_string()),
                ],
            ));
        }
        if kind == TX_QUERY {
            self.reflected = true;
        } else {
            self.heard(now, from, out);
        }
    }

    /// A data packet for this tunnel from `from`, of `len` inner bytes.
    pub fn on_data(&mut self, now: u64, from: SocketAddrV4, len: usize, out: &mut Vec<Action>) {
        self.c.rx_packets += 1;
        self.c.rx_bytes += len as u64;
        self.heard(now, from, out);
    }

    /// One line of the `tunnels` listing: the name, then `<key> <value>` pairs.
    pub fn listing(&self) -> String {
        let cands: Vec<String> = self.candidates.iter().map(ToString::to_string).collect();
        format!(
            "{} id {} udp {} local {}/{} state {} peer {} reflexive {} candidates {} \
             tx-packets {} rx-packets {}",
            self.name,
            self.spec.id,
            self.spec.udp,
            self.spec.local.0,
            self.spec.local.1,
            self.state.name(),
            ep(self.peer()),
            ep(self.reflexive),
            if cands.is_empty() {
                "-".to_owned()
            } else {
                cands.join(",")
            },
            self.c.tx_packets,
            self.c.rx_packets,
        )
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests;
