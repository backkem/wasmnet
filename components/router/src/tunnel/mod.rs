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

pub mod esp;
pub mod geneve;
pub mod key;
pub mod mss;
pub mod stun;

use std::collections::{BTreeMap, VecDeque};
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
/// What a keyed tunnel adds to an inner packet whose length plus 2 is a multiple of 4: the outer
/// IPv4 header, UDP and ESP (up to 3 more bytes of padding for other lengths).
pub const KEYED_OVERHEAD: u16 = 20 + 8 + esp::OVERHEAD as u16;
/// A keyed tunnel's default MTU: a 1500-byte path minus [`KEYED_OVERHEAD`] (1438, so a
/// full-size packet needs no padding).
pub const KEYED_MTU: u16 = 1500 - KEYED_OVERHEAD;
/// Checks a keyed tunnel remembers while it waits for their answers.
const PENDING: usize = 16;

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
    /// The tunnel key: with one, checks are signed and data is ESP ([`key`], [`esp`]).
    pub key: Option<key::Key>,
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
    "key",
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
        let key = seen.get("key").map(|v| key::Key::parse(v)).transpose()?;
        let udp = match seen.get("udp") {
            None if key.is_some() => esp::PORT,
            None => geneve::PORT,
            Some(v) => v
                .parse::<u16>()
                .ok()
                .filter(|&p| p != 0)
                .ok_or_else(|| format!("udp: `{v}` is not a port 1..=65535"))?,
        };
        let mtu = match seen.get("mtu") {
            None if key.is_some() => KEYED_MTU,
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
            key,
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
    /// Checks, answers and data refused by a keyed tunnel (or a signed check by a keyless one):
    /// unsigned, under another key, reflected, replayed, stale.
    pub auth_failed: u64,
    /// Of those, replays: a check counter or an ESP sequence number seen before.
    pub replayed: u64,
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
    /// A keyed tunnel's keys and what it knows of its peer's.
    crypto: Option<Crypto>,
    /// The reasons of refusals journalled since the tunnel last came up or changed its key: each
    /// is journalled once, then only counted.
    reported: Vec<&'static str>,
    /// A keyed tunnel's checks that await an answer, oldest first, at most [`PENDING`].
    pending: VecDeque<stun::TransactionId>,
}

/// A keyed tunnel's keys: the current one and, after a replacement, the previous one until the
/// peer proves it has the new key (or `dead` has passed).
#[derive(Clone, Debug)]
struct Crypto {
    cur: Keyed,
    prev: Option<Keyed>,
    /// When `prev` became previous.
    replaced: u64,
}

/// One key at this end: its epoch, the SPI this end receives on, the STUN password, and the
/// peer's state under it once an authenticated message told it.
#[derive(Clone, Debug)]
struct Keyed {
    key: key::Key,
    id: String,
    epoch: u64,
    spi: u32,
    password: Vec<u8>,
    peer: Option<Peer>,
}

/// The peer under one key: its SPI and epoch (`TUNNEL-SA`), the highest check counter seen
/// from it in that epoch, and the two SAs with their sequence number and replay window.
#[derive(Clone, Debug)]
struct Peer {
    spi: u32,
    epoch: u64,
    checks: u64,
    out: esp::Sa,
    seq: u32,
    inbound: esp::Sa,
    window: esp::Window,
}

impl Keyed {
    fn new(key: key::Key, epoch: u64, local: IpAddr) -> Keyed {
        Keyed {
            id: key.id(),
            spi: key.spi(epoch, local),
            password: key.stun_password(),
            epoch,
            key,
            peer: None,
        }
    }

    fn sa(&self) -> (u32, u64) {
        (self.spi, self.epoch)
    }

    /// The peer's `TUNNEL-SA` in an authenticated message, with its check counter if it is a
    /// check: refused if reflected, older than what is known, or a replayed check. A newer
    /// epoch (the peer restarted or set the key again) starts fresh SAs.
    fn learn(&mut self, sa: (u32, u64), check: Option<u64>) -> Result<(), &'static str> {
        let (spi, epoch) = sa;
        if spi == self.spi {
            return Err("reflected");
        }
        match &self.peer {
            Some(p) if epoch < p.epoch || (epoch == p.epoch && spi != p.spi) => {
                return Err("stale");
            }
            Some(p) if epoch == p.epoch => {}
            _ => {
                self.peer = Some(Peer {
                    spi,
                    epoch,
                    checks: 0,
                    out: esp::Sa::new(&self.key.esp(spi, self.epoch)),
                    seq: 0,
                    inbound: esp::Sa::new(&self.key.esp(self.spi, epoch)),
                    window: esp::Window::default(),
                });
            }
        }
        if let (Some(n), Some(p)) = (check, self.peer.as_mut()) {
            if n <= p.checks {
                return Err("replayed");
            }
            p.checks = n;
        }
        Ok(())
    }
}

/// Which of a keyed tunnel's keys a message checked under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Which {
    Cur,
    Prev,
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
        let crypto = spec.key.clone().map(|k| Crypto {
            cur: Keyed::new(k, now, spec.local.0),
            prev: None,
            replaced: now,
        });
        let mut t = Tunnel {
            name: name.to_owned(),
            candidates: spec.peers.clone(),
            spec,
            crypto,
            reported: Vec::new(),
            pending: VecDeque::new(),
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
        let retire = self
            .crypto
            .as_ref()
            .filter(|c| c.prev.is_some())
            .map(|c| c.replaced.saturating_add(self.spec.dead_ns));
        let own = match self.state {
            State::Up => Some(
                self.next
                    .min(self.last_rx.saturating_add(self.spec.dead_ns)),
            ),
            State::Probing => Some(self.next),
            State::Idle | State::Failed => None,
        };
        match (own, retire) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn check(&mut self, to: SocketAddrV4, out: &mut Vec<Action>) {
        self.seq += 1;
        self.c.checks_sent += 1;
        let t = txid(TX_CHECK, self.spec.id, self.seq);
        let user = self.spec.id.to_string();
        let datagram = match &self.crypto {
            Some(c) => {
                if self.pending.len() == PENDING {
                    self.pending.pop_front();
                }
                self.pending.push_back(t);
                stun::request_signed(&t, &user, c.cur.sa(), &c.cur.password)
            }
            None => stun::request(&t, Some(&user)),
        };
        out.push(Action::Send { to, datagram });
    }

    /// Timers: a probing round, a keepalive, or the peer gone silent.
    pub fn poll(&mut self, now: u64, out: &mut Vec<Action>) {
        if let Some(c) = self.crypto.as_mut()
            && c.prev.is_some()
            && now >= c.replaced.saturating_add(self.spec.dead_ns)
            && let Some(old) = c.prev.take()
        {
            out.push(ev(
                "tunnel-key-retired",
                vec![("tunnel", self.name.clone()), ("key", old.id)],
            ));
        }
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
            self.reported.clear();
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

    // ---- keys ------------------------------------------------------------------------------

    /// Whether the tunnel has a key.
    pub fn keyed(&self) -> bool {
        self.crypto.is_some()
    }

    /// The current key's id (`-` without a key).
    pub fn key_id(&self) -> String {
        self.crypto
            .as_ref()
            .map_or_else(|| "-".to_owned(), |c| c.cur.id.clone())
    }

    /// Whether this tunnel receives ESP on `spi` (under its current or previous key).
    pub fn has_spi(&self, spi: u32) -> bool {
        self.crypto
            .as_ref()
            .is_some_and(|c| c.cur.spi == spi || c.prev.as_ref().is_some_and(|p| p.spi == spi))
    }

    /// A message refused for `reason`: counted, and journalled as `tunnel-auth-failed` the
    /// first time this reason comes since the tunnel came up or changed its key.
    pub fn refuse(&mut self, reason: &'static str, from: SocketAddrV4, out: &mut Vec<Action>) {
        self.c.auth_failed += 1;
        if reason == "replayed" {
            self.c.replayed += 1;
        }
        if !self.reported.contains(&reason) {
            self.reported.push(reason);
            out.push(ev(
                "tunnel-auth-failed",
                vec![
                    ("tunnel", self.name.clone()),
                    ("from", from.to_string()),
                    ("reason", reason.to_owned()),
                ],
            ));
        }
    }

    /// Which key a signed message checks under, if any, and its `TUNNEL-SA`.
    fn authenticate(
        &self,
        d: &[u8],
        signed: &stun::Signed,
    ) -> Result<(Which, (u32, u64)), &'static str> {
        let Some(c) = &self.crypto else {
            return Err("keyed-peer");
        };
        let Some(i) = &signed.integrity else {
            return Err("unsigned");
        };
        let which = if stun::verify(d, i, &c.cur.password) {
            Which::Cur
        } else if c
            .prev
            .as_ref()
            .is_some_and(|p| stun::verify(d, i, &p.password))
        {
            Which::Prev
        } else {
            return Err("integrity");
        };
        let sa = signed.sa.ok_or("unsigned")?;
        Ok((which, sa))
    }

    fn keyed_mut(&mut self, which: Which) -> Option<&mut Keyed> {
        let c = self.crypto.as_mut()?;
        match which {
            Which::Cur => Some(&mut c.cur),
            Which::Prev => c.prev.as_mut(),
        }
    }

    /// A message under the current key proves the peer has it: the previous key goes.
    fn confirmed(&mut self, which: Which, out: &mut Vec<Action>) {
        if which != Which::Cur {
            return;
        }
        if let Some(c) = self.crypto.as_mut()
            && let Some(old) = c.prev.take()
        {
            out.push(ev(
                "tunnel-key-confirmed",
                vec![
                    ("tunnel", self.name.clone()),
                    ("key", c.cur.id.clone()),
                    ("previous", old.id),
                ],
            ));
        }
    }

    /// A check (`d`, decoded) for this tunnel from `from`. Without a key, as [`on_request`]
    /// (a signed check is refused: the peer has a key this end lacks). With one, only a check
    /// that checks under the current or previous key, is not reflected, stale or replayed, is
    /// answered (signed, with the same key) and counts as hearing the peer.
    ///
    /// [`on_request`]: Self::on_request
    pub fn on_request_signed(
        &mut self,
        now: u64,
        from: SocketAddrV4,
        t: &stun::TransactionId,
        d: &[u8],
        signed: &stun::Signed,
        out: &mut Vec<Action>,
    ) {
        if self.crypto.is_none() {
            if signed.integrity.is_some() {
                self.refuse("keyed-peer", from, out);
            } else {
                self.on_request(now, from, t, out);
            }
            return;
        }
        let (which, sa) = match self.authenticate(d, signed) {
            Ok(a) => a,
            Err(r) => return self.refuse(r, from, out),
        };
        let (_, _, counter) = parse_txid(t);
        let k = self.keyed_mut(which).expect("authenticated");
        if let Err(r) = k.learn(sa, Some(counter)) {
            return self.refuse(r, from, out);
        }
        let datagram = stun::success_signed(t, SocketAddr::V4(from), k.sa(), &k.password);
        self.c.requests_received += 1;
        out.push(Action::Send { to: from, datagram });
        self.confirmed(which, out);
        if self.state == State::Up {
            self.heard(now, from, out);
        } else {
            self.add_candidate(now, from, "peer-reflexive", out);
        }
    }

    /// A success response (`d`, decoded) for this tunnel. Without a key, as [`on_response`]. A
    /// keyed tunnel takes an answer to a reflector query as a keyless one does (its reflexive
    /// endpoint, nothing more); an answer to a check counts only if it checks under one of its
    /// keys and answers a check it is still waiting for (each once).
    ///
    /// [`on_response`]: Self::on_response
    #[allow(clippy::too_many_arguments)] // the decoded message and its bytes, as on_response takes
    pub fn on_response_signed(
        &mut self,
        now: u64,
        from: SocketAddrV4,
        t: &stun::TransactionId,
        mapped: Option<SocketAddr>,
        d: &[u8],
        signed: &stun::Signed,
        out: &mut Vec<Action>,
    ) {
        let (kind, _, _) = parse_txid(t);
        if self.crypto.is_none() || kind == TX_QUERY {
            if self.crypto.is_none() && signed.integrity.is_some() {
                return self.refuse("keyed-peer", from, out);
            }
            return self.on_response(now, from, t, mapped, out);
        }
        let (which, sa) = match self.authenticate(d, signed) {
            Ok(a) => a,
            Err(r) => return self.refuse(r, from, out),
        };
        let Some(at) = self.pending.iter().position(|p| p == t) else {
            return self.refuse("unexpected", from, out);
        };
        if let Err(r) = self
            .keyed_mut(which)
            .expect("authenticated")
            .learn(sa, None)
        {
            return self.refuse(r, from, out);
        }
        self.pending.remove(at);
        self.confirmed(which, out);
        self.on_response(now, from, t, mapped, out);
    }

    /// An ESP packet `d` for one of this tunnel's SPIs from `from`: its inner packet, once it
    /// opened under the SA of the key that SPI belongs to and was not a replay; the peer is
    /// heard (and may roam) only then.
    pub fn on_esp(
        &mut self,
        now: u64,
        from: SocketAddrV4,
        d: &[u8],
        out: &mut Vec<Action>,
    ) -> Option<Vec<u8>> {
        let spi = esp::spi_of(d)?;
        let which = match &self.crypto {
            Some(c) if c.cur.spi == spi => Which::Cur,
            Some(c) if c.prev.as_ref().is_some_and(|p| p.spi == spi) => Which::Prev,
            _ => return None,
        };
        let k = self.keyed_mut(which).expect("its SPI");
        let Some(p) = k.peer.as_mut() else {
            self.refuse("no-sa", from, out);
            return None;
        };
        let inner = match esp::open(&p.inbound, &mut p.window, d) {
            Ok((inner, _)) => inner,
            Err(esp::Error::Replayed) => {
                self.refuse("replayed", from, out);
                return None;
            }
            Err(_) => {
                self.refuse("esp", from, out);
                return None;
            }
        };
        self.confirmed(which, out);
        self.on_data(now, from, inner.len(), out);
        Some(inner)
    }

    /// The ESP packet for `inner` toward the peer, under the newest key the peer has proven it
    /// holds; `None` when it has proven none yet, or that key's SA has used every sequence
    /// number (the controller must replace the key).
    pub fn seal(&mut self, inner: &[u8], out: &mut Vec<Action>) -> Option<Vec<u8>> {
        let name = self.name.clone();
        let c = self.crypto.as_mut()?;
        let k = if c.cur.peer.is_some() {
            &mut c.cur
        } else {
            c.prev.as_mut().filter(|p| p.peer.is_some())?
        };
        let p = k.peer.as_mut()?;
        if p.seq == u32::MAX {
            if !self.reported.contains(&"exhausted") {
                self.reported.push("exhausted");
                out.push(ev(
                    "tunnel-key-exhausted",
                    vec![("tunnel", name), ("key", k.id.clone())],
                ));
            }
            return None;
        }
        p.seq += 1;
        Some(esp::seal(&p.out, p.spi, p.seq, inner))
    }

    /// Replaces the key: the new one is current from now on (a new epoch, a new SPI, checks
    /// signed with it at once); the old one stays as the previous key, still accepted and still
    /// used to send, until the peer proves it holds the new one or `dead` has passed. `false`:
    /// the tunnel has this key already, or none at all (a keyless tunnel gets one only by being
    /// added again).
    pub fn replace_key(
        &mut self,
        now: u64,
        key: key::Key,
        out: &mut Vec<Action>,
    ) -> Result<bool, String> {
        let local = self.spec.local.0;
        let Some(c) = self.crypto.as_mut() else {
            return Err(format!(
                "tunnel `{}` has no key: remove it and add it again with one",
                self.name
            ));
        };
        if c.cur.key == key {
            return Ok(false);
        }
        let epoch = now.max(c.cur.epoch + 1);
        let new = Keyed::new(key.clone(), epoch, local);
        let old = std::mem::replace(&mut c.cur, new);
        out.push(ev(
            "tunnel-key-replaced",
            vec![
                ("tunnel", self.name.clone()),
                ("key", c.cur.id.clone()),
                ("previous", old.id.clone()),
            ],
        ));
        c.prev = Some(old);
        c.replaced = now;
        self.spec.key = Some(key);
        self.reported.clear();
        self.pending.clear();
        // Tell the peer at once: a check under the new key now, not at the next keepalive.
        if self.state == State::Up {
            self.next = now;
        }
        Ok(true)
    }

    /// One line of the `tunnels` listing: the name, then `<key> <value>` pairs.
    pub fn listing(&self) -> String {
        let cands: Vec<String> = self.candidates.iter().map(ToString::to_string).collect();
        format!(
            "{} id {} udp {} local {}/{} state {} peer {} reflexive {} candidates {} \
             tx-packets {} rx-packets {}{}",
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
            // Only a keyed tunnel lists its key, so a keyless line is as it was.
            if self.keyed() {
                format!(" key {}", self.key_id())
            } else {
                String::new()
            },
        )
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod keyed_tests;
#[cfg(test)]
mod tests;
