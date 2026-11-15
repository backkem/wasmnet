//! mdns-responder: a Multicast DNS responder (RFC 6762) for one host name, as a wasmnet app.
//! It claims `<hostname>.local` on the link, answers A and AAAA questions for it with
//! the node's addresses, and never returns: a daemon.
//!
//! # Config (`wasi:config`, keys under `app.mdns-responder.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `hostname` | the name to claim, one label (`alice` claims `alice.local`) | required |
//! | `families` | the groups to listen on: `ipv4` (224.0.0.251), `ipv6` (ff02::fb), or both (a list) | `ipv4,ipv6` |
//! | `ttl` | the TTL of its records, whole seconds | `120s` |
//! | `link-local` | also announce IPv6 link-local addresses | `false` |
//! | `start` | virtual time to wait before probing | `0` |
//!
//! # Behaviour (RFC 6762)
//!
//! * **Probing** (§8.1): three queries for the name (type ANY, the first with the QU bit), 250 ms
//!   apart, with the proposed A/AAAA records in the authority section. They start after a delay
//!   of 0–249 ms; the RFC wants it random, here it is derived from the name (an FNV hash), so a
//!   simulation's timeline does not move with the seed while two names still spread out.
//! * **Simultaneous probes** (§8.2): another host's probe for the name while probing (a query
//!   with records for it in the authority section) is a tiebreak: both sets of records are
//!   compared in lexicographical order, and the earlier one loses. The loser probes for the same
//!   name again one second later (`mdns-probe-lost`); the winner goes on.
//! * **Conflict** (§9): a response that holds a record for the name with other data than ours
//!   while probing (another host owns it) makes the responder pick the next name,
//!   `<hostname>-2`, `-3`, ..., and probe again at once. Such an answer while announced (someone
//!   else claims it) does the same. A record identical to one of ours is no conflict.
//! * **Announcing** (§8.3): two unsolicited responses, one second apart, with every record
//!   (cache-flush bit set). Not done yet: announcing again when the node's addresses change
//!   after that (§8.4), for example when a later DHCP lease differs.
//! * **Answering** (§6): a question for the name (A, AAAA or ANY; class IN, the QU bit ignored)
//!   is answered at once (the records are unique, so no delay):
//!   - from a port other than 5353 (a one-shot "legacy" querier, §6.7): unicast to that port, the
//!     query's id and question copied, TTL at most 10 s, no cache-flush bit;
//!   - with the QU bit (§5.4): unicast to the querier's port 5353;
//!   - otherwise by multicast to the group the query came on.
//!
//!   A record the querier already holds with at least half its TTL left (known-answer
//!   suppression, §7.1) is left out; nothing left, no answer. The other family's records go in
//!   the additional section.
//! * Every mDNS packet leaves with hop limit 255 (§11) and multicast loopback off (the responder
//!   must not hear itself).
//!
//! # Journal
//!
//! `mdns-probing {name, attempt}`, `mdns-probe-lost {name, from}`, `mdns-conflict {name, from}`,
//! `mdns-renamed {from, to}`,
//! `mdns-announced {name, addresses}`, `mdns-answered {name, types, to, mode}` (`mode`:
//! `legacy-unicast`, `unicast` or `multicast`).

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::net::{IpAddr, SocketAddr};
pub use wasmnet_app_kit::app_pairs;

use wasmnet_wire::dns::{
    self, CLASS_IN, MDNS_CLASS_BIT, MDNS_PORT, Message, Question, RData, Record, rtype,
};
use wasmnet_wire::parse_duration;

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "mdns-responder";
/// RFC 6762 §8.1: probes 250 ms apart, three of them.
pub const PROBE_INTERVAL_NS: u64 = 250_000_000;
pub const PROBES: u32 = 3;
/// §8.3: two announcements, one second apart.
pub const ANNOUNCE_INTERVAL_NS: u64 = 1_000_000_000;
pub const ANNOUNCEMENTS: u32 = 2;
/// §8.2: a host that loses a simultaneous-probe tiebreak probes again one second later.
pub const TIEBREAK_DEFER_NS: u64 = 1_000_000_000;
/// §6.7: a legacy unicast answer carries a TTL of at most 10 s.
pub const LEGACY_TTL: u32 = 10;
const MS: u64 = 1_000_000;

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

/// The parsed config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub hostname: String,
    pub ipv4: bool,
    pub ipv6: bool,
    pub ttl: u32,
    pub link_local: bool,
    pub start_ns: u64,
}

impl Config {
    /// Parses this app's pairs (prefix already stripped). Unknown keys are errors.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Self, ConfigError> {
        let mut c = Config {
            hostname: String::new(),
            ipv4: true,
            ipv6: true,
            ttl: 120,
            link_local: false,
            start_ns: 0,
        };
        for (key, value) in pairs {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            match key.as_str() {
                "hostname" => {
                    // A host name label (RFC 1123 §2.1): no `_`, which DNS names allow.
                    if value.contains(['.', '_']) || !dns::valid_name(&value) {
                        return Err(invalid("one label of letters, digits and -"));
                    }
                    c.hostname = value.to_ascii_lowercase();
                }
                "families" => {
                    let list: Vec<&str> = value.split(',').map(str::trim).collect();
                    if list.is_empty() || list.iter().any(|f| *f != "ipv4" && *f != "ipv6") {
                        return Err(invalid("ipv4, ipv6 or both"));
                    }
                    c.ipv4 = list.contains(&"ipv4");
                    c.ipv6 = list.contains(&"ipv6");
                }
                "ttl" => {
                    c.ttl = parse_duration(&value)
                        .filter(|ns| *ns >= 1_000_000_000 && ns % 1_000_000_000 == 0)
                        .and_then(|ns| u32::try_from(ns / 1_000_000_000).ok())
                        .ok_or_else(|| invalid("whole seconds, at least 1s"))?;
                }
                "link-local" => {
                    c.link_local = value.parse().map_err(|_| invalid("true or false"))?;
                }
                "start" => {
                    c.start_ns = parse_duration(&value).ok_or_else(|| invalid("a duration"))?;
                }
                _ => return Err(ConfigError::Unknown { key }),
            }
        }
        if c.hostname.is_empty() {
            return Err(ConfigError::Missing {
                key: "hostname".into(),
                expected: "the name to claim, like alice",
            });
        }
        Ok(c)
    }
}

/// Where a packet goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    /// To the group of this family, from the responder's socket of that family.
    Group { v6: bool },
    /// To one querier.
    Unicast(SocketAddr),
}

/// One packet to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub to: Dest,
    pub message: Message,
}

/// One journal event: kind and fields.
pub type Note = (&'static str, Vec<(String, String)>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Waiting to send probe `n` (0-based) at `at`.
    Probing {
        n: u32,
        at: u64,
    },
    /// Waiting to send announcement `n` at `at`.
    Announcing {
        n: u32,
        at: u64,
    },
    Ready,
}

/// The responder's state machine. Every input carries the time; nothing reads a clock.
#[derive(Debug)]
pub struct Responder {
    pub config: Config,
    /// The name it claims now, `alice.local` (`alice-2.local` after a conflict).
    pub name: String,
    renames: u32,
    state: State,
    /// The first probe went out: until then (the `start` delay), packets are ignored.
    begun: bool,
    /// The addresses last announced (filtered, in order).
    announced: Vec<IpAddr>,
}

fn kv(k: &str, v: impl ToString) -> (String, String) {
    (k.to_owned(), v.to_string())
}

/// FNV-1a of the name: the probe delay's stand-in for randomness.
fn fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

/// A record's place in §8.2's lexicographical order: class (without the cache-flush bit), type,
/// then the rdata's bytes. Host probes carry A and AAAA records, whose wire rdata is the address;
/// other data is compared by its raw bytes, or its presentation text for names.
fn order_key(r: &Record) -> (u16, u16, Vec<u8>) {
    let data = match &r.data {
        RData::A(a) => a.octets().to_vec(),
        RData::Aaaa(a) => a.octets().to_vec(),
        RData::Other(raw) => raw.clone(),
        other => other.text().into_bytes(),
    };
    (r.class & !MDNS_CLASS_BIT, r.rtype, data)
}

fn join(addrs: &[IpAddr]) -> String {
    addrs
        .iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn is_link_local(a: &IpAddr) -> bool {
    match a {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

impl Responder {
    pub fn new(config: Config) -> Self {
        let name = format!("{}.local", config.hostname);
        let start = config.start_ns + (fnv(&name) % 250) * MS;
        Self {
            config,
            name,
            renames: 0,
            begun: false,
            state: State::Probing { n: 0, at: start },
            announced: Vec::new(),
        }
    }

    /// The addresses it answers with, from the interface's (link-local IPv6 only if asked).
    pub fn usable(&self, addrs: &[IpAddr]) -> Vec<IpAddr> {
        addrs
            .iter()
            .filter(|a| self.config.link_local || !is_link_local(a))
            .filter(|a| !a.is_loopback() && !a.is_unspecified())
            .copied()
            .collect()
    }

    /// When [`tick`](Self::tick) must run next.
    pub fn next_deadline(&self) -> Option<u64> {
        match self.state {
            State::Probing { at, .. } | State::Announcing { at, .. } => Some(at),
            State::Ready => None,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.state == State::Ready
    }

    fn records(&self, addrs: &[IpAddr], ttl: u32, flush: bool, types: &[u16]) -> Vec<Record> {
        let class = if flush {
            CLASS_IN | MDNS_CLASS_BIT
        } else {
            CLASS_IN
        };
        addrs
            .iter()
            .filter_map(|a| {
                let (t, data) = match a {
                    IpAddr::V4(v4) => (rtype::A, RData::A(*v4)),
                    IpAddr::V6(v6) => (rtype::AAAA, RData::Aaaa(*v6)),
                };
                types.contains(&t).then(|| Record {
                    name: self.name.clone(),
                    rtype: t,
                    class,
                    ttl,
                    data,
                })
            })
            .collect()
    }

    fn groups(&self) -> Vec<Dest> {
        let mut d = Vec::new();
        if self.config.ipv4 {
            d.push(Dest::Group { v6: false });
        }
        if self.config.ipv6 {
            d.push(Dest::Group { v6: true });
        }
        d
    }

    /// Runs the timers at `now` with the node's current addresses `addrs`.
    pub fn tick(&mut self, now: u64, addrs: &[IpAddr]) -> (Vec<Packet>, Vec<Note>) {
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let usable = self.usable(addrs);
        // §8.4: the addresses changed after we announced them: announce again.
        if self.state == State::Ready && usable != self.announced {
            self.state = State::Announcing { n: 0, at: now };
        }
        match self.state {
            State::Probing { n, at } if at <= now => {
                if usable.is_empty() {
                    // Nothing to claim yet (a DHCP lease to come): look again in a while.
                    self.state = State::Probing {
                        n,
                        at: now + PROBE_INTERVAL_NS,
                    };
                    return (out, notes);
                }
                self.begun = true;
                if n == 0 {
                    notes.push((
                        "mdns-probing",
                        vec![kv("name", &self.name), kv("attempt", self.renames + 1)],
                    ));
                }
                let mut q = Message::query(0, &self.name, rtype::ANY);
                q.flags = 0; // mDNS queries: no RD
                if n == 0 {
                    q.questions[0].qclass |= MDNS_CLASS_BIT; // QU on the first probe
                }
                q.authorities =
                    self.records(&usable, self.config.ttl, false, &[rtype::A, rtype::AAAA]);
                for to in self.groups() {
                    out.push(Packet {
                        to,
                        message: q.clone(),
                    });
                }
                self.state = if n + 1 < PROBES {
                    State::Probing {
                        n: n + 1,
                        at: now + PROBE_INTERVAL_NS,
                    }
                } else {
                    // §8.3: announce 250 ms after the last probe went unanswered.
                    State::Announcing {
                        n: 0,
                        at: now + PROBE_INTERVAL_NS,
                    }
                };
            }
            State::Announcing { n, at } if at <= now => {
                let mut r = Message {
                    flags: 0x8400, // QR, AA
                    ..Message::default()
                };
                r.answers = self.records(&usable, self.config.ttl, true, &[rtype::A, rtype::AAAA]);
                for to in self.groups() {
                    out.push(Packet {
                        to,
                        message: r.clone(),
                    });
                }
                if n == 0 {
                    notes.push((
                        "mdns-announced",
                        vec![kv("name", &self.name), kv("addresses", join(&usable))],
                    ));
                }
                self.announced = usable;
                self.state = if n + 1 < ANNOUNCEMENTS {
                    State::Announcing {
                        n: n + 1,
                        at: now + ANNOUNCE_INTERVAL_NS,
                    }
                } else {
                    State::Ready
                };
            }
            _ => {}
        }
        (out, notes)
    }

    /// Picks the next name after a conflict and probes again at once.
    fn conflict(&mut self, now: u64, from: SocketAddr, notes: &mut Vec<Note>) {
        notes.push((
            "mdns-conflict",
            vec![kv("name", &self.name), kv("from", from.ip())],
        ));
        self.renames += 1;
        let old = std::mem::replace(
            &mut self.name,
            format!("{}-{}.local", self.config.hostname, self.renames + 1),
        );
        notes.push(("mdns-renamed", vec![kv("from", old), kv("to", &self.name)]));
        self.announced.clear();
        self.state = State::Probing { n: 0, at: now };
    }

    /// §8.2, simultaneous probe tiebreaking: `m`, a query that arrived while we probe, is another
    /// host's probe for our name when its authority section holds records for it. Both sides'
    /// records are sorted and compared pairwise (class without the cache-flush bit, type, then
    /// the raw rdata); a list that runs out first is earlier. Ours later or equal: we go on.
    /// Ours earlier: we lost, and probe for the same name again in one second (by then the
    /// winner defends it, and its answer is a conflict).
    fn tiebreak(
        &mut self,
        now: u64,
        from: SocketAddr,
        m: &Message,
        usable: &[IpAddr],
        notes: &mut Vec<Note>,
    ) {
        let probe_for_us = m
            .questions
            .iter()
            .any(|q| dns::same_name(&q.name, &self.name));
        let mut theirs: Vec<(u16, u16, Vec<u8>)> = m
            .authorities
            .iter()
            .filter(|r| dns::same_name(&r.name, &self.name))
            .map(order_key)
            .collect();
        if !probe_for_us || theirs.is_empty() {
            return;
        }
        let mut mine: Vec<(u16, u16, Vec<u8>)> = self
            .records(usable, self.config.ttl, false, &[rtype::A, rtype::AAAA])
            .iter()
            .map(order_key)
            .collect();
        mine.sort();
        theirs.sort();
        // Vec's ordering is exactly the RFC's: pairwise, and a prefix is earlier.
        if mine < theirs {
            notes.push((
                "mdns-probe-lost",
                vec![kv("name", &self.name), kv("from", from.ip())],
            ));
            self.state = State::Probing {
                n: 0,
                at: now + TIEBREAK_DEFER_NS,
            };
        }
    }

    /// Handles one datagram that arrived at `now` from `from` on the socket of family `v6`.
    pub fn on_packet(
        &mut self,
        now: u64,
        from: SocketAddr,
        v6: bool,
        payload: &[u8],
        addrs: &[IpAddr],
    ) -> (Vec<Packet>, Vec<Note>) {
        let mut out = Vec::new();
        let mut notes = Vec::new();
        if !self.begun {
            // Not started yet: like a host that has not booted its responder.
            return (out, notes);
        }
        let Ok(m) = Message::parse(payload) else {
            return (out, notes);
        };
        if m.opcode() != 0 {
            return (out, notes);
        }
        let ours = |r: &Record| dns::same_name(&r.name, &self.name);
        let usable = self.usable(addrs);
        if m.is_response() {
            // Someone else answers for our name with other data: a conflict (§9: same name and
            // type, inconsistent rdata). A record that is exactly one of ours is no conflict.
            // Our own packets never come back (loopback is off).
            let mine = self.records(&usable, 0, false, &[rtype::A, rtype::AAAA]);
            let conflicting = |r: &Record| {
                ours(r) && !mine.iter().any(|o| o.rtype == r.rtype && o.data == r.data)
            };
            if m.answers.iter().chain(&m.additionals).any(conflicting) {
                self.conflict(now, from, &mut notes);
            }
            return (out, notes);
        }
        if let State::Probing { .. } = self.state {
            self.tiebreak(now, from, &m, &usable, &mut notes);
            return (out, notes);
        }
        if !self.is_ready() {
            return (out, notes);
        }
        let asked: Vec<&Question> = m
            .questions
            .iter()
            .filter(|q| dns::same_name(&q.name, &self.name))
            .filter(|q| q.class() == CLASS_IN || q.class() == 255)
            .collect();
        if asked.is_empty() {
            return (out, notes);
        }
        let mut types: Vec<u16> = Vec::new();
        for q in &asked {
            match q.qtype {
                rtype::ANY => types.extend([rtype::A, rtype::AAAA]),
                t @ (rtype::A | rtype::AAAA) => types.push(t),
                _ => {}
            }
        }
        let legacy = from.port() != MDNS_PORT;
        let ttl = if legacy {
            self.config.ttl.min(LEGACY_TTL)
        } else {
            self.config.ttl
        };
        // Known-answer suppression (§7.1).
        let known = |r: &Record| {
            m.answers
                .iter()
                .any(|k| ours(k) && k.data == r.data && k.ttl >= self.config.ttl / 2)
        };
        let mut answers = self.records(&usable, ttl, !legacy, &types);
        answers.retain(|r| !known(r));
        if answers.is_empty() {
            return (out, notes);
        }
        let others: Vec<u16> = [rtype::A, rtype::AAAA]
            .into_iter()
            .filter(|t| !types.contains(t))
            .collect();
        let mode;
        let mut r = Message {
            flags: 0x8400, // QR, AA
            ..Message::default()
        };
        let to = if legacy {
            mode = "legacy-unicast";
            r.id = m.id;
            r.questions = asked.iter().map(|q| (*q).clone()).collect();
            for q in &mut r.questions {
                q.qclass &= !MDNS_CLASS_BIT;
            }
            Dest::Unicast(from)
        } else if asked.iter().any(|q| q.unicast_response()) {
            mode = "unicast";
            Dest::Unicast(from)
        } else {
            mode = "multicast";
            Dest::Group { v6 }
        };
        let names: Vec<String> = types.iter().map(|t| dns::type_name(*t)).collect();
        r.answers = answers;
        if !legacy {
            r.additionals = self.records(&usable, ttl, true, &others);
        }
        notes.push((
            "mdns-answered",
            vec![
                kv("name", &self.name),
                kv("types", names.join(",")),
                kv("to", from),
                kv("mode", mode),
            ],
        ));
        out.push(Packet { to, message: r });
        (out, notes)
    }
}

#[cfg(test)]
mod tests;
