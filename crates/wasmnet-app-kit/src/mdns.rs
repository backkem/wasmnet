//! DNS-SD service browsing over Multicast DNS (RFC 6763 over RFC 6762), for an app's own UDP
//! sockets.
//!
//! [`Browser`] is a state machine with no I/O and no clock: the app feeds it the time, the
//! datagrams it receives on port 5353 ([`Browser::on_message`]) and its timer
//! ([`Browser::tick`]), sends the queries it returns to the mDNS groups (`224.0.0.251:5353`,
//! `[ff02::fb]:5353`), and acts on the [`Event`]s. It keeps a cache of every record it hears
//! and, for the service types it browses and the instances it resolves:
//!
//! * **Continuous querying** (RFC 6762 §5.2): the first query 20–120 ms after
//!   [`Browser::browse`], then 1 s, 2 s, 4 s ... apart, doubling up to one hour. Each query
//!   carries the PTR records it already holds with more than half their TTL left (known-answer
//!   suppression, §7.1).
//! * **Cache maintenance** (§5.2): a record it still needs is asked for again at 80, 85, 90 and
//!   95 % of its TTL (plus up to 2 % jitter); one nobody refreshed expires at its TTL.
//! * **Goodbyes** (§10.1): a record received with TTL 0 expires one second later.
//! * **Cache flush** (§10.2): a record with the cache-flush bit replaces the other records of
//!   its name and type that are more than one second old (they expire one second later).
//! * **Resolving** an instance ([`Browser::resolve`]): its SRV and TXT, then the addresses of
//!   the SRV's host, whatever is not cached yet (responders usually send all of it with the PTR
//!   answer), asked 1 s, 2 s, 4 s ... apart until it is complete.
//!
//! The jitter comes from the seed given to [`Browser::new`]: random in the RFC, here whatever
//! the app chooses (`wasi:random`, or a hash of its config so the timeline does not move with
//! the network's seed).
//!
//! An app that cannot bind port 5353 (another app on the node holds it) may send the same
//! queries from any port: responders then answer by unicast, with TTLs of at most 10 s
//! (§6.7), and everything here works the same, with more refreshes.
//!
//! Not done: the QU bit on the first query (§5.4), duplicate question suppression (§7.3),
//! passive observation of other hosts' failures (§10.5), subtypes, and a helper for the
//! `_services._dns-sd._udp` meta-query (an app that wants the list of service types sends its
//! own query for [`dns::DNS_SD_SERVICES`]).

use std::collections::BTreeMap;
use std::net::IpAddr;

use wasmnet_wire::dns::{self, CLASS_IN, MDNS_CLASS_BIT, Message, Question, RData, Record, rtype};

pub use wasmnet_wire::dns::{TxtPair, txt_pairs};

const MS: u64 = 1_000_000;
const SECOND: u64 = 1_000_000_000;
/// The longest interval between two queries for one service type (RFC 6762 §5.2).
pub const MAX_INTERVAL_NS: u64 = 3_600 * SECOND;
/// The most records the cache holds; records past it are not cached.
pub const MAX_RECORDS: usize = 4_096;

/// Why an instance went away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// Its PTR came with TTL 0 (the service was withdrawn).
    Goodbye,
    /// Its PTR's TTL ran out and nobody refreshed it (the host went away).
    Expired,
}

impl Removal {
    pub fn as_str(self) -> &'static str {
        match self {
            Removal::Goodbye => "goodbye",
            Removal::Expired => "expired",
        }
    }
}

/// What a resolved instance is: where to connect and its attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// Its full name, `Alpha Web._http._tcp.local` (escaped as [`dns`] does).
    pub name: String,
    /// The instance alone, `Alpha Web`.
    pub instance: String,
    /// The SRV's target, `alpha.local`.
    pub host: String,
    pub port: u16,
    /// The TXT record's strings ([`txt_pairs`] reads them as attributes).
    pub txt: Vec<Vec<u8>>,
    /// The host's addresses, IPv4 first, each family in order.
    pub addresses: Vec<IpAddr>,
}

impl Resolved {
    /// The TXT attributes (RFC 6763 §6).
    pub fn attributes(&self) -> Vec<TxtPair> {
        txt_pairs(&self.txt)
    }

    /// The TXT attributes as text: `path=/,secure` (values not UTF-8 are shown lossily).
    pub fn attributes_text(&self) -> String {
        self.attributes()
            .iter()
            .map(|(k, v)| match v {
                Some(v) => format!("{k}={}", String::from_utf8_lossy(v)),
                None => k.clone(),
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// What the browser saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A new instance of a browsed type.
    Found {
        /// `_http._tcp`.
        service_type: String,
        /// `Alpha Web`.
        instance: String,
        /// `Alpha Web._http._tcp.local`.
        name: String,
    },
    /// An instance of a browsed type is gone.
    Removed {
        service_type: String,
        instance: String,
        name: String,
        reason: Removal,
    },
    /// An instance being resolved is complete (SRV, TXT and at least one address), or its
    /// data changed since it was last reported.
    Resolved(Resolved),
}

/// One cached record.
#[derive(Clone, Debug)]
struct Entry {
    record: Record,
    received: u64,
    expires: u64,
    /// Refresh queries sent for it so far (0 to 4).
    refreshes: u8,
    next_refresh: Option<u64>,
    goodbye: bool,
}

/// Owner (lowercase), type, data as on the wire.
type Key = (String, u16, Vec<u8>);

#[derive(Clone, Debug)]
struct Browse {
    service_type: String,
    /// `_http._tcp.local`.
    name: String,
    next_at: u64,
    interval: u64,
}

#[derive(Clone, Debug)]
struct Resolve {
    name: String,
    /// The next query, while incomplete.
    next_at: Option<u64>,
    interval: u64,
    last: Option<Resolved>,
}

/// A DNS-SD browser on one link: see the [module](self).
#[derive(Clone, Debug)]
pub struct Browser {
    rng: u64,
    browses: Vec<Browse>,
    resolves: Vec<Resolve>,
    cache: BTreeMap<Key, Entry>,
}

fn key(r: &Record) -> Key {
    (r.name.to_ascii_lowercase(), r.rtype, r.data.wire_bytes())
}

fn question(name: &str, qtype: u16) -> Question {
    Question {
        name: name.to_owned(),
        qtype,
        qclass: CLASS_IN,
    }
}

impl Browser {
    /// A browser with nothing to do yet; `seed` drives the jitter.
    pub fn new(seed: u64) -> Self {
        Self {
            rng: seed,
            browses: Vec::new(),
            resolves: Vec::new(),
            cache: BTreeMap::new(),
        }
    }

    /// splitmix64.
    fn random(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Starts browsing `service_type` (`_http._tcp`) in `.local`: the first query goes out 20 to
    /// 120 ms from `now`. Browsing a type twice changes nothing.
    pub fn browse(&mut self, now: u64, service_type: &str) {
        let name = format!("{service_type}.local");
        if self.browses.iter().any(|b| dns::same_name(&b.name, &name)) {
            return;
        }
        let delay = (20 + self.random() % 101) * MS;
        self.browses.push(Browse {
            service_type: service_type.to_owned(),
            name,
            next_at: now + delay,
            interval: SECOND,
        });
    }

    /// Starts resolving the instance `name` (its full name, `Alpha Web._http._tcp.local`): from
    /// the cache if it is all there, otherwise by querying for what is missing, from `now` on.
    pub fn resolve(&mut self, now: u64, name: &str) {
        if self.resolves.iter().any(|r| dns::same_name(&r.name, name)) {
            return;
        }
        self.resolves.push(Resolve {
            name: name.to_owned(),
            next_at: Some(now),
            interval: SECOND,
            last: None,
        });
    }

    /// Stops resolving `name` (an instance that went away, say).
    pub fn stop_resolving(&mut self, name: &str) {
        self.resolves.retain(|r| !dns::same_name(&r.name, name));
    }

    /// The instances of `service_type` cached now, by full name, in order.
    pub fn instances(&self, service_type: &str) -> Vec<String> {
        let owner = format!("{service_type}.local").to_ascii_lowercase();
        self.cache
            .values()
            .filter(|e| e.record.name.eq_ignore_ascii_case(&owner) && e.record.rtype == rtype::PTR)
            .filter_map(|e| match &e.record.data {
                RData::Ptr(n) => Some(n.clone()),
                _ => None,
            })
            .collect()
    }

    /// When [`tick`](Self::tick) must run next.
    pub fn next_deadline(&self) -> Option<u64> {
        let browses = self.browses.iter().map(|b| b.next_at);
        let resolves = self.resolves.iter().filter_map(|r| r.next_at);
        let interest = self.interest();
        let cache = self.cache.iter().flat_map(|(k, e)| {
            let refresh = e.next_refresh.filter(|_| interest(k));
            [Some(e.expires), refresh].into_iter().flatten()
        });
        browses.chain(resolves).chain(cache).min()
    }

    /// Which cached records the browser keeps fresh: PTRs of browsed types, and the SRV, TXT
    /// and addresses of instances it resolves.
    fn interest(&self) -> impl Fn(&Key) -> bool + '_ {
        let browsed: Vec<String> = self
            .browses
            .iter()
            .map(|b| b.name.to_ascii_lowercase())
            .collect();
        let mut owners: Vec<String> = Vec::new();
        for r in &self.resolves {
            let name = r.name.to_ascii_lowercase();
            for (k, e) in self.cache.range((name.clone(), rtype::SRV, Vec::new())..) {
                if k.0 != name || k.1 != rtype::SRV {
                    break;
                }
                if let RData::Srv { target, .. } = &e.record.data {
                    owners.push(target.to_ascii_lowercase());
                }
            }
            owners.push(name);
        }
        move |k: &Key| match k.1 {
            rtype::PTR => browsed.contains(&k.0),
            rtype::SRV | rtype::TXT | rtype::A | rtype::AAAA => owners.contains(&k.0),
            _ => false,
        }
    }

    /// The refresh time for the `n`th refresh (0 to 3) of a record received at `received` with
    /// `ttl` seconds: 80, 85, 90 or 95 % of the TTL, plus 0 to 2 %.
    fn refresh_at(&mut self, received: u64, ttl: u32, n: u8) -> Option<u64> {
        if n >= 4 || ttl == 0 {
            return None;
        }
        let ttl_ns = u64::from(ttl) * SECOND;
        let percent = 80 + 5 * u64::from(n);
        let jitter = self.random() % 201; // hundredths of a percent, 0 to 2 %
        Some(received + ttl_ns * percent / 100 + ttl_ns * jitter / 10_000)
    }

    /// Takes one datagram received at `now` (any mDNS message; queries are ignored) and returns
    /// what changed.
    pub fn on_message(&mut self, now: u64, payload: &[u8]) -> Vec<Event> {
        let Ok(m) = Message::parse(payload) else {
            return Vec::new();
        };
        if !m.is_response() || m.opcode() != 0 || m.rcode() != 0 {
            return Vec::new();
        }
        let mut events = Vec::new();
        for r in m.answers.iter().chain(&m.additionals) {
            if r.class & !MDNS_CLASS_BIT != CLASS_IN {
                continue;
            }
            self.take(now, r, &mut events);
        }
        events.extend(self.check_resolves(now));
        events
    }

    fn browsed_type(&self, owner: &str) -> Option<&Browse> {
        self.browses.iter().find(|b| dns::same_name(&b.name, owner))
    }

    fn take(&mut self, now: u64, r: &Record, events: &mut Vec<Event>) {
        let k = key(r);
        if r.ttl == 0 {
            // A goodbye: gone in one second (§10.1).
            if let Some(e) = self.cache.get_mut(&k) {
                e.expires = e.expires.min(now + SECOND);
                e.goodbye = true;
                e.next_refresh = None;
            }
            return;
        }
        if r.cache_flush() {
            // §10.2: the others of this name and type, older than a second, go in a second.
            for (other, e) in self.cache.iter_mut() {
                if other.0 == k.0 && other.1 == k.1 && *other != k && e.received + SECOND < now {
                    e.expires = e.expires.min(now + SECOND);
                    e.next_refresh = None;
                }
            }
        }
        let new = !self.cache.contains_key(&k);
        if new && self.cache.len() >= MAX_RECORDS {
            return;
        }
        let next_refresh = self.refresh_at(now, r.ttl, 0);
        let mut record = r.clone();
        record.class &= !MDNS_CLASS_BIT;
        self.cache.insert(
            k,
            Entry {
                record,
                received: now,
                expires: now + u64::from(r.ttl) * SECOND,
                refreshes: 0,
                next_refresh,
                goodbye: false,
            },
        );
        if new
            && r.rtype == rtype::PTR
            && let RData::Ptr(name) = &r.data
            && let Some(b) = self.browsed_type(&r.name)
        {
            let (instance, _) = dns::split_instance(name);
            events.push(Event::Found {
                service_type: b.service_type.clone(),
                instance,
                name: name.clone(),
            });
        }
    }

    /// What the cache says about `name` now, if it is complete.
    fn resolved(&self, name: &str) -> Option<Resolved> {
        let owner = name.to_ascii_lowercase();
        let of_type = |t: u16| {
            let o = owner.clone();
            self.cache
                .range((owner.clone(), t, Vec::new())..)
                .take_while(move |(k, _)| k.0 == o && k.1 == t)
                .map(|(_, e)| &e.record.data)
        };
        let (target, port) = of_type(rtype::SRV).find_map(|d| match d {
            RData::Srv { target, port, .. } => Some((target.clone(), *port)),
            _ => None,
        })?;
        let txt = of_type(rtype::TXT).find_map(|d| match d {
            RData::Txt(t) => Some(t.clone()),
            _ => None,
        })?;
        let host = target.to_ascii_lowercase();
        let mut addresses: Vec<IpAddr> = self
            .cache
            .range((host.clone(), 0, Vec::new())..)
            .take_while(|(k, _)| k.0 == host)
            .filter_map(|(_, e)| match e.record.data {
                RData::A(a) => Some(IpAddr::V4(a)),
                RData::Aaaa(a) => Some(IpAddr::V6(a)),
                _ => None,
            })
            .collect();
        addresses.sort();
        if addresses.is_empty() {
            return None;
        }
        Some(Resolved {
            name: name.to_owned(),
            instance: dns::split_instance(name).0,
            host: target,
            port,
            txt,
            addresses,
        })
    }

    /// Reports resolutions that are complete or changed; re-arms queries for those that are
    /// incomplete again.
    fn check_resolves(&mut self, now: u64) -> Vec<Event> {
        let mut events = Vec::new();
        for i in 0..self.resolves.len() {
            let now_resolved = self.resolved(&self.resolves[i].name);
            let r = &mut self.resolves[i];
            match now_resolved {
                Some(res) => {
                    r.next_at = None;
                    r.interval = SECOND;
                    if r.last.as_ref() != Some(&res) {
                        r.last = Some(res.clone());
                        events.push(Event::Resolved(res));
                    }
                }
                None if r.next_at.is_none() => {
                    r.next_at = Some(now);
                    r.interval = SECOND;
                }
                None => {}
            }
        }
        events
    }

    /// Runs the timers at `now`: expiries (and their events) and the queries due, at most one
    /// message (to send to each group the app listens on).
    pub fn tick(&mut self, now: u64) -> (Vec<Message>, Vec<Event>) {
        let mut events = Vec::new();
        // Expiries.
        let gone: Vec<Key> = self
            .cache
            .iter()
            .filter(|(_, e)| e.expires <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for k in gone {
            let Some(e) = self.cache.remove(&k) else {
                continue;
            };
            if let RData::Ptr(name) = &e.record.data
                && let Some(b) = self.browsed_type(&e.record.name)
            {
                events.push(Event::Removed {
                    service_type: b.service_type.clone(),
                    instance: dns::split_instance(name).0,
                    name: name.clone(),
                    reason: if e.goodbye {
                        Removal::Goodbye
                    } else {
                        Removal::Expired
                    },
                });
            }
        }
        events.extend(self.check_resolves(now));

        let mut q = Message::default();
        let ask = |q: &mut Message, name: &str, t: u16| {
            if !q
                .questions
                .iter()
                .any(|o| o.qtype == t && dns::same_name(&o.name, name))
            {
                q.questions.push(question(name, t));
            }
        };
        // Browsing.
        for i in 0..self.browses.len() {
            let b = &mut self.browses[i];
            if b.next_at <= now {
                ask(&mut q, &b.name, rtype::PTR);
                b.next_at = now + b.interval;
                b.interval = (b.interval * 2).min(MAX_INTERVAL_NS);
            }
        }
        // Resolving what is missing.
        for i in 0..self.resolves.len() {
            let Some(at) = self.resolves[i].next_at else {
                continue;
            };
            if at > now {
                continue;
            }
            let name = self.resolves[i].name.clone();
            let owner = name.to_ascii_lowercase();
            let has = |t: u16| {
                self.cache
                    .range((owner.clone(), t, Vec::new())..)
                    .next()
                    .is_some_and(|(k, _)| k.0 == owner && k.1 == t)
            };
            let (has_srv, has_txt) = (has(rtype::SRV), has(rtype::TXT));
            if !has_srv {
                ask(&mut q, &name, rtype::SRV);
            }
            if !has_txt {
                ask(&mut q, &name, rtype::TXT);
            }
            if has_srv {
                let targets: Vec<String> = self
                    .cache
                    .range((owner.clone(), rtype::SRV, Vec::new())..)
                    .take_while(|(k, _)| k.0 == owner && k.1 == rtype::SRV)
                    .filter_map(|(_, e)| match &e.record.data {
                        RData::Srv { target, .. } => Some(target.clone()),
                        _ => None,
                    })
                    .collect();
                for t in targets {
                    ask(&mut q, &t, rtype::A);
                    ask(&mut q, &t, rtype::AAAA);
                }
            }
            let r = &mut self.resolves[i];
            r.next_at = Some(now + r.interval);
            r.interval = (r.interval * 2).min(MAX_INTERVAL_NS);
        }
        // Refreshing what is still needed.
        let interest = self.interest();
        let due: Vec<Key> = self
            .cache
            .iter()
            .filter(|(k, e)| e.next_refresh.is_some_and(|t| t <= now) && interest(k))
            .map(|(k, _)| k.clone())
            .collect();
        drop(interest);
        for k in due {
            let (name, t, received, ttl, n) = {
                let e = &self.cache[&k];
                (
                    e.record.name.clone(),
                    e.record.rtype,
                    e.received,
                    e.record.ttl,
                    e.refreshes + 1,
                )
            };
            ask(&mut q, &name, t);
            let next = self.refresh_at(received, ttl, n);
            if let Some(e) = self.cache.get_mut(&k) {
                e.refreshes = n;
                e.next_refresh = next;
            }
        }
        if q.questions.is_empty() {
            return (Vec::new(), events);
        }
        // Known answers (§7.1): PTRs we hold with more than half their TTL left.
        for question in &q.questions {
            if question.qtype != rtype::PTR {
                continue;
            }
            let owner = question.name.to_ascii_lowercase();
            for (k, e) in self.cache.range((owner.clone(), rtype::PTR, Vec::new())..) {
                if k.0 != owner || k.1 != rtype::PTR {
                    break;
                }
                let left = e.expires.saturating_sub(now);
                if e.goodbye || left * 2 <= u64::from(e.record.ttl) * SECOND {
                    continue;
                }
                let mut known = e.record.clone();
                known.ttl = u32::try_from(left / SECOND).unwrap_or(u32::MAX);
                q.answers.push(known);
            }
        }
        (vec![q], events)
    }
}

#[cfg(test)]
mod tests;
