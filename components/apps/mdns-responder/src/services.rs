//! DNS-SD (RFC 6763) on the responder: the services in its config, advertised over Multicast
//! DNS next to the host name.
//!
//! Each service is an instance name (`Alpha Web`), a service type (`_http._tcp`), a port and
//! TXT attributes. Its records, all in `.local`:
//!
//! | owner | type | data | kind | TTL |
//! |---|---|---|---|---|
//! | `_services._dns-sd._udp.local` | PTR | `_http._tcp.local` | shared | `service-ttl` |
//! | `_http._tcp.local` | PTR | `Alpha Web._http._tcp.local` | shared | `service-ttl` |
//! | `Alpha Web._http._tcp.local` | SRV | `0 0 80 <hostname>.local` | unique | `ttl` |
//! | `Alpha Web._http._tcp.local` | TXT | `path=/` ... | unique | `service-ttl` |
//!
//! # Behaviour
//!
//! * **Waiting for the host name.** A service's SRV names the host, so a service starts once the
//!   host name went out in its first announcement. If the host name is lost to a conflict later,
//!   its services wait again, and probe and announce once the new name is claimed.
//! * **Probing** (RFC 6762 §8.1): three queries 250 ms apart, after a delay of 0–249 ms derived
//!   from the instance's full name (like the host name's). Each holds a question for every
//!   service probing at that step (type ANY, the first with the QU bit) and the proposed SRV and
//!   TXT records in the authority section.
//! * **Simultaneous probes** (§8.2): another host's probe for the same instance name (its
//!   authority section holds records for it) is a tiebreak over the sorted SRV and TXT records;
//!   the loser probes again one second later.
//! * **Conflicts** (§9): a response with an SRV or TXT record for the instance name whose data
//!   differs from ours (and whose TTL is not zero) renames the service: `Alpha Web (2)`,
//!   `Alpha Web (3)`, ... (RFC 6763 §4.1 leaves the form to the host; this is the usual one),
//!   and it probes again at once. That holds while probing and after.
//! * **Announcing** (§8.3): two responses one second apart with the four records above
//!   (cache-flush bit on SRV and TXT), the host's addresses as additional records, and, when the
//!   host has no address of one family, an NSEC for the host name that says so (§6.1).
//! * **Answering** (§6) questions of class IN or ANY, once a service has begun announcing:
//!   - `_services._dns-sd._udp.local` PTR (or ANY): one PTR per service type;
//!   - `<type>.local` PTR (or ANY): one PTR per instance of that type, with each instance's SRV
//!     and TXT and the host's addresses as additional records (RFC 6763 §12.1);
//!   - the instance name, SRV, TXT or ANY: those records, the host's addresses as additional
//!     records (§12.2); any other type: an NSEC that lists SRV and TXT (§6.1).
//!
//!   Known answers in the query with at least half our TTL left are left out (§7.1). A one-shot
//!   querier (a source port other than 5353) gets a unicast answer with its id and questions and
//!   TTLs of at most 10 s, without cache-flush bits (§6.7); a question with the QU bit, a unicast
//!   answer (§5.4); everything else goes to the group, an answer holding a shared record (a PTR)
//!   20–120 ms later (§6), the delay derived from the host name, the time and the querier.
//! * **Goodbye** (§10.1): at its `until` time a service sends its records once more with TTL 0
//!   (the `_services._dns-sd._udp` PTR too, when no other service of its type is left) and stops
//!   answering for them.
//!
//! Not done: subtypes (§7.1 of RFC 6763), unicast DNS-SD domains, duplicate answer suppression
//! (§7.4), a known-answer list spread over several packets (§7.2), and announcing again when a
//! TXT record changes (services are fixed by the config).
//!
//! # Journal
//!
//! `mdns-service-probing {instance, type, attempt}`, `mdns-service-probe-lost {instance, from}`,
//! `mdns-service-conflict {instance, from}`, `mdns-service-renamed {from, to}`,
//! `mdns-service-announced {instance, type, port, target}`, `mdns-service-withdrawn {instance,
//! type}`, and `mdns-answered {name, types, to, mode}` as for the host name (`name` lists the
//! names answered).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use wasmnet_wire::dns::{
    self, CLASS_IN, DNS_SD_SERVICES, MDNS_CLASS_BIT, MDNS_PORT, Message, Question, RData, Record,
    TxtPair, rtype,
};
use wasmnet_wire::parse_duration;

use crate::{
    ANNOUNCE_INTERVAL_NS, ANNOUNCEMENTS, ConfigError, Dest, LEGACY_TTL, MS, Note,
    PROBE_INTERVAL_NS, PROBES, Packet, Responder, TIEBREAK_DEFER_NS, fnv, kv, order_key,
};

/// One service from the config (`service.<id>.*`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceConfig {
    /// The `<id>` in its keys: it orders the services and names none of their records.
    pub id: String,
    /// The instance name as configured, unescaped (`Alpha Web`).
    pub instance: String,
    /// `_http._tcp`.
    pub service_type: String,
    pub port: u16,
    /// The TXT attributes, in order; none is one empty string on the wire.
    pub txt: Vec<TxtPair>,
    /// When to withdraw it, virtual time (the glue adds the app's start).
    pub until_ns: Option<u64>,
}

/// The service keys as they come, grouped by id.
#[derive(Default)]
pub(crate) struct Partial {
    by_id: BTreeMap<String, BTreeMap<String, (String, String)>>,
}

fn invalid(key: &str, value: &str, expected: &'static str) -> ConfigError {
    ConfigError::Invalid {
        key: key.to_owned(),
        value: value.to_owned(),
        expected,
    }
}

/// Splits a TXT list at commas that are not escaped (`\,` is a comma, `\\` a backslash), each
/// item trimmed.
pub(crate) fn split_txt(value: &str) -> Vec<String> {
    let mut items = vec![String::new()];
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(next @ (',' | '\\')) => items.last_mut().unwrap().push(next),
                Some(other) => {
                    let item = items.last_mut().unwrap();
                    item.push('\\');
                    item.push(other);
                }
                None => items.last_mut().unwrap().push('\\'),
            },
            ',' => items.push(String::new()),
            c => items.last_mut().unwrap().push(c),
        }
    }
    items.into_iter().map(|i| i.trim().to_owned()).collect()
}

impl Partial {
    /// Takes `service.<id>.<field>` (`rest` is `<id>.<field>`).
    pub(crate) fn add(&mut self, key: &str, rest: &str, value: &str) -> Result<(), ConfigError> {
        let Some((id, field)) = rest.split_once('.') else {
            return Err(ConfigError::Unknown { key: key.into() });
        };
        if id.is_empty() || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return Err(ConfigError::Unknown { key: key.into() });
        }
        if !["instance", "type", "port", "txt", "until"].contains(&field) {
            return Err(ConfigError::Unknown { key: key.into() });
        }
        self.by_id
            .entry(id.to_owned())
            .or_default()
            .insert(field.to_owned(), (key.to_owned(), value.to_owned()));
        Ok(())
    }

    /// Checks every service, in id order.
    pub(crate) fn finish(self) -> Result<Vec<ServiceConfig>, ConfigError> {
        let mut out: Vec<ServiceConfig> = Vec::new();
        for (id, fields) in self.by_id {
            let required = |field: &str, expected: &'static str| {
                fields.get(field).ok_or_else(|| ConfigError::Missing {
                    key: format!("service.{id}.{field}"),
                    expected,
                })
            };
            let (k, v) = required("instance", "an instance name, like My Web")?;
            if !dns::valid_instance(v) {
                return Err(invalid(
                    k,
                    v,
                    "1 to 63 bytes of UTF-8, no control characters",
                ));
            }
            let instance = v.clone();
            let (k, v) = required("type", "a service type, like _http._tcp")?;
            if !dns::valid_service_type(v) {
                return Err(invalid(k, v, "_<name>._tcp or _<name>._udp"));
            }
            let service_type = v.to_ascii_lowercase();
            let (k, v) = required("port", "the service's port")?;
            let port = v
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| invalid(k, v, "a port, 1 to 65535"))?;
            let mut txt: Vec<TxtPair> = Vec::new();
            if let Some((k, v)) = fields.get("txt") {
                let expected = "key or key=value items, keys of printable ASCII without =, \
                                at most 255 bytes each, no key twice";
                for item in split_txt(v) {
                    let (key, value) = match item.split_once('=') {
                        Some((key, value)) => (key, Some(value.as_bytes().to_vec())),
                        None => (item.as_str(), None),
                    };
                    let repeated = txt.iter().any(|(k2, _)| k2.eq_ignore_ascii_case(key));
                    if !dns::valid_txt_key(key) || item.len() > 255 || repeated {
                        return Err(invalid(k, v, expected));
                    }
                    txt.push((key.to_owned(), value));
                }
            }
            let until_ns = match fields.get("until") {
                Some((k, v)) => Some(parse_duration(v).ok_or_else(|| invalid(k, v, "a duration"))?),
                None => None,
            };
            if out.iter().any(|s| {
                s.instance.eq_ignore_ascii_case(&instance) && s.service_type == service_type
            }) {
                return Err(invalid(
                    &format!("service.{id}.instance"),
                    &instance,
                    "an instance name no other service of this type has",
                ));
            }
            out.push(ServiceConfig {
                id,
                instance,
                service_type,
                port,
                txt,
                until_ns,
            });
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SvcState {
    /// Until the host name is claimed.
    Waiting,
    Probing {
        n: u32,
        at: u64,
    },
    Announcing {
        n: u32,
        at: u64,
    },
    Ready,
    Withdrawn,
}

/// One service and where it is.
#[derive(Debug)]
pub(crate) struct Service {
    config: ServiceConfig,
    /// The instance name now (`Alpha Web (2)` after a conflict), unescaped.
    instance: String,
    renames: u32,
    state: SvcState,
    /// Its records went out: a withdrawal sends goodbyes.
    announced: bool,
}

impl Service {
    pub(crate) fn new(config: ServiceConfig) -> Self {
        Self {
            instance: config.instance.clone(),
            config,
            renames: 0,
            state: SvcState::Waiting,
            announced: false,
        }
    }

    /// The instance's full name, `Alpha Web._http._tcp.local`.
    fn name(&self) -> String {
        dns::instance_name(&self.instance, &self.config.service_type, "local")
    }

    /// `_http._tcp.local`.
    fn type_name(&self) -> String {
        format!("{}.local", self.config.service_type)
    }

    /// Answers for its records: it began announcing and was not withdrawn.
    fn live(&self) -> bool {
        matches!(self.state, SvcState::Announcing { .. } | SvcState::Ready)
    }

    fn deadline(&self) -> Option<u64> {
        let timer = match self.state {
            SvcState::Probing { at, .. } | SvcState::Announcing { at, .. } => Some(at),
            _ => None,
        };
        let until = self
            .config
            .until_ns
            .filter(|_| self.state != SvcState::Withdrawn);
        [timer, until].into_iter().flatten().min()
    }

    /// The next name after a conflict: `<instance> (<n>)`, the configured name shortened (at a
    /// character boundary) so that the whole stays within 63 bytes.
    fn rename(&mut self) -> String {
        self.renames += 1;
        let suffix = format!(" ({})", self.renames + 1);
        let mut base = self.config.instance.as_str();
        while base.len() + suffix.len() > 63 {
            let mut cut = base.len() - 1;
            while !base.is_char_boundary(cut) {
                cut -= 1;
            }
            base = &base[..cut];
        }
        std::mem::replace(&mut self.instance, format!("{base}{suffix}"))
    }
}

/// Answer `r` was already known to the querier with at least half its TTL left (§7.1).
fn known(m: &Message, r: &Record) -> bool {
    m.answers.iter().any(|k| {
        dns::same_name(&k.name, &r.name)
            && k.rtype == r.rtype
            && k.data == r.data
            && k.ttl >= r.ttl / 2
    })
}

fn push_unique(list: &mut Vec<Record>, r: Record) {
    if !list
        .iter()
        .any(|o| dns::same_name(&o.name, &r.name) && o.rtype == r.rtype && o.data == r.data)
    {
        list.push(r);
    }
}

impl Responder {
    /// The earliest timer of the services and held answers.
    pub(crate) fn services_deadline(&self) -> Option<u64> {
        self.services
            .iter()
            .filter_map(Service::deadline)
            .chain(self.pending.iter().map(|(at, _)| *at))
            .min()
    }

    /// The host name was lost (a conflict): services that started wait for the next name.
    pub(crate) fn host_lost(&mut self) {
        self.claimed = false;
        for s in &mut self.services {
            if !matches!(s.state, SvcState::Withdrawn) {
                s.state = SvcState::Waiting;
            }
        }
    }

    /// The instance names this responder advertises now, unescaped: `(instance, type)`.
    pub fn service_instances(&self) -> Vec<(String, String)> {
        self.services
            .iter()
            .filter(|s| s.state != SvcState::Withdrawn)
            .map(|s| (s.instance.clone(), s.config.service_type.clone()))
            .collect()
    }

    /// Every service is announced (or withdrawn).
    pub fn services_ready(&self) -> bool {
        self.services
            .iter()
            .all(|s| matches!(s.state, SvcState::Ready | SvcState::Withdrawn))
    }

    fn class(flush: bool) -> u16 {
        if flush {
            CLASS_IN | MDNS_CLASS_BIT
        } else {
            CLASS_IN
        }
    }

    fn ptr(&self, s: &Service, ttl: u32) -> Record {
        Record {
            name: s.type_name(),
            rtype: rtype::PTR,
            class: CLASS_IN,
            ttl,
            data: RData::Ptr(s.name()),
        }
    }

    fn meta_ptr(service_type: &str, ttl: u32) -> Record {
        Record {
            name: DNS_SD_SERVICES.into(),
            rtype: rtype::PTR,
            class: CLASS_IN,
            ttl,
            data: RData::Ptr(format!("{service_type}.local")),
        }
    }

    fn srv(&self, s: &Service, ttl: u32, flush: bool) -> Record {
        Record {
            name: s.name(),
            rtype: rtype::SRV,
            class: Self::class(flush),
            ttl,
            data: RData::Srv {
                priority: 0,
                weight: 0,
                port: s.config.port,
                target: self.name.clone(),
            },
        }
    }

    fn txt(&self, s: &Service, ttl: u32, flush: bool) -> Record {
        Record {
            name: s.name(),
            rtype: rtype::TXT,
            class: Self::class(flush),
            ttl,
            data: RData::Txt(dns::txt_strings(&s.config.txt)),
        }
    }

    fn nsec(name: String, types: Vec<u16>, ttl: u32, flush: bool) -> Record {
        Record {
            name: name.clone(),
            rtype: rtype::NSEC,
            class: Self::class(flush),
            ttl,
            data: RData::Nsec { next: name, types },
        }
    }

    /// The host's addresses as additional records, and an NSEC for the host name when it has
    /// no address of one family (RFC 6762 §6.1, RFC 6763 §12).
    fn host_additionals(&self, usable: &[IpAddr], ttl: u32, flush: bool) -> Vec<Record> {
        let mut out = self.records(usable, ttl, flush, &[rtype::A, rtype::AAAA]);
        let mut types: Vec<u16> = out.iter().map(|r| r.rtype).collect();
        types.sort_unstable();
        types.dedup();
        if types.len() == 1 {
            out.push(Self::nsec(self.name.clone(), types, ttl, flush));
        }
        out
    }

    /// The services' timers: start, probe, announce, withdraw, and held answers.
    pub(crate) fn services_tick(
        &mut self,
        now: u64,
        usable: &[IpAddr],
        out: &mut Vec<Packet>,
        notes: &mut Vec<Note>,
    ) {
        if self.services.is_empty() {
            return;
        }
        let (ttl, service_ttl) = (self.config.ttl, self.config.service_ttl);

        // Withdrawals: goodbyes for what was announced.
        let mut goodbye = Message {
            flags: 0x8400,
            ..Message::default()
        };
        for i in 0..self.services.len() {
            let s = &self.services[i];
            if s.state == SvcState::Withdrawn || s.config.until_ns.is_none_or(|t| t > now) {
                continue;
            }
            if s.announced {
                goodbye.answers.push(self.ptr(s, 0));
                goodbye.answers.push(self.srv(s, 0, true));
                goodbye.answers.push(self.txt(s, 0, true));
            }
            let (announced, ty) = (s.announced, s.config.service_type.clone());
            notes.push((
                "mdns-service-withdrawn",
                vec![kv("instance", &s.instance), kv("type", &ty)],
            ));
            self.services[i].state = SvcState::Withdrawn;
            let others = self.services.iter().any(|o| {
                o.config.service_type == ty && o.state != SvcState::Withdrawn && o.announced
            });
            if announced && !others {
                goodbye.answers.push(Self::meta_ptr(&ty, 0));
            }
        }
        if !goodbye.answers.is_empty() {
            for to in self.groups() {
                out.push(Packet {
                    to,
                    message: goodbye.clone(),
                });
            }
        }

        // The host name is claimed: waiting services start probing.
        if self.claimed {
            for s in &mut self.services {
                if s.state == SvcState::Waiting {
                    let delay = (fnv(&s.name()) % 250) * MS;
                    s.state = SvcState::Probing {
                        n: 0,
                        at: now + delay,
                    };
                }
            }
        }

        // Probes due now, in one query.
        let mut probe = Message::default();
        for i in 0..self.services.len() {
            let SvcState::Probing { n, at } = self.services[i].state else {
                continue;
            };
            if at > now {
                continue;
            }
            let s = &self.services[i];
            if n == 0 {
                notes.push((
                    "mdns-service-probing",
                    vec![
                        kv("instance", &s.instance),
                        kv("type", &s.config.service_type),
                        kv("attempt", s.renames + 1),
                    ],
                ));
            }
            probe.questions.push(Question {
                name: s.name(),
                qtype: rtype::ANY,
                qclass: if n == 0 {
                    CLASS_IN | MDNS_CLASS_BIT
                } else {
                    CLASS_IN
                },
            });
            probe.authorities.push(self.srv(s, ttl, false));
            probe.authorities.push(self.txt(s, service_ttl, false));
            self.services[i].state = if n + 1 < PROBES {
                SvcState::Probing {
                    n: n + 1,
                    at: now + PROBE_INTERVAL_NS,
                }
            } else {
                SvcState::Announcing {
                    n: 0,
                    at: now + PROBE_INTERVAL_NS,
                }
            };
        }
        if !probe.questions.is_empty() {
            for to in self.groups() {
                out.push(Packet {
                    to,
                    message: probe.clone(),
                });
            }
        }

        // Announcements due now, in one response.
        let mut announce = Message {
            flags: 0x8400,
            ..Message::default()
        };
        for i in 0..self.services.len() {
            let SvcState::Announcing { n, at } = self.services[i].state else {
                continue;
            };
            if at > now {
                continue;
            }
            let s = &self.services[i];
            push_unique(&mut announce.answers, self.ptr(s, service_ttl));
            push_unique(
                &mut announce.answers,
                Self::meta_ptr(&s.config.service_type, service_ttl),
            );
            announce.answers.push(self.srv(s, ttl, true));
            announce.answers.push(self.txt(s, service_ttl, true));
            if n == 0 {
                notes.push((
                    "mdns-service-announced",
                    vec![
                        kv("instance", &s.instance),
                        kv("type", &s.config.service_type),
                        kv("port", s.config.port),
                        kv("target", &self.name),
                    ],
                ));
            }
            let s = &mut self.services[i];
            s.announced = true;
            s.state = if n + 1 < ANNOUNCEMENTS {
                SvcState::Announcing {
                    n: n + 1,
                    at: now + ANNOUNCE_INTERVAL_NS,
                }
            } else {
                SvcState::Ready
            };
        }
        if !announce.answers.is_empty() {
            announce.additionals = self.host_additionals(usable, ttl, true);
            for to in self.groups() {
                out.push(Packet {
                    to,
                    message: announce.clone(),
                });
            }
        }

        // Held answers whose time came, in the order they were held.
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|(at, _)| *at <= now);
        self.pending = later;
        out.extend(due.into_iter().map(|(_, p)| p));
    }

    /// Renames service `i` after a conflict and probes again at once.
    fn service_conflict(&mut self, i: usize, now: u64, from: SocketAddr, notes: &mut Vec<Note>) {
        let s = &mut self.services[i];
        notes.push((
            "mdns-service-conflict",
            vec![kv("instance", &s.instance), kv("from", from.ip())],
        ));
        let old = s.rename();
        notes.push((
            "mdns-service-renamed",
            vec![kv("from", old), kv("to", &s.instance)],
        ));
        s.announced = false;
        s.state = if self.claimed {
            SvcState::Probing { n: 0, at: now }
        } else {
            SvcState::Waiting
        };
    }

    /// The services' part of a message: conflicts, tiebreaks and answers.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn services_on_message(
        &mut self,
        now: u64,
        from: SocketAddr,
        v6: bool,
        m: &Message,
        usable: &[IpAddr],
        out: &mut Vec<Packet>,
        notes: &mut Vec<Note>,
    ) {
        if self.services.is_empty() {
            return;
        }
        let (ttl, service_ttl) = (self.config.ttl, self.config.service_ttl);
        if m.is_response() {
            for i in 0..self.services.len() {
                let s = &self.services[i];
                if matches!(s.state, SvcState::Waiting | SvcState::Withdrawn) {
                    continue;
                }
                let name = s.name();
                let mine = [self.srv(s, ttl, false), self.txt(s, service_ttl, false)];
                let conflicting = m.answers.iter().chain(&m.additionals).any(|r| {
                    dns::same_name(&r.name, &name)
                        && r.ttl > 0
                        && (r.rtype == rtype::SRV || r.rtype == rtype::TXT)
                        && !mine.iter().any(|o| o.rtype == r.rtype && o.data == r.data)
                });
                if conflicting {
                    self.service_conflict(i, now, from, notes);
                }
            }
            return;
        }

        // Another host probing for a name we probe for: the tiebreak (§8.2).
        for i in 0..self.services.len() {
            let s = &self.services[i];
            if !matches!(s.state, SvcState::Probing { .. }) {
                continue;
            }
            let name = s.name();
            let probe_for_it = m.questions.iter().any(|q| dns::same_name(&q.name, &name));
            let mut theirs: Vec<_> = m
                .authorities
                .iter()
                .filter(|r| dns::same_name(&r.name, &name))
                .map(order_key)
                .collect();
            if !probe_for_it || theirs.is_empty() {
                continue;
            }
            let mut mine: Vec<_> = [self.srv(s, ttl, false), self.txt(s, service_ttl, false)]
                .iter()
                .map(order_key)
                .collect();
            mine.sort();
            theirs.sort();
            if mine < theirs {
                notes.push((
                    "mdns-service-probe-lost",
                    vec![kv("instance", &s.instance), kv("from", from.ip())],
                ));
                self.services[i].state = SvcState::Probing {
                    n: 0,
                    at: now + TIEBREAK_DEFER_NS,
                };
            }
        }

        // Questions about live services.
        let legacy = from.port() != MDNS_PORT;
        let cap = |t: u32| if legacy { t.min(LEGACY_TTL) } else { t };
        let flush = !legacy;
        let mut answers: Vec<Record> = Vec::new();
        let mut additionals: Vec<Record> = Vec::new();
        let mut asked: Vec<Question> = Vec::new();
        let mut with_host = false;
        for q in &m.questions {
            if q.class() != CLASS_IN && q.class() != 255 {
                continue;
            }
            let ptr_or_any = q.qtype == rtype::PTR || q.qtype == rtype::ANY;
            let before = answers.len();
            if dns::same_name(&q.name, DNS_SD_SERVICES) && ptr_or_any {
                for s in self.services.iter().filter(|s| s.live()) {
                    push_unique(
                        &mut answers,
                        Self::meta_ptr(&s.config.service_type, cap(service_ttl)),
                    );
                }
            }
            for s in self.services.iter().filter(|s| s.live()) {
                if dns::same_name(&q.name, &s.type_name()) && ptr_or_any {
                    push_unique(&mut answers, self.ptr(s, cap(service_ttl)));
                    push_unique(&mut additionals, self.srv(s, cap(ttl), flush));
                    push_unique(&mut additionals, self.txt(s, cap(service_ttl), flush));
                    with_host = true;
                }
                if dns::same_name(&q.name, &s.name()) {
                    match q.qtype {
                        rtype::SRV => {
                            answers.push(self.srv(s, cap(ttl), flush));
                            with_host = true;
                        }
                        rtype::TXT => answers.push(self.txt(s, cap(service_ttl), flush)),
                        rtype::ANY => {
                            answers.push(self.srv(s, cap(ttl), flush));
                            answers.push(self.txt(s, cap(service_ttl), flush));
                            with_host = true;
                        }
                        _ => answers.push(Self::nsec(
                            s.name(),
                            vec![rtype::TXT, rtype::SRV],
                            cap(ttl),
                            flush,
                        )),
                    }
                }
            }
            if answers.len() > before {
                asked.push(q.clone());
            }
        }
        answers.retain(|r| !known(m, r));
        if answers.is_empty() {
            return;
        }
        if with_host {
            for r in self.host_additionals(usable, cap(ttl), flush) {
                push_unique(&mut additionals, r);
            }
        }
        additionals.retain(|r| {
            !answers
                .iter()
                .any(|a| dns::same_name(&a.name, &r.name) && a.rtype == r.rtype && a.data == r.data)
        });
        let shared = answers.iter().any(|r| r.rtype == rtype::PTR);
        let mut r = Message {
            flags: 0x8400, // QR, AA
            answers,
            additionals,
            ..Message::default()
        };
        let mut names: Vec<String> = asked.iter().map(|q| q.name.clone()).collect();
        names.dedup();
        let mut types: Vec<String> = r.answers.iter().map(|a| dns::type_name(a.rtype)).collect();
        types.dedup();
        let (to, mode, at) = if legacy {
            r.id = m.id;
            r.questions = asked
                .iter()
                .map(|q| Question {
                    qclass: q.qclass & !MDNS_CLASS_BIT,
                    ..q.clone()
                })
                .collect();
            (Dest::Unicast(from), "legacy-unicast", now)
        } else if asked.iter().any(Question::unicast_response) {
            (Dest::Unicast(from), "unicast", now)
        } else if shared {
            let delay = 20 + fnv(&format!("{} {now} {from}", self.name)) % 101;
            (Dest::Group { v6 }, "multicast", now + delay * MS)
        } else {
            (Dest::Group { v6 }, "multicast", now)
        };
        notes.push((
            "mdns-answered",
            vec![
                kv("name", names.join(",")),
                kv("types", types.join(",")),
                kv("to", from),
                kv("mode", mode),
            ],
        ));
        let packet = Packet { to, message: r };
        if at > now {
            self.pending.push((at, packet));
        } else {
            out.push(packet);
        }
    }

    /// For tests: whether a service with this instance name is announced or ready.
    #[cfg(test)]
    pub(crate) fn service_live(&self, instance: &str) -> bool {
        self.services
            .iter()
            .any(|s| s.instance == instance && s.live())
    }
}
