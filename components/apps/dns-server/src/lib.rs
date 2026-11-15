//! dns-server: an authoritative DNS server (RFC 1035) for static zones, as a wasmnet app.
//! It answers queries over UDP from the records in its config and never returns: a daemon.
//! It does not recurse: a name outside its zones is `REFUSED`.
//!
//! # Config (`wasi:config`, keys under `app.dns-server.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `listen` | the local socket address, `0.0.0.0:53` or `[::]:53` | `0.0.0.0:53` |
//! | `zone` | the zones it is authoritative for, one name or a list (`internal`) | required |
//! | `records.<name>` | the name's addresses, one or a list (`10.0.1.10,fd00:1::10`): A and AAAA records | none |
//! | `cname.<name>` | the name is an alias of another (a CNAME record) | none |
//! | `ttl` | the TTL of every record, whole seconds | `60s` |
//!
//! A `<name>` (or CNAME target) that is not inside a zone and does not end with a dot is relative
//! to the first zone: `records.web` is `web.internal`, while `cname.out = "example.com."` points
//! out of the zones. Names match case-insensitively.
//!
//! # Answers
//!
//! * A, AAAA, CNAME, SOA (at a zone's apex) and ANY queries. A CNAME is followed inside the
//!   zones (up to 8 links) and the chain goes into the answer section, as servers do.
//! * A name with no records at all is `NXDOMAIN`; a name with records of other types only is
//!   `NOERROR` with no answer (NODATA). Both carry the zone's SOA in the authority section (RFC
//!   2308), so a resolver knows how long to cache the negative answer. The SOA is synthetic:
//!   `ns.<zone> hostmaster.<zone> 1 3600 600 86400 <ttl>`.
//! * Every answer from a zone is authoritative (AA). RA is clear (no recursion).
//! * A name outside every zone is `REFUSED`; another opcode is `NOTIMP`; zero or several
//!   questions are `FORMERR`; a response (QR set) is ignored; garbage shorter than a header is
//!   dropped.
//!
//! # Journal
//!
//! `dns-server-listening {address, zones, records}`, then per query `dns-served {from, id, name,
//! type, rcode, answers}` (`answers`: the answer section's data, comma-separated).

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
pub use wasmnet_app_kit::app_pairs;

use wasmnet_wire::dns::{self, CLASS_IN, Message, RData, Record, rcode, rtype};
use wasmnet_wire::parse_duration;

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "dns-server";
/// CNAME links followed per answer.
const MAX_CHAIN: usize = 8;

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

/// The parsed config: zones and their records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    /// Lowercase, no trailing dot.
    pub zones: Vec<String>,
    pub ttl: u32,
    /// Lowercase owner name → its records' data, in config order.
    pub records: BTreeMap<String, Vec<RData>>,
}

fn normalize(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

fn in_zone(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

impl Config {
    /// Parses this app's pairs (prefix already stripped). Unknown keys are errors.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Self, ConfigError> {
        let mut listen = SocketAddr::from(([0, 0, 0, 0], dns::PORT));
        let mut zones = Vec::new();
        let mut ttl = 60;
        let mut raw: Vec<(String, String, String)> = Vec::new();
        for (key, value) in pairs {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            match key.as_str() {
                "listen" => {
                    listen = value
                        .parse()
                        .map_err(|_| invalid("a socket address like 0.0.0.0:53 or [::]:53"))?;
                }
                "zone" => {
                    for z in value.split(',').map(str::trim) {
                        if !dns::valid_name(z) {
                            return Err(invalid("domain names like internal"));
                        }
                        zones.push(normalize(z));
                    }
                }
                "ttl" => {
                    ttl = parse_duration(&value)
                        .filter(|ns| ns % 1_000_000_000 == 0)
                        .and_then(|ns| u32::try_from(ns / 1_000_000_000).ok())
                        .ok_or_else(|| invalid("whole seconds like 60s"))?;
                }
                _ => {
                    let (kind, name) = key
                        .split_once('.')
                        .filter(|(k, _)| *k == "records" || *k == "cname")
                        .ok_or_else(|| ConfigError::Unknown { key: key.clone() })?;
                    if !dns::valid_name(name) {
                        return Err(invalid("a record name of letters, digits, - and _"));
                    }
                    raw.push((kind.to_owned(), name.to_owned(), value.clone()));
                }
            }
        }
        if zones.is_empty() {
            return Err(ConfigError::Missing {
                key: "zone".into(),
                expected: "the zone(s) to serve, like internal",
            });
        }
        let qualify = |name: &str| {
            let n = normalize(name);
            if name.ends_with('.') || zones.iter().any(|z| in_zone(&n, z)) {
                n
            } else {
                format!("{n}.{}", zones[0])
            }
        };
        let mut records: BTreeMap<String, Vec<RData>> = BTreeMap::new();
        for (kind, name, value) in raw {
            let owner = qualify(&name);
            let key = format!("{kind}.{name}");
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            let entry = records.entry(owner).or_default();
            if kind == "cname" {
                if !dns::valid_name(&value) {
                    return Err(invalid("a name"));
                }
                entry.push(RData::Cname(qualify(&value)));
            } else {
                for a in value.split(',').map(str::trim) {
                    entry.push(match a.parse::<IpAddr>() {
                        Ok(IpAddr::V4(v4)) => RData::A(v4),
                        Ok(IpAddr::V6(v6)) => RData::Aaaa(v6),
                        Err(_) => return Err(invalid("IP addresses like 10.0.1.10,fd00:1::10")),
                    });
                }
            }
        }
        for (owner, data) in &records {
            let cnames = data.iter().filter(|d| matches!(d, RData::Cname(_))).count();
            if cnames > 0 && data.len() != 1 {
                return Err(ConfigError::Invalid {
                    key: format!("cname.{owner}"),
                    value: String::new(),
                    expected: "a CNAME to be the name's only record (RFC 1034 §3.6.2)",
                });
            }
        }
        Ok(Config {
            listen,
            zones,
            ttl,
            records,
        })
    }

    /// Records in all zones.
    pub fn record_count(&self) -> usize {
        self.records.values().map(Vec::len).sum()
    }
}

/// One journal event: kind and fields.
pub type Note = (&'static str, Vec<(String, String)>);

fn rtype_of(d: &RData) -> u16 {
    match d {
        RData::A(_) => rtype::A,
        RData::Aaaa(_) => rtype::AAAA,
        RData::Cname(_) => rtype::CNAME,
        RData::Ns(_) => rtype::NS,
        RData::Ptr(_) => rtype::PTR,
        RData::Soa { .. } => rtype::SOA,
        RData::Other(_) => 0,
    }
}

/// The authoritative server.
#[derive(Debug)]
pub struct Server {
    pub config: Config,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    fn soa(&self, zone: &str) -> Record {
        Record {
            name: zone.to_owned(),
            rtype: rtype::SOA,
            class: CLASS_IN,
            ttl: self.config.ttl,
            data: RData::Soa {
                mname: format!("ns.{zone}"),
                rname: format!("hostmaster.{zone}"),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86400,
                minimum: self.config.ttl,
            },
        }
    }

    /// The longest zone that holds `name`.
    fn zone_of(&self, name: &str) -> Option<&str> {
        self.config
            .zones
            .iter()
            .filter(|z| in_zone(name, z))
            .max_by_key(|z| z.len())
            .map(String::as_str)
    }

    /// The name exists: it has records, is a zone apex, or lies above a name that has.
    fn exists(&self, name: &str) -> bool {
        self.config.zones.iter().any(|z| z == name)
            || self
                .config
                .records
                .keys()
                .any(|k| k == name || k.ends_with(&format!(".{name}")))
    }

    /// Answers one query's bytes: the response bytes (none for a response or garbage), and the
    /// journal note.
    pub fn answer(&self, from: &str, query: &[u8]) -> (Option<Vec<u8>>, Option<Note>) {
        let q = match Message::parse(query) {
            Ok(q) => q,
            Err(_) if query.len() >= 12 => {
                // A header we can echo: FORMERR.
                let mut head = Message {
                    id: u16::from_be_bytes([query[0], query[1]]),
                    flags: u16::from_be_bytes([query[2], query[3]]),
                    ..Message::default()
                };
                if head.is_response() {
                    return (None, None);
                }
                head.questions.clear();
                let r = Message::response_to(&head, rcode::FORMERR);
                return (Some(r.encode()), Some(self.note(from, &r, "", 0)));
            }
            Err(_) => return (None, None),
        };
        if q.is_response() {
            return (None, None);
        }
        let mut r = Message::response_to(&q, rcode::NOERROR);
        if q.opcode() != 0 {
            r.set_rcode(rcode::NOTIMP);
            return self.done(from, r);
        }
        let [question] = q.questions.as_slice() else {
            r.questions.clear();
            r.set_rcode(rcode::FORMERR);
            return self.done(from, r);
        };
        let name = normalize(&question.name);
        let Some(zone) = self.zone_of(&name).map(str::to_owned) else {
            r.set_rcode(rcode::REFUSED);
            return self.done(from, r);
        };
        r.set_authoritative(true);
        if question.qclass != CLASS_IN && question.qclass != 255 {
            r.set_rcode(rcode::REFUSED);
            return self.done(from, r);
        }
        let qtype = question.qtype;
        let mut current = name;
        for _ in 0..=MAX_CHAIN {
            let data = self.config.records.get(&current);
            let cname = data.and_then(|d| {
                d.iter().find_map(|x| match x {
                    RData::Cname(t) => Some(t.clone()),
                    _ => None,
                })
            });
            if let Some(target) = cname.filter(|_| qtype != rtype::CNAME) {
                r.answers.push(Record {
                    name: current.clone(),
                    rtype: rtype::CNAME,
                    class: CLASS_IN,
                    ttl: self.config.ttl,
                    data: RData::Cname(target.clone()),
                });
                if self.zone_of(&target).is_none() {
                    // Out of our zones: the resolver chases it (we do not recurse).
                    return self.done(from, r);
                }
                current = target;
                continue;
            }
            for d in data.into_iter().flatten() {
                if qtype == rtype::ANY || rtype_of(d) == qtype {
                    r.answers.push(Record {
                        name: current.clone(),
                        rtype: rtype_of(d),
                        class: CLASS_IN,
                        ttl: self.config.ttl,
                        data: d.clone(),
                    });
                }
            }
            if (qtype == rtype::SOA || qtype == rtype::ANY) && current == zone {
                r.answers.push(self.soa(&zone));
            }
            let found = r.answers.iter().any(|a| a.name == current);
            if !found {
                if !self.exists(&current) {
                    r.set_rcode(rcode::NXDOMAIN);
                }
                let soa_zone = self.zone_of(&current).unwrap_or(&zone).to_owned();
                r.authorities.push(self.soa(&soa_zone));
            }
            return self.done(from, r);
        }
        // A CNAME loop: give up like a server would.
        r.set_rcode(rcode::SERVFAIL);
        self.done(from, r)
    }

    fn done(&self, from: &str, r: Message) -> (Option<Vec<u8>>, Option<Note>) {
        let (name, qtype) = r
            .questions
            .first()
            .map(|q| (q.name.clone(), q.qtype))
            .unwrap_or_default();
        let note = self.note(from, &r, &name, qtype);
        (Some(r.encode()), Some(note))
    }

    fn note(&self, from: &str, r: &Message, name: &str, qtype: u16) -> Note {
        let answers: Vec<String> = r.answers.iter().map(|a| a.data.text()).collect();
        (
            "dns-served",
            vec![
                ("from".into(), from.to_owned()),
                ("id".into(), r.id.to_string()),
                ("name".into(), name.to_owned()),
                ("type".into(), dns::type_name(qtype)),
                ("rcode".into(), dns::rcode_name(r.rcode())),
                ("answers".into(), answers.join(",")),
            ],
        )
    }
}

#[cfg(test)]
mod tests;
