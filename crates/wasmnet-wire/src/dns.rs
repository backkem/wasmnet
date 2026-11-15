//! DNS messages (RFC 1035, RFC 3596 for AAAA): parse and encode.
//!
//! Shared by the netstack's stub resolver (`wasi:sockets/ip-name-lookup`), the `dns-server` app
//! and packet decoders. Parsing follows compression pointers (bounded, so a pointer loop is
//! an error, never a hang); encoding compresses names against earlier names in the message, as
//! servers do. Only the record types wasmnet uses have typed data ([`RData`]); every other type
//! round-trips as raw bytes.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::net::{Ipv4Addr, Ipv6Addr};

/// The DNS port.
pub const PORT: u16 = 53;
/// Class IN.
pub const CLASS_IN: u16 = 1;
/// The largest message over UDP without EDNS (RFC 1035 §4.2.1).
pub const MAX_UDP: usize = 512;

/// Multicast DNS (RFC 6762): the port and the groups.
pub const MDNS_PORT: u16 = 5353;
pub const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
/// mDNS reuses the class field's top bit: in a question it asks for a unicast response (the
/// "QU" bit, RFC 6762 §5.4), in a record it is the cache-flush bit (§10.2). The rest is the class.
pub const MDNS_CLASS_BIT: u16 = 0x8000;

/// Record types.
pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const OPT: u16 = 41;
    pub const ANY: u16 = 255;
}

/// Response codes.
pub mod rcode {
    pub const NOERROR: u8 = 0;
    pub const FORMERR: u8 = 1;
    pub const SERVFAIL: u8 = 2;
    pub const NXDOMAIN: u8 = 3;
    pub const NOTIMP: u8 = 4;
    pub const REFUSED: u8 = 5;
}

/// `A`, `AAAA`, ... or `TYPE<n>` (RFC 3597).
pub fn type_name(t: u16) -> String {
    match t {
        rtype::A => "A".into(),
        rtype::NS => "NS".into(),
        rtype::CNAME => "CNAME".into(),
        rtype::SOA => "SOA".into(),
        rtype::PTR => "PTR".into(),
        rtype::MX => "MX".into(),
        rtype::TXT => "TXT".into(),
        rtype::AAAA => "AAAA".into(),
        rtype::SRV => "SRV".into(),
        rtype::OPT => "OPT".into(),
        rtype::ANY => "ANY".into(),
        n => format!("TYPE{n}"),
    }
}

/// Parses [`type_name`] (case-insensitive).
pub fn type_from_name(name: &str) -> Option<u16> {
    let upper = name.to_ascii_uppercase();
    if let Some(n) = upper.strip_prefix("TYPE") {
        return n.parse().ok();
    }
    [
        rtype::A,
        rtype::NS,
        rtype::CNAME,
        rtype::SOA,
        rtype::PTR,
        rtype::MX,
        rtype::TXT,
        rtype::AAAA,
        rtype::SRV,
        rtype::OPT,
        rtype::ANY,
    ]
    .into_iter()
    .find(|&t| type_name(t) == upper)
}

/// `NOERROR`, `NXDOMAIN`, ... or `RCODE<n>`.
pub fn rcode_name(r: u8) -> String {
    match r {
        rcode::NOERROR => "NOERROR".into(),
        rcode::FORMERR => "FORMERR".into(),
        rcode::SERVFAIL => "SERVFAIL".into(),
        rcode::NXDOMAIN => "NXDOMAIN".into(),
        rcode::NOTIMP => "NOTIMP".into(),
        rcode::REFUSED => "REFUSED".into(),
        n => format!("RCODE{n}"),
    }
}

/// Parses [`rcode_name`] (case-insensitive) or a number.
pub fn rcode_from_name(name: &str) -> Option<u8> {
    if let Ok(n) = name.parse() {
        return Some(n);
    }
    let upper = name.to_ascii_uppercase();
    (0..=5).find(|&r| rcode_name(r) == upper)
}

/// Whether `name` is a valid host name to look up or serve: dot-separated labels of 1..=63
/// letters, digits, `-` or `_`, not starting or ending with `-`, at most 253 characters (one
/// trailing dot allowed).
pub fn valid_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// A message that could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("DNS message truncated")]
    Truncated,
    #[error("DNS name malformed (bad label or pointer)")]
    BadName,
    #[error("DNS record data malformed")]
    BadRecord,
}

/// One question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// Dotted, without the trailing dot, as on the wire (case preserved).
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl Question {
    /// mDNS: the question asks for a unicast response (QU bit).
    pub fn unicast_response(&self) -> bool {
        self.qclass & MDNS_CLASS_BIT != 0
    }

    /// The class without the mDNS QU bit.
    pub fn class(&self) -> u16 {
        self.qclass & !MDNS_CLASS_BIT
    }
}

impl Record {
    /// mDNS: the record has the cache-flush bit set (a unique record).
    pub fn cache_flush(&self) -> bool {
        self.class & MDNS_CLASS_BIT != 0
    }
}

/// Typed record data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Ptr(String),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// Any other type, as raw bytes.
    Other(Vec<u8>),
}

impl RData {
    /// Presentation form: `10.0.0.1`, `fd00::1`, `web.lan`, `ns.lan hostmaster.lan 1 ...`.
    pub fn text(&self) -> String {
        match self {
            RData::A(a) => a.to_string(),
            RData::Aaaa(a) => a.to_string(),
            RData::Cname(n) | RData::Ns(n) | RData::Ptr(n) => n.clone(),
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"),
            RData::Other(b) => format!("\\# {}", b.len()),
        }
    }
}

/// One resource record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

/// A DNS message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    /// The raw flags word: QR, opcode, AA, TC, RD, RA, Z, RCODE.
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

const QR: u16 = 0x8000;
const AA: u16 = 0x0400;
const TC: u16 = 0x0200;
const RD: u16 = 0x0100;
const RA: u16 = 0x0080;

impl Message {
    /// A standard query for `name` (recursion desired, like a stub resolver).
    pub fn query(id: u16, name: &str, qtype: u16) -> Self {
        Message {
            id,
            flags: RD,
            questions: vec![Question {
                name: name.strip_suffix('.').unwrap_or(name).into(),
                qtype,
                qclass: CLASS_IN,
            }],
            ..Message::default()
        }
    }

    /// An empty response to `query`: same id, question, opcode and RD; QR set; `rcode`.
    pub fn response_to(query: &Message, rcode: u8) -> Self {
        Message {
            id: query.id,
            flags: QR | (query.flags & (0x7800 | RD)) | u16::from(rcode & 0x0f),
            questions: query.questions.clone(),
            ..Message::default()
        }
    }

    pub fn is_response(&self) -> bool {
        self.flags & QR != 0
    }
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x0f) as u8
    }
    pub fn authoritative(&self) -> bool {
        self.flags & AA != 0
    }
    pub fn truncated(&self) -> bool {
        self.flags & TC != 0
    }
    pub fn recursion_desired(&self) -> bool {
        self.flags & RD != 0
    }
    pub fn recursion_available(&self) -> bool {
        self.flags & RA != 0
    }
    pub fn set_authoritative(&mut self, on: bool) {
        self.flags = if on {
            self.flags | AA
        } else {
            self.flags & !AA
        };
    }
    pub fn set_rcode(&mut self, rcode: u8) {
        self.flags = (self.flags & !0x0f) | u16::from(rcode & 0x0f);
    }

    /// Parses a UDP payload.
    pub fn parse(b: &[u8]) -> Result<Self, DnsError> {
        let word = |at: usize| -> Result<u16, DnsError> {
            Ok(u16::from_be_bytes(
                b.get(at..at + 2)
                    .ok_or(DnsError::Truncated)?
                    .try_into()
                    .map_err(|_| DnsError::Truncated)?,
            ))
        };
        let (id, flags) = (word(0)?, word(2)?);
        let counts = [word(4)?, word(6)?, word(8)?, word(10)?];
        let mut at = 12;
        let mut questions = Vec::new();
        for _ in 0..counts[0] {
            let name = read_name(b, &mut at)?;
            let qtype = word(at)?;
            let qclass = word(at + 2)?;
            at += 4;
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }
        let mut sections: [Vec<Record>; 3] = Default::default();
        for (section, &count) in sections.iter_mut().zip(&counts[1..]) {
            for _ in 0..count {
                section.push(read_record(b, &mut at)?);
            }
        }
        let [answers, authorities, additionals] = sections;
        Ok(Message {
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// The UDP payload, names compressed against earlier ones.
    ///
    /// The message must be encodable: at most 65535 entries per section, record data of at most
    /// 65535 bytes, and names of non-empty labels of at most 63 bytes ([`valid_name`]'s
    /// shape; what [`Message::parse`] returns always is). Debug builds check this and panic;
    /// release builds keep the old behaviour (counts and lengths cut to 16 bits, labels to 63
    /// bytes), so a valid message's bytes never depend on the build.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&self.id.to_be_bytes());
        b.extend_from_slice(&self.flags.to_be_bytes());
        for n in [
            self.questions.len(),
            self.answers.len(),
            self.authorities.len(),
            self.additionals.len(),
        ] {
            debug_assert!(n <= usize::from(u16::MAX), "a DNS section of {n} entries");
            b.extend_from_slice(&(n as u16).to_be_bytes());
        }
        let mut seen = BTreeMap::new();
        for q in &self.questions {
            write_name(&mut b, &q.name, &mut seen);
            b.extend_from_slice(&q.qtype.to_be_bytes());
            b.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for r in self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
        {
            write_name(&mut b, &r.name, &mut seen);
            b.extend_from_slice(&r.rtype.to_be_bytes());
            b.extend_from_slice(&r.class.to_be_bytes());
            b.extend_from_slice(&r.ttl.to_be_bytes());
            let len_at = b.len();
            b.extend_from_slice(&[0, 0]);
            match &r.data {
                RData::A(a) => b.extend_from_slice(&a.octets()),
                RData::Aaaa(a) => b.extend_from_slice(&a.octets()),
                RData::Cname(n) | RData::Ns(n) | RData::Ptr(n) => write_name(&mut b, n, &mut seen),
                RData::Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                } => {
                    write_name(&mut b, mname, &mut seen);
                    write_name(&mut b, rname, &mut seen);
                    for v in [serial, refresh, retry, expire, minimum] {
                        b.extend_from_slice(&v.to_be_bytes());
                    }
                }
                RData::Other(raw) => b.extend_from_slice(raw),
            }
            let len = b.len() - len_at - 2;
            debug_assert!(len <= usize::from(u16::MAX), "{len} bytes of record data");
            b[len_at..len_at + 2].copy_from_slice(&(len as u16).to_be_bytes());
        }
        b
    }
}

/// Reads a (possibly compressed) name at `*at` and moves `*at` past it.
fn read_name(b: &[u8], at: &mut usize) -> Result<String, DnsError> {
    let mut name = String::new();
    let mut pos = *at;
    let mut jumped = false;
    // Every pointer must go strictly backwards, which stops a pointer to itself, but not labels
    // that run into the same pointer again: that loops, and only the jump cap ends it.
    let mut jumps = 0;
    loop {
        let len = *b.get(pos).ok_or(DnsError::Truncated)?;
        match len & 0xc0 {
            0x00 if len == 0 => {
                if !jumped {
                    *at = pos + 1;
                }
                return Ok(name);
            }
            0x00 => {
                let label = b
                    .get(pos + 1..pos + 1 + usize::from(len))
                    .ok_or(DnsError::Truncated)?;
                if !name.is_empty() {
                    name.push('.');
                }
                if label.iter().any(|&c| c == b'.' || !c.is_ascii_graphic()) {
                    return Err(DnsError::BadName);
                }
                name.extend(label.iter().map(|&c| char::from(c)));
                if name.len() > 253 {
                    return Err(DnsError::BadName);
                }
                pos += 1 + usize::from(len);
            }
            0xc0 => {
                let lo = *b.get(pos + 1).ok_or(DnsError::Truncated)?;
                let target = usize::from(u16::from_be_bytes([len & 0x3f, lo]));
                if target >= pos || jumps > 64 {
                    return Err(DnsError::BadName);
                }
                if !jumped {
                    *at = pos + 2;
                }
                jumped = true;
                jumps += 1;
                pos = target;
            }
            _ => return Err(DnsError::BadName),
        }
    }
}

fn read_record(b: &[u8], at: &mut usize) -> Result<Record, DnsError> {
    let name = read_name(b, at)?;
    let field = |from: usize, n: usize| b.get(from..from + n).ok_or(DnsError::Truncated);
    let head = field(*at, 10)?;
    let rtype = u16::from_be_bytes([head[0], head[1]]);
    let class = u16::from_be_bytes([head[2], head[3]]);
    let ttl = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    let len = usize::from(u16::from_be_bytes([head[8], head[9]]));
    let start = *at + 10;
    let raw = field(start, len)?;
    let name_in = |mut p: usize| -> Result<String, DnsError> {
        let n = read_name(b, &mut p)?;
        (p <= start + len).then_some(n).ok_or(DnsError::BadRecord)
    };
    let data = match rtype {
        rtype::A => RData::A(Ipv4Addr::from(
            <[u8; 4]>::try_from(raw).map_err(|_| DnsError::BadRecord)?,
        )),
        rtype::AAAA => RData::Aaaa(Ipv6Addr::from(
            <[u8; 16]>::try_from(raw).map_err(|_| DnsError::BadRecord)?,
        )),
        rtype::CNAME => RData::Cname(name_in(start)?),
        rtype::NS => RData::Ns(name_in(start)?),
        rtype::PTR => RData::Ptr(name_in(start)?),
        rtype::SOA => {
            let mut p = start;
            let mname = read_name(b, &mut p)?;
            let rname = read_name(b, &mut p)?;
            let nums = b
                .get(p..p + 20)
                .filter(|_| p + 20 == start + len)
                .ok_or(DnsError::BadRecord)?;
            let n = |i: usize| u32::from_be_bytes([nums[i], nums[i + 1], nums[i + 2], nums[i + 3]]);
            RData::Soa {
                mname,
                rname,
                serial: n(0),
                refresh: n(4),
                retry: n(8),
                expire: n(12),
                minimum: n(16),
            }
        }
        _ => RData::Other(raw.to_vec()),
    };
    *at = start + len;
    Ok(Record {
        name,
        rtype,
        class,
        ttl,
        data,
    })
}

/// Writes `name`, ending in a pointer to the longest suffix already written (offsets < 0x4000).
fn write_name(b: &mut Vec<u8>, name: &str, seen: &mut BTreeMap<String, u16>) {
    let name = name.strip_suffix('.').unwrap_or(name);
    let mut rest = name;
    while !rest.is_empty() {
        // Case-sensitive: a pointer must reproduce the name exactly (servers may match
        // case-insensitively, but then the copy is not byte-identical).
        let key = String::from(rest);
        if let Some(&off) = seen.get(&key) {
            b.extend_from_slice(&(0xc000 | off).to_be_bytes());
            return;
        }
        if b.len() < 0x4000 {
            seen.insert(key, b.len() as u16);
        }
        let (label, tail) = rest.split_once('.').unwrap_or((rest, ""));
        // An empty label would end the name early; one over 63 bytes cannot be written.
        debug_assert!(
            (1..=63).contains(&label.len()),
            "a DNS label of {} bytes in {name:?}",
            label.len()
        );
        let label = &label.as_bytes()[..label.len().min(63)];
        b.push(label.len() as u8);
        b.extend_from_slice(label);
        rest = tail;
    }
    b.push(0);
}

/// Case-insensitive name equality, ignoring one trailing dot.
pub fn same_name(a: &str, b: &str) -> bool {
    a.strip_suffix('.')
        .unwrap_or(a)
        .eq_ignore_ascii_case(b.strip_suffix('.').unwrap_or(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Inside wasmtime (panic = abort) a panic cannot be caught: native runs check it.
    #[cfg(all(debug_assertions, panic = "unwind"))]
    #[should_panic(expected = "a DNS label of 64 bytes")]
    fn encoding_a_label_over_63_bytes_is_caught() {
        Message::query(1, &format!("{}.lan", "a".repeat(64)), rtype::A).encode();
    }

    #[test]
    // Inside wasmtime (panic = abort) a panic cannot be caught: native runs check it.
    #[cfg(all(debug_assertions, panic = "unwind"))]
    #[should_panic(expected = "a DNS label of 0 bytes")]
    fn encoding_an_empty_label_is_caught() {
        Message::query(1, "a..lan", rtype::A).encode();
    }

    #[test]
    fn a_label_of_63_bytes_encodes() {
        let name = format!("{}.lan", "a".repeat(63));
        let q = Message::query(1, &name, rtype::A);
        assert_eq!(Message::parse(&q.encode()).unwrap(), q);
    }

    #[test]
    fn query_and_response_round_trip_with_compression() {
        let q = Message::query(0xbeef, "web.lan.", rtype::A);
        let qb = q.encode();
        assert_eq!(qb.len(), 12 + 9 + 4, "header, 3web3lan0, type, class");
        let back = Message::parse(&qb).unwrap();
        assert_eq!(back, q);
        assert!(!back.is_response() && back.recursion_desired());
        assert_eq!(back.questions[0].name, "web.lan");

        let mut r = Message::response_to(&q, rcode::NOERROR);
        r.set_authoritative(true);
        r.answers.push(Record {
            name: "www.lan".into(),
            rtype: rtype::CNAME,
            class: CLASS_IN,
            ttl: 60,
            data: RData::Cname("web.lan".into()),
        });
        r.answers.push(Record {
            name: "web.lan".into(),
            rtype: rtype::A,
            class: CLASS_IN,
            ttl: 60,
            data: RData::A(Ipv4Addr::new(10, 0, 1, 10)),
        });
        r.authorities.push(Record {
            name: "lan".into(),
            rtype: rtype::SOA,
            class: CLASS_IN,
            ttl: 60,
            data: RData::Soa {
                mname: "ns.lan".into(),
                rname: "hostmaster.lan".into(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86400,
                minimum: 60,
            },
        });
        let rb = r.encode();
        // "web.lan" in the CNAME data and the A owner are pointers to the question.
        assert!(rb.windows(2).filter(|w| *w == [0xc0, 0x0c]).count() >= 2);
        let back = Message::parse(&rb).unwrap();
        assert_eq!(back, r);
        assert!(back.is_response() && back.authoritative());
        assert_eq!((back.id, back.rcode()), (0xbeef, rcode::NOERROR));
        assert_eq!(back.answers[1].data.text(), "10.0.1.10");
        assert_eq!(rcode_name(3), "NXDOMAIN");
        assert_eq!(rcode_from_name("nxdomain"), Some(3));
        assert_eq!(type_name(28), "AAAA");
        assert_eq!(type_from_name("aaaa"), Some(28));
        assert_eq!(type_from_name("TYPE99"), Some(99));
        assert!(same_name("Web.LAN.", "web.lan"));
    }

    #[test]
    fn names_are_validated() {
        assert!(valid_name("web.lan") && valid_name("web.lan.") && valid_name("_dns-sd._udp.lan"));
        assert!(
            !valid_name("") && !valid_name(".") && !valid_name("a..b") && !valid_name("-a.lan")
        );
        assert!(!valid_name(&"a".repeat(64)) && !valid_name("a b"));
    }

    #[test]
    fn malformed_messages_are_errors_not_panics() {
        let good = Message::query(1, "web.lan", rtype::AAAA).encode();
        for n in 0..good.len() {
            assert!(Message::parse(&good[..n]).is_err(), "cut at {n}");
        }
        // A pointer to itself, and a forward pointer.
        let mut looped = good[..12].to_vec();
        looped[5] = 1;
        looped.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert_eq!(Message::parse(&looped), Err(DnsError::BadName));
        // A record whose A data is 3 bytes.
        let mut r = Message::response_to(&Message::query(1, "a", rtype::A), 0).encode();
        r[7] = 1;
        r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 3, 1, 2, 3]);
        assert_eq!(Message::parse(&r), Err(DnsError::BadRecord));
    }
}
