//! DNS messages (RFC 1035, RFC 3596 for AAAA, RFC 2782 for SRV, RFC 4034 for NSEC): parse and
//! encode, plus the DNS-SD helpers of RFC 6763 (service instance names, TXT key/value pairs).
//!
//! Shared by the netstack's stub resolver (`wasi:sockets/ip-name-lookup`), the `dns-server` and
//! `mdns-responder` apps, the app kit's service browser and packet decoders. Parsing follows
//! compression pointers (bounded, so a pointer loop is an error, never a hang); encoding
//! compresses names against earlier names in the message, as servers do (in SRV and NSEC data
//! too, which RFC 6762 §18.14 allows for Multicast DNS). Only the record types wasmnet uses have
//! typed data ([`RData`]); every other type round-trips as raw bytes.
//!
//! # Names
//!
//! A name is held in presentation form: labels joined by dots, without the trailing dot, case
//! preserved. A label is any 1 to 63 bytes on the wire (a DNS-SD instance name such as
//! `My Printer (2)` holds spaces, and may hold a dot), so the text escapes as RFC 1035 §5.1
//! does: `\.` is a dot inside a label, `\\` a backslash, and `\DDD` (three decimal digits) a
//! control character, or any byte of a label that is not UTF-8. A label that is valid UTF-8
//! keeps its other characters as they are. Parsing a name and encoding it again gives back the
//! same bytes. [`escape_label`] and [`unescape_label`] convert one label.

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
    pub const NSEC: u16 = 47;
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
        rtype::NSEC => "NSEC".into(),
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
        rtype::NSEC,
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
    /// Where a service is (RFC 2782): its host and port.
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Character strings (RFC 1035 §3.3.14), each at most 255 bytes. DNS-SD puts one key or
    /// `key=value` pair in each string ([`txt_pairs`], [`txt_strings`]). No strings at all is
    /// empty record data; RFC 6763 §6.1 writes an empty TXT record as one empty string instead.
    Txt(Vec<Vec<u8>>),
    /// The owner has records of these types and no others (RFC 4034 §4). Multicast DNS uses it
    /// for negative answers with `next` set to the owner itself (RFC 6762 §6.1). `types` is
    /// ascending and without repeats when parsed, and must be so to encode identically.
    Nsec {
        next: String,
        types: Vec<u16>,
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
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => format!("{priority} {weight} {port} {target}"),
            RData::Txt(strings) => strings
                .iter()
                .map(|s| quoted(s))
                .collect::<Vec<_>>()
                .join(" "),
            RData::Nsec { next, types } => {
                let mut t = next.clone();
                for ty in types {
                    t.push(' ');
                    t.push_str(&type_name(*ty));
                }
                t
            }
            RData::Other(b) => format!("\\# {}", b.len()),
        }
    }

    /// The record data as on the wire with every name written out in full (no compression
    /// pointers): what RFC 6762 §8.2 compares in a probe tiebreak, and a key for a cache.
    pub fn wire_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        write_rdata(&mut b, self, None);
        b
    }
}

/// A character string in presentation form: in double quotes, `"` and `\` escaped, bytes
/// outside printable ASCII as `\DDD`.
fn quoted(s: &[u8]) -> String {
    let mut t = String::from("\"");
    for &c in s {
        match c {
            b'"' | b'\\' => {
                t.push('\\');
                t.push(char::from(c));
            }
            0x20..=0x7e => t.push(char::from(c)),
            _ => t.push_str(&format!("\\{c:03}")),
        }
    }
    t.push('"');
    t
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
                name: strip_root(name).into(),
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
            write_rdata(&mut b, &r.data, Some(&mut seen));
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
    // On the wire: every label with its length byte, plus the root's zero (at most 255).
    let mut wire_len = 1;
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
                wire_len += 1 + label.len();
                if wire_len > 255 {
                    return Err(DnsError::BadName);
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&escape_label_bytes(label));
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
    let end = start + len;
    let raw = field(start, len)?;
    let name_in = |mut p: usize| -> Result<String, DnsError> {
        let n = read_name(b, &mut p)?;
        (p <= end).then_some(n).ok_or(DnsError::BadRecord)
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
                .filter(|_| p + 20 == end)
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
        rtype::SRV => {
            let w = |i: usize| -> Result<u16, DnsError> {
                Ok(u16::from_be_bytes([
                    *raw.get(i).ok_or(DnsError::BadRecord)?,
                    *raw.get(i + 1).ok_or(DnsError::BadRecord)?,
                ]))
            };
            RData::Srv {
                priority: w(0)?,
                weight: w(2)?,
                port: w(4)?,
                target: name_in(start + 6).map_err(|_| DnsError::BadRecord)?,
            }
        }
        rtype::TXT => {
            let mut strings = Vec::new();
            let mut rest = raw;
            while let Some((&n, tail)) = rest.split_first() {
                let s = tail.get(..usize::from(n)).ok_or(DnsError::BadRecord)?;
                strings.push(s.to_vec());
                rest = &tail[usize::from(n)..];
            }
            RData::Txt(strings)
        }
        rtype::NSEC => {
            let mut p = start;
            let next = read_name(b, &mut p)?;
            if p > end {
                return Err(DnsError::BadRecord);
            }
            RData::Nsec {
                next,
                types: read_type_bitmap(&b[p..end])?,
            }
        }
        _ => RData::Other(raw.to_vec()),
    };
    *at = end;
    Ok(Record {
        name,
        rtype,
        class,
        ttl,
        data,
    })
}

/// RFC 4034 §4.1.2's type bit maps, in their one canonical form: windows ascending, each of 1
/// to 32 bytes whose last byte is not zero. Anything else is malformed, so that what parses
/// encodes back to the same bytes.
fn read_type_bitmap(mut b: &[u8]) -> Result<Vec<u16>, DnsError> {
    let mut types = Vec::new();
    let mut last_window: Option<u8> = None;
    while !b.is_empty() {
        let [window, len, ..] = *b else {
            return Err(DnsError::BadRecord);
        };
        let bits = b
            .get(2..2 + usize::from(len))
            .filter(|bits| (1..=32).contains(&bits.len()) && bits.last() != Some(&0))
            .ok_or(DnsError::BadRecord)?;
        if last_window.is_some_and(|w| w >= window) {
            return Err(DnsError::BadRecord);
        }
        last_window = Some(window);
        for (i, byte) in bits.iter().enumerate() {
            for bit in 0..8u16 {
                if byte & (0x80u8 >> bit) != 0 {
                    types.push(u16::from(window) << 8 | (i as u16) << 3 | bit);
                }
            }
        }
        b = &b[2 + bits.len()..];
    }
    Ok(types)
}

fn write_type_bitmap(b: &mut Vec<u8>, types: &[u16]) {
    let mut set: Vec<u16> = types.to_vec();
    set.sort_unstable();
    set.dedup();
    let mut i = 0;
    while i < set.len() {
        let window = (set[i] >> 8) as u8;
        let mut bits = [0u8; 32];
        let mut used = 0;
        while i < set.len() && (set[i] >> 8) as u8 == window {
            let low = usize::from(set[i] as u8);
            bits[low / 8] |= 0x80 >> (low % 8);
            used = low / 8 + 1;
            i += 1;
        }
        b.push(window);
        b.push(used as u8);
        b.extend_from_slice(&bits[..used]);
    }
}

/// Writes record data; names are compressed against `seen` when it is given, written out in
/// full otherwise.
fn write_rdata(b: &mut Vec<u8>, data: &RData, mut seen: Option<&mut BTreeMap<String, u16>>) {
    let mut name = |b: &mut Vec<u8>, n: &str| match seen.as_deref_mut() {
        Some(seen) => write_name(b, n, seen),
        None => write_name(b, n, &mut BTreeMap::new()),
    };
    match data {
        RData::A(a) => b.extend_from_slice(&a.octets()),
        RData::Aaaa(a) => b.extend_from_slice(&a.octets()),
        RData::Cname(n) | RData::Ns(n) | RData::Ptr(n) => name(b, n),
        RData::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            name(b, mname);
            name(b, rname);
            for v in [serial, refresh, retry, expire, minimum] {
                b.extend_from_slice(&v.to_be_bytes());
            }
        }
        RData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            for v in [priority, weight, port] {
                b.extend_from_slice(&v.to_be_bytes());
            }
            name(b, target);
        }
        RData::Txt(strings) => {
            for s in strings {
                debug_assert!(s.len() <= 255, "a TXT string of {} bytes", s.len());
                let s = &s[..s.len().min(255)];
                b.push(s.len() as u8);
                b.extend_from_slice(s);
            }
        }
        RData::Nsec { next, types } => {
            name(b, next);
            write_type_bitmap(b, types);
        }
        RData::Other(raw) => b.extend_from_slice(raw),
    }
}

/// Writes `name`, ending in a pointer to the longest suffix already written (offsets < 0x4000).
fn write_name(b: &mut Vec<u8>, name: &str, seen: &mut BTreeMap<String, u16>) {
    let name = strip_root(name);
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
        let (label, tail) = split_label(rest);
        let label = unescape_label(label);
        // An empty label would end the name early; one over 63 bytes cannot be written.
        debug_assert!(
            (1..=63).contains(&label.len()),
            "a DNS label of {} bytes in {name:?}",
            label.len()
        );
        let label = &label[..label.len().min(63)];
        b.push(label.len() as u8);
        b.extend_from_slice(label);
        rest = tail;
    }
    b.push(0);
}

/// The name without its trailing dot (the root), if it has one that is not escaped.
fn strip_root(name: &str) -> &str {
    match name.strip_suffix('.') {
        Some(rest) if rest.bytes().rev().take_while(|&c| c == b'\\').count() % 2 == 0 => rest,
        _ => name,
    }
}

/// Splits a name in presentation form at its first unescaped dot: the first label (still
/// escaped) and the rest.
pub fn split_label(name: &str) -> (&str, &str) {
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'.' => return (&name[..i], &name[i + 1..]),
            _ => i += 1,
        }
    }
    (name, "")
}

/// One label of a name in presentation form, as text: a dot becomes `\.`, a backslash `\\`, and
/// a control character `\DDD`. `escape_label("Web (2)")` is `Web (2)`;
/// `escape_label("v1.2")` is `v1\.2`.
pub fn escape_label(label: &str) -> String {
    escape_label_bytes(label.as_bytes())
}

/// [`escape_label`] for a label's raw bytes, as [`Message::parse`] does it: UTF-8 stays as it
/// is (but for dots, backslashes and control characters); in a label that is not UTF-8 every
/// byte outside printable ASCII is `\DDD`.
pub fn escape_label_bytes(label: &[u8]) -> String {
    let mut t = String::with_capacity(label.len());
    let escape = |t: &mut String, c: u32| match c {
        0x2e => t.push_str("\\."),
        0x5c => t.push_str("\\\\"),
        0..=0x1f | 0x7f => t.push_str(&format!("\\{c:03}")),
        _ => {}
    };
    match core::str::from_utf8(label) {
        Ok(s) => {
            for ch in s.chars() {
                match u32::from(ch) {
                    c @ (0x2e | 0x5c | 0..=0x1f | 0x7f) => escape(&mut t, c),
                    _ => t.push(ch),
                }
            }
        }
        Err(_) => {
            for &c in label {
                match c {
                    b'.' | b'\\' | 0..=0x1f | 0x7f => escape(&mut t, u32::from(c)),
                    0x20..=0x7e => t.push(char::from(c)),
                    _ => t.push_str(&format!("\\{c:03}")),
                }
            }
        }
    }
    t
}

/// The bytes of one label in presentation form: the inverse of [`escape_label_bytes`]. A
/// backslash that starts no valid escape is kept as it is.
pub fn unescape_label(label: &str) -> Vec<u8> {
    let b = label.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            let digits = b
                .get(i + 1..i + 4)
                .filter(|d| d.iter().all(u8::is_ascii_digit));
            if let Some(d) = digits {
                let v = d.iter().fold(0u32, |v, c| v * 10 + u32::from(c - b'0'));
                if let Ok(byte) = u8::try_from(v) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
            if let Some(&c) = b.get(i + 1)
                && !c.is_ascii_digit()
            {
                out.push(c);
                i += 2;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Case-insensitive name equality, ignoring one trailing dot.
pub fn same_name(a: &str, b: &str) -> bool {
    strip_root(a).eq_ignore_ascii_case(strip_root(b))
}

// ---- DNS-SD (RFC 6763) ------------------------------------------------------------------------

/// The name a DNS-SD browser asks for the service types on a link (RFC 6763 §9).
pub const DNS_SD_SERVICES: &str = "_services._dns-sd._udp.local";

/// Whether `t` is a service type as RFC 6763 §7 writes it: `_<name>._tcp` or `_<name>._udp`,
/// where the name has 1 to 15 letters, digits and hyphens, at least one letter, and no hyphen
/// at either end or next to another (RFC 6335 §5.1).
pub fn valid_service_type(t: &str) -> bool {
    let Some((name, proto)) = t.split_once('.') else {
        return false;
    };
    let Some(name) = name.strip_prefix('_') else {
        return false;
    };
    (proto == "_tcp" || proto == "_udp")
        && (1..=15).contains(&name.len())
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        && name.bytes().any(|c| c.is_ascii_alphabetic())
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
}

/// Whether `instance` can be a service instance name (RFC 6763 §4.1.1): 1 to 63 bytes of UTF-8,
/// no control characters. Dots, spaces and any other characters are allowed.
pub fn valid_instance(instance: &str) -> bool {
    (1..=63).contains(&instance.len()) && !instance.chars().any(char::is_control)
}

/// The full name of a service instance: `instance_name("Web (2)", "_http._tcp", "local")` is
/// `Web (2)._http._tcp.local`, the instance label escaped ([`escape_label`]).
pub fn instance_name(instance: &str, service_type: &str, domain: &str) -> String {
    format!("{}.{service_type}.{domain}", escape_label(instance))
}

/// Splits a service instance's full name into its instance (unescaped; bytes that are not
/// UTF-8 replaced) and the rest, the service type and domain:
/// `Web (2)._http._tcp.local` is `("Web (2)", "_http._tcp.local")`.
pub fn split_instance(name: &str) -> (String, &str) {
    let (label, rest) = split_label(strip_root(name));
    let bytes = unescape_label(label);
    (String::from_utf8_lossy(&bytes).into_owned(), rest)
}

/// One TXT attribute (RFC 6763 §6.4, §6.5): a key with no value (`key`, a boolean that is
/// present), or with a value that may be empty (`key=`) and may hold any bytes.
pub type TxtPair = (String, Option<Vec<u8>>);

/// The strings of a TXT record for these attributes, in order: `key` or `key=value`. With no
/// attributes, one empty string (RFC 6763 §6.1). Keys are not checked here
/// ([`valid_txt_key`]); a string longer than 255 bytes is the caller's to avoid.
pub fn txt_strings(pairs: &[TxtPair]) -> Vec<Vec<u8>> {
    if pairs.is_empty() {
        return vec![Vec::new()];
    }
    pairs
        .iter()
        .map(|(key, value)| {
            let mut s = key.as_bytes().to_vec();
            if let Some(v) = value {
                s.push(b'=');
                s.extend_from_slice(v);
            }
            s
        })
        .collect()
}

/// Whether `key` can be a TXT attribute's key (RFC 6763 §6.4): 1 to 9 characters are
/// recommended, at most 255 bytes are allowed, of printable ASCII (space included) except `=`.
pub fn valid_txt_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 255
        && key.bytes().all(|c| (0x20..=0x7e).contains(&c) && c != b'=')
}

/// The attributes in a TXT record's strings, as RFC 6763 §6.4 reads them: an empty string, one
/// that starts with `=` or whose key is not printable ASCII is skipped, and of a key that
/// appears twice (compared without case) only the first counts.
pub fn txt_pairs(strings: &[Vec<u8>]) -> Vec<TxtPair> {
    let mut out: Vec<TxtPair> = Vec::new();
    for s in strings {
        let (key, value) = match s.iter().position(|&c| c == b'=') {
            Some(i) => (&s[..i], Some(s[i + 1..].to_vec())),
            None => (&s[..], None),
        };
        let Ok(key) = core::str::from_utf8(key) else {
            continue;
        };
        if !valid_txt_key(key) || out.iter().any(|(k, _)| k.eq_ignore_ascii_case(key)) {
            continue;
        }
        out.push((key.to_string(), value));
    }
    out
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

    fn record(name: &str, rtype: u16, data: RData) -> Record {
        Record {
            name: name.into(),
            rtype,
            class: CLASS_IN | MDNS_CLASS_BIT,
            ttl: 120,
            data,
        }
    }

    #[test]
    fn service_records_round_trip_with_compression() {
        let instance = instance_name("Alpha Web (2)", "_http._tcp", "local");
        assert_eq!(instance, "Alpha Web (2)._http._tcp.local");
        let mut m = Message {
            flags: 0x8400,
            ..Message::default()
        };
        m.answers.push(record(
            "_http._tcp.local",
            rtype::PTR,
            RData::Ptr(instance.clone()),
        ));
        m.answers.push(record(
            &instance,
            rtype::SRV,
            RData::Srv {
                priority: 0,
                weight: 0,
                port: 80,
                target: "alpha.local".into(),
            },
        ));
        m.answers.push(record(
            &instance,
            rtype::TXT,
            RData::Txt(vec![b"path=/".to_vec(), b"secure".to_vec()]),
        ));
        m.additionals.push(record(
            "alpha.local",
            rtype::NSEC,
            RData::Nsec {
                next: "alpha.local".into(),
                types: vec![rtype::A],
            },
        ));
        let bytes = m.encode();
        assert_eq!(Message::parse(&bytes).unwrap(), m);
        // The SRV target and the NSEC's next name point at earlier copies.
        // Six bytes, then `alpha` and a pointer to `local` (from `_http._tcp.local`).
        let srv_at = bytes
            .windows(6)
            .position(|w| w == [0, 0, 0, 0, 0, 80])
            .unwrap();
        assert_eq!(bytes[srv_at - 2..srv_at], [0, 14], "6 + 5alpha + pointer");
        let nsec_name = bytes.len() - 3 - 2;
        assert_eq!(
            bytes[nsec_name] & 0xc0,
            0xc0,
            "the NSEC next name is a pointer"
        );
        assert_eq!(m.answers[1].data.text(), "0 0 80 alpha.local");
        assert_eq!(m.answers[2].data.text(), "\"path=/\" \"secure\"");
        assert_eq!(m.additionals[0].data.text(), "alpha.local A");
        // RFC 4034 §4.1.2: window 0, one byte, bit 1 (A).
        assert_eq!(
            m.additionals[0].data.wire_bytes(),
            [
                5, b'a', b'l', b'p', b'h', b'a', 5, b'l', b'o', b'c', b'a', b'l', 0, 0, 1, 0x40
            ]
        );
        assert_eq!(type_name(rtype::NSEC), "NSEC");
        assert_eq!(type_from_name("nsec"), Some(rtype::NSEC));
    }

    #[test]
    fn instance_labels_escape_dots_and_backslashes() {
        assert_eq!(escape_label("v1.2 \\ x"), "v1\\.2 \\\\ x");
        assert_eq!(unescape_label("v1\\.2 \\\\ x"), b"v1.2 \\ x");
        assert_eq!(escape_label_bytes(&[0xff, b'a', 7]), "\\255a\\007");
        assert_eq!(unescape_label("\\255a\\007"), [0xff, b'a', 7]);
        assert_eq!(escape_label("Café"), "Café");
        let name = instance_name("v1.2", "_ipp._tcp", "local");
        assert_eq!(name, "v1\\.2._ipp._tcp.local");
        assert_eq!(
            split_instance(&name),
            (String::from("v1.2"), "_ipp._tcp.local")
        );
        let m = Message::query(0, &name, rtype::SRV);
        let bytes = m.encode();
        // One label of four bytes, `v1.2`, then `_ipp`.
        assert_eq!(&bytes[12..18], &[4, b'v', b'1', b'.', b'2', 4]);
        assert_eq!(Message::parse(&bytes).unwrap(), m);
        // A name ending in an escaped dot keeps it.
        assert_eq!(strip_root("a\\."), "a\\.");
        assert_eq!(strip_root("a\\\\."), "a\\\\");
        assert!(same_name("A\\.b.local.", "a\\.B.local"));
    }

    #[test]
    fn service_types_and_instances_are_validated() {
        assert!(valid_service_type("_http._tcp") && valid_service_type("_x-y2._udp"));
        for bad in [
            "http._tcp",
            "_http._sctp",
            "_._tcp",
            "_-a._tcp",
            "_a--b._tcp",
            "_12._tcp",
        ] {
            assert!(!valid_service_type(bad), "{bad}");
        }
        assert!(
            !valid_service_type("_abcdefghijklmnop._tcp"),
            "16 characters"
        );
        assert!(valid_instance("My Printer (2)") && valid_instance("a.b"));
        assert!(!valid_instance("") && !valid_instance("a\nb") && !valid_instance(&"x".repeat(64)));
    }

    #[test]
    fn txt_attributes_follow_rfc_6763() {
        let pairs = vec![
            (String::from("path"), Some(b"/".to_vec())),
            (String::from("secure"), None),
            (String::from("empty"), Some(Vec::new())),
        ];
        let strings = txt_strings(&pairs);
        assert_eq!(
            strings,
            [b"path=/".to_vec(), b"secure".to_vec(), b"empty=".to_vec()]
        );
        assert_eq!(txt_pairs(&strings), pairs);
        assert_eq!(txt_strings(&[]), [Vec::<u8>::new()], "one empty string");
        // Skipped: empty, no key, a repeated key (any case); the first value wins.
        let read = txt_pairs(&[
            Vec::new(),
            b"=x".to_vec(),
            b"a=1".to_vec(),
            b"A=2".to_vec(),
            b"b=x=y".to_vec(),
        ]);
        assert_eq!(
            read,
            [
                (String::from("a"), Some(b"1".to_vec())),
                (String::from("b"), Some(b"x=y".to_vec()))
            ]
        );
    }

    #[test]
    fn malformed_service_records_are_errors() {
        let answer = |rtype: u16, data: &[u8]| {
            let mut r = Message::response_to(&Message::query(1, "a", rtype::A), 0).encode();
            r[7] = 1;
            r.extend_from_slice(&[0xc0, 12]);
            r.extend_from_slice(&rtype.to_be_bytes());
            r.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            r.extend_from_slice(&(data.len() as u16).to_be_bytes());
            r.extend_from_slice(data);
            Message::parse(&r)
        };
        // A TXT string that runs past the record.
        assert_eq!(answer(rtype::TXT, &[3, b'a']), Err(DnsError::BadRecord));
        assert!(answer(rtype::TXT, &[]).is_ok(), "empty TXT data");
        // An SRV shorter than its fixed part, or whose target runs past the record.
        assert_eq!(answer(rtype::SRV, &[0, 0, 0]), Err(DnsError::BadRecord));
        assert_eq!(
            answer(rtype::SRV, &[0, 0, 0, 0, 0, 80, 1, b'a']),
            Err(DnsError::BadRecord)
        );
        // NSEC bitmaps: a trailing zero byte, an empty window, windows out of order.
        let nsec = |bitmap: &[u8]| {
            let mut d = vec![0];
            d.extend_from_slice(bitmap);
            answer(rtype::NSEC, &d)
        };
        assert!(nsec(&[0, 1, 0x40]).is_ok());
        assert_eq!(nsec(&[0, 2, 0x40, 0]), Err(DnsError::BadRecord));
        assert_eq!(nsec(&[0, 0]), Err(DnsError::BadRecord));
        assert_eq!(nsec(&[1, 1, 0x40, 0, 1, 0x40]), Err(DnsError::BadRecord));
        assert_eq!(nsec(&[0, 1]), Err(DnsError::BadRecord));
    }
}
