//! STUN Binding (RFC 8489), the subset a tunnel uses for its checks, keepalives and reflexive
//! address: requests with an optional `USERNAME`, success responses with `XOR-MAPPED-ADDRESS`.
//!
//! A STUN message shares the tunnel's UDP port with Geneve; [`is_stun`] tells them apart by the
//! magic cookie at bytes 4..8, where a Geneve header has its VNI and a reserved zero byte, so
//! no Geneve packet can be taken for STUN.
//!
//! No `MESSAGE-INTEGRITY` and no `FINGERPRINT`: there are no credentials to check yet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The magic cookie, bytes 4..8 of every STUN message.
pub const MAGIC: u32 = 0x2112_A442;
/// The fixed header.
pub const HEADER: usize = 20;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// RFC 8489 §14.3: at most 763 bytes before padding; ours are much shorter.
const MAX_USERNAME: usize = 763;

/// A transaction id: 96 bits the requester picks and the response repeats.
pub type TransactionId = [u8; 12];

/// A decoded message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// A Binding request, with its `USERNAME` if it has one.
    Request {
        txid: TransactionId,
        username: Option<String>,
    },
    /// A Binding success response, with its `XOR-MAPPED-ADDRESS` if it has one.
    Success {
        txid: TransactionId,
        mapped: Option<SocketAddr>,
    },
    /// A Binding error response (never sent here; received ones are ignored).
    Error { txid: TransactionId },
}

/// Why a datagram is not a message this module accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("shorter than a STUN header, or no magic cookie")]
    NotStun,
    #[error("the length field disagrees with the datagram")]
    Length,
    #[error("an attribute runs past the message")]
    Attribute,
    #[error("a comprehension-required attribute this side does not know")]
    Unknown,
    #[error("a malformed USERNAME or XOR-MAPPED-ADDRESS")]
    Value,
    #[error("a method or class other than Binding request, success or error")]
    Method,
}

/// Whether `d` starts like a STUN message: the two top bits zero and the magic cookie.
pub fn is_stun(d: &[u8]) -> bool {
    d.len() >= HEADER && d[0] & 0xc0 == 0 && d[4..8] == MAGIC.to_be_bytes()
}

fn header(kind: u16, len: usize, txid: &TransactionId) -> Vec<u8> {
    let mut m = Vec::with_capacity(HEADER + len);
    m.extend_from_slice(&kind.to_be_bytes());
    m.extend_from_slice(&(len as u16).to_be_bytes());
    m.extend_from_slice(&MAGIC.to_be_bytes());
    m.extend_from_slice(txid);
    m
}

fn attribute(m: &mut Vec<u8>, kind: u16, value: &[u8]) {
    m.extend_from_slice(&kind.to_be_bytes());
    m.extend_from_slice(&(value.len() as u16).to_be_bytes());
    m.extend_from_slice(value);
    m.resize(m.len().next_multiple_of(4), 0);
}

fn padded(n: usize) -> usize {
    4 + n.next_multiple_of(4)
}

/// A Binding request; `username` (at most 763 bytes, longer is cut) names what it is for.
pub fn request(txid: &TransactionId, username: Option<&str>) -> Vec<u8> {
    let user = username.map(|u| &u.as_bytes()[..u.len().min(MAX_USERNAME)]);
    let len = user.map_or(0, |u| padded(u.len()));
    let mut m = header(BINDING_REQUEST, len, txid);
    if let Some(u) = user {
        attribute(&mut m, ATTR_USERNAME, u);
    }
    m
}

/// A Binding success response that tells the requester the endpoint it was seen from.
pub fn success(txid: &TransactionId, mapped: SocketAddr) -> Vec<u8> {
    let value = xor_address(txid, mapped);
    let mut m = header(BINDING_SUCCESS, padded(value.len()), txid);
    attribute(&mut m, ATTR_XOR_MAPPED_ADDRESS, &value);
    m
}

/// `XOR-MAPPED-ADDRESS`'s value: reserved, family, port and address, each XORed with the
/// cookie (and, for IPv6, the transaction id).
fn xor_address(txid: &TransactionId, a: SocketAddr) -> Vec<u8> {
    let cookie = MAGIC.to_be_bytes();
    let port = a.port() ^ (MAGIC >> 16) as u16;
    let mut v = vec![0, 0];
    v.extend_from_slice(&port.to_be_bytes());
    match a.ip() {
        IpAddr::V4(ip) => {
            v[1] = 0x01;
            v.extend(ip.octets().iter().zip(cookie).map(|(b, k)| b ^ k));
        }
        IpAddr::V6(ip) => {
            v[1] = 0x02;
            let key = cookie.iter().chain(txid.iter());
            v.extend(ip.octets().iter().zip(key).map(|(b, k)| b ^ k));
        }
    }
    v
}

fn parse_xor_address(txid: &TransactionId, v: &[u8]) -> Result<SocketAddr, Error> {
    let cookie = MAGIC.to_be_bytes();
    let port = match v.get(2..4) {
        Some(p) => u16::from_be_bytes([p[0], p[1]]) ^ (MAGIC >> 16) as u16,
        None => return Err(Error::Value),
    };
    match (v.get(1), v.len()) {
        (Some(0x01), 8) => {
            let mut o = [0u8; 4];
            for (i, b) in o.iter_mut().enumerate() {
                *b = v[4 + i] ^ cookie[i];
            }
            Ok(SocketAddr::new(Ipv4Addr::from(o).into(), port))
        }
        (Some(0x02), 20) => {
            let key: Vec<u8> = cookie.iter().chain(txid.iter()).copied().collect();
            let mut o = [0u8; 16];
            for (i, b) in o.iter_mut().enumerate() {
                *b = v[4 + i] ^ key[i];
            }
            Ok(SocketAddr::new(Ipv6Addr::from(o).into(), port))
        }
        _ => Err(Error::Value),
    }
}

/// Decodes a Binding request, success or error response. Unknown comprehension-optional
/// attributes (0x8000 and up) are skipped; an unknown comprehension-required one rejects the
/// message, as RFC 8489 §7.3.1 asks (a server would answer 420; this side only drops it).
pub fn parse(d: &[u8]) -> Result<Message, Error> {
    if !is_stun(d) {
        return Err(Error::NotStun);
    }
    let kind = u16::from_be_bytes([d[0], d[1]]);
    let len = usize::from(u16::from_be_bytes([d[2], d[3]]));
    if len % 4 != 0 || HEADER + len != d.len() {
        return Err(Error::Length);
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&d[8..20]);
    let mut username = None;
    let mut mapped = None;
    let mut at = HEADER;
    while at < d.len() {
        let head = d.get(at..at + 4).ok_or(Error::Attribute)?;
        let t = u16::from_be_bytes([head[0], head[1]]);
        let l = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let value = d.get(at + 4..at + 4 + l).ok_or(Error::Attribute)?;
        match t {
            ATTR_USERNAME => {
                if l > MAX_USERNAME {
                    return Err(Error::Value);
                }
                let u = std::str::from_utf8(value).map_err(|_| Error::Value)?;
                username = Some(u.to_owned());
            }
            ATTR_XOR_MAPPED_ADDRESS => mapped = Some(parse_xor_address(&txid, value)?),
            t if t < 0x8000 => return Err(Error::Unknown),
            _ => {}
        }
        at += padded(l);
    }
    match kind {
        BINDING_REQUEST => Ok(Message::Request { txid, username }),
        BINDING_SUCCESS => Ok(Message::Success { txid, mapped }),
        BINDING_ERROR => Ok(Message::Error { txid }),
        _ => Err(Error::Method),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const TX: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    #[test]
    fn a_request_matches_rfc_5769s_layout() {
        let m = request(&TX, Some("7"));
        // Binding request, length 8 (one attribute of 1 byte, padded to 4), the cookie, the id.
        assert_eq!(m[..4], [0x00, 0x01, 0x00, 0x08]);
        assert_eq!(m[4..8], [0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(m[8..20], TX);
        assert_eq!(m[20..], [0x00, 0x06, 0x00, 0x01, b'7', 0, 0, 0]);
        assert_eq!(
            parse(&m),
            Ok(Message::Request {
                txid: TX,
                username: Some("7".into())
            })
        );
        let plain = request(&TX, None);
        assert_eq!(plain.len(), HEADER);
        assert_eq!(
            parse(&plain),
            Ok(Message::Request {
                txid: TX,
                username: None
            })
        );
    }

    #[test]
    fn xor_mapped_address_matches_rfc_5769() {
        // RFC 5769 §2.2: 192.0.2.1:32853 encodes as port 0xa147, address 0xe112a643.
        let a: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        let m = success(&TX, a);
        assert_eq!(m[..4], [0x01, 0x01, 0x00, 0x0c]);
        assert_eq!(
            m[20..],
            [
                0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43
            ]
        );
        assert_eq!(
            parse(&m),
            Ok(Message::Success {
                txid: TX,
                mapped: Some(a)
            })
        );
        // RFC 5769 §2.3: 2001:db8:1234:5678:11:2233:4455:6677 port 32853, with its id.
        let tx: TransactionId = [
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ];
        let a: SocketAddr = "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
            .parse()
            .unwrap();
        let m = success(&tx, a);
        assert_eq!(
            m[24..],
            [
                0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25,
                0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9
            ]
        );
        assert_eq!(
            parse(&m),
            Ok(Message::Success {
                txid: tx,
                mapped: Some(a)
            })
        );
    }

    #[test]
    fn malformed_messages_are_refused() {
        let good = request(&TX, Some("12"));
        assert_eq!(parse(&good[..19]), Err(Error::NotStun));
        let mut cut = good.clone();
        cut.truncate(22);
        assert_eq!(parse(&cut), Err(Error::Length));
        // An attribute longer than the message.
        let mut long = good.clone();
        long[23] = 40;
        assert_eq!(parse(&long), Err(Error::Attribute));
        // A comprehension-required attribute we do not know, and an optional one we skip.
        let mut m = header(BINDING_REQUEST, 8, &TX);
        attribute(&mut m, 0x0008, &[0; 4]);
        assert_eq!(parse(&m), Err(Error::Unknown));
        let mut m = header(BINDING_REQUEST, 8, &TX);
        attribute(&mut m, 0x8022, &[0; 4]);
        assert!(parse(&m).is_ok());
        // Not Binding.
        let mut m = request(&TX, None);
        m[1] = 0x02;
        assert_eq!(parse(&m), Err(Error::Method));
        // A Geneve header is never STUN: its byte 7 is zero, the cookie's is 0x42.
        assert!(!is_stun(&[
            0, 0, 0x86, 0xdd, 0x21, 0x12, 0xa4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]));
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 2048,
            rng_seed: proptest::test_runner::RngSeed::Fixed(8489),
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]

        #[test]
        fn arbitrary_bytes_never_panic(d in proptest::collection::vec(any::<u8>(), 0..96)) {
            let _ = parse(&d);
        }

        #[test]
        fn arbitrary_bytes_after_a_valid_header_never_panic(
            kind in prop_oneof![Just(0x0001u16), Just(0x0101), Just(0x0111), any::<u16>()],
            body in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let len = body.len() & !3;
            let mut m = header(kind & 0x3fff, len, &TX);
            m.extend_from_slice(&body[..len]);
            let _ = parse(&m);
        }

        #[test]
        fn responses_round_trip(ip in any::<[u8; 4]>(), port in any::<u16>(), tx in any::<[u8; 12]>()) {
            let a = SocketAddr::new(Ipv4Addr::from(ip).into(), port);
            prop_assert_eq!(parse(&success(&tx, a)), Ok(Message::Success { txid: tx, mapped: Some(a) }));
        }
    }
}
