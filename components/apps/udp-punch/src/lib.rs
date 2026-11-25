//! udp-punch: a test fixture for UDP hole punching through NATs (RFC 5128 §3.3).
//!
//! Two roles, picked by `role`:
//!
//! * **rendezvous**: listens on `listen`. A peer registers with `REG <name>`; the server notes
//!   the endpoint it saw the datagram come from (the peer's public endpoint, behind a NAT).
//!   Once two peers are known it sends each `PEER <name> <ip:port>`, the other's public
//!   endpoint, and answers every later `REG` of either the same way. It never returns.
//! * **peer**: binds `local`, waits `start`, and sends `REG <name>` to `server` every
//!   `interval` until the server answers (at most `register-tries` times). Then, `tries` times,
//!   once per `interval`, it sends `PUNCH <name> <n>` to the endpoint the server gave it and to
//!   every endpoint it heard the other peer from (a peer-reflexive endpoint, as ICE learns
//!   one), and answers each `PUNCH` it receives with `ACK <name>` to where it came from. It
//!   hears the other peer when a `PUNCH` or an `ACK` arrives from anywhere but the server, and
//!   exits `ok` when it did.
//!
//! # Config (`wasi:config`, keys under `app.udp-punch.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `role` | `rendezvous` or `peer` | **required** |
//! | `listen` | rendezvous: the local socket address | `0.0.0.0:3478` |
//! | `server` | peer: the rendezvous server's IPv4 socket address | **required** for a peer |
//! | `name` | peer: its name, `a-z`, `0-9` and `-`, 1 to 32 characters | **required** for a peer |
//! | `local` | peer: the local socket address | `0.0.0.0:4000` |
//! | `start` | peer: wait before registering | `0` |
//! | `interval` | peer: time between two registrations, or two punch rounds; above zero | `100ms` |
//! | `register-tries` | peer: registrations before giving up, 1..=1000 | `20` |
//! | `tries` | peer: punch rounds, 1..=1000 | `10` |
//!
//! # Journal
//!
//! * rendezvous: `punch-registered {name, endpoint}` per new or moved peer;
//! * peer: `punch-peer {name, peer, endpoint}` once the server answered, `punch-heard {name,
//!   from, message}` the first time the other peer is heard, and `punch-done {name, result,
//!   advertised, heard-from, sent, received}` at the end: `result` is `connected`, `failed`
//!   (never heard) or `no-peer` (the server never answered).

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::net::SocketAddr;
pub use wasmnet_app_kit::app_pairs;
use wasmnet_wire::parse_duration;

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "udp-punch";

/// A config value that cannot be used. The app logs it and exits with an error.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("config app.{APP}.{key}={value:?}: expected {expected}")]
    Invalid {
        key: String,
        value: String,
        expected: &'static str,
    },
    #[error("config app.{APP}.{key}: unknown key")]
    Unknown { key: String },
    #[error("config app.{APP}: {0}")]
    Missing(&'static str),
}

/// A peer's settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub server: SocketAddr,
    pub name: String,
    pub local: SocketAddr,
    pub start_ns: u64,
    pub interval_ns: u64,
    pub register_tries: u32,
    pub tries: u32,
}

/// The parsed config: one role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Config {
    Rendezvous { listen: SocketAddr },
    Peer(Peer),
}

fn valid_name(n: &str) -> bool {
    (1..=32).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Config {
    /// Parses this app's pairs (prefix already stripped). Unknown keys are errors.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Self, ConfigError> {
        let mut role = None;
        let mut listen: SocketAddr = SocketAddr::from(([0, 0, 0, 0], 3478));
        let mut server = None;
        let mut name = None;
        let mut peer = Peer {
            server: SocketAddr::from(([0, 0, 0, 0], 0)),
            name: String::new(),
            local: SocketAddr::from(([0, 0, 0, 0], 4000)),
            start_ns: 0,
            interval_ns: 100_000_000,
            register_tries: 20,
            tries: 10,
        };
        for (key, value) in pairs {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            let count = |v: &str| v.parse::<u32>().ok().filter(|n| (1..=1000).contains(n));
            match key.as_str() {
                "role" => {
                    role = Some(match value.as_str() {
                        "rendezvous" => false,
                        "peer" => true,
                        _ => return Err(invalid("rendezvous or peer")),
                    })
                }
                "listen" => {
                    listen = value
                        .parse()
                        .map_err(|_| invalid("a socket address like 0.0.0.0:3478"))?
                }
                "server" => {
                    server = Some(
                        value
                            .parse::<SocketAddr>()
                            .ok()
                            .filter(|a| a.is_ipv4() && a.port() != 0)
                            .ok_or_else(|| {
                                invalid("an IPv4 socket address like 203.0.113.9:3478")
                            })?,
                    )
                }
                "name" => {
                    if !valid_name(&value) {
                        return Err(invalid("a-z, 0-9 and -, 1 to 32 characters"));
                    }
                    name = Some(value.clone());
                }
                "local" => {
                    peer.local = value
                        .parse()
                        .map_err(|_| invalid("a socket address like 0.0.0.0:4000"))?
                }
                "start" => {
                    peer.start_ns = parse_duration(&value).ok_or_else(|| invalid("a duration"))?
                }
                "interval" => {
                    peer.interval_ns = parse_duration(&value)
                        .filter(|&n| n > 0)
                        .ok_or_else(|| invalid("a duration above zero"))?
                }
                "register-tries" => {
                    peer.register_tries = count(&value).ok_or_else(|| invalid("1..=1000"))?
                }
                "tries" => peer.tries = count(&value).ok_or_else(|| invalid("1..=1000"))?,
                _ => return Err(ConfigError::Unknown { key }),
            }
        }
        match role {
            None => Err(ConfigError::Missing("`role` is required")),
            Some(false) => Ok(Config::Rendezvous { listen }),
            Some(true) => {
                peer.server = server.ok_or(ConfigError::Missing("a peer needs `server`"))?;
                peer.name = name.ok_or(ConfigError::Missing("a peer needs `name`"))?;
                Ok(Config::Peer(peer))
            }
        }
    }
}

/// A datagram of the protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Peer → server.
    Reg(String),
    /// Server → peer: the other peer's name and public endpoint.
    PeerAt(String, SocketAddr),
    /// Peer → peer.
    Punch(String, u32),
    /// Peer → peer, the answer to a punch.
    Ack(String),
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Message::Reg(n) => format!("REG {n}"),
            Message::PeerAt(n, a) => format!("PEER {n} {a}"),
            Message::Punch(n, k) => format!("PUNCH {n} {k}"),
            Message::Ack(n) => format!("ACK {n}"),
        }
        .into_bytes()
    }

    /// Parses a datagram; anything else is `None` (ignored).
    pub fn parse(data: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(data).ok()?;
        let words: Vec<&str> = text.split(' ').collect();
        let name = |n: &str| valid_name(n).then(|| n.to_owned());
        match words.as_slice() {
            ["REG", n] => Some(Message::Reg(name(n)?)),
            ["PEER", n, a] => Some(Message::PeerAt(name(n)?, a.parse().ok()?)),
            ["PUNCH", n, k] => Some(Message::Punch(name(n)?, k.parse().ok()?)),
            ["ACK", n] => Some(Message::Ack(name(n)?)),
            _ => None,
        }
    }
}

/// The rendezvous server's registrations: the first two names, in order, and where each was
/// last seen.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    peers: Vec<(String, SocketAddr)>,
}

impl Registry {
    /// `name` registered from `from`. Returns whether that is news (a new peer or a new
    /// endpoint), and the answers to send: `(to, message)`.
    pub fn register(&mut self, name: &str, from: SocketAddr) -> (bool, Vec<(SocketAddr, Message)>) {
        let known = self.peers.len();
        let news = match self.peers.iter_mut().find(|(n, _)| n == name) {
            Some((_, at)) if *at == from => false,
            Some((_, at)) => {
                *at = from;
                true
            }
            None if known < 2 => {
                self.peers.push((name.to_owned(), from));
                true
            }
            None => return (false, Vec::new()),
        };
        let mut answers = Vec::new();
        if let [(a, at_a), (b, at_b)] = self.peers.as_slice() {
            let (me, other, other_at) = if a == name {
                (at_a, b, at_b)
            } else {
                (at_b, a, at_a)
            };
            answers.push((*me, Message::PeerAt(other.clone(), *other_at)));
            if news {
                // The pair just became complete (or one moved): tell the other one too.
                let them_at = if a == name { at_b } else { at_a };
                answers.push((*them_at, Message::PeerAt(name.to_owned(), from)));
            }
        }
        (news, answers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn config_roles_and_errors() {
        assert_eq!(
            Config::from_pairs(pairs(&[("role", "rendezvous")])).unwrap(),
            Config::Rendezvous {
                listen: "0.0.0.0:3478".parse().unwrap()
            }
        );
        let Config::Peer(p) = Config::from_pairs(pairs(&[
            ("role", "peer"),
            ("server", "203.0.113.9:3478"),
            ("name", "a"),
            ("interval", "50ms"),
        ]))
        .unwrap() else {
            panic!("a peer")
        };
        assert_eq!(
            (p.interval_ns, p.tries, p.local.port()),
            (50_000_000, 10, 4000)
        );
        for (p, needle) in [
            (pairs(&[]), "role"),
            (pairs(&[("role", "peer"), ("name", "a")]), "server"),
            (pairs(&[("role", "peer"), ("server", "1.2.3.4:5")]), "name"),
            (pairs(&[("role", "peer"), ("name", "A")]), "name"),
            (pairs(&[("role", "x")]), "role"),
            (pairs(&[("role", "peer"), ("tries", "0")]), "tries"),
            (pairs(&[("colour", "red")]), "unknown"),
        ] {
            let err = Config::from_pairs(p).unwrap_err().to_string();
            assert!(err.contains(needle), "{err}");
        }
    }

    #[test]
    fn messages_round_trip() {
        for m in [
            Message::Reg("a".into()),
            Message::PeerAt("b".into(), "203.0.113.2:1024".parse().unwrap()),
            Message::Punch("a".into(), 3),
            Message::Ack("b".into()),
        ] {
            assert_eq!(Message::parse(&m.encode()), Some(m));
        }
        assert_eq!(Message::parse(b"REG"), None);
        assert_eq!(Message::parse(b"PUNCH a x"), None);
        assert_eq!(Message::parse(&[0xff, 0]), None);
    }

    #[test]
    fn the_registry_pairs_the_first_two() {
        let (a, b): (SocketAddr, SocketAddr) = (
            "203.0.113.1:4000".parse().unwrap(),
            "203.0.113.2:4000".parse().unwrap(),
        );
        let mut r = Registry::default();
        assert_eq!(r.register("a", a), (true, Vec::new()));
        let (news, answers) = r.register("b", b);
        assert!(news);
        assert_eq!(
            answers,
            [
                (b, Message::PeerAt("a".into(), a)),
                (a, Message::PeerAt("b".into(), b)),
            ]
        );
        let (news, answers) = r.register("a", a);
        assert!(!news);
        assert_eq!(answers, [(a, Message::PeerAt("b".into(), b))]);
        assert_eq!(
            r.register("c", a),
            (false, Vec::new()),
            "a third is ignored"
        );
    }
}
