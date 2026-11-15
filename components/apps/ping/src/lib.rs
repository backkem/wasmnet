//! ping: ICMP echo, as a wasmnet app.
//!
//! Each session opens an ICMP echo socket (`wasmnet:sockets-ext/icmp`, Linux's unprivileged ping
//! socket: the stack picks the echo identifier), asks for its ICMP errors (`IP_RECVERR`), and
//! sends `count` echo requests, `interval` apart, with sequence numbers from 1 and a payload of
//! `size` bytes (0, 1, 2, ...). Each request is answered by its echo reply, by an ICMP error that
//! quotes it (a router's unreachable or time exceeded), or times out `timeout` after it was sent.
//! The round trip runs from `send` to `receive`, as ping measures it, so the first request's
//! includes neighbor resolution. Sessions run concurrently, in one task.
//!
//! # Config (`wasi:config`, keys under `app.ping.`)
//!
//! One unnamed session (`app.ping.target`, ...), named ones (`app.ping.<name>.target`, ...; for
//! example `app.ping.v4.target = "10.0.0.2"`), or both. Session keys:
//!
//! | key | value | default |
//! |---|---|---|
//! | `target` | a host name (the node's `hosts.<name>`, DNS, mDNS) or an IP literal (required) | |
//! | `count` | echo requests, 1..=1000 | `3` |
//! | `interval` | time between requests (`1s`, `10ms`) | `1s` |
//! | `start` | virtual time of the first request | `0` |
//! | `timeout` | how long a request waits for its reply | `1s` |
//! | `size` | payload bytes, 0..=1452 | `56` |
//! | `ttl` | the requests' hop limit, 1..=255 | the node's |
//!
//! The unnamed session is called `ping`; sessions are listed in name order.
//!
//! # Journal (times in virtual ns)
//!
//! * `ping-start {session, target, address, id, count, size}`: `id` is the identifier the stack
//!   picked;
//! * `ping-reply {session, target, from, seq, bytes, rtt-ns, dup, hop-limit}`: `hop-limit` is the
//!   reply's TTL / hop limit (sockets-ext 0.1.4, `receive-datagram`), absent if unknown;
//! * `ping-error {session, target, from, seq, error, icmp-type, icmp-code}`: an ICMP error about
//!   a request (`error` as the netstack names it: `host-unreachable`, `time-exceeded`, ...);
//! * `ping-timeout {session, target, seq}`;
//! * `ping-done {session, target, transmitted, received, errors, loss-pct}`.
//!
//! The log mimics iputils `ping`. The app exits `ok` when every session got at least one reply.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::collections::BTreeMap;
pub use wasmnet_app_kit::app_pairs;

use wasmnet_wire::parse_duration;

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "ping";

const SESSION_KEYS: [&str; 7] = [
    "target", "count", "interval", "start", "timeout", "size", "ttl",
];

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
    #[error("config app.{APP}: no session (set app.{APP}.target or app.{APP}.<name>.target)")]
    Empty,
}

/// One ping session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub name: String,
    pub target: String,
    pub count: u16,
    pub interval_ns: u64,
    pub start_ns: u64,
    pub timeout_ns: u64,
    pub size: usize,
    pub ttl: Option<u8>,
}

fn ranged<T: std::str::FromStr + PartialOrd>(v: &str, lo: T, hi: T) -> Option<T> {
    v.trim().parse::<T>().ok().filter(|n| *n >= lo && *n <= hi)
}

/// Parses this app's pairs (prefix already stripped) into sessions, in name order.
pub fn sessions(pairs: Vec<(String, String)>) -> Result<Vec<Session>, ConfigError> {
    let mut by_name: BTreeMap<String, Vec<(String, String, String)>> = BTreeMap::new();
    for (key, value) in pairs {
        let (name, field) = match key.rsplit_once('.') {
            Some((name, field)) if !name.contains('.') && SESSION_KEYS.contains(&field) => {
                (name.to_owned(), field.to_owned())
            }
            None if SESSION_KEYS.contains(&key.as_str()) => (APP.to_owned(), key.clone()),
            _ => return Err(ConfigError::Unknown { key }),
        };
        by_name.entry(name).or_default().push((key, field, value));
    }
    if by_name.is_empty() {
        return Err(ConfigError::Empty);
    }
    let mut out = Vec::new();
    for (name, fields) in by_name {
        let mut s = Session {
            target: String::new(),
            count: 3,
            interval_ns: 1_000_000_000,
            start_ns: 0,
            timeout_ns: 1_000_000_000,
            size: 56,
            ttl: None,
            name: name.clone(),
        };
        for (key, field, value) in fields {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            match field.as_str() {
                "target" => {
                    let t = value.trim();
                    if t.is_empty() {
                        return Err(invalid("a host name or an IP address"));
                    }
                    s.target = t.to_owned();
                }
                "count" => s.count = ranged(&value, 1, 1000).ok_or_else(|| invalid("1..=1000"))?,
                "interval" => {
                    s.interval_ns = parse_duration(&value)
                        .filter(|&n| n > 0)
                        .ok_or_else(|| invalid("a duration above zero like 1s"))?
                }
                "start" => {
                    s.start_ns =
                        parse_duration(&value).ok_or_else(|| invalid("a duration like 10ms"))?
                }
                "timeout" => {
                    s.timeout_ns = parse_duration(&value)
                        .filter(|&n| n > 0)
                        .ok_or_else(|| invalid("a duration above zero like 1s"))?
                }
                "size" => s.size = ranged(&value, 0, 1452).ok_or_else(|| invalid("0..=1452"))?,
                "ttl" => s.ttl = Some(ranged(&value, 1, 255).ok_or_else(|| invalid("1..=255"))?),
                _ => unreachable!("only session keys are grouped"),
            }
        }
        if s.target.is_empty() {
            let key = if name == APP {
                "target".to_owned()
            } else {
                format!("{name}.target")
            };
            return Err(ConfigError::Missing {
                key,
                expected: "a host name or an IP address",
            });
        }
        out.push(s);
    }
    Ok(out)
}

/// An echo request as the app writes it: the identifier is left 0 (the stack fills it in, and
/// the checksum), the sequence number is `seq`, the payload `size` bytes 0, 1, 2, ...
pub fn echo_request(v6: bool, seq: u16, size: usize) -> Vec<u8> {
    let mut m = vec![if v6 { 128 } else { 8 }, 0, 0, 0, 0, 0];
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend((0..size).map(|i| i as u8));
    m
}

/// The sequence number of an echo reply (the socket delivers only its own replies).
pub fn reply_seq(reply: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(reply.get(6..8)?.try_into().ok()?))
}

/// IP header bytes plus the ICMP message: what iputils prints in parentheses.
pub fn packet_bytes(v6: bool, size: usize) -> usize {
    size + 8 + if v6 { 40 } else { 20 }
}

/// Milliseconds with three decimals, as ping prints them.
pub fn fmt_ms(ns: u64) -> String {
    format!("{}.{:03} ms", ns / 1_000_000, (ns / 1_000) % 1_000)
}

fn ms_value(ns: u64) -> String {
    format!("{}.{:03}", ns / 1_000_000, (ns / 1_000) % 1_000)
}

/// An ICMP error's name (the netstack's and router's names) and iputils' text for it.
pub fn error_name(v6: bool, icmp_type: u8, code: u8) -> (&'static str, &'static str) {
    match (v6, icmp_type, code) {
        (false, 11, _) => ("time-exceeded", "Time to live exceeded"),
        (true, 3, _) => ("time-exceeded", "Time exceeded: Hop limit"),
        (false, 3, 0) => ("net-unreachable", "Destination Net Unreachable"),
        (true, 1, 0) => ("net-unreachable", "Destination unreachable: No route"),
        (false, 3, 1) => ("host-unreachable", "Destination Host Unreachable"),
        (true, 1, 3) => (
            "host-unreachable",
            "Destination unreachable: Address unreachable",
        ),
        (false, 3, 2) => ("protocol-unreachable", "Destination Protocol Unreachable"),
        (false, 3, 3) => ("port-unreachable", "Destination Port Unreachable"),
        (true, 1, 4) => (
            "port-unreachable",
            "Destination unreachable: Port unreachable",
        ),
        (false, 3, 4) => ("frag-needed", "Frag needed"),
        (false, 3, 9 | 10 | 13) => ("admin-prohibited", "Packet filtered"),
        (true, 1, 1) => (
            "admin-prohibited",
            "Destination unreachable: Administratively prohibited",
        ),
        (true, 1, 2) => ("beyond-scope", "Destination unreachable: Beyond scope"),
        (true, 2, _) => ("packet-too-big", "Packet too big"),
        (false, 12, _) | (true, 4, _) => ("parameter-problem", "Parameter problem"),
        _ => ("unreachable", "Destination unreachable"),
    }
}

/// A session's tally.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub transmitted: u64,
    pub received: u64,
    pub errors: u64,
    pub rtts: Vec<u64>,
}

impl Stats {
    pub fn loss_pct(&self) -> u64 {
        if self.transmitted == 0 {
            return 0;
        }
        (self.transmitted - self.received.min(self.transmitted)) * 100 / self.transmitted
    }

    /// iputils' summary: the counts line, and the rtt line when anything came back.
    pub fn lines(&self, target: &str) -> Vec<String> {
        let errors = if self.errors > 0 {
            format!("+{} errors, ", self.errors)
        } else {
            String::new()
        };
        let mut out = vec![
            format!("--- {target} ping statistics ---"),
            format!(
                "{} packets transmitted, {} received, {errors}{}% packet loss",
                self.transmitted,
                self.received,
                self.loss_pct()
            ),
        ];
        if let (Some(min), Some(max)) = (self.rtts.iter().min(), self.rtts.iter().max()) {
            let avg = self.rtts.iter().sum::<u64>() / self.rtts.len() as u64;
            out.push(format!(
                "rtt min/avg/max = {}/{}/{} ms",
                ms_value(*min),
                ms_value(avg),
                ms_value(*max)
            ));
        }
        out
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
    fn unnamed_and_named_sessions_in_name_order() {
        let s = sessions(pairs(&[
            ("v6.target", "2001:db8::2"),
            ("v6.count", "1"),
            ("v6.interval", "10ms"),
            ("target", "web"),
            ("ttl", "2"),
            ("a.target", "10.0.0.2"),
            ("a.size", "0"),
            ("a.start", "5ms"),
            ("a.timeout", "250ms"),
        ]))
        .unwrap();
        let names: Vec<&str> = s.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a", "ping", "v6"]);
        assert_eq!(
            (s[0].size, s[0].start_ns, s[0].timeout_ns, s[0].count),
            (0, 5_000_000, 250_000_000, 3)
        );
        assert_eq!(
            (s[1].target.as_str(), s[1].ttl, s[1].size),
            ("web", Some(2), 56)
        );
        assert_eq!((s[2].count, s[2].interval_ns), (1, 10_000_000));
    }

    #[test]
    fn bad_config_is_named() {
        for (p, needle) in [
            (&[][..], "no session"),
            (&[("count", "3")][..], "ping.target"),
            (&[("x.count", "3")][..], "x.target"),
            (&[("target", "a"), ("count", "0")][..], "count"),
            (&[("target", "a"), ("ttl", "0")][..], "ttl"),
            (&[("target", "a"), ("interval", "0ms")][..], "interval"),
            (&[("target", "a"), ("size", "1453")][..], "size"),
            (&[("target", "a"), ("bogus", "1")][..], "unknown"),
            (&[("x.y.target", "a")][..], "unknown"),
        ] {
            let e = sessions(pairs(p)).unwrap_err().to_string();
            assert!(e.contains(needle), "{e} lacks {needle}");
        }
    }

    #[test]
    fn requests_and_replies() {
        let r = echo_request(false, 258, 3);
        assert_eq!(r, [8, 0, 0, 0, 0, 0, 1, 2, 0, 1, 2]);
        assert_eq!(echo_request(true, 1, 0)[0], 128);
        assert_eq!(reply_seq(&[0, 0, 0, 0, 0x42, 0x01, 0, 7]), Some(7));
        assert_eq!(reply_seq(&[0, 0, 0]), None);
        assert_eq!(packet_bytes(false, 56), 84);
        assert_eq!(packet_bytes(true, 56), 104);
    }

    #[test]
    fn output_lines() {
        assert_eq!(fmt_ms(500_000), "0.500 ms");
        assert_eq!(fmt_ms(1_234_567_000), "1234.567 ms");
        assert_eq!(error_name(false, 3, 1).1, "Destination Host Unreachable");
        assert_eq!(error_name(true, 3, 0).0, "time-exceeded");
        let s = Stats {
            transmitted: 3,
            received: 2,
            errors: 1,
            rtts: vec![1_000_000, 500_000],
        };
        assert_eq!(
            s.lines("10.0.0.2"),
            [
                "--- 10.0.0.2 ping statistics ---",
                "3 packets transmitted, 2 received, +1 errors, 33% packet loss",
                "rtt min/avg/max = 0.500/0.750/1.000 ms",
            ]
        );
        let none = Stats {
            transmitted: 1,
            ..Stats::default()
        };
        assert_eq!(none.lines("x").len(), 2);
        assert_eq!(none.loss_pct(), 100);
    }
}
