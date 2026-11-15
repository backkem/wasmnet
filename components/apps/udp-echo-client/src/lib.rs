//! udp-echo-client: a wasmnet app that sends `count` UDP datagrams to an echo server, one at a
//! time, waits for each echo with a timeout on virtual `wasi:clocks`, measures round-trip times
//! and exits: `ok` when every datagram came back, an error otherwise.
//!
//! # Config (`wasi:config`, keys under `app.udp-echo-client.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `target` | the server: an IP address or a name from the node's `hosts.<name>` table (required) | |
//! | `port` | the server's UDP port, 1..=65535 | `7` |
//! | `count` | datagrams to send, 1..=1000 | `3` |
//! | `interval` | time between the scheduled sends (`10ms`); a send never starts before the previous datagram was answered or timed out | `1s` |
//! | `size` | payload bytes, 4..=65507 (the first 4 are the sequence number) | `32` |
//! | `timeout` | how long to wait for each echo | `1s` |
//! | `start` | virtual time to wait before resolving the target | `0` |
//!
//! # Timing
//!
//! The RTT runs from the app's `send` call to the `receive` that returned the echo, both read
//! from the virtual monotonic clock. With whole-microsecond link latencies it is exactly the sum
//! of the latencies there and back. The first datagram also pays for ARP (or NDP): the netstack
//! holds it until the server's MAC is known.
//!
//! # Journal
//!
//! * `udp-echo-start {target, peer, local, count, size}`;
//! * `udp-echo-request {seq, bytes}` when `send` returned;
//! * `udp-echo-reply {seq, from, bytes, rtt-ns}`;
//! * `udp-echo-timeout {seq, waited-ns}`: exactly `timeout` after the send;
//! * `udp-echo-done {transmitted, received, loss-pct, rtt-min-ns, rtt-avg-ns, rtt-max-ns}`.
//!
//! A late echo of an earlier datagram (after its timeout) is logged and ignored.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

pub use wasmnet_app_kit::app_pairs;
use wasmnet_wire::parse_duration;

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "udp-echo-client";

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
    pub target: String,
    pub port: u16,
    pub count: u32,
    pub interval_ns: u64,
    pub size: usize,
    pub timeout_ns: u64,
    pub start_ns: u64,
}

fn ranged<T: std::str::FromStr + PartialOrd>(v: &str, lo: T, hi: T) -> Option<T> {
    v.parse::<T>().ok().filter(|n| *n >= lo && *n <= hi)
}

impl Config {
    /// Parses this app's pairs (prefix already stripped). Unknown keys are errors.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Self, ConfigError> {
        let mut target = None;
        let mut c = Config {
            target: String::new(),
            port: 7,
            count: 3,
            interval_ns: 1_000_000_000,
            size: 32,
            timeout_ns: 1_000_000_000,
            start_ns: 0,
        };
        for (key, value) in pairs {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            let positive = |v: &str| parse_duration(v).filter(|&ns| ns > 0);
            match key.as_str() {
                "target" if !value.trim().is_empty() => target = Some(value.trim().to_owned()),
                "target" => return Err(invalid("an IP address or a host name")),
                "port" => {
                    c.port = ranged(&value, 1, u16::MAX).ok_or_else(|| invalid("1..=65535"))?
                }
                "count" => c.count = ranged(&value, 1, 1000).ok_or_else(|| invalid("1..=1000"))?,
                "size" => c.size = ranged(&value, 4, 65_507).ok_or_else(|| invalid("4..=65507"))?,
                "interval" => {
                    c.interval_ns =
                        positive(&value).ok_or_else(|| invalid("a duration like 10ms"))?
                }
                "timeout" => {
                    c.timeout_ns = positive(&value).ok_or_else(|| invalid("a duration like 1s"))?
                }
                "start" => {
                    c.start_ns = parse_duration(&value).ok_or_else(|| invalid("a duration"))?
                }
                _ => return Err(ConfigError::Unknown { key }),
            }
        }
        c.target = target.ok_or_else(|| ConfigError::Missing {
            key: "target".to_owned(),
            expected: "an IP address or a host name",
        })?;
        Ok(c)
    }

    /// When datagram `seq` (from 1) is due, relative to the start: `start + (seq - 1) * interval`.
    pub fn due(&self, seq: u32) -> u64 {
        self.start_ns
            .saturating_add(u64::from(seq.saturating_sub(1)).saturating_mul(self.interval_ns))
    }
}

/// The payload of datagram `seq`: the sequence number (big-endian), then `a..z` repeated.
pub fn payload(seq: u32, size: usize) -> Vec<u8> {
    let mut p = seq.to_be_bytes().to_vec();
    p.extend((0..size.saturating_sub(4)).map(|i| b'a' + (i % 26) as u8));
    p.truncate(size.max(4));
    p
}

/// What a received datagram is, compared with the datagram `seq` we are waiting for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The exact echo of `seq`.
    Echo,
    /// The exact echo of an earlier datagram (it came back after its timeout).
    Late(u32),
    /// Anything else.
    Garbled,
}

/// Classifies a datagram received while waiting for the echo of `seq`.
pub fn classify(data: &[u8], seq: u32, size: usize) -> Reply {
    let Some(got) = data
        .get(..4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    else {
        return Reply::Garbled;
    };
    if data != payload(got, size).as_slice() {
        return Reply::Garbled;
    }
    match got {
        s if s == seq => Reply::Echo,
        s if s < seq && s > 0 => Reply::Late(s),
        _ => Reply::Garbled,
    }
}

/// Round-trip statistics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub transmitted: u32,
    pub rtts: Vec<u64>,
}

impl Stats {
    pub fn received(&self) -> u32 {
        self.rtts.len() as u32
    }

    /// Loss in whole percent (rounded down).
    pub fn loss_pct(&self) -> u32 {
        match self.transmitted {
            0 => 0,
            t => (t - self.received().min(t)) * 100 / t,
        }
    }

    /// `(min, avg, max)` RTT in ns (the average rounded down), if anything came back.
    pub fn rtt(&self) -> Option<(u64, u64, u64)> {
        let min = *self.rtts.iter().min()?;
        let max = *self.rtts.iter().max()?;
        let avg = self.rtts.iter().sum::<u64>() / self.rtts.len() as u64;
        Some((min, avg, max))
    }

    /// The `udp-echo-done` event fields.
    pub fn fields(&self) -> Vec<(String, String)> {
        let (min, avg, max) = self.rtt().unwrap_or_default();
        [
            ("transmitted", self.transmitted.to_string()),
            ("received", self.received().to_string()),
            ("loss-pct", self.loss_pct().to_string()),
            ("rtt-min-ns", min.to_string()),
            ("rtt-avg-ns", avg.to_string()),
            ("rtt-max-ns", max.to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
    }
}

/// `1.234 ms` from nanoseconds (truncated to µs), for log lines only.
pub fn fmt_ms(ns: u64) -> String {
    format!("{}.{:03} ms", ns / 1_000_000, ns / 1_000 % 1_000)
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
    fn config_defaults_values_and_errors() {
        let all = pairs(&[
            ("mac", "02:00:00:00:00:02"),
            ("app.udp-echo-client.target", "server"),
            ("app.udp-echo-client.count", "5"),
            ("app.udp-echo-client.interval", "10ms"),
            ("app.udp-echo-client.timeout", "20ms"),
            ("app.udp-echo-client.size", "64"),
            ("app.udp-echo-client.port", "9"),
            ("app.udp-echo-client.start", "5ms"),
            ("app.udp-echo-server.listen", "0.0.0.0:7"),
        ]);
        let c = Config::from_pairs(app_pairs(all, APP)).unwrap();
        assert_eq!(
            c,
            Config {
                target: "server".to_owned(),
                port: 9,
                count: 5,
                interval_ns: 10_000_000,
                size: 64,
                timeout_ns: 20_000_000,
                start_ns: 5_000_000,
            }
        );
        assert_eq!((c.due(1), c.due(3)), (5_000_000, 25_000_000));
        let d = Config::from_pairs(pairs(&[("target", "10.0.0.1")])).unwrap();
        assert_eq!((d.port, d.count, d.size), (7, 3, 32));
        for (p, needle) in [
            (pairs(&[]), "required"),
            (pairs(&[("target", " ")]), "target"),
            (pairs(&[("target", "a"), ("port", "0")]), "port"),
            (pairs(&[("target", "a"), ("size", "3")]), "size"),
            (pairs(&[("target", "a"), ("timeout", "0ms")]), "timeout"),
            (pairs(&[("target", "a"), ("count", "1001")]), "count"),
            (pairs(&[("target", "a"), ("colour", "red")]), "unknown"),
        ] {
            let err = Config::from_pairs(p).unwrap_err().to_string();
            assert!(err.contains(needle), "{err}");
        }
    }

    #[test]
    fn payloads_and_replies() {
        let p = payload(2, 10);
        assert_eq!(p, [0, 0, 0, 2, b'a', b'b', b'c', b'd', b'e', b'f']);
        assert_eq!(payload(7, 4), 7u32.to_be_bytes());
        assert_eq!(classify(&p, 2, 10), Reply::Echo);
        assert_eq!(classify(&p, 3, 10), Reply::Late(2));
        assert_eq!(classify(&p, 1, 10), Reply::Garbled);
        assert_eq!(classify(&p[..9], 2, 10), Reply::Garbled);
        assert_eq!(classify(b"xy", 2, 10), Reply::Garbled);
        let mut bad = p.clone();
        bad[9] ^= 1;
        assert_eq!(classify(&bad, 2, 10), Reply::Garbled);
    }

    #[test]
    fn stats() {
        let mut s = Stats {
            transmitted: 4,
            rtts: vec![1_000_000, 500_000, 500_001],
        };
        assert_eq!(s.received(), 3);
        assert_eq!(s.loss_pct(), 25);
        assert_eq!(s.rtt(), Some((500_000, 666_667, 1_000_000)));
        assert_eq!(fmt_ms(500_000), "0.500 ms");
        s.rtts.clear();
        assert_eq!(s.rtt(), None);
        assert_eq!(s.loss_pct(), 100);
        assert_eq!(s.fields()[3], ("rtt-min-ns".to_owned(), "0".to_owned()));
    }
}
