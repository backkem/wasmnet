//! traceroute: the classic UDP traceroute, as a wasmnet app.
//!
//! For each target, for TTL 1, 2, ...: send `queries` UDP probes with that unicast hop limit
//! (`udp-socket.set-unicast-hop-limit`, standard WASI) to destination ports 33434, 33435, ...
//! (one port per probe, so an ICMP error names its probe), and wait up to `wait` for the ICMP
//! error each one draws, read through `wasmnet:sockets-ext/udp.receive-error` (Linux's
//! `IP_RECVERR`): a router's **time exceeded** names that hop, the target's **port unreachable**
//! ends the trace. Other unreachables end it too, annotated like traceroute's `!N`, `!H`, `!X`,
//! `!P`, `!F`. Probes are sequential: the next one leaves when the previous one was answered or
//! timed out (traceroute's `-N 1`), which also keeps each probe's hop limit its own (the
//! netstack applies a socket's hop limit when a datagram leaves).
//!
//! # Config (`wasi:config`, keys under `app.traceroute.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `target` | a host name (the node's `hosts.<name>`) or an IP literal | |
//! | `targets` | several (a config array); `target` and `targets` add up, at least one is required | |
//! | `max-hops` | 1..=64 | `30` |
//! | `queries` | probes per hop, 1..=10 | `3` |
//! | `wait` | how long a probe waits for its ICMP error | `1s` |
//! | `port` | the first destination port | `33434` |
//! | `size` | probe payload bytes, 0..=1400 | `32` |
//! | `start` | virtual time of the first probe | `0` |
//! | `gap` | virtual time between two traces | `0` |
//!
//! # Journal (times in virtual ns)
//!
//! * `traceroute-start {target, address, max-hops, queries, packet-bytes}`;
//! * `traceroute-probe {target, ttl, probe, port, result, from, rtt-ns}`: `result` is
//!   `time-exceeded`, `reached`, `timeout` or an unreachable (`net-unreachable`, ...);
//! * `traceroute-hop {target, ttl, from, line}`: `from` is the hop's (first) reporter or `*`,
//!   `line` the traceroute output line;
//! * `traceroute-done {target, hops, reached, path}`: `path` lists each hop's reporter, `*` for
//!   a silent one.
//!
//! The log mimics traceroute's output. The app exits `ok` when every target was reached.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::net::IpAddr;
pub use wasmnet_app_kit::app_pairs;

use wasmnet_wire::parse_duration;

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "traceroute";

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
    pub targets: Vec<String>,
    pub max_hops: u8,
    pub queries: u8,
    pub wait_ns: u64,
    pub port: u16,
    pub size: usize,
    pub start_ns: u64,
    pub gap_ns: u64,
}

fn ranged<T: std::str::FromStr + PartialOrd>(v: &str, lo: T, hi: T) -> Option<T> {
    v.trim().parse::<T>().ok().filter(|n| *n >= lo && *n <= hi)
}

impl Config {
    /// Parses this app's pairs (prefix already stripped). Unknown keys are errors.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Self, ConfigError> {
        let mut c = Config {
            targets: Vec::new(),
            max_hops: 30,
            queries: 3,
            wait_ns: 1_000_000_000,
            port: 33434,
            size: 32,
            start_ns: 0,
            gap_ns: 0,
        };
        for (key, value) in pairs {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            match key.as_str() {
                "target" | "targets" => {
                    for t in value.split(',').map(str::trim) {
                        if t.is_empty() {
                            return Err(invalid("a host name or an IP address"));
                        }
                        c.targets.push(t.to_owned());
                    }
                }
                "max-hops" => {
                    c.max_hops = ranged(&value, 1, 64).ok_or_else(|| invalid("1..=64"))?
                }
                "queries" => c.queries = ranged(&value, 1, 10).ok_or_else(|| invalid("1..=10"))?,
                "wait" => {
                    c.wait_ns = parse_duration(&value)
                        .filter(|&n| n > 0)
                        .ok_or_else(|| invalid("a duration above zero like 1s"))?
                }
                "port" => c.port = ranged(&value, 1, 65_000).ok_or_else(|| invalid("1..=65000"))?,
                "size" => c.size = ranged(&value, 0, 1400).ok_or_else(|| invalid("0..=1400"))?,
                "start" => {
                    c.start_ns =
                        parse_duration(&value).ok_or_else(|| invalid("a duration like 10ms"))?
                }
                "gap" => {
                    c.gap_ns =
                        parse_duration(&value).ok_or_else(|| invalid("a duration like 1500ms"))?
                }
                _ => return Err(ConfigError::Unknown { key }),
            }
        }
        if c.targets.is_empty() {
            return Err(ConfigError::Missing {
                key: "target".to_owned(),
                expected: "a host name or an IP address to trace",
            });
        }
        Ok(c)
    }

    /// The destination port of probe number `seq` (0-based over the whole trace).
    pub fn probe_port(&self, seq: u32) -> u16 {
        self.port.wrapping_add(seq as u16)
    }
}

/// What one probe found out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A router on the way: ICMP time exceeded.
    TimeExceeded,
    /// The target itself answered (port unreachable): the trace is done.
    Reached,
    /// Another destination unreachable: the trace ends here, annotated.
    Unreachable(&'static str, &'static str),
    /// No answer within `wait`.
    Timeout,
}

impl Outcome {
    /// Classifies an ICMP error (raw type and code of the socket's family) from `reporter`,
    /// about a probe sent to `target`.
    pub fn of(v6: bool, icmp_type: u8, code: u8, reporter: IpAddr, target: IpAddr) -> Self {
        let port_unreachable = matches!((v6, icmp_type, code), (false, 3, 3) | (true, 1, 4));
        match (v6, icmp_type, code) {
            (false, 11, _) | (true, 3, _) => Outcome::TimeExceeded,
            _ if port_unreachable && reporter == target => Outcome::Reached,
            (false, 3, 0) | (true, 1, 0) => Outcome::Unreachable("net-unreachable", "!N"),
            (false, 3, 1) | (true, 1, 3) => Outcome::Unreachable("host-unreachable", "!H"),
            (false, 3, 2) => Outcome::Unreachable("protocol-unreachable", "!P"),
            (false, 3, 4) | (true, 2, _) => Outcome::Unreachable("frag-needed", "!F"),
            (false, 3, 9 | 10 | 13) | (true, 1, 1) => {
                Outcome::Unreachable("admin-prohibited", "!X")
            }
            (false, 3, 3) | (true, 1, 4) => Outcome::Unreachable("port-unreachable", "!P"),
            _ => Outcome::Unreachable("unreachable", "!"),
        }
    }

    /// The `result` field of `traceroute-probe`.
    pub fn name(self) -> &'static str {
        match self {
            Outcome::TimeExceeded => "time-exceeded",
            Outcome::Reached => "reached",
            Outcome::Unreachable(name, _) => name,
            Outcome::Timeout => "timeout",
        }
    }

    /// Whether the trace stops after this hop.
    pub fn ends_trace(self) -> bool {
        matches!(self, Outcome::Reached | Outcome::Unreachable(..))
    }
}

/// One probe's result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub outcome: Outcome,
    /// Who answered (`None`: nobody, a timeout).
    pub from: Option<IpAddr>,
    pub rtt_ns: u64,
}

/// `0.300 ms` (microsecond resolution, like traceroute's three decimals).
pub fn fmt_ms(ns: u64) -> String {
    format!("{}.{:03} ms", ns / 1_000_000, ns / 1_000 % 1_000)
}

/// A hop's output line, traceroute style: ` 2  10.0.12.2  0.600 ms  0.600 ms  *`. A reporter
/// is printed before its first time, and again whenever it changes within the hop.
pub fn hop_line(ttl: u8, probes: &[Probe]) -> String {
    let mut line = format!("{ttl:>2} ");
    let mut last: Option<IpAddr> = None;
    for p in probes {
        match p.from {
            None => line.push_str(" *"),
            Some(from) => {
                if last != Some(from) {
                    line.push_str(&format!(" {from}"));
                    last = Some(from);
                }
                line.push_str(&format!("  {}", fmt_ms(p.rtt_ns)));
                if let Outcome::Unreachable(_, note) = p.outcome {
                    line.push_str(&format!(" {note}"));
                }
            }
        }
    }
    line
}

/// The packet size traceroute prints: IP header + UDP header + payload.
pub fn packet_bytes(v6: bool, size: usize) -> usize {
    size + 8 + if v6 { 40 } else { 20 }
}

/// A probe's payload: recognisable bytes (`wasmnet traceroute` repeated).
pub fn payload(size: usize) -> Vec<u8> {
    b"wasmnet traceroute "
        .iter()
        .copied()
        .cycle()
        .take(size)
        .collect()
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
    fn config_defaults_and_errors() {
        let all = pairs(&[
            ("ipv4", "10.0.1.10/24"),
            ("app.traceroute.targets", "web,fd00:3::10"),
            ("app.traceroute.queries", "2"),
            ("app.traceroute.wait", "500ms"),
            ("app.traceroute.gap", "1200ms"),
        ]);
        let c = Config::from_pairs(app_pairs(all, APP)).unwrap();
        assert_eq!(c.targets, vec!["web", "fd00:3::10"]);
        assert_eq!((c.max_hops, c.queries, c.port, c.size), (30, 2, 33434, 32));
        assert_eq!((c.wait_ns, c.gap_ns), (500_000_000, 1_200_000_000));
        assert_eq!(c.probe_port(4), 33438);
        for (p, needle) in [
            (pairs(&[]), "required"),
            (pairs(&[("target", "a"), ("max-hops", "0")]), "max-hops"),
            (pairs(&[("target", "a"), ("queries", "11")]), "queries"),
            (pairs(&[("target", "a"), ("wait", "0")]), "wait"),
            (pairs(&[("target", "a"), ("colour", "red")]), "unknown"),
        ] {
            let e = Config::from_pairs(p).unwrap_err().to_string();
            assert!(e.contains(needle), "{e}");
        }
    }

    #[test]
    fn classifies_icmp_errors() {
        let (router, target): (IpAddr, IpAddr) =
            ("10.0.1.1".parse().unwrap(), "10.0.3.10".parse().unwrap());
        assert_eq!(
            Outcome::of(false, 11, 0, router, target),
            Outcome::TimeExceeded
        );
        assert_eq!(Outcome::of(false, 3, 3, target, target), Outcome::Reached);
        assert_eq!(
            Outcome::of(false, 3, 0, router, target),
            Outcome::Unreachable("net-unreachable", "!N")
        );
        assert_eq!(
            Outcome::of(false, 3, 3, router, target).name(),
            "port-unreachable",
            "a port unreachable from someone else is not the target"
        );
        let (r6, t6): (IpAddr, IpAddr) =
            ("fd00:1::1".parse().unwrap(), "fd00:3::10".parse().unwrap());
        assert_eq!(Outcome::of(true, 3, 0, r6, t6), Outcome::TimeExceeded);
        assert_eq!(Outcome::of(true, 1, 4, t6, t6), Outcome::Reached);
        assert_eq!(Outcome::of(true, 1, 3, r6, t6).name(), "host-unreachable");
        assert!(Outcome::Reached.ends_trace() && !Outcome::TimeExceeded.ends_trace());
        assert!(!Outcome::Timeout.ends_trace());
    }

    #[test]
    fn hop_lines_look_like_traceroute() {
        let a: IpAddr = "10.0.1.1".parse().unwrap();
        let b: IpAddr = "10.0.9.1".parse().unwrap();
        let p = |from: Option<IpAddr>, rtt_ns, outcome| Probe {
            outcome,
            from,
            rtt_ns,
        };
        let te = Outcome::TimeExceeded;
        assert_eq!(
            hop_line(
                1,
                &[
                    p(Some(a), 300_000, te),
                    p(Some(a), 300_000, te),
                    p(Some(a), 1_250_500, te)
                ]
            ),
            " 1  10.0.1.1  0.300 ms  0.300 ms  1.250 ms"
        );
        assert_eq!(
            hop_line(
                12,
                &[
                    p(None, 0, Outcome::Timeout),
                    p(Some(a), 1_000, te),
                    p(Some(b), 2_000, te)
                ]
            ),
            "12  * 10.0.1.1  0.001 ms 10.0.9.1  0.002 ms"
        );
        let n = Outcome::Unreachable("net-unreachable", "!N");
        assert_eq!(
            hop_line(3, &[p(Some(a), 500_000, n)]),
            " 3  10.0.1.1  0.500 ms !N"
        );
        assert_eq!(packet_bytes(false, 32), 60);
        assert_eq!(packet_bytes(true, 32), 80);
        assert_eq!(payload(10), b"wasmnet tr");
    }
}
