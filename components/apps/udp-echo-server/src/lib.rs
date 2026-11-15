//! udp-echo-server: a wasmnet app that sends every UDP datagram it receives straight back to
//! its sender (RFC 862 style), forever: a daemon.
//!
//! # Config (`wasi:config`, keys under `app.udp-echo-server.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `listen` | the local socket address, `0.0.0.0:7` or `[::]:7` | `0.0.0.0:7` |
//! | `count` | exit after echoing this many datagrams (1..) | never: a daemon |
//! | `copies` | how many times each datagram is sent back, 1..=16 (more than 1 is a duplicating server: back-to-back `send`s, used by a lost-wake regression test) | `1` |
//!
//! # Journal
//!
//! * `udp-echo-listening {address}` once bound;
//! * `udp-echoed {peer, bytes}` per datagram (a log line too).
//!
//! The glue (`component.rs`) is a few lines of `wasip3` socket calls; everything that can be
//! decided without a socket lives here.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::net::SocketAddr;
pub use wasmnet_app_kit::app_pairs;

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "udp-echo-server";

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
}

/// The parsed config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    /// `None`: serve forever.
    pub count: Option<u32>,
    /// Echoes sent back per datagram.
    pub copies: u32,
}

impl Config {
    /// Parses this app's pairs (prefix already stripped). Unknown keys are errors.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Self, ConfigError> {
        let mut config = Config {
            listen: SocketAddr::from(([0, 0, 0, 0], 7)),
            count: None,
            copies: 1,
        };
        for (key, value) in pairs {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            match key.as_str() {
                "listen" => {
                    config.listen = value
                        .parse()
                        .map_err(|_| invalid("a socket address like 0.0.0.0:7 or [::]:7"))?;
                }
                "count" => {
                    let n: u32 = value
                        .parse()
                        .ok()
                        .filter(|&n| n > 0)
                        .ok_or_else(|| invalid("a datagram count of at least 1"))?;
                    config.count = Some(n);
                }
                "copies" => {
                    config.copies = value
                        .parse()
                        .ok()
                        .filter(|n| (1..=16).contains(n))
                        .ok_or_else(|| invalid("1..=16 echoes per datagram"))?;
                }
                _ => return Err(ConfigError::Unknown { key }),
            }
        }
        Ok(config)
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
    fn defaults_prefix_and_errors() {
        let all = pairs(&[
            ("ipv4", "10.0.0.1/24"),
            ("app.udp-echo-server.listen", "[::]:9"),
            ("app.udp-echo-client.count", "3"),
        ]);
        let mine = app_pairs(all, APP);
        assert_eq!(mine, pairs(&[("listen", "[::]:9")]));
        let c = Config::from_pairs(mine).unwrap();
        assert_eq!(c.listen, "[::]:9".parse().unwrap());
        assert_eq!(c.count, None);
        let d = Config::from_pairs(Vec::new()).unwrap();
        assert_eq!(
            (d.listen.to_string(), d.count),
            ("0.0.0.0:7".to_owned(), None)
        );
        assert_eq!(
            Config::from_pairs(pairs(&[("count", "2")])).unwrap().count,
            Some(2)
        );
        for (p, needle) in [
            (pairs(&[("listen", "7")]), "listen"),
            (pairs(&[("count", "0")]), "count"),
            (pairs(&[("copies", "0")]), "copies"),
            (pairs(&[("colour", "red")]), "unknown"),
        ] {
            let err = Config::from_pairs(p).unwrap_err().to_string();
            assert!(err.contains(needle), "{err}");
        }
    }
}
