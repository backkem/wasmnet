//! service-browse: browses DNS-SD service types over Multicast DNS with the app kit's browser
//! ([`wasmnet_app_kit::mdns`]), resolves the instances it finds, reports all of it as journal
//! events, and can fetch `GET <path>` from one instance by the address and port it resolved.
//! It never returns: a daemon.
//!
//! # Config (`wasi:config`, keys under `app.service-browse.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `type` | the service types to browse, a list (`_http._tcp,_ipp._tcp`) | required |
//! | `families` | the groups to query on: `ipv4` (224.0.0.251), `ipv6` (ff02::fb), or both | `ipv4,ipv6` |
//! | `resolve` | `all`, `none`, or a list of instance names to resolve when found (`\,` is a comma) | `all` |
//! | `fetch` | an instance name: once it resolves, fetch from it over HTTP, once | none |
//! | `fetch-path` | the path to fetch, starting with `/` | `/` |
//! | `start` | virtual time to wait before browsing | `0` |
//!
//! It binds port 5353 (so responders answer it by multicast and it hears every announcement);
//! when another app of the node holds that port it binds any port instead and gets unicast
//! answers (RFC 6762 §6.7), and logs that it did.
//!
//! # Journal
//!
//! `dnssd-found {type, instance}`, `dnssd-removed {type, instance, reason}` (`goodbye` or
//! `expired`), `dnssd-resolved {instance, host, port, txt, addresses}` (each time a resolution
//! completes or changes), `dnssd-fetched {instance, address, port, status, body-bytes}` or
//! `dnssd-fetch-failed {instance, address, error}`.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

pub use wasmnet_app_kit::app_pairs;
use wasmnet_app_kit::mdns::{Event, Resolved};
use wasmnet_wire::dns;
use wasmnet_wire::parse_duration;

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "service-browse";

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

/// Which instances to resolve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvePolicy {
    All,
    None,
    /// These instance names (compared without ASCII case).
    Only(Vec<String>),
}

/// The parsed config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub types: Vec<String>,
    pub ipv4: bool,
    pub ipv6: bool,
    pub resolve: ResolvePolicy,
    pub fetch: Option<String>,
    pub fetch_path: String,
    pub start_ns: u64,
}

/// Splits a list at commas that are not escaped (`\,`), each item trimmed.
pub fn split_list(value: &str) -> Vec<String> {
    let mut items = vec![String::new()];
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        let item = items.last_mut().expect("never empty");
        match c {
            '\\' => match chars.next() {
                Some(',') => item.push(','),
                Some(other) => {
                    item.push('\\');
                    item.push(other);
                }
                None => item.push('\\'),
            },
            ',' => items.push(String::new()),
            c => item.push(c),
        }
    }
    items.into_iter().map(|i| i.trim().to_owned()).collect()
}

impl Config {
    /// Parses this app's pairs (prefix already stripped). Unknown keys are errors.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Self, ConfigError> {
        let mut c = Config {
            types: Vec::new(),
            ipv4: true,
            ipv6: true,
            resolve: ResolvePolicy::All,
            fetch: None,
            fetch_path: "/".into(),
            start_ns: 0,
        };
        for (key, value) in pairs {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            match key.as_str() {
                "type" => {
                    let types: Vec<String> = value
                        .split(',')
                        .map(|t| t.trim().to_ascii_lowercase())
                        .collect();
                    if !types.iter().all(|t| dns::valid_service_type(t)) {
                        return Err(invalid("service types like _http._tcp, comma-separated"));
                    }
                    c.types = types;
                }
                "families" => {
                    let list: Vec<&str> = value.split(',').map(str::trim).collect();
                    if list.iter().any(|f| *f != "ipv4" && *f != "ipv6") {
                        return Err(invalid("ipv4, ipv6 or both"));
                    }
                    c.ipv4 = list.contains(&"ipv4");
                    c.ipv6 = list.contains(&"ipv6");
                }
                "resolve" => {
                    c.resolve = match value.as_str() {
                        "all" => ResolvePolicy::All,
                        "none" => ResolvePolicy::None,
                        _ => {
                            let names = split_list(&value);
                            if !names.iter().all(|n| dns::valid_instance(n)) {
                                return Err(invalid("all, none, or instance names"));
                            }
                            ResolvePolicy::Only(names)
                        }
                    };
                }
                "fetch" => {
                    if !dns::valid_instance(&value) {
                        return Err(invalid("an instance name"));
                    }
                    c.fetch = Some(value);
                }
                "fetch-path" => {
                    if !value.starts_with('/') || value.contains([' ', '\r', '\n']) {
                        return Err(invalid("a path starting with /, no spaces"));
                    }
                    c.fetch_path = value;
                }
                "start" => {
                    c.start_ns = parse_duration(&value).ok_or_else(|| invalid("a duration"))?;
                }
                _ => return Err(ConfigError::Unknown { key }),
            }
        }
        if c.types.is_empty() {
            return Err(ConfigError::Missing {
                key: "type".into(),
                expected: "the service types to browse, like _http._tcp",
            });
        }
        Ok(c)
    }

    /// Whether to resolve this instance when it is found: the policy says so, or it is the one
    /// to fetch from.
    pub fn wants(&self, instance: &str) -> bool {
        let fetch = self
            .fetch
            .as_deref()
            .is_some_and(|f| f.eq_ignore_ascii_case(instance));
        fetch
            || match &self.resolve {
                ResolvePolicy::All => true,
                ResolvePolicy::None => false,
                ResolvePolicy::Only(names) => {
                    names.iter().any(|n| n.eq_ignore_ascii_case(instance))
                }
            }
    }

    /// The seed of the browser's jitter: a hash of the types, so the timeline does not move with
    /// the network's seed (two browsers of the same types still spread out by their start).
    pub fn seed(&self) -> u64 {
        let mut h = wasmnet_app_kit::Fnv::default();
        for t in &self.types {
            h.update(t.as_bytes());
            h.update(b",");
        }
        h.0
    }
}

/// One journal event: kind and fields.
pub type Note = (&'static str, Vec<(String, String)>);

fn kv(k: &str, v: impl ToString) -> (String, String) {
    (k.to_owned(), v.to_string())
}

/// The journal event for a browser event.
pub fn note(e: &Event) -> Note {
    match e {
        Event::Found {
            service_type,
            instance,
            ..
        } => (
            "dnssd-found",
            vec![kv("type", service_type), kv("instance", instance)],
        ),
        Event::Removed {
            service_type,
            instance,
            reason,
            ..
        } => (
            "dnssd-removed",
            vec![
                kv("type", service_type),
                kv("instance", instance),
                kv("reason", reason.as_str()),
            ],
        ),
        Event::Resolved(r) => (
            "dnssd-resolved",
            vec![
                kv("instance", &r.instance),
                kv("host", &r.host),
                kv("port", r.port),
                kv("txt", r.attributes_text()),
                kv(
                    "addresses",
                    r.addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        ),
        // An event a later browser reports and this app does not know yet.
        _ => ("dnssd-event", Vec::new()),
    }
}

/// The HTTP/1.1 request for `path` on a resolved instance (one request, then the server closes).
pub fn request(r: &Resolved, path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        r.host.trim_end_matches('.'),
        r.port
    )
    .into_bytes()
}

/// The status code and the body's length of a whole response read to the end, or `None` when
/// it has no complete status line and head.
pub fn response(bytes: &[u8]) -> Option<(u16, usize)> {
    let head_end = bytes.windows(4).position(|w| w == b"\r\n\r\n")?;
    let line_end = bytes.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&bytes[..line_end]).ok()?;
    let mut parts = line.split(' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let status = parts.next()?.parse().ok()?;
    Some((status, bytes.len() - head_end - 4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmnet_app_kit::mdns::Removal;

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn config_keys_and_errors() {
        let c = Config::from_pairs(pairs(&[
            ("type", "_HTTP._tcp, _ipp._tcp"),
            ("families", "ipv4"),
            ("resolve", "Alpha Web, Beta\\, the second"),
            ("fetch", "Gamma"),
            ("fetch-path", "/index.html"),
            ("start", "2s"),
        ]))
        .unwrap();
        assert_eq!(c.types, ["_http._tcp", "_ipp._tcp"]);
        assert!(c.ipv4 && !c.ipv6);
        assert_eq!(
            c.resolve,
            ResolvePolicy::Only(vec!["Alpha Web".into(), "Beta, the second".into()])
        );
        assert!(c.wants("alpha web") && c.wants("Gamma") && !c.wants("Delta"));
        assert_eq!(c.start_ns, 2_000_000_000);
        let all = Config::from_pairs(pairs(&[("type", "_http._tcp")])).unwrap();
        assert!(all.wants("anything") && all.ipv4 && all.ipv6);
        assert_ne!(all.seed(), c.seed());
        for (p, needle) in [
            (pairs(&[]), "type"),
            (pairs(&[("type", "http")]), "_http._tcp"),
            (
                pairs(&[("type", "_http._tcp"), ("fetch-path", "x")]),
                "path",
            ),
            (
                pairs(&[("type", "_http._tcp"), ("families", "ipx")]),
                "families",
            ),
            (
                pairs(&[("type", "_http._tcp"), ("colour", "red")]),
                "unknown",
            ),
        ] {
            let err = Config::from_pairs(p).unwrap_err().to_string();
            assert!(err.contains(needle), "{err}");
        }
    }

    fn resolved() -> Resolved {
        Resolved::new("Alpha Web._http._tcp.local", "Alpha Web", "alpha.local", 80)
            .txt(vec![b"path=/".to_vec(), b"secure".to_vec()])
            .addresses(vec![
                "10.0.0.10".parse().unwrap(),
                "fd00::10".parse().unwrap(),
            ])
    }

    #[test]
    fn events_become_journal_notes() {
        let n = note(&Event::Resolved(resolved()));
        assert_eq!(n.0, "dnssd-resolved");
        assert!(n.1.contains(&kv("txt", "path=/,secure")));
        assert!(n.1.contains(&kv("addresses", "10.0.0.10,fd00::10")));
        let n = note(&Event::Removed {
            service_type: "_http._tcp".into(),
            instance: "Alpha Web".into(),
            name: "Alpha Web._http._tcp.local".into(),
            reason: Removal::Goodbye,
        });
        assert!(n.1.contains(&kv("reason", "goodbye")));
    }

    #[test]
    fn a_request_and_its_response() {
        assert_eq!(
            request(&resolved(), "/"),
            b"GET / HTTP/1.1\r\nHost: alpha.local:80\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
            Some((200, 5))
        );
        assert_eq!(response(b"HTTP/1.1 404 Not Found\r\n\r\n"), Some((404, 0)));
        assert_eq!(response(b"HTTP/1.1 200 OK\r\n"), None);
        assert_eq!(response(b"SSH-2.0\r\n\r\n"), None);
        assert_eq!(split_list("a\\,b, c ,"), ["a,b", "c", ""]);
    }
}
