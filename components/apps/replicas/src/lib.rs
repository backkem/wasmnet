//! replicas: a small in-world controller that keeps `replicas` copies of a device running and
//! registered with a load balancer. It is an ordinary wasmnet app
//! (world `wasmnet:app/app`) that also imports `wasmnet:infra/devices`, which the host serves
//! only to a node the embedder marks as a controller (`DeviceOptions::infra`).
//!
//! Every `period` it compares what it wants (`replicas` instances named `<prefix>-1` ..
//! `<prefix>-N`, made from `template`) with what the world has (`wasmnet:infra`'s `list` of the
//! devices labelled `replicas=<prefix>`), and closes the gap: it applies missing or failed
//! instances, starts stopped ones (an operator's ×), removes the ones past `replicas`, and
//! registers running instances with the load balancer's admin API **over TCP on the network**
//! (deregistering the ones that stopped or go away). Its own changes are derived operator events
//! (journalled as `infra-*` on this node); what it observes comes from `watch`.
//!
//! Desired state comes from config, and live from **stdin**: a line `replicas=N` (what the
//! host delivers to the node's stdin, from an operator's console or a scripted input).
//!
//! # Config (`wasi:config`, keys under `app.replicas.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `replicas` | how many instances, `0..=max` | `1` |
//! | `max` | the most `replicas` may become (stdin included) | `16` |
//! | `prefix` | instance names `<prefix>-<n>` and their label `replicas=<prefix>` | `web` |
//! | `period` | virtual time between two reconciles | `500ms` |
//! | `start` | virtual time before the first reconcile | `0` |
//! | `grace` | a removed instance keeps running this long first (`stop` with grace) | `0` |
//! | `template.component` | the instances' catalog name (`node:http-server`) | required |
//! | `template.stdio` | `journal` or `capture` (anything else is a config error) | `capture` |
//! | `template.fuel_per_instant` | the instances' fuel per virtual instant (`50M`, `4G`) | the network's |
//! | `template.config.<key>` | the instances' config; values may use `{n}`, `{n+K}`, `{n:02x}`, `{name}`, `{prefix}` | |
//! | `template.wire.<i>.port`, `.to`, `.latency` | the instances' cables: own port, `device` (its first free port) or `device:port` (templated), latency | |
//! | `backend` | what to register for instance n (`10.0.1.{n}:80`); unset: no load balancer | |
//! | `lb` | the load balancer's admin address, `ipv4:port` | required with `backend` |
//! | `register` | the admin request that registers an instance: `METHOD /path` (templated, also `{backend}`) | `PUT /backends/{name}` |
//! | `register-body` | its body (templated; JSON if it starts with `{`) | `{backend}` |
//! | `deregister` | the admin request that deregisters one | `DELETE /backends/{name}` |
//! | `half-close` | `true`: each admin request leaves with its FIN right behind it (a client that half-closes early); `false`: the FIN goes after the response | `false` |
//!
//! # Journal
//!
//! `replicas-desired {replicas, from}` (from `config` or `stdin`), `replicas-observed {name, change,
//! phase}` for each watch event, `replicas-registered {name, backend, status}`,
//! `replicas-deregistered {name, status}`, `replicas-error {what, error}`; the `infra-*` events of
//! its calls come from the host.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::collections::{BTreeMap, BTreeSet};

use wasmnet_det_cbor as det_cbor;

use det_cbor::Value;
use wasmnet_wire::parse_duration;

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "replicas";

/// The label key of the instances.
pub const LABEL: &str = "replicas";

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

/// One cable of the template.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cable {
    pub port: u32,
    pub to: String,
    pub latency_ns: u64,
}

/// An HTTP request template: `METHOD /path`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestTemplate {
    pub method: String,
    pub target: String,
}

/// The load balancer to register with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lb {
    pub addr: std::net::SocketAddrV4,
    pub backend: String,
    pub register: RequestTemplate,
    pub register_body: String,
    pub deregister: RequestTemplate,
    /// Half-close with the request (`half-close = true`), not after the response.
    pub half_close: bool,
}

/// The parsed config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub replicas: u32,
    pub max: u32,
    pub prefix: String,
    pub period_ns: u64,
    pub start_ns: u64,
    pub grace_ns: u64,
    pub component: String,
    pub stdio: Option<String>,
    /// The instances' fuel per virtual instant (`template.fuel_per_instant`: `4G`, `50M`, a number).
    pub fuel: Option<u64>,
    pub config: BTreeMap<String, String>,
    pub wire: Vec<Cable>,
    pub lb: Option<Lb>,
}

fn invalid(key: &str, value: &str, expected: &'static str) -> ConfigError {
    ConfigError::Invalid {
        key: key.to_owned(),
        value: value.to_owned(),
        expected,
    }
}

fn request(key: &str, v: &str) -> Result<RequestTemplate, ConfigError> {
    let (m, t) = v
        .trim()
        .split_once(' ')
        .ok_or_else(|| invalid(key, v, "`METHOD /path`"))?;
    if m.is_empty() || !m.bytes().all(|b| b.is_ascii_uppercase()) || !t.starts_with('/') {
        return Err(invalid(key, v, "`METHOD /path`"));
    }
    Ok(RequestTemplate {
        method: m.to_owned(),
        target: t.trim().to_owned(),
    })
}

impl Config {
    /// The config from its `(key, value)` pairs (keys without the `app.replicas.` prefix).
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Config, ConfigError> {
        let mut c = Config {
            replicas: 1,
            max: 16,
            prefix: "web".to_owned(),
            period_ns: 500_000_000,
            start_ns: 0,
            grace_ns: 0,
            component: String::new(),
            stdio: None,
            fuel: None,
            config: BTreeMap::new(),
            wire: Vec::new(),
            lb: None,
        };
        let mut wire: BTreeMap<u32, Cable> = BTreeMap::new();
        let (mut lb, mut backend) = (None, None);
        // The defaults speak http-lb's admin API: `PUT /backends/<name>` with the address as
        // the body, `DELETE /backends/<name>`.
        let mut register = request("register", "PUT /backends/{name}")?;
        let mut deregister = request("deregister", "DELETE /backends/{name}")?;
        let mut register_body = "{backend}".to_owned();
        let mut half_close = false;
        let dur =
            |k: &str, v: &str| parse_duration(v.trim()).ok_or_else(|| invalid(k, v, "a duration"));
        for (k, v) in pairs {
            if let Some(key) = k.strip_prefix("template.config.") {
                c.config.insert(key.to_owned(), v);
                continue;
            }
            if let Some(rest) = k.strip_prefix("template.wire.") {
                let (i, field) = rest
                    .split_once('.')
                    .ok_or(ConfigError::Unknown { key: k.clone() })?;
                let i: u32 = i
                    .parse()
                    .map_err(|_| invalid(&k, &v, "template.wire.<index>.<field>"))?;
                let cable = wire.entry(i).or_default();
                match field {
                    "port" => {
                        cable.port = v
                            .trim()
                            .parse()
                            .map_err(|_| invalid(&k, &v, "a port number"))?
                    }
                    "to" => cable.to = v.trim().to_owned(),
                    "latency" => cable.latency_ns = dur(&k, &v)?,
                    _ => return Err(ConfigError::Unknown { key: k }),
                }
                continue;
            }
            match k.as_str() {
                "replicas" => {
                    c.replicas = v.trim().parse().map_err(|_| invalid(&k, &v, "a count"))?
                }
                "max" => c.max = v.trim().parse().map_err(|_| invalid(&k, &v, "a count"))?,
                "prefix" => {
                    let ok = !v.is_empty()
                        && v.len() <= 32
                        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
                    if !ok {
                        return Err(invalid(&k, &v, "letters, digits and `-`"));
                    }
                    c.prefix = v;
                }
                "period" => c.period_ns = dur(&k, &v)?.max(1),
                "start" => c.start_ns = dur(&k, &v)?,
                "grace" => c.grace_ns = dur(&k, &v)?,
                "template.component" => c.component = v.trim().to_owned(),
                "template.stdio" => match v.trim() {
                    s @ ("journal" | "capture") => c.stdio = Some(s.to_owned()),
                    _ => return Err(invalid(&k, &v, "journal or capture")),
                },
                "template.fuel_per_instant" => {
                    c.fuel = Some(
                        fuel(v.trim())
                            .ok_or_else(|| invalid(&k, &v, "a count, or with K, M or G"))?,
                    );
                }
                "backend" => backend = Some(v.trim().to_owned()),
                "lb" => lb = Some(v.trim().parse().map_err(|_| invalid(&k, &v, "ipv4:port"))?),
                "register" => register = request(&k, &v)?,
                "register-body" => register_body = v,
                "deregister" => deregister = request(&k, &v)?,
                "half-close" => {
                    half_close = match v.trim() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(invalid(&k, &v, "true or false")),
                    }
                }
                _ => return Err(ConfigError::Unknown { key: k }),
            }
        }
        if c.component.is_empty() {
            return Err(ConfigError::Missing {
                key: "template.component".to_owned(),
                expected: "the instances' catalog name",
            });
        }
        if c.replicas > c.max {
            return Err(invalid(
                "replicas",
                &c.replicas.to_string(),
                "at most `max`",
            ));
        }
        c.wire = wire.into_values().collect();
        if c.wire.iter().any(|w| w.to.is_empty()) {
            return Err(ConfigError::Missing {
                key: "template.wire.<i>.to".to_owned(),
                expected: "the far device",
            });
        }
        c.lb = match (backend, lb) {
            (None, _) => None,
            (Some(backend), Some(addr)) => Some(Lb {
                addr,
                backend,
                register,
                register_body,
                deregister,
                half_close,
            }),
            (Some(_), None) => {
                return Err(ConfigError::Missing {
                    key: "lb".to_owned(),
                    expected: "the load balancer's admin address, ipv4:port",
                });
            }
        };
        Ok(c)
    }

    /// Instance `n`'s name.
    pub fn name(&self, n: u32) -> String {
        format!("{}-{n}", self.prefix)
    }

    /// The index of an instance name of ours.
    pub fn index(&self, name: &str) -> Option<u32> {
        name.strip_prefix(&self.prefix)?
            .strip_prefix('-')?
            .parse()
            .ok()
            .filter(|&n| n > 0)
    }

    /// `text` with `{n}`, `{n:02x}`, `{name}`, `{prefix}` (and `extra`) filled in for instance n.
    pub fn expand(&self, text: &str, n: u32, extra: &[(&str, &str)]) -> String {
        let name = self.name(n);
        let mut out = text
            .replace("{n:02x}", &format!("{n:02x}"))
            .replace("{n}", &n.to_string())
            .replace("{name}", &name)
            .replace("{prefix}", &self.prefix);
        for (k, v) in extra {
            out = out.replace(&format!("{{{k}}}"), v);
        }
        // `{n+K}`: the instance number plus K (`10.0.1.{n+10}`), as the fleet panel writes it.
        while let Some(i) = out.find("{n+") {
            let Some(j) = out[i..].find('}') else {
                break;
            };
            let Ok(k) = out[i + 3..i + j].parse::<u32>() else {
                break;
            };
            out.replace_range(i..=i + j, &(n + k).to_string());
        }
        out
    }

    /// Instance `n`'s device spec, CBOR (`wit/infra/infra.wit`).
    pub fn spec(&self, n: u32) -> Vec<u8> {
        let config = self
            .config
            .iter()
            .map(|(k, v)| (Value::text(k.as_str()), Value::text(self.expand(v, n, &[]))))
            .collect();
        let mut m = vec![
            (
                Value::text("component"),
                Value::text(self.component.as_str()),
            ),
            (Value::text("config"), Value::Map(config)),
        ];
        if let Some(s) = &self.stdio {
            m.push((Value::text("stdio"), Value::text(s.as_str())));
        }
        if let Some(f) = self.fuel {
            m.push((Value::text("fuel_per_instant"), Value::Uint(f)));
        }
        if !self.wire.is_empty() {
            let cables = self
                .wire
                .iter()
                .map(|w| {
                    let mut e = vec![
                        (Value::text("port"), Value::Uint(u64::from(w.port))),
                        (Value::text("to"), Value::text(self.expand(&w.to, n, &[]))),
                    ];
                    if w.latency_ns > 0 {
                        e.push((Value::text("latency"), Value::Uint(w.latency_ns)));
                    }
                    Value::Map(e)
                })
                .collect();
            m.push((Value::text("wire"), Value::Array(cables)));
        }
        Value::Map(m).encode()
    }

    /// The instances' labels.
    pub fn labels(&self) -> Vec<(String, String)> {
        vec![(LABEL.to_owned(), self.prefix.clone())]
    }

    /// What to register for instance `n` (none without a load balancer).
    pub fn backend(&self, n: u32) -> Option<String> {
        self.lb.as_ref().map(|lb| self.expand(&lb.backend, n, &[]))
    }

    /// The admin request head (and body) that registers (`up`) or deregisters instance `n`.
    pub fn admin_request(&self, n: u32, up: bool) -> Option<Vec<u8>> {
        let lb = self.lb.as_ref()?;
        let backend = self.backend(n).unwrap_or_default();
        let vars = [("backend", backend.as_str())];
        let t = if up { &lb.register } else { &lb.deregister };
        let target = self.expand(&t.target, n, &vars);
        let body = if up {
            self.expand(&lb.register_body, n, &vars)
        } else {
            String::new()
        };
        let mut head = format!(
            "{} {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: wasmnet-replicas\r\nConnection: close\r\nContent-Length: {}\r\n",
            t.method,
            lb.addr,
            body.len()
        );
        if body.starts_with('{') {
            head.push_str("Content-Type: application/json\r\n");
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(body.as_bytes());
        Some(out)
    }
}

/// `4G`, `50M`, `500K` or a plain number.
fn fuel(v: &str) -> Option<u64> {
    let (digits, mult) = match v.as_bytes().last()? {
        b'K' => (&v[..v.len() - 1], 1_000),
        b'M' => (&v[..v.len() - 1], 1_000_000),
        b'G' => (&v[..v.len() - 1], 1_000_000_000),
        _ => (v, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(mult)
}

/// A desired-state line from stdin: `replicas=N` (spaces allowed around `=`).
pub fn parse_line(line: &str, max: u32) -> Option<u32> {
    let (k, v) = line.trim().split_once('=')?;
    if k.trim() != "replicas" {
        return None;
    }
    v.trim().parse().ok().filter(|&n| n <= max)
}

/// Splits complete lines off `buf` (the rest stays for the next read).
pub fn take_lines(buf: &mut Vec<u8>) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(i) = buf.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = buf.drain(..=i).collect();
        out.push(String::from_utf8_lossy(&line).trim_end().to_owned());
    }
    out
}

/// The status code of an HTTP response (its first line), if it has one.
pub fn status_of(response: &[u8]) -> Option<u16> {
    let line = response.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// What the controller sees of an instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    Pending,
    Running,
    Stopped,
    Failed,
    /// Being removed (its queued requests lead there).
    Leaving,
}

/// One reconcile step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Apply instance n (missing, or its creation failed).
    Apply(u32),
    Start(String),
    /// Take it out of the load balancer.
    Deregister(String, u32),
    Register(String, u32),
    /// Stop (with grace) and remove.
    Remove(String),
}

/// The steps from what the world has (`seen`, by name) to `desired` instances, given which are
/// registered. Deregistering comes before removing, registering after everything else.
pub fn plan(
    c: &Config,
    desired: u32,
    seen: &BTreeMap<String, Seen>,
    registered: &BTreeSet<String>,
) -> Vec<Action> {
    let mut out = Vec::new();
    let wanted: BTreeSet<String> = (1..=desired).map(|n| c.name(n)).collect();
    // Out of service first: registered but not running and wanted.
    for name in registered {
        let up = wanted.contains(name) && seen.get(name) == Some(&Seen::Running);
        if !up && let Some(n) = c.index(name) {
            out.push(Action::Deregister(name.clone(), n));
        }
    }
    for (name, s) in seen {
        if !wanted.contains(name) && *s != Seen::Leaving {
            out.push(Action::Remove(name.clone()));
        }
    }
    for n in 1..=desired {
        let name = c.name(n);
        match seen.get(&name) {
            None | Some(Seen::Failed) => out.push(Action::Apply(n)),
            Some(Seen::Stopped) => out.push(Action::Start(name)),
            // A leaving namesake (scaled down, then up again before it went): apply anew.
            Some(Seen::Leaving) => out.push(Action::Apply(n)),
            Some(Seen::Pending | Seen::Running) => {}
        }
    }
    if c.lb.is_some() {
        for n in 1..=desired {
            let name = c.name(n);
            if seen.get(&name) == Some(&Seen::Running) && !registered.contains(&name) {
                out.push(Action::Register(name, n));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(extra: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut v = vec![
            ("template.component", "node:http-server"),
            ("template.config.ipv4", "10.0.1.{n}/24"),
            ("template.config.mac", "02:00:00:00:02:{n:02x}"),
            ("template.wire.0.port", "0"),
            ("template.wire.0.to", "sw"),
            ("template.wire.0.latency", "50us"),
        ];
        v.extend_from_slice(extra);
        v.into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    #[test]
    fn config_and_templates() {
        let c = Config::from_pairs(pairs(&[
            ("replicas", "3"),
            ("backend", "10.0.1.{n}:80"),
            ("lb", "10.0.0.2:9000"),
        ]))
        .expect("valid");
        assert_eq!(c.replicas, 3);
        assert_eq!(c.name(12), "web-12");
        assert_eq!(c.index("web-12"), Some(12));
        assert_eq!(c.index("webx-1"), None);
        assert_eq!(c.expand("02:{n:02x}", 12, &[]), "02:0c");
        assert_eq!(c.expand("10.0.1.{n+10}:{n}", 2, &[]), "10.0.1.12:2");
        let spec = det_cbor::decode(&c.spec(2)).expect("cbor");
        assert_eq!(
            spec.get("config")
                .and_then(|m| m.get("ipv4"))
                .and_then(Value::as_text),
            Some("10.0.1.2/24")
        );
        // The defaults speak http-lb's admin API: the address is the body.
        let head = String::from_utf8(c.admin_request(2, true).expect("lb")).expect("utf8");
        assert!(
            head.starts_with("PUT /backends/web-2 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(
            head.ends_with("Content-Length: 11\r\n\r\n10.0.1.2:80"),
            "{head}"
        );
        let head = String::from_utf8(c.admin_request(2, false).expect("lb")).expect("utf8");
        assert!(
            head.starts_with("DELETE /backends/web-2 HTTP/1.1\r\n") && head.ends_with("\r\n\r\n"),
            "{head}"
        );
        // An explicit request and body replace both defaults.
        let custom = Config::from_pairs(pairs(&[
            ("backend", "10.0.1.{n}:80"),
            ("lb", "10.0.0.2:9000"),
            ("register", "POST /backends/{name}?addr={backend}"),
            ("register-body", ""),
        ]))
        .expect("valid");
        let head = String::from_utf8(custom.admin_request(2, true).expect("lb")).expect("utf8");
        assert!(
            head.starts_with("POST /backends/web-2?addr=10.0.1.2:80 HTTP/1.1\r\n")
                && head.ends_with("Content-Length: 0\r\n\r\n"),
            "{head}"
        );
        assert!(Config::from_pairs(pairs(&[("template.stdio", "journal")])).is_ok());
        assert!(Config::from_pairs(pairs(&[("template.stdio", "tty")])).is_err());
        assert!(!c.lb.as_ref().expect("lb").half_close);
        let early = Config::from_pairs(pairs(&[
            ("backend", "10.0.1.{n}:80"),
            ("lb", "10.0.0.2:9000"),
            ("half-close", "true"),
        ]))
        .expect("valid");
        assert!(early.lb.expect("lb").half_close);
        assert!(Config::from_pairs(pairs(&[("half-close", "yes")])).is_err());
        assert!(Config::from_pairs(pairs(&[("backend", "x")])).is_err());
        assert!(Config::from_pairs(pairs(&[("bogus", "1")])).is_err());
        assert!(Config::from_pairs(vec![]).is_err());
    }

    #[test]
    fn stdin_lines() {
        let mut buf = b"replicas=4\nreplicas = 2\r\nnoise\nrepl".to_vec();
        let lines = take_lines(&mut buf);
        assert_eq!(buf, b"repl");
        let got: Vec<_> = lines.iter().map(|l| parse_line(l, 16)).collect();
        assert_eq!(got, [Some(4), Some(2), None]);
        assert_eq!(parse_line("replicas=99", 16), None);
        assert_eq!(status_of(b"HTTP/1.1 204 No Content\r\n"), Some(204));
    }

    #[test]
    fn plans_converge() {
        let c = Config::from_pairs(pairs(&[
            ("backend", "10.0.1.{n}:80"),
            ("lb", "10.0.0.2:9000"),
        ]))
        .expect("valid");
        let mut seen = BTreeMap::new();
        let reg = BTreeSet::new();
        assert_eq!(
            plan(&c, 2, &seen, &reg),
            [Action::Apply(1), Action::Apply(2)]
        );
        seen.insert("web-1".to_owned(), Seen::Running);
        seen.insert("web-2".to_owned(), Seen::Stopped);
        seen.insert("web-3".to_owned(), Seen::Running);
        let reg: BTreeSet<String> = ["web-2".to_owned(), "web-3".to_owned()].into();
        assert_eq!(
            plan(&c, 2, &seen, &reg),
            [
                Action::Deregister("web-2".into(), 2),
                Action::Deregister("web-3".into(), 3),
                Action::Remove("web-3".into()),
                Action::Start("web-2".into()),
                Action::Register("web-1".into(), 1),
            ]
        );
    }
}
