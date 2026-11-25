//! http-server: a tiny HTTP/1.1 server, as a wasmnet app. It listens on a
//! `wasi:sockets@0.3.0` TCP socket, serves static routes from its config plus a generated body
//! (`GET /big?n=<bytes>`), keeps connections alive, serves several connections at once, and
//! never returns: a daemon.
//!
//! # Config (`wasi:config`, keys under `app.http-server.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `listen` | the local socket address, `0.0.0.0:80` or `[::]:80`; or a list, one listener each: `["10.0.1.10:80", "[fd00:1::10]:80"]` serves both families (a listener serves its own family only: `0.0.0.0` is IPv4, `[::]` is IPv6) | `0.0.0.0:80` |
//! | `backlog` | the listen backlog hint (`set-listen-backlog-size`), 1..=1024 | the netstack's |
//! | `keep-alive` | `true`: honour persistent connections (HTTP/1.1 default, `Connection: keep-alive` on 1.0); `false`: `Connection: close` after every response | `true` |
//! | `max-requests` | requests per connection before the server closes it, 1..=100000 | `100` |
//! | `no-delay` | `true`: `TCP_NODELAY` on every accepted connection (`wasmnet:sockets-ext/tcp`) | `false` |
//! | `recv-buffer`, `send-buffer` | the listener's socket buffer sizes in bytes (inherited by accepted connections) | the netstack's |
//! | `big-max` | the largest `/big?n=` body, bytes | `16777216` |
//! | `route.<name>.path` | a route's path, `/` or `/about` (required per route) | |
//! | `route.<name>.body` | its body text; `{args}` is replaced by the node's arguments after `argv[0]` (one space between them) and `{env:NAME}` by its environment variable `NAME` (empty if unset), both from `wasi:cli/environment` | `""` |
//! | `route.<name>.body-base64` | its body as standard base64 (with `=` padding), for a binary body such as a component a store node serves; never templated; replaces `body` | |
//! | `route.<name>.type` | its `Content-Type` | `text/plain` |
//! | `route.<name>.sse-events` | (embedder surface, unstable) makes the route an event stream (`text/event-stream`): events `1..=N`, see [`Sse`]; `GET` only | |
//! | `route.<name>.sse-interval-ms` | the virtual time between two events, `0..=60000` | `1000` |
//! | `instance`, `version` | the instance's name and version: sent as `X-Instance` and `X-Version` on every response; `{instance}` and `{version}` in route bodies are replaced; without routes, `GET /` answers `<instance> <version>` | none |
//! | `health` | a health route's path: `GET` answers `503 not ready` until `ready-after`, then `200 ok` | `/healthz` with `ready-after`, else none |
//! | `ready-after` | virtual time after the app started before the health route answers `200` | `0` |
//!
//! Without any route the server answers `GET /` with `hello from wasmnet\n`. `GET /big?n=N`
//! answers N bytes of a position-dependent pattern ([`pattern`]), generated chunk by chunk as
//! the connection drains. Only `GET` is served (`405` otherwise), plus `POST /echo` (embedder
//! surface, unstable), which answers
//! its body back (at most 1 MiB); an unknown path is `404`, a
//! malformed request `400` (then the connection closes).
//!
//! An event-stream route answers `GET` with `Content-Type: text/event-stream`, no
//! `Content-Length` and `Connection: close`, then writes `id: <k>` / `data: tick <k>` / a blank
//! line for each event, one interval (virtual time) apart, and closes the connection after the
//! last. A `Last-Event-ID: <n>` request header starts at event `n + 1` ([`resume_from`]).
//!
//! # Journal
//!
//! * `http-listening {address, backlog}`;
//! * `http-accepted {conn, peer}` per connection (`conn` counts from 1);
//! * `http-request {conn, method, target, version}`;
//! * `http-response {conn, status, bytes, body-bytes, body-fnv, keep-alive}` once the whole
//!   response went into the connection's send stream (`body-fnv`: FNV-1a 64 of the body, hex);
//!   for an event stream, once its last event went in (or a write failed);
//! * `http-closed {conn, peer, requests, reason, send}`: `reason` is `peer-closed` (the client's
//!   FIN), `close` (the server ended it), `bad-request` or `error`; `send` is how the send
//!   future resolved (`ok`, or the error code).
//!
//! Everything that can be decided without a socket lives here; the glue (`component.rs`) moves
//! bytes.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::net::SocketAddr;
pub use wasmnet_app_kit::{Fnv, app_pairs, error_name};

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "http-server";

/// `Server:` header.
pub const SERVER: &str = "wasmnet-http-server";

/// The media type of an event-stream route (`sse-events`).
pub const EVENT_STREAM: &str = "text/event-stream";

/// The virtual time between two events when `sse-interval-ms` is not set.
pub const SSE_INTERVAL_MS: u64 = 1000;

/// The body of `GET /` when no route is configured.
pub const DEFAULT_BODY: &str = "hello from wasmnet\n";

/// Bytes of a generated body per write.
pub const CHUNK: usize = 16 * 1024;

/// How many of `remaining` bytes fit in `available`. `remaining` comes from a peer (a
/// `Content-Length`, a query parameter) and is 64 bits wide; a component's `usize` is 32, so the
/// comparison is made before the narrowing, never after it.
pub fn take_len(remaining: u64, available: usize) -> usize {
    remaining.min(available as u64) as usize
}

/// The largest request head the server reads before answering `400`.
pub const MAX_HEAD: usize = 16 * 1024;

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

/// An event-stream route: events `1..=events`, `interval_ms` apart in virtual time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sse {
    pub events: u64,
    pub interval_ms: u64,
}

/// One route: static (`body`), or an event stream (`sse`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub path: String,
    pub body: Vec<u8>,
    pub content_type: String,
    pub sse: Option<Sse>,
    /// The body came from `body-base64`: bytes, never templated.
    pub raw: bool,
}

/// The parsed config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// At least one; each gets its own listener.
    pub listen: Vec<SocketAddr>,
    pub backlog: Option<u64>,
    pub keep_alive: bool,
    pub max_requests: u32,
    pub no_delay: bool,
    pub recv_buffer: Option<u64>,
    pub send_buffer: Option<u64>,
    pub big_max: u64,
    /// In route-name order.
    pub routes: Vec<Route>,
    /// The instance's name and version: `X-Instance` and `X-Version` on every
    /// response, and `{instance}` / `{version}` in route bodies.
    pub instance: Option<String>,
    pub version: Option<String>,
    /// The health route: `503` until `ready_after_ns` of virtual time after the app started,
    /// then `200`.
    pub health: Option<String>,
    pub ready_after_ns: u64,
}

fn ranged(v: &str, lo: u64, hi: u64) -> Option<u64> {
    v.trim()
        .parse::<u64>()
        .ok()
        .filter(|n| (lo..=hi).contains(n))
}

/// Standard base64 (RFC 4648, `+` and `/`, `=` padding to a multiple of four), decoded.
pub fn base64(text: &str) -> Option<Vec<u8>> {
    let text = text.as_bytes();
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let quads = text.len() / 4;
    for (n, quad) in text.chunks(4).enumerate() {
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && n + 1 != quads) {
            return None;
        }
        let mut acc = 0u32;
        for &c in &quad[..4 - pad] {
            acc = acc << 6 | u32::from(value(c)?);
        }
        acc <<= 6 * pad as u32;
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    Some(out)
}

/// An instance name or version: letters, digits, `-`, `.` and `_`, 1 to 32 characters (it goes
/// into a header line as it is).
fn label(v: &str) -> bool {
    let v = v.trim();
    (1..=32).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

/// The health route when `ready-after` is set without `health`.
pub const HEALTH_PATH: &str = "/healthz";

impl Config {
    /// `X-Instance` and `X-Version` header lines for every response (empty without them).
    pub fn identity_headers(&self) -> String {
        let mut out = String::new();
        if let Some(i) = &self.instance {
            out.push_str(&format!("X-Instance: {i}\r\n"));
        }
        if let Some(v) = &self.version {
            out.push_str(&format!("X-Version: {v}\r\n"));
        }
        out
    }
}

fn boolean(v: &str) -> Option<bool> {
    match v.trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

impl Config {
    /// Parses this app's pairs (prefix already stripped). Unknown keys are errors.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Self, ConfigError> {
        let mut c = Config {
            listen: vec![SocketAddr::from(([0, 0, 0, 0], 80))],
            backlog: None,
            keep_alive: true,
            max_requests: 100,
            no_delay: false,
            recv_buffer: None,
            send_buffer: None,
            big_max: 16 << 20,
            routes: Vec::new(),
            instance: None,
            version: None,
            health: None,
            ready_after_ns: 0,
        };
        let mut ready_after = None;
        // name -> (path, body, type, sse-events, sse-interval-ms, body-base64)
        type Draft = (
            Option<String>,
            String,
            String,
            Option<u64>,
            Option<u64>,
            Option<Vec<u8>>,
        );
        let mut routes: std::collections::BTreeMap<String, Draft> =
            std::collections::BTreeMap::new();
        for (key, value) in pairs {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            if let Some(rest) = key.strip_prefix("route.") {
                let (name, field) = rest
                    .rsplit_once('.')
                    .ok_or(ConfigError::Unknown { key: key.clone() })?;
                let route = routes.entry(name.to_owned()).or_insert_with(|| {
                    (
                        None,
                        String::new(),
                        "text/plain".to_owned(),
                        None,
                        None,
                        None,
                    )
                });
                match field {
                    "path" if value.starts_with('/') && !value.contains([' ', '?']) => {
                        route.0 = Some(value.clone())
                    }
                    "path" => return Err(invalid("a path starting with / (no query)")),
                    "body" => route.1 = value.clone(),
                    "body-base64" => {
                        route.5 = Some(base64(&value).ok_or_else(|| invalid("standard base64"))?)
                    }
                    "type" if !value.trim().is_empty() => route.2 = value.trim().to_owned(),
                    "type" => return Err(invalid("a content type")),
                    "sse-events" => {
                        route.3 =
                            Some(ranged(&value, 1, 100_000).ok_or_else(|| invalid("1..=100000"))?)
                    }
                    "sse-interval-ms" => {
                        route.4 =
                            Some(ranged(&value, 0, 60_000).ok_or_else(|| invalid("0..=60000"))?)
                    }
                    _ => return Err(ConfigError::Unknown { key }),
                }
                continue;
            }
            match key.as_str() {
                "listen" => {
                    c.listen = value
                        .split(',')
                        .map(|a| a.trim().parse().ok())
                        .collect::<Option<Vec<SocketAddr>>>()
                        .filter(|l| !l.is_empty())
                        .ok_or_else(|| invalid("a socket address like 0.0.0.0:80, or a list"))?
                }
                "backlog" => {
                    c.backlog = Some(ranged(&value, 1, 1024).ok_or_else(|| invalid("1..=1024"))?)
                }
                "keep-alive" => {
                    c.keep_alive = boolean(&value).ok_or_else(|| invalid("true or false"))?
                }
                "no-delay" => {
                    c.no_delay = boolean(&value).ok_or_else(|| invalid("true or false"))?
                }
                "max-requests" => {
                    c.max_requests =
                        ranged(&value, 1, 100_000).ok_or_else(|| invalid("1..=100000"))? as u32
                }
                "recv-buffer" => {
                    c.recv_buffer =
                        Some(ranged(&value, 1, 1 << 30).ok_or_else(|| invalid("a size in bytes"))?)
                }
                "send-buffer" => {
                    c.send_buffer =
                        Some(ranged(&value, 1, 1 << 30).ok_or_else(|| invalid("a size in bytes"))?)
                }
                "big-max" => {
                    c.big_max =
                        ranged(&value, 0, 1 << 32).ok_or_else(|| invalid("a size in bytes"))?
                }
                "instance" if label(&value) => c.instance = Some(value.trim().to_owned()),
                "instance" => return Err(invalid("letters, digits, -, . and _ (at most 32)")),
                "version" if label(&value) => c.version = Some(value.trim().to_owned()),
                "version" => return Err(invalid("letters, digits, -, . and _ (at most 32)")),
                "health" if value.starts_with('/') && !value.contains([' ', '?']) => {
                    c.health = Some(value.clone())
                }
                "health" => return Err(invalid("a path starting with / (no query)")),
                "ready-after" => {
                    ready_after = Some(
                        wasmnet_wire::parse_duration(value.trim())
                            .ok_or_else(|| invalid("a duration"))?,
                    )
                }
                _ => return Err(ConfigError::Unknown { key }),
            }
        }
        for (name, (path, body, content_type, events, interval, raw)) in routes {
            let path = path.ok_or_else(|| ConfigError::Missing {
                key: format!("route.{name}.path"),
                expected: "a path starting with /",
            })?;
            let sse = match (events, interval) {
                (Some(events), interval) => Some(Sse {
                    events,
                    interval_ms: interval.unwrap_or(SSE_INTERVAL_MS),
                }),
                (None, None) => None,
                (None, Some(_)) => {
                    return Err(ConfigError::Missing {
                        key: format!("route.{name}.sse-events"),
                        expected: "a count, with sse-interval-ms",
                    });
                }
            };
            c.routes.push(Route {
                path,
                raw: raw.is_some(),
                body: raw.unwrap_or_else(|| body.into_bytes()),
                content_type,
                sse,
            });
        }
        if c.routes.is_empty() {
            // An instance with a name says it (`web-2 v1`).
            let body = match (&c.instance, &c.version) {
                (Some(i), Some(v)) => format!("{i} {v}\n"),
                (Some(i), None) => format!("{i}\n"),
                _ => DEFAULT_BODY.to_owned(),
            };
            c.routes.push(Route {
                path: "/".to_owned(),
                body: body.into_bytes(),
                content_type: "text/plain".to_owned(),
                sse: None,
                raw: false,
            });
        }
        if c.instance.is_some() || c.version.is_some() {
            let (i, v) = (
                c.instance.clone().unwrap_or_default(),
                c.version.clone().unwrap_or_default(),
            );
            for r in c.routes.iter_mut().filter(|r| !r.raw) {
                let text = String::from_utf8_lossy(&r.body)
                    .replace("{instance}", &i)
                    .replace("{version}", &v);
                r.body = text.into_bytes();
            }
        }
        if let Some(ns) = ready_after {
            c.ready_after_ns = ns;
            c.health.get_or_insert_with(|| HEALTH_PATH.to_owned());
        }
        Ok(c)
    }

    /// Whether a route body names the node's arguments or environment (`{args}`, `{env:NAME}`).
    pub fn wants_environment(&self) -> bool {
        self.routes.iter().filter(|r| !r.raw).any(|r| {
            let b = String::from_utf8_lossy(&r.body);
            b.contains("{args}") || b.contains("{env:")
        })
    }

    /// Replaces `{args}` in route bodies with the node's arguments after `argv[0]`, one space
    /// between them, and `{env:NAME}` with the value of its environment variable `NAME`
    /// (empty if it has none). What is put in is not looked at again.
    pub fn with_environment(&mut self, args: &[String], env: &[(String, String)]) {
        let joined = args.join(" ");
        for r in self.routes.iter_mut().filter(|r| !r.raw) {
            let text = String::from_utf8_lossy(&r.body).into_owned();
            let mut out = String::with_capacity(text.len());
            let mut rest = text.as_str();
            loop {
                let next = [("{args}", true), ("{env:", false)]
                    .into_iter()
                    .filter_map(|(m, args)| rest.find(m).map(|i| (i, m, args)))
                    .min();
                let Some((i, marker, is_args)) = next else {
                    out.push_str(rest);
                    break;
                };
                out.push_str(&rest[..i]);
                let after = &rest[i + marker.len()..];
                if is_args {
                    out.push_str(&joined);
                    rest = after;
                    continue;
                }
                match after.find('}') {
                    Some(end) => {
                        let name = &after[..end];
                        if let Some((_, v)) = env.iter().find(|(k, _)| k == name) {
                            out.push_str(v);
                        }
                        rest = &after[end + 1..];
                    }
                    None => {
                        out.push_str(&rest[i..]);
                        break;
                    }
                }
            }
            r.body = out.into_bytes();
        }
    }
}

/// A parsed request head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    /// The minor version: `1` for HTTP/1.1, `0` for HTTP/1.0.
    pub version: u8,
    /// The client asked to keep the connection (HTTP/1.1 without `Connection: close`, or
    /// HTTP/1.0 with `Connection: keep-alive`).
    pub keep_alive: bool,
    /// The request body to skip.
    pub content_length: u64,
    /// The `Last-Event-ID` header, when it is a number.
    pub last_event_id: Option<u64>,
    /// Bytes of the head, including the blank line.
    pub head_len: usize,
}

/// What [`parse_request`] found at the start of the buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Head {
    Complete(Request),
    /// More bytes are needed.
    Partial,
    /// Not HTTP/1.x: answer `400` and close.
    Invalid(String),
}

fn has_token(value: &[u8], token: &str) -> bool {
    String::from_utf8_lossy(value)
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// Parses a request head at the start of `buf` (with `httparse`).
pub fn parse_request(buf: &[u8]) -> Head {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    let head_len = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) if buf.len() > MAX_HEAD => {
            return Head::Invalid("request head too large".to_owned());
        }
        Ok(httparse::Status::Partial) => return Head::Partial,
        Err(e) => return Head::Invalid(e.to_string()),
    };
    let version = req.version.unwrap_or(1);
    let mut keep_alive = version >= 1;
    let mut content_length = 0;
    let mut seen_length = false;
    let mut last_event_id = None;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("last-event-id") {
            last_event_id = std::str::from_utf8(h.value)
                .ok()
                .and_then(|v| v.trim().parse().ok());
        } else if h.name.eq_ignore_ascii_case("connection") {
            if has_token(h.value, "close") {
                keep_alive = false;
            } else if has_token(h.value, "keep-alive") {
                keep_alive = true;
            }
        } else if h.name.eq_ignore_ascii_case("content-length") {
            match std::str::from_utf8(h.value)
                .ok()
                .and_then(|v| v.trim().parse().ok())
            {
                // RFC 9112 §6.3: differing values make the message invalid.
                Some(n) if seen_length && n != content_length => {
                    return Head::Invalid("differing Content-Length values".to_owned());
                }
                Some(n) => {
                    content_length = n;
                    seen_length = true;
                }
                None => return Head::Invalid("bad Content-Length".to_owned()),
            }
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            return Head::Invalid(
                "request bodies with Transfer-Encoding are not supported".to_owned(),
            );
        }
    }
    Head::Complete(Request {
        method: req.method.unwrap_or_default().to_owned(),
        target: req.path.unwrap_or_default().to_owned(),
        version,
        keep_alive,
        content_length,
        last_event_id,
        head_len,
    })
}

/// A response body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Bytes(Vec<u8>),
    /// `n` bytes of [`pattern`], generated as the connection drains.
    Pattern(u64),
    /// Events `first..=last` ([`sse_event`]), `interval_ms` apart (an event-stream route).
    Events {
        first: u64,
        last: u64,
        interval_ms: u64,
    },
}

/// A response to one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: String,
    pub body: Body,
}

impl Response {
    fn text(status: u16, reason: &'static str, body: &str) -> Self {
        Self {
            status,
            reason,
            content_type: "text/plain".to_owned(),
            body: Body::Bytes(body.as_bytes().to_vec()),
        }
    }

    /// `400 Bad Request` (the connection then closes).
    pub fn bad_request() -> Self {
        Self::text(400, "Bad Request", "bad request\n")
    }

    pub fn body_len(&self) -> u64 {
        match &self.body {
            Body::Bytes(b) => b.len() as u64,
            Body::Pattern(n) => *n,
            Body::Events { first, last, .. } => {
                (*first..=*last).map(|id| sse_event(id).len() as u64).sum()
            }
        }
    }

    /// The status line and headers. An event stream has no `Content-Length`: it ends when the
    /// connection does.
    pub fn head(&self, keep_alive: bool) -> Vec<u8> {
        self.head_with(keep_alive, "")
    }

    /// [`Self::head`] with extra header lines (each ending in `\r\n`) after `Server:`: the
    /// instance's identity ([`Config::identity_headers`]).
    pub fn head_with(&self, keep_alive: bool, extra: &str) -> Vec<u8> {
        if let Body::Events { .. } = self.body {
            return format!(
                "HTTP/1.1 200 OK\r\nServer: {SERVER}\r\n{extra}Content-Type: {EVENT_STREAM}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
            )
            .into_bytes();
        }
        format!(
            "HTTP/1.1 {} {}\r\nServer: {SERVER}\r\n{extra}Content-Type: {}\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body_len(),
            if keep_alive { "keep-alive" } else { "close" },
        )
        .into_bytes()
    }
}

/// The value of query parameter `key` in `query` (`a=1&n=5`).
fn query_param<'q>(query: &'q str, key: &str) -> Option<&'q str> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// The largest body `POST /echo` sends back.
pub const ECHO_MAX: u64 = 1 << 20;

/// `POST /echo` with a body of at most [`ECHO_MAX`] bytes: the server
/// keeps the body and answers it back ([`echo`]). Every other request is [`respond`]ed.
pub fn echo_wanted(req: &Request) -> bool {
    let path = req
        .target
        .split_once('?')
        .map_or(req.target.as_str(), |(p, _)| p);
    req.method == "POST" && path == "/echo" && req.content_length <= ECHO_MAX
}

/// The answer to `POST /echo`: the request body, as text.
pub fn echo(body: Vec<u8>) -> Response {
    Response {
        status: 200,
        reason: "OK",
        content_type: "text/plain; charset=utf-8".to_owned(),
        body: Body::Bytes(body),
    }
}

/// The path of a request target, without its query.
fn path_of(target: &str) -> &str {
    target.split_once('?').map_or(target, |(p, _)| p)
}

/// The first event a request gets: after `Last-Event-ID: n`, event `n + 1`; otherwise event 1.
pub fn resume_from(last_event_id: Option<u64>) -> u64 {
    last_event_id.map_or(1, |n| n.saturating_add(1))
}

/// One event of an event stream: its `id`, its `data`, and the blank line that ends it.
pub fn sse_event(id: u64) -> Vec<u8> {
    format!("id: {id}\ndata: tick {id}\n\n").into_bytes()
}

/// Whether `req` is a `GET` of an event-stream route.
pub fn is_event_stream(config: &Config, req: &Request) -> bool {
    req.method == "GET"
        && config
            .routes
            .iter()
            .any(|r| r.sse.is_some() && r.path == path_of(&req.target))
}

/// Routes one request, the server being ready ([`respond_at`] with no `ready-after` left).
pub fn respond(config: &Config, req: &Request) -> Response {
    respond_at(config, req, u64::MAX)
}

/// Routes one request `uptime_ns` of virtual time after the app started: the health route
/// answers `503` until `ready-after`, then `200` (for readiness gates).
pub fn respond_at(config: &Config, req: &Request, uptime_ns: u64) -> Response {
    if req.method == "GET"
        && let Some(health) = &config.health
        && path_of(&req.target) == health
    {
        return if uptime_ns < config.ready_after_ns {
            Response::text(503, "Service Unavailable", "not ready\n")
        } else {
            Response::text(200, "OK", "ok\n")
        };
    }
    if req.method != "GET" {
        return Response::text(405, "Method Not Allowed", "only GET is served\n");
    }
    let (path, query) = req.target.split_once('?').unwrap_or((&req.target, ""));
    if let Some(route) = config.routes.iter().find(|r| r.path == path) {
        if let Some(sse) = route.sse {
            return Response {
                status: 200,
                reason: "OK",
                content_type: EVENT_STREAM.to_owned(),
                body: Body::Events {
                    first: resume_from(req.last_event_id),
                    last: sse.events,
                    interval_ms: sse.interval_ms,
                },
            };
        }
        return Response {
            status: 200,
            reason: "OK",
            content_type: route.content_type.clone(),
            body: Body::Bytes(route.body.clone()),
        };
    }
    if path == "/big" {
        return match query_param(query, "n").and_then(|n| n.parse::<u64>().ok()) {
            Some(n) if n <= config.big_max => Response {
                status: 200,
                reason: "OK",
                content_type: "application/octet-stream".to_owned(),
                body: Body::Pattern(n),
            },
            Some(_) => Response::text(400, "Bad Request", "n is above big-max\n"),
            None => Response::text(400, "Bad Request", "use /big?n=<bytes>\n"),
        };
    }
    Response::text(404, "Not Found", "not found\n")
}

/// Byte `i` of a generated body: position-dependent, so a lost, duplicated or reordered byte
/// changes the hash.
pub fn pattern(i: u64) -> u8 {
    ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8 ^ (i >> 32) as u8
}

/// Bytes `start..start + len` of the generated body.
pub fn pattern_chunk(start: u64, len: usize) -> Vec<u8> {
    (start..start + len as u64).map(pattern).collect()
}

/// Whether the server keeps the connection after this response.
pub fn keep_open(config: &Config, req: &Request, served: u32) -> bool {
    config.keep_alive
        && req.keep_alive
        && served < config.max_requests
        && !is_event_stream(config, req)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A length a peer sends can exceed what a 32-bit `usize` holds; narrowing first would turn
    /// 4 GiB into 0 and the body would never be consumed.
    #[test]
    fn a_length_above_four_gigabytes_is_not_narrowed_before_it_is_compared() {
        assert_eq!(take_len(1 << 32, 100), 100);
        assert_eq!(take_len((1 << 32) + 5, CHUNK), CHUNK);
        assert_eq!(take_len(u64::MAX, 0), 0);
        assert_eq!(take_len(7, 100), 7);
        assert_eq!(take_len(0, 100), 0);
    }

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn get(target: &str) -> Request {
        Request {
            method: "GET".to_owned(),
            target: target.to_owned(),
            version: 1,
            keep_alive: true,
            content_length: 0,
            last_event_id: None,
            head_len: 0,
        }
    }

    #[test]
    fn base64_bodies_are_bytes_never_templated() {
        assert_eq!(base64("").unwrap(), b"");
        assert_eq!(base64("Zg==").unwrap(), b"f");
        assert_eq!(base64("Zm8=").unwrap(), b"fo");
        assert_eq!(base64("Zm9v").unwrap(), b"foo");
        assert_eq!(base64("AP8A/w==").unwrap(), [0, 255, 0, 255]);
        for bad in ["Zg", "Zg=a", "Z===", "Zg==Zg==", "Zm9v!A==", "Zm 9v"] {
            assert_eq!(base64(bad), None, "{bad}");
        }
        let c = Config::from_pairs(vec![
            ("instance".to_owned(), "a".to_owned()),
            ("route.w.path".to_owned(), "/w".to_owned()),
            // `{instance}` in bytes: not replaced.
            (
                "route.w.body-base64".to_owned(),
                "e2luc3RhbmNlfQD/".to_owned(),
            ),
            ("route.w.type".to_owned(), "application/wasm".to_owned()),
        ])
        .unwrap();
        assert_eq!(c.routes[0].body, b"{instance}\x00\xff");
        assert!(c.routes[0].raw);
        let bad = vec![("route.w.body-base64".to_owned(), "!".to_owned())];
        assert!(Config::from_pairs(bad).is_err());
    }

    #[test]
    fn instance_version_and_readiness() {
        let c = Config::from_pairs(pairs(&[
            ("instance", "web-2"),
            ("version", "v1"),
            ("ready-after", "2s"),
        ]))
        .unwrap();
        assert_eq!(c.health.as_deref(), Some(HEALTH_PATH));
        let r = respond(&c, &get("/"));
        assert_eq!(r.body, Body::Bytes(b"web-2 v1\n".to_vec()));
        let head = String::from_utf8(r.head_with(false, &c.identity_headers())).unwrap();
        assert!(
            head.starts_with(
                "HTTP/1.1 200 OK\r\nServer: wasmnet-http-server\r\nX-Instance: web-2\r\nX-Version: v1\r\nContent-Type: text/plain\r\n"
            ),
            "{head}"
        );
        assert_eq!(respond_at(&c, &get("/healthz"), 1_999_999_999).status, 503);
        assert_eq!(
            respond_at(&c, &get("/healthz?x"), 2_000_000_000).status,
            200
        );
        // Routes keep their bodies, with the placeholders filled in.
        let c = Config::from_pairs(pairs(&[
            ("instance", "web-3"),
            ("health", "/up"),
            ("route.i.path", "/"),
            ("route.i.body", "I am {instance} ({version})\n"),
        ]))
        .unwrap();
        assert_eq!(c.ready_after_ns, 0);
        assert_eq!(
            respond(&c, &get("/")).body,
            Body::Bytes(b"I am web-3 ()\n".to_vec())
        );
        assert_eq!(respond_at(&c, &get("/up"), 0).status, 200);
        assert_eq!(c.identity_headers(), "X-Instance: web-3\r\n");
        // The node's arguments and environment, where a body names them.
        let mut e = Config::from_pairs(pairs(&[
            ("route.e.path", "/"),
            (
                "route.e.body",
                "{args}|{env:GREETING}|{env:NONE}|{env:X}|{env:open",
            ),
        ]))
        .unwrap();
        assert!(e.wants_environment());
        let env = [
            ("GREETING".to_owned(), "hi".to_owned()),
            ("X".to_owned(), "{args}".to_owned()),
        ];
        e.with_environment(&["-v".to_owned(), "two".to_owned()], &env);
        assert_eq!(
            respond(&e, &get("/")).body,
            Body::Bytes(b"-v two|hi||{args}|{env:open".to_vec()),
            "a value is not looked at again; an unclosed name stays"
        );
        assert!(!c.wants_environment());
        // Without them nothing changes: no header, the old default body.
        let plain = Config::from_pairs(Vec::new()).unwrap();
        assert!(!plain.wants_environment());
        assert_eq!(plain.identity_headers(), "");
        assert_eq!(respond(&plain, &get("/healthz")).status, 404);
        for bad in [
            ("instance", "web 2"),
            ("version", ""),
            ("health", "up"),
            ("ready-after", "soon"),
        ] {
            assert!(Config::from_pairs(pairs(&[bad])).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn config_routes_defaults_and_errors() {
        let all = pairs(&[
            ("ipv4", "10.0.0.1/24"),
            ("app.http-server.listen", "0.0.0.0:8080"),
            ("app.http-server.backlog", "4"),
            ("app.http-server.keep-alive", "false"),
            ("app.http-server.route.index.path", "/"),
            ("app.http-server.route.index.body", "hi\n"),
            ("app.http-server.route.about.path", "/about"),
            ("app.http-server.route.about.type", "text/html"),
        ]);
        let c = Config::from_pairs(app_pairs(all, APP)).unwrap();
        assert_eq!(c.listen, vec![SocketAddr::from(([0, 0, 0, 0], 8080))]);
        let two = pairs(&[("listen", "10.0.1.10:80,[fd00:1::10]:80")]);
        let two = Config::from_pairs(two).unwrap();
        assert_eq!(two.listen.len(), 2);
        assert!(two.listen[1].is_ipv6());
        assert_eq!(
            (c.backlog, c.keep_alive, c.max_requests),
            (Some(4), false, 100)
        );
        assert_eq!(c.routes.len(), 2);
        assert_eq!(c.routes[0].path, "/about");
        assert_eq!(c.routes[0].content_type, "text/html");
        assert_eq!(c.routes[1].body, b"hi\n");
        let d = Config::from_pairs(Vec::new()).unwrap();
        assert_eq!(d.routes[0].body, DEFAULT_BODY.as_bytes());
        for (p, needle) in [
            (pairs(&[("listen", "nope")]), "listen"),
            (pairs(&[("backlog", "0")]), "backlog"),
            (pairs(&[("keep-alive", "yes")]), "keep-alive"),
            (pairs(&[("route.x.body", "b")]), "required"),
            (pairs(&[("route.x.path", "no-slash")]), "path"),
            (pairs(&[("route.x.colour", "red")]), "unknown"),
            (pairs(&[("colour", "red")]), "unknown"),
        ] {
            let err = Config::from_pairs(p).unwrap_err().to_string();
            assert!(err.contains(needle), "{err}");
        }
    }

    #[test]
    fn requests_parse_with_keep_alive_rules() {
        let r = b"GET /big?n=5 HTTP/1.1\r\nHost: web\r\n\r\nGET / HTTP/1.1\r\n";
        let Head::Complete(req) = parse_request(r) else {
            panic!("complete")
        };
        assert_eq!(
            (req.method.as_str(), req.target.as_str()),
            ("GET", "/big?n=5")
        );
        assert_eq!((req.version, req.keep_alive, req.head_len), (1, true, 36));
        assert_eq!(parse_request(&r[..20]), Head::Partial);
        let close = b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
        assert!(matches!(
            parse_request(close),
            Head::Complete(Request {
                keep_alive: false,
                ..
            })
        ));
        let ten = b"GET / HTTP/1.0\r\n\r\n";
        assert!(matches!(
            parse_request(ten),
            Head::Complete(Request {
                keep_alive: false,
                version: 0,
                ..
            })
        ));
        let ten_ka = b"GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n";
        assert!(matches!(
            parse_request(ten_ka),
            Head::Complete(Request {
                keep_alive: true,
                ..
            })
        ));
        let body = b"POST /x HTTP/1.1\r\nContent-Length: 7\r\n\r\n";
        assert!(matches!(
            parse_request(body),
            Head::Complete(Request {
                content_length: 7,
                ..
            })
        ));
        assert!(matches!(
            parse_request(b"\x16\x03\x01junk\r\n\r\n"),
            Head::Invalid(_)
        ));
        assert!(matches!(
            parse_request(&[b'a'; MAX_HEAD + 1]),
            Head::Invalid(_)
        ));
        // RFC 9112 §6.3: differing Content-Length values are invalid; identical copies are one.
        assert_eq!(
            parse_request(b"POST /x HTTP/1.1\r\nContent-Length: 7\r\nContent-Length: 70\r\n\r\n"),
            Head::Invalid("differing Content-Length values".to_owned())
        );
        assert!(matches!(
            parse_request(b"POST /x HTTP/1.1\r\nContent-Length: 7\r\nContent-Length: 7\r\n\r\n"),
            Head::Complete(Request {
                content_length: 7,
                ..
            })
        ));
    }

    #[test]
    fn routing_and_heads() {
        let c = Config::from_pairs(pairs(&[("big-max", "100")])).unwrap();
        let r = respond(&c, &get("/"));
        assert_eq!((r.status, r.body_len()), (200, DEFAULT_BODY.len() as u64));
        let head = String::from_utf8(r.head(true)).unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(
            head.contains("Content-Length: 19\r\nConnection: keep-alive\r\n\r\n"),
            "{head}"
        );
        assert!(
            String::from_utf8(r.head(false))
                .unwrap()
                .contains("Connection: close")
        );
        assert_eq!(respond(&c, &get("/big?n=100")).body, Body::Pattern(100));
        assert_eq!(respond(&c, &get("/big?x=1&n=7")).body, Body::Pattern(7));
        assert_eq!(respond(&c, &get("/big?n=101")).status, 400);
        assert_eq!(respond(&c, &get("/big")).status, 400);
        assert_eq!(respond(&c, &get("/nope")).status, 404);
        let mut post = get("/");
        post.method = "POST".to_owned();
        assert_eq!(respond(&c, &post).status, 405);
        assert!(keep_open(&c, &get("/"), 1));
        let one = Config {
            max_requests: 1,
            ..c
        };
        assert!(!keep_open(&one, &get("/"), 1));
    }

    #[test]
    fn event_streams_format_and_resume() {
        let c = Config::from_pairs(pairs(&[
            ("route.feed.path", "/events"),
            ("route.feed.sse-events", "3"),
            ("route.feed.sse-interval-ms", "250"),
            ("route.plain.path", "/plain"),
            ("route.plain.body", "x"),
        ]))
        .unwrap();
        assert_eq!(
            c.routes[0].sse,
            Some(Sse {
                events: 3,
                interval_ms: 250
            })
        );
        assert_eq!(c.routes[1].sse, None);
        // The formatting: id, data, blank line.
        assert_eq!(sse_event(2), b"id: 2\ndata: tick 2\n\n");
        // A fresh request gets every event, as a close-delimited stream.
        let r = respond(&c, &get("/events?x=1"));
        assert_eq!(
            r.body,
            Body::Events {
                first: 1,
                last: 3,
                interval_ms: 250
            }
        );
        assert_eq!(r.content_type, EVENT_STREAM);
        let head = String::from_utf8(r.head(false)).unwrap();
        assert!(
            head.contains("Content-Type: text/event-stream\r\n"),
            "{head}"
        );
        assert!(!head.contains("Content-Length"), "{head}");
        assert!(head.ends_with("Connection: close\r\n\r\n"), "{head}");
        assert_eq!(
            r.body_len(),
            (sse_event(1).len() + sse_event(2).len() + sse_event(3).len()) as u64
        );
        assert!(!keep_open(&c, &get("/events"), 1));
        // Last-Event-ID: n starts at n + 1; past the end there is nothing left to send.
        let mut resume = get("/events");
        resume.last_event_id = Some(1);
        assert!(matches!(
            respond(&c, &resume).body,
            Body::Events {
                first: 2,
                last: 3,
                ..
            }
        ));
        resume.last_event_id = Some(9);
        assert_eq!(respond(&c, &resume).body_len(), 0);
        // A POST to the stream is refused; a static route keeps its keep-alive.
        let mut post = get("/events");
        post.method = "POST".to_owned();
        assert_eq!(respond(&c, &post).status, 405);
        assert!(keep_open(&c, &get("/plain"), 1));
        // The header parses, numbers only.
        let h = b"GET /events HTTP/1.1\r\nLast-Event-ID: 4\r\n\r\n";
        assert!(matches!(
            parse_request(h),
            Head::Complete(Request {
                last_event_id: Some(4),
                ..
            })
        ));
        let h = b"GET /events HTTP/1.1\r\nLast-Event-ID: abc\r\n\r\n";
        assert!(matches!(
            parse_request(h),
            Head::Complete(Request {
                last_event_id: None,
                ..
            })
        ));
        // Config errors: a zero count, and an interval without a count.
        assert!(
            Config::from_pairs(pairs(&[
                ("route.f.path", "/f"),
                ("route.f.sse-events", "0")
            ]))
            .is_err()
        );
        let err = Config::from_pairs(pairs(&[
            ("route.f.path", "/f"),
            ("route.f.sse-interval-ms", "5"),
        ]))
        .unwrap_err()
        .to_string();
        assert!(err.contains("sse-events"), "{err}");
    }

    #[test]
    fn pattern_and_fnv() {
        assert_eq!(error_name("ErrorCode::ConnectionReset"), "connection-reset");
        assert_eq!(
            pattern_chunk(0, 4),
            [pattern(0), pattern(1), pattern(2), pattern(3)]
        );
        let whole = pattern_chunk(0, 3 * CHUNK + 5);
        let mut parts = Vec::new();
        let mut start = 0u64;
        while (start as usize) < whole.len() {
            let n = CHUNK.min(whole.len() - start as usize);
            parts.extend(pattern_chunk(start, n));
            start += n as u64;
        }
        assert_eq!(parts, whole);
        let mut f = Fnv::default();
        f.update(b"");
        assert_eq!(f.hex(), "cbf29ce484222325");
        f.update(b"a");
        assert_eq!(f.hex(), "af63dc4c8601ec8c");
        // Distinct neighbours: a shifted body hashes differently.
        assert_ne!(pattern_chunk(0, 64), pattern_chunk(1, 64));
    }
}
