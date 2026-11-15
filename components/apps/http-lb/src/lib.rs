//! http-lb: an HTTP/1.1 load balancer, as a wasmnet app. It accepts
//! client connections on its `listen` address and proxies each request to one healthy backend,
//! chosen round-robin or at random (from the node's seeded `wasi:random`, so a seed replays the
//! same choices). It checks every backend's health with a real `GET` on an interval, and serves a
//! small admin API on its own port: backends are registered and deregistered by HTTP requests on
//! the wire, never by a poke into its config. It never returns: a daemon.
//!
//! # Config (`wasi:config`, keys under `app.http-lb.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `listen` | the client-facing socket address | `0.0.0.0:80` |
//! | `admin` | the admin API's socket address | `0.0.0.0:8080` |
//! | `policy` | `round-robin` or `random` | `round-robin` |
//! | `backend.<name>` | a backend registered at start, `ip:port` (`<name>`: `a-z`, `0-9`, `-`, at most 32) | none |
//! | `health.path` | the health check's request target | `/healthz` |
//! | `health.interval` | virtual time between two checks of one backend | `1s` |
//! | `health.timeout` | a check that has not answered by then failed | `250ms` |
//! | `health.healthy` | consecutive passes that put a backend in rotation, 1..=10 | `1` |
//! | `health.unhealthy` | consecutive failures that take it out, 1..=10 | `2` |
//! | `connect-timeout` | a proxied request whose backend connection is not up by then fails (`502`) | `300ms` |
//! | `timeout` | a proxied request whose response has not fully arrived by then fails (`504`) | `2s` |
//!
//! A newly registered backend is `checking`: it gets no traffic until a health check passes
//! (the first one runs at once). A check passes on any `2xx` or `3xx` status. A request that
//! reaches a backend that then fails is answered `502` (no retry on another backend: the failure
//! stays visible to the client); with no backend in rotation it is `503`.
//!
//! One `timeout` covers reading a client's request: its head and its body. A response's body
//! is delimited as RFC 9112 §6.3 says: none for a `HEAD` request or a `1xx`, `204` or `304`
//! status (interim `1xx` responses are passed on with the final one), else `Content-Length`,
//! else the backend's FIN. A head with differing `Content-Length` values is invalid (§6.3):
//! a request is answered `400`, a response is `bad-response`; identical copies count as one.
//!
//! **Limits.** No `Transfer-Encoding`: a request that has one is answered `400`, a response
//! that has one is a `502` (`bad-response`). A response is buffered whole, at most 4 MiB, and a
//! request body at most [`MAX_BODY`]. One request per connection on both sides.
//!
//! # The admin API (on `admin`, one request per connection)
//!
//! | request | answer |
//! |---|---|
//! | `GET /backends` | `200`, one line per backend: `<name> <addr> <state> hits=<n> errors=<n>` |
//! | `PUT /backends/<name>` with the body `ip:port` | `201` (new), `200` (already so, or moved), `503` (already [`MAX_BACKENDS`]) |
//! | `DELETE /backends/<name>` | `200`, or `404` |
//! | `GET /policy` | `200`, the policy |
//! | `PUT /policy` with the body `round-robin` or `random` | `200`, or `400` |
//!
//! # Journal
//!
//! * `lb-listening {address, role}` (`role`: `proxy` or `admin`);
//! * `lb-registered {backend, addr, via}` (`via`: `config` or `admin`), `lb-deregistered
//!   {backend, via}`;
//! * `lb-health {backend, state, reason}` when a backend changes state (`checking`, `up`,
//!   `down`; `reason`: the check's status or error);
//! * `lb-forward {request, client, backend, status, result, again}` per proxied request: `result` is
//!   `ok` or why it failed (`connect-timeout`, `timeout`, `reset`, `bad-response`, `no-backend`;
//!   then `backend` is empty); `again`: `true` when it went to the same backend as the request
//!   before (round-robin never does that with two or more backends up; random sometimes does);
//! * `lb-admin {method, target, status}` per admin request; `lb-policy {policy, via}`;
//! * `lb-bad-request {role, client, error}`: a malformed request, answered `400` and counted;
//!   never a trap.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::fmt;
use std::net::SocketAddr;
pub use wasmnet_app_kit::{app_pairs, error_name};

use wasmnet_wire::parse_duration;

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "http-lb";

/// `Server:` header of the load balancer's own answers.
pub const SERVER: &str = "wasmnet-http-lb";

/// The largest request or response head read.
pub const MAX_HEAD: usize = 16 * 1024;

/// The largest request body proxied (or read by the admin API).
pub const MAX_BODY: u64 = 1 << 20;

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

/// How a backend is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    RoundRobin,
    Random,
}

impl Policy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "round-robin" => Some(Self::RoundRobin),
            "random" => Some(Self::Random),
            _ => None,
        }
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RoundRobin => "round-robin",
            Self::Random => "random",
        })
    }
}

/// The health check's settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthConfig {
    pub path: String,
    pub interval_ns: u64,
    pub timeout_ns: u64,
    pub healthy: u32,
    pub unhealthy: u32,
}

/// The parsed config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    pub admin: SocketAddr,
    pub policy: Policy,
    /// In name order.
    pub backends: Vec<(String, SocketAddr)>,
    pub health: HealthConfig,
    pub connect_timeout_ns: u64,
    pub timeout_ns: u64,
}

/// A backend name: `a-z`, `0-9` and `-`, 1 to 32 characters.
pub fn valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Config {
    /// Parses this app's pairs (prefix already stripped). Unknown keys are errors.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Self, ConfigError> {
        let mut c = Config {
            listen: SocketAddr::from(([0, 0, 0, 0], 80)),
            admin: SocketAddr::from(([0, 0, 0, 0], 8080)),
            policy: Policy::RoundRobin,
            backends: Vec::new(),
            health: HealthConfig {
                path: "/healthz".to_owned(),
                interval_ns: 1_000_000_000,
                timeout_ns: 250_000_000,
                healthy: 1,
                unhealthy: 2,
            },
            connect_timeout_ns: 300_000_000,
            timeout_ns: 2_000_000_000,
        };
        let mut backends = std::collections::BTreeMap::new();
        for (key, value) in pairs {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            let duration = || parse_duration(value.trim()).ok_or_else(|| invalid("a duration"));
            let count = || {
                value
                    .trim()
                    .parse::<u32>()
                    .ok()
                    .filter(|n| (1..=10).contains(n))
                    .ok_or_else(|| invalid("1..=10"))
            };
            if let Some(name) = key.strip_prefix("backend.") {
                if !valid_name(name) {
                    return Err(invalid("a backend name of a-z, 0-9 and - (at most 32)"));
                }
                let addr = value
                    .trim()
                    .parse()
                    .map_err(|_| invalid("ip:port, like 10.0.1.11:80"))?;
                backends.insert(name.to_owned(), addr);
                continue;
            }
            match key.as_str() {
                "listen" => c.listen = value.trim().parse().map_err(|_| invalid("ip:port"))?,
                "admin" => c.admin = value.trim().parse().map_err(|_| invalid("ip:port"))?,
                "policy" => {
                    c.policy =
                        Policy::parse(&value).ok_or_else(|| invalid("round-robin or random"))?
                }
                "health.path" if value.starts_with('/') && !value.contains(' ') => {
                    c.health.path = value.clone()
                }
                "health.path" => return Err(invalid("a path starting with /")),
                "health.interval" => c.health.interval_ns = duration()?.max(1),
                "health.timeout" => c.health.timeout_ns = duration()?.max(1),
                "health.healthy" => c.health.healthy = count()?,
                "health.unhealthy" => c.health.unhealthy = count()?,
                "connect-timeout" => c.connect_timeout_ns = duration()?.max(1),
                "timeout" => c.timeout_ns = duration()?.max(1),
                _ => return Err(ConfigError::Unknown { key }),
            }
        }
        c.backends = backends.into_iter().collect();
        if c.listen.port() == c.admin.port() && c.listen.ip() == c.admin.ip() {
            return Err(ConfigError::Invalid {
                key: "admin".to_owned(),
                value: c.admin.to_string(),
                expected: "another address than `listen`",
            });
        }
        Ok(c)
    }
}

// ---------------------------------------------------------------------------------------------
// The backend pool

/// A backend's place in rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Registered, no health check passed yet: no traffic.
    Checking,
    /// In rotation.
    Up,
    /// Taken out by failed health checks.
    Down,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Checking => "checking",
            Self::Up => "up",
            Self::Down => "down",
        })
    }
}

/// One backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backend {
    pub name: String,
    pub addr: SocketAddr,
    pub state: State,
    /// Consecutive passed or failed checks (one of them is 0).
    pub passes: u32,
    pub fails: u32,
    /// Proxied requests answered by it, and failed on it.
    pub hits: u64,
    pub errors: u64,
    /// Bumped by every registration of this name: a check that started before the backend was
    /// registered again (or moved) does not count.
    pub epoch: u64,
}

/// What a registration changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registered {
    New,
    /// Already registered at that address: nothing changed.
    Same,
    /// Registered at another address before: it is checked again.
    Moved,
    /// Not registered: the pool already holds [`MAX_BACKENDS`].
    Full,
}

/// The most backends the pool holds (the admin API answers `503` past it).
pub const MAX_BACKENDS: usize = 1024;

/// The backends, in registration order, and how the next one is chosen.
#[derive(Clone, Debug)]
pub struct Pool {
    pub backends: Vec<Backend>,
    pub policy: Policy,
    healthy: u32,
    unhealthy: u32,
    /// Round-robin: where the search for the next backend starts (an index into `backends`).
    next: usize,
    epochs: u64,
}

impl Pool {
    pub fn new(policy: Policy, health: &HealthConfig) -> Self {
        Self {
            backends: Vec::new(),
            policy,
            healthy: health.healthy,
            unhealthy: health.unhealthy,
            next: 0,
            epochs: 0,
        }
    }

    pub fn get(&self, name: &str) -> Option<&Backend> {
        self.backends.iter().find(|b| b.name == name)
    }

    /// Registers `name` at `addr`. A new or moved backend starts `checking`.
    pub fn register(&mut self, name: &str, addr: SocketAddr) -> Registered {
        self.epochs += 1;
        let epoch = self.epochs;
        if let Some(b) = self.backends.iter_mut().find(|b| b.name == name) {
            if b.addr == addr {
                return Registered::Same;
            }
            b.addr = addr;
            b.state = State::Checking;
            b.passes = 0;
            b.fails = 0;
            b.epoch = epoch;
            return Registered::Moved;
        }
        if self.backends.len() >= MAX_BACKENDS {
            return Registered::Full;
        }
        self.backends.push(Backend {
            name: name.to_owned(),
            addr,
            state: State::Checking,
            passes: 0,
            fails: 0,
            hits: 0,
            errors: 0,
            epoch,
        });
        Registered::New
    }

    /// Removes `name`. False if it was not registered.
    pub fn deregister(&mut self, name: &str) -> bool {
        let Some(i) = self.backends.iter().position(|b| b.name == name) else {
            return false;
        };
        self.backends.remove(i);
        // The rotation goes on where it was.
        if i < self.next {
            self.next -= 1;
        }
        if self.next >= self.backends.len() {
            self.next = 0;
        }
        true
    }

    /// How many backends are in rotation.
    pub fn up(&self) -> usize {
        self.backends
            .iter()
            .filter(|b| b.state == State::Up)
            .count()
    }

    /// Whether choosing needs a random number (the random policy, with a choice to make).
    pub fn wants_random(&self) -> bool {
        self.policy == Policy::Random && self.up() > 1
    }

    /// Chooses the backend for the next request: round-robin over the backends in rotation (in
    /// registration order), or the `random`-th of them. `None` when none is in rotation.
    pub fn pick(&mut self, random: u64) -> Option<(String, SocketAddr)> {
        let n = self.backends.len();
        let chosen = match self.policy {
            Policy::RoundRobin => (0..n)
                .map(|k| (self.next + k) % n)
                .find(|&i| self.backends[i].state == State::Up)?,
            Policy::Random => {
                let up: Vec<usize> = (0..n)
                    .filter(|&i| self.backends[i].state == State::Up)
                    .collect();
                if up.is_empty() {
                    return None;
                }
                up[(random % up.len() as u64) as usize]
            }
        };
        self.next = (chosen + 1) % n;
        let b = &self.backends[chosen];
        Some((b.name.clone(), b.addr))
    }

    /// Counts a proxied request's result on its backend (gone by now: nothing).
    pub fn record(&mut self, name: &str, ok: bool) {
        if let Some(b) = self.backends.iter_mut().find(|b| b.name == name) {
            if ok {
                b.hits += 1;
            } else {
                b.errors += 1;
            }
        }
    }

    /// A health check's result for `name` as registered at `epoch`. Returns the new state when
    /// it changed. A result for a deregistered backend, or from before a re-registration, is
    /// ignored.
    pub fn checked(&mut self, name: &str, epoch: u64, pass: bool) -> Option<State> {
        let (healthy, unhealthy) = (self.healthy, self.unhealthy);
        let b = self
            .backends
            .iter_mut()
            .find(|b| b.name == name && b.epoch == epoch)?;
        let next = if pass {
            b.fails = 0;
            b.passes = b.passes.saturating_add(1);
            (b.state != State::Up && b.passes >= healthy).then_some(State::Up)
        } else {
            b.passes = 0;
            b.fails = b.fails.saturating_add(1);
            match b.state {
                State::Up if b.fails >= unhealthy => Some(State::Down),
                // A backend that never passed is down at its first failure.
                State::Checking => Some(State::Down),
                _ => None,
            }
        };
        if let Some(s) = next {
            b.state = s;
        }
        next
    }

    /// `GET /backends`: one line per backend.
    pub fn listing(&self) -> String {
        let mut out = String::new();
        for b in &self.backends {
            out.push_str(&format!(
                "{} {} {} hits={} errors={}\n",
                b.name, b.addr, b.state, b.hits, b.errors
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------
// HTTP

/// A parsed request head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    /// The minor version: `1` for HTTP/1.1.
    pub version: u8,
    /// Every header but the hop-by-hop ones (`Connection`, `Keep-Alive`, `Proxy-Connection`),
    /// in order, as `(name, value)`.
    pub headers: Vec<(String, Vec<u8>)>,
    pub content_length: u64,
    /// Bytes of the head, including the blank line.
    pub head_len: usize,
}

/// What a head parser found at the start of the buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Head<T> {
    Complete(T),
    Partial,
    Invalid(String),
}

/// Parses a request head (with `httparse`).
pub fn parse_request(buf: &[u8]) -> Head<Request> {
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
    let mut out = Request {
        method: req.method.unwrap_or_default().to_owned(),
        target: req.path.unwrap_or_default().to_owned(),
        version: req.version.unwrap_or(1),
        headers: Vec::new(),
        content_length: 0,
        head_len,
    };
    let mut length = None;
    for h in req.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        match name.as_str() {
            "connection" | "keep-alive" | "proxy-connection" => continue,
            "transfer-encoding" => {
                return Head::Invalid(
                    "request bodies with Transfer-Encoding are not supported".to_owned(),
                );
            }
            "content-length" => match content_length(length, h.value) {
                // An identical copy is forwarded once.
                Ok(_) if length.is_some() => continue,
                Ok(n) if n <= MAX_BODY => {
                    length = Some(n);
                    out.content_length = n;
                }
                Ok(_) => return Head::Invalid("request body too large".to_owned()),
                Err(e) => return Head::Invalid(e.to_owned()),
            },
            _ => {}
        }
        out.headers.push((h.name.to_owned(), h.value.to_vec()));
    }
    Head::Complete(out)
}

impl Request {
    /// The head sent to the backend: the same request line and headers, one request per
    /// connection (`Connection: close`), and `X-Forwarded-For` with the client's address.
    pub fn upstream_head(&self, client_ip: &str) -> Vec<u8> {
        let mut out = format!("{} {} HTTP/1.1\r\n", self.method, self.target).into_bytes();
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("x-forwarded-for") {
                continue;
            }
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        let forwarded = self
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("x-forwarded-for"))
            .map(|(_, v)| format!("{}, {client_ip}", String::from_utf8_lossy(v)))
            .unwrap_or_else(|| client_ip.to_owned());
        out.extend_from_slice(
            format!("X-Forwarded-For: {forwarded}\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        out
    }
}

/// A parsed response head: what the proxy needs to know of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub head_len: usize,
}

/// How a response's body ends (RFC 9112 §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyLength {
    /// An interim (`1xx`, not `101`) response: no body, and the final response follows.
    Interim,
    /// No body: a response to `HEAD`, or a `101`, `204` or `304` (whatever its headers say).
    None,
    /// `Content-Length` bytes.
    Exactly(u64),
    /// To the backend's FIN.
    ToClose,
    /// `Transfer-Encoding`: not supported (the proxy answers `502`).
    Unsupported,
}

/// RFC 9112 §6.3, in its order: a response to `HEAD` and every `1xx`, `204` and `304` has no
/// body; then `Transfer-Encoding`, then `Content-Length`, else the body runs to the close.
pub fn body_length(method: &str, head: &ResponseHead) -> BodyLength {
    match head.status {
        100..=199 if head.status != 101 => BodyLength::Interim,
        101 | 204 | 304 => BodyLength::None,
        _ if method.eq_ignore_ascii_case("HEAD") => BodyLength::None,
        _ if head.chunked => BodyLength::Unsupported,
        _ => head
            .content_length
            .map_or(BodyLength::ToClose, BodyLength::Exactly),
    }
}

/// The `Content-Length` of a message, from every such header (RFC 9112 §6.3: differing values
/// are an error; identical copies count as one). `Err` names the problem.
fn content_length(seen: Option<u64>, value: &[u8]) -> Result<u64, &'static str> {
    let n = std::str::from_utf8(value)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .ok_or("bad Content-Length")?;
    match seen {
        Some(m) if m != n => Err("differing Content-Length values"),
        _ => Ok(n),
    }
}

/// Parses a backend's response head.
pub fn parse_response(buf: &[u8]) -> Head<ResponseHead> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let head_len = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) if buf.len() > MAX_HEAD => {
            return Head::Invalid("response head too large".to_owned());
        }
        Ok(httparse::Status::Partial) => return Head::Partial,
        Err(e) => return Head::Invalid(e.to_string()),
    };
    let mut out = ResponseHead {
        status: resp.code.unwrap_or(0),
        content_length: None,
        chunked: false,
        head_len,
    };
    for h in resp.headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
            match content_length(out.content_length, h.value) {
                Ok(n) => out.content_length = Some(n),
                Err(e) => return Head::Invalid(e.to_owned()),
            }
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            out.chunked = true;
        }
    }
    Head::Complete(out)
}

/// One of the load balancer's own answers (the admin API's, `400`, `502`, `503`, `504`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub reason: &'static str,
    pub body: String,
}

impl Answer {
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        let reason = match status {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Unknown",
        };
        Self {
            status,
            reason,
            body: body.into(),
        }
    }

    /// The whole response, `Connection: close`.
    pub fn bytes(&self) -> Vec<u8> {
        format!(
            "HTTP/1.1 {} {}\r\nServer: {SERVER}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.status,
            self.reason,
            self.body.len(),
            self.body
        )
        .into_bytes()
    }
}

/// What an admin request changed, for the journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Registered { name: String, addr: SocketAddr },
    Deregistered { name: String },
    Policy(Policy),
}

/// Serves one admin request (its body already read). Returns the answer and what changed.
pub fn admin(pool: &mut Pool, method: &str, target: &str, body: &[u8]) -> (Answer, Option<Change>) {
    let path = target.split_once('?').map_or(target, |(p, _)| p);
    let body = String::from_utf8_lossy(body);
    let body = body.trim();
    match (method, path) {
        ("GET", "/backends") => (Answer::new(200, pool.listing()), None),
        ("GET", "/policy") => (Answer::new(200, format!("{}\n", pool.policy)), None),
        ("PUT", "/policy") => match Policy::parse(body) {
            Some(p) => {
                pool.policy = p;
                (Answer::new(200, format!("{p}\n")), Some(Change::Policy(p)))
            }
            None => (Answer::new(400, "want round-robin or random\n"), None),
        },
        (_, "/backends" | "/policy") => (Answer::new(405, "method not allowed\n"), None),
        (m, p) => match p.strip_prefix("/backends/") {
            Some(name) if !valid_name(name) => (
                Answer::new(400, "a backend name is a-z, 0-9 and - (at most 32)\n"),
                None,
            ),
            Some(name) if m == "PUT" => match body.parse::<SocketAddr>() {
                Ok(addr) => {
                    let (status, word) = match pool.register(name, addr) {
                        Registered::New => (201, "registered"),
                        Registered::Same => (200, "already registered"),
                        Registered::Moved => (200, "moved"),
                        Registered::Full => {
                            return (Answer::new(503, "the backend pool is full\n"), None);
                        }
                    };
                    let change = (status == 201 || word == "moved").then(|| Change::Registered {
                        name: name.to_owned(),
                        addr,
                    });
                    (
                        Answer::new(status, format!("{word} {name} {addr}\n")),
                        change,
                    )
                }
                Err(_) => (Answer::new(400, "want ip:port in the body\n"), None),
            },
            Some(name) if m == "DELETE" => {
                if pool.deregister(name) {
                    (
                        Answer::new(200, format!("deregistered {name}\n")),
                        Some(Change::Deregistered {
                            name: name.to_owned(),
                        }),
                    )
                } else {
                    (Answer::new(404, format!("no backend {name}\n")), None)
                }
            }
            Some(name) if m == "GET" => match pool.get(name) {
                Some(b) => (
                    Answer::new(
                        200,
                        format!(
                            "{} {} {} hits={} errors={}\n",
                            b.name, b.addr, b.state, b.hits, b.errors
                        ),
                    ),
                    None,
                ),
                None => (Answer::new(404, format!("no backend {name}\n")), None),
            },
            Some(_) => (Answer::new(405, "method not allowed\n"), None),
            None => (Answer::new(404, "not found\n"), None),
        },
    }
}

/// The health check's request.
pub fn health_request(path: &str, host: &SocketAddr) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {SERVER}-health\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// Whether a health check's status passes: `2xx` or `3xx`.
pub fn passes(status: u16) -> bool {
    (200..400).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn pool(policy: Policy) -> Pool {
        let c = Config::from_pairs(Vec::new()).unwrap();
        Pool::new(policy, &c.health)
    }

    /// Registers and passes one check: in rotation.
    fn up(p: &mut Pool, name: &str, a: &str) {
        p.register(name, addr(a));
        let e = p.get(name).unwrap().epoch;
        assert_eq!(p.checked(name, e, true), Some(State::Up));
    }

    #[test]
    fn config_keys_defaults_and_errors() {
        let all = pairs(&[
            ("ipv4", "10.0.1.2/24"),
            ("app.http-lb.listen", "0.0.0.0:80"),
            ("app.http-lb.admin", "0.0.0.0:8081"),
            ("app.http-lb.policy", "random"),
            ("app.http-lb.backend.web-2", "10.0.1.12:80"),
            ("app.http-lb.backend.web-1", "10.0.1.11:80"),
            ("app.http-lb.health.interval", "500ms"),
            ("app.http-lb.health.unhealthy", "3"),
        ]);
        let c = Config::from_pairs(app_pairs(all, APP)).unwrap();
        assert_eq!(c.policy, Policy::Random);
        assert_eq!(c.admin, addr("0.0.0.0:8081"));
        let names: Vec<&str> = c.backends.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["web-1", "web-2"]);
        assert_eq!((c.health.interval_ns, c.health.unhealthy), (500_000_000, 3));
        assert_eq!(c.health.path, "/healthz");
        for (p, needle) in [
            (pairs(&[("policy", "fastest")]), "policy"),
            (pairs(&[("backend.Web", "10.0.0.1:80")]), "backend name"),
            (pairs(&[("backend.w", "10.0.0.1")]), "ip:port"),
            (pairs(&[("health.healthy", "0")]), "1..=10"),
            (pairs(&[("admin", "0.0.0.0:80")]), "another address"),
            (pairs(&[("colour", "red")]), "unknown"),
        ] {
            let err = Config::from_pairs(p).unwrap_err().to_string();
            assert!(err.contains(needle), "{err}");
        }
    }

    #[test]
    fn round_robin_skips_backends_out_of_rotation() {
        let mut p = pool(Policy::RoundRobin);
        assert_eq!(p.pick(0), None);
        up(&mut p, "a", "10.0.0.1:80");
        up(&mut p, "b", "10.0.0.2:80");
        up(&mut p, "c", "10.0.0.3:80");
        let seq: Vec<String> = (0..6).map(|_| p.pick(0).unwrap().0).collect();
        assert_eq!(seq, ["a", "b", "c", "a", "b", "c"]);
        // A registered backend gets nothing until a check passes.
        p.register("d", addr("10.0.0.4:80"));
        let seq: Vec<String> = (0..3).map(|_| p.pick(0).unwrap().0).collect();
        assert_eq!(seq, ["a", "b", "c"]);
        let e = p.get("d").unwrap().epoch;
        p.checked("d", e, true);
        let seq: Vec<String> = (0..4).map(|_| p.pick(0).unwrap().0).collect();
        // The rotation goes on where it was: d is next after c.
        assert_eq!(seq, ["d", "a", "b", "c"]);
        // Deregistering keeps the rotation's place.
        assert!(p.deregister("a"));
        assert!(!p.deregister("a"));
        let seq: Vec<String> = (0..3).map(|_| p.pick(0).unwrap().0).collect();
        assert_eq!(seq, ["d", "b", "c"]);
    }

    #[test]
    fn random_uses_its_number_over_the_backends_up() {
        let mut p = pool(Policy::Random);
        up(&mut p, "a", "10.0.0.1:80");
        assert!(!p.wants_random());
        up(&mut p, "b", "10.0.0.2:80");
        p.register("x", addr("10.0.0.9:80"));
        assert!(p.wants_random());
        assert_eq!(p.pick(0).unwrap().0, "a");
        assert_eq!(p.pick(1).unwrap().0, "b");
        assert_eq!(p.pick(7).unwrap().0, "b");
    }

    #[test]
    fn health_thresholds_and_stale_results() {
        let mut p = pool(Policy::RoundRobin);
        p.register("a", addr("10.0.0.1:80"));
        let e = p.get("a").unwrap().epoch;
        // Never passed: down at the first failure, up at the first pass.
        assert_eq!(p.checked("a", e, false), Some(State::Down));
        assert_eq!(p.checked("a", e, false), None);
        assert_eq!(p.checked("a", e, true), Some(State::Up));
        // In rotation: two failures (the default) take it out.
        assert_eq!(p.checked("a", e, false), None);
        assert_eq!(p.checked("a", e, true), None);
        assert_eq!(p.checked("a", e, false), None);
        assert_eq!(p.checked("a", e, false), Some(State::Down));
        // Moved: checking again; an older check's result is ignored.
        assert_eq!(p.register("a", addr("10.0.0.5:80")), Registered::Moved);
        assert_eq!(p.get("a").unwrap().state, State::Checking);
        assert_eq!(p.checked("a", e, true), None);
        assert_eq!(p.register("a", addr("10.0.0.5:80")), Registered::Same);
        assert_eq!(p.checked("zz", 1, true), None);
    }

    #[test]
    fn admin_api() {
        let mut p = pool(Policy::RoundRobin);
        let (a, ch) = admin(&mut p, "PUT", "/backends/web-4", b"10.0.1.14:80\n");
        assert_eq!(a.status, 201);
        assert_eq!(
            ch,
            Some(Change::Registered {
                name: "web-4".into(),
                addr: addr("10.0.1.14:80")
            })
        );
        let (a, ch) = admin(&mut p, "PUT", "/backends/web-4", b"10.0.1.14:80");
        assert_eq!((a.status, ch), (200, None));
        let (a, _) = admin(&mut p, "GET", "/backends", b"");
        assert_eq!(a.body, "web-4 10.0.1.14:80 checking hits=0 errors=0\n");
        assert_eq!(
            admin(&mut p, "PUT", "/backends/web-4", b"nope").0.status,
            400
        );
        assert_eq!(
            admin(&mut p, "PUT", "/backends/Web 4", b"10.0.0.1:80")
                .0
                .status,
            400
        );
        assert_eq!(admin(&mut p, "POST", "/backends/web-4", b"").0.status, 405);
        assert_eq!(admin(&mut p, "POST", "/backends", b"").0.status, 405);
        assert_eq!(admin(&mut p, "GET", "/nothing", b"").0.status, 404);
        let (a, ch) = admin(&mut p, "PUT", "/policy", b"random");
        assert_eq!((a.status, ch), (200, Some(Change::Policy(Policy::Random))));
        assert_eq!(admin(&mut p, "GET", "/policy", b"").0.body, "random\n");
        assert_eq!(admin(&mut p, "PUT", "/policy", b"best").0.status, 400);
        let (a, ch) = admin(&mut p, "DELETE", "/backends/web-4", b"");
        assert_eq!(a.status, 200);
        assert!(matches!(ch, Some(Change::Deregistered { .. })));
        assert_eq!(
            admin(&mut p, "DELETE", "/backends/web-4", b"").0.status,
            404
        );
        let bytes = String::from_utf8(Answer::new(503, "none\n").bytes()).unwrap();
        assert!(bytes.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(bytes.ends_with("Content-Length: 5\r\nConnection: close\r\n\r\nnone\n"));
    }

    #[test]
    fn requests_are_rewritten_for_one_request_per_connection() {
        let raw = b"GET /x HTTP/1.1\r\nHost: lb\r\nConnection: keep-alive\r\nUser-Agent: t\r\n\r\n";
        let Head::Complete(r) = parse_request(raw) else {
            panic!("complete")
        };
        assert_eq!(r.head_len, raw.len());
        let up = String::from_utf8(r.upstream_head("10.0.1.3")).unwrap();
        assert_eq!(
            up,
            "GET /x HTTP/1.1\r\nHost: lb\r\nUser-Agent: t\r\nX-Forwarded-For: 10.0.1.3\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(parse_request(&raw[..12]), Head::Partial);
        for bad in [
            &b"\x16\x03\x01junk\r\n\r\n"[..],
            b"POST / HTTP/1.1\r\nContent-Length: x\r\n\r\n",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n",
        ] {
            assert!(matches!(parse_request(bad), Head::Invalid(_)), "{bad:?}");
        }
        let big = vec![b'a'; MAX_HEAD + 1];
        assert!(matches!(parse_request(&big), Head::Invalid(_)));
    }

    #[test]
    fn the_pool_is_bounded() {
        let mut p = pool(Policy::RoundRobin);
        for i in 0..MAX_BACKENDS {
            let (a, _) = admin(&mut p, "PUT", &format!("/backends/b{i}"), b"10.0.0.1:80");
            assert_eq!(a.status, 201);
        }
        let (a, ch) = admin(&mut p, "PUT", "/backends/one-more", b"10.0.0.1:80");
        assert_eq!((a.status, ch), (503, None));
        assert_eq!(p.backends.len(), MAX_BACKENDS);
        // Known names still move, and a freed place is taken again.
        assert_eq!(
            admin(&mut p, "PUT", "/backends/b0", b"10.0.0.2:80")
                .0
                .status,
            200
        );
        assert_eq!(admin(&mut p, "DELETE", "/backends/b1", b"").0.status, 200);
        assert_eq!(
            admin(&mut p, "PUT", "/backends/one-more", b"10.0.0.1:80")
                .0
                .status,
            201
        );
    }

    #[test]
    fn differing_content_lengths_are_rejected() {
        // RFC 9112 §6.3.
        let bad = b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd";
        assert_eq!(
            parse_request(bad),
            Head::Invalid("differing Content-Length values".into())
        );
        let twice = b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc";
        let Head::Complete(r) = parse_request(twice) else {
            panic!("identical copies are one")
        };
        assert_eq!(r.content_length, 3);
        let up = String::from_utf8(r.upstream_head("10.0.1.3")).unwrap();
        assert_eq!(up.matches("Content-Length").count(), 1, "{up}");
        assert!(matches!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"),
            Head::Invalid(_)
        ));
    }

    #[test]
    fn bodiless_responses_end_at_their_head() {
        // RFC 9112 §6.3: HEAD, 1xx, 204 and 304 have no body, whatever their headers say.
        let head = |raw: &[u8]| match parse_response(raw) {
            Head::Complete(h) => h,
            other => panic!("{other:?}"),
        };
        let ok = head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
        assert_eq!(body_length("GET", &ok), BodyLength::Exactly(5));
        assert_eq!(body_length("HEAD", &ok), BodyLength::None);
        for raw in [
            &b"HTTP/1.1 204 No Content\r\n\r\n"[..],
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
        ] {
            assert_eq!(body_length("GET", &head(raw)), BodyLength::None, "{raw:?}");
        }
        let cont = head(b"HTTP/1.1 100 Continue\r\n\r\n");
        assert_eq!(body_length("POST", &cont), BodyLength::Interim);
        let to_close = head(b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(body_length("GET", &to_close), BodyLength::ToClose);
        let chunked = head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(body_length("GET", &chunked), BodyLength::Unsupported);
        assert_eq!(body_length("HEAD", &chunked), BodyLength::None);
    }

    #[test]
    fn responses_and_checks() {
        let r = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 9\r\n\r\nnot ready";
        let Head::Complete(h) = parse_response(r) else {
            panic!("complete")
        };
        assert_eq!((h.status, h.content_length), (503, Some(9)));
        assert!(!passes(h.status));
        assert!(passes(200) && passes(301) && !passes(404));
        assert!(matches!(
            parse_response(b"SSH-2.0\r\n\r\n"),
            Head::Invalid(_)
        ));
        let req = String::from_utf8(health_request("/healthz", &addr("10.0.1.11:80"))).unwrap();
        assert!(req.starts_with("GET /healthz HTTP/1.1\r\nHost: 10.0.1.11:80\r\n"));
        assert_eq!(
            error_name("ErrorCode::ConnectionRefused"),
            "connection-refused"
        );
    }
}
