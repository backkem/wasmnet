//! http-get: an HTTP/1.1 GET client, as a wasmnet app. It fetches the URLs from
//! its config, one after the other, over `wasi:sockets@0.3.0` TCP, and exits: `ok` when every
//! fetch succeeded (or was aborted on purpose), an error otherwise.
//!
//! # Config (`wasi:config`, keys under `app.http-get.`)
//!
//! | key | value | default |
//! |---|---|---|
//! | `url` | one URL, `http://host[:port]/path?query`; `host` is an IP literal (`[fd00::1]` for IPv6) or a name from the node's `hosts.<name>` table | |
//! | `urls` | several URLs (a config array, flattened to `a,b`); `url` and `urls` add up, at least one is required | |
//! | `keep-alive` | `true`: send `Connection: keep-alive` and reuse one connection for consecutive URLs on the same host and port; `false`: one connection per URL, `Connection: close` | `false` |
//! | `start` | virtual time to wait before the first request | `0` |
//! | `interval` | virtual time between two requests | `0` |
//! | `request-delay` | virtual time between a new connection and its first request (a slow client's think time) | `0` |
//! | `recv-buffer`, `send-buffer` | socket buffer sizes in bytes, set before `connect` (the receive buffer is the TCP window) | the netstack's |
//! | `read-size` | bytes asked for per stream read, 1..=1048576 | `65536` |
//! | `read-pause` | virtual time to wait after each read: a slow reader | `0` |
//! | `abort-after` | abort the connection (`wasmnet:sockets-ext/tcp.abort`, an RST) once this many body bytes arrived | never |
//! | `no-delay` | `true`: `TCP_NODELAY` | `false` |
//! | `proxy` | (embedder surface, unstable) an HTTP forward proxy, `http://host:port`: every request goes there with its absolute URL; `https://` URLs need one | none |
//! | `accept` | the `Accept:` header | `*/*` |
//! | `repeat` | how many times the URL list is fetched, 1..=1000000, or `forever` (a load generator) | `1` |
//! | `quiet` | `true`: journal only `http-get-done` and errors per request (no connected, response or closed events, no info lines): a long stream of requests stays small | `false` |
//! | `console` | `true`: after the URLs (none are needed then), read requests from stdin, one per line, `METHOD URL [BODY]` (`GET`, `PUT`, `POST`, `DELETE` or `PATCH`; the body is the rest of the line); each answer's status line and body go to stdout. Lines written to its stdin while the network runs (`Op::Stdin`) make it an admin console | `false` |
//! | `half-close` | `true`: send our FIN together with each request, before the response arrives (a client that half-closes early); no keep-alive then | `false` |
//!
//! # Journal (times in virtual ns, measured from the start of each request)
//!
//! * `http-get-connected {url, peer, local, connect-ns}` for every new connection;
//! * `http-get-response {url, status, reason, version, headers, content-type, content-length,
//!   connection, first-byte-ns}` once the response head arrived (`headers`: the header names,
//!   lowercase, comma-separated);
//! * `http-get-done {url, status, body-bytes, body-fnv, connect-ns, first-byte-ns, done-ns,
//!   reused}` (`body-fnv`: FNV-1a 64 of the body, hex; `reused`: the request rode an existing
//!   connection), plus `instance` and `version` when the response named its instance
//!   (`X-Instance`, `X-Version`, as http-server sends them), and `method` when it was not `GET`;
//! * `http-get-aborted {url, body-bytes, send, receive}`: the abort, with how the socket's two
//!   futures resolved;
//! * `http-get-closed {peer, requests, send, receive}` when a connection is closed;
//! * `http-get-error {url, error}`;
//! * `http-get-summary {requests, ok, aborted, failed, connections}` at the end.
//!
//! Only `Content-Length` bodies and read-to-EOF bodies are understood (`Transfer-Encoding:
//! chunked` is an error).

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

pub use wasmnet_app_kit::{Fnv, app_pairs, error_name};
use wasmnet_wire::parse_duration;

/// The app's name: its config prefix (`app.<name>.`) and its node export (`app-<name>`).
pub const APP: &str = "http-get";

/// `User-Agent:` header.
pub const USER_AGENT: &str = "wasmnet-http-get";

/// The largest response head the client accepts.
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

/// A parsed `http://` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    /// As configured.
    pub text: String,
    /// The host without brackets: an IP literal or a name.
    pub host: String,
    pub port: u16,
    /// Path and query, at least `/`.
    pub target: String,
    /// `https://` (fetched through a `proxy` only).
    pub https: bool,
}

impl Url {
    /// `http://host[:port]/path`, or `https://` (only through a `proxy`). No user info, no
    /// fragment.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (https, rest) = match (text.strip_prefix("http://"), text.strip_prefix("https://")) {
            (Some(rest), _) => (false, rest),
            (None, Some(rest)) => (true, rest),
            (None, None) => return Err(format!("{text:?}: only http:// and https:// URLs")),
        };
        let (authority, target) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (host, after) = v6
                .split_once(']')
                .ok_or_else(|| format!("{text:?}: unclosed [ in the host"))?;
            let port = match after.strip_prefix(':') {
                Some(p) => Some(p),
                None if after.is_empty() => None,
                None => return Err(format!("{text:?}: junk after the IPv6 host")),
            };
            (host, port)
        } else {
            match authority.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        let port = match port {
            None if https => 443,
            None => 80,
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or_else(|| format!("{text:?}: bad port"))?,
        };
        if host.is_empty() || host.contains(['@', ' ']) || target.contains([' ', '#']) {
            return Err(format!("{text:?}: not a plain http URL"));
        }
        Ok(Self {
            text: text.to_owned(),
            host: host.to_owned(),
            port,
            target: target.to_owned(),
            https,
        })
    }

    /// The `Host:` header value.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == if self.https { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The request head for this URL (origin-form: straight to the server).
    pub fn request(&self, keep_alive: bool) -> Vec<u8> {
        self.request_via(keep_alive, false, "*/*")
    }

    /// The absolute URL, as a forward proxy wants it in the request line.
    pub fn absolute(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{scheme}://{}{}", self.host_header(), self.target)
    }

    /// The request head, in absolute form when it goes to a forward proxy (`proxy`).
    pub fn request_via(&self, keep_alive: bool, proxy: bool, accept: &str) -> Vec<u8> {
        self.request_with("GET", &[], keep_alive, proxy, accept)
    }

    /// A request with any method and a body (`Content-Length` when there is one): the console's
    /// requests. With `GET` and no body it is exactly [`Self::request_via`]'s.
    pub fn request_with(
        &self,
        method: &str,
        body: &[u8],
        keep_alive: bool,
        proxy: bool,
        accept: &str,
    ) -> Vec<u8> {
        let target = if proxy {
            self.absolute()
        } else {
            self.target.clone()
        };
        let length = if body.is_empty() {
            String::new()
        } else {
            format!("Content-Length: {}\r\n", body.len())
        };
        let mut out = format!(
            "{method} {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nAccept: {accept}\r\nConnection: {}\r\n{length}\r\n",
            self.host_header(),
            if keep_alive { "keep-alive" } else { "close" },
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }
}

/// One request: a URL of the config (a `GET`), or a console line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub method: String,
    pub url: Url,
    pub body: Vec<u8>,
}

impl Command {
    pub fn get(url: &Url) -> Self {
        Self {
            method: "GET".to_owned(),
            url: url.clone(),
            body: Vec::new(),
        }
    }

    /// A console line: `METHOD URL [BODY]` (the body is the rest of the line, trimmed). `None`
    /// for an empty line or a `#` comment.
    pub fn parse(line: &str) -> Option<Result<Self, String>> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (method, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let rest = rest.trim_start();
        let (url, body) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        let method = method.to_ascii_uppercase();
        if !matches!(method.as_str(), "GET" | "PUT" | "POST" | "DELETE" | "PATCH") {
            return Some(Err(format!(
                "{line:?}: want METHOD URL [BODY], METHOD one of GET, PUT, POST, DELETE, PATCH"
            )));
        }
        Some(match Url::parse(url) {
            Ok(url) if url.https => Err(format!("{line:?}: only http:// URLs")),
            Ok(url) => Ok(Self {
                method,
                url,
                body: body.trim().as_bytes().to_vec(),
            }),
            Err(e) => Err(e),
        })
    }
}

/// The parsed config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub urls: Vec<Url>,
    pub keep_alive: bool,
    pub start_ns: u64,
    pub interval_ns: u64,
    pub request_delay_ns: u64,
    pub recv_buffer: Option<u64>,
    pub send_buffer: Option<u64>,
    pub read_size: usize,
    pub read_pause_ns: u64,
    pub abort_after: Option<u64>,
    pub no_delay: bool,
    /// A forward proxy (`http_proxy`): every request goes there, in absolute form.
    pub proxy: Option<Url>,
    /// The `Accept:` header.
    pub accept: String,
    /// Rounds over the URL list; `None`: forever.
    pub repeat: Option<u64>,
    pub quiet: bool,
    /// Requests from stdin after the URLs.
    pub console: bool,
    /// Our FIN right after each request (a client that half-closes early), not after the response.
    pub half_close: bool,
}

fn ranged(v: &str, lo: u64, hi: u64) -> Option<u64> {
    v.trim()
        .parse::<u64>()
        .ok()
        .filter(|n| (lo..=hi).contains(n))
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
            urls: Vec::new(),
            keep_alive: false,
            start_ns: 0,
            interval_ns: 0,
            request_delay_ns: 0,
            recv_buffer: None,
            send_buffer: None,
            read_size: 65_536,
            read_pause_ns: 0,
            abort_after: None,
            no_delay: false,
            proxy: None,
            accept: "*/*".to_owned(),
            repeat: Some(1),
            quiet: false,
            console: false,
            half_close: false,
        };
        let (mut one, mut many) = (Vec::new(), Vec::new());
        for (key, value) in pairs {
            let invalid = |expected| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                expected,
            };
            let duration = |v: &str| parse_duration(v.trim());
            let size = |v: &str| ranged(v, 1, 1 << 30);
            match key.as_str() {
                "url" => one.push(Url::parse(value.trim()).map_err(|_| invalid("an http:// URL"))?),
                "urls" => {
                    for u in value.split(',').map(str::trim).filter(|u| !u.is_empty()) {
                        many.push(
                            Url::parse(u).map_err(|_| invalid("http:// URLs, comma-separated"))?,
                        );
                    }
                }
                "keep-alive" => {
                    c.keep_alive = boolean(&value).ok_or_else(|| invalid("true or false"))?
                }
                "no-delay" => {
                    c.no_delay = boolean(&value).ok_or_else(|| invalid("true or false"))?
                }
                "start" => c.start_ns = duration(&value).ok_or_else(|| invalid("a duration"))?,
                "interval" => {
                    c.interval_ns = duration(&value).ok_or_else(|| invalid("a duration"))?
                }
                "request-delay" => {
                    c.request_delay_ns = duration(&value).ok_or_else(|| invalid("a duration"))?
                }
                "read-pause" => {
                    c.read_pause_ns = duration(&value).ok_or_else(|| invalid("a duration"))?
                }
                "recv-buffer" => {
                    c.recv_buffer = Some(size(&value).ok_or_else(|| invalid("a size in bytes"))?)
                }
                "send-buffer" => {
                    c.send_buffer = Some(size(&value).ok_or_else(|| invalid("a size in bytes"))?)
                }
                "read-size" => {
                    c.read_size =
                        ranged(&value, 1, 1 << 20).ok_or_else(|| invalid("1..=1048576"))? as usize
                }
                "abort-after" => {
                    c.abort_after =
                        Some(ranged(&value, 0, u64::MAX).ok_or_else(|| invalid("a byte count"))?)
                }
                "proxy" => {
                    c.proxy = Some(
                        Url::parse(value.trim())
                            .ok()
                            .filter(|u| !u.https)
                            .ok_or_else(|| invalid("an http://host:port proxy URL"))?,
                    )
                }
                "accept" => c.accept = value.trim().to_owned(),
                "repeat" if value.trim() == "forever" => c.repeat = None,
                "repeat" => {
                    c.repeat = Some(
                        ranged(&value, 1, 1_000_000)
                            .ok_or_else(|| invalid("1..=1000000, or forever"))?,
                    )
                }
                "quiet" => c.quiet = boolean(&value).ok_or_else(|| invalid("true or false"))?,
                "console" => c.console = boolean(&value).ok_or_else(|| invalid("true or false"))?,
                "half-close" => {
                    c.half_close = boolean(&value).ok_or_else(|| invalid("true or false"))?
                }
                _ => return Err(ConfigError::Unknown { key }),
            }
        }
        c.urls = one.into_iter().chain(many).collect();
        if c.proxy.is_none()
            && let Some(u) = c.urls.iter().find(|u| u.https)
        {
            return Err(ConfigError::Invalid {
                key: "url".to_owned(),
                value: u.text.clone(),
                expected: "an http:// URL (https:// needs a `proxy`)",
            });
        }
        if c.urls.is_empty() && !c.console {
            return Err(ConfigError::Missing {
                key: "url".to_owned(),
                expected: "an http:// URL (or `urls`)",
            });
        }
        Ok(c)
    }
}

/// A parsed response head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    /// The minor version: `1` for HTTP/1.1.
    pub version: u8,
    /// Header names, lowercase, in order.
    pub names: Vec<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    /// The `Connection` header, lowercase.
    pub connection: Option<String>,
    /// `X-Instance` and `X-Version`: which instance answered (as http-server sends them).
    pub instance: Option<String>,
    pub app_version: Option<String>,
    pub chunked: bool,
    /// Bytes of the head, including the blank line.
    pub head_len: usize,
}

impl ResponseHead {
    /// Whether the server keeps the connection open after this response.
    pub fn keeps_alive(&self) -> bool {
        let close = self
            .connection
            .as_deref()
            .is_some_and(|c| c.split(',').any(|t| t.trim() == "close"));
        let keep = self
            .connection
            .as_deref()
            .is_some_and(|c| c.split(',').any(|t| t.trim() == "keep-alive"));
        !close && (self.version >= 1 || keep) && self.content_length.is_some()
    }
}

/// What [`parse_response`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Head {
    Complete(ResponseHead),
    Partial,
    Invalid(String),
}

/// Parses a response head at the start of `buf` (with `httparse`).
pub fn parse_response(buf: &[u8]) -> Head {
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
    let text = |v: &[u8]| String::from_utf8_lossy(v).trim().to_owned();
    let mut head = ResponseHead {
        status: resp.code.unwrap_or(0),
        reason: resp.reason.unwrap_or_default().to_owned(),
        version: resp.version.unwrap_or(1),
        names: Vec::new(),
        content_type: None,
        content_length: None,
        connection: None,
        instance: None,
        app_version: None,
        chunked: false,
        head_len,
    };
    for h in resp.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        match name.as_str() {
            "content-type" => head.content_type = Some(text(h.value)),
            "content-length" => match text(h.value).parse() {
                Ok(n) => head.content_length = Some(n),
                Err(_) => return Head::Invalid("bad Content-Length".to_owned()),
            },
            "connection" => head.connection = Some(text(h.value).to_ascii_lowercase()),
            "x-instance" => head.instance = Some(text(h.value)),
            "x-version" => head.app_version = Some(text(h.value)),
            "transfer-encoding" => {
                head.chunked = text(h.value).to_ascii_lowercase().contains("chunked")
            }
            _ => {}
        }
        head.names.push(name);
    }
    Head::Complete(head)
}

/// The run's tally.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub requests: u32,
    pub ok: u32,
    pub aborted: u32,
    pub failed: u32,
    pub connections: u32,
}

impl Tally {
    /// The exit status: every request succeeded or was aborted on purpose.
    pub fn success(&self) -> bool {
        self.failed == 0 && self.ok + self.aborted == self.requests
    }

    pub fn fields(&self) -> Vec<(String, String)> {
        [
            ("requests", self.requests),
            ("ok", self.ok),
            ("aborted", self.aborted),
            ("failed", self.failed),
            ("connections", self.connections),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_string()))
        .collect()
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
    fn urls_parse() {
        let u = Url::parse("http://web/big?n=5").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.target.as_str()),
            ("web", 80, "/big?n=5")
        );
        assert_eq!(u.host_header(), "web");
        let u = Url::parse("http://10.0.0.1:8080").unwrap();
        assert_eq!((u.port, u.target.as_str()), (8080, "/"));
        assert_eq!(u.host_header(), "10.0.0.1:8080");
        let u = Url::parse("http://[fd00::1]:81/x").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("fd00::1", 81));
        assert_eq!(u.host_header(), "[fd00::1]:81");
        let u = Url::parse("https://registry.npmjs.org/left-pad").unwrap();
        assert_eq!(
            (u.port, u.host_header().as_str()),
            (443, "registry.npmjs.org")
        );
        let via = String::from_utf8(u.request_via(false, true, "application/json")).unwrap();
        assert!(via.starts_with(
            "GET https://registry.npmjs.org/left-pad HTTP/1.1\r\nHost: registry.npmjs.org\r\n"
        ));
        assert!(via.contains("Accept: application/json\r\n"));
        let only_https = Config::from_pairs(vec![("url".into(), "https://x/".into())]);
        assert!(only_https.is_err());
        for bad in [
            "ftp://x/",
            "http://",
            "http://h:0/",
            "http://h:x/",
            "http://[fd00::1/",
            "http://u@h/",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
        let req = String::from_utf8(Url::parse("http://web/").unwrap().request(true)).unwrap();
        assert_eq!(
            req,
            "GET / HTTP/1.1\r\nHost: web\r\nUser-Agent: wasmnet-http-get\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
        );
    }

    #[test]
    fn console_lines_and_requests_with_bodies() {
        let cmd = Command::parse("put http://10.0.1.2:8080/backends/web-4   10.0.1.14:80 \n")
            .unwrap()
            .unwrap();
        assert_eq!(cmd.method, "PUT");
        assert_eq!(cmd.url.target, "/backends/web-4");
        assert_eq!(cmd.body, b"10.0.1.14:80");
        let req =
            String::from_utf8(
                cmd.url
                    .request_with(&cmd.method, &cmd.body, false, false, "*/*"),
            )
            .unwrap();
        assert_eq!(
            req,
            "PUT /backends/web-4 HTTP/1.1\r\nHost: 10.0.1.2:8080\r\nUser-Agent: wasmnet-http-get\r\nAccept: */*\r\nConnection: close\r\nContent-Length: 12\r\n\r\n10.0.1.14:80"
        );
        let del = Command::parse("DELETE http://lb:8080/backends/web-2")
            .unwrap()
            .unwrap();
        assert!(del.body.is_empty());
        // A GET without a body is exactly the old request.
        let u = Url::parse("http://web/").unwrap();
        assert_eq!(
            u.request_with("GET", &[], true, false, "*/*"),
            u.request(true)
        );
        assert_eq!(Command::get(&u).method, "GET");
        assert!(Command::parse("  ").is_none());
        assert!(Command::parse("# a comment").is_none());
        for bad in ["FETCH http://x/", "GET", "GET ftp://x/", "PUT https://x/ y"] {
            assert!(matches!(Command::parse(bad), Some(Err(_))), "{bad}");
        }
    }

    #[test]
    fn repeat_quiet_and_console_config() {
        let c = Config::from_pairs(pairs(&[("console", "true"), ("half-close", "true")])).unwrap();
        assert!(c.half_close);
        assert!(c.console && c.urls.is_empty());
        assert_eq!(c.repeat, Some(1));
        let c = Config::from_pairs(pairs(&[
            ("url", "http://lb/"),
            ("repeat", "forever"),
            ("quiet", "true"),
        ]))
        .unwrap();
        assert_eq!((c.repeat, c.quiet), (None, true));
        let c = Config::from_pairs(pairs(&[("url", "http://lb/"), ("repeat", "3")])).unwrap();
        assert_eq!(c.repeat, Some(3));
        for bad in [("repeat", "0"), ("repeat", "always"), ("quiet", "yes")] {
            let p = pairs(&[("url", "http://lb/"), bad]);
            assert!(Config::from_pairs(p).is_err(), "{bad:?}");
        }
        let h =
            b"HTTP/1.1 200 OK\r\nX-Instance: web-2\r\nX-Version: v1\r\nContent-Length: 0\r\n\r\n";
        let Head::Complete(h) = parse_response(h) else {
            panic!("complete")
        };
        assert_eq!(
            (h.instance.as_deref(), h.app_version.as_deref()),
            (Some("web-2"), Some("v1"))
        );
    }

    #[test]
    fn config_keys_and_errors() {
        let all = pairs(&[
            ("app.http-get.url", "http://server/"),
            ("app.http-get.urls", "http://server/a,http://server/b"),
            ("app.http-get.keep-alive", "true"),
            ("app.http-get.start", "20ms"),
            ("app.http-get.recv-buffer", "2048"),
            ("app.http-get.abort-after", "65536"),
            ("app.http-get.read-pause", "1ms"),
            ("app.http-get.request-delay", "200us"),
            ("app.http-server.listen", "0.0.0.0:80"),
        ]);
        let c = Config::from_pairs(app_pairs(all, APP)).unwrap();
        let targets: Vec<&str> = c.urls.iter().map(|u| u.target.as_str()).collect();
        assert_eq!(targets, ["/", "/a", "/b"]);
        assert!(c.keep_alive);
        assert_eq!((c.start_ns, c.read_pause_ns), (20_000_000, 1_000_000));
        assert_eq!(c.request_delay_ns, 200_000);
        assert_eq!((c.recv_buffer, c.abort_after), (Some(2048), Some(65_536)));
        for (p, needle) in [
            (pairs(&[]), "required"),
            (pairs(&[("url", "ftp://x/")]), "url"),
            (
                pairs(&[("url", "http://x/"), ("keep-alive", "1")]),
                "keep-alive",
            ),
            (
                pairs(&[("url", "http://x/"), ("read-size", "0")]),
                "read-size",
            ),
            (pairs(&[("url", "http://x/"), ("colour", "red")]), "unknown"),
        ] {
            let err = Config::from_pairs(p).unwrap_err().to_string();
            assert!(err.contains(needle), "{err}");
        }
    }

    #[test]
    fn responses_parse() {
        let r = b"HTTP/1.1 200 OK\r\nServer: s\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello";
        let Head::Complete(h) = parse_response(r) else {
            panic!("complete")
        };
        assert_eq!((h.status, h.reason.as_str(), h.version), (200, "OK", 1));
        assert_eq!(
            h.names,
            ["server", "content-type", "content-length", "connection"]
        );
        assert_eq!((h.content_length, h.head_len), (Some(5), r.len() - 5));
        assert!(h.keeps_alive());
        assert_eq!(parse_response(&r[..10]), Head::Partial);
        let close = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        assert!(
            matches!(parse_response(close), Head::Complete(h) if !h.keeps_alive() && h.status == 404)
        );
        let eof = b"HTTP/1.0 200 OK\r\n\r\n";
        assert!(
            matches!(parse_response(eof), Head::Complete(h) if !h.keeps_alive() && h.content_length.is_none())
        );
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(parse_response(chunked), Head::Complete(h) if h.chunked));
        assert!(matches!(
            parse_response(b"SSH-2.0-x\r\n\r\n"),
            Head::Invalid(_)
        ));
    }

    #[test]
    fn fnv_and_tally() {
        assert_eq!(error_name("ErrorCode::ConnectionReset"), "connection-reset");
        assert_eq!(error_name("InvalidState"), "invalid-state");
        let mut f = Fnv::default();
        f.update(b"a");
        assert_eq!(f.hex(), "af63dc4c8601ec8c");
        let t = Tally {
            requests: 3,
            ok: 2,
            aborted: 1,
            failed: 0,
            connections: 2,
        };
        assert!(t.success());
        assert!(!Tally { failed: 1, ..t }.success());
        assert_eq!(t.fields()[2], ("aborted".to_owned(), "1".to_owned()));
    }
}
