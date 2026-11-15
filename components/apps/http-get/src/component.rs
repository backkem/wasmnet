//! wit-bindgen glue: exports `wasi:cli/run@0.3.0` and fetches URLs over the standard `wasip3`
//! TCP socket, name-lookup and clock bindings (world `wasmnet:app/app`), plus
//! `wasmnet:sockets-ext/tcp` for `abort` and `TCP_NODELAY`.

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use wasip3::clocks::monotonic_clock;
use wasip3::sockets::ip_name_lookup::{self, IpAddress};
use wasip3::sockets::types::{ErrorCode, IpAddressFamily, TcpSocket};
use wit_bindgen::{FutureReader, StreamReader, StreamResult, StreamWriter};

use crate::{
    APP, Command, Config, Fnv, Head, MAX_HEAD, Tally, Url, app_pairs, error_name, parse_response,
};

use wasmnet_app_kit::{to_std, to_wit};

wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};
use wasmnet::sockets_ext::tcp as ext;

fn ip(a: IpAddress) -> IpAddr {
    match a {
        IpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        IpAddress::Ipv6((a, b, c, d, e, f, g, h)) => {
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
        }
    }
}

/// `ok`, or the error code in kebab case (`connection-reset`).
fn outcome(r: Result<(), ErrorCode>) -> String {
    match r {
        Ok(()) => "ok".to_owned(),
        Err(e) => error_name(&format!("{e:?}")),
    }
}

/// One open connection: the socket, its two streams and their futures.
struct Conn {
    /// `host:port` as written in the URL: what a later URL must match to reuse it.
    key: (String, u16),
    peer: SocketAddr,
    socket: TcpSocket,
    rx: StreamReader<u8>,
    rx_done: FutureReader<Result<(), ErrorCode>>,
    /// `None` once our FIN was queued.
    tx: Option<StreamWriter<u8>>,
    send_done: FutureReader<Result<(), ErrorCode>>,
    /// Bytes read past the last response.
    buf: Vec<u8>,
    /// The server's FIN arrived.
    eof: bool,
    /// When the last read returned (before any `read-pause`).
    read_at: u64,
    requests: u32,
}

impl Conn {
    /// One read into `buf`, then the configured pause (a slow reader).
    async fn read(&mut self, c: &Config) {
        let (status, chunk) = self.rx.read(Vec::with_capacity(c.read_size)).await;
        self.read_at = monotonic_clock::now();
        match status {
            StreamResult::Complete(_) => self.buf.extend_from_slice(&chunk),
            StreamResult::Dropped => self.eof = true,
            StreamResult::Cancelled => {}
        }
        if c.read_pause_ns > 0 && !self.eof {
            monotonic_clock::wait_for(c.read_pause_ns).await;
        }
    }

    /// An orderly close: our FIN, then read to the server's FIN, then both futures.
    async fn close(mut self, c: &Config) {
        drop(self.tx.take());
        while !self.eof {
            self.buf.clear();
            self.read(c).await;
        }
        let send = outcome(self.send_done.await);
        let receive = outcome(self.rx_done.await);
        drop(self.rx);
        drop(self.socket);
        if c.quiet {
            return;
        }
        event(
            "http-get-closed",
            &[
                ("peer", self.peer.to_string()),
                ("requests", self.requests.to_string()),
                ("send", send),
                ("receive", receive),
            ],
        );
    }

    /// An abortive close (`wasmnet:sockets-ext/tcp.abort`): one RST. Returns how the send and
    /// receive futures resolved.
    async fn abort(self) -> (String, String) {
        ext::abort(&self.socket);
        drop(self.rx);
        drop(self.tx);
        let send = outcome(self.send_done.await);
        let receive = outcome(self.rx_done.await);
        drop(self.socket);
        (send, receive)
    }
}

/// Resolves the URL's host and connects, with the configured socket options.
async fn connect(c: &Config, url: &Url) -> Result<Conn, String> {
    // Through a forward proxy, every connection goes to the proxy.
    let url = c.proxy.as_ref().unwrap_or(url);
    let addrs = ip_name_lookup::resolve_addresses(url.host.clone())
        .await
        .map_err(|e| format!("resolve {}: {e:?}", url.host))?;
    let addr = addrs
        .into_iter()
        .map(ip)
        .next()
        .ok_or_else(|| format!("resolve {}: no address", url.host))?;
    let peer = SocketAddr::new(addr, url.port);
    let family = if addr.is_ipv4() {
        IpAddressFamily::Ipv4
    } else {
        IpAddressFamily::Ipv6
    };
    let socket = TcpSocket::create(family).map_err(|e| format!("create: {e:?}"))?;
    if let Some(n) = c.recv_buffer {
        socket
            .set_receive_buffer_size(n)
            .map_err(|e| format!("recv-buffer: {e:?}"))?;
    }
    if let Some(n) = c.send_buffer {
        socket
            .set_send_buffer_size(n)
            .map_err(|e| format!("send-buffer: {e:?}"))?;
    }
    if c.no_delay {
        ext::set_no_delay(&socket, true).map_err(|e| format!("no-delay: {e:?}"))?;
    }
    socket
        .connect(to_wit(peer))
        .await
        .map_err(|e| format!("connect {peer}: {}", outcome(Err(e))))?;
    let (rx, rx_done) = socket.receive();
    let (tx, tx_reader) = wasip3::wit_stream::new::<u8>();
    let send_done = socket.send(tx_reader);
    Ok(Conn {
        key: (url.host.clone(), url.port),
        peer,
        socket,
        rx,
        rx_done,
        tx: Some(tx),
        send_done,
        buf: Vec::new(),
        eof: false,
        read_at: 0,
        requests: 0,
    })
}

/// How one fetch ended.
enum Fetched {
    /// The whole response arrived. `keep`: the connection may carry the next request.
    /// `body`: kept for a console request (printed to stdout), empty otherwise.
    Done {
        status: u16,
        reason: String,
        keep: bool,
        body: Vec<u8>,
    },
    /// `abort-after` bytes arrived: abort now.
    Abort { body: u64 },
}

/// One request on `conn`. Times are virtual ns since `t0`. `keep_body`: keep the response body
/// (a console request).
async fn fetch(
    c: &Config,
    conn: &mut Conn,
    cmd: &Command,
    t0: u64,
    connect_ns: Option<u64>,
    keep_body: bool,
) -> Result<Fetched, String> {
    let url = &cmd.url;
    conn.requests += 1;
    let reused = connect_ns.is_none();
    if !reused && c.request_delay_ns > 0 {
        monotonic_clock::wait_for(c.request_delay_ns).await;
    }
    let Some(tx) = conn.tx.as_mut() else {
        return Err("the connection is closing".to_owned());
    };
    let head = url.request_with(
        &cmd.method,
        &cmd.body,
        c.keep_alive,
        c.proxy.is_some(),
        &c.accept,
    );
    if !tx.write_all(head).await.is_empty() {
        return Err("the connection closed before the request was sent".to_owned());
    }
    // A client that half-closes early: our FIN goes with the request.
    if c.half_close {
        drop(conn.tx.take());
    }
    if !c.quiet {
        log::log(
            Level::Info,
            &format!("{APP}: {} {} ({})", cmd.method, url.text, conn.peer),
        );
    }
    let mut first_byte = (!conn.buf.is_empty()).then(|| monotonic_clock::now() - t0);
    let head = loop {
        match parse_response(&conn.buf) {
            Head::Complete(h) => break h,
            Head::Invalid(e) => return Err(format!("bad response: {e}")),
            Head::Partial if conn.eof => return Err("closed before the response head".to_owned()),
            Head::Partial => {}
        }
        conn.read(c).await;
        if first_byte.is_none() && !conn.buf.is_empty() {
            first_byte = Some(conn.read_at - t0);
        }
    };
    let first_byte = first_byte.unwrap_or_default();
    let opt = |v: &Option<String>| v.clone().unwrap_or_default();
    if !c.quiet {
        event(
            "http-get-response",
            &[
                ("url", url.text.clone()),
                ("status", head.status.to_string()),
                ("reason", head.reason.clone()),
                ("version", format!("HTTP/1.{}", head.version)),
                ("headers", head.names.join(",")),
                ("content-type", opt(&head.content_type)),
                (
                    "content-length",
                    head.content_length
                        .map(|n| n.to_string())
                        .unwrap_or_default(),
                ),
                ("connection", opt(&head.connection)),
                ("first-byte-ns", first_byte.to_string()),
            ],
        );
    }
    if head.chunked {
        return Err("chunked bodies are not supported".to_owned());
    }
    conn.buf.drain(..head.head_len);
    let mut fnv = Fnv::default();
    let mut body = 0u64;
    let mut kept = Vec::new();
    loop {
        let want = head.content_length.map_or(u64::MAX, |n| n - body);
        let take = (conn.buf.len() as u64).min(want) as usize;
        fnv.update(&conn.buf[..take]);
        if keep_body && kept.len() < MAX_HEAD {
            kept.extend_from_slice(&conn.buf[..take.min(MAX_HEAD - kept.len())]);
        }
        conn.buf.drain(..take);
        body += take as u64;
        if c.abort_after.is_some_and(|a| body >= a) {
            return Ok(Fetched::Abort { body });
        }
        if head.content_length == Some(body) {
            break;
        }
        if conn.eof {
            if head.content_length.is_some() {
                return Err(format!("the body ended after {body} bytes"));
            }
            break;
        }
        conn.read(c).await;
    }
    // The last byte arrived with the last read (a read pause after it does not count).
    let done = conn.read_at.max(t0) - t0;
    if !c.quiet {
        log::log(
            Level::Info,
            &format!(
                "{APP}: {} {} {}: {body} body bytes, fnv {}, first byte {} ns, done {} ns",
                url.text,
                head.status,
                head.reason,
                fnv.hex(),
                first_byte,
                done
            ),
        );
    }
    let mut fields = vec![
        ("url", url.text.clone()),
        ("status", head.status.to_string()),
        ("body-bytes", body.to_string()),
        ("body-fnv", fnv.hex()),
        ("connect-ns", connect_ns.unwrap_or(0).to_string()),
        ("first-byte-ns", first_byte.to_string()),
        ("done-ns", done.to_string()),
        ("reused", reused.to_string()),
    ];
    // Only when there is something to say: other runs' journals stay as they were.
    if cmd.method != "GET" {
        fields.push(("method", cmd.method.clone()));
    }
    if let Some(i) = &head.instance {
        fields.push(("instance", i.clone()));
    }
    if let Some(v) = &head.app_version {
        fields.push(("version", v.clone()));
    }
    event("http-get-done", &fields);
    Ok(Fetched::Done {
        status: head.status,
        reason: head.reason.clone(),
        keep: c.keep_alive && !c.half_close && head.keeps_alive() && !conn.eof,
        body: kept,
    })
}

/// Fetches every URL. `Ok(true)` when every fetch succeeded or was aborted on purpose.
async fn client() -> Result<bool, String> {
    let t_start = monotonic_clock::now();
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let c = Config::from_pairs(app_pairs(pairs, APP)).map_err(|e| e.to_string())?;
    if c.start_ns > 0 {
        monotonic_clock::wait_until(t_start + c.start_ns).await;
    }
    let mut tally = Tally::default();
    let mut open: Option<Conn> = None;
    // The URL list, `repeat` times (or forever: a load generator).
    let mut round = 0u64;
    while !c.urls.is_empty() && c.repeat.is_none_or(|n| round < n) {
        for (i, url) in c.urls.iter().enumerate() {
            if (i > 0 || round > 0) && c.interval_ns > 0 {
                monotonic_clock::wait_for(c.interval_ns).await;
            }
            one(&c, &mut open, &mut tally, &Command::get(url), false).await;
        }
        round += 1;
    }
    if c.console {
        if let Some(conn) = open.take() {
            conn.close(&c).await;
        }
        console(&c, &mut tally).await;
    }
    if let Some(conn) = open {
        conn.close(&c).await;
    }
    log::log(
        Level::Info,
        &format!(
            "{APP}: {} requests, {} ok, {} aborted, {} failed, {} connections",
            tally.requests, tally.ok, tally.aborted, tally.failed, tally.connections
        ),
    );
    log::event("http-get-summary", &tally.fields());
    Ok(tally.success())
}

/// The console: requests read from stdin, one per line, each on a connection of
/// its own; their answers printed to stdout. It reads until stdin ends (in a live session it
/// never does: the next line is the next write to stdin).
async fn console(c: &Config, tally: &mut Tally) {
    let (mut rx, _done) = wasip3::cli::stdin::read_via_stream();
    let mut pending: Vec<u8> = Vec::new();
    loop {
        while let Some(nl) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=nl).collect();
            let line = String::from_utf8_lossy(&line).into_owned();
            match Command::parse(&line) {
                None => {}
                Some(Err(e)) => {
                    tally.requests += 1;
                    tally.failed += 1;
                    println!("? {e}");
                    log::log(Level::Warn, &format!("{APP}: {e}"));
                    event(
                        "http-get-error",
                        &[("url", line.trim().to_owned()), ("error", e)],
                    );
                }
                Some(Ok(cmd)) => {
                    println!("> {} {}", cmd.method, cmd.url.text);
                    let mut open = None;
                    match one(c, &mut open, tally, &cmd, true).await {
                        Some((status, reason, body)) => {
                            println!("< {status} {reason}");
                            let text = String::from_utf8_lossy(&body);
                            for l in text.lines() {
                                println!("  {l}");
                            }
                        }
                        None => println!("< failed"),
                    }
                    if let Some(conn) = open {
                        conn.close(c).await;
                    }
                }
            }
        }
        let (status, chunk) = rx.read(Vec::with_capacity(4096)).await;
        match status {
            StreamResult::Complete(_) => pending.extend_from_slice(&chunk),
            StreamResult::Dropped => break,
            StreamResult::Cancelled => {}
        }
    }
    // A last line without a newline.
    if !pending.is_empty() {
        pending.push(b'\n');
        let line = String::from_utf8_lossy(&pending).into_owned();
        if let Some(Ok(cmd)) = Command::parse(&line) {
            let mut open = None;
            if let Some((status, reason, _)) = one(c, &mut open, tally, &cmd, true).await {
                println!("< {status} {reason}");
            }
            if let Some(conn) = open {
                conn.close(c).await;
            }
        }
    }
}

/// One request, on `open` when it goes to the same place (keep-alive), else on a new connection
/// (left in `open` when it may carry the next one). Returns the status, reason and (for a
/// console request) the body, or `None` when it failed.
async fn one(
    c: &Config,
    open: &mut Option<Conn>,
    tally: &mut Tally,
    cmd: &Command,
    keep_body: bool,
) -> Option<(u16, String, Vec<u8>)> {
    let url = &cmd.url;
    tally.requests += 1;
    let t0 = monotonic_clock::now();
    if let Some(conn) = open.take() {
        let dest = c.proxy.as_ref().unwrap_or(url);
        if conn.key == (dest.host.clone(), dest.port) {
            *open = Some(conn);
        } else {
            conn.close(c).await;
        }
    }
    let (mut conn, connect_ns) = match open.take() {
        Some(conn) => (conn, None),
        None => match connect(c, url).await {
            Ok(conn) => {
                tally.connections += 1;
                let ns = monotonic_clock::now() - t0;
                if !c.quiet {
                    let local = conn
                        .socket
                        .get_local_address()
                        .map(|a| to_std(a).to_string())
                        .unwrap_or_default();
                    log::log(
                        Level::Info,
                        &format!("{APP}: connected {local} -> {} in {ns} ns", conn.peer),
                    );
                    event(
                        "http-get-connected",
                        &[
                            ("url", url.text.clone()),
                            ("peer", conn.peer.to_string()),
                            ("local", local),
                            ("connect-ns", ns.to_string()),
                        ],
                    );
                }
                (conn, Some(ns))
            }
            Err(e) => {
                tally.failed += 1;
                log::log(Level::Warn, &format!("{APP}: {}: {e}", url.text));
                event("http-get-error", &[("url", url.text.clone()), ("error", e)]);
                return None;
            }
        },
    };
    match fetch(c, &mut conn, cmd, t0, connect_ns, keep_body).await {
        Ok(Fetched::Done {
            status,
            reason,
            keep,
            body,
        }) => {
            if status < 400 {
                tally.ok += 1;
            } else {
                tally.failed += 1;
            }
            if keep {
                *open = Some(conn);
            } else {
                conn.close(c).await;
            }
            Some((status, reason, body))
        }
        Ok(Fetched::Abort { body }) => {
            tally.aborted += 1;
            let (send, receive) = conn.abort().await;
            log::log(
                Level::Info,
                &format!("{APP}: aborted {} after {body} body bytes (RST)", url.text),
            );
            event(
                "http-get-aborted",
                &[
                    ("url", url.text.clone()),
                    ("body-bytes", body.to_string()),
                    ("send", send),
                    ("receive", receive),
                ],
            );
            None
        }
        Err(e) => {
            tally.failed += 1;
            log::log(Level::Warn, &format!("{APP}: {}: {e}", url.text));
            event("http-get-error", &[("url", url.text.clone()), ("error", e)]);
            conn.close(c).await;
            None
        }
    }
}

struct App;

impl exports::wasi::cli::run::Guest for App {
    async fn run() -> Result<(), ()> {
        match client().await {
            Ok(true) => Ok(()),
            Ok(false) => Err(()),
            Err(e) => {
                log::log(Level::Error, &format!("{APP}: {e}"));
                Err(())
            }
        }
    }
}

export!(App);
