//! wit-bindgen glue: exports `wasi:cli/run@0.3.0` and serves HTTP/1.1 over the standard `wasip3`
//! TCP socket bindings (world `wasmnet:app/app`), plus `wasmnet:sockets-ext/tcp` for
//! `TCP_NODELAY`.
//!
//! Concurrency without spawning: `run` polls the accept stream and every connection's future
//! itself (one component-model task). Each connection owns its socket, its receive stream and
//! one send stream for all its responses; dropping the send stream is the FIN.

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;

use wasip3::cli::environment;
use wasip3::clocks::monotonic_clock;
use wasip3::sockets::types::{ErrorCode, IpAddressFamily, TcpSocket};
use wit_bindgen::{StreamReader, StreamResult, StreamWriter};

use crate::{
    APP, Body, CHUNK, Config, Fnv, Head, Request, Response, app_pairs, echo, echo_wanted,
    error_name, keep_open, parse_request, pattern_chunk, respond_at, sse_event, take_len,
};

use wasmnet_app_kit::{to_std, to_wit};

wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};
use wasmnet::sockets_ext::tcp as ext;

fn code(e: ErrorCode) -> String {
    error_name(&format!("{e:?}"))
}

/// What the connection's read side produced next.
enum Next {
    Request(Request),
    /// The client closed its side between requests.
    Eof,
    /// Not a valid HTTP/1.x request (or the client closed mid-request).
    Bad(String),
}

/// Reads until `buf` starts with a complete request head.
async fn next_request(rx: &mut StreamReader<u8>, buf: &mut Vec<u8>) -> Next {
    loop {
        match parse_request(buf) {
            Head::Complete(r) => return Next::Request(r),
            Head::Invalid(e) => return Next::Bad(e),
            Head::Partial => {}
        }
        let (status, chunk) = rx.read(Vec::with_capacity(CHUNK)).await;
        match status {
            StreamResult::Complete(_) => buf.extend_from_slice(&chunk),
            StreamResult::Dropped if buf.is_empty() => return Next::Eof,
            StreamResult::Dropped => return Next::Bad("the client closed mid-request".to_owned()),
            StreamResult::Cancelled => {}
        }
    }
}

/// Reads the `n`-byte request body (from `buf` first). `None` if the client closed first.
async fn read_body(rx: &mut StreamReader<u8>, buf: &mut Vec<u8>, n: u64) -> Option<Vec<u8>> {
    // The caller admits only bodies of at most `ECHO_MAX` bytes; a length that does not fit a
    // `usize` is refused like a client that went away.
    let n = usize::try_from(n).ok()?;
    while buf.len() < n {
        let (status, chunk) = rx.read(Vec::with_capacity(CHUNK)).await;
        match status {
            StreamResult::Complete(_) => buf.extend_from_slice(&chunk),
            StreamResult::Dropped => return None,
            StreamResult::Cancelled => {}
        }
    }
    Some(buf.drain(..n).collect())
}

/// Drops `n` request-body bytes, from `buf` first. False if the client closed first.
async fn skip_body(rx: &mut StreamReader<u8>, buf: &mut Vec<u8>, mut n: u64) -> bool {
    let take = take_len(n, buf.len());
    buf.drain(..take);
    n -= take as u64;
    while n > 0 {
        let (status, chunk) = rx.read(Vec::with_capacity(CHUNK)).await;
        match status {
            StreamResult::Complete(_) => {
                let used = take_len(n, chunk.len());
                buf.extend_from_slice(&chunk[used..]);
                n -= used as u64;
            }
            StreamResult::Dropped => return false,
            StreamResult::Cancelled => {}
        }
    }
    true
}

/// Writes one response. Returns the body's hash, or `None` if the connection failed (the
/// netstack dropped our stream: a reset).
async fn write_response(
    tx: &mut StreamWriter<u8>,
    resp: &Response,
    keep: bool,
    extra: &str,
) -> Option<Fnv> {
    let mut fnv = Fnv::default();
    let mut head = resp.head_with(keep, extra);
    match &resp.body {
        Body::Bytes(b) => {
            fnv.update(b);
            head.extend_from_slice(b);
            tx.write_all(head).await.is_empty().then_some(fnv)
        }
        Body::Pattern(n) => {
            if !tx.write_all(head).await.is_empty() {
                return None;
            }
            let mut sent = 0u64;
            while sent < *n {
                let len = take_len(*n - sent, CHUNK);
                let chunk = pattern_chunk(sent, len);
                fnv.update(&chunk);
                if !tx.write_all(chunk).await.is_empty() {
                    return None;
                }
                sent += len as u64;
            }
            Some(fnv)
        }
        Body::Events {
            first,
            last,
            interval_ms,
        } => {
            // Each event goes out as it is due: `interval_ms` of virtual time after the last.
            if !tx.write_all(head).await.is_empty() {
                return None;
            }
            let mut fnv = Fnv::default();
            for id in *first..=*last {
                if id > *first {
                    // wasi:clocks durations are nanoseconds.
                    monotonic_clock::wait_for(*interval_ms * 1_000_000).await;
                }
                let event = sse_event(id);
                fnv.update(&event);
                if !tx.write_all(event).await.is_empty() {
                    return None;
                }
            }
            Some(fnv)
        }
    }
}

/// Serves one connection until either side ends it.
async fn serve(config: Rc<Config>, started: u64, conn: u32, socket: TcpSocket) {
    let peer = socket
        .get_remote_address()
        .map(|a| to_std(a).to_string())
        .unwrap_or_else(code);
    let id = conn.to_string();
    log::log(
        Level::Info,
        &format!("{APP}: connection {conn} from {peer}"),
    );
    event(
        "http-accepted",
        &[("conn", id.clone()), ("peer", peer.clone())],
    );
    if config.no_delay {
        let _ = ext::set_no_delay(&socket, true);
    }
    let (mut rx, _rx_done) = socket.receive();
    let (mut tx, tx_reader) = wasip3::wit_stream::new::<u8>();
    let send_done = socket.send(tx_reader);

    let mut buf = Vec::new();
    let mut served = 0u32;
    let reason = loop {
        let (req, bad) = match next_request(&mut rx, &mut buf).await {
            Next::Request(req) => (Some(req), None),
            Next::Eof => break "peer-closed",
            Next::Bad(e) => (None, Some(e)),
        };
        let (resp, keep) = match &req {
            Some(req) => {
                buf.drain(..req.head_len);
                served += 1;
                event(
                    "http-request",
                    &[
                        ("conn", id.clone()),
                        ("method", req.method.clone()),
                        ("target", req.target.clone()),
                        ("version", format!("HTTP/1.{}", req.version)),
                    ],
                );
                log::log(
                    Level::Info,
                    &format!(
                        "{APP}: {peer} \"{} {} HTTP/1.{}\"",
                        req.method, req.target, req.version
                    ),
                );
                // `POST /echo` keeps its body; every other body is skipped.
                let resp = if echo_wanted(req) {
                    let Some(body) = read_body(&mut rx, &mut buf, req.content_length).await else {
                        break "peer-closed";
                    };
                    echo(body)
                } else {
                    if !skip_body(&mut rx, &mut buf, req.content_length).await {
                        break "peer-closed";
                    }
                    respond_at(&config, req, monotonic_clock::now().saturating_sub(started))
                };
                (resp, keep_open(&config, req, served))
            }
            None => {
                log::log(
                    Level::Warn,
                    &format!(
                        "{APP}: bad request from {peer}: {}",
                        bad.unwrap_or_default()
                    ),
                );
                (Response::bad_request(), false)
            }
        };
        let identity = config.identity_headers();
        let bytes = resp.head_with(keep, &identity).len() as u64 + resp.body_len();
        let Some(fnv) = write_response(&mut tx, &resp, keep, &identity).await else {
            break "error";
        };
        event(
            "http-response",
            &[
                ("conn", id.clone()),
                ("status", resp.status.to_string()),
                ("bytes", bytes.to_string()),
                ("body-bytes", resp.body_len().to_string()),
                ("body-fnv", fnv.hex()),
                ("keep-alive", keep.to_string()),
            ],
        );
        log::log(
            Level::Info,
            &format!(
                "{APP}: {} {} -> {peer} ({} body bytes, fnv {})",
                resp.status,
                resp.reason,
                resp.body_len(),
                fnv.hex()
            ),
        );
        if req.is_none() {
            break "bad-request";
        }
        if !keep {
            break "close";
        }
    };
    // Our FIN, after everything written so far; the future resolves once it was all acked.
    drop(tx);
    let send = match send_done.await {
        Ok(()) => "ok".to_owned(),
        Err(e) => code(e),
    };
    // Nothing more is read: dropping the stream is SHUT_RD (never an RST).
    drop(rx);
    log::log(
        Level::Info,
        &format!("{APP}: connection {conn} from {peer} closed ({reason}, {served} requests)"),
    );
    event(
        "http-closed",
        &[
            ("conn", id),
            ("peer", peer),
            ("requests", served.to_string()),
            ("reason", reason.to_owned()),
            ("send", send),
        ],
    );
}

type Conn = Pin<Box<dyn Future<Output = ()>>>;
type Accepting = Pin<Box<dyn Future<Output = (StreamReader<TcpSocket>, Option<TcpSocket>)>>>;

/// The next connection from the accept stream (the future owns the stream and gives it back).
fn accept_next(mut incoming: StreamReader<TcpSocket>) -> Accepting {
    Box::pin(async move {
        let next = incoming.next().await;
        (incoming, next)
    })
}

/// Creates, configures, binds and starts one listener on `addr`, and logs `http-listening`.
fn open(config: &Config, addr: SocketAddr) -> Result<(TcpSocket, StreamReader<TcpSocket>), String> {
    let family = if addr.is_ipv4() {
        IpAddressFamily::Ipv4
    } else {
        IpAddressFamily::Ipv6
    };
    let listener = TcpSocket::create(family).map_err(|e| format!("create: {e:?}"))?;
    if let Some(n) = config.backlog {
        listener
            .set_listen_backlog_size(n)
            .map_err(|e| format!("backlog: {e:?}"))?;
    }
    if let Some(n) = config.recv_buffer {
        listener
            .set_receive_buffer_size(n)
            .map_err(|e| format!("recv-buffer: {e:?}"))?;
    }
    if let Some(n) = config.send_buffer {
        listener
            .set_send_buffer_size(n)
            .map_err(|e| format!("send-buffer: {e:?}"))?;
    }
    if config.no_delay {
        ext::set_no_delay(&listener, true).map_err(|e| format!("no-delay: {e:?}"))?;
    }
    listener
        .bind(to_wit(addr))
        .map_err(|e| format!("bind {addr}: {e:?}"))?;
    let incoming = listener.listen().map_err(|e| format!("listen: {e:?}"))?;
    let local = listener
        .get_local_address()
        .map(to_std)
        .map_err(|e| format!("local address: {e:?}"))?;
    let backlog = config
        .backlog
        .map_or("default".to_owned(), |b| b.to_string());
    log::log(Level::Info, &format!("{APP}: listening on tcp {local}"));
    event(
        "http-listening",
        &[("address", local.to_string()), ("backlog", backlog)],
    );
    Ok((listener, incoming))
}

async fn listen() -> Result<(), String> {
    let started = monotonic_clock::now();
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let mut config = Config::from_pairs(app_pairs(pairs, APP)).map_err(|e| e.to_string())?;
    if config.wants_environment() {
        // `wasi:cli/environment`: the node's arguments after argv[0], and its variables.
        let args: Vec<String> = environment::get_arguments().into_iter().skip(1).collect();
        config.with_environment(&args, &environment::get_environment());
    }
    let mut listeners = Vec::new();
    let mut accepting: Vec<Option<Accepting>> = Vec::new();
    for &addr in &config.listen {
        let (listener, incoming) = open(&config, addr)?;
        listeners.push(listener);
        accepting.push(Some(accept_next(incoming)));
    }

    let config = Rc::new(config);
    let mut conns: Vec<Conn> = Vec::new();
    let mut count = 0u32;
    poll_fn(|cx| {
        loop {
            let mut accepted = false;
            for slot in accepting.iter_mut() {
                if let Some(a) = slot.as_mut()
                    && let Poll::Ready((incoming, next)) = a.as_mut().poll(cx)
                {
                    match next {
                        Some(socket) => {
                            count += 1;
                            conns.push(Box::pin(serve(config.clone(), started, count, socket)));
                            *slot = Some(accept_next(incoming));
                            accepted = true;
                        }
                        None => *slot = None,
                    }
                }
            }
            conns.retain_mut(|c| c.as_mut().poll(cx).is_pending());
            if !accepted {
                break;
            }
        }
        if accepting.iter().all(Option::is_none) && conns.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    // The listeners must outlive the loop: dropping one stops listening.
    drop(listeners);
    Err("the accept stream ended".to_owned())
}

struct App;

impl exports::wasi::cli::run::Guest for App {
    async fn run() -> Result<(), ()> {
        listen().await.map_err(|e| {
            log::log(Level::Error, &format!("{APP}: {e}"));
        })
    }
}

export!(App);
