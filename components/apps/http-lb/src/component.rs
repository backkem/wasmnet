//! wit-bindgen glue: exports `wasi:cli/run@0.3.0`, accepts and proxies over the standard
//! `wasip3` TCP socket bindings (world `wasmnet:app/app`), and draws the random policy's numbers
//! from `wasi:random` (the node's seeded PRNG).
//!
//! Concurrency without spawning: `run` polls both accept streams, every connection's future and
//! every health check itself (one component-model task), like http-server. The pool is shared
//! through an `Rc<RefCell<..>>` that is never borrowed across an `await`.

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::RefCell;
use std::future::{Future, IntoFuture, poll_fn};
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::task::Poll;

use wasip3::clocks::monotonic_clock;
use wasip3::sockets::types::{ErrorCode, IpAddressFamily, TcpSocket};
use wit_bindgen::{FutureReader, StreamReader, StreamResult, StreamWriter};

use crate::{
    APP, Answer, BodyLength, Change, Config, Head, MAX_BODY, Pool, Registered, Request, State,
    admin, app_pairs, body_length, error_name, health_request, parse_request, parse_response,
    passes,
};

use wasmnet_app_kit::{to_std, to_wit};

wasmnet_app_kit::app_bindings!();

use wasi::config::store;
use wasmnet::link::log::{self, Level};

/// Bytes asked for per stream read.
const CHUNK: usize = 16 * 1024;

/// How long a closing connection waits for its last bytes to be acknowledged (virtual ns).
const LINGER: u64 = 2_000_000_000;

/// The largest backend response passed on (buffered whole).
const MAX_RESPONSE: usize = 4 << 20;

fn code(e: ErrorCode) -> String {
    error_name(&format!("{e:?}"))
}

/// `fut`, or `None` once `ns` of virtual time passed first (the future is then dropped).
async fn within<T>(ns: u64, fut: impl Future<Output = T>) -> Option<T> {
    let mut fut = pin!(fut);
    let mut sleep = pin!(monotonic_clock::wait_for(ns));
    poll_fn(|cx| {
        if let Poll::Ready(v) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(v));
        }
        if sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

/// One TCP connection: the socket and its two streams.
struct Conn {
    socket: TcpSocket,
    rx: StreamReader<u8>,
    tx: Option<StreamWriter<u8>>,
    /// Resolves once everything sent (and our FIN) was acknowledged.
    send_done: FutureReader<Result<(), ErrorCode>>,
    rx_done: FutureReader<Result<(), ErrorCode>>,
    /// Bytes read so far and not consumed.
    buf: Vec<u8>,
    eof: bool,
}

impl Conn {
    fn new(socket: TcpSocket) -> Self {
        let (rx, rx_done) = socket.receive();
        let (tx, tx_reader) = wasip3::wit_stream::new::<u8>();
        let send_done = socket.send(tx_reader);
        Self {
            socket,
            rx,
            tx: Some(tx),
            send_done,
            rx_done,
            buf: Vec::new(),
            eof: false,
        }
    }

    async fn read(&mut self) {
        let (status, chunk) = self.rx.read(Vec::with_capacity(CHUNK)).await;
        match status {
            StreamResult::Complete(_) => self.buf.extend_from_slice(&chunk),
            StreamResult::Dropped => self.eof = true,
            StreamResult::Cancelled => {}
        }
    }

    /// Writes everything; false if the connection is gone.
    async fn write(&mut self, bytes: Vec<u8>) -> bool {
        match self.tx.as_mut() {
            Some(tx) => tx.write_all(bytes).await.is_empty(),
            None => false,
        }
    }

    /// Reads until `buf` starts with a complete request head.
    async fn request(&mut self) -> Result<Request, String> {
        loop {
            match parse_request(&self.buf) {
                Head::Complete(r) => return Ok(r),
                Head::Invalid(e) => return Err(e),
                Head::Partial if self.eof && self.buf.is_empty() => {
                    return Err("closed before a request".to_owned());
                }
                Head::Partial if self.eof => return Err("closed mid-request".to_owned()),
                Head::Partial => self.read().await,
            }
        }
    }

    /// Takes the `n`-byte body after a head of `head_len` bytes.
    async fn body(&mut self, head_len: usize, n: u64) -> Option<Vec<u8>> {
        self.buf.drain(..head_len);
        let n = n.min(MAX_BODY) as usize;
        while self.buf.len() < n {
            if self.eof {
                return None;
            }
            self.read().await;
        }
        Some(self.buf.drain(..n).collect())
    }

    /// The request head and its body (`None`: closed before the whole body arrived), read
    /// together so one request timeout covers both: a client that sends a head and stalls
    /// cannot hold the connection forever.
    async fn request_and_body(&mut self) -> Result<(Request, Option<Vec<u8>>), String> {
        let req = self.request().await?;
        let body = self.body(req.head_len, req.content_length).await;
        Ok((req, body))
    }

    /// Our FIN, then (for at most [`LINGER`] of virtual time) the peer's acknowledgement of
    /// everything sent; the receive side is dropped with the connection (SHUT_RD, never an RST).
    async fn finish(mut self) {
        drop(self.tx.take());
        let _ = within(LINGER, self.send_done.into_future()).await;
        drop(self.rx);
        drop(self.rx_done);
        drop(self.socket);
    }
}

/// Connects to `addr`.
async fn connect(addr: SocketAddr) -> Result<Conn, String> {
    let family = if addr.is_ipv4() {
        IpAddressFamily::Ipv4
    } else {
        IpAddressFamily::Ipv6
    };
    let socket = TcpSocket::create(family).map_err(|e| format!("create: {e:?}"))?;
    socket.connect(to_wit(addr)).await.map_err(code)?;
    Ok(Conn::new(socket))
}

/// Reads a whole response to a `method` request on `conn`: interim (`1xx`) heads, the final
/// head, then its body as RFC 9112 §6.3 delimits it ([`body_length`]: none, by
/// `Content-Length`, else to the backend's FIN). Returns the final status and every byte,
/// interim responses included (a proxy passes them on).
async fn read_response(conn: &mut Conn, method: &str) -> Result<(u16, Vec<u8>), String> {
    // Where the head being read starts (after the interim responses).
    let mut start = 0;
    let (head, length) = loop {
        match parse_response(&conn.buf[start..]) {
            Head::Complete(h) => match body_length(method, &h) {
                BodyLength::Interim if start + h.head_len > MAX_RESPONSE => {
                    return Err("bad-response".to_owned());
                }
                BodyLength::Interim => start += h.head_len,
                BodyLength::Unsupported => return Err("bad-response".to_owned()),
                length => break (h, length),
            },
            Head::Invalid(_) => return Err("bad-response".to_owned()),
            Head::Partial if conn.eof => return Err("reset".to_owned()),
            Head::Partial => conn.read().await,
        }
    };
    let head_end = start + head.head_len;
    loop {
        let body = conn.buf.len() - head_end;
        match length {
            BodyLength::None => {
                conn.buf.truncate(head_end);
                break;
            }
            BodyLength::Exactly(n) if body as u64 >= n => {
                conn.buf.truncate(head_end + n as usize);
                break;
            }
            _ if conn.eof => {
                if length != BodyLength::ToClose {
                    return Err("reset".to_owned());
                }
                break;
            }
            _ if conn.buf.len() > MAX_RESPONSE => return Err("bad-response".to_owned()),
            _ => conn.read().await,
        }
    }
    Ok((head.status, std::mem::take(&mut conn.buf)))
}

/// Everything the futures share.
struct Lb {
    config: Config,
    pool: Pool,
    /// Per backend name: when its next health check is due, and the registration (epoch) of
    /// the check running now, if one is.
    due: Vec<(String, u64, Option<u64>)>,
    requests: u64,
    /// The backend the last request went to (`again`: the same one twice in a row).
    last: Option<String>,
    bad: u64,
}

type Shared = Rc<RefCell<Lb>>;

impl Lb {
    /// Schedules an immediate check of a new or moved backend.
    fn check_now(&mut self, name: &str) {
        let now = monotonic_clock::now();
        match self.due.iter_mut().find(|d| d.0 == name) {
            Some(d) => d.1 = now,
            None => self.due.push((name.to_owned(), now, None)),
        }
    }

    fn registered(&mut self, name: &str, addr: SocketAddr, via: &str) {
        log::log(
            Level::Info,
            &format!("{APP}: registered {name} at {addr} ({via})"),
        );
        event(
            "lb-registered",
            &[
                ("backend", name.to_owned()),
                ("addr", addr.to_string()),
                ("via", via.to_owned()),
            ],
        );
        event(
            "lb-health",
            &[
                ("backend", name.to_owned()),
                ("state", State::Checking.to_string()),
                ("reason", "registered".to_owned()),
            ],
        );
        self.check_now(name);
    }
}

/// One health check of `addr`: the status, or why it failed.
async fn probe(addr: SocketAddr, path: &str) -> Result<u16, String> {
    let mut conn = connect(addr).await?;
    if !conn.write(health_request(path, &addr)).await {
        return Err("reset".to_owned());
    }
    let r = read_response(&mut conn, "GET").await;
    conn.finish().await;
    r.map(|(status, _)| status)
}

/// Checks `name` (as registered at `epoch`) once and applies the result.
async fn check(lb: Shared, name: String, epoch: u64, addr: SocketAddr) {
    let (path, timeout) = {
        let l = lb.borrow();
        (l.config.health.path.clone(), l.config.health.timeout_ns)
    };
    let result = within(timeout, probe(addr, &path))
        .await
        .unwrap_or_else(|| Err("timeout".to_owned()));
    let (pass, reason) = match &result {
        Ok(status) => (passes(*status), status.to_string()),
        Err(e) => (false, e.clone()),
    };
    let mut l = lb.borrow_mut();
    let interval = l.config.health.interval_ns;
    // The next check: an interval from now, or at once when the backend was registered again
    // (or moved) while this one ran (its result is stale and ignored below).
    let current = l.pool.get(&name).map(|b| b.epoch);
    if let Some(d) = l.due.iter_mut().find(|d| d.0 == name)
        && d.2 == Some(epoch)
    {
        d.2 = None;
        let now = monotonic_clock::now();
        d.1 = if current == Some(epoch) {
            now.max(d.1) + interval
        } else {
            now
        };
    }
    if let Some(state) = l.pool.checked(&name, epoch, pass) {
        log::log(Level::Info, &format!("{APP}: {name} is {state} ({reason})"));
        event(
            "lb-health",
            &[
                ("backend", name),
                ("state", state.to_string()),
                ("reason", reason),
            ],
        );
    }
}

/// Answers a malformed request `400` and counts it.
async fn bad_request(lb: &Shared, conn: &mut Conn, role: &str, client: &str, error: String) {
    lb.borrow_mut().bad += 1;
    log::log(
        Level::Warn,
        &format!("{APP}: bad {role} request from {client}: {error}"),
    );
    event(
        "lb-bad-request",
        &[
            ("role", role.to_owned()),
            ("client", client.to_owned()),
            ("error", error),
        ],
    );
    conn.write(Answer::new(400, "bad request\n").bytes()).await;
}

fn peer_of(socket: &TcpSocket) -> SocketAddr {
    socket
        .get_remote_address()
        .map(to_std)
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
}

/// Proxies one client request to one backend.
async fn proxy(lb: Shared, socket: TcpSocket) {
    let client = peer_of(&socket);
    let mut conn = Conn::new(socket);
    let timeout = lb.borrow().config.timeout_ns;
    let (req, body) = match within(timeout, conn.request_and_body()).await {
        Some(Ok((r, Some(body)))) => (r, body),
        // Closed before the whole body arrived.
        Some(Ok((_, None))) => {
            conn.finish().await;
            return;
        }
        Some(Err(e)) if conn.buf.is_empty() && conn.eof => {
            let _ = e;
            conn.finish().await;
            return;
        }
        Some(Err(e)) => {
            bad_request(&lb, &mut conn, "proxy", &client.to_string(), e).await;
            conn.finish().await;
            return;
        }
        None => {
            conn.finish().await;
            return;
        }
    };
    // Choose: a random number only when the random policy has a choice to make.
    let (id, pick, again, connect_timeout) = {
        let mut l = lb.borrow_mut();
        l.requests += 1;
        let r = if l.pool.wants_random() {
            wasip3::random::random::get_random_u64()
        } else {
            0
        };
        let pick = l.pool.pick(r);
        let name = pick.as_ref().map(|p| p.0.clone());
        let again = name.is_some() && name == l.last;
        if name.is_some() {
            l.last = name;
        }
        (l.requests, pick, again, l.config.connect_timeout_ns)
    };
    let fields = |backend: &str, status: u16, result: &str| {
        [
            ("request", id.to_string()),
            ("client", client.ip().to_string()),
            ("backend", backend.to_owned()),
            ("status", status.to_string()),
            ("result", result.to_owned()),
            ("again", again.to_string()),
        ]
    };
    let Some((name, addr)) = pick else {
        event("lb-forward", &fields("", 503, "no-backend"));
        conn.write(Answer::new(503, "no backend is in rotation\n").bytes())
            .await;
        conn.finish().await;
        return;
    };
    let outcome: Result<(u16, Vec<u8>), (u16, String)> = async {
        let mut up = match within(connect_timeout, connect(addr)).await {
            None => return Err((502, "connect-timeout".to_owned())),
            Some(Err(e)) => return Err((502, e)),
            Some(Ok(c)) => c,
        };
        let mut head = req.upstream_head(&client.ip().to_string());
        head.extend_from_slice(&body);
        let r = within(timeout, async {
            if !up.write(head).await {
                return Err("reset".to_owned());
            }
            read_response(&mut up, &req.method).await
        })
        .await;
        up.finish().await;
        match r {
            None => Err((504, "timeout".to_owned())),
            Some(Err(e)) => Err((502, e)),
            Some(Ok(v)) => Ok(v),
        }
    }
    .await;
    match outcome {
        Ok((status, bytes)) => {
            lb.borrow_mut().pool.record(&name, true);
            event("lb-forward", &fields(&name, status, "ok"));
            conn.write(bytes).await;
        }
        Err((status, why)) => {
            lb.borrow_mut().pool.record(&name, false);
            log::log(
                Level::Warn,
                &format!("{APP}: request {id} to {name} ({addr}): {why}"),
            );
            event("lb-forward", &fields(&name, status, &why));
            conn.write(Answer::new(status, format!("{name}: {why}\n")).bytes())
                .await;
        }
    }
    conn.finish().await;
}

/// Serves one admin request.
async fn admin_conn(lb: Shared, socket: TcpSocket) {
    let client = peer_of(&socket);
    let mut conn = Conn::new(socket);
    let timeout = lb.borrow().config.timeout_ns;
    let (req, body) = match within(timeout, conn.request_and_body()).await {
        Some(Ok((r, Some(body)))) => (r, body),
        // Closed before the whole body arrived.
        Some(Ok((_, None))) => {
            conn.finish().await;
            return;
        }
        Some(Err(_)) if conn.buf.is_empty() && conn.eof => {
            conn.finish().await;
            return;
        }
        Some(Err(e)) => {
            bad_request(&lb, &mut conn, "admin", &client.to_string(), e).await;
            conn.finish().await;
            return;
        }
        None => {
            conn.finish().await;
            return;
        }
    };
    let answer = {
        let mut l = lb.borrow_mut();
        let (answer, change) = admin(&mut l.pool, &req.method, &req.target, &body);
        event(
            "lb-admin",
            &[
                ("method", req.method.clone()),
                ("target", req.target.clone()),
                ("status", answer.status.to_string()),
            ],
        );
        match change {
            Some(Change::Registered { name, addr }) => l.registered(&name, addr, "admin"),
            Some(Change::Deregistered { name }) => {
                l.due.retain(|d| d.0 != name);
                log::log(Level::Info, &format!("{APP}: deregistered {name}"));
                event(
                    "lb-deregistered",
                    &[("backend", name), ("via", "admin".to_owned())],
                );
            }
            Some(Change::Policy(p)) => {
                log::log(Level::Info, &format!("{APP}: policy {p}"));
                event(
                    "lb-policy",
                    &[("policy", p.to_string()), ("via", "admin".to_owned())],
                );
            }
            None => {}
        }
        answer
    };
    conn.write(answer.bytes()).await;
    conn.finish().await;
}

type Task = Pin<Box<dyn Future<Output = ()>>>;
type Accepting = Pin<Box<dyn Future<Output = (StreamReader<TcpSocket>, Option<TcpSocket>)>>>;

/// The next connection from the accept stream (the future owns the stream and gives it back).
fn accept_next(mut incoming: StreamReader<TcpSocket>) -> Accepting {
    Box::pin(async move {
        let next = incoming.next().await;
        (incoming, next)
    })
}

/// Creates, binds and starts one listener, and logs `lb-listening`.
fn open(addr: SocketAddr, role: &str) -> Result<(TcpSocket, StreamReader<TcpSocket>), String> {
    let family = if addr.is_ipv4() {
        IpAddressFamily::Ipv4
    } else {
        IpAddressFamily::Ipv6
    };
    let listener = TcpSocket::create(family).map_err(|e| format!("create: {e:?}"))?;
    listener
        .bind(to_wit(addr))
        .map_err(|e| format!("bind {addr}: {e:?}"))?;
    let incoming = listener.listen().map_err(|e| format!("listen: {e:?}"))?;
    log::log(Level::Info, &format!("{APP}: {role} on tcp {addr}"));
    event(
        "lb-listening",
        &[("address", addr.to_string()), ("role", role.to_owned())],
    );
    Ok((listener, incoming))
}

async fn serve() -> Result<(), String> {
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let config = Config::from_pairs(app_pairs(pairs, APP)).map_err(|e| e.to_string())?;
    let (proxy_listener, proxy_in) = open(config.listen, "proxy")?;
    let (admin_listener, admin_in) = open(config.admin, "admin")?;
    let lb: Shared = Rc::new(RefCell::new(Lb {
        pool: Pool::new(config.policy, &config.health),
        config: config.clone(),
        due: Vec::new(),
        requests: 0,
        last: None,
        bad: 0,
    }));
    event(
        "lb-policy",
        &[
            ("policy", config.policy.to_string()),
            ("via", "config".to_owned()),
        ],
    );
    for (name, addr) in &config.backends {
        let mut l = lb.borrow_mut();
        if l.pool.register(name, *addr) == Registered::New {
            l.registered(name, *addr, "config");
        }
    }

    let mut accepting: [Option<(bool, Accepting)>; 2] = [
        Some((false, accept_next(proxy_in))),
        Some((true, accept_next(admin_in))),
    ];
    let mut tasks: Vec<Task> = Vec::new();
    // The health checker's timer: its deadline and its wait.
    let mut timer: Option<(u64, Task)> = None;
    poll_fn(|cx| {
        loop {
            let mut progress = false;
            for slot in accepting.iter_mut() {
                if let Some((is_admin, a)) = slot.as_mut()
                    && let Poll::Ready((incoming, next)) = a.as_mut().poll(cx)
                {
                    let is_admin = *is_admin;
                    match next {
                        Some(socket) => {
                            let task: Task = if is_admin {
                                Box::pin(admin_conn(lb.clone(), socket))
                            } else {
                                Box::pin(proxy(lb.clone(), socket))
                            };
                            tasks.push(task);
                            *slot = Some((is_admin, accept_next(incoming)));
                            progress = true;
                        }
                        None => *slot = None,
                    }
                }
            }
            // Health checks that are due, in registration order.
            let now = monotonic_clock::now();
            let starting: Vec<(String, u64, SocketAddr)> = {
                let mut l = lb.borrow_mut();
                let Lb { pool, due, .. } = &mut *l;
                let mut out = Vec::new();
                for b in &pool.backends {
                    if let Some(d) = due.iter_mut().find(|d| d.0 == b.name)
                        && d.2.is_none()
                        && d.1 <= now
                    {
                        d.2 = Some(b.epoch);
                        out.push((b.name.clone(), b.epoch, b.addr));
                    }
                }
                out
            };
            for (name, epoch, addr) in starting {
                tasks.push(Box::pin(check(lb.clone(), name, epoch, addr)));
                progress = true;
            }
            let before = tasks.len();
            tasks.retain_mut(|t| t.as_mut().poll(cx).is_pending());
            if tasks.len() != before {
                progress = true;
            }
            // The timer: armed for the earliest check not running yet.
            let next = lb
                .borrow()
                .due
                .iter()
                .filter(|d| d.2.is_none())
                .map(|d| d.1)
                .min();
            match (next, &mut timer) {
                (None, _) => timer = None,
                (Some(at), Some((armed, _))) if *armed <= at => {}
                (Some(at), _) => {
                    timer = Some((at, Box::pin(monotonic_clock::wait_until(at))));
                }
            }
            if let Some((_, t)) = timer.as_mut()
                && t.as_mut().poll(cx).is_ready()
            {
                timer = None;
                progress = true;
            }
            if !progress {
                break;
            }
        }
        if accepting.iter().all(Option::is_none) && tasks.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    // The listeners must outlive the loop: dropping one stops listening.
    drop(proxy_listener);
    drop(admin_listener);
    Err("the accept streams ended".to_owned())
}

struct App;

impl exports::wasi::cli::run::Guest for App {
    async fn run() -> Result<(), ()> {
        serve().await.map_err(|e| {
            log::log(Level::Error, &format!("{APP}: {e}"));
        })
    }
}

export!(App);
