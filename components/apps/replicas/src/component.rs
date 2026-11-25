//! wit-bindgen glue: exports `wasi:cli/run@0.3.0`; reconciles through `wasmnet:infra/devices`,
//! registers instances over the standard `wasip3` TCP socket, reads desired state from the
//! standard `wasi:cli/stdin@0.3.0`.

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddrV4;
use std::rc::Rc;

use wasip3::clocks::monotonic_clock;
use wasip3::sockets::types::{IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, TcpSocket};
use wit_bindgen::StreamResult;

use crate::{
    APP, Action, Config, Fetch, Seen, parse_line, plan, response_body, status_of, take_lines,
};

wit_bindgen::generate!({
    inline: "
        package app:replicas;
        world replicas {
            include wasmnet:app/app@0.1.0;
            import wasmnet:infra/devices@0.1.2;
            import wasmnet:infra/changes@0.1.2;
            import wasmnet:infra/components@0.1.2;
        }
    ",
    path: [
        "../../../wit/deps/clocks",
        "../../../wit/deps/random",
        "../../../wit/deps/filesystem",
        "../../../wit/deps/sockets",
        "../../../wit/deps/cli",
        "../../../wit/deps/config",
        "../../../wit/link",
        "../../../wit/sockets-ext",
        "../../../wit/app",
        "../../../wit/infra",
    ],
    generate_all,
    with: {
        "wasi:sockets/types@0.3.0": wasip3::sockets::types,
        "wasi:sockets/ip-name-lookup@0.3.0": wasip3::sockets::ip_name_lookup,
        "wasi:clocks/types@0.3.0": wasip3::clocks::types,
        "wasi:clocks/monotonic-clock@0.3.0": wasip3::clocks::monotonic_clock,
    },
});

use wasi::config::store;
use wasmnet::infra::events::TableSince;
use wasmnet::infra::types::{ChangeKind, Phase};
use wasmnet::infra::{changes, components, devices};
use wasmnet::link::log::{self, Level};

fn event(kind: &str, fields: &[(&str, String)]) {
    let fields: Vec<(String, String)> = fields
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    log::event(kind, &fields);
}

fn phase_name(p: Phase) -> &'static str {
    match p {
        Phase::Pending => "pending",
        Phase::Running => "running",
        Phase::Stopped => "stopped",
        Phase::Crashed => "crashed",
        Phase::Removed => "removed",
        Phase::Failed => "failed",
    }
}

fn error(what: &str, e: impl std::fmt::Debug) {
    let e = format!("{e:?}");
    log::log(Level::Warn, &format!("{APP}: {what}: {e}"));
    event("replicas-error", &[("what", what.to_owned()), ("error", e)]);
}

/// Reads `replicas=N` lines from stdin into `desired`, forever (stdin never ends in a simulation).
async fn read_stdin(desired: Rc<Cell<u32>>, max: u32) {
    let (mut rx, _done) = wasip3::cli::stdin::read_via_stream();
    let mut buf = Vec::new();
    loop {
        let (status, chunk) = rx.read(Vec::with_capacity(256)).await;
        buf.extend_from_slice(&chunk);
        for line in take_lines(&mut buf) {
            match parse_line(&line, max) {
                Some(n) if n != desired.get() => {
                    desired.set(n);
                    event(
                        "replicas-desired",
                        &[("replicas", n.to_string()), ("from", "stdin".to_owned())],
                    );
                }
                Some(_) => {}
                None if line.trim().is_empty() => {}
                None => log::log(
                    Level::Warn,
                    &format!("{APP}: stdin: `{line}` is not `replicas=N` (N at most {max})"),
                ),
            }
        }
        if matches!(status, StreamResult::Dropped) {
            return;
        }
    }
}

/// One admin request to the load balancer over TCP: the response's status code.
async fn admin(addr: SocketAddrV4, request: Vec<u8>, half_close: bool) -> Result<u16, String> {
    let socket = TcpSocket::create(IpAddressFamily::Ipv4).map_err(|e| format!("create: {e:?}"))?;
    let [a, b, c, d] = addr.ip().octets();
    socket
        .connect(IpSocketAddress::Ipv4(Ipv4SocketAddress {
            port: addr.port(),
            address: (a, b, c, d),
        }))
        .await
        .map_err(|e| format!("connect {addr}: {e:?}"))?;
    let (mut rx, rx_done) = socket.receive();
    let (mut tx, tx_reader) = wasip3::wit_stream::new::<u8>();
    let send_done = socket.send(tx_reader);
    if !tx.write_all(request).await.is_empty() {
        return Err("closed before the request was sent".to_owned());
    }
    // By default our FIN goes after the response, as an interactive console's does.
    // `half-close = true` sends it right behind the request: once that stalled the load balancer
    // in a browser runtime (a jco task-registration bug), so a regression test keeps it working.
    let mut tx = Some(tx);
    if half_close {
        drop(tx.take());
    }
    let mut response = Vec::new();
    loop {
        let (status, chunk) = rx.read(Vec::with_capacity(4096)).await;
        response.extend_from_slice(&chunk);
        // The status line is all we need; the server closes after its response.
        if !matches!(status, StreamResult::Complete(_)) || response.len() > 64 * 1024 {
            break;
        }
    }
    drop(tx);
    drop(rx);
    let _ = send_done.await;
    let _ = rx_done.await;
    drop(socket);
    status_of(&response).ok_or_else(|| "no HTTP response".to_owned())
}

/// Fetches the instances' component from its store over TCP (one `GET`, the whole response
/// read until the server closes), and supplies it to the host: its digest reference.
async fn fetch_component(f: &Fetch) -> Result<String, String> {
    let socket = TcpSocket::create(IpAddressFamily::Ipv4).map_err(|e| format!("create: {e:?}"))?;
    let [a, b, c, d] = f.addr.ip().octets();
    socket
        .connect(IpSocketAddress::Ipv4(Ipv4SocketAddress {
            port: f.addr.port(),
            address: (a, b, c, d),
        }))
        .await
        .map_err(|e| format!("connect {}: {e:?}", f.addr))?;
    let (mut rx, rx_done) = socket.receive();
    let (mut tx, tx_reader) = wasip3::wit_stream::new::<u8>();
    let send_done = socket.send(tx_reader);
    if !tx.write_all(f.request()).await.is_empty() {
        return Err("closed before the request was sent".to_owned());
    }
    // Room for the head besides the largest body it accepts.
    let limit = usize::try_from(f.max)
        .unwrap_or(usize::MAX)
        .saturating_add(16 << 10);
    let mut response = Vec::new();
    let too_large = loop {
        let (status, chunk) = rx.read(Vec::with_capacity(64 << 10)).await;
        response.extend_from_slice(&chunk);
        if response.len() > limit {
            break true;
        }
        if !matches!(status, StreamResult::Complete(_)) {
            break false;
        }
    };
    drop(tx);
    drop(rx);
    let _ = send_done.await;
    let _ = rx_done.await;
    drop(socket);
    if too_large {
        return Err(format!("the component is larger than {} bytes", f.max));
    }
    let body = response_body(&response)?;
    let digest = components::supply(f.digest.as_deref(), body).map_err(|e| format!("{e:?}"))?;
    event(
        "replicas-supplied",
        &[("digest", digest.clone()), ("size", body.len().to_string())],
    );
    Ok(digest)
}

/// What the world has of our instances, by name.
fn seen(c: &Config) -> BTreeMap<String, Seen> {
    let (_, items) = devices::list(&c.labels());
    items
        .into_iter()
        .filter(|d| c.index(&d.name).is_some())
        .map(|d| {
            let s = match (d.phase, d.target) {
                (_, Some(Phase::Removed)) => Seen::Leaving,
                (Phase::Running, Some(Phase::Stopped)) => Seen::Leaving,
                (Phase::Stopped, Some(Phase::Running)) => Seen::Pending,
                (Phase::Pending, _) => Seen::Pending,
                (Phase::Running, _) => Seen::Running,
                (Phase::Stopped, _) => Seen::Stopped,
                // A crashed instance is started again, like a stopped one.
                (Phase::Crashed, _) => Seen::Stopped,
                (Phase::Failed, _) => Seen::Failed,
                (Phase::Removed, _) => Seen::Leaving,
            };
            (d.name, s)
        })
        .collect()
}

async fn step(c: &Config, desired: u32, registered: &mut BTreeSet<String>) {
    let labels = c.labels();
    for action in plan(c, desired, &seen(c), registered) {
        match action {
            Action::Apply(n) => {
                if let Err(e) = devices::apply(None, &c.name(n), &labels, &c.spec(n)) {
                    error(&format!("apply {}", c.name(n)), e);
                }
            }
            Action::Start(name) => {
                if let Err(e) = devices::start(None, &name) {
                    error(&format!("start {name}"), e);
                }
            }
            Action::Remove(name) => {
                if c.grace_ns > 0
                    && let Err(e) = devices::stop(None, &name, c.grace_ns)
                {
                    error(&format!("stop {name}"), e);
                }
                if let Err(e) = devices::remove(None, &name) {
                    error(&format!("remove {name}"), e);
                }
            }
            Action::Register(name, n) => {
                let (Some(lb), Some(req)) = (c.lb.as_ref(), c.admin_request(n, true)) else {
                    continue;
                };
                match admin(lb.addr, req, lb.half_close).await {
                    Ok(status) => {
                        if (200..300).contains(&status) {
                            registered.insert(name.clone());
                        }
                        event(
                            "replicas-registered",
                            &[
                                ("name", name),
                                ("backend", c.backend(n).unwrap_or_default()),
                                ("status", status.to_string()),
                            ],
                        );
                    }
                    Err(e) => error(&format!("register {name}"), e),
                }
            }
            Action::Deregister(name, n) => {
                let (Some(lb), Some(req)) = (c.lb.as_ref(), c.admin_request(n, false)) else {
                    continue;
                };
                match admin(lb.addr, req, lb.half_close).await {
                    Ok(status) => {
                        // Gone already (404) is as good as gone.
                        if (200..300).contains(&status) || status == 404 {
                            registered.remove(&name);
                        }
                        event(
                            "replicas-deregistered",
                            &[("name", name), ("status", status.to_string())],
                        );
                    }
                    Err(e) => error(&format!("deregister {name}"), e),
                }
            }
        }
    }
}

async fn controller() -> Result<(), String> {
    let t_start = monotonic_clock::now();
    let pairs = store::get_all().map_err(|e| format!("config: {e:?}"))?;
    let prefix = format!("app.{APP}.");
    let pairs = pairs
        .into_iter()
        .filter_map(|(k, v)| k.strip_prefix(&prefix).map(|k| (k.to_owned(), v)))
        .collect();
    let mut c = Config::from_pairs(pairs).map_err(|e| e.to_string())?;
    let desired = Rc::new(Cell::new(c.replicas));
    event(
        "replicas-desired",
        &[
            ("replicas", c.replicas.to_string()),
            ("from", "config".to_owned()),
        ],
    );
    wit_bindgen::spawn_local(read_stdin(desired.clone(), c.max));
    if c.start_ns > 0 {
        monotonic_clock::wait_until(t_start + c.start_ns).await;
    }
    let labels = c.labels();
    let mut rv = 0;
    let mut registered = BTreeSet::new();
    loop {
        // What changed since the last pass, as the world reports it.
        let (next, changes) = devices::watch(&labels, rv, 256);
        rv = next;
        for ch in changes {
            let kind = match ch.kind {
                ChangeKind::Added => "added",
                ChangeKind::Modified => "modified",
                ChangeKind::Deleted => "deleted",
            };
            event(
                "replicas-observed",
                &[
                    ("name", ch.device.name),
                    ("change", kind.to_owned()),
                    ("phase", phase_name(ch.device.phase).to_owned()),
                ],
            );
        }
        // A fetched component first: nothing is applied before the host has it.
        if c.component.is_empty()
            && let Some(f) = &c.fetch
        {
            match fetch_component(f).await {
                Ok(digest) => c.component = digest,
                Err(e) => error("fetch", e),
            }
        }
        if !c.component.is_empty() {
            step(&c, desired.get(), &mut registered).await;
        }
        if c.wake {
            // Until a device it sees changes (its own requests applying included), or `period`:
            // `changes.wait-any` on its table view alone (the same wake as `changes.wait`).
            let deadline = monotonic_clock::now().saturating_add(c.period_ns);
            let table = TableSince {
                selector: labels.clone(),
                since: rv,
            };
            if let Err(e) = changes::wait_any(Some(table), Vec::new(), Some(deadline)).await {
                error("wait", e);
                monotonic_clock::wait_for(c.period_ns).await;
            }
        } else {
            monotonic_clock::wait_for(c.period_ns).await;
        }
    }
}

struct Component;

impl exports::wasi::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        controller().await.map_err(|e| {
            log::log(Level::Error, &format!("{APP}: {e}"));
        })
    }
}

export!(Component);
