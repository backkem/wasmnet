//! TCP sockets for the node's apps: the logic behind the exported `wasi:sockets/types`
//! `tcp-socket` resource and `wasmnet:sockets-ext/tcp`, over smoltcp TCP sockets.
//!
//! The component glue (`component.rs`) holds one [`SocketId`] per WASI resource and calls these
//! methods with the stack borrowed (no import calls inside, driver rule 3). The byte pumps that
//! move data between the apps' `stream<u8>`s and smoltcp's buffers live in the driver task and
//! call the pump helpers here ([`TcpSockets::send_room`], [`TcpSockets::recv_step`], ...).
//! Everything here is pure: the same calls in the same order give the same sockets, ports and
//! segments.
//!
//! # WASI semantics, and where they meet smoltcp
//!
//! * `create` allocates nothing in smoltcp. `bind` only reserves an address; `connect` and
//!   `listen` create smoltcp sockets with the buffer sizes and options set so far.
//! * Ephemeral ports count up from [`FIRST_EPHEMERAL`] (deterministic; no RNG), skipping ports
//!   any live TCP socket still uses (TIME-WAIT included). An explicit `bind` ignores TIME-WAIT
//!   (WASI asks for implicit `SO_REUSEADDR`).
//! * **The listen backlog is N smoltcp sockets in LISTEN** on the port (smoltcp has no
//!   backlog of its own). Every socket takes one SYN. Connections that are mid-handshake, or
//!   established but not yet taken by the app, count against the backlog; while the backlog is
//!   full no socket listens, so a further SYN draws smoltcp's RST (Linux would drop it). The
//!   backlog is clamped to [1, [`MAX_BACKLOG`]] and defaults to [`DEFAULT_BACKLOG`].
//! * **Families never conflict** (every WASI IPv6 socket is `IPV6_V6ONLY`): `0.0.0.0:80` and
//!   `[::]:80` listen side by side (smoltcp issue #7). smoltcp ignores the
//!   family, so whichever wildcard LISTEN socket comes first takes a SYN of either family;
//!   after every poll, a connection that reached a listener of the other family is handed to
//!   the listener that owns it (same port and family; its address, or the unspecified one),
//!   with that listener's options. Only when no listener owns it is it reset.
//! * `send` / FIN: the app's stream end is the only close signal. Dropping its writer queues a
//!   FIN after the data already accepted ([`TcpSockets::finish_send`]).
//! * **A dropped receive stream is `SHUT_RD`**: nothing goes on the wire, and data that still
//!   arrives is discarded (and acknowledged, so the peer is not stalled), never answered with an
//!   RST. The receive future then resolves once the peer's direction ends.
//! * **RST only comes from `wasmnet:sockets-ext/tcp.abort`** (or from smoltcp itself, for a
//!   segment to a port nobody listens on). After an abort, both of this socket's futures
//!   resolve to `connection-reset`.
//! * smoltcp does not say *why* a connection closed, so the table records whether the peer's
//!   FIN was ever seen (CLOSE-WAIT, LAST-ACK, CLOSING, TIME-WAIT): CLOSED after a FIN is an
//!   orderly end, CLOSED without one is a reset (an RST, or a timeout).
//! * A dropped resource whose connection is still open closes it (FIN, if not sent yet), keeps
//!   discarding what arrives, and leaves the smoltcp socket as an *orphan* until it is CLOSED
//!   (after TIME-WAIT), or at most [`ORPHAN_LIMIT_NS`].
//! * Keep-alive maps onto smoltcp's single keep-alive interval plus its timeout: probes start
//!   after `keep-alive-idle-time` of silence, and the connection is dropped after
//!   `idle + interval * count` without a sign of life (an approximation of Linux's
//!   `TCP_KEEPIDLE`/`TCP_KEEPINTVL`/`TCP_KEEPCNT`).
//! * Buffer sizes are clamped to [[`MIN_BUFFER`], [`MAX_BUFFER`]] and take effect at
//!   `connect`/`listen` (smoltcp cannot resize a socket's buffers). The receive buffer is the
//!   advertised window, so a small one makes backpressure visible on the wire.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{self, State};
use smoltcp::time::Duration;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};

use crate::observe::IcmpError;
use crate::udp::{Family, SockError, is_mapped, routable};

/// The netstack's name for one `tcp-socket` resource (its own id space, apart from UDP's).
pub type SocketId = u32;

/// First ephemeral port (IANA dynamic range).
pub const FIRST_EPHEMERAL: u16 = 49_152;
/// Default smoltcp buffer size per direction (bytes). Above 64 KiB smoltcp scales the window.
pub const DEFAULT_BUFFER: u64 = 65_536;
/// Smallest buffer (one minimal IPv4 MSS).
pub const MIN_BUFFER: u64 = 536;
/// Largest buffer.
pub const MAX_BUFFER: u64 = 1 << 20;
/// Default listen backlog (WASI's hint; Linux defaults to `SOMAXCONN`).
pub const DEFAULT_BACKLOG: u64 = 8;
/// Largest backlog: every slot is a smoltcp socket with its own buffers.
pub const MAX_BACKLOG: u64 = 64;
/// How long a `connect` (or a half-open accepted connection) waits for the handshake.
pub const CONNECT_TIMEOUT_NS: u64 = 75_000_000_000;
/// The longest a dropped socket's connection may linger before it is aborted.
pub const ORPHAN_LIMIT_NS: u64 = 120_000_000_000;
/// The most bytes one [`TcpSockets::recv_step`] hands to the receive pump.
pub const RECV_CHUNK: usize = 65_536;

/// Linux defaults for keep-alive (`TCP_KEEPIDLE` 2 h, `TCP_KEEPINTVL` 75 s, `TCP_KEEPCNT` 9).
const KEEP_IDLE_NS: u64 = 7_200_000_000_000;
const KEEP_INTERVAL_NS: u64 = 75_000_000_000;
const KEEP_COUNT: u32 = 9;

fn smol_duration(ns: u64) -> Duration {
    Duration::from_micros(ns / 1_000)
}

/// Per-socket options. A listener's options are inherited by the sockets it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub rx_buffer: u64,
    pub tx_buffer: u64,
    /// `None`: the node's default.
    pub hop_limit: Option<u8>,
    pub keep_alive: bool,
    pub keep_idle_ns: u64,
    pub keep_interval_ns: u64,
    pub keep_count: u32,
    /// `TCP_NODELAY` (`wasmnet:sockets-ext/tcp.set-no-delay`): Nagle off.
    pub no_delay: bool,
    pub backlog: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            rx_buffer: DEFAULT_BUFFER,
            tx_buffer: DEFAULT_BUFFER,
            hop_limit: None,
            keep_alive: false,
            keep_idle_ns: KEEP_IDLE_NS,
            keep_interval_ns: KEEP_INTERVAL_NS,
            keep_count: KEEP_COUNT,
            no_delay: false,
            backlog: DEFAULT_BACKLOG,
        }
    }
}

impl Options {
    /// smoltcp's timeout for an established connection: only with keep-alive on.
    fn established_timeout(&self) -> Option<Duration> {
        self.keep_alive.then(|| {
            smol_duration(
                self.keep_idle_ns.saturating_add(
                    self.keep_interval_ns
                        .saturating_mul(u64::from(self.keep_count)),
                ),
            )
        })
    }

    /// Applies the options that may change at any time (Nagle, hop limit, keep-alive).
    fn apply(&self, sock: &mut tcp::Socket<'static>, default_hops: u8) {
        sock.set_nagle_enabled(!self.no_delay);
        sock.set_hop_limit(Some(self.hop_limit.unwrap_or(default_hops)));
        sock.set_keep_alive(self.keep_alive.then(|| smol_duration(self.keep_idle_ns)));
    }

    /// A new smoltcp socket with these buffers and options.
    fn socket(&self, default_hops: u8) -> tcp::Socket<'static> {
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; self.rx_buffer as usize]),
            tcp::SocketBuffer::new(vec![0u8; self.tx_buffer as usize]),
        );
        self.apply(&mut sock, default_hops);
        sock
    }
}

/// What the TCP logic needs from the stack for one call.
pub struct TcpNet<'a> {
    pub iface: &'a mut Interface,
    pub sockets: &'a mut SocketSet<'static>,
    /// The node's unicast hop limit (the default for new sockets).
    pub hop_limit: u8,
    /// A default route exists for IPv4 / IPv6.
    pub gateway_v4: bool,
    pub gateway_v6: bool,
}

/// TCP counters (part of the netstack's `counters`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpCounters {
    pub sockets: u64,
    pub connects: u64,
    pub connected: u64,
    pub connect_failed: u64,
    /// Connects failed by an ICMP error while in SYN-SENT.
    pub connect_unreachable: u64,
    pub listens: u64,
    pub accepted: u64,
    /// Most connections ever queued on one listener at once (mid-handshake or not yet taken).
    pub backlog_peak: u64,
    /// Bytes the apps wrote into smoltcp / read out of it.
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Bytes discarded after `SHUT_RD` (a dropped receive stream or resource).
    pub rx_discarded: u64,
    /// FINs we queued (the app dropped its send stream, or its socket).
    pub fins: u64,
    /// Receive streams that ended with the peer's FIN.
    pub eofs: u64,
    /// Receive streams that ended without the peer's FIN (an RST, a timeout, or a local abort).
    pub resets: u64,
    /// `wasmnet:sockets-ext/tcp.abort` calls that reset a connection.
    pub aborts: u64,
    /// Times a send pump found smoltcp's transmit buffer full (app-side backpressure).
    pub send_waits: u64,
    /// Times a connection's receive buffer filled up (a zero window: the app reads too slowly).
    pub rx_window_full: u64,
    /// Orphaned connections (dropped resources) that reached CLOSED, or were aborted.
    pub orphans_reaped: u64,
}

/// What [`TcpSockets::recv_step`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecvStep {
    /// Bytes to offer the app (they stay in smoltcp until [`TcpSockets::consume`]).
    Data(Vec<u8>),
    /// The peer's direction ended: `Ok` after its FIN, `Err` after a reset.
    End(Result<(), SockError>),
}

/// What [`TcpSockets::accept`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accept {
    /// A new connected socket for the app.
    Conn(SocketId),
    /// The listener was closed: the accept stream ends.
    Closed,
}

#[derive(Debug)]
struct Conn {
    handle: SocketHandle,
    /// The peer's FIN was seen, so a later CLOSED is an orderly end.
    fin_seen: bool,
    /// `abort` was called.
    aborted: bool,
    /// The app dropped its receive stream (`SHUT_RD`): arriving data is discarded.
    rd_shut: bool,
    /// We queued our FIN.
    wr_shut: bool,
    send_started: bool,
    recv_started: bool,
    /// The send pump is waiting for transmit space (for [`TcpCounters::send_waits`]).
    send_blocked: bool,
    /// The receive buffer is full (for [`TcpCounters::rx_window_full`]).
    rx_full: bool,
    /// The end was counted (EOF or reset).
    end_counted: bool,
}

impl Conn {
    fn new(handle: SocketHandle) -> Self {
        Self {
            handle,
            fin_seen: false,
            aborted: false,
            rd_shut: false,
            wr_shut: false,
            send_started: false,
            recv_started: false,
            send_blocked: false,
            rx_full: false,
            end_counted: false,
        }
    }

    /// The connection is over without the peer's FIN: an RST, a timeout or our abort.
    fn is_reset(&self, sock: &tcp::Socket<'static>) -> bool {
        self.aborted || (sock.state() == State::Closed && !self.fin_seen)
    }
}

#[derive(Debug)]
struct Listener {
    /// Sockets in LISTEN, each waiting for one SYN.
    listening: Vec<SocketHandle>,
    /// Sockets mid-handshake (SYN-RECEIVED).
    embryonic: Vec<SocketHandle>,
    /// Established connections the app has not taken yet, in completion order.
    ready: VecDeque<SocketHandle>,
    /// Taken from `ready` and on their way through the accept stream.
    handoff: u64,
    /// The app stopped accepting (resource or accept stream dropped).
    closed: bool,
}

impl Listener {
    fn queued(&self) -> u64 {
        (self.embryonic.len() + self.ready.len()) as u64 + self.handoff
    }
}

#[derive(Debug)]
enum Phase {
    Unbound,
    Bound,
    Listening(Listener),
    Connecting {
        handle: SocketHandle,
        since: u64,
        /// An ICMP error said the peer cannot be reached: the connect fails at its next poll.
        failed: Option<SockError>,
    },
    Connected(Conn),
    /// A failed connect: only `drop` is left.
    Closed,
}

#[derive(Debug)]
struct Entry {
    family: Family,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    opts: Options,
    phase: Phase,
    /// The resource was dropped; the entry stays while a job (pump, accept loop) runs.
    dropped: bool,
    /// Driver jobs (pumps, the accept loop) that still use this entry.
    jobs: u32,
}

/// A connection whose resource is gone, kept until smoltcp is done with it.
#[derive(Debug)]
struct Orphan {
    handle: SocketHandle,
    since: u64,
}

/// Every app TCP socket of the node.
#[derive(Debug)]
pub struct TcpSockets {
    entries: BTreeMap<SocketId, Entry>,
    next_id: SocketId,
    next_port: u16,
    orphans: Vec<Orphan>,
    pub counters: TcpCounters,
}

impl Default for TcpSockets {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_id: 1,
            next_port: FIRST_EPHEMERAL,
            orphans: Vec::new(),
            counters: TcpCounters::default(),
        }
    }
}

/// A listener's sockets come from [`arm`], which this mirrors for a restore.
fn listen_socket(local: SocketAddr, opts: &Options, hops: u8) -> Option<tcp::Socket<'static>> {
    let mut sock = opts.socket(hops);
    sock.set_timeout(Some(smol_duration(CONNECT_TIMEOUT_NS)));
    sock.listen(IpListenEndpoint {
        addr: (!local.ip().is_unspecified()).then(|| IpAddress::from(local.ip())),
        port: local.port(),
    })
    .ok()?;
    Some(sock)
}

impl TcpSockets {
    /// No socket at all, live or orphaned.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.orphans.is_empty()
    }

    /// The listeners that a restore must hand back with a fresh accept stream (their accept
    /// loop ran when the state was saved).
    pub fn listeners(&self) -> Vec<SocketId> {
        self.entries
            .iter()
            .filter(|(_, e)| matches!(e.phase, Phase::Listening(_)))
            .map(|(&id, _)| id)
            .collect()
    }

    /// Every socket's id, in order.
    pub fn ids(&self) -> Vec<SocketId> {
        self.entries.keys().copied().collect()
    }

    /// `id` is a live, not dropped socket.
    pub fn exists(&self, id: SocketId) -> bool {
        self.entries.get(&id).is_some_and(|e| !e.dropped)
    }

    /// The table for a quiescent snapshot: unbound, bound and listening
    /// sockets with nothing queued, and the smoltcp slots of each listener's LISTEN sockets.
    /// A connection, a half-open or queued one, an orphan or a dropped socket refuses it.
    pub fn snapshot_save(
        &self,
        w: &mut crate::snapshot::W,
        sockets: &SocketSet<'static>,
    ) -> crate::snapshot::Res<()> {
        use crate::snapshot::Counters;
        if !self.orphans.is_empty() {
            return Err("a closed TCP connection is still winding down".into());
        }
        w.u32(self.next_id);
        w.u16(self.next_port);
        self.counters.put(w);
        w.count(self.entries.len());
        for (&id, e) in &self.entries {
            if e.dropped {
                return Err(format!("TCP socket {id} was dropped and is still in use"));
            }
            w.u32(id);
            w.bool(e.family == Family::Ipv6);
            w.sock(e.local);
            w.sock(e.remote);
            let o = &e.opts;
            w.u64(o.rx_buffer);
            w.u64(o.tx_buffer);
            w.opt_u8(o.hop_limit);
            w.bool(o.keep_alive);
            w.u64(o.keep_idle_ns);
            w.u64(o.keep_interval_ns);
            w.u32(o.keep_count);
            w.bool(o.no_delay);
            w.u64(o.backlog);
            match &e.phase {
                Phase::Unbound => w.u8(0),
                Phase::Bound => w.u8(1),
                Phase::Listening(l) => {
                    if l.closed || l.queued() > 0 {
                        return Err(format!("TCP listener {id} has connections queued"));
                    }
                    if l.listening
                        .iter()
                        .any(|&h| sockets.get::<tcp::Socket>(h).state() != State::Listen)
                    {
                        return Err(format!("TCP listener {id} is mid-handshake"));
                    }
                    w.u8(2);
                    w.count(l.listening.len());
                    for h in &l.listening {
                        w.u64(h.index() as u64);
                    }
                }
                _ => return Err(format!("TCP socket {id} is connecting or connected")),
            }
        }
        Ok(())
    }

    /// Puts [`snapshot_save`](Self::snapshot_save)'s table back into an empty one, every LISTEN
    /// socket at its saved smoltcp slot. The listeners' accept loops are not running: each
    /// starts when the app takes its listener back (`reclaim-listener`).
    pub fn snapshot_restore(
        &mut self,
        r: &mut crate::snapshot::R<'_>,
        sockets: &mut SocketSet<'static>,
        node_hops: u8,
    ) -> crate::snapshot::Res<()> {
        use crate::snapshot::Counters;
        self.next_id = r.u32()?;
        self.next_port = r.u16()?;
        self.counters = TcpCounters::get(r)?;
        for _ in 0..r.count()? {
            let id = r.u32()?;
            let family = if r.bool()? {
                Family::Ipv6
            } else {
                Family::Ipv4
            };
            let local = r.sock()?;
            let remote = r.sock()?;
            let opts = Options {
                rx_buffer: r.u64()?,
                tx_buffer: r.u64()?,
                hop_limit: r.opt_u8()?,
                keep_alive: r.bool()?,
                keep_idle_ns: r.u64()?,
                keep_interval_ns: r.u64()?,
                keep_count: r.u32()?,
                no_delay: r.bool()?,
                backlog: r.u64()?,
            };
            let phase = match r.u8()? {
                0 => Phase::Unbound,
                1 => Phase::Bound,
                2 => {
                    let bound = local.ok_or("snapshot: a TCP listener is not bound")?;
                    let mut l = Listener {
                        listening: Vec::new(),
                        embryonic: Vec::new(),
                        ready: VecDeque::new(),
                        handoff: 0,
                        closed: false,
                    };
                    for _ in 0..r.count()? {
                        let slot = r.u64()? as usize;
                        let sock = listen_socket(bound, &opts, node_hops)
                            .ok_or_else(|| format!("snapshot: listening on {bound}"))?;
                        l.listening.push(
                            sockets
                                .add_at(slot, sock)
                                .ok_or("snapshot: two sockets in one slot")?,
                        );
                    }
                    Phase::Listening(l)
                }
                v => return Err(format!("snapshot: bad TCP phase {v}")),
            };
            self.entries.insert(
                id,
                Entry {
                    family,
                    local,
                    remote,
                    opts,
                    phase,
                    dropped: false,
                    jobs: 0,
                },
            );
        }
        Ok(())
    }

    /// Every socket, for inspection. Read only. A listener's queues are its
    /// backlog (connections not yet accepted); a connection's are smoltcp's buffers, in bytes.
    pub fn inspect(&self, sockets: &SocketSet<'static>) -> Vec<crate::debug::SockInfo> {
        self.entries
            .iter()
            .map(|(&id, e)| {
                let (state, rx, tx) = match &e.phase {
                    Phase::Unbound => ("unbound".to_owned(), 0, 0),
                    Phase::Bound => ("bound".to_owned(), 0, 0),
                    Phase::Listening(l) => ("listen".to_owned(), l.queued(), 0),
                    Phase::Connecting { .. } => ("syn-sent".to_owned(), 0, 0),
                    Phase::Connected(c) => {
                        let s = sockets.get::<tcp::Socket>(c.handle);
                        (
                            s.state().to_string().to_ascii_lowercase(),
                            s.recv_queue() as u64,
                            s.send_queue() as u64,
                        )
                    }
                    Phase::Closed => ("closed".to_owned(), 0, 0),
                };
                crate::debug::SockInfo {
                    id,
                    family: e.family.name(),
                    local: e.local,
                    remote: e.remote,
                    state,
                    rx_queued: rx,
                    tx_queued: tx,
                }
            })
            .collect()
    }
}

fn endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(IpAddress::from(addr.ip()), addr.port())
}

fn socket_addr(ep: IpEndpoint) -> SocketAddr {
    SocketAddr::new(IpAddr::from(ep.addr), ep.port)
}

/// `true` when two bindings on the same port would compete for the same connections (the
/// families never do: [`crate::udp::overlaps`]).
fn overlaps(a: IpAddr, b: IpAddr) -> bool {
    crate::udp::overlaps(a, b)
}

/// The peer's FIN has been received in this state.
fn fin_state(state: State) -> bool {
    matches!(
        state,
        State::CloseWait | State::LastAck | State::Closing | State::TimeWait
    )
}

/// smoltcp is done with the socket: CLOSED, and any final RST already sent.
fn finished(sock: &tcp::Socket<'static>) -> bool {
    sock.state() == State::Closed && sock.remote_endpoint().is_none()
}

/// Discards everything in `sock`'s receive buffer. Returns the byte count.
fn discard(sock: &mut tcp::Socket<'static>) -> u64 {
    let mut total = 0u64;
    while let Ok(n) = sock.recv(|b| (b.len(), b.len())) {
        if n == 0 {
            break;
        }
        total += n as u64;
    }
    total
}

impl TcpSockets {
    fn entry(&self, id: SocketId) -> Result<&Entry, SockError> {
        self.entries.get(&id).ok_or(SockError::InvalidState)
    }

    fn entry_mut(&mut self, id: SocketId) -> Result<&mut Entry, SockError> {
        self.entries.get_mut(&id).ok_or(SockError::InvalidState)
    }

    fn conn(&self, id: SocketId) -> Result<&Conn, SockError> {
        match &self.entry(id)?.phase {
            Phase::Connected(c) => Ok(c),
            _ => Err(SockError::InvalidState),
        }
    }

    fn conn_mut(&mut self, id: SocketId) -> Result<&mut Conn, SockError> {
        match &mut self.entry_mut(id)?.phase {
            Phase::Connected(c) => Ok(c),
            _ => Err(SockError::InvalidState),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Resource life cycle

    /// `tcp-socket.create`.
    pub fn create(&mut self, family: Family) -> SocketId {
        self.insert(Entry {
            family,
            local: None,
            remote: None,
            opts: Options::default(),
            phase: Phase::Unbound,
            dropped: false,
            jobs: 0,
        })
    }

    fn insert(&mut self, entry: Entry) -> SocketId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.counters.sockets += 1;
        self.entries.insert(id, entry);
        id
    }

    /// The resource was dropped at `now`. A live connection is closed (FIN) and lingers as an
    /// orphan; a listener stops listening. The entry itself goes once no job uses it.
    pub fn close(&mut self, id: SocketId, now: u64, sockets: &mut SocketSet<'static>) {
        let Some(entry) = self.entries.get_mut(&id) else {
            return;
        };
        entry.dropped = true;
        match &mut entry.phase {
            Phase::Listening(l) => l.closed = true,
            Phase::Connected(conn) => {
                let sock = sockets.get_mut::<tcp::Socket>(conn.handle);
                // Nobody can send any more unless a send pump still runs: FIN now.
                if !conn.send_started && !conn.wr_shut && !conn.aborted {
                    conn.wr_shut = true;
                    if sock.may_send() {
                        self.counters.fins += 1;
                    }
                    sock.close();
                }
                // Nobody will read: whatever arrives is discarded (`SHUT_RD`).
                if !conn.recv_started {
                    conn.rd_shut = true;
                    self.counters.rx_discarded += discard(sock);
                }
            }
            _ => {}
        }
        self.reap_entry(id, now, sockets);
    }

    /// While a listener's accept loop waits for the app: was the listener closed meanwhile?
    pub fn listener_closed(&self, listener: SocketId) -> Option<()> {
        match self.entries.get(&listener).map(|e| &e.phase) {
            Some(Phase::Listening(l)) if !l.closed => None,
            _ => Some(()),
        }
    }

    /// After the FIN: `Ok` once every byte the app sent was acknowledged, an error if the
    /// connection was reset first, `None` while data is still in flight.
    pub fn send_flushed(
        &self,
        id: SocketId,
        sockets: &SocketSet<'static>,
    ) -> Option<Result<(), SockError>> {
        let conn = match self.conn(id) {
            Ok(c) => c,
            Err(e) => return Some(Err(e)),
        };
        let sock = sockets.get::<tcp::Socket>(conn.handle);
        if conn.is_reset(sock) {
            Some(Err(SockError::ConnectionReset))
        } else if sock.send_queue() == 0 {
            Some(Ok(()))
        } else {
            None
        }
    }

    /// A driver job that used `id` is done.
    pub fn job_done(&mut self, id: SocketId, now: u64, sockets: &mut SocketSet<'static>) {
        if let Some(e) = self.entries.get_mut(&id) {
            e.jobs = e.jobs.saturating_sub(1);
        }
        self.reap_entry(id, now, sockets);
    }

    /// A driver job starts using `id`.
    pub fn job_started(&mut self, id: SocketId) {
        if let Some(e) = self.entries.get_mut(&id) {
            e.jobs += 1;
        }
    }

    /// Removes a dropped entry no job uses any more, handing its connection to the orphans.
    fn reap_entry(&mut self, id: SocketId, now: u64, sockets: &mut SocketSet<'static>) {
        let removable = self
            .entries
            .get(&id)
            .is_some_and(|e| e.dropped && e.jobs == 0);
        if !removable {
            return;
        }
        let Some(entry) = self.entries.remove(&id) else {
            return;
        };
        match entry.phase {
            Phase::Connected(conn) => {
                let sock = sockets.get_mut::<tcp::Socket>(conn.handle);
                if !conn.wr_shut && !conn.aborted {
                    sock.close();
                    if sock.state() != State::Closed {
                        self.counters.fins += 1;
                    }
                }
                discard(sock);
                self.orphan(conn.handle, now, sockets);
            }
            Phase::Connecting { handle, .. } => {
                sockets.get_mut::<tcp::Socket>(handle).abort();
                self.orphan(handle, now, sockets);
            }
            Phase::Listening(l) => self.shut_listener(l, now, sockets),
            Phase::Unbound | Phase::Bound | Phase::Closed => {}
        }
    }

    fn orphan(&mut self, handle: SocketHandle, now: u64, sockets: &mut SocketSet<'static>) {
        if finished(sockets.get::<tcp::Socket>(handle)) {
            sockets.remove(handle);
        } else {
            self.orphans.push(Orphan { handle, since: now });
        }
    }

    /// Stops a listener: queued connections are reset, the LISTEN sockets removed.
    fn shut_listener(&mut self, l: Listener, now: u64, sockets: &mut SocketSet<'static>) {
        for h in l.listening {
            sockets.remove(h);
        }
        for h in l.embryonic.into_iter().chain(l.ready) {
            sockets.get_mut::<tcp::Socket>(h).abort();
            self.orphan(h, now, sockets);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Addresses

    pub fn family(&self, id: SocketId) -> Result<Family, SockError> {
        Ok(self.entry(id)?.family)
    }

    pub fn local_address(&self, id: SocketId) -> Result<SocketAddr, SockError> {
        self.entry(id)?.local.ok_or(SockError::InvalidState)
    }

    pub fn remote_address(&self, id: SocketId) -> Result<SocketAddr, SockError> {
        let e = self.entry(id)?;
        match e.phase {
            Phase::Connected(_) => e.remote.ok_or(SockError::InvalidState),
            _ => Err(SockError::InvalidState),
        }
    }

    pub fn is_listening(&self, id: SocketId) -> bool {
        self.entry(id)
            .is_ok_and(|e| matches!(e.phase, Phase::Listening(_)))
    }

    /// Whether `port` is bound (or listened on) by another socket with an overlapping address.
    fn in_use(&self, port: u16, ip: IpAddr) -> bool {
        self.entries.values().any(|e| {
            matches!(e.phase, Phase::Bound | Phase::Listening(_))
                && e.local
                    .is_some_and(|l| l.port() == port && overlaps(l.ip(), ip))
        })
    }

    /// Whether any live smoltcp TCP socket uses local `port` (an ephemeral port must be fresh,
    /// so a new connection never meets an old one in TIME-WAIT).
    fn port_busy(&self, port: u16, sockets: &SocketSet<'static>) -> bool {
        let used = |h: SocketHandle| {
            let s = sockets.get::<tcp::Socket>(h);
            s.local_endpoint().is_some_and(|ep| ep.port == port) || s.listen_endpoint().port == port
        };
        let bound = self.entries.values().any(|e| {
            matches!(e.phase, Phase::Bound | Phase::Listening(_))
                && e.local.is_some_and(|l| l.port() == port)
        });
        bound
            || self.orphans.iter().any(|o| used(o.handle))
            || self.entries.values().any(|e| match &e.phase {
                Phase::Connected(c) => used(c.handle),
                Phase::Connecting { handle, .. } => used(*handle),
                _ => false,
            })
    }

    fn ephemeral(&mut self, sockets: &SocketSet<'static>) -> Result<u16, SockError> {
        for _ in 0..=(u16::MAX - FIRST_EPHEMERAL) {
            let port = self.next_port;
            self.next_port = if port == u16::MAX {
                FIRST_EPHEMERAL
            } else {
                port + 1
            };
            if !self.port_busy(port, sockets) {
                return Ok(port);
            }
        }
        Err(SockError::AddressInUse)
    }

    /// `tcp-socket.bind`. Returns the address actually bound (the port filled in).
    pub fn bind(
        &mut self,
        id: SocketId,
        local: SocketAddr,
        net: &mut TcpNet<'_>,
    ) -> Result<SocketAddr, SockError> {
        let entry = self.entry(id)?;
        if !matches!(entry.phase, Phase::Unbound) {
            return Err(SockError::InvalidState);
        }
        let ip = local.ip();
        if Family::of(ip) != entry.family || is_mapped(ip) || ip.is_multicast() {
            return Err(SockError::InvalidArgument);
        }
        if !ip.is_unspecified() && !net.iface.has_ip_addr(IpAddress::from(ip)) {
            return Err(SockError::AddressNotBindable);
        }
        let port = match local.port() {
            0 => self.ephemeral(net.sockets)?,
            p if self.in_use(p, ip) => return Err(SockError::AddressInUse),
            p => p,
        };
        let bound = SocketAddr::new(ip, port);
        let entry = self.entry_mut(id)?;
        entry.local = Some(bound);
        entry.phase = Phase::Bound;
        Ok(bound)
    }

    // -----------------------------------------------------------------------------------------
    // connect

    /// The first half of `tcp-socket.connect`: checks, binds implicitly and sends the SYN (at
    /// the driver's next pass). [`connect_poll`](Self::connect_poll) reports the outcome.
    pub fn connect(
        &mut self,
        id: SocketId,
        remote: SocketAddr,
        now: u64,
        net: &mut TcpNet<'_>,
    ) -> Result<(), SockError> {
        let entry = self.entry(id)?;
        let ip = remote.ip();
        if Family::of(ip) != entry.family
            || ip.is_unspecified()
            || ip.is_multicast()
            || remote.port() == 0
            || is_mapped(ip)
            || matches!(ip, IpAddr::V4(a) if a.is_broadcast())
        {
            return Err(SockError::InvalidArgument);
        }
        let local = match entry.phase {
            Phase::Unbound => None,
            Phase::Bound => entry.local,
            _ => return Err(SockError::InvalidState),
        };
        if !routable(net.iface, ip, net.gateway_v4, net.gateway_v6) {
            return Err(SockError::RemoteUnreachable);
        }
        let port = match local {
            Some(l) => l.port(),
            None => self.ephemeral(net.sockets)?,
        };
        let opts = self.entry(id)?.opts;
        let mut sock = opts.socket(net.hop_limit);
        sock.set_timeout(Some(smol_duration(CONNECT_TIMEOUT_NS)));
        let listen = IpListenEndpoint {
            addr: local
                .map(|l| l.ip())
                .filter(|ip| !ip.is_unspecified())
                .map(IpAddress::from),
            port,
        };
        sock.connect(net.iface.context(), endpoint(remote), listen)
            .map_err(|_| SockError::InvalidArgument)?;
        let local_ep = sock.local_endpoint().map(socket_addr);
        let handle = net.sockets.add(sock);
        self.counters.connects += 1;
        let entry = self.entry_mut(id)?;
        entry.local = local_ep.or(local);
        entry.remote = Some(remote);
        entry.phase = Phase::Connecting {
            handle,
            since: now,
            failed: None,
        };
        Ok(())
    }

    /// The outcome of a `connect` in progress: `None` while the handshake runs.
    pub fn connect_poll(
        &mut self,
        id: SocketId,
        now: u64,
        sockets: &mut SocketSet<'static>,
    ) -> Option<Result<(), SockError>> {
        let entry = self.entries.get_mut(&id)?;
        let Phase::Connecting {
            handle,
            since,
            failed,
        } = entry.phase
        else {
            return Some(match entry.phase {
                Phase::Connected(_) => Ok(()),
                _ => Err(SockError::InvalidState),
            });
        };
        if let Some(e) = failed {
            // Like Linux in SYN-SENT: give up at once, silently (no RST to a peer that cannot
            // be reached).
            sockets.remove(handle);
            entry.phase = Phase::Closed;
            self.counters.connect_failed += 1;
            return Some(Err(e));
        }
        let sock = sockets.get_mut::<tcp::Socket>(handle);
        match sock.state() {
            State::SynSent | State::SynReceived => None,
            State::Closed => {
                let timed_out = now.saturating_sub(since) >= CONNECT_TIMEOUT_NS;
                let done = finished(sock);
                entry.phase = Phase::Closed;
                self.counters.connect_failed += 1;
                if done {
                    sockets.remove(handle);
                } else {
                    self.orphans.push(Orphan { handle, since: now });
                }
                Some(Err(if timed_out {
                    SockError::Timeout
                } else {
                    SockError::ConnectionRefused
                }))
            }
            state => {
                sock.set_timeout(entry.opts.established_timeout());
                let mut conn = Conn::new(handle);
                conn.fin_seen = fin_state(state);
                entry.local = sock.local_endpoint().map(socket_addr).or(entry.local);
                entry.phase = Phase::Connected(conn);
                self.counters.connected += 1;
                Some(Ok(()))
            }
        }
    }

    /// An ICMP error about one of our TCP segments arrived (smoltcp ignores them). A connect
    /// still in SYN-SENT to that peer from that port fails at its next poll, as on Linux
    /// (`tcp_v4_err`): `connection-refused` for a port unreachable, `remote-unreachable` for
    /// everything else that [`IcmpError::is_hard`] accepts. An established connection is not
    /// affected (Linux only records a soft error). Returns whether a connect was failed.
    pub fn icmp_error(&mut self, e: &IcmpError, sockets: &SocketSet<'static>) -> bool {
        if e.proto != 6 || !e.is_hard() {
            return false;
        }
        let err = if e.name() == "port-unreachable" {
            SockError::ConnectionRefused
        } else {
            SockError::RemoteUnreachable
        };
        let remote = SocketAddr::new(e.orig_dst, e.dport);
        for entry in self.entries.values_mut() {
            if let Phase::Connecting { handle, failed, .. } = &mut entry.phase
                && failed.is_none()
                && entry.local.map(|l| l.port()) == Some(e.sport)
                && entry.remote == Some(remote)
                && sockets.get::<tcp::Socket>(*handle).state() == State::SynSent
            {
                *failed = Some(err);
                self.counters.connect_unreachable += 1;
                return true;
            }
        }
        false
    }

    // -----------------------------------------------------------------------------------------
    // listen / accept

    /// `tcp-socket.listen`: binds implicitly and arms the backlog's LISTEN sockets.
    pub fn listen(&mut self, id: SocketId, net: &mut TcpNet<'_>) -> Result<SocketAddr, SockError> {
        let entry = self.entry(id)?;
        let local = match entry.phase {
            Phase::Bound => entry.local.ok_or(SockError::InvalidState)?,
            Phase::Unbound => {
                let any = SocketAddr::new(entry.family.unspecified(), 0);
                self.bind(id, any, net)?
            }
            _ => return Err(SockError::InvalidState),
        };
        let entry = self.entry_mut(id)?;
        let mut l = Listener {
            listening: Vec::new(),
            embryonic: Vec::new(),
            ready: VecDeque::new(),
            handoff: 0,
            closed: false,
        };
        let (opts, hops) = (entry.opts, net.hop_limit);
        arm(&mut l, local, &opts, hops, net.sockets);
        entry.phase = Phase::Listening(l);
        self.counters.listens += 1;
        Ok(local)
    }

    /// The accept loop's next connection: `None` while there is none yet.
    pub fn accept(&mut self, listener: SocketId, sockets: &SocketSet<'static>) -> Option<Accept> {
        let entry = self.entries.get_mut(&listener)?;
        let (family, opts) = (entry.family, entry.opts);
        let Phase::Listening(l) = &mut entry.phase else {
            return Some(Accept::Closed);
        };
        if l.closed {
            return Some(Accept::Closed);
        }
        let handle = l.ready.pop_front()?;
        l.handoff += 1;
        let sock = sockets.get::<tcp::Socket>(handle);
        let mut conn = Conn::new(handle);
        conn.fin_seen = fin_state(sock.state());
        let id = self.insert(Entry {
            family,
            local: sock.local_endpoint().map(socket_addr),
            remote: sock.remote_endpoint().map(socket_addr),
            opts: Options {
                backlog: DEFAULT_BACKLOG,
                ..opts
            },
            phase: Phase::Connected(conn),
            dropped: false,
            jobs: 0,
        });
        self.counters.accepted += 1;
        Some(Accept::Conn(id))
    }

    /// The accept stream delivered one connection to the app.
    pub fn delivered(&mut self, listener: SocketId) {
        if let Some(Entry {
            phase: Phase::Listening(l),
            ..
        }) = self.entries.get_mut(&listener)
        {
            l.handoff = l.handoff.saturating_sub(1);
        }
    }

    /// The app dropped the accept stream: stop listening.
    pub fn stop_listening(&mut self, listener: SocketId) {
        if let Some(Entry {
            phase: Phase::Listening(l),
            ..
        }) = self.entries.get_mut(&listener)
        {
            l.closed = true;
        }
    }

    // -----------------------------------------------------------------------------------------
    // Pumps

    /// `tcp-socket.send` was called: allowed once, on a connected socket.
    pub fn start_send(&mut self, id: SocketId) -> Result<(), SockError> {
        let conn = self.conn_mut(id)?;
        if conn.send_started {
            return Err(SockError::InvalidState);
        }
        conn.send_started = true;
        Ok(())
    }

    /// `tcp-socket.receive` was called: allowed once, on a connected socket.
    pub fn start_recv(&mut self, id: SocketId) -> Result<(), SockError> {
        let conn = self.conn_mut(id)?;
        if conn.recv_started {
            return Err(SockError::InvalidState);
        }
        conn.recv_started = true;
        Ok(())
    }

    /// How many bytes the send pump may read from the app now: `None` while smoltcp's transmit
    /// buffer is full, an error once the connection cannot carry more data.
    pub fn send_room(
        &mut self,
        id: SocketId,
        sockets: &SocketSet<'static>,
    ) -> Option<Result<usize, SockError>> {
        let conn = match self.conn_mut(id) {
            Ok(c) => c,
            Err(e) => return Some(Err(e)),
        };
        let sock = sockets.get::<tcp::Socket>(conn.handle);
        if conn.is_reset(sock) {
            return Some(Err(SockError::ConnectionReset));
        }
        if !sock.may_send() {
            return Some(Err(SockError::ConnectionBroken));
        }
        let free = sock.send_capacity() - sock.send_queue();
        if free == 0 {
            if !conn.send_blocked {
                conn.send_blocked = true;
                self.counters.send_waits += 1;
            }
            return None;
        }
        conn.send_blocked = false;
        Some(Ok(free))
    }

    /// While the send pump waits for the app: has the connection failed meanwhile?
    pub fn send_check(&self, id: SocketId, sockets: &SocketSet<'static>) -> Option<SockError> {
        let conn = match self.conn(id) {
            Ok(c) => c,
            Err(e) => return Some(e),
        };
        let sock = sockets.get::<tcp::Socket>(conn.handle);
        if conn.is_reset(sock) {
            Some(SockError::ConnectionReset)
        } else if !sock.may_send() {
            Some(SockError::ConnectionBroken)
        } else {
            None
        }
    }

    /// Queues the app's bytes (at most what [`send_room`](Self::send_room) allowed).
    pub fn send(
        &mut self,
        id: SocketId,
        data: &[u8],
        sockets: &mut SocketSet<'static>,
    ) -> Result<(), SockError> {
        let handle = self.conn(id)?.handle;
        match sockets.get_mut::<tcp::Socket>(handle).send_slice(data) {
            Ok(n) if n == data.len() => {
                self.counters.tx_bytes += n as u64;
                Ok(())
            }
            _ => Err(SockError::ConnectionReset),
        }
    }

    /// The app dropped its send stream: FIN after the queued data.
    pub fn finish_send(&mut self, id: SocketId, sockets: &mut SocketSet<'static>) {
        if let Ok(conn) = self.conn_mut(id)
            && !conn.wr_shut
        {
            conn.wr_shut = true;
            sockets.get_mut::<tcp::Socket>(conn.handle).close();
            self.counters.fins += 1;
        }
    }

    /// The receive pump's next step: data to offer, the end of the peer's direction, or `None`
    /// to wait.
    pub fn recv_step(
        &mut self,
        id: SocketId,
        sockets: &mut SocketSet<'static>,
    ) -> Option<RecvStep> {
        let conn = match self.conn_mut(id) {
            Ok(c) => c,
            Err(e) => return Some(RecvStep::End(Err(e))),
        };
        let sock = sockets.get_mut::<tcp::Socket>(conn.handle);
        if conn.is_reset(sock) {
            return Some(RecvStep::End(Err(SockError::ConnectionReset)));
        }
        if sock.can_recv() {
            let mut buf = vec![0u8; sock.recv_queue().min(RECV_CHUNK)];
            let n = sock.peek_slice(&mut buf).unwrap_or(0);
            buf.truncate(n);
            return Some(RecvStep::Data(buf));
        }
        if sock.may_recv() || matches!(sock.state(), State::SynSent | State::SynReceived) {
            return None;
        }
        Some(RecvStep::End(Ok(())))
    }

    /// While the receive pump waits for the app: has the connection been reset meanwhile?
    pub fn recv_check(&self, id: SocketId, sockets: &SocketSet<'static>) -> Option<SockError> {
        let conn = match self.conn(id) {
            Ok(c) => c,
            Err(e) => return Some(e),
        };
        conn.is_reset(sockets.get::<tcp::Socket>(conn.handle))
            .then_some(SockError::ConnectionReset)
    }

    /// The app took `n` bytes: they leave smoltcp, which reopens the window.
    pub fn consume(&mut self, id: SocketId, n: usize, sockets: &mut SocketSet<'static>) {
        let Ok(conn) = self.conn(id) else { return };
        let sock = sockets.get_mut::<tcp::Socket>(conn.handle);
        let mut left = n;
        while left > 0 {
            match sock.recv(|b| {
                let k = b.len().min(left);
                (k, k)
            }) {
                Ok(0) | Err(_) => break,
                Ok(k) => left -= k,
            }
        }
        self.counters.rx_bytes += (n - left) as u64;
    }

    /// The app dropped its receive stream: `SHUT_RD`. Data still queued, and data that arrives
    /// from now on, is discarded.
    pub fn shutdown_read(&mut self, id: SocketId, sockets: &mut SocketSet<'static>) {
        let Ok(conn) = self.conn_mut(id) else { return };
        conn.rd_shut = true;
        let n = discard(sockets.get_mut::<tcp::Socket>(conn.handle));
        self.counters.rx_discarded += n;
    }

    /// After `SHUT_RD`: how the peer's direction ended, or `None` while it is still open.
    pub fn recv_end(
        &self,
        id: SocketId,
        sockets: &SocketSet<'static>,
    ) -> Option<Result<(), SockError>> {
        let conn = match self.conn(id) {
            Ok(c) => c,
            Err(e) => return Some(Err(e)),
        };
        let sock = sockets.get::<tcp::Socket>(conn.handle);
        if conn.is_reset(sock) {
            Some(Err(SockError::ConnectionReset))
        } else if conn.fin_seen || sock.state() == State::Closed {
            Some(Ok(()))
        } else {
            None
        }
    }

    /// The receive pump finished; `eof` when it ended with the peer's FIN.
    pub fn recv_finished(&mut self, id: SocketId, result: Result<(), SockError>) {
        if let Ok(conn) = self.conn_mut(id)
            && !conn.end_counted
        {
            conn.end_counted = true;
            match result {
                Ok(()) => self.counters.eofs += 1,
                Err(SockError::ConnectionReset) => self.counters.resets += 1,
                Err(_) => {}
            }
        }
    }

    /// `wasmnet:sockets-ext/tcp.abort`: RST now. Does nothing on an unconnected socket.
    pub fn abort(&mut self, id: SocketId, sockets: &mut SocketSet<'static>) {
        let Ok(conn) = self.conn_mut(id) else { return };
        if conn.aborted {
            return;
        }
        conn.aborted = true;
        let sock = sockets.get_mut::<tcp::Socket>(conn.handle);
        let open = sock.state() != State::Closed;
        sock.abort();
        if open {
            self.counters.aborts += 1;
        }
    }

    // -----------------------------------------------------------------------------------------
    // Options

    fn opts_mut(&mut self, id: SocketId) -> Result<&mut Options, SockError> {
        Ok(&mut self.entry_mut(id)?.opts)
    }

    pub fn options(&self, id: SocketId) -> Result<Options, SockError> {
        Ok(self.entry(id)?.opts)
    }

    /// Re-applies the changeable options to a connected socket.
    fn reapply(&mut self, id: SocketId, net_hops: u8, sockets: &mut SocketSet<'static>) {
        let Ok(entry) = self.entry(id) else { return };
        let opts = entry.opts;
        let handle = match &entry.phase {
            Phase::Connected(c) => c.handle,
            Phase::Connecting { handle, .. } => *handle,
            _ => return,
        };
        let sock = sockets.get_mut::<tcp::Socket>(handle);
        opts.apply(sock, net_hops);
        if matches!(entry.phase, Phase::Connected(_)) {
            sock.set_timeout(opts.established_timeout());
        }
    }

    /// `set-listen-backlog-size`: clamped to [1, [`MAX_BACKLOG`]]. On a listener it applies to
    /// the next re-arm.
    pub fn set_backlog(&mut self, id: SocketId, value: u64) -> Result<(), SockError> {
        if value == 0 {
            return Err(SockError::InvalidArgument);
        }
        let entry = self.entry_mut(id)?;
        if matches!(entry.phase, Phase::Connecting { .. } | Phase::Connected(_)) {
            return Err(SockError::InvalidState);
        }
        entry.opts.backlog = value.clamp(1, MAX_BACKLOG);
        Ok(())
    }

    /// `set-keep-alive-enabled` / `-idle-time` / `-interval` / `-count` (`which` names the
    /// field; values of 0 are `invalid-argument`, except for `enabled`).
    pub fn set_keep_alive(
        &mut self,
        id: SocketId,
        change: KeepAlive,
        net_hops: u8,
        sockets: &mut SocketSet<'static>,
    ) -> Result<(), SockError> {
        let opts = self.opts_mut(id)?;
        match change {
            KeepAlive::Enabled(on) => opts.keep_alive = on,
            KeepAlive::Idle(0) | KeepAlive::Interval(0) | KeepAlive::Count(0) => {
                return Err(SockError::InvalidArgument);
            }
            // smoltcp keeps time in µs: never less than 1 ms.
            KeepAlive::Idle(ns) => opts.keep_idle_ns = ns.max(1_000_000),
            KeepAlive::Interval(ns) => opts.keep_interval_ns = ns.max(1_000_000),
            KeepAlive::Count(n) => opts.keep_count = n.min(127) as u32,
        }
        self.reapply(id, net_hops, sockets);
        Ok(())
    }

    /// `set-hop-limit`.
    pub fn set_hop_limit(
        &mut self,
        id: SocketId,
        value: u8,
        net_hops: u8,
        sockets: &mut SocketSet<'static>,
    ) -> Result<(), SockError> {
        if value == 0 {
            return Err(SockError::InvalidArgument);
        }
        self.opts_mut(id)?.hop_limit = Some(value);
        self.reapply(id, net_hops, sockets);
        Ok(())
    }

    /// `wasmnet:sockets-ext/tcp.set-no-delay`.
    pub fn set_no_delay(
        &mut self,
        id: SocketId,
        value: bool,
        net_hops: u8,
        sockets: &mut SocketSet<'static>,
    ) -> Result<(), SockError> {
        if matches!(self.entry(id)?.phase, Phase::Closed) {
            return Err(SockError::InvalidState);
        }
        self.opts_mut(id)?.no_delay = value;
        self.reapply(id, net_hops, sockets);
        Ok(())
    }

    /// `get-receive-buffer-size` (`rx`) or `get-send-buffer-size`: a connected socket reports
    /// its actual buffer.
    pub fn buffer_size(
        &self,
        id: SocketId,
        rx: bool,
        sockets: &SocketSet<'static>,
    ) -> Result<u64, SockError> {
        let e = self.entry(id)?;
        if let Phase::Connected(c) = &e.phase {
            let s = sockets.get::<tcp::Socket>(c.handle);
            return Ok(if rx {
                s.recv_capacity()
            } else {
                s.send_capacity()
            } as u64);
        }
        Ok(if rx {
            e.opts.rx_buffer
        } else {
            e.opts.tx_buffer
        })
    }

    /// `set-receive-buffer-size` (`rx`) / `set-send-buffer-size`: clamped to
    /// [[`MIN_BUFFER`], [`MAX_BUFFER`]]; takes effect at `connect`/`listen`.
    pub fn set_buffer_size(&mut self, id: SocketId, rx: bool, value: u64) -> Result<(), SockError> {
        if value == 0 {
            return Err(SockError::InvalidArgument);
        }
        let value = value.clamp(MIN_BUFFER, MAX_BUFFER);
        let opts = self.opts_mut(id)?;
        if rx {
            opts.rx_buffer = value;
        } else {
            opts.tx_buffer = value;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // After every `Interface::poll`

    /// Brings the table up to date with smoltcp: FINs seen, `SHUT_RD` discards, zero windows,
    /// listener queues (re-arming LISTEN sockets), finished orphans. Returns whether it changed
    /// anything smoltcp should act on (another poll is due).
    pub fn after_poll(&mut self, now: u64, hops: u8, sockets: &mut SocketSet<'static>) -> bool {
        let mut progress = false;
        let counters = &mut self.counters;
        // Connections that reached a listener of the other family: `(from listener, port, socket)`.
        let mut strays: Vec<(SocketId, u16, SocketHandle)> = Vec::new();
        for (&id, entry) in self.entries.iter_mut() {
            let local = entry.local;
            let (family, opts) = (entry.family, entry.opts);
            match &mut entry.phase {
                Phase::Connected(conn) => {
                    let sock = sockets.get_mut::<tcp::Socket>(conn.handle);
                    if fin_state(sock.state()) {
                        conn.fin_seen = true;
                    }
                    if conn.rd_shut {
                        let n = discard(sock);
                        counters.rx_discarded += n;
                        progress |= n > 0;
                    }
                    let full = sock.recv_queue() == sock.recv_capacity();
                    if full && !conn.rx_full {
                        counters.rx_window_full += 1;
                    }
                    conn.rx_full = full;
                }
                Phase::Listening(l) => {
                    if l.closed {
                        continue;
                    }
                    let Some(local) = local else { continue };
                    let (moved, wrong) = sort(l, family, sockets);
                    progress |= moved;
                    strays.extend(wrong.into_iter().map(|h| (id, local.port(), h)));
                    counters.backlog_peak = counters.backlog_peak.max(l.queued());
                    let before = l.listening.len();
                    arm(l, local, &opts, hops, sockets);
                    progress |= l.listening.len() != before;
                }
                _ => {}
            }
        }
        // Hand each stray to the listener of its own family, or reset it (smoltcp issue #7).
        for (from, port, h) in strays {
            let sock = sockets.get_mut::<tcp::Socket>(h);
            let family = sock
                .remote_endpoint()
                .map(|ep| Family::of(IpAddr::from(ep.addr)));
            let dst = sock.local_endpoint().map(|ep| IpAddr::from(ep.addr));
            let owner = family.and_then(|f| self.owning_listener(port, f, dst));
            let target = owner.unwrap_or(from);
            let Some(Entry {
                opts,
                phase: Phase::Listening(l),
                ..
            }) = self.entries.get_mut(&target)
            else {
                continue;
            };
            let handshake = sock.state() == State::SynReceived;
            match owner {
                // Nobody listens for this family: the handshake completes and
                // the connection is then reset. The listener keeps it until it is CLOSED
                // (after the RST went out).
                None if handshake => l.embryonic.push(h),
                None => {
                    sock.abort();
                    l.embryonic.push(h);
                    progress = true;
                }
                Some(_) => {
                    opts.apply(sock, hops);
                    if handshake {
                        l.embryonic.push(h);
                    } else {
                        sock.set_timeout(None);
                        l.ready.push_back(h);
                    }
                    progress = true;
                }
            }
        }
        // Closed listeners whose accept loop has not noticed yet: reset their queue now.
        for entry in self.entries.values_mut() {
            if let Phase::Listening(l) = &mut entry.phase
                && l.closed
                && !(l.listening.is_empty() && l.embryonic.is_empty() && l.ready.is_empty())
            {
                let shut = Listener {
                    listening: std::mem::take(&mut l.listening),
                    embryonic: std::mem::take(&mut l.embryonic),
                    ready: std::mem::take(&mut l.ready),
                    handoff: 0,
                    closed: true,
                };
                for h in shut.listening {
                    sockets.remove(h);
                }
                for h in shut.embryonic.into_iter().chain(shut.ready) {
                    sockets.get_mut::<tcp::Socket>(h).abort();
                    self.orphans.push(Orphan {
                        handle: h,
                        since: now,
                    });
                }
                progress = true;
            }
        }
        let counters = &mut self.counters;
        self.orphans.retain(|o| {
            let sock = sockets.get_mut::<tcp::Socket>(o.handle);
            counters.rx_discarded += discard(sock);
            if !finished(sock) && now.saturating_sub(o.since) >= ORPHAN_LIMIT_NS {
                sock.abort();
                return true;
            }
            if finished(sock) {
                sockets.remove(o.handle);
                counters.orphans_reaped += 1;
                return false;
            }
            true
        });
        progress
    }

    /// The live listener on `port` that owns a connection of `family` to local address `dst`:
    /// one bound to exactly `dst` first, else the family's unspecified-address listener.
    fn owning_listener(&self, port: u16, family: Family, dst: Option<IpAddr>) -> Option<SocketId> {
        let listeners = || {
            self.entries.iter().filter(move |(_, e)| {
                e.family == family
                    && matches!(&e.phase, Phase::Listening(l) if !l.closed)
                    && e.local.is_some_and(|l| l.port() == port)
            })
        };
        let exact = listeners().find(|(_, e)| e.local.map(|l| l.ip()) == dst);
        let any = || listeners().find(|(_, e)| e.local.is_some_and(|l| l.ip().is_unspecified()));
        exact.or_else(any).map(|(&id, _)| id)
    }

    /// The earliest orphan deadline (smoltcp's own `poll_at` covers everything else).
    pub fn next_deadline(&self) -> Option<u64> {
        self.orphans
            .iter()
            .map(|o| o.since.saturating_add(ORPHAN_LIMIT_NS))
            .min()
    }

    /// Open sockets (resources not yet dropped).
    pub fn open(&self) -> usize {
        self.entries.values().filter(|e| !e.dropped).count()
    }

    /// Connections still held for dropped sockets.
    pub fn orphans(&self) -> usize {
        self.orphans.len()
    }
}

/// One keep-alive setter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepAlive {
    Enabled(bool),
    Idle(u64),
    Interval(u64),
    Count(u64),
}

/// Moves a listener's sockets to where their state says they belong: LISTEN, mid-handshake,
/// or ready for the app. A failed handshake is dropped. A connection of the other family
/// (smoltcp lets a wildcard LISTEN socket take a SYN of either family) is taken out and
/// returned, for [`TcpSockets::after_poll`] to hand to its own listener. Returns whether
/// anything moved, and those strays.
fn sort(
    l: &mut Listener,
    family: Family,
    sockets: &mut SocketSet<'static>,
) -> (bool, Vec<SocketHandle>) {
    let mut moved = false;
    let mut strays = Vec::new();
    let all: Vec<SocketHandle> = l.listening.drain(..).chain(l.embryonic.drain(..)).collect();
    for h in all {
        let sock = sockets.get_mut::<tcp::Socket>(h);
        let wrong = sock
            .remote_endpoint()
            .is_some_and(|ep| Family::of(IpAddr::from(ep.addr)) != family);
        match sock.state() {
            State::Listen => l.listening.push(h),
            State::Closed => {
                sockets.remove(h);
                moved = true;
            }
            _ if wrong => strays.push(h),
            State::SynReceived => {
                l.embryonic.push(h);
            }
            _ => {
                // Established (or already further).
                sock.set_timeout(None);
                l.ready.push_back(h);
                moved = true;
            }
        }
    }
    (moved, strays)
}

/// Arms LISTEN sockets until listening + queued connections fill the backlog.
fn arm(
    l: &mut Listener,
    local: SocketAddr,
    opts: &Options,
    hops: u8,
    sockets: &mut SocketSet<'static>,
) {
    let listen = IpListenEndpoint {
        addr: (!local.ip().is_unspecified()).then(|| IpAddress::from(local.ip())),
        port: local.port(),
    };
    while (l.listening.len() as u64) + l.queued() < opts.backlog {
        let mut sock = opts.socket(hops);
        // A half-open connection gives up like a connect does.
        sock.set_timeout(Some(smol_duration(CONNECT_TIMEOUT_NS)));
        if sock.listen(listen).is_err() {
            break;
        }
        l.listening.push(sockets.add(sock));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_and_clamps() {
        let o = Options::default();
        assert_eq!((o.rx_buffer, o.backlog, o.no_delay), (65_536, 8, false));
        assert_eq!(o.established_timeout(), None);
        let ka = Options {
            keep_alive: true,
            keep_idle_ns: 1_000_000_000,
            keep_interval_ns: 500_000_000,
            keep_count: 4,
            ..o
        };
        assert_eq!(ka.established_timeout(), Some(Duration::from_millis(3_000)));
        let mut t = TcpSockets::default();
        let id = t.create(Family::Ipv4);
        assert_eq!(t.set_backlog(id, 0), Err(SockError::InvalidArgument));
        t.set_backlog(id, 1_000).unwrap();
        assert_eq!(t.options(id).unwrap().backlog, MAX_BACKLOG);
        t.set_buffer_size(id, true, 1).unwrap();
        assert_eq!(t.options(id).unwrap().rx_buffer, MIN_BUFFER);
        t.set_buffer_size(id, false, u64::MAX).unwrap();
        assert_eq!(t.options(id).unwrap().tx_buffer, MAX_BUFFER);
        assert_eq!(
            t.set_buffer_size(id, false, 0),
            Err(SockError::InvalidArgument)
        );
        assert!(fin_state(State::TimeWait) && !fin_state(State::FinWait2));
        assert!(overlaps(
            "0.0.0.0".parse().unwrap(),
            "10.0.0.1".parse().unwrap()
        ));
        assert!(!overlaps("0.0.0.0".parse().unwrap(), "::".parse().unwrap()));
    }
}
