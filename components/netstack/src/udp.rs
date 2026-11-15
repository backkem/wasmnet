//! UDP sockets for the node's apps: the logic behind the exported `wasi:sockets/types`
//! `udp-socket` resource, over smoltcp UDP sockets.
//!
//! The component glue (`component.rs`) holds one [`SocketId`] per WASI resource and calls these
//! methods with the stack borrowed (no import calls inside, driver rule 3). Everything here is
//! pure: the same calls in the same order give the same sockets, ports and datagrams.
//!
//! WASI semantics, and where they meet smoltcp:
//! * `create` allocates nothing in smoltcp. The smoltcp socket exists from `bind` on (explicit,
//!   or implicit on the first `connect`/`send`, to `0.0.0.0:0` / `[::]:0`).
//! * Ephemeral ports count up from [`FIRST_EPHEMERAL`] (deterministic; no RNG).
//! * A local address must be unspecified or one of the node's unicast addresses
//!   (`address-not-bindable`). Two bindings conflict when their ports are equal, their
//!   families are equal and their addresses overlap (an unspecified address overlaps every
//!   address of its family). Bindings of **different families never conflict**, like Linux
//!   with `IPV6_V6ONLY` (every WASI IPv6 socket is V6ONLY): `0.0.0.0:7` and `[::]:7` coexist
//!   (smoltcp issue #7 in `docs/upstream/smoltcp.md`).
//! * smoltcp itself ignores the family: it hands a datagram to the first socket whose port
//!   matches and whose address is unspecified or equal, so an IPv4 datagram can land in the
//!   `[::]:7` socket. On a port bound by both families, [`UdpSockets::demux`] therefore moves
//!   every received datagram, after each `Interface::poll`, into the queue of the socket that
//!   owns it: same family, and the destination address if the socket has one (a specific
//!   address wins over the unspecified one). A datagram nobody owns is dropped
//!   (`udp-rx-filtered`). Ports bound by one family only are left alone.
//! * `send` queues the datagram in smoltcp's tx buffer and returns, like `sendto(2)`: it goes out
//!   at the next driver pass, after ARP/NDP if needed. A full buffer is [`Send::WouldBlock`]: the
//!   glue parks the call until the driver made progress, then retries. Too large for one frame
//!   (no IP fragmentation) is `datagram-too-large`; a destination outside every on-link prefix
//!   with no gateway for its family is `remote-unreachable`.
//! * `receive` pops one datagram. A datagram of the other family (an IPv6 socket is `V6ONLY`),
//!   or from another peer than the connected one, is dropped and counted (`udp-rx-filtered`).
//!   smoltcp does not report ICMP errors to UDP sockets, so a datagram to a dead port shows up
//!   only as an ICMP port unreachable on the wire, and the app's own timeout decides, unless
//!   the app asked for its socket's errors with `wasmnet:sockets-ext/udp` (`IP_RECVERR`):
//!   then the netstack queues every ICMP error that quotes one of the socket's datagrams
//!   ([`UdpSockets::icmp_error`]) and `receive-error` hands them out (traceroute).
//! * Multicast (`wasmnet:sockets-ext/multicast`): a socket keeps its groups, its
//!   multicast hop limit, loopback flag and interface; [`UdpSockets::groups`] is what the stack
//!   joins on the interface. Each datagram leaves with its own hop limit (multicast or unicast):
//!   `send` stamps the smoltcp socket, and waits (`would-block`) while datagrams with another one
//!   are still queued, because smoltcp applies one per-socket hop limit at dispatch (#9).
//! * Dropping a socket with datagrams still queued keeps the smoltcp socket for up to
//!   [`LINGER_NS`] (about as long as an ARP resolution may fail), then discards what is left.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};

use crate::observe::IcmpError;

/// The netstack's name for one `udp-socket` resource.
pub type SocketId = u32;

/// First ephemeral port (IANA dynamic range).
pub const FIRST_EPHEMERAL: u16 = 49_152;
/// Default and maximum smoltcp buffer sizes (payload bytes per direction).
pub const DEFAULT_BUFFER: u64 = 65_536;
const MAX_BUFFER: u64 = 1 << 20;
/// Datagram slots per smoltcp buffer.
const SLOTS: usize = 64;
/// How long a dropped socket keeps sending its queued datagrams.
pub const LINGER_NS: u64 = 3_000_000_000;
/// ICMP errors queued per socket (`wasmnet:sockets-ext/udp`).
pub const ERROR_QUEUE: usize = 16;
/// The node's interfaces: one, `eth0`, index 1 (0 means "the default" wherever an index is taken).
pub const INTERFACES: u32 = 1;

/// An address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Family::Ipv4,
            IpAddr::V6(_) => Family::Ipv6,
        }
    }

    /// `ipv4` or `ipv6`.
    pub fn name(self) -> &'static str {
        match self {
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
        }
    }

    pub fn unspecified(self) -> IpAddr {
        match self {
            Family::Ipv4 => IpAddr::from([0u8; 4]),
            Family::Ipv6 => IpAddr::from([0u16; 8]),
        }
    }

    /// IP + UDP header bytes.
    fn overhead(self) -> usize {
        match self {
            Family::Ipv4 => 20 + 8,
            Family::Ipv6 => 40 + 8,
        }
    }
}

/// The `wasi:sockets` error codes the socket logic (UDP and TCP) produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockError {
    InvalidArgument,
    InvalidState,
    AddressInUse,
    AddressNotBindable,
    RemoteUnreachable,
    DatagramTooLarge,
    /// TCP: the peer answered the SYN with an RST.
    ConnectionRefused,
    /// TCP: the connection was reset (an RST from the peer, a timeout, or a local `abort`).
    ConnectionReset,
    /// TCP: the connection can no longer carry data in this direction (it was closed).
    ConnectionBroken,
    /// TCP: `connect` gave up.
    Timeout,
}

/// What `send` did with a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Send {
    /// Queued in smoltcp; it leaves at the next driver pass.
    Queued,
    /// smoltcp's tx buffer is full: retry after the driver made progress.
    WouldBlock,
}

/// What the UDP logic needs from the stack for one call.
pub struct Net<'a> {
    pub iface: &'a Interface,
    pub sockets: &'a mut SocketSet<'static>,
    /// IP MTU.
    pub mtu: u16,
    /// The node's unicast hop limit (the default for new sockets).
    pub hop_limit: u8,
    /// The node's multicast hop limit (the default for new sockets).
    pub multicast_hop_limit: u8,
    /// A default route exists for IPv4 / IPv6.
    pub gateway_v4: bool,
    pub gateway_v6: bool,
}

impl Net<'_> {
    fn is_ours(&self, ip: IpAddr) -> bool {
        self.iface.has_ip_addr(IpAddress::from(ip))
    }

    /// On-link (inside one of our prefixes), multicast/broadcast, or covered by a gateway.
    fn routable(&self, ip: IpAddr) -> bool {
        routable(self.iface, ip, self.gateway_v4, self.gateway_v6)
    }

    /// The largest payload that fits one frame of this family (no fragmentation).
    pub fn max_payload(&self, family: Family) -> usize {
        usize::from(self.mtu).saturating_sub(family.overhead())
    }
}

/// Whether `ip` can be reached from `iface`: on-link (inside one of its prefixes),
/// multicast/broadcast, or covered by a default gateway of its family. Shared by UDP and TCP.
pub fn routable(iface: &Interface, ip: IpAddr, gateway_v4: bool, gateway_v6: bool) -> bool {
    let smol = IpAddress::from(ip);
    let on_link = iface.ip_addrs().iter().any(|c| c.contains_addr(&smol));
    let group = match ip {
        IpAddr::V4(a) => a.is_multicast() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_multicast(),
    };
    let gateway = match ip {
        IpAddr::V4(_) => gateway_v4,
        IpAddr::V6(_) => gateway_v6,
    };
    on_link || group || gateway
}

/// A multicast destination: sent with the multicast hop limit. An IPv4 broadcast is not:
/// like POSIX, it uses the unicast TTL.
pub(crate) fn is_multicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_multicast(),
        IpAddr::V6(a) => a.is_multicast(),
    }
}

/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are not supported on either family.
pub fn is_mapped(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(a) if a.to_ipv4_mapped().is_some())
}

/// UDP counters (part of the netstack's `counters`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UdpCounters {
    pub sockets: u64,
    pub binds: u64,
    pub tx_datagrams: u64,
    pub tx_bytes: u64,
    pub rx_datagrams: u64,
    pub rx_bytes: u64,
    pub rx_filtered: u64,
    pub would_block: u64,
    pub linger_expired: u64,
    /// ICMP errors queued for sockets that asked for them (`wasmnet:sockets-ext/udp`).
    pub icmp_errors: u64,
    /// ...and the ones dropped because that socket's error queue was full.
    pub icmp_errors_dropped: u64,
    /// Sends that waited for the tx queue to drain because their hop limit differs from
    /// the queued datagrams' (per-datagram hop limits on a per-socket smoltcp setting).
    pub hop_limit_waits: u64,
    /// Multicast datagrams delivered back to the node itself (`multicast-loopback`).
    pub multicast_looped: u64,
}

#[derive(Debug)]
struct Entry {
    family: Family,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    handle: Option<SocketHandle>,
    /// Set by `set-unicast-hop-limit`; `None` is the node's default.
    hop_limit: Option<u8>,
    /// `wasmnet:sockets-ext/multicast`: groups joined, the multicast hop limit (`None`:
    /// the node's), loopback, the outgoing interface (0: default).
    groups: Vec<IpAddr>,
    multicast_hop_limit: Option<u8>,
    multicast_loopback: bool,
    multicast_interface: u32,
    rx_buffer: u64,
    tx_buffer: u64,
    /// `wasmnet:sockets-ext/udp.set-recv-errors`: queue ICMP errors for this socket.
    recv_errors: bool,
    errors: VecDeque<IcmpError>,
    /// Datagrams [`UdpSockets::demux`] took out of smoltcp for this socket (ports bound by
    /// both families), in arrival order, with their total payload bytes.
    pending: VecDeque<(Vec<u8>, SocketAddr)>,
    pending_bytes: u64,
}

/// Every app UDP socket of the node.
#[derive(Debug)]
pub struct UdpSockets {
    entries: BTreeMap<SocketId, Entry>,
    next_id: SocketId,
    next_port: u16,
    /// Dropped sockets still sending: `(handle, port, give-up deadline)`.
    closing: Vec<(SocketHandle, u16, u64)>,
    pub counters: UdpCounters,
}

impl Default for UdpSockets {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_id: 1,
            next_port: FIRST_EPHEMERAL,
            closing: Vec::new(),
            counters: UdpCounters::default(),
        }
    }
}

impl UdpSockets {
    /// Every socket's id, in order.
    pub fn ids(&self) -> Vec<SocketId> {
        self.entries.keys().copied().collect()
    }

    /// No socket at all, live or lingering.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.closing.is_empty()
    }

    /// The table for a quiescent snapshot: every socket with its options and
    /// its smoltcp slot; refused while a socket lingers or holds a datagram or an ICMP error.
    pub fn snapshot_save(
        &self,
        w: &mut crate::snapshot::W,
        sockets: &SocketSet<'static>,
    ) -> crate::snapshot::Res<()> {
        use crate::snapshot::Counters;
        if !self.closing.is_empty() {
            return Err("a closed UDP socket is still sending".into());
        }
        w.u32(self.next_id);
        w.u16(self.next_port);
        self.counters.put(w);
        w.count(self.entries.len());
        for (&id, e) in &self.entries {
            if !e.errors.is_empty() || !e.pending.is_empty() {
                return Err(format!("UDP socket {id} has data waiting"));
            }
            if let Some(h) = e.handle {
                let s = sockets.get::<udp::Socket>(h);
                if s.can_recv() || s.send_queue() > 0 {
                    return Err(format!("UDP socket {id} has data waiting"));
                }
            }
            w.u32(id);
            w.bool(e.family == Family::Ipv6);
            w.sock(e.local);
            w.sock(e.remote);
            w.opt_u64(e.handle.map(|h| h.index() as u64));
            w.opt_u8(e.hop_limit);
            w.count(e.groups.len());
            for g in &e.groups {
                w.ip(*g);
            }
            w.opt_u8(e.multicast_hop_limit);
            w.bool(e.multicast_loopback);
            w.u32(e.multicast_interface);
            w.u64(e.rx_buffer);
            w.u64(e.tx_buffer);
            w.bool(e.recv_errors);
        }
        Ok(())
    }

    /// Puts [`snapshot_save`](Self::snapshot_save)'s table back into an empty one, each bound
    /// socket at its saved smoltcp slot.
    pub fn snapshot_restore(
        &mut self,
        r: &mut crate::snapshot::R<'_>,
        sockets: &mut SocketSet<'static>,
        node_hops: u8,
    ) -> crate::snapshot::Res<()> {
        use crate::snapshot::Counters;
        self.next_id = r.u32()?;
        self.next_port = r.u16()?;
        self.counters = UdpCounters::get(r)?;
        for _ in 0..r.count()? {
            let id = r.u32()?;
            let family = if r.bool()? {
                Family::Ipv6
            } else {
                Family::Ipv4
            };
            let local = r.sock()?;
            let remote = r.sock()?;
            let slot = r.opt_u64()?;
            let hop_limit = r.opt_u8()?;
            let mut groups = Vec::new();
            for _ in 0..r.count()? {
                groups.push(r.ip()?);
            }
            let mut e = Entry {
                family,
                local,
                remote,
                handle: None,
                hop_limit,
                groups,
                multicast_hop_limit: r.opt_u8()?,
                multicast_loopback: r.bool()?,
                multicast_interface: r.u32()?,
                rx_buffer: r.u64()?,
                tx_buffer: r.u64()?,
                recv_errors: r.bool()?,
                errors: VecDeque::new(),
                pending: VecDeque::new(),
                pending_bytes: 0,
            };
            if let Some(slot) = slot {
                let bound = local.ok_or("snapshot: a UDP socket in a slot is not bound")?;
                let buffer = |bytes: u64| {
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; SLOTS],
                        vec![0u8; bytes as usize],
                    )
                };
                let mut socket = udp::Socket::new(buffer(e.rx_buffer), buffer(e.tx_buffer));
                let ip = bound.ip();
                socket
                    .bind(IpListenEndpoint {
                        addr: (!ip.is_unspecified()).then(|| IpAddress::from(ip)),
                        port: bound.port(),
                    })
                    .map_err(|e| format!("snapshot: rebinding UDP {bound}: {e}"))?;
                socket.set_hop_limit(Some(e.hop_limit.unwrap_or(node_hops)));
                e.handle = Some(
                    sockets
                        .add_at(slot as usize, socket)
                        .ok_or("snapshot: two sockets in one slot")?,
                );
            }
            self.entries.insert(id, e);
        }
        Ok(())
    }

    /// Every socket, for inspection. Read only. Queues are bytes: smoltcp's
    /// buffers plus the datagrams demultiplexed for this socket.
    pub fn inspect(&self, sockets: &SocketSet<'static>) -> Vec<crate::debug::SockInfo> {
        self.entries
            .iter()
            .map(|(&id, e)| {
                let (rx, tx) = e.handle.map_or((0, 0), |h| {
                    let s = sockets.get::<udp::Socket>(h);
                    (s.recv_queue() as u64, s.send_queue() as u64)
                });
                let state = if e.remote.is_some() {
                    "connected"
                } else if e.local.is_some() {
                    "bound"
                } else {
                    "unbound"
                };
                crate::debug::SockInfo {
                    id,
                    family: e.family.name(),
                    local: e.local,
                    remote: e.remote,
                    state: state.to_owned(),
                    rx_queued: rx + e.pending_bytes,
                    tx_queued: tx,
                }
            })
            .collect()
    }
}

/// `true` when two bindings on the same port would compete for the same datagrams: same
/// family, and one is unspecified or both are equal. Families never compete (V6ONLY).
pub(crate) fn overlaps(a: IpAddr, b: IpAddr) -> bool {
    Family::of(a) == Family::of(b) && (a.is_unspecified() || b.is_unspecified() || a == b)
}

fn endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(IpAddress::from(addr.ip()), addr.port())
}

fn socket_addr(ep: IpEndpoint) -> SocketAddr {
    SocketAddr::new(IpAddr::from(ep.addr), ep.port)
}

impl UdpSockets {
    fn entry(&self, id: SocketId) -> Result<&Entry, SockError> {
        self.entries.get(&id).ok_or(SockError::InvalidState)
    }

    fn entry_mut(&mut self, id: SocketId) -> Result<&mut Entry, SockError> {
        self.entries.get_mut(&id).ok_or(SockError::InvalidState)
    }

    /// `udp-socket.create`.
    pub fn create(&mut self, family: Family) -> SocketId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.counters.sockets += 1;
        self.entries.insert(
            id,
            Entry {
                family,
                local: None,
                remote: None,
                handle: None,
                hop_limit: None,
                groups: Vec::new(),
                multicast_hop_limit: None,
                multicast_loopback: true,
                multicast_interface: 0,
                recv_errors: false,
                errors: VecDeque::new(),
                pending: VecDeque::new(),
                pending_bytes: 0,
                rx_buffer: DEFAULT_BUFFER,
                tx_buffer: DEFAULT_BUFFER,
            },
        );
        id
    }

    pub fn family(&self, id: SocketId) -> Result<Family, SockError> {
        Ok(self.entry(id)?.family)
    }

    pub fn local_address(&self, id: SocketId) -> Result<SocketAddr, SockError> {
        self.entry(id)?.local.ok_or(SockError::InvalidState)
    }

    pub fn remote_address(&self, id: SocketId) -> Result<SocketAddr, SockError> {
        self.entry(id)?.remote.ok_or(SockError::InvalidState)
    }

    /// Ports in use, with the address each one is bound to (open and lingering sockets).
    fn in_use(&self, port: u16, ip: IpAddr) -> bool {
        let open = self
            .entries
            .values()
            .filter_map(|e| e.local)
            .any(|l| l.port() == port && overlaps(l.ip(), ip));
        open || self.closing.iter().any(|&(_, p, _)| p == port)
    }

    fn ephemeral(&mut self, ip: IpAddr) -> Result<u16, SockError> {
        for _ in 0..=(u16::MAX - FIRST_EPHEMERAL) {
            let port = self.next_port;
            self.next_port = if port == u16::MAX {
                FIRST_EPHEMERAL
            } else {
                port + 1
            };
            if !self.in_use(port, ip) {
                return Ok(port);
            }
        }
        Err(SockError::AddressInUse)
    }

    /// `udp-socket.bind`. Returns the address actually bound (the port filled in).
    pub fn bind(
        &mut self,
        id: SocketId,
        local: SocketAddr,
        net: &mut Net<'_>,
    ) -> Result<SocketAddr, SockError> {
        let entry = self.entry(id)?;
        if entry.local.is_some() {
            return Err(SockError::InvalidState);
        }
        if Family::of(local.ip()) != entry.family || is_mapped(local.ip()) {
            return Err(SockError::InvalidArgument);
        }
        let ip = local.ip();
        if !ip.is_unspecified() && !net.is_ours(ip) {
            return Err(SockError::AddressNotBindable);
        }
        let port = match local.port() {
            0 => self.ephemeral(ip)?,
            p if self.in_use(p, ip) => return Err(SockError::AddressInUse),
            p => p,
        };
        let entry = self.entry_mut(id)?;
        let bound = SocketAddr::new(ip, port);
        let buffer = |bytes: u64| {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; SLOTS],
                vec![0u8; bytes as usize],
            )
        };
        let mut socket = udp::Socket::new(buffer(entry.rx_buffer), buffer(entry.tx_buffer));
        let listen = IpListenEndpoint {
            addr: (!ip.is_unspecified()).then(|| IpAddress::from(ip)),
            port,
        };
        socket
            .bind(listen)
            .map_err(|_| SockError::AddressNotBindable)?;
        socket.set_hop_limit(Some(entry.hop_limit.unwrap_or(net.hop_limit)));
        entry.handle = Some(net.sockets.add(socket));
        entry.local = Some(bound);
        self.counters.binds += 1;
        Ok(bound)
    }

    /// Binds to the unspecified address and an ephemeral port, unless already bound.
    fn ensure_bound(&mut self, id: SocketId, net: &mut Net<'_>) -> Result<SocketAddr, SockError> {
        let entry = self.entry(id)?;
        match entry.local {
            Some(local) => Ok(local),
            None => {
                let any = SocketAddr::new(entry.family.unspecified(), 0);
                self.bind(id, any, net)
            }
        }
    }

    /// Checks a peer address for `connect`/`send`.
    fn check_peer(&self, id: SocketId, peer: SocketAddr) -> Result<(), SockError> {
        let ip = peer.ip();
        if Family::of(ip) != self.entry(id)?.family
            || ip.is_unspecified()
            || peer.port() == 0
            || is_mapped(ip)
        {
            return Err(SockError::InvalidArgument);
        }
        Ok(())
    }

    /// `udp-socket.connect`: remembers the peer (binding implicitly). No traffic.
    pub fn connect(
        &mut self,
        id: SocketId,
        remote: SocketAddr,
        net: &mut Net<'_>,
    ) -> Result<(), SockError> {
        self.check_peer(id, remote)?;
        self.ensure_bound(id, net)?;
        self.entry_mut(id)?.remote = Some(remote);
        Ok(())
    }

    /// `udp-socket.disconnect`.
    pub fn disconnect(&mut self, id: SocketId) -> Result<(), SockError> {
        match self.entry_mut(id)?.remote.take() {
            Some(_) => Ok(()),
            None => Err(SockError::InvalidState),
        }
    }

    /// `udp-socket.send`: queues one datagram for `to` (or the connected peer).
    pub fn send(
        &mut self,
        id: SocketId,
        data: &[u8],
        to: Option<SocketAddr>,
        net: &mut Net<'_>,
    ) -> Result<Send, SockError> {
        let entry = self.entry(id)?;
        let dst = match (to, entry.remote) {
            (Some(to), Some(connected)) if to != connected => {
                return Err(SockError::InvalidArgument);
            }
            (Some(to), _) | (None, Some(to)) => to,
            (None, None) => return Err(SockError::InvalidArgument),
        };
        self.check_peer(id, dst)?;
        let family = entry.family;
        if data.len() > net.max_payload(family) {
            return Err(SockError::DatagramTooLarge);
        }
        if !net.routable(dst.ip()) {
            return Err(SockError::RemoteUnreachable);
        }
        self.ensure_bound(id, net)?;
        let entry = self.entry(id)?;
        let handle = entry.handle.ok_or(SockError::InvalidState)?;
        // Per-datagram hop limits (smoltcp #9 keeps one hop limit per socket and applies it
        // when a datagram leaves): stamp the socket with this datagram's hop limit, and if
        // datagrams with another one are still queued, wait until they left.
        let hops = if is_multicast(dst.ip()) {
            entry.multicast_hop_limit.unwrap_or(net.multicast_hop_limit)
        } else {
            entry.hop_limit.unwrap_or(net.hop_limit)
        };
        let socket = net.sockets.get_mut::<udp::Socket>(handle);
        if socket.hop_limit() != Some(hops) {
            if socket.send_queue() > 0 {
                self.counters.hop_limit_waits += 1;
                return Ok(Send::WouldBlock);
            }
            socket.set_hop_limit(Some(hops));
        }
        match socket.send_slice(data, endpoint(dst)) {
            Ok(()) => {
                self.counters.tx_datagrams += 1;
                self.counters.tx_bytes += data.len() as u64;
                Ok(Send::Queued)
            }
            Err(udp::SendError::BufferFull) => {
                self.counters.would_block += 1;
                Ok(Send::WouldBlock)
            }
            Err(udp::SendError::Unaddressable) => Err(SockError::InvalidArgument),
        }
    }

    /// `udp-socket.receive`: the next datagram for this socket, or `None` if there is none yet.
    pub fn receive(
        &mut self,
        id: SocketId,
        net: &mut Net<'_>,
    ) -> Result<Option<(Vec<u8>, SocketAddr)>, SockError> {
        let entry = self.entries.get_mut(&id).ok_or(SockError::InvalidState)?;
        let (Some(handle), Some(_)) = (entry.handle, entry.local) else {
            return Err(SockError::InvalidState);
        };
        let (family, remote) = (entry.family, entry.remote);
        // Datagrams the family demultiplexer already set aside for this socket come first.
        while let Some((payload, from)) = entry.pending.pop_front() {
            entry.pending_bytes -= payload.len() as u64;
            if remote.is_some_and(|r| r != from) {
                self.counters.rx_filtered += 1;
                continue;
            }
            self.counters.rx_datagrams += 1;
            self.counters.rx_bytes += payload.len() as u64;
            return Ok(Some((payload, from)));
        }
        let socket = net.sockets.get_mut::<udp::Socket>(handle);
        while let Ok((payload, meta)) = socket.recv() {
            let from = socket_addr(meta.endpoint);
            if Family::of(from.ip()) != family || remote.is_some_and(|r| r != from) {
                self.counters.rx_filtered += 1;
                continue;
            }
            self.counters.rx_datagrams += 1;
            self.counters.rx_bytes += payload.len() as u64;
            return Ok(Some((payload.to_vec(), from)));
        }
        Ok(None)
    }

    pub fn unicast_hop_limit(&self, id: SocketId, default: u8) -> Result<u8, SockError> {
        Ok(self.entry(id)?.hop_limit.unwrap_or(default))
    }

    pub fn set_unicast_hop_limit(
        &mut self,
        id: SocketId,
        value: u8,
        _net: &mut Net<'_>,
    ) -> Result<(), SockError> {
        if value == 0 {
            return Err(SockError::InvalidArgument);
        }
        // Applies to datagrams sent from now on; `send` stamps it.
        self.entry_mut(id)?.hop_limit = Some(value);
        Ok(())
    }

    /// The receive (`rx = true`) or send buffer size. It takes effect at `bind`; read back, it
    /// is the clamped value.
    pub fn buffer_size(&self, id: SocketId, rx: bool) -> Result<u64, SockError> {
        let e = self.entry(id)?;
        Ok(if rx { e.rx_buffer } else { e.tx_buffer })
    }

    /// Sets a buffer size, clamped to `[one full datagram, 1 MiB]`. A bound socket keeps the
    /// buffers it has (smoltcp cannot resize them) and reads back their actual size.
    pub fn set_buffer_size(
        &mut self,
        id: SocketId,
        rx: bool,
        value: u64,
        net: &Net<'_>,
    ) -> Result<(), SockError> {
        if value == 0 {
            return Err(SockError::InvalidArgument);
        }
        let entry = self.entry_mut(id)?;
        if entry.handle.is_some() {
            return Ok(());
        }
        let min = net.max_payload(entry.family) as u64;
        let value = value.clamp(min, MAX_BUFFER);
        if rx {
            entry.rx_buffer = value;
        } else {
            entry.tx_buffer = value;
        }
        Ok(())
    }

    /// `wasmnet:sockets-ext/udp.set-recv-errors` (`IP_RECVERR`): from now on, queue the ICMP
    /// errors about this socket's datagrams (`false` stops and empties the queue).
    pub fn set_recv_errors(&mut self, id: SocketId, value: bool) -> Result<(), SockError> {
        let entry = self.entry_mut(id)?;
        entry.recv_errors = value;
        if !value {
            entry.errors.clear();
        }
        Ok(())
    }

    pub fn recv_errors(&self, id: SocketId) -> Result<bool, SockError> {
        Ok(self.entry(id)?.recv_errors)
    }

    /// An ICMP error about a UDP datagram arrived: queue it for the socket bound to its source
    /// port, if that socket asked for errors. At most [`ERROR_QUEUE`] wait per socket (Linux bounds
    /// the error queue by the receive buffer); the newest is dropped when full.
    /// Returns whether a socket took it.
    pub fn icmp_error(&mut self, e: &IcmpError) -> bool {
        if e.proto != 17 {
            return false;
        }
        let family = if e.v6 { Family::Ipv6 } else { Family::Ipv4 };
        let Some(entry) = self.entries.values_mut().find(|en| {
            en.recv_errors
                && en.family == family
                && en.local.is_some_and(|l| {
                    l.port() == e.sport && (l.ip().is_unspecified() || l.ip() == e.orig_src)
                })
        }) else {
            return false;
        };
        if entry.errors.len() >= ERROR_QUEUE {
            self.counters.icmp_errors_dropped += 1;
            return false;
        }
        entry.errors.push_back(*e);
        self.counters.icmp_errors += 1;
        true
    }

    /// `wasmnet:sockets-ext/udp.receive-error`: the oldest queued ICMP error, or `None` if there
    /// is none yet. `invalid-state` unless the socket asked for errors.
    pub fn take_error(&mut self, id: SocketId) -> Result<Option<IcmpError>, SockError> {
        let entry = self.entry_mut(id)?;
        if !entry.recv_errors {
            return Err(SockError::InvalidState);
        }
        Ok(entry.errors.pop_front())
    }

    /// The resource was dropped at `now`. A socket with datagrams still queued lingers.
    pub fn close(&mut self, id: SocketId, now: u64, sockets: &mut SocketSet<'static>) {
        let Some(entry) = self.entries.remove(&id) else {
            return;
        };
        let (Some(handle), Some(local)) = (entry.handle, entry.local) else {
            return;
        };
        if sockets.get::<udp::Socket>(handle).send_queue() > 0 {
            self.closing
                .push((handle, local.port(), now.saturating_add(LINGER_NS)));
        } else {
            sockets.remove(handle);
        }
    }

    /// The family demultiplexer (smoltcp issue #7): on every port bound by both families, takes
    /// each received datagram out of whichever smoltcp socket caught it and queues it for the
    /// socket that owns it (`Self::owner`), or drops it (`udp-rx-filtered`) if none does.
    /// Call after every `Interface::poll`. Returns whether it moved anything.
    pub fn demux(&mut self, sockets: &mut SocketSet<'static>) -> bool {
        let bound = |family| {
            self.entries
                .values()
                .filter(move |e| e.family == family && e.handle.is_some())
                .filter_map(|e| e.local.map(|l| l.port()))
                .collect::<std::collections::BTreeSet<u16>>()
        };
        let (v4, v6) = (bound(Family::Ipv4), bound(Family::Ipv6));
        let mut moved = false;
        for port in v4.intersection(&v6).copied() {
            let handles: Vec<SocketHandle> = self
                .entries
                .values()
                .filter(|e| e.local.is_some_and(|l| l.port() == port))
                .filter_map(|e| e.handle)
                .collect();
            for handle in handles {
                let socket = sockets.get_mut::<udp::Socket>(handle);
                while let Ok((payload, meta)) = socket.recv() {
                    moved = true;
                    let from = socket_addr(meta.endpoint);
                    let to = meta.local_address.map(IpAddr::from);
                    let owner = self.owner(port, Family::of(from.ip()), to);
                    let Some(entry) = owner.and_then(|id| self.entries.get_mut(&id)) else {
                        self.counters.rx_filtered += 1;
                        continue;
                    };
                    // Bounded like the smoltcp buffer it stands in for.
                    let len = payload.len() as u64;
                    if entry.pending.len() >= SLOTS || entry.pending_bytes + len > entry.rx_buffer {
                        self.counters.rx_filtered += 1;
                        continue;
                    }
                    entry.pending_bytes += len;
                    entry.pending.push_back((payload.to_vec(), from));
                }
            }
        }
        moved
    }

    /// The socket on `port` that owns a datagram of `family` sent to `to`: a socket bound to
    /// exactly `to` first, else the family's unspecified-address socket.
    fn owner(&self, port: u16, family: Family, to: Option<IpAddr>) -> Option<SocketId> {
        let on_port = || {
            self.entries.iter().filter(move |(_, e)| {
                e.family == family
                    && e.handle.is_some()
                    && e.local.is_some_and(|l| l.port() == port)
            })
        };
        let exact = on_port().find(|(_, e)| e.local.map(|l| l.ip()) == to);
        let any = || on_port().find(|(_, e)| e.local.is_some_and(|l| l.ip().is_unspecified()));
        exact.or_else(any).map(|(&id, _)| id)
    }

    /// Removes lingering sockets that drained or gave up. Call after every `Interface::poll`.
    pub fn reap(&mut self, now: u64, sockets: &mut SocketSet<'static>) {
        let counters = &mut self.counters;
        self.closing.retain(|&(handle, _, deadline)| {
            let drained = sockets.get::<udp::Socket>(handle).send_queue() == 0;
            if drained || deadline <= now {
                if !drained {
                    counters.linger_expired += 1;
                }
                sockets.remove(handle);
                false
            } else {
                true
            }
        });
    }

    /// The earliest linger deadline, if a dropped socket is still sending.
    pub fn next_deadline(&self) -> Option<u64> {
        self.closing.iter().map(|&(_, _, d)| d).min()
    }

    // -----------------------------------------------------------------------------------------
    // multicast (`wasmnet:sockets-ext/multicast`)

    /// `join-multicast-group`. The interface joins at the stack's next pass ([`Self::groups`]).
    pub fn join(&mut self, id: SocketId, group: IpAddr, interface: u32) -> Result<(), SockError> {
        let entry = self.entry_mut(id)?;
        if Family::of(group) != entry.family || !is_multicast(group) || interface > INTERFACES {
            return Err(SockError::InvalidArgument);
        }
        if entry.groups.contains(&group) {
            return Err(SockError::AddressInUse);
        }
        entry.groups.push(group);
        Ok(())
    }

    /// `leave-multicast-group`.
    pub fn leave(&mut self, id: SocketId, group: IpAddr, interface: u32) -> Result<(), SockError> {
        let entry = self.entry_mut(id)?;
        let at = entry
            .groups
            .iter()
            .position(|g| *g == group)
            .filter(|_| interface <= INTERFACES)
            .ok_or(SockError::InvalidArgument)?;
        entry.groups.remove(at);
        Ok(())
    }

    /// Every group some open socket is a member of (the interface's memberships).
    pub fn groups(&self) -> std::collections::BTreeSet<IpAddr> {
        self.entries
            .values()
            .flat_map(|e| e.groups.iter().copied())
            .collect()
    }

    pub fn multicast_hop_limit(&self, id: SocketId, default: u8) -> Result<u8, SockError> {
        Ok(self.entry(id)?.multicast_hop_limit.unwrap_or(default))
    }

    /// Applies to datagrams sent to a group from now on (`send` stamps it).
    pub fn set_multicast_hop_limit(&mut self, id: SocketId, value: u8) -> Result<(), SockError> {
        if value == 0 {
            return Err(SockError::InvalidArgument);
        }
        self.entry_mut(id)?.multicast_hop_limit = Some(value);
        Ok(())
    }

    pub fn multicast_loopback(&self, id: SocketId) -> Result<bool, SockError> {
        Ok(self.entry(id)?.multicast_loopback)
    }

    pub fn set_multicast_loopback(&mut self, id: SocketId, value: bool) -> Result<(), SockError> {
        self.entry_mut(id)?.multicast_loopback = value;
        Ok(())
    }

    pub fn multicast_interface(&self, id: SocketId) -> Result<u32, SockError> {
        Ok(self.entry(id)?.multicast_interface)
    }

    pub fn set_multicast_interface(&mut self, id: SocketId, value: u32) -> Result<(), SockError> {
        if value > INTERFACES {
            return Err(SockError::InvalidArgument);
        }
        self.entry_mut(id)?.multicast_interface = value;
        Ok(())
    }

    /// Whether a multicast datagram the node sent from local port `port` of `family` is to be
    /// looped back: the open socket bound to that port asked for it (the default). Counts it.
    pub fn loops_back(&mut self, family: Family, port: u16) -> bool {
        let looped = self.entries.values().any(|e| {
            e.family == family && e.multicast_loopback && e.local.is_some_and(|l| l.port() == port)
        });
        if looped {
            self.counters.multicast_looped += 1;
        }
        looped
    }

    /// Open sockets (not counting lingering ones).
    pub fn open(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_rules() {
        let any4: IpAddr = "0.0.0.0".parse().unwrap();
        let any6: IpAddr = "::".parse().unwrap();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let c: IpAddr = "fd00::1".parse().unwrap();
        assert!(overlaps(any4, a) && overlaps(c, any6) && overlaps(a, a) && overlaps(any6, any6));
        assert!(!overlaps(a, b));
        // Families never overlap (every IPv6 socket is V6ONLY): smoltcp issue #7.
        assert!(!overlaps(any4, any6) && !overlaps(a, any6) && !overlaps(any4, c));
        assert!(is_mapped("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!is_mapped("fd00::1".parse().unwrap()));
        assert_eq!(Family::Ipv6.overhead(), 48);
    }
}
