//! ICMP echo sockets for the node's apps: the logic behind the exported
//! `wasmnet:sockets-ext/icmp` `icmp-socket` resource, Linux's unprivileged ping sockets
//! (`SOCK_DGRAM` + `IPPROTO_ICMP` / `IPPROTO_ICMPV6`), over smoltcp ICMP sockets.
//!
//! Like [`crate::udp`], everything here is pure and called by the glue with the stack borrowed.
//!
//! * `create` allocates nothing in smoltcp. The smoltcp socket exists from `bind` on (explicit,
//!   or implicit on the first `connect`/`send`), bound to `Endpoint::Ident(identifier)`.
//! * **Identifiers** belong to the stack. Identifier 0 (or an implicit bind) picks the next one
//!   from a rover that starts at the node's seeded identifier (the analogue of a pid) and skips
//!   0 and every identifier an ICMP socket of either family holds; an explicit identifier
//!   conflicts only with a socket of the same family (`address-in-use`), as on Linux.
//! * **Send**: the app's bytes are a whole ICMP echo request; the identifier and checksum are
//!   overwritten (the ICMPv6 checksum covers the source address smoltcp will choose).
//! * **Receive**: smoltcp hands an `Ident` socket every echo request *and* reply with its
//!   identifier, of both families. Only echo replies of the socket's family (from the connected
//!   peer, if any) are delivered; the rest is dropped and counted (`icmp-rx-filtered`).
//! * **Errors** (`set-recv-errors`): an ICMP error quoting one of the socket's echo requests
//!   (same family and identifier, and the bound address if specific) is queued, at most
//!   [`ERROR_QUEUE`] per socket.
//! * **Hop limits**: like UDP (smoltcp #9) smoltcp applies one hop limit per socket when a
//!   packet leaves, so `send` stamps the socket and waits (`would-block`) while requests with
//!   another hop limit are still queued.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::icmp;
use smoltcp::wire::{Icmpv4Packet, Icmpv6Packet, IpAddress};

use crate::observe::IcmpError;
use crate::udp::{ERROR_QUEUE, Family, Net, Send, SockError, is_mapped, is_multicast};

/// The netstack's name for one `icmp-socket` resource.
pub type SocketId = u32;

/// One received echo reply: the ICMP message, its source and the hop limit it arrived with.
pub type Datagram = (Vec<u8>, IpAddr, Option<u8>);

/// Packet slots per smoltcp buffer (a burst of unanswered requests, or replies from a group).
const SLOTS: usize = 16;

/// ICMP socket counters (part of the netstack's `counters`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IcmpCounters {
    pub sockets: u64,
    pub binds: u64,
    /// Echo requests queued by apps, and replies delivered to them.
    pub requests: u64,
    pub replies: u64,
    /// Messages smoltcp gave a socket that were not for it (another family, a request, another
    /// peer).
    pub rx_filtered: u64,
    pub would_block: u64,
    pub errors_queued: u64,
    pub errors_dropped: u64,
}

#[derive(Debug)]
struct Entry {
    family: Family,
    /// The bound address and identifier.
    local: Option<(IpAddr, u16)>,
    remote: Option<IpAddr>,
    handle: Option<SocketHandle>,
    /// Set by `set-unicast-hop-limit`; `None` is the node's default.
    hop_limit: Option<u8>,
    recv_errors: bool,
    errors: VecDeque<IcmpError>,
}

/// Every app ICMP socket of the node.
#[derive(Debug)]
pub struct IcmpSockets {
    entries: BTreeMap<SocketId, Entry>,
    next_id: SocketId,
    next_ident: u16,
    pub counters: IcmpCounters,
    /// The hop limits echo replies to our sockets arrived with, as the stack saw their frames:
    /// `(identifier, source, sequence, hop limit)`, oldest first, at most `HOPS`. What
    /// `receive-datagram` reports. Only replies for an identifier a socket
    /// holds are noted, and a socket's are forgotten when it closes, so a quiescent stack (no
    /// socket) has none.
    hops: VecDeque<(u16, IpAddr, u16, u8)>,
}

/// Reply hop limits remembered at most (a burst of unread replies; older ones report `none`).
const HOPS: usize = 64;

impl IcmpSockets {
    /// A table whose first picked identifier is `first_ident` (0 becomes 1).
    pub fn new(first_ident: u16) -> Self {
        Self {
            entries: BTreeMap::new(),
            next_id: 1,
            next_ident: first_ident,
            counters: IcmpCounters::default(),
            hops: VecDeque::new(),
        }
    }

    /// Its state for a quiescent snapshot: refused while an app holds an ICMP
    /// socket (v1 restores no echo session), else the id and identifier rovers and the counters.
    pub fn snapshot_save(&self, w: &mut crate::snapshot::W) -> crate::snapshot::Res<()> {
        if !self.entries.is_empty() {
            return Err("an app holds an ICMP echo socket".into());
        }
        w.u32(self.next_id);
        w.u16(self.next_ident);
        let c = &self.counters;
        for v in [
            c.sockets,
            c.binds,
            c.requests,
            c.replies,
            c.rx_filtered,
            c.would_block,
            c.errors_queued,
            c.errors_dropped,
        ] {
            w.u64(v);
        }
        Ok(())
    }

    /// Puts [`snapshot_save`](Self::snapshot_save)'s state back.
    pub fn snapshot_restore(&mut self, r: &mut crate::snapshot::R<'_>) -> crate::snapshot::Res<()> {
        self.next_id = r.u32()?;
        self.next_ident = r.u16()?;
        self.counters = IcmpCounters {
            sockets: r.u64()?,
            binds: r.u64()?,
            requests: r.u64()?,
            replies: r.u64()?,
            rx_filtered: r.u64()?,
            would_block: r.u64()?,
            errors_queued: r.u64()?,
            errors_dropped: r.u64()?,
        };
        Ok(())
    }

    /// No app ICMP socket.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn entry(&self, id: SocketId) -> Result<&Entry, SockError> {
        self.entries.get(&id).ok_or(SockError::InvalidState)
    }

    fn entry_mut(&mut self, id: SocketId) -> Result<&mut Entry, SockError> {
        self.entries.get_mut(&id).ok_or(SockError::InvalidState)
    }

    fn in_use(&self, ident: u16, family: Option<Family>) -> bool {
        self.entries.values().any(|e| {
            e.local.is_some_and(|(_, i)| i == ident) && family.is_none_or(|f| f == e.family)
        })
    }

    /// The next free identifier from the rover (never 0), for a socket bound to identifier 0.
    pub fn pick_ident(&mut self) -> Result<u16, SockError> {
        for _ in 0..=u16::MAX {
            let ident = self.next_ident;
            self.next_ident = self.next_ident.wrapping_add(1);
            if ident != 0 && !self.in_use(ident, None) {
                return Ok(ident);
            }
        }
        Err(SockError::AddressInUse)
    }

    /// `icmp-socket.create`.
    pub fn create(&mut self, family: Family) -> SocketId {
        let id = self.next_id;
        self.next_id += 1;
        self.entries.insert(
            id,
            Entry {
                family,
                local: None,
                remote: None,
                handle: None,
                hop_limit: None,
                recv_errors: false,
                errors: VecDeque::new(),
            },
        );
        self.counters.sockets += 1;
        id
    }

    pub fn family(&self, id: SocketId) -> Result<Family, SockError> {
        Ok(self.entry(id)?.family)
    }

    /// `icmp-socket.bind`. Returns the identifier bound (picked when `ident` is 0).
    pub fn bind(
        &mut self,
        id: SocketId,
        local: IpAddr,
        ident: u16,
        net: &mut Net<'_>,
    ) -> Result<u16, SockError> {
        let entry = self.entry(id)?;
        if entry.local.is_some() {
            return Err(SockError::InvalidState);
        }
        let family = entry.family;
        if Family::of(local) != family || is_mapped(local) {
            return Err(SockError::InvalidArgument);
        }
        if !local.is_unspecified() && !net.iface.has_ip_addr(IpAddress::from(local)) {
            return Err(SockError::AddressNotBindable);
        }
        let ident = match ident {
            0 => self.pick_ident()?,
            i if self.in_use(i, Some(family)) => return Err(SockError::AddressInUse),
            i => i,
        };
        let payload = SLOTS * (usize::from(net.mtu) + 8);
        let buffer = || {
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; SLOTS], vec![0u8; payload])
        };
        let mut socket = icmp::Socket::new(buffer(), buffer());
        socket
            .bind(icmp::Endpoint::Ident(ident))
            .map_err(|_| SockError::AddressNotBindable)?;
        let entry = self.entry_mut(id)?;
        entry.handle = Some(net.sockets.add(socket));
        entry.local = Some((local, ident));
        self.counters.binds += 1;
        Ok(ident)
    }

    fn ensure_bound(&mut self, id: SocketId, net: &mut Net<'_>) -> Result<(), SockError> {
        let entry = self.entry(id)?;
        if entry.local.is_none() {
            let any = entry.family.unspecified();
            self.bind(id, any, 0, net)?;
        }
        Ok(())
    }

    fn check_peer(&self, id: SocketId, peer: IpAddr) -> Result<(), SockError> {
        if Family::of(peer) != self.entry(id)?.family || peer.is_unspecified() || is_mapped(peer) {
            return Err(SockError::InvalidArgument);
        }
        Ok(())
    }

    /// `icmp-socket.connect`: remembers the peer (binding implicitly). No traffic.
    pub fn connect(
        &mut self,
        id: SocketId,
        remote: IpAddr,
        net: &mut Net<'_>,
    ) -> Result<(), SockError> {
        self.check_peer(id, remote)?;
        self.ensure_bound(id, net)?;
        self.entry_mut(id)?.remote = Some(remote);
        Ok(())
    }

    pub fn disconnect(&mut self, id: SocketId) -> Result<(), SockError> {
        let entry = self.entry_mut(id)?;
        if entry.remote.take().is_none() {
            return Err(SockError::InvalidState);
        }
        Ok(())
    }

    pub fn local_address(&self, id: SocketId) -> Result<IpAddr, SockError> {
        self.entry(id)?
            .local
            .map(|(a, _)| a)
            .ok_or(SockError::InvalidState)
    }

    pub fn identifier(&self, id: SocketId) -> Result<u16, SockError> {
        self.entry(id)?
            .local
            .map(|(_, i)| i)
            .ok_or(SockError::InvalidState)
    }

    pub fn remote_address(&self, id: SocketId) -> Result<IpAddr, SockError> {
        self.entry(id)?.remote.ok_or(SockError::InvalidState)
    }

    /// `icmp-socket.send`: checks and queues one echo request.
    pub fn send(
        &mut self,
        id: SocketId,
        data: &[u8],
        to: Option<IpAddr>,
        net: &mut Net<'_>,
    ) -> Result<Send, SockError> {
        let entry = self.entry(id)?;
        let family = entry.family;
        let request = match family {
            Family::Ipv4 => 8,
            Family::Ipv6 => 128,
        };
        if data.len() < 8 || data[0] != request || data[1] != 0 {
            return Err(SockError::InvalidArgument);
        }
        let dst = match (to, entry.remote) {
            (Some(to), _) => {
                self.check_peer(id, to)?;
                to
            }
            (None, Some(remote)) => remote,
            (None, None) => return Err(SockError::InvalidArgument),
        };
        let ip_header = match family {
            Family::Ipv4 => 20,
            Family::Ipv6 => 40,
        };
        if data.len() + ip_header > usize::from(net.mtu) {
            return Err(SockError::DatagramTooLarge);
        }
        if !crate::udp::routable(net.iface, dst, net.gateway_v4, net.gateway_v6) {
            return Err(SockError::RemoteUnreachable);
        }
        self.ensure_bound(id, net)?;
        let entry = self.entry(id)?;
        let (Some(handle), Some((local, ident))) = (entry.handle, entry.local) else {
            return Err(SockError::InvalidState);
        };
        let hops = if is_multicast(dst) {
            net.multicast_hop_limit
        } else {
            entry.hop_limit.unwrap_or(net.hop_limit)
        };
        // The ICMPv6 checksum covers the source address smoltcp will choose.
        let src6 = match dst {
            IpAddr::V6(d) => {
                let src = net.iface.get_source_address_ipv6(&d);
                if !local.is_unspecified() && IpAddr::V6(src) != local {
                    return Err(SockError::InvalidArgument);
                }
                Some((src, d))
            }
            IpAddr::V4(_) => None,
        };
        let socket = net.sockets.get_mut::<icmp::Socket>(handle);
        if socket.send_queue() > 0 && socket.hop_limit() != Some(hops) {
            self.counters.would_block += 1;
            return Ok(Send::WouldBlock);
        }
        socket.set_hop_limit(Some(hops));
        let Ok(buf) = socket.send(data.len(), IpAddress::from(dst)) else {
            self.counters.would_block += 1;
            return Ok(Send::WouldBlock);
        };
        buf.copy_from_slice(data);
        buf[4..6].copy_from_slice(&ident.to_be_bytes());
        match src6 {
            None => Icmpv4Packet::new_unchecked(buf).fill_checksum(),
            Some((src, d)) => Icmpv6Packet::new_unchecked(buf).fill_checksum(&src, &d),
        }
        self.counters.requests += 1;
        Ok(Send::Queued)
    }

    /// `icmp-socket.receive`: the next echo reply for this socket, or `None` if there is none
    /// yet.
    pub fn receive(
        &mut self,
        id: SocketId,
        net: &mut Net<'_>,
    ) -> Result<Option<(Vec<u8>, IpAddr)>, SockError> {
        let entry = self.entry(id)?;
        let (Some(handle), Some(_)) = (entry.handle, entry.local) else {
            return Err(SockError::InvalidState);
        };
        let (family, remote) = (entry.family, entry.remote);
        let reply = match family {
            Family::Ipv4 => 0,
            Family::Ipv6 => 129,
        };
        let socket = net.sockets.get_mut::<icmp::Socket>(handle);
        while let Ok((payload, from)) = socket.recv() {
            let from = IpAddr::from(from);
            if Family::of(from) != family
                || payload.first() != Some(&reply)
                || payload.len() < 8
                || remote.is_some_and(|r| r != from)
            {
                self.counters.rx_filtered += 1;
                continue;
            }
            self.counters.replies += 1;
            return Ok(Some((payload.to_vec(), from)));
        }
        Ok(None)
    }

    /// An echo reply for `ident` from `from` arrived with `hop_limit`: remembered for
    /// `receive-datagram` if a socket holds `ident`.
    pub fn note_reply(&mut self, ident: u16, from: IpAddr, seq: u16, hop_limit: u8) {
        if !self.in_use(ident, None) {
            return;
        }
        if self.hops.len() >= HOPS {
            self.hops.pop_front();
        }
        self.hops.push_back((ident, from, seq, hop_limit));
    }

    /// `icmp-socket.receive-datagram`: [`receive`](Self::receive), plus the hop limit the reply
    /// arrived with (`None` if it was not seen, which only a burst of more than `HOPS` unread
    /// replies causes).
    pub fn receive_datagram(
        &mut self,
        id: SocketId,
        net: &mut Net<'_>,
    ) -> Result<Option<Datagram>, SockError> {
        let Some((data, from)) = self.receive(id, net)? else {
            return Ok(None);
        };
        let ident = self.identifier(id)?;
        let seq = u16::from_be_bytes([data[6], data[7]]);
        let hop = self
            .hops
            .iter()
            .position(|&(i, f, s, _)| (i, f, s) == (ident, from, seq))
            .and_then(|at| self.hops.remove(at))
            .map(|(.., h)| h);
        Ok(Some((data, from, hop)))
    }

    pub fn unicast_hop_limit(&self, id: SocketId, default: u8) -> Result<u8, SockError> {
        Ok(self.entry(id)?.hop_limit.unwrap_or(default))
    }

    pub fn set_unicast_hop_limit(&mut self, id: SocketId, value: u8) -> Result<(), SockError> {
        if value == 0 {
            return Err(SockError::InvalidArgument);
        }
        self.entry_mut(id)?.hop_limit = Some(value);
        Ok(())
    }

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

    /// An ICMP error about an echo request arrived: queue it for the socket that sent it, if
    /// that socket asked for errors. Returns whether a socket took it.
    pub fn icmp_error(&mut self, e: &IcmpError) -> bool {
        if e.proto != if e.v6 { 58 } else { 1 } {
            return false;
        }
        let family = if e.v6 { Family::Ipv6 } else { Family::Ipv4 };
        let Some(entry) = self.entries.values_mut().find(|en| {
            en.recv_errors
                && en.family == family
                && en.local.is_some_and(|(addr, ident)| {
                    ident == e.sport && (addr.is_unspecified() || addr == e.orig_src)
                })
        }) else {
            return false;
        };
        if entry.errors.len() >= ERROR_QUEUE {
            self.counters.errors_dropped += 1;
            return false;
        }
        entry.errors.push_back(*e);
        self.counters.errors_queued += 1;
        true
    }

    /// `icmp-socket.receive-error`: the oldest queued error, or `None` if there is none yet.
    pub fn take_error(&mut self, id: SocketId) -> Result<Option<IcmpError>, SockError> {
        let entry = self.entry_mut(id)?;
        if !entry.recv_errors {
            return Err(SockError::InvalidState);
        }
        Ok(entry.errors.pop_front())
    }

    /// The resource was dropped: requests still queued are discarded, the identifier is free.
    pub fn close(&mut self, id: SocketId, sockets: &mut SocketSet<'static>) {
        let Some(entry) = self.entries.remove(&id) else {
            return;
        };
        if let Some(handle) = entry.handle {
            sockets.remove(handle);
        }
        if let Some((_, ident)) = entry.local
            && !self.in_use(ident, None)
        {
            self.hops.retain(|&(i, ..)| i != ident);
        }
    }

    /// Every socket, for inspection. Queues are bytes in smoltcp's buffers.
    pub fn inspect(&self, sockets: &SocketSet<'static>) -> Vec<crate::debug::SockInfo> {
        self.entries
            .iter()
            .map(|(&id, e)| {
                let (rx, tx) = e.handle.map_or((0, 0), |h| {
                    let s = sockets.get::<icmp::Socket>(h);
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
                    // The identifier stands where a port would.
                    local: e.local.map(|(a, i)| std::net::SocketAddr::new(a, i)),
                    remote: e.remote.map(|a| std::net::SocketAddr::new(a, 0)),
                    state: state.to_owned(),
                    rx_queued: rx,
                    tx_queued: tx,
                }
            })
            .collect()
    }

    pub fn open(&self) -> usize {
        self.entries.len()
    }
}
