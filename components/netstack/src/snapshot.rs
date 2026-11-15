//! Quiescent snapshots of the stack: [`Stack::save`] and
//! [`Stack::restore`], behind `wasmnet:netstack/state`.
//!
//! Embedder surface, unstable: the interface, its state format and `snapshot.paused` may
//! change between versions without notice.
//!
//! A snapshot is only taken at a **quiescent** point: no TCP connection (only unbound, bound
//! and listening sockets with nothing queued), no UDP datagram or ICMP error waiting, no
//! lingering socket, no lookup in flight, no frame queued, no DHCP client and no ICMP echo socket.
//! Anything else is refused with the reason, and the stack is unchanged. At such a point the
//! state that differs from a fresh stack built from the same config is small: smoltcp's
//! interface state (its random generator, neighbor cache, multicast groups and report timers;
//! the `snapshot` patch of our vendored smoltcp), the sockets and the slots they occupy (smoltcp
//! polls sockets in slot order, so the order of frames depends on it), and our own tables,
//! counters and generators. A restore puts exactly that onto a fresh stack, so the restored
//! node sends the same frames at the same (device) instants as the saved one would have.
//!
//! The format is ours and versioned (`NSSTATE` + version), little-endian, every collection in
//! its in-memory order; the device's time base is the caller's (`component.rs` keeps the
//! shift between the host's clock and the device's).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use smoltcp::iface::{GroupPhase, IgmpReport, InterfaceState, MldReport};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, Ipv4Address, Ipv6Address};
use wasmnet_wire::MacAddr;

use crate::device::FrameCounters;
use crate::resolver::ResolverCounters;
use crate::stack::{Stack, StackCounters};
use crate::tcp::TcpCounters;
use crate::udp::UdpCounters;

const MAGIC: &[u8; 7] = b"NSSTATE";
/// 2: version 1 had a reserved `u32` after the ICMP sockets, always 0.
const VERSION: u8 = 2;

/// A snapshot writer: little-endian scalars, length-prefixed collections.
#[derive(Default)]
pub struct W(pub Vec<u8>);

impl W {
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn bool(&mut self, v: bool) {
        self.u8(u8::from(v));
    }
    pub fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i64(&mut self, v: i64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn count(&mut self, n: usize) {
        self.u32(n as u32);
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.count(b.len());
        self.0.extend_from_slice(b);
    }
    pub fn opt_u8(&mut self, v: Option<u8>) {
        self.bool(v.is_some());
        self.u8(v.unwrap_or(0));
    }
    pub fn opt_u64(&mut self, v: Option<u64>) {
        self.bool(v.is_some());
        self.u64(v.unwrap_or(0));
    }
    pub fn ip(&mut self, a: IpAddr) {
        match a {
            IpAddr::V4(a) => {
                self.u8(4);
                self.0.extend_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                self.u8(6);
                self.0.extend_from_slice(&a.octets());
            }
        }
    }
    pub fn sock(&mut self, a: Option<SocketAddr>) {
        self.bool(a.is_some());
        if let Some(a) = a {
            self.ip(a.ip());
            self.u16(a.port());
        }
    }
    pub fn instant(&mut self, t: Instant) {
        self.i64(t.total_micros());
    }
    pub fn mac(&mut self, m: MacAddr) {
        self.0.extend_from_slice(&m.octets());
    }
}

/// A snapshot reader; every malformed input is an error, never a panic.
pub struct R<'a> {
    b: &'a [u8],
    at: usize,
}

pub type Res<T> = Result<T, String>;

impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }
    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len());
        let end = end.ok_or_else(|| format!("snapshot truncated at byte {}", self.at))?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Res<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }
    pub fn u8(&mut self) -> Res<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn bool(&mut self) -> Res<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(format!("snapshot: bad bool {v}")),
        }
    }
    pub fn u16(&mut self) -> Res<u16> {
        Ok(u16::from_le_bytes(self.arr()?))
    }
    pub fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    pub fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    pub fn i64(&mut self) -> Res<i64> {
        Ok(i64::from_le_bytes(self.arr()?))
    }
    pub fn count(&mut self) -> Res<usize> {
        let n = self.u32()? as usize;
        // Every element takes at least a byte: a bound that never trusts a corrupt length.
        if n > self.b.len() - self.at {
            return Err(format!("snapshot: length {n} past the end"));
        }
        Ok(n)
    }
    pub fn bytes(&mut self) -> Res<Vec<u8>> {
        let n = self.count()?;
        Ok(self.take(n)?.to_vec())
    }
    pub fn opt_u8(&mut self) -> Res<Option<u8>> {
        let some = self.bool()?;
        let v = self.u8()?;
        Ok(some.then_some(v))
    }
    pub fn opt_u64(&mut self) -> Res<Option<u64>> {
        let some = self.bool()?;
        let v = self.u64()?;
        Ok(some.then_some(v))
    }
    pub fn ip(&mut self) -> Res<IpAddr> {
        match self.u8()? {
            4 => Ok(IpAddr::V4(Ipv4Addr::from(self.arr::<4>()?))),
            6 => Ok(IpAddr::V6(Ipv6Addr::from(self.arr::<16>()?))),
            v => Err(format!("snapshot: bad address family {v}")),
        }
    }
    pub fn sock(&mut self) -> Res<Option<SocketAddr>> {
        Ok(if self.bool()? {
            Some(SocketAddr::new(self.ip()?, self.u16()?))
        } else {
            None
        })
    }
    pub fn instant(&mut self) -> Res<Instant> {
        Ok(Instant::from_micros(self.i64()?))
    }
    pub fn mac(&mut self) -> Res<MacAddr> {
        Ok(MacAddr(self.arr::<6>()?))
    }
    pub fn end(&self) -> Res<()> {
        if self.at == self.b.len() {
            Ok(())
        } else {
            Err(format!(
                "snapshot: {} bytes left over",
                self.b.len() - self.at
            ))
        }
    }
}

/// Counters are plain `u64` fields, written in declaration order. The struct literal lists
/// every field, so a new counter fails to compile here until it is saved too.
pub trait Counters: Sized {
    fn put(&self, w: &mut W);
    fn get(r: &mut R<'_>) -> Res<Self>;
}

macro_rules! counters {
    ($t:ty { $($f:ident),* $(,)? }) => {
        impl Counters for $t {
            fn put(&self, w: &mut W) {
                $(w.u64(self.$f);)*
            }
            fn get(r: &mut R<'_>) -> Res<Self> {
                Ok(Self { $($f: r.u64()?,)* })
            }
        }
    };
}

counters!(StackCounters {
    polls,
    passes,
    iface_polls,
    stale_poll_at,
    arp_resolved,
    ndp_resolved,
    multicast_queries,
    icmp_errors_received,
    multicast_joins,
    multicast_leaves,
});
counters!(FrameCounters {
    rx_frames,
    rx_bytes,
    tx_frames,
    tx_bytes,
    tx_padded,
});
counters!(ResolverCounters {
    lookups,
    queries,
    responses,
    timeouts,
    icmp_errors,
    resolved,
    failed,
    ignored,
});
counters!(UdpCounters {
    sockets,
    binds,
    tx_datagrams,
    tx_bytes,
    rx_datagrams,
    rx_bytes,
    rx_filtered,
    would_block,
    linger_expired,
    icmp_errors,
    icmp_errors_dropped,
    hop_limit_waits,
    multicast_looped,
});
counters!(TcpCounters {
    sockets,
    connects,
    connected,
    connect_failed,
    connect_unreachable,
    listens,
    accepted,
    backlog_peak,
    tx_bytes,
    rx_bytes,
    rx_discarded,
    fins,
    eofs,
    resets,
    aborts,
    send_waits,
    rx_window_full,
    orphans_reaped,
});

fn smol_ip(a: IpAddress) -> IpAddr {
    IpAddr::from(a)
}

fn put_iface(w: &mut W, s: &InterfaceState) -> Res<()> {
    w.u64(s.rand);
    w.bool(s.ipv4_id.is_some());
    w.u16(s.ipv4_id.unwrap_or(0));
    w.count(s.neighbors.len());
    for (a, hw, t) in &s.neighbors {
        w.ip(smol_ip(*a));
        match hw {
            HardwareAddress::Ethernet(e) => w.0.extend_from_slice(&e.0),
            #[allow(unreachable_patterns)]
            _ => return Err("a neighbor that is not on Ethernet".into()),
        }
        w.instant(*t);
    }
    w.count(s.silent_until.len());
    for (a, t) in &s.silent_until {
        w.ip(smol_ip(*a));
        w.instant(*t);
    }
    w.count(s.groups.len());
    for (a, p) in &s.groups {
        w.ip(smol_ip(*a));
        w.u8(match p {
            GroupPhase::Joining => 0,
            GroupPhase::Joined => 1,
            GroupPhase::Leaving => 2,
        });
    }
    match s.igmp {
        IgmpReport::Inactive => w.u8(0),
        IgmpReport::ToGeneralQuery {
            v1,
            timeout,
            interval,
            next_index,
        } => {
            w.u8(1);
            w.bool(v1);
            w.instant(timeout);
            w.u64(interval.total_micros());
            w.u64(next_index as u64);
        }
        IgmpReport::ToSpecificQuery { v1, timeout, group } => {
            w.u8(2);
            w.bool(v1);
            w.instant(timeout);
            w.ip(IpAddr::V4(group));
        }
    }
    match s.mld {
        MldReport::Inactive => w.u8(0),
        MldReport::ToGeneralQuery { timeout } => {
            w.u8(1);
            w.instant(timeout);
        }
        MldReport::ToSpecificQuery { group, timeout } => {
            w.u8(2);
            w.ip(IpAddr::V6(group));
            w.instant(timeout);
        }
    }
    Ok(())
}

fn v4(a: IpAddr) -> Res<Ipv4Address> {
    match a {
        IpAddr::V4(a) => Ok(a),
        _ => Err("snapshot: expected an IPv4 address".into()),
    }
}

fn v6(a: IpAddr) -> Res<Ipv6Address> {
    match a {
        IpAddr::V6(a) => Ok(a),
        _ => Err("snapshot: expected an IPv6 address".into()),
    }
}

fn get_iface(r: &mut R<'_>) -> Res<InterfaceState> {
    let rand = r.u64()?;
    let has_id = r.bool()?;
    let id = r.u16()?;
    let mut neighbors = Vec::new();
    for _ in 0..r.count()? {
        let a = IpAddress::from(r.ip()?);
        let hw = HardwareAddress::Ethernet(EthernetAddress(r.arr::<6>()?));
        neighbors.push((a, hw, r.instant()?));
    }
    let mut silent_until = Vec::new();
    for _ in 0..r.count()? {
        silent_until.push((IpAddress::from(r.ip()?), r.instant()?));
    }
    let mut groups = Vec::new();
    for _ in 0..r.count()? {
        let a = IpAddress::from(r.ip()?);
        let p = match r.u8()? {
            0 => GroupPhase::Joining,
            1 => GroupPhase::Joined,
            2 => GroupPhase::Leaving,
            v => return Err(format!("snapshot: bad group state {v}")),
        };
        groups.push((a, p));
    }
    let igmp = match r.u8()? {
        0 => IgmpReport::Inactive,
        1 => IgmpReport::ToGeneralQuery {
            v1: r.bool()?,
            timeout: r.instant()?,
            interval: Duration::from_micros(r.u64()?),
            next_index: r.u64()? as usize,
        },
        2 => IgmpReport::ToSpecificQuery {
            v1: r.bool()?,
            timeout: r.instant()?,
            group: v4(r.ip()?)?,
        },
        v => return Err(format!("snapshot: bad IGMP state {v}")),
    };
    let mld = match r.u8()? {
        0 => MldReport::Inactive,
        1 => MldReport::ToGeneralQuery {
            timeout: r.instant()?,
        },
        2 => MldReport::ToSpecificQuery {
            group: v6(r.ip()?)?,
            timeout: r.instant()?,
        },
        v => return Err(format!("snapshot: bad MLD state {v}")),
    };
    Ok(InterfaceState {
        rand,
        ipv4_id: has_id.then_some(id),
        neighbors,
        silent_until,
        groups,
        igmp,
        mld,
    })
}

fn put_times<K: Copy>(w: &mut W, m: &BTreeMap<K, u64>, ip: impl Fn(K) -> IpAddr) {
    w.count(m.len());
    for (k, t) in m {
        w.ip(ip(*k));
        w.u64(*t);
    }
}

impl Stack {
    /// The stack's state, if it is quiescent (the module docs); otherwise why not.
    pub fn save(&self) -> Res<Vec<u8>> {
        self.quiescent()?;
        let mut w = W::default();
        w.0.extend_from_slice(MAGIC);
        w.u8(VERSION);
        // What the restoring stack must have been built from (the same config).
        w.mac(self.mac);
        let addrs: Vec<String> = self
            .iface
            .ip_addrs()
            .iter()
            .map(|c| c.to_string())
            .collect();
        w.bytes(addrs.join(",").as_bytes());
        put_iface(&mut w, &self.iface.snapshot_state())?;
        put_times(&mut w, &self.arp_pending, IpAddr::V4);
        put_times(&mut w, &self.nd_pending, IpAddr::V6);
        let (due, window) = self.mcast.parts();
        w.opt_u64(due);
        w.opt_u64(window.map(|w| w.0));
        w.opt_u64(window.map(|w| w.1));
        w.bool(self.carrier);
        w.count(self.joined.len());
        for a in &self.joined {
            w.ip(*a);
        }
        w.count(self.neighbors.len());
        for (a, (m, t)) in &self.neighbors {
            w.ip(*a);
            w.mac(*m);
            w.u64(*t);
        }
        self.icmp.snapshot_save(&mut w)?;
        self.counters.put(&mut w);
        self.dev.counters.put(&mut w);
        self.resolver.snapshot_save(&mut w);
        self.udp.snapshot_save(&mut w, &self.sockets)?;
        self.tcp.snapshot_save(&mut w, &self.sockets)?;
        Ok(w.0)
    }

    /// Puts a saved state onto this stack, which must be fresh and built from the same config
    /// (the same MAC and addresses): no app socket yet. On an error the stack must be dropped.
    pub fn restore(&mut self, bytes: &[u8]) -> Res<()> {
        let mut r = R::new(bytes);
        if r.take(MAGIC.len())? != MAGIC {
            return Err("not a netstack state".into());
        }
        let version = r.u8()?;
        if version != VERSION {
            return Err(format!(
                "netstack state version {version}, expected {VERSION}"
            ));
        }
        let mac = r.mac()?;
        if mac != self.mac {
            return Err(format!(
                "the state is of MAC {mac}, this node is {}",
                self.mac
            ));
        }
        let addrs = String::from_utf8(r.bytes()?).map_err(|e| e.to_string())?;
        let ours: Vec<String> = self
            .iface
            .ip_addrs()
            .iter()
            .map(|c| c.to_string())
            .collect();
        if addrs != ours.join(",") {
            return Err(format!(
                "the state is of addresses {addrs}, this node has {}",
                ours.join(",")
            ));
        }
        if self.sockets.iter().next().is_some()
            || !self.udp.is_empty()
            || !self.tcp.is_empty()
            || !self.icmp.is_empty()
        {
            return Err("a netstack state restores onto a fresh stack only".into());
        }
        let iface = get_iface(&mut r)?;
        self.iface.restore_state(&iface)?;
        let mut arp = BTreeMap::new();
        for _ in 0..r.count()? {
            arp.insert(v4(r.ip()?)?, r.u64()?);
        }
        let mut nd = BTreeMap::new();
        for _ in 0..r.count()? {
            nd.insert(v6(r.ip()?)?, r.u64()?);
        }
        self.arp_pending = arp;
        self.nd_pending = nd;
        let due = r.opt_u64()?;
        let from = r.opt_u64()?;
        let end = r.opt_u64()?;
        self.mcast = crate::mcast::MulticastDeadline::from_parts(due, from.zip(end));
        self.carrier = r.bool()?;
        let mut joined = BTreeSet::new();
        for _ in 0..r.count()? {
            joined.insert(r.ip()?);
        }
        self.joined = joined;
        let mut neighbors = BTreeMap::new();
        for _ in 0..r.count()? {
            let a = r.ip()?;
            neighbors.insert(a, (r.mac()?, r.u64()?));
        }
        self.neighbors = neighbors;
        self.icmp.snapshot_restore(&mut r)?;
        self.counters = StackCounters::get(&mut r)?;
        self.dev.counters = FrameCounters::get(&mut r)?;
        self.resolver.snapshot_restore(&mut r)?;
        let hops = self.hop_limit;
        self.udp.snapshot_restore(&mut r, &mut self.sockets, hops)?;
        self.tcp.snapshot_restore(&mut r, &mut self.sockets, hops)?;
        r.end()
    }

    /// `Ok` when the stack is at a quiescent point; otherwise the first reason it is not.
    fn quiescent(&self) -> Res<()> {
        if !self.rx_seen.is_empty() || !self.dev.rx.is_empty() || !self.dev.tx.is_empty() {
            return Err("frames are queued".into());
        }
        if self.dhcp.is_some() {
            return Err("a DHCP client runs (quiescent snapshots need static addresses)".into());
        }
        if self.resolver.in_flight() > 0 {
            return Err("a name lookup is in flight".into());
        }
        Ok(())
    }
}
