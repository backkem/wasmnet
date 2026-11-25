//! The stack: a smoltcp `Interface` over the [`QueueDevice`], its sockets (the apps' ICMP, UDP and TCP
//! sockets), the multicast deadline and the resolution trackers. Pure logic: the
//! driver task in `component.rs` owns the only instance and calls [`Stack::poll`] and
//! [`Stack::next_wakeup`].
//!
//! Every input is explicit: `now` in virtual nanoseconds, frames, the MAC and the random seeds.
//! Nothing here reads a clock or an RNG, so the same inputs always give the same frames.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, SocketSet};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use wasmnet_wire::MacAddr;

use crate::config::{Config, eui64_link_local};
use crate::device::QueueDevice;
use crate::dhcp::DhcpClient;
use crate::icmp::IcmpSockets;
use crate::mcast::MulticastDeadline;
use crate::names::{self, LookupError};
use crate::observe::{Observed, observe};
use crate::resolver::{LookupId, Resolver, Start};
use crate::tcp::{TcpNet, TcpSockets};
use crate::time::{deadline_ns, to_smol};
use crate::udp::{Family, Net, UdpSockets};
use crate::{Event, Level, Note, Output};

/// Most smoltcp passes in one `poll` before it yields to the driver (which then re-polls at the
/// same instant). A pass that keeps making progress this long is a bug, but must not hang.
const MAX_PASSES: u32 = 64;
/// Guard against a stale `poll_at` (at or before now after a pass that made no progress): wait
/// one virtual microsecond instead of spinning (never seen to happen).
const STALE_GUARD_NS: u64 = 1_000;

/// Stack-level counters (the `counters` export adds the frame and driver counters).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackCounters {
    pub polls: u64,
    pub passes: u64,
    pub iface_polls: u64,
    pub stale_poll_at: u64,
    pub arp_resolved: u64,
    pub ndp_resolved: u64,
    pub multicast_queries: u64,
    /// ICMP errors addressed to us.
    pub icmp_errors_received: u64,
    /// Groups the interface joined and left for the apps.
    pub multicast_joins: u64,
    pub multicast_leaves: u64,
}

/// One network interface (`eth0`) and everything above it.
pub struct Stack {
    pub(crate) iface: Interface,
    pub(crate) dev: QueueDevice,
    pub(crate) sockets: SocketSet<'static>,
    pub(crate) mac: MacAddr,
    pub(crate) ipv4: Option<Ipv4Addr>,
    pub(crate) ipv6: Vec<Ipv6Addr>,
    pub(crate) mtu: u16,
    /// Frames received since the last poll, classified when they arrived.
    pub(crate) rx_seen: Vec<Observed>,
    /// Neighbors we asked for, and when we first asked.
    pub(crate) arp_pending: BTreeMap<Ipv4Addr, u64>,
    pub(crate) nd_pending: BTreeMap<Ipv6Addr, u64>,
    pub(crate) mcast: MulticastDeadline,
    pub(crate) carrier: bool,
    /// The apps' UDP sockets.
    pub(crate) udp: UdpSockets,
    /// The apps' TCP sockets.
    pub(crate) tcp: TcpSockets,
    pub(crate) hosts: BTreeMap<String, Vec<IpAddr>>,
    pub(crate) hop_limit: u8,
    pub(crate) gateway_v4: bool,
    pub(crate) gateway_v6: bool,
    /// The DHCPv4 client, with `ipv4 = "dhcp"`.
    pub(crate) dhcp: Option<DhcpClient>,
    /// The stub resolver behind `ip-name-lookup` and its static servers (`dns`).
    pub(crate) resolver: Resolver,
    pub(crate) dns_static: Vec<IpAddr>,
    /// A global IPv6 address is configured (the resolver then asks for AAAA too).
    pub(crate) ipv6_global: bool,
    /// The node's multicast hop limit, and the groups the interface joined for the apps.
    pub(crate) multicast_hop_limit: u8,
    pub(crate) joined: std::collections::BTreeSet<IpAddr>,
    /// Neighbors learned from ARP packets addressed to us and neighbor adverts, with the virtual
    /// time each was last seen: what inspection reports (smoltcp's cache is not enumerable).
    pub(crate) neighbors: BTreeMap<IpAddr, (MacAddr, u64)>,
    /// Entries evicted from `neighbors`, `arp_pending` and `nd_pending` to keep each at most
    /// [`MAX_TABLE`] (counter `neighbors-evicted`). Not part of a snapshot: a restored stack
    /// counts from 0.
    pub(crate) neighbor_evictions: u64,
    /// The apps' ICMP echo sockets, and the echo identifier rover.
    pub(crate) icmp: IcmpSockets,
    pub counters: StackCounters,
}

/// The most entries each of the stack's own neighbor tables (`neighbors`, `arp_pending`,
/// `nd_pending`) holds: they fill from the wire. A new entry in a full table evicts the oldest
/// (by its time; ties in address order).
pub const MAX_TABLE: usize = 1024;

/// Makes room for a new `key` in `map` (at most [`MAX_TABLE`] entries) by evicting the entry
/// whose `time` is the oldest. Returns whether it evicted one.
fn make_room<K: Ord + Copy, V>(
    map: &mut BTreeMap<K, V>,
    key: &K,
    time: impl Fn(&V) -> u64,
) -> bool {
    if map.len() < MAX_TABLE || map.contains_key(key) {
        return false;
    }
    let oldest = map
        .iter()
        .min_by_key(|(k, v)| (time(v), **k))
        .map(|(k, _)| *k);
    oldest.and_then(|k| map.remove(&k)).is_some()
}

/// The resolver's seed, derived from smoltcp's (no extra `wasi:random` draw, so every other
/// draw of the node keeps its value).
fn resolver_seed(random_seed: u64) -> u64 {
    random_seed ^ 0x7265_736f_6c76_6572 // "resolver"
}

impl Stack {
    /// Builds the interface at virtual time `now`.
    ///
    /// * `mac`: the port's MAC (configured, or derived from the seeded RNG by the caller).
    /// * `random_seed`: smoltcp's only entropy (IPv4 identification, TCP ISNs, MLD delays).
    /// * `ident_seed`: the first echo identifier the ICMP sockets pick (then counting up; zero is
    ///   skipped), the analogue of a process id.
    pub fn new(config: &Config, mac: MacAddr, random_seed: u64, ident_seed: u16, now: u64) -> Self {
        let mut dev = QueueDevice::new(usize::from(config.mtu));
        let mut icfg = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(mac.octets())));
        icfg.random_seed = random_seed;
        let mut iface = Interface::new(icfg, &mut dev, to_smol(now));

        let link_local = config
            .ipv6_link_local
            .unwrap_or_else(|| eui64_link_local(mac));
        let mut ipv6 = vec![link_local];
        ipv6.extend(config.ipv6.map(|c| c.addr));
        iface.update_ip_addrs(|addrs| {
            // At most three addresses; the feature `iface-max-addr-count-4` leaves room.
            if let Some(v4) = config.ipv4 {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(v4.addr), v4.prefix));
            }
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(link_local), 64));
            if let Some(v6) = config.ipv6 {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(v6.addr), v6.prefix));
            }
        });
        if let Some(gw) = config.ipv4_gateway {
            let _ = iface.routes_mut().add_default_ipv4_route(gw);
        }
        if let Some(gw) = config.ipv6_gateway {
            let _ = iface.routes_mut().add_default_ipv6_route(gw);
        }

        let mut mcast = MulticastDeadline::default();
        // Setting the addresses joined the IPv6 solicited-node groups: their MLD reports are due.
        mcast.control_changed(now);
        let mut sockets = SocketSet::new(Vec::new());
        let dhcp = config
            .dhcp
            .then(|| DhcpClient::new(&mut sockets, config.hostname.as_deref(), now));
        Self {
            iface,
            dev,
            sockets,
            mac,
            ipv4: config.ipv4.map(|c| c.addr),
            ipv6,
            mtu: config.mtu,
            rx_seen: Vec::new(),
            arp_pending: BTreeMap::new(),
            nd_pending: BTreeMap::new(),
            mcast,
            carrier: false,
            udp: UdpSockets::default(),
            tcp: TcpSockets::new(config.tcp_congestion),
            hosts: config.hosts.clone(),
            hop_limit: config.hop_limit,
            gateway_v4: config.ipv4_gateway.is_some(),
            gateway_v6: config.ipv6_gateway.is_some(),
            dhcp,
            resolver: {
                let mut r = Resolver::new(
                    resolver_seed(random_seed),
                    config.resolver_timeout_ns,
                    config.resolver_attempts,
                );
                r.mdns_timeout_ns = config.mdns_timeout_ns;
                r.mdns_attempts = config.mdns_attempts;
                r
            },
            dns_static: config.dns.clone(),
            ipv6_global: config.ipv6.is_some(),
            multicast_hop_limit: config.multicast_hop_limit,
            joined: std::collections::BTreeSet::new(),
            neighbors: BTreeMap::new(),
            neighbor_evictions: 0,
            icmp: IcmpSockets::new(ident_seed),
            counters: StackCounters::default(),
        }
    }

    /// The resolver is configured: static DNS servers, or a DHCP client that may lease some.
    fn resolver_on(&self) -> bool {
        !self.dns_static.is_empty() || self.dhcp.is_some()
    }

    /// The DNS servers in use: the static ones, else the lease's.
    pub fn dns_servers(&self) -> Vec<IpAddr> {
        if !self.dns_static.is_empty() {
            return self.dns_static.clone();
        }
        self.dhcp.as_ref().map(DhcpClient::dns).unwrap_or_default()
    }

    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    /// One line for the log: MAC, MTU and addresses.
    pub fn describe(&self) -> String {
        let mut s = format!("netstack eth0: mac {} mtu {}", self.mac, self.mtu);
        for cidr in self.iface.ip_addrs() {
            s.push_str(&format!(" {cidr}"));
        }
        if self.dhcp.is_some() {
            s.push_str(" ipv4 dhcp");
        }
        if !self.dns_static.is_empty() {
            let dns: Vec<String> = self.dns_static.iter().map(IpAddr::to_string).collect();
            s.push_str(&format!(" dns {}", dns.join(",")));
        }
        s
    }

    /// Queues a frame that arrived on `eth0`. Only enqueues: the next [`poll`](Self::poll)
    /// processes it.
    pub fn receive(&mut self, frame: Vec<u8>) {
        let mut seen = observe(&frame);
        // An ICMP error counts only in a frame our NIC accepts (ours, broadcast or multicast),
        // as smoltcp would: a switch flooding another host's frame must not fail our connect.
        if let Observed::IcmpError(_) = seen {
            let dst = frame.get(..6).and_then(MacAddr::from_slice);
            if !dst.is_some_and(|d| d == self.mac || d.is_multicast()) {
                seen = Observed::Other;
            }
        }
        self.rx_seen.push(seen);
        self.dev.push_rx(frame);
    }

    /// Records a carrier change. smoltcp has no notion of carrier; the host drops frames sent on
    /// a down link.
    pub fn link_state(&mut self, up: bool) {
        self.carrier = up;
    }

    pub fn carrier(&self) -> bool {
        self.carrier
    }

    /// Runs the stack at `now` until it makes no more progress: DHCP and resolver timers, smoltcp
    /// ingress/egress, replies, the TCP table's bookkeeping. Returns the frames to transmit and
    /// the diagnostics, in order, and whether anything happened at all ([`Output::active`]: the
    /// driver's TCP pumps then look at their sockets again).
    pub fn poll(&mut self, now: u64) -> Output {
        self.counters.polls += 1;
        let mut out = Output::default();
        for _ in 0..MAX_PASSES {
            self.counters.passes += 1;
            if !self.rx_seen.is_empty() {
                out.active = true;
            }
            for seen in std::mem::take(&mut self.rx_seen) {
                self.on_rx(now, seen, &mut out);
            }
            let mut progressed = false;
            // Before the poll, so a socket that gave up does not ask for its neighbor again.
            self.udp.reap(now, &mut self.sockets);
            // Group memberships the apps' sockets want: join or leave at this pass, so the
            // IGMP/MLD report leaves at the instant of the call.
            progressed |= self.sync_groups(now, &mut out);
            self.counters.iface_polls += 1;
            let result = self
                .iface
                .poll(to_smol(now), &mut self.dev, &mut self.sockets);
            self.mcast.polled(now);
            let frames = self.dev.take_tx();
            for frame in &frames {
                self.on_tx(now, observe(frame), &mut out);
            }
            // Multicast loopback: a copy of a datagram to a group this node has joined goes
            // back up the stack, never onto the wire.
            for frame in &frames {
                self.loop_back(frame);
            }
            let sent = !frames.is_empty();
            out.frames.extend(frames);
            // A DHCP lease bound, renewed or lost: apply it before anything else looks at
            // the addresses.
            if let Some(dhcp) = &mut self.dhcp
                && dhcp.poll(now, &mut self.iface, &mut self.sockets, &mut out)
            {
                progressed = true;
                self.ipv4 = dhcp.lease().map(|l| l.address);
                self.gateway_v4 = dhcp.lease().is_some_and(|l| l.router.is_some());
            }
            self.udp.reap(now, &mut self.sockets);
            // Ports bound by both families: hand each datagram to its family's socket (#7).
            out.active |= self.udp.demux(&mut self.sockets);
            // The resolver reads its answers and sends due queries. A query it queued
            // leaves at the next pass, at this instant.
            if self.resolver.in_flight() > 0 {
                let mut net = Net {
                    iface: &self.iface,
                    sockets: &mut self.sockets,
                    mtu: self.mtu,
                    hop_limit: self.hop_limit,
                    multicast_hop_limit: self.multicast_hop_limit,
                    gateway_v4: self.gateway_v4,
                    gateway_v6: self.gateway_v6,
                };
                progressed |= self.resolver.poll(now, &mut self.udp, &mut net, &mut out);
            }
            progressed |= self.tcp.after_poll(now, self.hop_limit, &mut self.sockets);
            let changed = result == PollResult::SocketStateChanged;
            out.active |= changed || sent || progressed;
            let more = !self.rx_seen.is_empty() || !self.dev.rx.is_empty();
            if !(changed || sent || progressed || more) {
                break;
            }
        }
        out
    }

    /// When the driver must poll next: the earliest of smoltcp's `poll_at`, the sockets' timers
    /// and the multicast deadline, or `None` when only a new frame can create work. Never at
    /// or before `now` (see `STALE_GUARD_NS`).
    pub fn next_wakeup(&mut self, now: u64) -> Option<u64> {
        let smol = self
            .iface
            .poll_at(to_smol(now), &self.sockets)
            .map(|t| deadline_ns(t, now));
        let next = smol
            .into_iter()
            .chain(self.mcast.next(now))
            .chain(self.udp.next_deadline())
            .chain(self.tcp.next_deadline())
            .chain(self.resolver.next_deadline())
            .min()?;
        if next <= now {
            self.counters.stale_poll_at += 1;
            return Some(now + STALE_GUARD_NS);
        }
        Some(next)
    }

    fn on_rx(&mut self, now: u64, seen: Observed, out: &mut Output) {
        match seen {
            Observed::Arp {
                sender_mac,
                sender_ip,
                target_ip,
                ..
            } if Some(target_ip) == self.ipv4 => {
                if !sender_ip.is_unspecified() {
                    self.learn_neighbor(IpAddr::V4(sender_ip), sender_mac, now);
                }
                if let Some(asked) = self.arp_pending.remove(&sender_ip) {
                    self.counters.arp_resolved += 1;
                    out.event(Event::new(
                        "arp-resolved",
                        &[
                            ("ip", sender_ip.to_string()),
                            ("mac", sender_mac.to_string()),
                            ("after-ns", (now - asked).to_string()),
                        ],
                    ));
                }
            }
            Observed::NeighborAdvert { target, mac } => {
                self.learn_neighbor(IpAddr::V6(target), mac, now);
                if let Some(asked) = self.nd_pending.remove(&target) {
                    self.counters.ndp_resolved += 1;
                    out.event(Event::new(
                        "ndp-resolved",
                        &[
                            ("ip", target.to_string()),
                            ("mac", mac.to_string()),
                            ("after-ns", (now - asked).to_string()),
                        ],
                    ));
                }
            }
            Observed::IcmpError(e) if self.iface.has_ip_addr(IpAddress::from(e.to)) => {
                self.counters.icmp_errors_received += 1;
                let lowered = self.tcp.path_mtu(&e, self.mtu, &mut self.sockets);
                let effect = if lowered.is_some() {
                    "path-mtu-lowered"
                } else if self.tcp.icmp_error(&e, &self.sockets) {
                    "connect-failed"
                } else if self.udp.icmp_error(&e) || self.icmp.icmp_error(&e) {
                    "queued"
                } else {
                    "none"
                };
                let about = match (e.orig_dst, e.proto) {
                    (IpAddr::V6(a), 6 | 17) => format!("[{a}]:{}", e.dport),
                    (a, 6 | 17) => format!("{a}:{}", e.dport),
                    (a, _) => a.to_string(),
                };
                let proto = match e.proto {
                    1 => "icmp".to_owned(),
                    6 => "tcp".to_owned(),
                    17 => "udp".to_owned(),
                    58 => "icmpv6".to_owned(),
                    n => n.to_string(),
                };
                out.event(Event::new(
                    "icmp-error-received",
                    &[
                        ("from", e.from.to_string()),
                        ("error", e.name().to_owned()),
                        ("icmp-type", e.icmp_type.to_string()),
                        ("icmp-code", e.code.to_string()),
                        ("proto", proto),
                        ("about", about),
                        ("local-port", e.sport.to_string()),
                        ("effect", effect.to_owned()),
                    ],
                ));
                if let Some(p) = lowered {
                    out.event(Event::new(
                        "path-mtu-lowered",
                        &[
                            ("peer", p.peer.to_string()),
                            ("local-port", p.local_port.to_string()),
                            ("mtu", p.mtu.to_string()),
                            ("mss", p.mss.to_string()),
                        ],
                    ));
                }
            }
            // An echo reply to one of our ICMP sockets: its hop limit, for `receive-datagram`
            // (smoltcp's ICMP socket keeps only the payload and the source).
            Observed::Echo {
                reply: true,
                src,
                ident,
                seq,
                hop_limit,
                ..
            } => self.icmp.note_reply(ident, src, seq, hop_limit),
            Observed::MulticastQuery { max_resp_ns } => {
                self.counters.multicast_queries += 1;
                self.mcast.query(now, max_resp_ns);
                out.log(
                    Level::Debug,
                    format!("multicast query, max response {max_resp_ns}ns"),
                );
            }
            _ => {}
        }
    }

    fn on_tx(&mut self, now: u64, sent: Observed, _out: &mut Output) {
        match sent {
            Observed::Arp {
                reply: false,
                target_ip,
                ..
            } => {
                if make_room(&mut self.arp_pending, &target_ip, |t| *t) {
                    self.neighbor_evictions += 1;
                }
                self.arp_pending.entry(target_ip).or_insert(now);
            }
            Observed::NeighborSolicit { target } if !self.ipv6.contains(&target) => {
                if make_room(&mut self.nd_pending, &target, |t| *t) {
                    self.neighbor_evictions += 1;
                }
                self.nd_pending.entry(target).or_insert(now);
            }
            _ => {}
        }
    }

    /// Records that `ip` is at `mac`, seen at `now` (bounded: [`MAX_TABLE`]).
    fn learn_neighbor(&mut self, ip: IpAddr, mac: MacAddr, now: u64) {
        if make_room(&mut self.neighbors, &ip, |(_, t)| *t) {
            self.neighbor_evictions += 1;
        }
        self.neighbors.insert(ip, (mac, now));
    }

    /// Joins and leaves the groups the apps' sockets want. Returns whether it changed any.
    fn sync_groups(&mut self, now: u64, out: &mut Output) -> bool {
        let wanted = self.udp.groups();
        if wanted == self.joined {
            return false;
        }
        for &group in wanted.difference(&self.joined) {
            match self.iface.join_multicast_group(IpAddress::from(group)) {
                Ok(()) => {
                    self.counters.multicast_joins += 1;
                    out.event(Event::new(
                        "multicast-joined",
                        &[("group", group.to_string())],
                    ));
                }
                Err(e) => out.log(Level::Warn, format!("join {group}: {e}")),
            }
        }
        for &group in self.joined.difference(&wanted) {
            let _ = self.iface.leave_multicast_group(IpAddress::from(group));
            self.counters.multicast_leaves += 1;
            out.event(Event::new(
                "multicast-left",
                &[("group", group.to_string())],
            ));
        }
        self.joined = wanted;
        self.mcast.control_changed(now);
        true
    }

    /// Multicast loopback: a UDP datagram this node sent to a group it joined, from a
    /// socket that keeps `multicast-loopback` on, is queued to be received by the node too.
    fn loop_back(&mut self, frame: &[u8]) {
        let Some((family, group, sport)) = udp_to_group(frame) else {
            return;
        };
        if self.iface.has_multicast_group(IpAddress::from(group))
            && self.udp.loops_back(family, sport)
        {
            self.dev.push_loopback(frame.to_vec());
        }
    }

    /// `wasmnet:sockets-ext/interfaces.list-interfaces`: the one interface, `eth0`.
    pub fn interface(&self) -> InterfaceInfo {
        InterfaceInfo {
            index: crate::udp::INTERFACES,
            name: "eth0".to_owned(),
            mac: self.mac,
            addresses: self
                .iface
                .ip_addrs()
                .iter()
                .map(|c| (IpAddr::from(c.address()), c.prefix_len()))
                .collect(),
            mtu: self.mtu,
            up: self.carrier,
        }
    }

    /// The apps' UDP sockets, with the parts of the stack they need for one call. The caller
    /// holds the stack borrowed for the call's duration, so it must not call any import.
    pub fn udp(&mut self) -> (&mut UdpSockets, Net<'_>) {
        let net = Net {
            iface: &self.iface,
            sockets: &mut self.sockets,
            mtu: self.mtu,
            hop_limit: self.hop_limit,
            multicast_hop_limit: self.multicast_hop_limit,
            gateway_v4: self.gateway_v4,
            gateway_v6: self.gateway_v6,
        };
        (&mut self.udp, net)
    }

    /// The apps' ICMP echo sockets, with the parts of the stack they need for one call.
    /// The caller holds the stack borrowed for the call's duration, so it must not call any
    /// import.
    pub fn icmp(&mut self) -> (&mut IcmpSockets, Net<'_>) {
        let net = Net {
            iface: &self.iface,
            sockets: &mut self.sockets,
            mtu: self.mtu,
            hop_limit: self.hop_limit,
            multicast_hop_limit: self.multicast_hop_limit,
            gateway_v4: self.gateway_v4,
            gateway_v6: self.gateway_v6,
        };
        (&mut self.icmp, net)
    }

    /// The apps' TCP sockets, with the parts of the stack they need for one call. The caller
    /// holds the stack borrowed for the call's duration, so it must not call any import.
    pub fn tcp(&mut self) -> (&mut TcpSockets, TcpNet<'_>) {
        let net = TcpNet {
            iface: &mut self.iface,
            sockets: &mut self.sockets,
            hop_limit: self.hop_limit,
            gateway_v4: self.gateway_v4,
            gateway_v6: self.gateway_v6,
        };
        (&mut self.tcp, net)
    }

    /// The node's default unicast hop limit.
    pub fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    /// `ip-name-lookup.resolve-addresses`: literals and the `hosts.<name>` table answer at once;
    /// any other name goes to DNS when the node has servers. A single-label name gets the
    /// lease's domain appended first (a `search` domain). The notes are for the caller to emit.
    pub fn lookup_start(&mut self, name: &str, now: u64) -> (Start, Vec<Note>) {
        let mut out = Output::default();
        let start = match names::resolve(&self.hosts, name) {
            // `.local`: a one-shot multicast DNS query (RFC 6762 §5.1), DNS servers or not.
            Err(LookupError::NameUnresolvable) if is_local(name) => {
                let v4 = self.ipv4.is_some();
                self.resolver
                    .start(name, now, &[], v4, self.ipv6_global, true, &mut out)
            }
            Err(LookupError::NameUnresolvable) if self.resolver_on() => {
                let bare = name.strip_suffix('.').unwrap_or(name);
                let domain = self
                    .dhcp
                    .as_ref()
                    .and_then(|d| d.lease())
                    .and_then(|l| l.domain.clone());
                let qname = match domain {
                    Some(d) if !bare.contains('.') && !name.ends_with('.') => format!("{bare}.{d}"),
                    _ => bare.to_owned(),
                };
                let servers = self.dns_servers();
                let v4 = self.ipv4.is_some();
                self.resolver
                    .start(&qname, now, &servers, v4, self.ipv6_global, false, &mut out)
            }
            done => Start::Done(done),
        };
        (start, out.notes)
    }

    /// The result of a pending lookup, once it has one.
    pub fn lookup_take(&mut self, id: LookupId) -> Option<Result<Vec<IpAddr>, LookupError>> {
        self.resolver.take(id)
    }

    /// The caller dropped a pending lookup.
    pub fn lookup_cancel(&mut self, id: LookupId, now: u64) {
        let mut net = Net {
            iface: &self.iface,
            sockets: &mut self.sockets,
            mtu: self.mtu,
            hop_limit: self.hop_limit,
            multicast_hop_limit: self.multicast_hop_limit,
            gateway_v4: self.gateway_v4,
            gateway_v6: self.gateway_v6,
        };
        self.resolver.cancel(id, now, &mut self.udp, &mut net);
    }

    /// The current DHCP lease, if the client is on and bound.
    pub fn dhcp_lease(&self) -> Option<&crate::dhcp::Lease> {
        self.dhcp.as_ref()?.lease()
    }

    /// The neighbors learned so far (see the field).
    pub fn neighbors(&self) -> &BTreeMap<IpAddr, (MacAddr, u64)> {
        &self.neighbors
    }

    /// The apps' UDP sockets, for inspection.
    pub fn udp_sockets(&self) -> Vec<crate::debug::SockInfo> {
        self.udp.inspect(&self.sockets)
    }

    /// The apps' ICMP echo sockets, for inspection.
    pub fn icmp_sockets(&self) -> Vec<crate::debug::SockInfo> {
        self.icmp.inspect(&self.sockets)
    }

    /// The apps' TCP sockets, for inspection.
    pub fn tcp_sockets(&self) -> Vec<crate::debug::SockInfo> {
        self.tcp.inspect(&self.sockets)
    }

    /// Counters, in a stable order (part of the `counters` export). The list has one fixed
    /// shape: every group is present on every node, at 0 where the node never used it.
    pub fn counters(&self) -> Vec<(String, u64)> {
        let d = self.dev.counters;
        let s = self.counters;
        let u = self.udp.counters;
        let t = self.tcp.counters;
        let i = self.icmp.counters;
        let dhcp = self.dhcp.as_ref().map(|d| d.counters).unwrap_or_default();
        let r = self.resolver.counters;
        [
            ("rx-frames", d.rx_frames),
            ("rx-bytes", d.rx_bytes),
            ("tx-frames", d.tx_frames),
            ("tx-bytes", d.tx_bytes),
            ("tx-padded", d.tx_padded),
            ("stack-polls", s.polls),
            ("stack-passes", s.passes),
            ("iface-polls", s.iface_polls),
            ("stale-poll-at", s.stale_poll_at),
            ("arp-resolved", s.arp_resolved),
            ("ndp-resolved", s.ndp_resolved),
            ("multicast-queries", s.multicast_queries),
            ("icmp-errors-received", s.icmp_errors_received),
            ("udp-sockets", u.sockets),
            ("udp-binds", u.binds),
            ("udp-tx-datagrams", u.tx_datagrams),
            ("udp-tx-bytes", u.tx_bytes),
            ("udp-rx-datagrams", u.rx_datagrams),
            ("udp-rx-bytes", u.rx_bytes),
            ("udp-rx-filtered", u.rx_filtered),
            ("udp-would-block", u.would_block),
            ("udp-linger-expired", u.linger_expired),
            ("udp-icmp-errors", u.icmp_errors),
            ("udp-icmp-errors-dropped", u.icmp_errors_dropped),
            ("tcp-sockets", t.sockets),
            ("tcp-connects", t.connects),
            ("tcp-connected", t.connected),
            ("tcp-connect-failed", t.connect_failed),
            ("tcp-connect-unreachable", t.connect_unreachable),
            ("tcp-listens", t.listens),
            ("tcp-accepted", t.accepted),
            ("tcp-backlog-peak", t.backlog_peak),
            ("tcp-tx-bytes", t.tx_bytes),
            ("tcp-rx-bytes", t.rx_bytes),
            ("tcp-rx-discarded", t.rx_discarded),
            ("tcp-fins", t.fins),
            ("tcp-eofs", t.eofs),
            ("tcp-resets", t.resets),
            ("tcp-aborts", t.aborts),
            ("tcp-send-waits", t.send_waits),
            ("tcp-rx-window-full", t.rx_window_full),
            ("tcp-orphans-reaped", t.orphans_reaped),
            ("tcp-path-mtu-lowered", t.path_mtu_lowered),
            ("tcp-open", self.tcp.open() as u64),
            ("tcp-orphans", self.tcp.orphans() as u64),
            ("multicast-joins", s.multicast_joins),
            ("multicast-leaves", s.multicast_leaves),
            ("multicast-groups", self.joined.len() as u64),
            ("udp-hop-limit-waits", u.hop_limit_waits),
            ("udp-multicast-looped", u.multicast_looped),
            ("icmp-sockets", i.sockets),
            ("icmp-binds", i.binds),
            ("icmp-requests", i.requests),
            ("icmp-replies", i.replies),
            ("icmp-rx-filtered", i.rx_filtered),
            ("icmp-would-block", i.would_block),
            ("icmp-errors-queued", i.errors_queued),
            ("icmp-errors-dropped", i.errors_dropped),
            ("icmp-open", self.icmp.open() as u64),
            ("dhcp-bound", dhcp.bound),
            ("dhcp-renewed", dhcp.renewed),
            ("dhcp-lost", dhcp.lost),
            ("dns-lookups", r.lookups),
            ("dns-queries", r.queries),
            ("dns-responses", r.responses),
            ("dns-timeouts", r.timeouts),
            ("dns-icmp-errors", r.icmp_errors),
            ("dns-resolved", r.resolved),
            ("dns-failed", r.failed),
            ("dns-ignored", r.ignored),
            // Neighbors dropped from a full table (`MAX_TABLE`).
            ("neighbors-evicted", self.neighbor_evictions),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
    }
}

/// One network interface, as `list-interfaces` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub index: u32,
    pub name: String,
    pub mac: MacAddr,
    /// Address and prefix length, in the interface's order (IPv4, IPv6 link-local, global).
    pub addresses: Vec<(IpAddr, u8)>,
    pub mtu: u16,
    pub up: bool,
}

/// The family, group and UDP source port of an Ethernet frame carrying a UDP datagram to a
/// multicast group (no IPv6 extension headers: the netstack sends none on UDP).
fn udp_to_group(frame: &[u8]) -> Option<(Family, IpAddr, u16)> {
    let ip = frame.get(14..)?;
    let (family, dst, l4) = match u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]) {
        0x0800 if *ip.get(9)? == 17 => {
            let o: [u8; 4] = ip.get(16..20)?.try_into().ok()?;
            let ihl = usize::from(ip.first()? & 0x0f) * 4;
            (Family::Ipv4, IpAddr::from(o), ihl)
        }
        0x86dd if *ip.get(6)? == 17 => {
            let o: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
            (Family::Ipv6, IpAddr::from(o), 40)
        }
        _ => return None,
    };
    let sport = u16::from_be_bytes([*ip.get(l4)?, *ip.get(l4 + 1)?]);
    dst.is_multicast().then_some((family, dst, sport))
}

/// A `.local` name (mDNS, RFC 6762 §3): ends with the label `local`, one trailing dot allowed.
fn is_local(name: &str) -> bool {
    let bare = name.strip_suffix('.').unwrap_or(name);
    bare.len() > 6
        && bare
            .get(bare.len() - 6..)
            .is_some_and(|t| t.eq_ignore_ascii_case(".local"))
}
