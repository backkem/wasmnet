//! The stack: one smoltcp `Interface` over a [`QueueDevice`] per port, the sockets (the apps'
//! ICMP, UDP and TCP sockets, in one socket set per port: [`crate::sockets`]), the routes, the
//! multicast deadlines and the resolution trackers. Pure logic: the driver task in
//! `component.rs` owns the only instance and calls [`Stack::poll`] and [`Stack::next_wakeup`].
//!
//! Every input is explicit: `now` in virtual nanoseconds, frames, the MACs and the random seeds.
//! Nothing here reads a clock or an RNG, so the same inputs always give the same frames.
//!
//! A node with several ports is a multi-homed host: each port is an interface of its own (its
//! MAC, MTU, addresses, neighbours, multicast memberships and DHCP client), the route table
//! ([`crate::route`]) picks the port each packet the node sends leaves by, and nothing is ever
//! forwarded from one port to another (that is the router's job).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, Route};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use wasmnet_wire::MacAddr;

use crate::config::{Config, PortConfig, eui64_link_local};
use crate::device::QueueDevice;
use crate::dhcp::DhcpClient;
use crate::icmp::IcmpSockets;
use crate::mcast::MulticastDeadline;
use crate::names::{self, LookupError};
use crate::observe::{Observed, observe};
use crate::resolver::{LookupId, Resolver, Start};
use crate::route::{StaticRoute, longest_match, network};
use crate::sockets::Sockets;
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

/// Stack-level counters (the `counters` export adds the frame and driver counters). The
/// neighbour, ICMP error and query counts are the sums over every port ([`PortCounters`] has
/// each port's).
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
    /// Groups the interfaces joined and left for the apps.
    pub multicast_joins: u64,
    pub multicast_leaves: u64,
}

/// One port's own counters (listed as `eth<N>.<name>` on a node with several ports).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortCounters {
    pub arp_resolved: u64,
    pub ndp_resolved: u64,
    pub multicast_queries: u64,
    pub icmp_errors_received: u64,
}

/// One port: a smoltcp interface and its device, and what the stack keeps per link.
pub struct Port {
    pub(crate) iface: Interface,
    pub(crate) dev: QueueDevice,
    pub(crate) mac: MacAddr,
    pub(crate) mtu: u16,
    /// The IPv4 address (static, or the lease's).
    pub(crate) ipv4: Option<Ipv4Addr>,
    /// The link-local address, then the global one if configured.
    pub(crate) ipv6: Vec<Ipv6Addr>,
    /// A global IPv6 address is configured (the resolver then asks for AAAA too).
    pub(crate) ipv6_global: bool,
    /// Frames received since the last poll, classified when they arrived.
    pub(crate) rx_seen: Vec<Observed>,
    /// Neighbors we asked for, and when we first asked.
    pub(crate) arp_pending: BTreeMap<Ipv4Addr, u64>,
    pub(crate) nd_pending: BTreeMap<Ipv6Addr, u64>,
    pub(crate) mcast: MulticastDeadline,
    pub(crate) carrier: bool,
    /// The DHCPv4 client, with `ipv4 = "dhcp"` on this port.
    pub(crate) dhcp: Option<DhcpClient>,
    /// The groups the interface joined for the apps.
    pub(crate) joined: BTreeSet<IpAddr>,
    /// Neighbors learned from ARP packets addressed to us and neighbor adverts, with the virtual
    /// time each was last seen: what inspection reports (smoltcp's cache is not enumerable).
    pub(crate) neighbors: BTreeMap<IpAddr, (MacAddr, u64)>,
    /// Entries evicted from `neighbors`, `arp_pending` and `nd_pending` to keep each at most
    /// [`MAX_TABLE`] (counter `neighbors-evicted`). Not part of a snapshot: a restored stack
    /// counts from 0.
    pub(crate) neighbor_evictions: u64,
    pub(crate) counters: PortCounters,
}

impl Port {
    fn new(config: &PortConfig, mac: MacAddr, random_seed: u64, now: u64) -> Self {
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
        let mut mcast = MulticastDeadline::default();
        // Setting the addresses joined the IPv6 solicited-node groups: their MLD reports are due.
        mcast.control_changed(now);
        Self {
            iface,
            dev,
            mac,
            mtu: config.mtu,
            ipv4: config.ipv4.map(|c| c.addr),
            ipv6,
            ipv6_global: config.ipv6.is_some(),
            rx_seen: Vec::new(),
            arp_pending: BTreeMap::new(),
            nd_pending: BTreeMap::new(),
            mcast,
            carrier: false,
            dhcp: None,
            joined: BTreeSet::new(),
            neighbors: BTreeMap::new(),
            neighbor_evictions: 0,
            counters: PortCounters::default(),
        }
    }

    /// Records that `ip` is at `mac`, seen at `now` (bounded: [`MAX_TABLE`]).
    fn learn_neighbor(&mut self, ip: IpAddr, mac: MacAddr, now: u64) {
        if make_room(&mut self.neighbors, &ip, |(_, t)| *t) {
            self.neighbor_evictions += 1;
        }
        self.neighbors.insert(ip, (mac, now));
    }

    /// The lease's router, as a default route of this port.
    fn leased_router(&self) -> Option<Ipv4Addr> {
        self.dhcp.as_ref()?.lease()?.router
    }
}

/// The ports and the routes: what choosing an outgoing port needs ([`crate::route`]).
#[derive(Clone, Copy)]
pub struct Routing<'a> {
    pub ports: &'a [Port],
    pub routes: &'a [StaticRoute],
}

fn is_link_local_v6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80)
}

/// A destination no route covers: a multicast group or the IPv4 limited broadcast. It leaves
/// by the socket's multicast interface, or the family's default port.
pub fn is_group(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_multicast() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_multicast(),
    }
}

impl Routing<'_> {
    /// The number of ports.
    pub fn count(&self) -> usize {
        self.ports.len()
    }

    /// The port that has `ip` as one of its addresses.
    pub fn port_of(&self, ip: IpAddr) -> Option<usize> {
        self.ports
            .iter()
            .position(|p| p.iface.has_ip_addr(IpAddress::from(ip)))
    }

    /// `ip` is one of the node's addresses.
    pub fn is_ours(&self, ip: IpAddr) -> bool {
        self.port_of(ip).is_some()
    }

    /// Port `port`'s IP MTU.
    pub fn mtu(&self, port: usize) -> u16 {
        self.ports.get(port).map_or(1500, |p| p.mtu)
    }

    /// The largest IP MTU of any port.
    pub fn max_mtu(&self) -> u16 {
        self.ports.iter().map(|p| p.mtu).max().unwrap_or(1500)
    }

    /// The port a packet to `dst` leaves by, or `None` when no route covers it.
    ///
    /// * `only`: the sender is tied to that port (a socket bound to one of its addresses: the
    ///   strong host model, RFC 1122 §3.3.4.2), so only its routes count.
    /// * `scope`: an IPv6 link-local destination's scope id (the interface index), which picks
    ///   the port on a node with several; 0 leaves it to the routes (the lowest port).
    /// * A group destination (multicast, `255.255.255.255`) leaves by `only`, else the family's
    ///   [`default_port`](Self::default_port).
    pub fn route(&self, dst: IpAddr, scope: u32, only: Option<usize>) -> Option<usize> {
        if is_group(dst) {
            return Some(only.unwrap_or_else(|| self.default_port(dst)));
        }
        let mut only = only;
        if self.ports.len() > 1 && scope != 0 && only.is_none() && is_link_local_v6(dst) {
            let p = scope as usize - 1;
            if p >= self.ports.len() {
                return None;
            }
            only = Some(p);
        }
        let allowed = move |p: usize| only.is_none_or(|o| o == p);
        let connected = self
            .ports
            .iter()
            .enumerate()
            .filter(move |(n, _)| allowed(*n))
            .flat_map(|(n, p)| {
                p.iface.ip_addrs().iter().map(move |c| {
                    let a = IpAddr::from(c.address());
                    (network(a, c.prefix_len()), c.prefix_len(), n)
                })
            });
        let statics = self
            .routes
            .iter()
            .filter(move |r| allowed(r.port))
            .map(|r| (r.dst, r.prefix, r.port));
        longest_match(connected.chain(statics).chain(self.leased(only)), dst)
    }

    /// The DHCP leases' default routes, port by port.
    fn leased(&self, only: Option<usize>) -> impl Iterator<Item = (IpAddr, u8, usize)> + '_ {
        self.ports
            .iter()
            .enumerate()
            .filter(move |(n, _)| only.is_none_or(|o| o == *n))
            .filter_map(|(n, p)| p.leased_router().map(|_| (IpAddr::from([0u8; 4]), 0, n)))
    }

    /// The port a group destination of `dst`'s family leaves by when the socket names no
    /// interface: the port of the family's first default route, else the lowest port with an
    /// address of the family, else port 0. Always 0 on a node with one port.
    pub fn default_port(&self, dst: IpAddr) -> usize {
        let v4 = dst.is_ipv4();
        let default = self
            .routes
            .iter()
            .filter(|r| r.prefix == 0 && r.dst.is_ipv4() == v4)
            .map(|r| r.port)
            .chain(self.leased(None).filter(|_| v4).map(|(_, _, n)| n))
            .next();
        default
            .or_else(|| {
                self.ports.iter().position(|p| {
                    p.iface
                        .ip_addrs()
                        .iter()
                        .any(|c| IpAddr::from(c.address()).is_ipv4() == v4)
                })
            })
            .unwrap_or(0)
    }
}

/// Every port and everything above them.
pub struct Stack {
    pub(crate) ports: Vec<Port>,
    pub(crate) sockets: Sockets,
    /// The static routes (`routes` and the gateway keys).
    pub(crate) routes: Vec<StaticRoute>,
    /// The apps' UDP sockets.
    pub(crate) udp: UdpSockets,
    /// The apps' TCP sockets.
    pub(crate) tcp: TcpSockets,
    pub(crate) hosts: BTreeMap<String, Vec<IpAddr>>,
    pub(crate) hop_limit: u8,
    /// The stub resolver behind `ip-name-lookup` and its static servers (`dns`).
    pub(crate) resolver: Resolver,
    pub(crate) dns_static: Vec<IpAddr>,
    /// The node's multicast hop limit.
    pub(crate) multicast_hop_limit: u8,
    /// The apps' ICMP echo sockets, and the echo identifier rover.
    pub(crate) icmp: IcmpSockets,
    pub counters: StackCounters,
}

/// The most entries each of the stack's own neighbor tables (`neighbors`, `arp_pending`,
/// `nd_pending`) holds per port: they fill from the wire. A new entry in a full table evicts
/// the oldest (by its time; ties in address order).
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

/// Port `n`'s smoltcp seed: port 0 has the node's own (as a node with one port always had), the
/// others one derived from it, so they draw nothing more from `wasi:random`.
fn port_seed(random_seed: u64, n: usize) -> u64 {
    if n == 0 {
        return random_seed;
    }
    let mut z = random_seed ^ (n as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A MAC for port `n` derived from port 0's `mac` (for a caller that drew none for it).
fn derived_mac(mac: MacAddr, n: usize) -> MacAddr {
    let o = mac.octets();
    let seed = u64::from_be_bytes([0, 0, o[0], o[1], o[2], o[3], o[4], o[5]]);
    MacAddr::local_from_seed(seed ^ ((n as u64) << 48))
}

/// The name of port `n`: `eth0`, `eth1`, ...
pub fn port_name(n: usize) -> String {
    format!("eth{n}")
}

impl Stack {
    /// Builds the interfaces at virtual time `now`.
    ///
    /// * `mac`: port 0's MAC (configured, or derived from the seeded RNG by the caller). Other
    ///   ports take their configured MAC, else one derived from it: the component passes them
    ///   all through [`Stack::with_macs`].
    /// * `random_seed`: smoltcp's only entropy (IPv4 identification, TCP ISNs, MLD delays).
    /// * `ident_seed`: the first echo identifier the ICMP sockets pick (then counting up; zero is
    ///   skipped), the analogue of a process id.
    pub fn new(config: &Config, mac: MacAddr, random_seed: u64, ident_seed: u16, now: u64) -> Self {
        let macs: Vec<MacAddr> = config
            .ports()
            .iter()
            .enumerate()
            .map(|(n, p)| match (n, p.mac) {
                (0, _) => mac,
                (_, Some(m)) => m,
                (n, None) => derived_mac(mac, n),
            })
            .collect();
        Self::with_macs(config, &macs, random_seed, ident_seed, now)
    }

    /// [`Stack::new`] with every port's MAC given (`macs[n]` is port n's; missing ones are
    /// derived from port 0's).
    pub fn with_macs(
        config: &Config,
        macs: &[MacAddr],
        random_seed: u64,
        ident_seed: u16,
        now: u64,
    ) -> Self {
        let port_configs = config.ports();
        let mut sockets = Sockets::new(port_configs.len());
        let mut ports = Vec::new();
        for (n, pc) in port_configs.iter().enumerate() {
            let mac = macs.get(n).copied().unwrap_or_else(|| {
                let first = macs.first().copied();
                derived_mac(first.unwrap_or(MacAddr::local_from_seed(0)), n)
            });
            let mut port = Port::new(pc, mac, port_seed(random_seed, n), now);
            // The port's own routes, for smoltcp's next hop (the gateway keys exactly as a node
            // with one port always set them). The table has room for every one of them
            // (`iface-max-route-count-64`; `routes` lists at most 32).
            for r in config.routes.iter().filter(|r| r.port == n) {
                let routes = port.iface.routes_mut();
                match (r.prefix, r.via) {
                    (0, IpAddr::V4(gw)) => {
                        let _ = routes.add_default_ipv4_route(gw);
                    }
                    (0, IpAddr::V6(gw)) => {
                        let _ = routes.add_default_ipv6_route(gw);
                    }
                    (prefix, via) => {
                        let route = Route {
                            cidr: IpCidr::new(IpAddress::from(r.dst), prefix),
                            via_router: IpAddress::from(via),
                            preferred_until: None,
                            expires_at: None,
                        };
                        routes.update(|v| {
                            let _ = v.push(route);
                        });
                    }
                }
            }
            if pc.dhcp {
                port.dhcp = Some(DhcpClient::new(
                    sockets.set_mut(n),
                    config.hostname.as_deref(),
                    now,
                ));
            }
            ports.push(port);
        }
        let count = ports.len();
        Self {
            ports,
            sockets,
            routes: config.routes.clone(),
            udp: UdpSockets::new(count),
            tcp: TcpSockets::new(config.tcp_congestion),
            hosts: config.hosts.clone(),
            hop_limit: config.hop_limit,
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
            multicast_hop_limit: config.multicast_hop_limit,
            icmp: IcmpSockets::new(ident_seed),
            counters: StackCounters::default(),
        }
    }

    /// The number of ports.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// The resolver is configured: static DNS servers, or a DHCP client that may lease some.
    fn resolver_on(&self) -> bool {
        !self.dns_static.is_empty() || self.ports.iter().any(|p| p.dhcp.is_some())
    }

    /// The DNS servers in use: the static ones, else the leases', port by port.
    pub fn dns_servers(&self) -> Vec<IpAddr> {
        if !self.dns_static.is_empty() {
            return self.dns_static.clone();
        }
        let mut all: Vec<IpAddr> = Vec::new();
        for d in self.ports.iter().filter_map(|p| p.dhcp.as_ref()) {
            for s in d.dns() {
                if !all.contains(&s) {
                    all.push(s);
                }
            }
        }
        all
    }

    /// Port 0's MAC.
    pub fn mac(&self) -> MacAddr {
        self.ports[0].mac
    }

    /// One line for the log: each port's MAC, MTU and addresses, and the static routes.
    pub fn describe(&self) -> String {
        let mut s = String::from("netstack");
        for (n, p) in self.ports.iter().enumerate() {
            if n > 0 {
                s.push(';');
            }
            s.push_str(&format!(" {}: mac {} mtu {}", port_name(n), p.mac, p.mtu));
            for cidr in p.iface.ip_addrs() {
                s.push_str(&format!(" {cidr}"));
            }
            if p.dhcp.is_some() {
                s.push_str(" ipv4 dhcp");
            }
        }
        if !self.dns_static.is_empty() {
            let dns: Vec<String> = self.dns_static.iter().map(IpAddr::to_string).collect();
            s.push_str(&format!(" dns {}", dns.join(",")));
        }
        // A node with one port and only gateway keys reads as it always did.
        let gateway_key = |r: &StaticRoute| r.prefix == 0;
        if self.ports.len() > 1 || !self.routes.iter().all(gateway_key) {
            let routes: Vec<String> = self.routes.iter().map(StaticRoute::describe).collect();
            if !routes.is_empty() {
                s.push_str(&format!("; routes {}", routes.join(", ")));
            }
        }
        s
    }

    /// Queues a frame that arrived on port 0 (`eth0`).
    pub fn receive(&mut self, frame: Vec<u8>) {
        self.receive_on(0, frame);
    }

    /// Queues a frame that arrived on `port`. Only enqueues: the next [`poll`](Self::poll)
    /// processes it. A frame for a port the node does not have is dropped.
    pub fn receive_on(&mut self, port: usize, frame: Vec<u8>) {
        let Some(p) = self.ports.get_mut(port) else {
            return;
        };
        let mut seen = observe(&frame);
        // An ICMP error counts only in a frame our NIC accepts (ours, broadcast or multicast),
        // as smoltcp would: a switch flooding another host's frame must not fail our connect.
        if let Observed::IcmpError(_) = seen {
            let dst = frame.get(..6).and_then(MacAddr::from_slice);
            if !dst.is_some_and(|d| d == p.mac || d.is_multicast()) {
                seen = Observed::Other;
            }
        }
        p.rx_seen.push(seen);
        p.dev.push_rx(frame);
    }

    /// Records a carrier change on port 0. smoltcp has no notion of carrier; the host drops
    /// frames sent on a down link.
    pub fn link_state(&mut self, up: bool) {
        self.link_state_on(0, up);
    }

    /// Records a carrier change on `port`.
    pub fn link_state_on(&mut self, port: usize, up: bool) {
        if let Some(p) = self.ports.get_mut(port) {
            p.carrier = up;
        }
    }

    /// Port 0's carrier.
    pub fn carrier(&self) -> bool {
        self.ports[0].carrier
    }

    /// An event of port `n`: on a node with several ports it names the port.
    fn tag(&self, n: usize, mut e: Event) -> Event {
        if self.ports.len() > 1 {
            e.fields.push(("port".to_owned(), port_name(n)));
        }
        e
    }

    /// Names port `n` in every event `out` gained since `mark` (several ports only).
    fn tag_since(&self, n: usize, out: &mut Output, mark: usize) {
        if self.ports.len() > 1 {
            for note in &mut out.notes[mark..] {
                if let Note::Event(e) = note {
                    e.fields.push(("port".to_owned(), port_name(n)));
                }
            }
        }
    }

    /// Runs the stack at `now` until it makes no more progress: DHCP and resolver timers, smoltcp
    /// ingress/egress on every port, replies, the TCP table's bookkeeping. Returns the frames to
    /// transmit, each with its port, and the diagnostics, in order, and whether anything
    /// happened at all ([`Output::active`]: the driver's TCP pumps then look at their sockets
    /// again).
    pub fn poll(&mut self, now: u64) -> Output {
        self.counters.polls += 1;
        let mut out = Output::default();
        for _ in 0..MAX_PASSES {
            self.counters.passes += 1;
            for n in 0..self.ports.len() {
                if !self.ports[n].rx_seen.is_empty() {
                    out.active = true;
                }
                for seen in std::mem::take(&mut self.ports[n].rx_seen) {
                    self.on_rx(n, now, seen, &mut out);
                }
            }
            let mut progressed = false;
            // Before the poll, so a socket that gave up does not ask for its neighbor again.
            self.udp.reap(now, &mut self.sockets);
            // Group memberships the apps' sockets want: join or leave at this pass, so the
            // IGMP/MLD report leaves at the instant of the call.
            progressed |= self.sync_groups(now, &mut out);
            let mut changed = false;
            let mut sent = false;
            for n in 0..self.ports.len() {
                self.counters.iface_polls += 1;
                let port = &mut self.ports[n];
                let result = port
                    .iface
                    .poll(to_smol(now), &mut port.dev, self.sockets.set_mut(n));
                port.mcast.polled(now);
                let frames = port.dev.take_tx();
                for frame in &frames {
                    self.on_tx(n, now, observe(frame));
                }
                // Multicast loopback: a copy of a datagram to a group this port has joined goes
                // back up the stack, never onto the wire.
                for frame in &frames {
                    self.loop_back(n, frame);
                }
                sent |= !frames.is_empty();
                out.frames.extend(frames.into_iter().map(|f| (n as u32, f)));
                changed |= result == PollResult::SocketStateChanged;
            }
            // A DHCP lease bound, renewed or lost: apply it before anything else looks at
            // the addresses.
            for n in 0..self.ports.len() {
                let mark = out.notes.len();
                let port = &mut self.ports[n];
                if let Some(dhcp) = &mut port.dhcp
                    && dhcp.poll(now, &mut port.iface, self.sockets.set_mut(n), &mut out)
                {
                    progressed = true;
                    port.ipv4 = dhcp.lease().map(|l| l.address);
                }
                self.tag_since(n, &mut out, mark);
            }
            self.udp.reap(now, &mut self.sockets);
            // Ports bound by both families: hand each datagram to its family's socket (#7).
            out.active |= self.udp.demux(&mut self.sockets);
            // The resolver reads its answers and sends due queries. A query it queued
            // leaves at the next pass, at this instant.
            if self.resolver.in_flight() > 0 {
                let mut net = Net {
                    routing: Routing {
                        ports: &self.ports,
                        routes: &self.routes,
                    },
                    sockets: &mut self.sockets,
                    hop_limit: self.hop_limit,
                    multicast_hop_limit: self.multicast_hop_limit,
                };
                progressed |= self.resolver.poll(now, &mut self.udp, &mut net, &mut out);
            }
            progressed |= self.tcp.after_poll(now, self.hop_limit, &mut self.sockets);
            out.active |= changed || sent || progressed;
            let more = self
                .ports
                .iter()
                .any(|p| !p.rx_seen.is_empty() || !p.dev.rx.is_empty());
            if !(changed || sent || progressed || more) {
                break;
            }
        }
        out
    }

    /// When the driver must poll next: the earliest of every port's smoltcp `poll_at` and
    /// multicast deadline and the sockets' timers, or `None` when only a new frame can create
    /// work. Never at or before `now` (see `STALE_GUARD_NS`).
    pub fn next_wakeup(&mut self, now: u64) -> Option<u64> {
        let mut next: Option<u64> = None;
        let mut earliest = |t: Option<u64>| {
            if let Some(t) = t {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        };
        for (n, port) in self.ports.iter_mut().enumerate() {
            earliest(
                port.iface
                    .poll_at(to_smol(now), self.sockets.set(n))
                    .map(|t| deadline_ns(t, now)),
            );
            earliest(port.mcast.next(now));
        }
        earliest(self.udp.next_deadline());
        earliest(self.tcp.next_deadline());
        earliest(self.resolver.next_deadline());
        let next = next?;
        if next <= now {
            self.counters.stale_poll_at += 1;
            return Some(now + STALE_GUARD_NS);
        }
        Some(next)
    }

    fn on_rx(&mut self, n: usize, now: u64, seen: Observed, out: &mut Output) {
        match seen {
            Observed::Arp {
                sender_mac,
                sender_ip,
                target_ip,
                ..
            } if Some(target_ip) == self.ports[n].ipv4 => {
                let port = &mut self.ports[n];
                if !sender_ip.is_unspecified() {
                    port.learn_neighbor(IpAddr::V4(sender_ip), sender_mac, now);
                }
                if let Some(asked) = port.arp_pending.remove(&sender_ip) {
                    self.counters.arp_resolved += 1;
                    port.counters.arp_resolved += 1;
                    let e = Event::new(
                        "arp-resolved",
                        &[
                            ("ip", sender_ip.to_string()),
                            ("mac", sender_mac.to_string()),
                            ("after-ns", (now - asked).to_string()),
                        ],
                    );
                    out.event(self.tag(n, e));
                }
            }
            Observed::NeighborAdvert { target, mac } => {
                let port = &mut self.ports[n];
                port.learn_neighbor(IpAddr::V6(target), mac, now);
                if let Some(asked) = port.nd_pending.remove(&target) {
                    self.counters.ndp_resolved += 1;
                    port.counters.ndp_resolved += 1;
                    let e = Event::new(
                        "ndp-resolved",
                        &[
                            ("ip", target.to_string()),
                            ("mac", mac.to_string()),
                            ("after-ns", (now - asked).to_string()),
                        ],
                    );
                    out.event(self.tag(n, e));
                }
            }
            Observed::IcmpError(e) if self.ports[n].iface.has_ip_addr(IpAddress::from(e.to)) => {
                self.counters.icmp_errors_received += 1;
                self.ports[n].counters.icmp_errors_received += 1;
                let lowered = self.tcp.path_mtu(&e, self.ports[n].mtu, &mut self.sockets);
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
                let ev = Event::new(
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
                );
                out.event(self.tag(n, ev));
                if let Some(p) = lowered {
                    let ev = Event::new(
                        "path-mtu-lowered",
                        &[
                            ("peer", p.peer.to_string()),
                            ("local-port", p.local_port.to_string()),
                            ("mtu", p.mtu.to_string()),
                            ("mss", p.mss.to_string()),
                        ],
                    );
                    out.event(self.tag(n, ev));
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
                let port = &mut self.ports[n];
                port.counters.multicast_queries += 1;
                port.mcast.query(now, max_resp_ns);
                let line = if self.ports.len() > 1 {
                    format!(
                        "{}: multicast query, max response {max_resp_ns}ns",
                        port_name(n)
                    )
                } else {
                    format!("multicast query, max response {max_resp_ns}ns")
                };
                out.log(Level::Debug, line);
            }
            _ => {}
        }
    }

    fn on_tx(&mut self, n: usize, now: u64, sent: Observed) {
        let port = &mut self.ports[n];
        match sent {
            Observed::Arp {
                reply: false,
                target_ip,
                ..
            } => {
                if make_room(&mut port.arp_pending, &target_ip, |t| *t) {
                    port.neighbor_evictions += 1;
                }
                port.arp_pending.entry(target_ip).or_insert(now);
            }
            Observed::NeighborSolicit { target } if !port.ipv6.contains(&target) => {
                if make_room(&mut port.nd_pending, &target, |t| *t) {
                    port.neighbor_evictions += 1;
                }
                port.nd_pending.entry(target).or_insert(now);
            }
            _ => {}
        }
    }

    /// Joins and leaves, on each port, the groups the apps' sockets want there. Returns whether
    /// it changed any.
    fn sync_groups(&mut self, now: u64, out: &mut Output) -> bool {
        let routing = Routing {
            ports: &self.ports,
            routes: &self.routes,
        };
        let wanted = self.udp.groups(|g| routing.default_port(g));
        let mut any = false;
        for n in 0..self.ports.len() {
            let here: BTreeSet<IpAddr> = wanted
                .iter()
                .filter(|(p, _)| *p == n)
                .map(|(_, g)| *g)
                .collect();
            if here == self.ports[n].joined {
                continue;
            }
            let mark = out.notes.len();
            let port = &mut self.ports[n];
            for &group in here.difference(&port.joined) {
                match port.iface.join_multicast_group(IpAddress::from(group)) {
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
            for &group in port.joined.difference(&here) {
                let _ = port.iface.leave_multicast_group(IpAddress::from(group));
                self.counters.multicast_leaves += 1;
                out.event(Event::new(
                    "multicast-left",
                    &[("group", group.to_string())],
                ));
            }
            port.joined = here;
            port.mcast.control_changed(now);
            self.tag_since(n, out, mark);
            any = true;
        }
        any
    }

    /// Multicast loopback: a UDP datagram this node sent out of port `n` to a group that port
    /// joined, from a socket that keeps `multicast-loopback` on, is queued to be received by the
    /// node too.
    fn loop_back(&mut self, n: usize, frame: &[u8]) {
        let Some((family, group, sport)) = udp_to_group(frame) else {
            return;
        };
        if self.ports[n]
            .iface
            .has_multicast_group(IpAddress::from(group))
            && self.udp.loops_back(family, sport)
        {
            self.ports[n].dev.push_loopback(frame.to_vec());
        }
    }

    /// Port `n` as `list-interfaces` reports it.
    fn interface_of(&self, n: usize) -> InterfaceInfo {
        let p = &self.ports[n];
        InterfaceInfo {
            index: n as u32 + 1,
            name: port_name(n),
            mac: p.mac,
            addresses: p
                .iface
                .ip_addrs()
                .iter()
                .map(|c| (IpAddr::from(c.address()), c.prefix_len()))
                .collect(),
            mtu: p.mtu,
            up: p.carrier,
        }
    }

    /// Port 0, `eth0`, as `wasmnet:sockets-ext/interfaces.list-interfaces` reports it.
    pub fn interface(&self) -> InterfaceInfo {
        self.interface_of(0)
    }

    /// `wasmnet:sockets-ext/interfaces.list-interfaces`: every port, in index order. Port N is
    /// interface index N + 1, named `eth<N>`.
    pub fn interfaces(&self) -> Vec<InterfaceInfo> {
        (0..self.ports.len())
            .map(|n| self.interface_of(n))
            .collect()
    }

    /// The apps' UDP sockets, with the parts of the stack they need for one call. The caller
    /// holds the stack borrowed for the call's duration, so it must not call any import.
    pub fn udp(&mut self) -> (&mut UdpSockets, Net<'_>) {
        let net = Net {
            routing: Routing {
                ports: &self.ports,
                routes: &self.routes,
            },
            sockets: &mut self.sockets,
            hop_limit: self.hop_limit,
            multicast_hop_limit: self.multicast_hop_limit,
        };
        (&mut self.udp, net)
    }

    /// The apps' ICMP echo sockets, with the parts of the stack they need for one call.
    /// The caller holds the stack borrowed for the call's duration, so it must not call any
    /// import.
    pub fn icmp(&mut self) -> (&mut IcmpSockets, Net<'_>) {
        let net = Net {
            routing: Routing {
                ports: &self.ports,
                routes: &self.routes,
            },
            sockets: &mut self.sockets,
            hop_limit: self.hop_limit,
            multicast_hop_limit: self.multicast_hop_limit,
        };
        (&mut self.icmp, net)
    }

    /// The apps' TCP sockets, with the parts of the stack they need for one call. The caller
    /// holds the stack borrowed for the call's duration, so it must not call any import.
    pub fn tcp(&mut self) -> (&mut TcpSockets, TcpNet<'_>) {
        let net = TcpNet {
            ports: &mut self.ports,
            routes: &self.routes,
            sockets: &mut self.sockets,
            hop_limit: self.hop_limit,
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
        let v4 = self.ports.iter().any(|p| p.ipv4.is_some());
        let v6 = self.ports.iter().any(|p| p.ipv6_global);
        let start = match names::resolve(&self.hosts, name) {
            // `.local`: a one-shot multicast DNS query (RFC 6762 §5.1), DNS servers or not.
            Err(LookupError::NameUnresolvable) if is_local(name) => {
                self.resolver.start(name, now, &[], v4, v6, true, &mut out)
            }
            Err(LookupError::NameUnresolvable) if self.resolver_on() => {
                let bare = name.strip_suffix('.').unwrap_or(name);
                let domain = self
                    .ports
                    .iter()
                    .filter_map(|p| p.dhcp.as_ref()?.lease()?.domain.clone())
                    .next();
                let qname = match domain {
                    Some(d) if !bare.contains('.') && !name.ends_with('.') => format!("{bare}.{d}"),
                    _ => bare.to_owned(),
                };
                let servers = self.dns_servers();
                self.resolver
                    .start(&qname, now, &servers, v4, v6, false, &mut out)
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
            routing: Routing {
                ports: &self.ports,
                routes: &self.routes,
            },
            sockets: &mut self.sockets,
            hop_limit: self.hop_limit,
            multicast_hop_limit: self.multicast_hop_limit,
        };
        self.resolver.cancel(id, now, &mut self.udp, &mut net);
    }

    /// Port 0's DHCP lease, if its client is on and bound.
    pub fn dhcp_lease(&self) -> Option<&crate::dhcp::Lease> {
        self.dhcp_lease_on(0)
    }

    /// Port `port`'s DHCP lease, if its client is on and bound.
    pub fn dhcp_lease_on(&self, port: usize) -> Option<&crate::dhcp::Lease> {
        self.ports.get(port)?.dhcp.as_ref()?.lease()
    }

    /// The neighbors port 0 learned so far (see [`Port`]).
    pub fn neighbors(&self) -> &BTreeMap<IpAddr, (MacAddr, u64)> {
        &self.ports[0].neighbors
    }

    /// The neighbors port `port` learned so far; `None` for a port the node does not have.
    pub fn neighbors_on(&self, port: usize) -> Option<&BTreeMap<IpAddr, (MacAddr, u64)>> {
        self.ports.get(port).map(|p| &p.neighbors)
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
    /// shape: every group is present on every node, at 0 where the node never used it. Frame,
    /// neighbour and DHCP counts are sums over the ports; [`port_counters`](Self::port_counters)
    /// has each port's.
    pub fn counters(&self) -> Vec<(String, u64)> {
        let mut d = crate::device::FrameCounters::default();
        let mut dhcp = crate::dhcp::DhcpCounters::default();
        let mut evicted = 0;
        let mut groups = 0;
        for p in &self.ports {
            let c = p.dev.counters;
            d.rx_frames += c.rx_frames;
            d.rx_bytes += c.rx_bytes;
            d.tx_frames += c.tx_frames;
            d.tx_bytes += c.tx_bytes;
            d.tx_padded += c.tx_padded;
            if let Some(c) = p.dhcp.as_ref().map(|d| d.counters) {
                dhcp.bound += c.bound;
                dhcp.renewed += c.renewed;
                dhcp.lost += c.lost;
            }
            evicted += p.neighbor_evictions;
            groups += p.joined.len() as u64;
        }
        let s = self.counters;
        let u = self.udp.counters;
        let t = self.tcp.counters;
        let i = self.icmp.counters;
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
            ("multicast-groups", groups),
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
            ("neighbors-evicted", evicted),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
    }

    /// Each port's own counters, `eth<N>.<name>`, port by port: empty on a node with one port
    /// (whose totals in [`counters`](Self::counters) are its port's), so its list is what it
    /// always was. The `counters` export lists them last, after the driver's.
    pub fn port_counters(&self) -> Vec<(String, u64)> {
        if self.ports.len() < 2 {
            return Vec::new();
        }
        let mut all = Vec::new();
        for (n, p) in self.ports.iter().enumerate() {
            let d = p.dev.counters;
            let c = p.counters;
            let dhcp = p.dhcp.as_ref().map(|d| d.counters).unwrap_or_default();
            for (k, v) in [
                ("rx-frames", d.rx_frames),
                ("rx-bytes", d.rx_bytes),
                ("tx-frames", d.tx_frames),
                ("tx-bytes", d.tx_bytes),
                ("arp-resolved", c.arp_resolved),
                ("ndp-resolved", c.ndp_resolved),
                ("multicast-queries", c.multicast_queries),
                ("icmp-errors-received", c.icmp_errors_received),
                ("multicast-groups", p.joined.len() as u64),
                ("dhcp-bound", dhcp.bound),
                ("neighbors-evicted", p.neighbor_evictions),
            ] {
                all.push((format!("{}.{k}", port_name(n)), v));
            }
        }
        all
    }
}

/// One network interface, as `list-interfaces` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// The port number plus one (`eth0` is 1).
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
