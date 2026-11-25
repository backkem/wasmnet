//! The router: receive a frame, decide, transmit frames. Pure logic over a [`Sink`].
//!
//! Per frame (`receive`):
//! 1. count it on its port; drop it if the port is down or unknown;
//! 2. **L2 filter** like a NIC: keep frames for the port's MAC, broadcast, and the IPv6 groups
//!    the port listens to (all-nodes, all-routers, the solicited-node groups of its addresses);
//!    anything else (a switch flooding unknown unicast) is counted (`l2-filtered`) and dropped;
//! 3. **ARP**: answer requests for the port's IPv4 address, learn the sender of anything aimed
//!    at us, and resolve waiting neighbors;
//! 4. **IPv4 / IPv6**: validate (header checksum, lengths), then either deliver locally (one of
//!    the router's addresses: echo requests are answered, UDP draws a port unreachable, TCP an
//!    RST, NDP is handled) or **forward**: TTL/hop-limit check (ICMP time exceeded), longest-prefix
//!    route lookup (ICMP net unreachable), per-port MTU (ICMP fragmentation needed / packet too
//!    big; the router never fragments), TTL decrement with an incremental checksum update, and
//!    the next hop's MAC from the neighbor table (queueing the packet while ARP/NDP runs; ICMP
//!    host unreachable if it never answers).
//!
//! ICMP errors follow RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e): never about an ICMP error, a
//! non-initial fragment, a packet from a non-unicast source, or (IPv4) a packet to a group
//! address. They come from the ingress port's address, quote as much of the offending packet as
//! fits 576 (IPv4) or 1280 (IPv6) bytes, and are routed like any packet the router originates.
//! There is no ICMP rate limiting: every error is counted and reported.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{
    ArpPacketSlice, Ethernet2HeaderSlice, Ipv4HeaderSlice, Ipv6HeaderSlice, Ipv6Slice,
};
use wasmnet_wire::{MacAddr, dhcp};

use crate::config::{Config, PortConfig, Trace, is_link_local_v6, usable_v4};
use crate::filter::{Filter, parse_rule};
use crate::nat::{Nat, Proto, Refusal, parse_forward};
use crate::neighbor::{Due, Enqueued, NeighborTable, Queued, Resolved};
use crate::route::{Prefix, Route, RouteKind, RouteTable};
use crate::track::{self, Kind};
use crate::wire::{
    self, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP,
    PROTO_UDP, Side,
};
use crate::{Event, Sink};

/// `first`-mode trace sets stop growing here (further first-time items are not reported).
const TRACE_CAP: usize = 4096;
/// RFC 1812: an ICMPv4 error is at most 576 bytes.
const ICMPV4_ERROR_MAX: usize = 576;
/// RFC 4443: an ICMPv6 error is at most the minimum MTU.
const ICMPV6_ERROR_MAX: usize = 1280;
/// RFC 1542 §4.1.1: a relay discards a BOOTREQUEST that already crossed this many relays.
const MAX_DHCP_HOPS: u8 = 16;

/// Per-port counters (`p<N>-…` in the `counters` export).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortCounters {
    pub rx_frames: u64,
    pub rx_bytes: u64,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    /// Packets that came in here and were routed (to any port).
    pub forwarded_in: u64,
    /// Packets routed out of here.
    pub forwarded_out: u64,
    /// IP packets that came in here and were dropped (each one is a `forward-drop` event).
    pub dropped: u64,
}

/// Router-wide counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub rx_frames: u64,
    pub rx_bytes: u64,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub rx_port_down: u64,
    pub l2_filtered: u64,
    pub malformed: u64,
    pub bad_checksum: u64,
    pub unknown_ethertype: u64,
    pub martian: u64,
    pub not_forwarded: u64,
    pub local_v4: u64,
    pub local_v6: u64,
    pub forwarded_v4: u64,
    pub forwarded_v6: u64,
    pub ttl_expired: u64,
    pub no_route: u64,
    pub port_down_drops: u64,
    pub frag_needed: u64,
    pub too_big: u64,
    pub frag_unsupported: u64,
    pub scope_drops: u64,
    pub neighbor_drops: u64,
    pub queue_overflow: u64,
    pub icmp_errors_sent: u64,
    pub icmp_errors_suppressed: u64,
    pub echo_replies: u64,
    pub tcp_resets: u64,
    pub arp_requests: u64,
    pub arp_replies: u64,
    pub arp_resolved: u64,
    pub arp_failed: u64,
    pub ns_sent: u64,
    pub na_sent: u64,
    pub ndp_resolved: u64,
    pub ndp_failed: u64,
    pub ra_sent: u64,
    pub trace_suppressed: u64,
    /// Static routes added and removed by commands (a replacement counts in both).
    pub routes_added: u64,
    pub routes_removed: u64,
    /// DHCP relay: requests relayed to a server, replies relayed to a client, requests
    /// dropped (too many hops).
    pub dhcp_relayed_to_server: u64,
    pub dhcp_relayed_to_client: u64,
    pub dhcp_relay_dropped: u64,
}

struct Port {
    cfg: PortConfig,
    up: bool,
    c: PortCounters,
}

impl Port {
    fn v6_addrs(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        std::iter::once(self.cfg.link_local).chain(self.cfg.ipv6.map(|(a, _)| a))
    }
}

/// A flow, for `ttl-decrement`'s `first` mode.
type FlowKey = (u8, IpAddr, u16, IpAddr, u16);

/// The router.
pub struct Router {
    cfg: Config,
    ports: Vec<Port>,
    routes: RouteTable,
    neigh: NeighborTable,
    ip_id: u16,
    traced_dsts: BTreeSet<IpAddr>,
    traced_flows: BTreeSet<FlowKey>,
    pub counters: Counters,
    /// Address translation, when a port has `nat` (`docs/design/nat.md`).
    nat: Option<Nat>,
    /// The allow lists and the flows they let through (inactive without rules).
    filter: Filter,
}

pub(crate) fn proto_name(p: u8) -> String {
    match p {
        PROTO_ICMP => "icmp".to_owned(),
        PROTO_TCP => "tcp".to_owned(),
        PROTO_UDP => "udp".to_owned(),
        PROTO_ICMPV6 => "icmpv6".to_owned(),
        n => n.to_string(),
    }
}

fn kv(k: &str, v: impl ToString) -> (String, String) {
    (k.to_owned(), v.to_string())
}

/// `10.0.1.10:80` or `[fd00::1]:80`; just the address when there are no ports.
fn endpoint(ip: IpAddr, port: Option<u16>) -> String {
    match (ip, port) {
        (IpAddr::V6(a), Some(p)) => format!("[{a}]:{p}"),
        (a, Some(p)) => format!("{a}:{p}"),
        (a, None) => a.to_string(),
    }
}

/// TCP/UDP ports of a transport header, if `proto` has them.
fn ports_of(proto: u8, l4: &[u8]) -> Option<(u16, u16)> {
    matches!(proto, PROTO_TCP | PROTO_UDP).then_some(())?;
    let b = l4.get(..4)?;
    Some((
        u16::from_be_bytes([b[0], b[1]]),
        u16::from_be_bytes([b[2], b[3]]),
    ))
}

/// The IPv4 header length of a packet that parsed already.
fn ihl(packet: &[u8]) -> usize {
    usize::from(packet[0] & 0x0f) * 4
}

fn v4_src(p: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(p[12], p[13], p[14], p[15])
}

fn v4_dst(p: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(p[16], p[17], p[18], p[19])
}

fn v6_at(p: &[u8], at: usize) -> Ipv6Addr {
    let o: [u8; 16] = p[at..at + 16].try_into().expect("16 bytes");
    Ipv6Addr::from(o)
}

/// The earlier of two optional deadlines.
fn earliest(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// Recomputes the ICMP checksum of an IPv4 packet carrying ICMP (after its quote changed).
fn refresh_icmp_checksum(p: &mut [u8]) {
    let at = ihl(p);
    p[at + 2..at + 4].copy_from_slice(&[0, 0]);
    let c = wire::checksum(&p[at..]);
    p[at + 2..at + 4].copy_from_slice(&c.to_be_bytes());
}

/// An IPv4 address from a tuple's `IpAddr` (NAT only sees IPv4).
fn v4_of(a: IpAddr) -> Option<Ipv4Addr> {
    match a {
        IpAddr::V4(a) => Some(a),
        IpAddr::V6(_) => None,
    }
}

/// `nat-forward-added` / `nat-forward-removed {proto, external, internal, port}`.
fn forward_event(kind: &'static str, f: &crate::nat::Forward) -> Event {
    Event::new(
        kind,
        vec![
            kv("proto", f.proto),
            kv("external", f.external),
            kv("internal", format!("{}:{}", f.internal.0, f.internal.1)),
            kv("port", f.port),
        ],
    )
}

/// A command's refusal to touch a connected route.
fn connected(r: &Route) -> String {
    format!(
        "{} is connected to port {}: its route cannot be changed",
        r.prefix, r.port
    )
}

/// ICMPv4 error types (an error is never sent about one of these).
fn is_icmpv4_error(t: u8) -> bool {
    matches!(t, 3 | 4 | 5 | 11 | 12)
}

/// Names for `icmp-error-sent.error`, the same for both families where they mean the same.
fn error_name(v6: bool, t: u8, code: u8) -> &'static str {
    match (v6, t, code) {
        (false, 11, _) | (true, 3, _) => "time-exceeded",
        (false, 3, 0) | (true, 1, 0) => "net-unreachable",
        (false, 3, 1) | (true, 1, 3) => "host-unreachable",
        (false, 3, 2) => "protocol-unreachable",
        (false, 3, 3) | (true, 1, 4) => "port-unreachable",
        (false, 3, 4) => "frag-needed",
        (true, 1, 2) => "beyond-scope",
        (true, 2, _) => "packet-too-big",
        (true, 4, 1) => "unrecognized-next-header",
        _ => "other",
    }
}

impl Router {
    pub fn new(cfg: Config) -> Self {
        let mut routes = RouteTable::default();
        for (n, p) in cfg.ports.iter().enumerate() {
            let port = n as u32;
            if let Some((a, l)) = p.ipv4 {
                routes.insert(Route {
                    prefix: Prefix::V4(u32::from(a), l),
                    via: None,
                    port,
                    kind: RouteKind::Connected,
                });
            }
            if let Some((a, l)) = p.ipv6 {
                routes.insert(Route {
                    prefix: Prefix::V6(u128::from(a), l),
                    via: None,
                    port,
                    kind: RouteKind::Connected,
                });
            }
        }
        for r in &cfg.routes {
            routes.insert(Route {
                prefix: r.prefix,
                via: r.via,
                port: r.port,
                kind: RouteKind::Static,
            });
        }
        let ports = cfg
            .ports
            .iter()
            .map(|p| Port {
                cfg: p.clone(),
                up: false,
                c: PortCounters::default(),
            })
            .collect();
        let nat = cfg.nat.clone().map(|n| {
            let addrs: BTreeMap<u32, Ipv4Addr> = cfg
                .ports
                .iter()
                .enumerate()
                .filter(|(_, p)| p.nat)
                .filter_map(|(i, p)| Some((i as u32, p.ipv4?.0)))
                .collect();
            Nat::new(
                n,
                addrs,
                cfg.conntrack,
                cfg.conntrack_max,
                cfg.trace_nat_filtered,
            )
        });
        let rules = cfg
            .ports
            .iter()
            .enumerate()
            .map(|(i, p)| (i as u32, p.allow.clone()))
            .collect();
        let filter = Filter::new(
            rules,
            cfg.conntrack,
            cfg.conntrack_max,
            cfg.trace_filter_drop,
        );
        Self {
            cfg,
            ports,
            routes,
            neigh: NeighborTable::default(),
            ip_id: 0,
            traced_dsts: BTreeSet::new(),
            traced_flows: BTreeSet::new(),
            counters: Counters::default(),
            nat,
            filter,
        }
    }

    /// The translation table, if a port translates.
    pub fn nat(&self) -> Option<&Nat> {
        self.nat.as_ref()
    }

    pub fn filter(&self) -> &Filter {
        &self.filter
    }

    fn is_outside(&self, port: u32) -> bool {
        self.nat.as_ref().is_some_and(|n| n.is_outside(port))
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn routes(&self) -> &RouteTable {
        &self.routes
    }

    pub fn is_up(&self, port: u32) -> bool {
        self.ports.get(port as usize).is_some_and(|p| p.up)
    }

    /// Log lines describing the ports and the routing table.
    pub fn describe(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "router: {} port(s), {} route(s), ttl {}",
            self.ports.len(),
            self.routes.len(),
            self.cfg.ttl
        )];
        for (n, p) in self.ports.iter().enumerate() {
            let mut s = format!("  port {n}: mac {} mtu {}", p.cfg.mac, p.cfg.mtu);
            if let Some((a, l)) = p.cfg.ipv4 {
                s.push_str(&format!(" {a}/{l}"));
            }
            if let Some((a, l)) = p.cfg.ipv6 {
                s.push_str(&format!(" {a}/{l}"));
            }
            s.push_str(&format!(" {}", p.cfg.link_local));
            if p.cfg.ra {
                s.push_str(" ra");
            }
            if p.cfg.nat {
                s.push_str(" nat");
            }
            if !p.cfg.allow.is_empty() {
                s.push_str(&format!(" allow {}", p.cfg.allow.len()));
            }
            lines.push(s);
        }
        if let Some(n) = &self.nat {
            let c = n.config();
            lines.push(format!(
                "  nat: mapping {}, filtering {}, hairpin {}, {} ports {}-{}, {} forward(s)",
                c.mapping.name(),
                c.filtering.name(),
                if c.hairpin { "on" } else { "off" },
                match c.allocation {
                    crate::nat::Allocation::Preserve => "preserved",
                    crate::nat::Allocation::Sequential => "sequential",
                },
                c.port_range.0,
                c.port_range.1,
                n.forwards().len()
            ));
        }
        for r in self.routes.routes() {
            lines.push(format!("  route {r}"));
        }
        lines
    }

    // ------------------------------------------------------------------------------------------
    // The device contract

    /// A frame arrived on `port` at `now`.
    pub fn receive(&mut self, now: u64, port: u32, frame: &[u8], out: &mut impl Sink) {
        self.counters.rx_frames += 1;
        self.counters.rx_bytes += frame.len() as u64;
        let Some(p) = self.ports.get_mut(port as usize) else {
            self.counters.malformed += 1;
            return;
        };
        p.c.rx_frames += 1;
        p.c.rx_bytes += frame.len() as u64;
        if !p.up {
            self.counters.rx_port_down += 1;
            return;
        }
        let Ok(eth) = Ethernet2HeaderSlice::from_slice(frame) else {
            self.counters.malformed += 1;
            return;
        };
        let (dst, src) = (MacAddr(eth.destination()), MacAddr(eth.source()));
        if !self.accepts(port, dst) {
            self.counters.l2_filtered += 1;
            return;
        }
        if src.is_multicast() {
            self.counters.malformed += 1;
            return;
        }
        let payload = &frame[wire::ETH_HEADER..];
        match eth.ether_type().0 {
            ETHERTYPE_ARP => self.arp_in(now, port, payload, out),
            ETHERTYPE_IPV4 => self.ipv4_in(now, port, payload, out),
            ETHERTYPE_IPV6 => self.ipv6_in(now, port, src, payload, out),
            _ => self.counters.unknown_ethertype += 1,
        }
    }

    /// Advances the neighbor timers to `now`; returns the next deadline.
    pub fn poll(&mut self, now: u64, out: &mut impl Sink) -> Option<u64> {
        for due in self.neigh.due(now, &self.cfg.neighbor) {
            match due {
                Due::Retry { port, ip } => self.solicit(port, ip, out),
                Due::Failed {
                    port,
                    ip,
                    attempts,
                    queue,
                } => {
                    let v6 = ip.is_ipv6();
                    if v6 {
                        self.counters.ndp_failed += 1;
                    } else {
                        self.counters.arp_failed += 1;
                    }
                    out.event(Event::new(
                        if v6 { "ndp-failed" } else { "arp-failed" },
                        vec![
                            kv("ip", ip),
                            kv("port", port),
                            kv("attempts", attempts),
                            kv("dropped", queue.len()),
                        ],
                    ));
                    for q in queue {
                        self.counters.neighbor_drops += 1;
                        let Some(from) = q.from else { continue };
                        if v6 {
                            self.icmp_error_v6(now, from, &q.packet, 1, 3, [0; 4], out);
                        } else {
                            // A packet translated on its way out is reported as it came in.
                            let packet = self.restore_source(port, from, q.packet);
                            self.icmp_error_v4(now, from, &packet, 3, 1, [0; 4], out);
                            self.drop_event("neighbor-unreachable", from, &packet, out);
                            continue;
                        }
                        self.drop_event("neighbor-unreachable", from, &q.packet, out);
                    }
                }
            }
        }
        let mut next = self.neigh.next_deadline();
        if let Some(nat) = self.nat.as_mut() {
            nat.expire(now, out);
            next = earliest(next, nat.next_deadline());
        }
        self.filter.expire(now);
        earliest(next, self.filter.next_deadline())
    }

    /// A port's carrier changed.
    pub fn link_state(&mut self, _now: u64, port: u32, up: bool, out: &mut impl Sink) {
        let Some(p) = self.ports.get_mut(port as usize) else {
            return;
        };
        if p.up == up {
            return;
        }
        p.up = up;
        out.event(Event::new(
            if up { "port-up" } else { "port-down" },
            vec![kv("port", port)],
        ));
        if up {
            if p.cfg.ra {
                self.send_ra(port, out);
            }
        } else {
            let dropped = self.neigh.flush_port(port);
            self.counters.neighbor_drops += dropped as u64;
        }
    }

    // ------------------------------------------------------------------------------------------
    // L2

    /// The NIC's receive filter.
    fn accepts(&self, port: u32, dst: MacAddr) -> bool {
        let p = &self.ports[port as usize];
        if dst == p.cfg.mac || dst.is_broadcast() {
            return true;
        }
        let o = dst.octets();
        if o[0] != 0x33 || o[1] != 0x33 {
            return false;
        }
        let all_nodes = wire::multicast_mac(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        let all_routers = wire::multicast_mac(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2));
        dst == all_nodes
            || dst == all_routers
            || p.v6_addrs()
                .any(|a| dst == wire::multicast_mac(wire::solicited_node(a)))
    }

    /// Transmits a frame and counts it.
    fn send_frame(&mut self, port: u32, frame: Vec<u8>, out: &mut impl Sink) {
        let p = &mut self.ports[port as usize];
        p.c.tx_frames += 1;
        p.c.tx_bytes += frame.len() as u64;
        self.counters.tx_frames += 1;
        self.counters.tx_bytes += frame.len() as u64;
        out.transmit(port, frame);
    }

    // ------------------------------------------------------------------------------------------
    // Neighbors

    fn arp_in(&mut self, now: u64, port: u32, payload: &[u8], out: &mut impl Sink) {
        let Ok(arp) = ArpPacketSlice::from_slice(payload) else {
            self.counters.malformed += 1;
            return;
        };
        if arp.hw_addr_type().0 != 1
            || arp.proto_addr_type().0 != ETHERTYPE_IPV4
            || arp.hw_addr_size() != 6
            || arp.proto_addr_size() != 4
        {
            self.counters.malformed += 1;
            return;
        }
        let (Some(sender_mac), Ok(sender_ip), Ok(target_ip)) = (
            MacAddr::from_slice(arp.sender_hw_addr()),
            <[u8; 4]>::try_from(arp.sender_protocol_addr()),
            <[u8; 4]>::try_from(arp.target_protocol_addr()),
        ) else {
            self.counters.malformed += 1;
            return;
        };
        let (sender_ip, target_ip) = (Ipv4Addr::from(sender_ip), Ipv4Addr::from(target_ip));
        let p = &self.ports[port as usize];
        let Some((mine, _)) = p.cfg.ipv4 else {
            return;
        };
        if !usable_v4(sender_ip) || !sender_mac.is_unicast() {
            // An ARP probe (sender 0.0.0.0) or junk: nothing to learn or answer.
            return;
        }
        let for_me = target_ip == mine;
        let resolved = self
            .neigh
            .learn(port, IpAddr::V4(sender_ip), sender_mac, now, for_me);
        if let Some(r) = resolved {
            self.resolved(now, port, IpAddr::V4(sender_ip), sender_mac, r, out);
        }
        if for_me && arp.operation().0 == 1 {
            let my_mac = self.ports[port as usize].cfg.mac;
            let reply = wire::arp(2, my_mac, mine, sender_mac, sender_ip);
            self.counters.arp_replies += 1;
            self.send_frame(
                port,
                wire::eth_frame(sender_mac, my_mac, ETHERTYPE_ARP, &reply),
                out,
            );
        }
    }

    /// A neighbor answered: report it and send what waited for it.
    fn resolved(
        &mut self,
        now: u64,
        port: u32,
        ip: IpAddr,
        mac: MacAddr,
        r: Resolved,
        out: &mut impl Sink,
    ) {
        let v6 = ip.is_ipv6();
        if v6 {
            self.counters.ndp_resolved += 1;
        } else {
            self.counters.arp_resolved += 1;
        }
        out.event(Event::new(
            if v6 { "ndp-resolved" } else { "arp-resolved" },
            vec![
                kv("ip", ip),
                kv("mac", mac),
                kv("port", port),
                kv("after-ns", now - r.asked_ns),
                kv("queued", r.queue.len()),
            ],
        ));
        let my_mac = self.ports[port as usize].cfg.mac;
        let ethertype = if v6 { ETHERTYPE_IPV6 } else { ETHERTYPE_IPV4 };
        for q in r.queue {
            self.send_frame(
                port,
                wire::eth_frame(mac, my_mac, ethertype, &q.packet),
                out,
            );
        }
    }

    /// Sends an ARP request or a Neighbor Solicitation for `ip` out of `port`.
    fn solicit(&mut self, port: u32, ip: IpAddr, out: &mut impl Sink) {
        let p = &self.ports[port as usize];
        let my_mac = p.cfg.mac;
        match ip {
            IpAddr::V4(target) => {
                // Without an IPv4 address on the port nobody can answer; the entry just fails.
                let Some((mine, _)) = p.cfg.ipv4 else { return };
                let req = wire::arp(1, my_mac, mine, MacAddr::ZERO, target);
                self.counters.arp_requests += 1;
                self.send_frame(
                    port,
                    wire::eth_frame(MacAddr::BROADCAST, my_mac, ETHERTYPE_ARP, &req),
                    out,
                );
            }
            IpAddr::V6(target) => {
                let src = p.cfg.link_local;
                let group = wire::solicited_node(target);
                let mut body = target.octets().to_vec();
                body.extend_from_slice(&wire::ll_option(1, my_mac));
                let icmp = wire::icmpv6(src, group, 135, 0, [0; 4], &body);
                let packet = wire::ipv6(src, group, PROTO_ICMPV6, 255, &icmp);
                self.counters.ns_sent += 1;
                self.send_frame(
                    port,
                    wire::eth_frame(wire::multicast_mac(group), my_mac, ETHERTYPE_IPV6, &packet),
                    out,
                );
            }
        }
    }

    /// Hands `packet` to `next_hop` on `port`, resolving its MAC first if needed.
    fn send_ip(
        &mut self,
        now: u64,
        port: u32,
        next_hop: IpAddr,
        packet: Vec<u8>,
        from: Option<u32>,
        out: &mut impl Sink,
    ) {
        let ethertype = if next_hop.is_ipv6() {
            ETHERTYPE_IPV6
        } else {
            ETHERTYPE_IPV4
        };
        if let Some(mac) = self.neigh.lookup(port, next_hop, now, &self.cfg.neighbor) {
            let my_mac = self.ports[port as usize].cfg.mac;
            self.send_frame(port, wire::eth_frame(mac, my_mac, ethertype, &packet), out);
            return;
        }
        let q = Queued { packet, from };
        match self
            .neigh
            .enqueue(port, next_hop, q, now, &self.cfg.neighbor)
        {
            Enqueued::Ask => self.solicit(port, next_hop, out),
            Enqueued::Waiting => {}
            Enqueued::Overflow(old) => {
                self.counters.queue_overflow += 1;
                if let Some(from) = old.from {
                    self.drop_event("queue-overflow", from, &old.packet, out);
                }
            }
        }
    }

    /// Routes and sends a packet the router built itself (to `dst`). A link-local IPv6
    /// destination is reached through `port` directly (it has no route).
    fn originate(
        &mut self,
        now: u64,
        port: u32,
        dst: IpAddr,
        packet: Vec<u8>,
        out: &mut impl Sink,
    ) {
        if let IpAddr::V6(a) = dst
            && is_link_local_v6(a)
        {
            self.send_ip(now, port, dst, packet, None, out);
            return;
        }
        let Some(route) = self.lookup(dst, out) else {
            self.counters.no_route += 1;
            return;
        };
        if !self.is_up(route.port) {
            self.counters.port_down_drops += 1;
            return;
        }
        let mut packet = packet;
        if self.is_outside(route.port) && packet.first().is_some_and(|b| b >> 4 == 4) {
            // An ICMP error about a packet the router translated on its way in leaves with the
            // quote as the remote sent it. Anything else it originates leaves as it is.
            let _ = self.translate_error_out(route.port, &mut packet);
        }
        self.send_ip(now, route.port, route.next_hop(dst), packet, None, out);
    }

    fn next_id(&mut self) -> u16 {
        self.ip_id = self.ip_id.wrapping_add(1);
        self.ip_id
    }

    // ------------------------------------------------------------------------------------------
    // Routing and tracing

    /// The route for `dst`, reported as `route-lookup` (per `trace.route-lookup`).
    fn lookup(&mut self, dst: IpAddr, out: &mut impl Sink) -> Option<Route> {
        let route = self.routes.lookup(dst).copied();
        let report = match self.cfg.trace_route_lookup {
            Trace::None => false,
            Trace::All => true,
            Trace::First => {
                if self.traced_dsts.contains(&dst) {
                    false
                } else if self.traced_dsts.len() >= TRACE_CAP {
                    self.counters.trace_suppressed += 1;
                    false
                } else {
                    self.traced_dsts.insert(dst)
                }
            }
        };
        if report {
            let mut fields = vec![kv("dst", dst)];
            match route {
                None => fields.push(kv("result", "no-route")),
                Some(r) => {
                    fields.push(kv("result", r.kind.name()));
                    fields.push(kv("prefix", r.prefix));
                    fields.push(kv(
                        "via",
                        r.via.map_or("on-link".to_owned(), |v| v.to_string()),
                    ));
                    fields.push(kv("port", r.port));
                }
            }
            out.event(Event::new("route-lookup", fields));
        }
        route
    }

    /// Reports a forwarded packet's TTL decrement (per `trace.ttl-decrement`).
    #[allow(clippy::too_many_arguments)]
    fn trace_ttl(
        &mut self,
        proto: u8,
        (src, dst): (IpAddr, IpAddr),
        l4: &[u8],
        ttl: u8,
        (from, to): (u32, u32),
        out: &mut impl Sink,
    ) {
        let ports = ports_of(proto, l4);
        let key = (
            proto,
            src,
            ports.map_or(0, |p| p.0),
            dst,
            ports.map_or(0, |p| p.1),
        );
        let report = match self.cfg.trace_ttl_decrement {
            Trace::None => false,
            Trace::All => true,
            Trace::First => {
                if self.traced_flows.contains(&key) {
                    false
                } else if self.traced_flows.len() >= TRACE_CAP {
                    self.counters.trace_suppressed += 1;
                    false
                } else {
                    self.traced_flows.insert(key)
                }
            }
        };
        if report {
            out.event(Event::new(
                "ttl-decrement",
                vec![
                    kv("proto", proto_name(proto)),
                    kv("src", endpoint(src, ports.map(|p| p.0))),
                    kv("dst", endpoint(dst, ports.map(|p| p.1))),
                    kv("ttl-in", ttl),
                    kv("ttl-out", ttl - 1),
                    kv("from-port", from),
                    kv("to-port", to),
                ],
            ));
        }
    }

    /// Reports a dropped IP packet (`forward-drop`) and counts it on its ingress port.
    fn drop_event(&mut self, reason: &str, port: u32, packet: &[u8], out: &mut impl Sink) {
        if let Some(p) = self.ports.get_mut(port as usize) {
            p.c.dropped += 1;
        }
        let (src, dst, proto) = match packet.first().map(|b| b >> 4) {
            Some(4) if packet.len() >= 20 => (
                IpAddr::V4(v4_src(packet)),
                IpAddr::V4(v4_dst(packet)),
                packet[9],
            ),
            Some(6) if packet.len() >= 40 => (
                IpAddr::V6(v6_at(packet, 8)),
                IpAddr::V6(v6_at(packet, 24)),
                packet[6],
            ),
            _ => return,
        };
        out.event(Event::new(
            "forward-drop",
            vec![
                kv("reason", reason),
                kv("src", src),
                kv("dst", dst),
                kv("proto", proto_name(proto)),
                kv("port", port),
            ],
        ));
    }

    // ------------------------------------------------------------------------------------------
    // DHCP relay agent (RFC 1542 §4)

    /// Handles a DHCP message for the relay agent: a client's BOOTREQUEST broadcast (or unicast
    /// to the port) on a port with `dhcp-relay`, or a server's BOOTREPLY to one of our `giaddr`s.
    /// Returns whether it was one (consumed here; it is never forwarded or answered with ICMP).
    fn dhcp_relay_in(&mut self, now: u64, port: u32, packet: &[u8], out: &mut impl Sink) -> bool {
        if packet[9] != PROTO_UDP || !self.relays() {
            return false;
        }
        let dst = v4_dst(packet);
        let udp = &packet[ihl(packet)..];
        let Some((_, dport)) = ports_of(PROTO_UDP, udp) else {
            return false;
        };
        let len = udp
            .get(4..6)
            .map_or(0, |l| usize::from(u16::from_be_bytes([l[0], l[1]])));
        let Some(payload) = udp.get(8..len.max(8)) else {
            return false;
        };
        if dport != dhcp::SERVER_PORT || payload.len() < dhcp::HEADER_LEN {
            return false;
        }
        let me = self.ports[port as usize].cfg.ipv4.map(|(a, _)| a);
        match payload[dhcp::offset::OP] {
            dhcp::BOOTREQUEST => {
                let servers = self.ports[port as usize].cfg.dhcp_relay.clone();
                let for_us =
                    dst.is_broadcast() || Some(dst) == me || self.is_directed_broadcast(dst);
                let (Some(me), false, true) = (me, servers.is_empty(), for_us) else {
                    return false;
                };
                self.relay_request(now, port, me, payload, &servers, out);
                true
            }
            dhcp::BOOTREPLY if self.is_mine_v4(dst) => {
                let giaddr = Ipv4Addr::from(
                    <[u8; 4]>::try_from(&payload[dhcp::offset::GIADDR..dhcp::offset::GIADDR + 4])
                        .unwrap_or([0; 4]),
                );
                let Some(to) = self.ports.iter().position(|p| {
                    p.cfg.ipv4.map(|(a, _)| a) == Some(giaddr) && !p.cfg.dhcp_relay.is_empty()
                }) else {
                    return false;
                };
                self.relay_reply(to as u32, giaddr, payload, out);
                true
            }
            _ => false,
        }
    }

    /// Any port relays DHCP.
    fn relays(&self) -> bool {
        self.ports.iter().any(|p| !p.cfg.dhcp_relay.is_empty())
    }

    /// Client → server: `giaddr` (if unset) becomes the port's address, `hops` + 1, and the
    /// message goes to every configured server from the egress port's address, UDP 67 → 67.
    #[allow(clippy::too_many_arguments)]
    fn relay_request(
        &mut self,
        now: u64,
        port: u32,
        me: Ipv4Addr,
        payload: &[u8],
        servers: &[Ipv4Addr],
        out: &mut impl Sink,
    ) {
        let mut msg = payload.to_vec();
        let hops = msg[dhcp::offset::HOPS];
        if hops >= MAX_DHCP_HOPS {
            self.counters.dhcp_relay_dropped += 1;
            self.relay_event("dropped", port, &msg, "", out);
            return;
        }
        msg[dhcp::offset::HOPS] = hops + 1;
        let g = dhcp::offset::GIADDR;
        if msg[g..g + 4] == [0; 4] {
            msg[g..g + 4].copy_from_slice(&me.octets());
        }
        for &server in servers {
            let Some(route) = self.lookup(IpAddr::V4(server), out) else {
                self.counters.no_route += 1;
                continue;
            };
            let from = self.ports[route.port as usize]
                .cfg
                .ipv4
                .map_or(me, |(a, _)| a);
            let id = self.next_id();
            let datagram = wire::udp_v4(from, server, dhcp::SERVER_PORT, dhcp::SERVER_PORT, &msg);
            let p = wire::ipv4(from, server, PROTO_UDP, self.cfg.ttl, id, &datagram);
            self.counters.dhcp_relayed_to_server += 1;
            self.relay_event("to-server", port, &msg, &server.to_string(), out);
            self.originate(now, port, IpAddr::V4(server), p, out);
        }
    }

    /// Server → client, on the port that owns `giaddr`: broadcast if the client asked for it (or
    /// the reply has no address, a NAK), else unicast to `yiaddr` at `chaddr` without ARP (the
    /// client cannot answer one yet). UDP 67 → 68, from `giaddr`.
    fn relay_reply(&mut self, port: u32, giaddr: Ipv4Addr, payload: &[u8], out: &mut impl Sink) {
        let o = dhcp::offset::YIADDR;
        let yiaddr = Ipv4Addr::from(<[u8; 4]>::try_from(&payload[o..o + 4]).unwrap_or([0; 4]));
        let flags = u16::from_be_bytes([
            payload[dhcp::offset::FLAGS],
            payload[dhcp::offset::FLAGS + 1],
        ]);
        let chaddr =
            MacAddr::from_slice(&payload[dhcp::offset::CHADDR..]).unwrap_or(MacAddr::BROADCAST);
        let broadcast = flags & dhcp::FLAG_BROADCAST != 0 || yiaddr.is_unspecified();
        let (dst_ip, dst_mac) = if broadcast {
            (Ipv4Addr::BROADCAST, MacAddr::BROADCAST)
        } else {
            (yiaddr, chaddr)
        };
        if !self.is_up(port) {
            self.counters.port_down_drops += 1;
            return;
        }
        let id = self.next_id();
        let datagram = wire::udp_v4(
            giaddr,
            dst_ip,
            dhcp::SERVER_PORT,
            dhcp::CLIENT_PORT,
            payload,
        );
        let p = wire::ipv4(giaddr, dst_ip, PROTO_UDP, self.cfg.ttl, id, &datagram);
        let my_mac = self.ports[port as usize].cfg.mac;
        self.counters.dhcp_relayed_to_client += 1;
        self.relay_event("to-client", port, payload, &dst_ip.to_string(), out);
        self.send_frame(
            port,
            wire::eth_frame(dst_mac, my_mac, ETHERTYPE_IPV4, &p),
            out,
        );
    }

    /// `dhcp-relayed {direction, port, xid, type, mac, to}`.
    fn relay_event(
        &mut self,
        direction: &str,
        port: u32,
        msg: &[u8],
        to: &str,
        out: &mut impl Sink,
    ) {
        let parsed = dhcp::Message::parse(msg).ok();
        let kind = parsed
            .as_ref()
            .and_then(dhcp::Message::message_type)
            .map_or("bootp", dhcp::MessageType::name);
        let mac = parsed
            .as_ref()
            .and_then(dhcp::Message::client_mac)
            .map(|m| m.to_string())
            .unwrap_or_default();
        let xid = parsed.map_or(0, |m| m.xid);
        out.event(Event::new(
            "dhcp-relayed",
            vec![
                kv("direction", direction),
                kv("port", port),
                kv("type", kind),
                kv("xid", format!("{xid:08x}")),
                kv("mac", mac),
                kv("to", to),
            ],
        ));
    }

    // ------------------------------------------------------------------------------------------
    // IPv4

    fn is_mine_v4(&self, a: Ipv4Addr) -> bool {
        self.ports
            .iter()
            .any(|p| p.cfg.ipv4.is_some_and(|(m, _)| m == a))
    }

    fn is_directed_broadcast(&self, a: Ipv4Addr) -> bool {
        self.ports.iter().any(|p| {
            p.cfg
                .ipv4
                .and_then(|(m, l)| Prefix::V4(u32::from(m), l).broadcast())
                == Some(a)
        })
    }

    fn ipv4_in(&mut self, now: u64, port: u32, payload: &[u8], out: &mut impl Sink) {
        let Ok(h) = Ipv4HeaderSlice::from_slice(payload) else {
            self.counters.malformed += 1;
            return;
        };
        let total = usize::from(h.total_len());
        if total < h.slice().len() || total > payload.len() {
            self.counters.malformed += 1;
            return;
        }
        // Ethernet padding ends here.
        let packet = &payload[..total];
        if wire::checksum(h.slice()) != 0 {
            self.counters.bad_checksum += 1;
            self.drop_event("bad-checksum", port, packet, out);
            return;
        }
        let (src, dst) = (h.source_addr(), h.destination_addr());
        // Before the source check: a DHCP client's request comes from 0.0.0.0.
        if self.dhcp_relay_in(now, port, packet, out) {
            return;
        }
        if !usable_v4(src) {
            self.counters.martian += 1;
            return;
        }
        if self.is_mine_v4(dst) {
            let outside = self.nat.as_ref().and_then(|n| n.port_with_addr(dst));
            let taken = match outside {
                Some(w) if w == port => self.nat_in(now, port, packet, out),
                Some(w) if !self.is_outside(port) => self.hairpin(now, port, w, packet, out),
                _ => false,
            };
            if !taken {
                self.local_v4(now, port, packet, out);
            }
        } else if dst.is_broadcast()
            || dst.is_multicast()
            || dst.is_unspecified()
            || dst.is_loopback()
            || self.is_directed_broadcast(dst)
        {
            self.counters.not_forwarded += 1;
        } else {
            self.forward_v4(now, port, packet.to_vec(), out);
        }
    }

    fn forward_v4(&mut self, now: u64, from: u32, mut packet: Vec<u8>, out: &mut impl Sink) {
        let (src, dst, ttl, proto) = (v4_src(&packet), v4_dst(&packet), packet[8], packet[9]);
        if ttl <= 1 {
            self.counters.ttl_expired += 1;
            self.icmp_error_v4(now, from, &packet, 11, 0, [0; 4], out);
            self.drop_event("ttl-exceeded", from, &packet, out);
            return;
        }
        let Some(route) = self.lookup(IpAddr::V4(dst), out) else {
            self.counters.no_route += 1;
            self.icmp_error_v4(now, from, &packet, 3, 0, [0; 4], out);
            self.drop_event("no-route", from, &packet, out);
            return;
        };
        if !self.is_up(route.port) {
            self.counters.port_down_drops += 1;
            self.icmp_error_v4(now, from, &packet, 3, 0, [0; 4], out);
            self.drop_event("port-down", from, &packet, out);
            return;
        }
        let mtu = self.ports[route.port as usize].cfg.mtu;
        if packet.len() > usize::from(mtu) {
            let df = packet[6] & 0x40 != 0;
            if df {
                self.counters.frag_needed += 1;
                let [hi, lo] = mtu.to_be_bytes();
                self.icmp_error_v4(now, from, &packet, 3, 4, [0, 0, hi, lo], out);
                self.drop_event("frag-needed", from, &packet, out);
            } else {
                // Fragmentation is not implemented: drop it, visibly.
                self.counters.frag_unsupported += 1;
                self.drop_event("fragmentation-unsupported", from, &packet, out);
            }
            return;
        }
        if !self.filter_ok(now, from, &packet, out) {
            return;
        }
        let l4 = &packet[ihl(&packet)..];
        let l4 = l4.get(..4).unwrap_or(l4).to_vec();
        if self.is_outside(route.port)
            && !self.is_outside(from)
            && let Err(reason) = self.translate_out(now, route.port, &mut packet, out)
        {
            self.drop_event(reason, from, &packet, out);
            return;
        }
        wire::decrement_ttl_v4(&mut packet);
        self.trace_ttl(
            proto,
            (IpAddr::V4(src), IpAddr::V4(dst)),
            &l4,
            ttl,
            (from, route.port),
            out,
        );
        self.counters.forwarded_v4 += 1;
        self.ports[from as usize].c.forwarded_in += 1;
        self.ports[route.port as usize].c.forwarded_out += 1;
        self.send_ip(
            now,
            route.port,
            route.next_hop(IpAddr::V4(dst)),
            packet,
            Some(from),
            out,
        );
    }

    fn local_v4(&mut self, now: u64, port: u32, packet: &[u8], out: &mut impl Sink) {
        self.counters.local_v4 += 1;
        let fragment =
            packet[6] & 0x20 != 0 || u16::from_be_bytes([packet[6] & 0x1f, packet[7]]) != 0;
        if fragment {
            // No reassembly for the router's own traffic.
            return;
        }
        let (src, dst) = (v4_src(packet), v4_dst(packet));
        let body = &packet[ihl(packet)..];
        match packet[9] {
            PROTO_ICMP => {
                if body.len() >= 8 && body[0] == 8 && wire::checksum(body) == 0 {
                    let mut rest = [0u8; 4];
                    rest.copy_from_slice(&body[4..8]);
                    let reply = wire::icmpv4(0, 0, rest, &body[8..]);
                    let id = self.next_id();
                    let p = wire::ipv4(dst, src, PROTO_ICMP, self.cfg.ttl, id, &reply);
                    self.counters.echo_replies += 1;
                    self.originate(now, port, IpAddr::V4(src), p, out);
                }
            }
            PROTO_UDP => self.icmp_error_v4(now, port, packet, 3, 3, [0; 4], out),
            PROTO_TCP => {
                if let Some((seq, ack, flags)) = wire::rst_for(body)
                    && let Some((sport, dport)) = ports_of(PROTO_TCP, body)
                {
                    let pseudo = wire::pseudo_v4(dst, src, PROTO_TCP, 20);
                    let seg = wire::tcp_segment(dport, sport, seq, ack, flags, pseudo);
                    let id = self.next_id();
                    let p = wire::ipv4(dst, src, PROTO_TCP, self.cfg.ttl, id, &seg);
                    self.counters.tcp_resets += 1;
                    self.originate(now, port, IpAddr::V4(src), p, out);
                }
            }
            _ => self.icmp_error_v4(now, port, packet, 3, 2, [0; 4], out),
        }
    }

    /// Sends an ICMPv4 error about `offending` (as received, or as queued) back to its source.
    #[allow(clippy::too_many_arguments)]
    fn icmp_error_v4(
        &mut self,
        now: u64,
        port: u32,
        offending: &[u8],
        icmp_type: u8,
        code: u8,
        rest: [u8; 4],
        out: &mut impl Sink,
    ) {
        let (src, dst) = (v4_src(offending), v4_dst(offending));
        let header = ihl(offending);
        let non_initial = u16::from_be_bytes([offending[6] & 0x1f, offending[7]]) != 0;
        let about_error = offending[9] == PROTO_ICMP
            && offending.get(header).is_some_and(|&t| is_icmpv4_error(t));
        let me = self.ports[port as usize]
            .cfg
            .ipv4
            .or_else(|| self.ports.iter().find_map(|p| p.cfg.ipv4))
            .map(|(a, _)| a);
        let Some(me) = me.filter(|_| {
            usable_v4(src)
                && !(dst.is_multicast() || dst.is_broadcast() || self.is_directed_broadcast(dst))
                && !non_initial
                && !about_error
        }) else {
            self.counters.icmp_errors_suppressed += 1;
            return;
        };
        let quote = &offending[..offending.len().min(ICMPV4_ERROR_MAX - 28)];
        let icmp = wire::icmpv4(icmp_type, code, rest, quote);
        let id = self.next_id();
        let packet = wire::ipv4(me, src, PROTO_ICMP, self.cfg.ttl, id, &icmp);
        self.icmp_error_event(
            false,
            icmp_type,
            code,
            IpAddr::V4(me),
            IpAddr::V4(src),
            offending,
            header,
            out,
        );
        self.originate(now, port, IpAddr::V4(src), packet, out);
    }

    #[allow(clippy::too_many_arguments)]
    fn icmp_error_event(
        &mut self,
        v6: bool,
        icmp_type: u8,
        code: u8,
        from: IpAddr,
        to: IpAddr,
        offending: &[u8],
        l4_at: usize,
        out: &mut impl Sink,
    ) {
        self.counters.icmp_errors_sent += 1;
        let (proto, dst) = if v6 {
            (offending[6], IpAddr::V6(v6_at(offending, 24)))
        } else {
            (offending[9], IpAddr::V4(v4_dst(offending)))
        };
        let l4 = offending.get(l4_at..).unwrap_or(&[]);
        let dport = ports_of(proto, l4).map(|p| p.1);
        out.event(Event::new(
            "icmp-error-sent",
            vec![
                kv("error", error_name(v6, icmp_type, code)),
                kv("icmp-type", icmp_type),
                kv("icmp-code", code),
                kv("from", from),
                kv("to", to),
                kv("about", endpoint(dst, dport)),
                kv("proto", proto_name(proto)),
            ],
        ));
    }

    // ------------------------------------------------------------------------------------------
    // IPv6

    fn is_mine_v6(&self, port: u32, a: Ipv6Addr) -> bool {
        if self
            .ports
            .iter()
            .any(|p| p.cfg.ipv6.is_some_and(|(m, _)| m == a))
        {
            return true;
        }
        let p = &self.ports[port as usize];
        a == p.cfg.link_local
            || a == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
            || a == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2)
            || p.v6_addrs().any(|m| a == wire::solicited_node(m))
    }

    fn ipv6_in(
        &mut self,
        now: u64,
        port: u32,
        eth_src: MacAddr,
        payload: &[u8],
        out: &mut impl Sink,
    ) {
        let Ok(h) = Ipv6HeaderSlice::from_slice(payload) else {
            self.counters.malformed += 1;
            return;
        };
        let total = 40 + usize::from(h.payload_length());
        if total > payload.len() {
            self.counters.malformed += 1;
            return;
        }
        let packet = &payload[..total];
        let (src, dst) = (h.source_addr(), h.destination_addr());
        if src.is_multicast() || src.is_loopback() {
            self.counters.martian += 1;
            return;
        }
        if self.is_mine_v6(port, dst) {
            self.local_v6(now, port, eth_src, packet, out);
        } else if dst.is_multicast() || dst.is_unspecified() || dst.is_loopback() {
            self.counters.not_forwarded += 1;
        } else if src.is_unspecified() {
            self.counters.martian += 1;
        } else if is_link_local_v6(dst) {
            self.counters.scope_drops += 1;
            self.drop_event("scope", port, packet, out);
        } else {
            self.forward_v6(now, port, packet.to_vec(), out);
        }
    }

    fn forward_v6(&mut self, now: u64, from: u32, mut packet: Vec<u8>, out: &mut impl Sink) {
        let (src, dst, hops, next) = (v6_at(&packet, 8), v6_at(&packet, 24), packet[7], packet[6]);
        if is_link_local_v6(src) {
            // A link-local source must not leave its link (RFC 4443 code 2).
            self.counters.scope_drops += 1;
            self.icmp_error_v6(now, from, &packet, 1, 2, [0; 4], out);
            self.drop_event("scope", from, &packet, out);
            return;
        }
        if hops <= 1 {
            self.counters.ttl_expired += 1;
            self.icmp_error_v6(now, from, &packet, 3, 0, [0; 4], out);
            self.drop_event("ttl-exceeded", from, &packet, out);
            return;
        }
        let Some(route) = self.lookup(IpAddr::V6(dst), out) else {
            self.counters.no_route += 1;
            self.icmp_error_v6(now, from, &packet, 1, 0, [0; 4], out);
            self.drop_event("no-route", from, &packet, out);
            return;
        };
        if !self.is_up(route.port) {
            self.counters.port_down_drops += 1;
            self.icmp_error_v6(now, from, &packet, 1, 0, [0; 4], out);
            self.drop_event("port-down", from, &packet, out);
            return;
        }
        let mtu = self.ports[route.port as usize].cfg.mtu;
        if packet.len() > usize::from(mtu) {
            self.counters.too_big += 1;
            let rest = u32::from(mtu).to_be_bytes();
            self.icmp_error_v6(now, from, &packet, 2, 0, rest, out);
            self.drop_event("packet-too-big", from, &packet, out);
            return;
        }
        if !self.filter_ok(now, from, &packet, out) {
            return;
        }
        packet[7] -= 1;
        let l4 = packet.get(40..44).unwrap_or(&[]).to_vec();
        self.trace_ttl(
            next,
            (IpAddr::V6(src), IpAddr::V6(dst)),
            &l4,
            hops,
            (from, route.port),
            out,
        );
        self.counters.forwarded_v6 += 1;
        self.ports[from as usize].c.forwarded_in += 1;
        self.ports[route.port as usize].c.forwarded_out += 1;
        self.send_ip(
            now,
            route.port,
            route.next_hop(IpAddr::V6(dst)),
            packet,
            Some(from),
            out,
        );
    }

    fn local_v6(
        &mut self,
        now: u64,
        port: u32,
        eth_src: MacAddr,
        packet: &[u8],
        out: &mut impl Sink,
    ) {
        self.counters.local_v6 += 1;
        let Ok(s) = Ipv6Slice::from_slice(packet) else {
            self.counters.malformed += 1;
            return;
        };
        let (src, dst, hops) = (v6_at(packet, 8), v6_at(packet, 24), packet[7]);
        let upper = s.payload();
        if upper.fragmented {
            return;
        }
        let body = upper.payload;
        let unicast = !dst.is_multicast();
        match upper.ip_number.0 {
            PROTO_ICMPV6 => self.icmpv6_in(now, port, eth_src, (src, dst, hops), body, out),
            PROTO_UDP if unicast => self.icmp_error_v6(now, port, packet, 1, 4, [0; 4], out),
            PROTO_TCP if unicast => {
                if let Some((seq, ack, flags)) = wire::rst_for(body)
                    && let Some((sport, dport)) = ports_of(PROTO_TCP, body)
                {
                    let pseudo = wire::pseudo_v6(dst, src, PROTO_TCP, 20);
                    let seg = wire::tcp_segment(dport, sport, seq, ack, flags, pseudo);
                    let p = wire::ipv6(dst, src, PROTO_TCP, self.cfg.ttl, &seg);
                    self.counters.tcp_resets += 1;
                    self.originate(now, port, IpAddr::V6(src), p, out);
                }
            }
            // An unknown upper layer right after the fixed header: parameter problem, pointing
            // at its Next Header field (offset 6).
            n if unicast && n == packet[6] && n != 59 => {
                self.icmp_error_v6(now, port, packet, 4, 1, [0, 0, 0, 6], out)
            }
            _ => {}
        }
    }

    fn icmpv6_in(
        &mut self,
        now: u64,
        port: u32,
        eth_src: MacAddr,
        (src, dst, hops): (Ipv6Addr, Ipv6Addr, u8),
        body: &[u8],
        out: &mut impl Sink,
    ) {
        if body.len() < 8
            || wire::finish(wire::sum16(
                body,
                wire::pseudo_v6(src, dst, PROTO_ICMPV6, body.len()),
            )) != 0
        {
            self.counters.bad_checksum += 1;
            return;
        }
        let my_mac = self.ports[port as usize].cfg.mac;
        match body[0] {
            128 if body[1] == 0 => {
                // Echo request → reply, from the address it was sent to (or, for a group, from
                // the port's address of the requester's scope).
                let me = if dst.is_multicast() {
                    match self.ports[port as usize].cfg.ipv6 {
                        Some((g, _)) if !is_link_local_v6(src) => g,
                        _ => self.ports[port as usize].cfg.link_local,
                    }
                } else {
                    dst
                };
                let mut rest = [0u8; 4];
                rest.copy_from_slice(&body[4..8]);
                let icmp = wire::icmpv6(me, src, 129, 0, rest, &body[8..]);
                let p = wire::ipv6(me, src, PROTO_ICMPV6, self.cfg.ttl, &icmp);
                self.counters.echo_replies += 1;
                self.originate(now, port, IpAddr::V6(src), p, out);
            }
            133 if hops == 255 && self.ports[port as usize].cfg.ra => self.send_ra(port, out),
            135 if hops == 255 && body[1] == 0 && body.len() >= 24 => {
                let target = v6_at(body, 8);
                if !self.ports[port as usize].v6_addrs().any(|a| a == target) {
                    return;
                }
                let slla = wire::find_ll_option(&body[24..], 1);
                if src.is_unspecified() {
                    // Duplicate address detection for one of our addresses: defend it.
                    self.send_na(port, target, None, my_mac, out);
                    return;
                }
                let mac = slla.unwrap_or(eth_src);
                if let Some(r) = self.neigh.learn(port, IpAddr::V6(src), mac, now, true) {
                    self.resolved(now, port, IpAddr::V6(src), mac, r, out);
                }
                self.send_na(port, target, Some((src, mac)), my_mac, out);
            }
            136 if hops == 255 && body[1] == 0 && body.len() >= 24 => {
                let target = v6_at(body, 8);
                let mac = wire::find_ll_option(&body[24..], 2).unwrap_or(eth_src);
                if let Some(r) = self.neigh.learn(port, IpAddr::V6(target), mac, now, false) {
                    self.resolved(now, port, IpAddr::V6(target), mac, r, out);
                }
            }
            _ => {}
        }
    }

    /// A Neighbor Advertisement for our `target`: solicited and unicast to `to`, or (DAD
    /// defence) unsolicited to all nodes.
    fn send_na(
        &mut self,
        port: u32,
        target: Ipv6Addr,
        to: Option<(Ipv6Addr, MacAddr)>,
        my_mac: MacAddr,
        out: &mut impl Sink,
    ) {
        let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let (dst, dst_mac, flags) = match to {
            Some((ip, mac)) => (ip, mac, 0xe0), // router, solicited, override
            None => (all_nodes, wire::multicast_mac(all_nodes), 0xa0), // router, override
        };
        let mut body = target.octets().to_vec();
        body.extend_from_slice(&wire::ll_option(2, my_mac));
        let icmp = wire::icmpv6(target, dst, 136, 0, [flags, 0, 0, 0], &body);
        let packet = wire::ipv6(target, dst, PROTO_ICMPV6, 255, &icmp);
        self.counters.na_sent += 1;
        self.send_frame(
            port,
            wire::eth_frame(dst_mac, my_mac, ETHERTYPE_IPV6, &packet),
            out,
        );
    }

    /// A Router Advertisement on `port` to all nodes: this router as a default router (1800 s),
    /// the port's MTU and its global prefix (on-link, autonomous).
    fn send_ra(&mut self, port: u32, out: &mut impl Sink) {
        let p = &self.ports[port as usize].cfg;
        let Some((global, len)) = p.ipv6 else { return };
        let (src, mac, mtu) = (p.link_local, p.mac, p.mtu);
        let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let prefix = Prefix::V6(u128::from(global), len).masked();
        let Prefix::V6(prefix_bits, _) = prefix else {
            return;
        };
        let mut body = Vec::new();
        body.extend_from_slice(&[0; 8]); // reachable time, retrans timer: unspecified
        body.extend_from_slice(&wire::ll_option(1, mac));
        body.extend_from_slice(&[5, 1, 0, 0]);
        body.extend_from_slice(&u32::from(mtu).to_be_bytes());
        body.extend_from_slice(&[3, 4, len, 0xc0]);
        body.extend_from_slice(&2_592_000u32.to_be_bytes()); // valid lifetime: 30 days
        body.extend_from_slice(&604_800u32.to_be_bytes()); // preferred lifetime: 7 days
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&prefix_bits.to_be_bytes());
        let icmp = wire::icmpv6(src, all_nodes, 134, 0, [64, 0, 0x07, 0x08], &body);
        let packet = wire::ipv6(src, all_nodes, PROTO_ICMPV6, 255, &icmp);
        self.counters.ra_sent += 1;
        self.send_frame(
            port,
            wire::eth_frame(wire::multicast_mac(all_nodes), mac, ETHERTYPE_IPV6, &packet),
            out,
        );
    }

    /// Sends an ICMPv6 error about `offending` back to its source.
    #[allow(clippy::too_many_arguments)]
    fn icmp_error_v6(
        &mut self,
        now: u64,
        port: u32,
        offending: &[u8],
        icmp_type: u8,
        code: u8,
        rest: [u8; 4],
        out: &mut impl Sink,
    ) {
        let (src, dst) = (v6_at(offending, 8), v6_at(offending, 24));
        // An error about an ICMPv6 error (types below 128) is never sent; this checks the
        // common case of no extension headers.
        let about_error =
            offending[6] == PROTO_ICMPV6 && offending.get(40).is_some_and(|&t| t < 128);
        let group_ok = icmp_type == 2 || (icmp_type == 4 && code == 2);
        let p = &self.ports[port as usize];
        let me = if is_link_local_v6(src) {
            Some(p.cfg.link_local)
        } else {
            p.cfg
                .ipv6
                .or_else(|| self.ports.iter().find_map(|q| q.cfg.ipv6))
                .map(|(a, _)| a)
        };
        let Some(me) = me.filter(|_| {
            !(src.is_unspecified() || src.is_multicast())
                && (!dst.is_multicast() || group_ok)
                && !about_error
        }) else {
            self.counters.icmp_errors_suppressed += 1;
            return;
        };
        let quote = &offending[..offending.len().min(ICMPV6_ERROR_MAX - 48)];
        let icmp = wire::icmpv6(me, src, icmp_type, code, rest, quote);
        let packet = wire::ipv6(me, src, PROTO_ICMPV6, self.cfg.ttl, &icmp);
        self.icmp_error_event(
            true,
            icmp_type,
            code,
            IpAddr::V6(me),
            IpAddr::V6(src),
            offending,
            40,
            out,
        );
        self.originate(now, port, IpAddr::V6(src), packet, out);
    }

    // ------------------------------------------------------------------------------------------
    // The packet filter and address translation (`docs/design/nat.md`)

    /// Whether the filter lets a packet that arrived on `from` be forwarded. Always true on a
    /// router without rules.
    fn filter_ok(&mut self, now: u64, from: u32, packet: &[u8], out: &mut impl Sink) -> bool {
        if !self.filter.active() {
            return true;
        }
        let Some(t) = track::tuple(packet) else {
            // A transport header too short to read: nothing a rule or a flow could match.
            self.filter.counters.dropped += 1;
            return false;
        };
        self.filter.check(now, from, &t, out)
    }

    /// Translates the source of a packet leaving through outside port `port` (from an inside
    /// port): a TCP, UDP or ICMP echo packet gets its mapping's external endpoint, an ICMP error
    /// about a packet that came in through a mapping gets its quote translated back. `Err` is
    /// the `forward-drop` reason.
    fn translate_out(
        &mut self,
        now: u64,
        port: u32,
        packet: &mut [u8],
        out: &mut impl Sink,
    ) -> Result<(), &'static str> {
        let Some(nat) = self.nat.as_mut() else {
            return Ok(());
        };
        let addr = nat.addr(port).ok_or("nat-no-mapping")?;
        let l4 = packet.len() - ihl(packet);
        let Some(t) = track::tuple(packet) else {
            nat.counters.malformed += 1;
            return Err("nat-malformed");
        };
        match t.kind {
            Kind::Fragment => {
                nat.counters.fragments += 1;
                Err("nat-fragment")
            }
            Kind::Error(_) => self.translate_error_out(port, packet).map_err(|r| {
                if let Some(n) = self.nat.as_mut() {
                    n.counters.no_mapping += 1;
                }
                r.reason()
            }),
            Kind::Plain => {
                let (p, src, sport, dst, dport) = t.key;
                let (Some(src), Some(dst)) = (v4_of(src), v4_of(dst)) else {
                    return Err("nat-unsupported");
                };
                let (proto, internal, remote) = match p {
                    PROTO_UDP | PROTO_TCP if l4 < if p == PROTO_UDP { 8 } else { 20 } => {
                        nat.counters.malformed += 1;
                        return Err("nat-malformed");
                    }
                    PROTO_UDP => (Proto::Udp, (src, sport), (dst, dport)),
                    PROTO_TCP => (Proto::Tcp, (src, sport), (dst, dport)),
                    PROTO_ICMP if packet[ihl(packet)] == 8 => (Proto::Icmp, (src, sport), (dst, 0)),
                    _ => {
                        nat.counters.unsupported += 1;
                        return Err("nat-unsupported");
                    }
                };
                let ext = nat
                    .outbound(now, port, proto, internal, remote, t.flags, out)
                    .map_err(Refusal::reason)?;
                wire::rewrite_v4(packet, Side::Src, addr, ext);
                Ok(())
            }
        }
    }

    /// An ICMPv4 error leaving through outside port `port` about a packet a remote sent through
    /// a mapping (its quote's destination is the inside endpoint): the quote's destination and
    /// the error's source become the outside address and the external port. `Err` when no
    /// mapping talked to that remote (the packet is left as it is).
    fn translate_error_out(&mut self, port: u32, packet: &mut [u8]) -> Result<(), Refusal> {
        let nat = self.nat.as_mut().ok_or(Refusal::NoMapping)?;
        let addr = nat.addr(port).ok_or(Refusal::NoMapping)?;
        let Some(Kind::Error((p, rsrc, rport, idst, iport))) = track::tuple(packet).map(|t| t.kind)
        else {
            return Err(Refusal::NoMapping);
        };
        let (Some(proto), Some(remote), Some(internal)) =
            (Proto::from_number(p), v4_of(rsrc), v4_of(idst))
        else {
            return Err(Refusal::NoMapping);
        };
        if proto == Proto::Icmp {
            return Err(Refusal::NoMapping);
        }
        let ext = nat
            .error_out(port, proto, (internal, iport), (remote, rport))
            .ok_or(Refusal::NoMapping)?;
        let quote = ihl(packet) + 8;
        wire::rewrite_v4(&mut packet[quote..], Side::Dst, addr, ext);
        wire::rewrite_v4(packet, Side::Src, addr, 0);
        refresh_icmp_checksum(packet);
        nat.counters.icmp_errors_translated += 1;
        Ok(())
    }

    /// A packet from the outside to outside port `port`'s own address: translated to the inside
    /// endpoint of its mapping and forwarded, or dropped. Returns `false` for what stays the
    /// router's own (echo requests, other protocols, ICMP errors about no mapping).
    fn nat_in(&mut self, now: u64, port: u32, packet: &[u8], out: &mut impl Sink) -> bool {
        let Some(nat) = self.nat.as_mut() else {
            return false;
        };
        let at = ihl(packet);
        let l4 = packet.len() - at;
        let Some(t) = track::tuple(packet) else {
            nat.counters.malformed += 1;
            return true;
        };
        let (p, src, sport, _, dport) = t.key;
        let Some(src) = v4_of(src) else {
            return false;
        };
        let (proto, ext, remote) = match t.kind {
            Kind::Fragment => {
                nat.counters.fragments += 1;
                return true;
            }
            Kind::Error(inner) => return self.nat_error_in(now, port, packet, inner, out),
            Kind::Plain => match p {
                PROTO_UDP | PROTO_TCP if l4 < if p == PROTO_UDP { 8 } else { 20 } => {
                    nat.counters.malformed += 1;
                    return true;
                }
                PROTO_UDP => (Proto::Udp, dport, (src, sport)),
                PROTO_TCP => (Proto::Tcp, dport, (src, sport)),
                PROTO_ICMP if packet[at] == 0 => (Proto::Icmp, dport, (src, 0)),
                _ => return false,
            },
        };
        if nat.peek(proto, port, ext).is_none() {
            // Unsolicited: dropped without an answer (RFC 5382 REQ-4 for TCP).
            nat.counters.no_mapping += 1;
            return true;
        }
        if packet[8] <= 1 {
            self.counters.ttl_expired += 1;
            self.icmp_error_v4(now, port, packet, 11, 0, [0; 4], out);
            self.drop_event("ttl-exceeded", port, packet, out);
            return true;
        }
        match nat.inbound(now, port, proto, ext, remote, t.flags, out) {
            Ok(internal) => {
                let mut p = packet.to_vec();
                wire::rewrite_v4(&mut p, Side::Dst, internal.0, internal.1);
                self.forward_v4(now, port, p, out);
            }
            Err(Refusal::Filtered) => {}
            Err(r) => self.drop_event(r.reason(), port, packet, out),
        }
        true
    }

    /// An ICMP error to the outside address about a packet that left through a mapping: it goes
    /// to the inside endpoint, its quote and destination rewritten.
    fn nat_error_in(
        &mut self,
        now: u64,
        port: u32,
        packet: &[u8],
        (p, isrc, isport, idst, idport): track::FlowKey,
        out: &mut impl Sink,
    ) -> bool {
        let Some(nat) = self.nat.as_mut() else {
            return false;
        };
        let (Some(proto), Some(isrc), Some(idst)) =
            (Proto::from_number(p), v4_of(isrc), v4_of(idst))
        else {
            return false;
        };
        if Some(isrc) != nat.addr(port) {
            return false;
        }
        let remote = (idst, if proto == Proto::Icmp { 0 } else { idport });
        let Some(internal) = nat.error_in(port, proto, isport, remote) else {
            return false;
        };
        let mut pkt = packet.to_vec();
        let quote = ihl(&pkt) + 8;
        wire::rewrite_v4(&mut pkt[quote..], Side::Src, internal.0, internal.1);
        wire::rewrite_v4(&mut pkt, Side::Dst, internal.0, 0);
        refresh_icmp_checksum(&mut pkt);
        nat.counters.icmp_errors_translated += 1;
        self.forward_v4(now, port, pkt, out);
        true
    }

    /// A packet from inside port `from` to outside port `w`'s address: when a mapping holds its
    /// destination port it is hairpinned to that mapping's inside endpoint, from the sender's
    /// own external endpoint (or refused, with `nat.hairpin = false`). Returns `false` for the
    /// router's own traffic.
    fn hairpin(&mut self, now: u64, from: u32, w: u32, packet: &[u8], out: &mut impl Sink) -> bool {
        let Some(nat) = self.nat.as_mut() else {
            return false;
        };
        let l4 = packet.len() - ihl(packet);
        let Some(t) = track::tuple(packet).filter(|t| t.kind == Kind::Plain) else {
            return false;
        };
        let (p, src, sport, _, dport) = t.key;
        let (proto, Some(src), Some(addr)) = (
            match p {
                PROTO_UDP if l4 >= 8 => Proto::Udp,
                PROTO_TCP if l4 >= 20 => Proto::Tcp,
                _ => return false,
            },
            v4_of(src),
            nat.addr(w),
        ) else {
            return false;
        };
        if nat.peek(proto, w, dport).is_none() {
            return false;
        }
        if !nat.config().hairpin {
            nat.counters.hairpin_refused += 1;
            self.drop_event("nat-hairpin-refused", from, packet, out);
            return true;
        }
        if packet[8] <= 1 {
            self.counters.ttl_expired += 1;
            self.icmp_error_v4(now, from, packet, 11, 0, [0; 4], out);
            self.drop_event("ttl-exceeded", from, packet, out);
            return true;
        }
        let ext = match nat.outbound(now, w, proto, (src, sport), (addr, dport), t.flags, out) {
            Ok(e) => e,
            Err(r) => {
                self.drop_event(r.reason(), from, packet, out);
                return true;
            }
        };
        let internal = match nat.inbound(now, w, proto, dport, (addr, ext), t.flags, out) {
            Ok(i) => i,
            Err(Refusal::Filtered) => return true,
            Err(r) => {
                self.drop_event(r.reason(), from, packet, out);
                return true;
            }
        };
        nat.counters.hairpinned += 1;
        let mut pkt = packet.to_vec();
        wire::rewrite_v4(&mut pkt, Side::Src, addr, ext);
        wire::rewrite_v4(&mut pkt, Side::Dst, internal.0, internal.1);
        self.forward_v4(now, from, pkt, out);
        true
    }

    /// A packet queued on outside port `port` after its source was translated, as it was before
    /// (for the ICMP error its inside sender gets when the next hop never answers).
    fn restore_source(&self, port: u32, from: u32, packet: Vec<u8>) -> Vec<u8> {
        let Some(nat) = self.nat.as_ref() else {
            return packet;
        };
        if !nat.is_outside(port) || nat.is_outside(from) {
            return packet;
        }
        let Some(t) = track::tuple(&packet).filter(|t| t.kind == Kind::Plain) else {
            return packet;
        };
        let (p, src, sport, _, _) = t.key;
        let proto = match (p, packet.get(ihl(&packet))) {
            (PROTO_UDP, _) => Proto::Udp,
            (PROTO_TCP, _) => Proto::Tcp,
            (PROTO_ICMP, Some(8)) => Proto::Icmp,
            _ => return packet,
        };
        match nat.internal_of(port, proto, sport) {
            Some(internal) if v4_of(src) == nat.addr(port) => {
                let mut p = packet;
                wire::rewrite_v4(&mut p, Side::Src, internal.0, internal.1);
                p
            }
            _ => packet,
        }
    }

    // ------------------------------------------------------------------------------------------
    // Commands (`wasmnet:control/commands`, documented in `wit/router/router.wit`)

    /// Runs one command at `now`: `route-add`, `route-replace` and `route-remove` change the
    /// static routes, `routes` lists the table. `Ok` says what it did; `Err` changed nothing.
    /// A change applies to every lookup from then on; queued packets, the neighbor table, the
    /// ports and the counters other than the route ones are untouched.
    pub fn command(
        &mut self,
        now: u64,
        command: &str,
        argument: &str,
        out: &mut impl Sink,
    ) -> Result<String, String> {
        let argument = argument.trim();
        match command {
            "route-add" => self.set_route(argument, false, out),
            "route-replace" => self.set_route(argument, true, out),
            "route-remove" => self.remove_route(argument, out),
            "routes" if argument.is_empty() => Ok(self
                .routes
                .routes()
                .iter()
                .map(Route::to_string)
                .collect::<Vec<_>>()
                .join("\n")),
            "forward-add" => self.forward_add(now, argument, out),
            "forward-remove" => self.forward_remove(argument, out),
            "allow-add" => self.allow_change(argument, true, out),
            "allow-remove" => self.allow_change(argument, false, out),
            "forwards" | "rules" | "mappings" if !argument.is_empty() => {
                Err(format!("`{command}` takes no argument"))
            }
            "forwards" => Ok(self
                .nat_ref()?
                .forwards()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")),
            "mappings" => Ok(self.nat_ref()?.listing()),
            "rules" => Ok(self.filter.listing()),
            "routes" => Err("`routes` takes no argument".to_owned()),
            other => Err(format!(
                "unknown command `{other}` (route-add, route-replace, route-remove, routes, \
                 forward-add, forward-remove, forwards, mappings, allow-add, allow-remove, rules)"
            )),
        }
    }

    fn nat_ref(&self) -> Result<&Nat, String> {
        self.nat
            .as_ref()
            .ok_or_else(|| "no port translates (port<N>.nat = masquerade)".to_owned())
    }

    fn forward_add(&mut self, now: u64, text: &str, out: &mut impl Sink) -> Result<String, String> {
        let ports = self.nat_ref()?.ports();
        let f = parse_forward(text, &ports).map_err(|why| format!("forward `{text}`: {why}"))?;
        let nat = self.nat.as_mut().ok_or("no port translates")?;
        let done = nat.add_forward(f, now)?;
        if done == "added" {
            out.event(forward_event("nat-forward-added", &f));
        }
        Ok(done.to_owned())
    }

    /// `forward-remove <forward>` or `forward-remove <proto> <external-port> [port <n>]`.
    fn forward_remove(&mut self, text: &str, out: &mut impl Sink) -> Result<String, String> {
        let ports = self.nat_ref()?.ports();
        let words: Vec<&str> = text.split_whitespace().collect();
        let (proto, external, port, exact) = if words.contains(&"to") {
            let f =
                parse_forward(text, &ports).map_err(|why| format!("forward `{text}`: {why}"))?;
            (f.proto, f.external, f.port, Some(f))
        } else {
            let (proto, external, rest) = match words.as_slice() {
                [p, e, rest @ ..] => (*p, *e, rest),
                _ => {
                    return Err(
                        "forward-remove needs a forward or `<proto> <external-port> [port <n>]`"
                            .to_owned(),
                    );
                }
            };
            // Reuse the forward parser for the protocol, the port and the router port.
            let probe = format!("{proto} {external} to 0.0.0.1:1 {}", rest.join(" "));
            let f = parse_forward(probe.trim(), &ports)
                .map_err(|why| format!("forward-remove `{text}`: {why}"))?;
            (f.proto, f.external, f.port, None)
        };
        let nat = self.nat.as_mut().ok_or("no port translates")?;
        let before = nat.forwards().to_vec();
        let done = nat.remove_forward(proto, port, external, exact)?;
        if done == "removed"
            && let Some(f) = before
                .iter()
                .find(|f| (f.proto, f.port, f.external) == (proto, port, external))
        {
            out.event(forward_event("nat-forward-removed", f));
        }
        Ok(done.to_owned())
    }

    /// `allow-add <port> <rule>` and `allow-remove <port> <rule>`.
    fn allow_change(
        &mut self,
        text: &str,
        add: bool,
        out: &mut impl Sink,
    ) -> Result<String, String> {
        let (port, rule) = text
            .split_once(char::is_whitespace)
            .ok_or("allow-add and allow-remove need `<port> <rule>`, like `1 tcp dport 80`")?;
        let port: u32 = port
            .parse()
            .ok()
            .filter(|&p| (p as usize) < self.ports.len())
            .ok_or_else(|| format!("port `{port}` does not exist"))?;
        let rule = parse_rule(rule.trim())?;
        let done = if add {
            self.filter.add(port, rule)?
        } else {
            self.filter.remove(port, rule)
        };
        if matches!(done, "added" | "removed") {
            out.event(Event::new(
                if add { "allow-added" } else { "allow-removed" },
                vec![kv("port", port), kv("rule", rule)],
            ));
        }
        Ok(done.to_owned())
    }

    /// A static route from a command's argument, checked against the ports like the config's.
    fn parse_static(&self, text: &str) -> Result<Route, String> {
        let r = crate::config::parse_route(text, &self.cfg.ports)
            .map_err(|why| format!("route `{text}`: {why}"))?;
        Ok(Route {
            prefix: r.prefix,
            via: r.via,
            port: r.port,
            kind: RouteKind::Static,
        })
    }

    fn set_route(
        &mut self,
        text: &str,
        replace: bool,
        out: &mut impl Sink,
    ) -> Result<String, String> {
        let new = self.parse_static(text)?;
        match self.routes.get(new.prefix).copied() {
            Some(old) if old.kind == RouteKind::Connected => Err(connected(&old)),
            Some(old) if old == new => Ok("unchanged".to_owned()),
            Some(old) if !replace => Err(format!(
                "a route for {} exists ({old}): use route-replace",
                old.prefix
            )),
            old => {
                self.routes.replace(new);
                if let Some(old) = old {
                    self.route_changed("route-removed", &old, out);
                }
                self.route_changed("route-added", &new, out);
                Ok(if old.is_some() { "replaced" } else { "added" }.to_owned())
            }
        }
    }

    fn remove_route(&mut self, text: &str, out: &mut impl Sink) -> Result<String, String> {
        let (prefix, exact) = match text.split_whitespace().count() {
            0 => return Err("route-remove needs a prefix or a route".to_owned()),
            1 if text == "default" => {
                return Err("`default` alone names no family: use 0.0.0.0/0 or ::/0".to_owned());
            }
            1 => {
                let p: Prefix = text
                    .parse()
                    .map_err(|_| format!("`{text}` is not a prefix like 10.0.3.0/24"))?;
                if !p.is_canonical() {
                    return Err(format!("{text}: host bits are set (use {})", p.masked()));
                }
                (p, None)
            }
            _ => {
                let r = self.parse_static(text)?;
                (r.prefix, Some(r))
            }
        };
        match self.routes.get(prefix).copied() {
            None => Ok("absent".to_owned()),
            Some(old) if old.kind == RouteKind::Connected => Err(connected(&old)),
            Some(old) if exact.is_some_and(|e| e != old) => {
                Err(format!("the route for {prefix} is `{old}`, not `{text}`"))
            }
            Some(old) => {
                self.routes.remove(prefix);
                self.route_changed("route-removed", &old, out);
                Ok("removed".to_owned())
            }
        }
    }

    /// Journals one change and counts it. Every destination's next lookup is traced again.
    fn route_changed(&mut self, kind: &'static str, r: &Route, out: &mut impl Sink) {
        if kind == "route-added" {
            self.counters.routes_added += 1;
        } else {
            self.counters.routes_removed += 1;
        }
        self.traced_dsts.clear();
        out.event(Event::new(
            kind,
            vec![
                kv("prefix", r.prefix),
                kv("via", r.via.map_or("on-link".to_owned(), |v| v.to_string())),
                kv("port", r.port),
            ],
        ));
    }

    // ------------------------------------------------------------------------------------------
    // Counters

    /// Every counter, in a stable order (the `counters` export).
    pub fn counter_list(&self) -> Vec<(String, u64)> {
        let c = &self.counters;
        let mut v: Vec<(String, u64)> = [
            ("rx-frames", c.rx_frames),
            ("rx-bytes", c.rx_bytes),
            ("tx-frames", c.tx_frames),
            ("tx-bytes", c.tx_bytes),
            ("rx-port-down", c.rx_port_down),
            ("l2-filtered", c.l2_filtered),
            ("malformed", c.malformed),
            ("bad-checksum", c.bad_checksum),
            ("unknown-ethertype", c.unknown_ethertype),
            ("martian", c.martian),
            ("not-forwarded", c.not_forwarded),
            ("local-v4", c.local_v4),
            ("local-v6", c.local_v6),
            ("forwarded-v4", c.forwarded_v4),
            ("forwarded-v6", c.forwarded_v6),
            ("ttl-expired", c.ttl_expired),
            ("no-route", c.no_route),
            ("port-down-drops", c.port_down_drops),
            ("frag-needed", c.frag_needed),
            ("too-big", c.too_big),
            ("frag-unsupported", c.frag_unsupported),
            ("scope-drops", c.scope_drops),
            // Packets queued for an evicted neighbor entry are neighbor drops too.
            (
                "neighbor-drops",
                c.neighbor_drops + self.neigh.evicted_packets,
            ),
            ("queue-overflow", c.queue_overflow),
            ("icmp-errors-sent", c.icmp_errors_sent),
            ("icmp-errors-suppressed", c.icmp_errors_suppressed),
            ("echo-replies", c.echo_replies),
            ("tcp-resets", c.tcp_resets),
            ("arp-requests", c.arp_requests),
            ("arp-replies", c.arp_replies),
            ("arp-resolved", c.arp_resolved),
            ("arp-failed", c.arp_failed),
            ("ns-sent", c.ns_sent),
            ("na-sent", c.na_sent),
            ("ndp-resolved", c.ndp_resolved),
            ("ndp-failed", c.ndp_failed),
            ("ra-sent", c.ra_sent),
            ("trace-suppressed", c.trace_suppressed),
            ("queued-peak", self.neigh.queued_peak as u64),
            ("neighbors", self.neigh.len() as u64),
            ("routes", self.routes.len() as u64),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        // Only routers whose routes a command changed list these (the others keep their
        // counter lists).
        if c.routes_added + c.routes_removed > 0 {
            v.push(("routes-added".to_owned(), c.routes_added));
            v.push(("routes-removed".to_owned(), c.routes_removed));
        }
        // Only routers that relay DHCP list these (other routers keep their counter lists).
        if self.relays() {
            for (k, val) in [
                ("dhcp-relayed-to-server", c.dhcp_relayed_to_server),
                ("dhcp-relayed-to-client", c.dhcp_relayed_to_client),
                ("dhcp-relay-dropped", c.dhcp_relay_dropped),
            ] {
                v.push((k.to_owned(), val));
            }
        }
        // Only routers that translate list these.
        if let Some(n) = &self.nat {
            let nc = n.counters;
            for (k, val) in [
                ("nat-mappings", n.mapping_count() as u64),
                ("nat-sessions", n.session_count() as u64),
                ("nat-forwards", n.forwards().len() as u64),
                ("nat-mappings-created", nc.mappings_created),
                ("nat-mappings-expired", nc.mappings_expired),
                ("nat-translated-out", nc.translated_out),
                ("nat-translated-in", nc.translated_in),
                ("nat-icmp-errors-translated", nc.icmp_errors_translated),
                ("nat-hairpinned", nc.hairpinned),
                ("nat-hairpin-refused", nc.hairpin_refused),
                ("nat-filtered", nc.filtered),
                ("nat-no-mapping", nc.no_mapping),
                ("nat-table-full", nc.table_full),
                ("nat-ports-exhausted", nc.ports_exhausted),
                ("nat-fragments", nc.fragments),
                ("nat-unsupported", nc.unsupported),
                ("nat-malformed", nc.malformed),
                ("nat-trace-suppressed", n.trace_suppressed),
            ] {
                v.push((k.to_owned(), val));
            }
        }
        // Only routers that filter (or did) list these.
        if self.filter.active() {
            let fc = self.filter.counters;
            for (k, val) in [
                ("filter-rules", self.filter.rule_count() as u64),
                ("filter-flows", self.filter.flow_count() as u64),
                ("filter-new-flows", fc.new_flows),
                ("filter-tracked", fc.tracked),
                ("filter-dropped", fc.dropped),
                ("filter-table-full", fc.table_full),
                ("filter-trace-suppressed", self.filter.trace_suppressed),
            ] {
                v.push((k.to_owned(), val));
            }
        }
        for (n, p) in self.ports.iter().enumerate() {
            let pc = p.c;
            for (k, val) in [
                ("rx-frames", pc.rx_frames),
                ("rx-bytes", pc.rx_bytes),
                ("tx-frames", pc.tx_frames),
                ("tx-bytes", pc.tx_bytes),
                ("forwarded-in", pc.forwarded_in),
                ("forwarded-out", pc.forwarded_out),
                ("dropped", pc.dropped),
            ] {
                v.push((format!("p{n}-{k}"), val));
            }
        }
        // Appears only once the neighbor table was full (`neighbor::MAX_ENTRIES`).
        if self.neigh.evicted > 0 {
            v.push(("neighbors-evicted".to_owned(), self.neigh.evicted));
        }
        v
    }

    /// A port's counters.
    pub fn port_counters(&self, port: u32) -> Option<PortCounters> {
        self.ports.get(port as usize).map(|p| p.c)
    }
}
