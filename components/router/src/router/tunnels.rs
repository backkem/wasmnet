//! The router's tunnel ports: where [`crate::tunnel`] meets routing.
//!
//! A tunnel is router port `cabled + slot`, after the cabled ports, in a slot that never moves
//! while the tunnel exists (a removed tunnel frees its slot for the next one), so routes over
//! other tunnels keep their port when one is removed. Commands, events and counters name the
//! tunnel, never its port number.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

use wasmnet_wire::MacAddr;

use super::{Port, PortCounters, Router, earliest, ihl, kv};
use crate::config::PortConfig;
use crate::route::{Prefix, Route, RouteKind};
use crate::tunnel::{self, Action, Spec, Tunnel, geneve, mss, stun};
use crate::wire::{self, PROTO_UDP};
use crate::{Event, Sink};

/// Router-wide tunnel counters.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Wide {
    /// Datagrams on a tunnel port that were neither STUN nor Geneve this router accepts, or
    /// that failed their UDP checksum.
    malformed: u64,
    /// Checks and data for a tunnel id this router does not have on that port.
    unknown_id: u64,
    /// Binding requests without a tunnel id answered (a reflexive-address service).
    bindings_answered: u64,
}

/// The tunnels of one router.
#[derive(Debug, Default)]
pub(crate) struct Tunnels {
    /// By slot: the tunnel at port `cabled + slot`.
    slots: Vec<Option<Tunnel>>,
    stun_server: Option<u16>,
    /// A tunnel or a STUN server existed: the router lists the tunnel counters from then on.
    used: bool,
    c: Wide,
}

impl Tunnels {
    pub(crate) fn new(stun_server: Option<u16>) -> Tunnels {
        Tunnels {
            used: stun_server.is_some(),
            stun_server,
            ..Tunnels::default()
        }
    }

    /// Whether a UDP datagram to `port` on one of the router's addresses is the tunnels'.
    fn listens(&self, port: u16) -> bool {
        self.stun_server == Some(port) || self.iter().any(|t| t.spec.udp == port)
    }

    fn iter(&self) -> impl Iterator<Item = &Tunnel> {
        self.slots.iter().flatten()
    }

    fn slot_of(&self, name: &str) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|t| t.name == name))
    }

    fn slot_for(&self, udp: u16, id: u32) -> Option<usize> {
        self.slots.iter().position(|s| {
            s.as_ref()
                .is_some_and(|t| t.spec.udp == udp && t.spec.id == id)
        })
    }
}

/// The port configuration a tunnel's port gets: its transit address and its MTU.
pub(crate) fn port_config(spec: &Spec, port: u32) -> PortConfig {
    let (ipv4, ipv6) = match spec.local {
        (IpAddr::V4(a), l) => (Some((a, l)), None),
        (IpAddr::V6(a), l) => (None, Some((a, l))),
    };
    PortConfig {
        mac: MacAddr([0; 6]),
        mtu: spec.mtu,
        ipv4,
        ipv6,
        // Never used on the wire (a tunnel has no neighbours); unique per port.
        link_local: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0xffff, port as u16),
        ra: false,
        dhcp_relay: Vec::new(),
        nat: false,
        allow: Vec::new(),
    }
}

/// The connected route of a tunnel's transit prefix.
pub(crate) fn connected_route(spec: &Spec, port: u32) -> Route {
    let prefix = match spec.local {
        (IpAddr::V4(a), l) => Prefix::V4(u32::from(a), l),
        (IpAddr::V6(a), l) => Prefix::V6(u128::from(a), l),
    };
    Route {
        prefix: prefix.masked(),
        via: None,
        port,
        kind: RouteKind::Connected,
    }
}

impl Router {
    fn cabled(&self) -> usize {
        self.cfg.ports.len()
    }

    /// The name a port goes by in events and listings: its number, or its tunnel's name.
    pub(super) fn port_name(&self, port: u32) -> String {
        match (port as usize).checked_sub(self.cabled()) {
            Some(slot) => self
                .tunnels
                .slots
                .get(slot)
                .and_then(Option::as_ref)
                .map_or_else(|| port.to_string(), |t| t.name.clone()),
            None => port.to_string(),
        }
    }

    /// A route as `routes` lists it: `port <n>` for a cabled port, `tunnel <name>` for a tunnel.
    pub(super) fn route_text(&self, r: &Route) -> String {
        if (r.port as usize) < self.cabled() {
            return r.to_string();
        }
        let mut s = r.prefix.to_string();
        if let Some(v) = r.via {
            s.push_str(&format!(" via {v}"));
        }
        s.push_str(&format!(
            " tunnel {} ({})",
            self.port_name(r.port),
            r.kind.name()
        ));
        s
    }

    /// The port of tunnel `name`, for routes that name it.
    pub(super) fn tunnel_port(&self, name: &str) -> Option<u32> {
        self.tunnels
            .slot_of(name)
            .map(|s| (self.cabled() + s) as u32)
    }

    /// Whether `port` is a tunnel's.
    pub(super) fn is_tunnel(&self, port: u32) -> bool {
        port as usize >= self.cabled()
    }

    /// The static tunnels of the config, in name order (their ports follow the cabled ones).
    pub(super) fn tunnels_from_config(&mut self, now: u64) {
        let tunnels = self.cfg.tunnels.clone();
        for (name, spec) in tunnels {
            self.tunnels.used = true;
            self.tunnels.slots.push(Some(Tunnel::new(&name, spec, now)));
        }
    }

    /// `tunnel-add <name> <key> <value>...`.
    pub(super) fn tunnel_add(
        &mut self,
        now: u64,
        text: &str,
        out: &mut impl Sink,
    ) -> Result<String, String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        let Some((name, settings)) = words.split_first() else {
            return Err("tunnel-add needs a name and its settings, like \
                        `to-b id 7 local fd00:ff::a/128`"
                .to_owned());
        };
        if !tunnel::valid_name(name) {
            return Err(format!(
                "`{name}`: a tunnel name is a-z, 0-9 and -, 1 to 32 characters, \
                 starting with a letter"
            ));
        }
        let spec = Spec::from_words(settings)?;
        if let Some(slot) = self.tunnels.slot_of(name) {
            let same = self.tunnels.slots[slot]
                .as_ref()
                .is_some_and(|t| t.spec == spec);
            return if same {
                Ok("unchanged".to_owned())
            } else {
                Err(format!(
                    "tunnel `{name}` exists with other settings: remove it first"
                ))
            };
        }
        if self.tunnels.iter().count() >= tunnel::MAX_TUNNELS {
            return Err(format!("this router has {} tunnels", tunnel::MAX_TUNNELS));
        }
        if let Some(other) = self
            .tunnels
            .iter()
            .find(|t| (t.spec.udp, t.spec.id) == (spec.udp, spec.id))
        {
            return Err(format!(
                "tunnel `{}` has id {} on udp {} already",
                other.name, spec.id, spec.udp
            ));
        }
        let slot = match self.tunnels.slots.iter().position(Option::is_none) {
            Some(s) => s,
            None => {
                self.tunnels.slots.push(None);
                self.tunnels.slots.len() - 1
            }
        };
        let port = (self.cabled() + slot) as u32;
        let p = Port {
            cfg: port_config(&spec, port),
            up: false,
            c: PortCounters::default(),
        };
        match self.ports.get_mut(port as usize) {
            Some(old) => *old = p,
            None => self.ports.push(p),
        }
        self.routes.insert(connected_route(&spec, port));
        self.traced_dsts.clear();
        out.event(Event::new(
            "tunnel-added",
            vec![
                kv("tunnel", name),
                kv("id", spec.id),
                kv("udp", spec.udp),
                kv("local", format!("{}/{}", spec.local.0, spec.local.1)),
                kv("mtu", spec.mtu),
            ],
        ));
        self.tunnels.used = true;
        self.tunnels.slots[slot] = Some(Tunnel::new(name, spec, now));
        Ok("added".to_owned())
    }

    /// `tunnel-remove <name>`: the tunnel, its port and every route over it.
    pub(super) fn tunnel_remove(
        &mut self,
        text: &str,
        out: &mut impl Sink,
    ) -> Result<String, String> {
        let name = text.trim();
        let Some(slot) = self.tunnels.slot_of(name) else {
            return Ok("absent".to_owned());
        };
        let port = (self.cabled() + slot) as u32;
        let over: Vec<Route> = self
            .routes
            .routes()
            .iter()
            .filter(|r| r.port == port)
            .copied()
            .collect();
        for r in &over {
            if r.kind == RouteKind::Static {
                self.route_changed("route-removed", r, out);
            }
            self.routes.remove(r.prefix);
        }
        self.traced_dsts.clear();
        let statics = over.iter().filter(|r| r.kind == RouteKind::Static).count();
        self.tunnels.slots[slot] = None;
        // The port stays as a free slot: without addresses, down.
        let p = &mut self.ports[port as usize];
        p.up = false;
        p.cfg.ipv4 = None;
        p.cfg.ipv6 = None;
        out.event(Event::new(
            "tunnel-removed",
            vec![kv("tunnel", name), kv("routes", statics)],
        ));
        Ok("removed".to_owned())
    }

    /// `tunnel-peer <name> <ip:port>` and `tunnel-peer-remove <name> <ip:port>`.
    pub(super) fn tunnel_peer(
        &mut self,
        now: u64,
        text: &str,
        add: bool,
        out: &mut impl Sink,
    ) -> Result<String, String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        let [name, endpoint] = words.as_slice() else {
            return Err("needs `<tunnel> <ip:port>`, like `to-b 203.0.113.2:6081`".to_owned());
        };
        let e = tunnel_endpoint(endpoint)?;
        let slot = self
            .tunnels
            .slot_of(name)
            .ok_or_else(|| format!("no tunnel `{name}`"))?;
        let mut actions = Vec::new();
        let Some(t) = self.tunnels.slots[slot].as_mut() else {
            return Err(format!("no tunnel `{name}`"));
        };
        let done = if add {
            if t.candidates().contains(&e) {
                "unchanged"
            } else if t.add_candidate(now, e, "command", &mut actions) {
                "added"
            } else {
                return Err(format!(
                    "tunnel `{name}` has {} candidates",
                    tunnel::MAX_CANDIDATES
                ));
            }
        } else if t.remove_candidate(e) {
            "removed"
        } else {
            "absent"
        };
        self.apply(now, slot, actions, out);
        Ok(done.to_owned())
    }

    /// `tunnels`: one line per tunnel, by name.
    pub(super) fn tunnel_listing(&self) -> String {
        let mut lines: Vec<String> = self.tunnels.iter().map(Tunnel::listing).collect();
        lines.sort();
        lines.join("\n")
    }

    /// Carries out what a tunnel asked for.
    fn apply(&mut self, now: u64, slot: usize, actions: Vec<Action>, out: &mut impl Sink) {
        let port = self.cabled() + slot;
        for a in actions {
            match a {
                Action::Send { to, datagram } => {
                    let Some(udp) = self.tunnels.slots[slot].as_ref().map(|t| t.spec.udp) else {
                        return;
                    };
                    if !self.outer_send(now, None, udp, to, &datagram, out)
                        && let Some(t) = self.tunnels.slots[slot].as_mut()
                    {
                        t.c.outer_drops += 1;
                    }
                }
                Action::Carrier(up) => self.ports[port].up = up,
                Action::Event(e) => out.event(e),
            }
        }
    }

    /// Sends one UDP datagram from the router's own address toward `dst`: from `src` if given
    /// (an answer leaves from the address its request was sent to), else from the egress port's
    /// IPv4 address. Returns whether it left (it may still wait for ARP).
    fn outer_send(
        &mut self,
        now: u64,
        src: Option<Ipv4Addr>,
        sport: u16,
        dst: SocketAddrV4,
        payload: &[u8],
        out: &mut impl Sink,
    ) -> bool {
        let to = IpAddr::V4(*dst.ip());
        let Some(route) = self.lookup(to, out) else {
            self.counters.no_route += 1;
            return false;
        };
        // An outer packet routed into a tunnel would loop; one out of a down port is lost.
        if self.is_tunnel(route.port) || !self.is_up(route.port) {
            return false;
        }
        let Some(src) = src.or(self.ports[route.port as usize].cfg.ipv4.map(|(a, _)| a)) else {
            return false;
        };
        let datagram = wire::udp_v4(src, *dst.ip(), sport, dst.port(), payload);
        if 20 + datagram.len() > usize::from(self.ports[route.port as usize].cfg.mtu) {
            return false;
        }
        let id = self.next_id();
        let p = wire::ipv4(src, *dst.ip(), PROTO_UDP, self.cfg.ttl, id, &datagram);
        self.send_ip(now, route.port, route.next_hop(to), p, None, out);
        true
    }

    /// An inner packet routed to tunnel port `port`: encapsulated toward the peer, or dropped
    /// while the tunnel is down.
    pub(super) fn tunnel_send(
        &mut self,
        now: u64,
        port: u32,
        mut packet: Vec<u8>,
        out: &mut impl Sink,
    ) {
        let slot = port as usize - self.cabled();
        let Some(t) = self.tunnels.slots.get_mut(slot).and_then(Option::as_mut) else {
            return;
        };
        let Some(peer) = t.peer() else {
            t.c.down_drops += 1;
            return;
        };
        if t.spec.mss_clamp && mss::clamp(&mut packet, t.spec.mtu) {
            t.c.mss_clamped += 1;
        }
        t.c.tx_packets += 1;
        t.c.tx_bytes += packet.len() as u64;
        let (udp, datagram) = (t.spec.udp, geneve::encap(t.spec.id, &packet));
        if !self.outer_send(now, None, udp, peer, &datagram, out)
            && let Some(t) = self.tunnels.slots[slot].as_mut()
        {
            t.c.outer_drops += 1;
        }
    }

    /// An IPv4 packet addressed to the router: if it is a UDP datagram to a tunnel port (or the
    /// STUN server port), it is handled here and `true` is returned.
    pub(super) fn tunnel_in(&mut self, now: u64, packet: &[u8], out: &mut impl Sink) -> bool {
        if packet[9] != PROTO_UDP || !self.tunnels.used {
            return false;
        }
        let fragment =
            packet[6] & 0x20 != 0 || u16::from_be_bytes([packet[6] & 0x1f, packet[7]]) != 0;
        let at = ihl(packet);
        let Some(udp) = packet.get(at..).filter(|u| u.len() >= 8) else {
            return false;
        };
        let (sport, dport) = (
            u16::from_be_bytes([udp[0], udp[1]]),
            u16::from_be_bytes([udp[2], udp[3]]),
        );
        if fragment || !self.tunnels.listens(dport) {
            return false;
        }
        let src = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap_or([0; 4]));
        let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap_or([0; 4]));
        let len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
        let checksum = u16::from_be_bytes([udp[6], udp[7]]);
        let valid = len >= 8
            && len <= udp.len()
            && (checksum == 0
                || wire::finish(wire::sum16(
                    &udp[..len],
                    wire::pseudo_v4(src, dst, PROTO_UDP, len),
                )) == 0);
        if !valid {
            self.tunnels.c.malformed += 1;
            return true;
        }
        let payload = &udp[8..len];
        let from = SocketAddrV4::new(src, sport);
        if stun::is_stun(payload) {
            self.stun_in(now, dst, dport, from, payload, out);
        } else {
            self.data_in(now, dport, from, payload, out);
        }
        true
    }

    fn stun_in(
        &mut self,
        now: u64,
        dst: Ipv4Addr,
        dport: u16,
        from: SocketAddrV4,
        payload: &[u8],
        out: &mut impl Sink,
    ) {
        let msg = match stun::parse(payload) {
            Ok(m) => m,
            Err(_) => {
                self.tunnels.c.malformed += 1;
                return;
            }
        };
        match msg {
            stun::Message::Request {
                txid,
                username: None,
            } => {
                self.tunnels.c.bindings_answered += 1;
                let answer = stun::success(&txid, SocketAddr::V4(from));
                self.outer_send(now, Some(dst), dport, from, &answer, out);
            }
            stun::Message::Request {
                txid,
                username: Some(u),
            } => {
                let slot = u
                    .parse::<u32>()
                    .ok()
                    .and_then(|id| self.tunnels.slot_for(dport, id));
                let Some(slot) = slot else {
                    self.tunnels.c.unknown_id += 1;
                    return;
                };
                let mut actions = Vec::new();
                if let Some(t) = self.tunnels.slots[slot].as_mut() {
                    t.on_request(now, from, &txid, &mut actions);
                }
                // The answer leaves from the address the check was sent to.
                for a in actions {
                    match a {
                        Action::Send { to, datagram } if to == from => {
                            self.outer_send(now, Some(dst), dport, to, &datagram, out);
                        }
                        other => self.apply(now, slot, vec![other], out),
                    }
                }
            }
            stun::Message::Success { txid, mapped } => {
                let (_, id, _) = tunnel::parse_txid(&txid);
                let Some(slot) = self.tunnels.slot_for(dport, id) else {
                    self.tunnels.c.unknown_id += 1;
                    return;
                };
                let mut actions = Vec::new();
                if let Some(t) = self.tunnels.slots[slot].as_mut() {
                    t.on_response(now, from, &txid, mapped, &mut actions);
                }
                self.apply(now, slot, actions, out);
            }
            stun::Message::Error { .. } => self.tunnels.c.malformed += 1,
        }
    }

    fn data_in(
        &mut self,
        now: u64,
        dport: u16,
        from: SocketAddrV4,
        payload: &[u8],
        out: &mut impl Sink,
    ) {
        let Ok(g) = geneve::decap(payload) else {
            self.tunnels.c.malformed += 1;
            return;
        };
        let Some(slot) = self.tunnels.slot_for(dport, g.vni) else {
            self.tunnels.c.unknown_id += 1;
            return;
        };
        let version = g.inner.first().map(|b| b >> 4);
        let expected = if g.proto == geneve::PROTO_IPV6 { 6 } else { 4 };
        if version != Some(expected) {
            self.tunnels.c.malformed += 1;
            return;
        }
        let mut inner = g.inner.to_vec();
        let mut actions = Vec::new();
        if let Some(t) = self.tunnels.slots[slot].as_mut() {
            t.on_data(now, from, inner.len(), &mut actions);
            if t.spec.mss_clamp && mss::clamp(&mut inner, t.spec.mtu) {
                t.c.mss_clamped += 1;
            }
        }
        self.apply(now, slot, actions, out);
        let port = (self.cabled() + slot) as u32;
        if expected == 6 {
            self.ipv6_in(now, port, MacAddr([0; 6]), &inner, out);
        } else {
            self.ipv4_in(now, port, &inner, out);
        }
    }

    /// Every tunnel's timers; the earliest next deadline.
    pub(super) fn tunnel_poll(&mut self, now: u64, out: &mut impl Sink) -> Option<u64> {
        let mut next = None;
        for slot in 0..self.tunnels.slots.len() {
            let mut actions = Vec::new();
            let Some(t) = self.tunnels.slots[slot].as_mut() else {
                continue;
            };
            t.poll(now, &mut actions);
            self.apply(now, slot, actions, out);
            if let Some(t) = self.tunnels.slots[slot].as_ref() {
                next = earliest(next, t.deadline());
            }
        }
        next
    }

    /// The tunnel counters: router-wide ones and `tunnel-<name>-*`, by name, once a tunnel or a
    /// STUN server existed.
    pub(super) fn tunnel_counters(&self, v: &mut Vec<(String, u64)>) {
        if !self.tunnels.used {
            return;
        }
        let w = self.tunnels.c;
        for (k, val) in [
            ("tunnels", self.tunnels.iter().count() as u64),
            ("tunnel-malformed", w.malformed),
            ("tunnel-unknown-id", w.unknown_id),
            ("stun-bindings-answered", w.bindings_answered),
        ] {
            v.push((k.to_owned(), val));
        }
        let mut named: Vec<(&str, usize)> = self
            .tunnels
            .slots
            .iter()
            .enumerate()
            .filter_map(|(s, t)| t.as_ref().map(|t| (t.name.as_str(), s)))
            .collect();
        named.sort();
        for (name, slot) in named {
            let Some(t) = self.tunnels.slots[slot].as_ref() else {
                continue;
            };
            let (c, pc) = (t.c, self.ports[self.cabled() + slot].c);
            for (k, val) in [
                ("tx-packets", c.tx_packets),
                ("tx-bytes", c.tx_bytes),
                ("rx-packets", c.rx_packets),
                ("rx-bytes", c.rx_bytes),
                ("forwarded-in", pc.forwarded_in),
                ("forwarded-out", pc.forwarded_out),
                ("dropped", pc.dropped),
                ("checks-sent", c.checks_sent),
                ("requests-received", c.requests_received),
                ("responses-received", c.responses_received),
                ("down-drops", c.down_drops),
                ("outer-drops", c.outer_drops),
                ("roamed", c.roamed),
                ("mss-clamped", c.mss_clamped),
                ("up", u64::from(t.state() == tunnel::State::Up)),
            ] {
                v.push((format!("tunnel-{name}-{k}"), val));
            }
        }
    }

    /// `describe` lines for the tunnels.
    pub(super) fn tunnel_lines(&self, lines: &mut Vec<String>) {
        if let Some(p) = self.tunnels.stun_server {
            lines.push(format!("  stun server: udp {p}"));
        }
        for t in self.tunnels.iter() {
            lines.push(format!(
                "  tunnel {}: id {} udp {} local {}/{} mtu {} peers {}",
                t.name,
                t.spec.id,
                t.spec.udp,
                t.spec.local.0,
                t.spec.local.1,
                t.spec.mtu,
                t.candidates().len()
            ));
        }
    }
}

/// An IPv4 endpoint for `tunnel-peer`, checked as the `peer` key is.
fn tunnel_endpoint(text: &str) -> Result<SocketAddrV4, String> {
    let spec = Spec::from_pairs([("id", "1"), ("local", "fd00::1/128"), ("peer", text)])?;
    spec.peers
        .first()
        .copied()
        .ok_or_else(|| format!("`{text}` is not an IPv4 endpoint"))
}
