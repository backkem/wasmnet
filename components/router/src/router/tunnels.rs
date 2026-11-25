//! The router's tunnel ports: where [`crate::tunnel`] meets routing.
//!
//! A tunnel is router port `cabled + slot`, after the cabled ports, in a slot that never moves
//! while the tunnel exists (a removed tunnel frees its slot for the next one), so routes over
//! other tunnels keep their port when one is removed. Commands, events and counters name the
//! tunnel, never its port number.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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

    /// The keyed tunnel on `udp` that receives ESP on `spi`.
    fn slot_for_spi(&self, udp: u16, spi: u32) -> Option<usize> {
        self.slots.iter().position(|s| {
            s.as_ref()
                .is_some_and(|t| t.spec.udp == udp && t.has_spi(spi))
        })
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
            let port = (self.cabled() + self.tunnels.slots.len()) as u32;
            self.filter.set_name(port, Some(&name));
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
        self.filter.set_name(port, Some(name));
        self.traced_dsts.clear();
        let mut fields = vec![
            kv("tunnel", name),
            kv("id", spec.id),
            kv("udp", spec.udp),
            kv("local", format!("{}/{}", spec.local.0, spec.local.1)),
            kv("mtu", spec.mtu),
        ];
        // A keyless tunnel's event is as it was before tunnels had keys.
        if let Some(k) = &spec.key {
            fields.push(kv("key", k.id()));
        }
        out.event(Event::new("tunnel-added", fields));
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
        // Its allow rules go with it; flows it let through end on their own timers.
        self.filter.clear(port);
        self.filter.set_name(port, None);
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

    /// `tunnel-key <name> <64 hex digits>`: a keyed tunnel's new key (see
    /// [`Tunnel::replace_key`]).
    pub(super) fn tunnel_key(
        &mut self,
        now: u64,
        text: &str,
        out: &mut impl Sink,
    ) -> Result<String, String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        let [name, key] = words.as_slice() else {
            return Err("needs `<tunnel> <key>`, the key as 64 hex digits".to_owned());
        };
        let key = tunnel::key::Key::parse(key)?;
        let slot = self
            .tunnels
            .slot_of(name)
            .ok_or_else(|| format!("no tunnel `{name}`"))?;
        let mut actions = Vec::new();
        let Some(t) = self.tunnels.slots[slot].as_mut() else {
            return Err(format!("no tunnel `{name}`"));
        };
        let changed = t.replace_key(now, key, &mut actions)?;
        self.apply(now, slot, actions, out);
        Ok(if changed { "replaced" } else { "unchanged" }.to_owned())
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
        // The port's MTU follows the tunnel's (its default follows the peer's outer family).
        if let Some(t) = self.tunnels.slots[slot].as_ref() {
            self.ports[port].cfg.mtu = t.mtu();
        }
    }

    /// Sends one UDP datagram from the router's own address toward `dst`, over IPv4 or IPv6 as
    /// `dst` is: from `src` if given (an answer leaves from the address its request was sent
    /// to), else from the egress port's address of that family (for IPv6 its configured one,
    /// never the link-local one). Returns whether it left (it may still wait for ARP or NDP).
    fn outer_send(
        &mut self,
        now: u64,
        src: Option<IpAddr>,
        sport: u16,
        dst: SocketAddr,
        payload: &[u8],
        out: &mut impl Sink,
    ) -> bool {
        let to = dst.ip();
        let Some(route) = self.lookup(to, out) else {
            self.counters.no_route += 1;
            return false;
        };
        // An outer packet routed into a tunnel would loop; one out of a down port is lost.
        if self.is_tunnel(route.port) || !self.is_up(route.port) {
            return false;
        }
        let cfg = &self.ports[route.port as usize].cfg;
        let mtu = usize::from(cfg.mtu);
        let p = match to {
            IpAddr::V4(to4) => {
                let src = match src {
                    Some(IpAddr::V4(a)) => Some(a),
                    _ => cfg.ipv4.map(|(a, _)| a),
                };
                let Some(src) = src else {
                    return false;
                };
                let datagram = wire::udp_v4(src, to4, sport, dst.port(), payload);
                if 20 + datagram.len() > mtu {
                    return false;
                }
                let id = self.next_id();
                wire::ipv4(src, to4, PROTO_UDP, self.cfg.ttl, id, &datagram)
            }
            IpAddr::V6(to6) => {
                let src = match src {
                    Some(IpAddr::V6(a)) => Some(a),
                    _ => cfg.ipv6.map(|(a, _)| a),
                };
                let Some(src) = src else {
                    return false;
                };
                let datagram = wire::udp_v6(src, to6, sport, dst.port(), payload);
                if 40 + datagram.len() > mtu {
                    return false;
                }
                wire::ipv6(src, to6, PROTO_UDP, self.cfg.ttl, &datagram)
            }
        };
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
        if t.spec.mss_clamp && mss::clamp(&mut packet, t.mtu()) {
            t.c.mss_clamped += 1;
        }
        let datagram = if t.keyed() {
            let mut actions = Vec::new();
            let sealed = t.seal(&packet, &mut actions);
            if sealed.is_none() {
                t.c.down_drops += 1;
            }
            self.apply(now, slot, actions, out);
            match sealed {
                Some(d) => d,
                None => return,
            }
        } else {
            geneve::encap(t.spec.id, &packet)
        };
        let Some(t) = self.tunnels.slots[slot].as_mut() else {
            return;
        };
        t.c.tx_packets += 1;
        t.c.tx_bytes += packet.len() as u64;
        let udp = t.spec.udp;
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
        let from = SocketAddr::new(IpAddr::V4(src), sport);
        self.datagram_in(now, IpAddr::V4(dst), dport, from, payload, out);
        true
    }

    /// An IPv6 packet addressed to the router (`upper` its UDP datagram, the packet having no
    /// extension headers or fragments): if it is to a tunnel port (or the STUN server port), it
    /// is handled here and `true` is returned. IPv6 requires the UDP checksum (RFC 8200 §8.1): a
    /// zero one is malformed. Link-local addresses are not tunnel endpoints.
    pub(super) fn tunnel_in_v6(
        &mut self,
        now: u64,
        (src, dst): (Ipv6Addr, Ipv6Addr),
        udp: &[u8],
        out: &mut impl Sink,
    ) -> bool {
        if !self.tunnels.used || udp.len() < 8 {
            return false;
        }
        let (sport, dport) = (
            u16::from_be_bytes([udp[0], udp[1]]),
            u16::from_be_bytes([udp[2], udp[3]]),
        );
        if !self.tunnels.listens(dport)
            || !tunnel::unicast_endpoint(IpAddr::V6(src))
            || !tunnel::unicast_endpoint(IpAddr::V6(dst))
        {
            return false;
        }
        let len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
        let checksum = u16::from_be_bytes([udp[6], udp[7]]);
        let valid = len >= 8
            && len <= udp.len()
            && checksum != 0
            && wire::finish(wire::sum16(
                &udp[..len],
                wire::pseudo_v6(src, dst, PROTO_UDP, len),
            )) == 0;
        if !valid {
            self.tunnels.c.malformed += 1;
            return true;
        }
        let from = SocketAddr::new(IpAddr::V6(src), sport);
        self.datagram_in(now, IpAddr::V6(dst), dport, from, &udp[8..len], out);
        true
    }

    /// A datagram to tunnel port `dport` on the router's address `dst`, either family.
    fn datagram_in(
        &mut self,
        now: u64,
        dst: IpAddr,
        dport: u16,
        from: SocketAddr,
        payload: &[u8],
        out: &mut impl Sink,
    ) {
        if stun::is_stun(payload) {
            self.stun_in(now, dst, dport, from, payload, out);
        } else {
            self.data_in(now, dport, from, payload, out);
        }
    }

    fn stun_in(
        &mut self,
        now: u64,
        dst: IpAddr,
        dport: u16,
        from: SocketAddr,
        payload: &[u8],
        out: &mut impl Sink,
    ) {
        let (msg, signed) = match stun::parse_signed(payload) {
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
                let answer = stun::success(&txid, from);
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
                    t.on_request_signed(now, from, &txid, payload, &signed, &mut actions);
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
                    t.on_response_signed(now, from, &txid, mapped, payload, &signed, &mut actions);
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
        from: SocketAddr,
        payload: &[u8],
        out: &mut impl Sink,
    ) {
        // ESP: an SPI with its top bit set, which neither STUN nor Geneve (version 0) has.
        if payload.first().is_some_and(|b| b & 0x80 != 0) {
            return self.esp_in(now, dport, from, payload, out);
        }
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
        let mut actions = Vec::new();
        // A keyed tunnel never takes cleartext.
        if let Some(t) = self.tunnels.slots[slot].as_mut()
            && t.keyed()
        {
            t.refuse("cleartext", from, &mut actions);
            return self.apply(now, slot, actions, out);
        }
        let mut inner = g.inner.to_vec();
        if let Some(t) = self.tunnels.slots[slot].as_mut() {
            t.on_data(now, from, inner.len(), &mut actions);
            if t.spec.mss_clamp && mss::clamp(&mut inner, t.mtu()) {
                t.c.mss_clamped += 1;
            }
        }
        self.apply(now, slot, actions, out);
        self.inner_in(now, slot, &inner, out);
    }

    /// An ESP packet for a keyed tunnel: opened by the tunnel whose SPI it names.
    fn esp_in(
        &mut self,
        now: u64,
        dport: u16,
        from: SocketAddr,
        payload: &[u8],
        out: &mut impl Sink,
    ) {
        let slot =
            tunnel::esp::spi_of(payload).and_then(|spi| self.tunnels.slot_for_spi(dport, spi));
        let Some(slot) = slot else {
            self.tunnels.c.unknown_id += 1;
            return;
        };
        let mut actions = Vec::new();
        let mut inner = None;
        if let Some(t) = self.tunnels.slots[slot].as_mut() {
            inner = t.on_esp(now, from, payload, &mut actions);
            if let Some(i) = inner.as_mut()
                && t.spec.mss_clamp
                && mss::clamp(i, t.mtu())
            {
                t.c.mss_clamped += 1;
            }
        }
        self.apply(now, slot, actions, out);
        if let Some(inner) = inner {
            self.inner_in(now, slot, &inner, out);
        }
    }

    /// An inner packet that came out of tunnel `slot`: it enters the router on the tunnel's port.
    fn inner_in(&mut self, now: u64, slot: usize, inner: &[u8], out: &mut impl Sink) {
        let port = (self.cabled() + slot) as u32;
        if inner.first().map(|b| b >> 4) == Some(6) {
            self.ipv6_in(now, port, MacAddr([0; 6]), inner, out);
        } else {
            self.ipv4_in(now, port, inner, out);
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
                ("auth-failed", c.auth_failed),
                ("replayed", c.replayed),
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
            let key = if t.keyed() {
                format!(" key {}", t.key_id())
            } else {
                String::new()
            };
            lines.push(format!(
                "  tunnel {}: id {} udp {} local {}/{} mtu {} peers {}{key}",
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

/// An endpoint (IPv4 or IPv6) for `tunnel-peer`, checked as the `peer` key is.
fn tunnel_endpoint(text: &str) -> Result<SocketAddr, String> {
    let spec = Spec::from_pairs([("id", "1"), ("local", "fd00::1/128"), ("peer", text)])?;
    spec.peers
        .first()
        .copied()
        .ok_or_else(|| format!("`{text}` is not an endpoint"))
}
