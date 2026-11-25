//! router: a stepped device that routes IPv4 and IPv6 between its ports.
//!
//! What it does, per port and per packet, is in [`router`]'s docs; the config keys are in
//! [`config`]. In short:
//!
//! * **Ports** have a MAC, an IP MTU, an IPv4 address/prefix, an IPv6 global address/prefix and a
//!   link-local address. Each prefix is a *connected* route.
//! * **Static routes** with longest-prefix match ([`route`]), including default routes.
//! * **ARP and NDP** ([`neighbor`]): request queueing, per-neighbor pacing (no shared one-per-
//!   second limit), a per-neighbor queue limit, retries and failure (ICMP host unreachable).
//! * **Forwarding** with TTL / hop-limit decrement (incremental IPv4 checksum update, RFC 1624).
//! * **ICMP** errors: time exceeded, net / host / port / protocol unreachable, fragmentation
//!   needed (DF) and packet too big; echo replies for every address of the router; TCP RSTs for
//!   segments addressed to it. No fragmentation, no ICMP rate limiting, no redirects.
//! * **Router Advertisements** (optional, off by default): one when a port comes up, and one per
//!   Router Solicitation.
//! * **Address translation** ([`nat`], optional: `port<N>.nat = masquerade`): NAT44 with port
//!   translation for UDP, TCP and ICMP echo, RFC 4787 mapping and filtering behaviours,
//!   hairpinning, port forwards, ICMP errors translated with their quotes, idle timeouts.
//! * **A packet filter** ([`filter`], optional: `port<N>.allow`): allow rules per ingress port,
//!   stateful on the connection tracking ([`track`]) the translation shares.
//! * **Tunnel ports** ([`tunnel`], optional: `tunnel.<name>.*` or `tunnel-add`): point-to-point
//!   ports without a cable whose packets cross the network in Geneve over UDP, from the
//!   router's own address; STUN Binding checks find the peer through NATs, keep it and follow
//!   it, and `stun-server` answers Binding requests (`docs/design/tunnels.md`).
//! * **Commands** (`wasmnet:control/commands`, [`Router::command`]): `route-add`,
//!   `route-replace` and `route-remove` change the static routes while the router runs, in the
//!   config's route syntax; `routes` lists the table. Their semantics are in
//!   `wit/router/router.wit`. `forward-add`, `forward-remove`, `forwards`, `mappings`,
//!   `allow-add`, `allow-remove` and `rules` do the same for forwards and allow rules.
//!   `tunnel-add`, `tunnel-remove`, `tunnel-peer`, `tunnel-peer-remove` and `tunnels` add,
//!   remove and list tunnels; routes over them name them (`fd00:b::/64 tunnel to-b`).
//! * **Events** (`wasmnet:link/log.event`): `route-lookup {dst, result, prefix, via, port}`,
//!   `route-added` / `route-removed {prefix, via, port}` (a command changed the table),
//!   `arp-resolved` / `ndp-resolved {ip, mac, port, after-ns, queued}`, `arp-failed` /
//!   `ndp-failed {ip, port, attempts, dropped}`, `ttl-decrement {proto, src, dst, ttl-in,
//!   ttl-out, from-port, to-port}`, `icmp-error-sent {error, icmp-type, icmp-code, from, to,
//!   about, proto}`, `forward-drop {reason, src, dst, proto, port}`, `port-up` / `port-down
//!   {port}`; with translation `nat-mapping-created` / `nat-mapping-expired`, `nat-filtered`,
//!   `nat-forward-added` / `nat-forward-removed`, with the filter `filter-drop`, `allow-added` /
//!   `allow-removed`; with tunnels `tunnel-added`, `tunnel-removed`, `tunnel-candidate`,
//!   `tunnel-reflexive`, `tunnel-up`, `tunnel-roamed`, `tunnel-down` and `tunnel-failed`, and
//!   a port field names a tunnel's port by the tunnel's name. `route-lookup`, `ttl-decrement`,
//!   `nat-filtered` and `filter-drop` can be one per packet, so by default they are reported
//!   once per destination or once per flow (`trace.*` in [`config`]).
//! * **Counters** (`wasmnet:link/counters`): router-wide ones and `p<N>-*` per port;
//!   `routes-added` and `routes-removed` once a command changed the table; `nat-*` on a router
//!   that translates, `filter-*` on one that filters, the tunnel counters
//!   (`tunnels`, `tunnel-malformed`, `tunnel-unknown-id`, `stun-bindings-answered` and
//!   `tunnel-<name>-*`) on one that has or had a tunnel or a STUN server.
//!
//! Everything here except `component.rs` is pure logic with no bindings: unit- and
//! property-tested inside wasmtime (`cargo xtask test-guest`).

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

pub mod config;
pub mod filter;
pub mod nat;
pub mod neighbor;
pub mod route;
pub mod router;
pub mod track;
pub mod tunnel;
pub mod wire;

#[cfg(test)]
mod tests;

pub use config::{Config, ConfigError};
pub use router::Router;

/// One structured event for `wasmnet:link/log.event`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Kebab-case kind (`route-lookup`, `arp-resolved`, ...).
    pub kind: &'static str,
    /// Kebab-case keys, string values.
    pub fields: Vec<(String, String)>,
}

impl Event {
    pub fn new(kind: &'static str, fields: Vec<(String, String)>) -> Self {
        Self { kind, fields }
    }

    /// The value of field `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Where the router's output goes: `wire.transmit` and `log.event` in the component, a recorder
/// in tests. Both are sync and never re-enter the router.
pub trait Sink {
    fn transmit(&mut self, port: u32, frame: Vec<u8>);
    fn event(&mut self, event: Event);
}
