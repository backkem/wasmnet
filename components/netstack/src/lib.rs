//! netstack: a smoltcp IP stack (`Medium::Ethernet`) as an **async wasmnet node**
//! (`docs/design/async-under-virtual-time.md`).
//!
//! The basics: static IPv4 and IPv6 (link-local plus an optional global address), ARP, NDP,
//! IGMP/MLD membership and ICMP echo replies (smoltcp's `auto-icmp-echo-reply`).
//!
//! It also **exports `wasi:sockets@0.3.0`** to the apps composed with it into a node (world
//! `wasmnet:netstack/netstack`; `docs/design/socket-extensions.md`): UDP sockets ([`udp`]) and
//! `ip-name-lookup` from a static hosts table ([`names`]).
//!
//! **TCP** ([`tcp`]): bind, listen with a real backlog (N LISTEN sockets), accept,
//! connect, and `stream<u8>` ↔ smoltcp buffers with backpressure, FIN ↔ EOF and RST ↔
//! `connection-reset`; plus `wasmnet:sockets-ext/tcp` (`abort`, `set-no-delay`).
//!
//! **ICMP errors**, which smoltcp ignores for TCP and UDP. The stack recognises the
//! ones addressed to it ([`observe`]), journals `icmp-error-received`, fails a TCP connect still
//! in SYN-SENT on an unreachable, as Linux does ([`tcp`]), and queues them for UDP sockets that
//! asked through `wasmnet:sockets-ext/udp` (`IP_RECVERR`, [`udp`]): what traceroute needs.
//!
//! **Zero-config boot**. `ipv4 = "dhcp"` runs smoltcp's DHCPv4 client and applies
//! each lease to the interface ([`dhcp`]); `ip-name-lookup` falls back from the hosts table to a
//! stub DNS resolver over the stack's own UDP sockets ([`resolver`]), which fails a lookup one
//! round trip after an ICMP port unreachable instead of timing out.
//!
//! **Multicast and mDNS**. `wasmnet:sockets-ext/{multicast,interfaces}`:
//! group memberships (IGMP/MLD), per-datagram hop limits, multicast loopback, the interface
//! list; and `.local` names resolved with one-shot mDNS queries ([`resolver`]).
//!
//! **A library with a typed debug API** ([`debug`]; world `wasmnet:netstack@0.1.0`). The world
//! exports no inspection interface: a component that wants one depends on this crate without
//! its `export` feature, invokes [`export_netstack!`] for the world and exports its own
//! contract over [`debug`] (reads of the interface, counters, app sockets and learned
//! neighbors).
//!
//! **ICMP echo sockets** ([`icmp`]), `wasmnet:sockets-ext/icmp`: Linux's
//! unprivileged ping sockets, for the `ping` app. The stack picks each socket's echo
//! identifier and queues the ICMP errors about its requests; `receive-datagram` also reports
//! each reply's TTL / hop limit, read off its frame ([`observe`]).
//!
//! **Quiescent snapshots** ([`snapshot`], `wasmnet:netstack/state`): at a point with no connection and nothing in flight, the stack's
//! state (smoltcp's interface state through our vendored patch, the app sockets in their
//! smoltcp slots, tables, generators, counters) and the driver's (timers, counters, the device
//! instant) save to bytes; a node built paused (`snapshot.paused`) restores them, its clock
//! shifted to the saved instant, and the app takes its sockets back (`reclaim-*`).
//!
//! # Shape (`docs/design/async-under-virtual-time.md`)
//!
//! The component exports `wasmnet:link/device`, `lifecycle` and `counters`
//! (world `counted-async-device`), plus `wasi:sockets/{types,ip-name-lookup}`,
//! `wasmnet:sockets-ext/{tcp,udp,multicast,interfaces,icmp}` and `wasmnet:netstack/state`:
//! * `ports()` answers one port, `eth0`, with the configured (or seeded) MAC and the IP MTU.
//! * `start()` builds the [`Stack`] and spawns **one** long-lived driver task, then returns.
//! * `receive()` only pushes the frame into the stack's rx queue and wakes the driver (push in).
//! * The driver polls the stack, hands every produced frame to `wire.transmit` (push out), and
//!   turns [`Stack::next_wakeup`] (smoltcp's `poll_at`, the sockets' timers and the multicast
//!   deadline) into a virtual `wasi:clocks` `wait-until`.
//! * `poll()` always answers `none`: an async node keeps time through `wasi:clocks`.
//! * Socket calls run in the calling app's task: sync ones change the stack and wake the driver,
//!   async ones (UDP `send`/`receive`, TCP `connect`) try once and park until the driver's next
//!   pass. None of them ever spawns a task.
//! * TCP `listen`, `send` and `receive` are sync but hand back streams: the accept loop and the
//!   byte pumps behind them run as jobs inside the driver task, which polls every job on every
//!   pass, then the stack, until neither moves.
//!
//! # The five netstack driver rules (enforced in `component.rs`)
//!
//! 1. **Wakes are level-triggered.** A wake sets a flag that the driver clears at the start of a
//!    pass and re-checks before it parks, so a wake that lands mid-pass is never lost.
//! 2. **Register the waker at the start of every poll**, never only when parking, and never
//!    `take()` it on wake.
//! 3. **Hold no borrow across an import call or a future drop.** The stack is borrowed only inside
//!    short closures that call no import. Frames, logs and events are collected first and handed
//!    to `wire.transmit`/`log` after the borrow ends. (Dropping a pending wit-bindgen future is a
//!    blocking `subtask.cancel`, during which sibling instances may re-enter our exports.)
//! 4. **Never cancel timers in the hot path.** A new `wait-until` is armed only when no armed one
//!    fires at or before the new deadline. Stale timers just fire later as spurious wakes.
//! 5. **Diagnostics go through the sync `wasmnet:link/log` import**, never `eprintln!` (a yield
//!    point in an async node).
//!
//! # Modules
//!
//! Everything here except `component.rs` is pure logic with no bindings, unit-tested inside
//! wasmtime (`cargo xtask test-guest`): [`config`] (`wasi:config` keys), [`time`] (u64 ns ↔
//! smoltcp µs), [`device`] (the smoltcp `phy::Device` adapter, padding), [`observe`] (frame
//! classification for diagnostics), [`mcast`] (the multicast deadline), [`dhcp`] (the
//! DHCP client), [`resolver`] (the stub DNS resolver), [`udp`]
//! (app UDP sockets), [`tcp`] (app TCP sockets), [`icmp`] (app ICMP echo sockets),
//! [`names`] (name lookup), [`debug`] (typed reads for debuggers) and [`stack`].
//!
//! # Embedding
//!
//! With the default feature `export` this crate's cdylib is the netstack component. An embedder
//! that exports more (an inspector component) depends on it with
//! `default-features = false` and invokes `netstack::export_netstack!(Component with_types_in
//! netstack::component)` once, naming `netstack::component::Component`. Cargo unifies features
//! within one invocation, so the embedder and this crate's own cdylib (with `export`) are built
//! in separate invocations; together, the embedder would export the world twice (a duplicate
//! symbol at link time).

#![deny(unsafe_code)]

/// The bindings, the driver and the exports. Public only for [`export_netstack!`]'s expansion
/// in an embedding crate.
#[cfg(not(test))]
#[doc(hidden)]
pub mod component;

/// Exports the world (`wasmnet:netstack@0.1.0`) from the component that invokes it, once:
/// `netstack::export_netstack!(Component with_types_in netstack::component)` with
/// `netstack::component::Component` in scope.
#[cfg(not(test))]
pub use component::export_netstack;

pub mod config;
pub mod debug;
pub mod device;
pub mod dhcp;
pub mod icmp;
pub mod mcast;
pub mod names;
pub mod observe;
pub mod resolver;
pub mod snapshot;
pub mod stack;
pub mod tcp;
pub mod time;
pub mod udp;

#[cfg(test)]
mod sim_tests;

pub use config::{Config, ConfigError};
pub use stack::Stack;

/// Severity of a log line (mirrors `wasmnet:link/log.level`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Debug,
    Info,
    Warn,
}

/// One structured event for `wasmnet:link/log.event`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Kebab-case kind: `arp-resolved`, `ndp-resolved`, `icmp-error-received`, `dhcp-*`,
    /// `multicast-*`, `name-lookup-*`, ...
    pub kind: &'static str,
    /// Kebab-case keys, string values.
    pub fields: Vec<(String, String)>,
}

impl Event {
    pub fn new(kind: &'static str, fields: &[(&str, String)]) -> Self {
        Self {
            kind,
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        }
    }

    /// The value of field `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// A diagnostic, in the order the stack produced it (logs and events interleave).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Note {
    Log(Level, String),
    Event(Event),
}

/// What one [`Stack::poll`] produced. The driver transmits the frames, in order, and records the
/// notes, after it released the stack.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub frames: Vec<Vec<u8>>,
    pub notes: Vec<Note>,
    /// Anything happened: frames in or out, a socket changed state, the TCP table moved. The
    /// driver then polls its TCP pumps again.
    pub active: bool,
}

impl Output {
    pub fn log(&mut self, level: Level, message: String) {
        self.notes.push(Note::Log(level, message));
    }

    pub fn event(&mut self, event: Event) {
        self.notes.push(Note::Event(event));
    }

    /// Every event, in order.
    pub fn events(&self) -> impl Iterator<Item = &Event> {
        self.notes.iter().filter_map(|n| match n {
            Note::Event(e) => Some(e),
            Note::Log(..) => None,
        })
    }
}

/// `1.234 ms` from nanoseconds (truncated to µs), for log lines only.
pub fn fmt_ms(ns: u64) -> String {
    format!("{}.{:03} ms", ns / 1_000_000, ns / 1_000 % 1_000)
}
