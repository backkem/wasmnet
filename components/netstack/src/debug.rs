//! Typed reads of a live netstack, for debuggers and inspectors built on this crate: the
//! interface and its addresses, the app sockets, the learned neighbors and the counters. No
//! paths and no encoding: an embedder maps these onto its own contract (for example an
//! inspection interface).
//!
//! The reads themselves are [`Stack`] methods ([`Stack::interface`], [`Stack::dns_servers`],
//! [`Stack::udp_sockets`], [`Stack::tcp_sockets`], [`Stack::icmp_sockets`],
//! [`Stack::neighbors`], [`Stack::counters`]); inside a running component, [`with_stack`] lends
//! the driver's stack to a closure and [`counters`] answers what the `counters` export answers.
//! Reads never change the stack.

use std::net::SocketAddr;

#[cfg(not(test))]
use crate::Stack;
pub use crate::stack::InterfaceInfo;

/// One app socket, as a debugger sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SockInfo {
    /// The netstack's id of the socket (unique per kind).
    pub id: u32,
    /// `ipv4` or `ipv6`.
    pub family: &'static str,
    pub local: Option<SocketAddr>,
    pub remote: Option<SocketAddr>,
    /// `unbound`, `bound`, `connected` for UDP and ICMP; `bound`, `listen`, `syn-sent`,
    /// smoltcp's state in lowercase or `closed` for TCP.
    pub state: String,
    /// Bytes queued for the app to read.
    pub rx_queued: u64,
    /// Bytes queued to send.
    pub tx_queued: u64,
}

/// Runs `f` on the running node's stack: `None` until `start()` built it (or a restore did).
/// The node itself is created first if needed (it reads its config, as `ports()` does).
///
/// A control-call helper: call it from an export, never from inside `f` or while the stack is
/// lent out. `f` must not call any import (netstack driver rule 3).
#[cfg(not(test))]
pub fn with_stack<R>(f: impl FnOnce(&Stack) -> R) -> Option<R> {
    crate::component::debug_with_stack(f)
}

/// Every counter, as the `wasmnet:link/counters` export answers: the stack's, then the driver's.
#[cfg(not(test))]
pub fn counters() -> Vec<(String, u64)> {
    crate::component::all_counters()
}

/// The device's clock (the host's virtual clock, shifted by a restore), in nanoseconds. A sync
/// host call: it never yields.
#[cfg(not(test))]
pub fn now() -> u64 {
    crate::component::device_now()
}

/// Wakes the driver, as an operator event at this instant does (driver rule 1): it runs a pass
/// at the current instant.
#[cfg(not(test))]
pub fn wake() {
    crate::component::wake_driver();
}
