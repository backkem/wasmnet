//! The smoltcp sockets of every port: one `SocketSet` per port, each polled by that port's
//! smoltcp `Interface` only.
//!
//! A smoltcp interface sends what any socket in the set it polls has queued, by its own routes
//! and from its own addresses, and hands every arriving packet to the sockets of that set. So a
//! socket lives in exactly one port's set, and a [`Handle`] names the port with the slot. An
//! app socket that is not tied to one port (bound to the unspecified address) has one smoltcp
//! socket in every port's set ([`crate::udp`], [`crate::tcp`], [`crate::icmp`]). On a node with
//! one port there is one set, and every handle is in it, as before.

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::{AnySocket, Socket};

/// One smoltcp socket: the port whose set holds it, and its slot there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle {
    /// 0 is `eth0`.
    pub port: usize,
    pub slot: SocketHandle,
}

/// Every port's socket set.
pub struct Sockets {
    sets: Vec<SocketSet<'static>>,
}

impl Sockets {
    /// `ports` empty sets (at least one).
    pub fn new(ports: usize) -> Self {
        Self {
            sets: (0..ports.max(1))
                .map(|_| SocketSet::new(Vec::new()))
                .collect(),
        }
    }

    /// The number of ports.
    pub fn ports(&self) -> usize {
        self.sets.len()
    }

    /// Adds `socket` to port `port`'s set.
    pub fn add<T: AnySocket<'static>>(&mut self, port: usize, socket: T) -> Handle {
        Handle {
            port,
            slot: self.sets[port].add(socket),
        }
    }

    /// Adds `socket` at slot `index` of port `port`'s set (a snapshot restore); `None` if the
    /// slot is taken.
    pub fn add_at<T: AnySocket<'static>>(
        &mut self,
        port: usize,
        index: usize,
        socket: T,
    ) -> Option<Handle> {
        let slot = self.sets.get_mut(port)?.add_at(index, socket)?;
        Some(Handle { port, slot })
    }

    /// # Panics
    /// If the handle is stale or of another socket type, like `SocketSet::get`.
    pub fn get<T: AnySocket<'static>>(&self, h: Handle) -> &T {
        self.sets[h.port].get::<T>(h.slot)
    }

    /// # Panics
    /// If the handle is stale or of another socket type, like `SocketSet::get_mut`.
    pub fn get_mut<T: AnySocket<'static>>(&mut self, h: Handle) -> &mut T {
        self.sets[h.port].get_mut::<T>(h.slot)
    }

    pub fn remove(&mut self, h: Handle) -> Socket<'static> {
        self.sets[h.port].remove(h.slot)
    }

    /// Port `port`'s set, for its interface's poll.
    pub fn set(&self, port: usize) -> &SocketSet<'static> {
        &self.sets[port]
    }

    pub fn set_mut(&mut self, port: usize) -> &mut SocketSet<'static> {
        &mut self.sets[port]
    }

    /// Every socket of every port, port by port, in slot order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (Handle, &mut Socket<'static>)> {
        self.sets.iter_mut().enumerate().flat_map(|(port, set)| {
            set.iter_mut()
                .map(move |(slot, s)| (Handle { port, slot }, s))
        })
    }

    /// No socket in any set.
    pub fn is_empty(&self) -> bool {
        self.sets.iter().all(|s| s.iter().next().is_none())
    }
}
