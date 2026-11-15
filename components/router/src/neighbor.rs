//! The neighbor table: ARP (IPv4) and NDP (IPv6) resolution state per `(port, address)`, with
//! queued packets.
//!
//! * A packet for an unknown neighbor creates an **incomplete** entry, queues the packet and asks
//!   at once (the caller sends the ARP request or Neighbor Solicitation).
//! * Further packets for it are queued (at most `neighbor.queue`; the oldest is dropped).
//! * The entry asks again every `neighbor.retry`, **per neighbor**: two neighbors never delay each
//!   other (smoltcp's one-request-per-second-per-interface limit is exactly what this avoids).
//!   After `neighbor.attempts` requests and one more retry interval without an answer
//!   it **fails**: the entry is removed and its queue handed back, so the router can answer each
//!   forwarded packet with an ICMP host unreachable.
//! * An answer (or any ARP / NDP message that names the neighbor) makes the entry **reachable**
//!   and hands back its queue, in order, for transmission.
//! * A reachable entry is trusted for `neighbor.lifetime`, checked lazily when it is used, so an
//!   idle router has no timers.
//! * The table holds at most [`MAX_ENTRIES`] entries, whatever arrives off the wire. A new entry
//!   in a full table evicts the oldest one first (reachable: learned earliest; incomplete: asked
//!   earliest; ties in key order). An evicted incomplete entry's queued packets are dropped.
//!   Both are counted ([`NeighborTable::evicted`], [`NeighborTable::evicted_packets`]).
//!
//! Everything is keyed in `BTreeMap`s: iteration order (and therefore retry order) is
//! deterministic.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;

use wasmnet_wire::MacAddr;

use crate::config::NeighborConfig;

/// A packet waiting for its next hop's MAC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queued {
    /// The IP packet (no Ethernet header).
    pub packet: Vec<u8>,
    /// The port a forwarded packet came in on; `None` for packets the router originated.
    pub from: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Incomplete {
        /// When the first request went out.
        asked_ns: u64,
        /// Requests sent so far.
        attempts: u32,
        /// When to ask again (or give up).
        next_ns: u64,
        queue: VecDeque<Queued>,
    },
    Reachable {
        mac: MacAddr,
        learned_ns: u64,
    },
}

/// What [`NeighborTable::enqueue`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Enqueued {
    /// A new incomplete entry: send the first request now.
    Ask,
    /// Queued behind an outstanding request.
    Waiting,
    /// Queued, but the queue was full: this (oldest) packet was dropped.
    Overflow(Queued),
}

/// A neighbor that just became reachable, with what was waiting for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub asked_ns: u64,
    pub attempts: u32,
    pub queue: VecDeque<Queued>,
}

/// Timer work from [`NeighborTable::due`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Due {
    /// Ask again.
    Retry { port: u32, ip: IpAddr },
    /// No answer: the entry is gone, and these packets cannot be delivered.
    Failed {
        port: u32,
        ip: IpAddr,
        attempts: u32,
        queue: VecDeque<Queued>,
    },
}

/// The most entries (reachable and incomplete, over every port) the table holds.
pub const MAX_ENTRIES: usize = 1024;

impl State {
    /// When the entry was learned or first asked for: its age for eviction.
    fn since(&self) -> u64 {
        match self {
            State::Incomplete { asked_ns, .. } => *asked_ns,
            State::Reachable { learned_ns, .. } => *learned_ns,
        }
    }
}

/// Every neighbor of every port.
#[derive(Clone, Debug, Default)]
pub struct NeighborTable {
    entries: BTreeMap<(u32, IpAddr), State>,
    queued: usize,
    /// Most packets queued at once.
    pub queued_peak: usize,
    /// Entries evicted to make room ([`MAX_ENTRIES`]).
    pub evicted: u64,
    /// Queued packets dropped with an evicted incomplete entry.
    pub evicted_packets: u64,
}

impl NeighborTable {
    /// Makes room for a new entry `key` in a full table: evicts the oldest entry.
    fn make_room(&mut self, key: (u32, IpAddr)) {
        if self.entries.len() < MAX_ENTRIES || self.entries.contains_key(&key) {
            return;
        }
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(k, s)| (s.since(), **k))
            .map(|(k, _)| *k);
        if let Some(state) = oldest.and_then(|k| self.entries.remove(&k)) {
            self.evicted += 1;
            if let State::Incomplete { queue, .. } = state {
                self.queued -= queue.len();
                self.evicted_packets += queue.len() as u64;
            }
        }
    }

    /// The neighbor's MAC, if it is reachable and its entry is still fresh at `now`.
    pub fn lookup(
        &mut self,
        port: u32,
        ip: IpAddr,
        now: u64,
        cfg: &NeighborConfig,
    ) -> Option<MacAddr> {
        match self.entries.get(&(port, ip)) {
            Some(State::Reachable { mac, learned_ns }) => {
                if now.saturating_sub(*learned_ns) < cfg.lifetime_ns {
                    Some(*mac)
                } else {
                    self.entries.remove(&(port, ip));
                    None
                }
            }
            _ => None,
        }
    }

    /// Queues `packet` for an unresolved neighbor (the caller checked [`lookup`](Self::lookup)).
    pub fn enqueue(
        &mut self,
        port: u32,
        ip: IpAddr,
        packet: Queued,
        now: u64,
        cfg: &NeighborConfig,
    ) -> Enqueued {
        self.make_room((port, ip));
        let entry = self.entries.entry((port, ip)).or_insert(State::Incomplete {
            asked_ns: now,
            attempts: 0,
            next_ns: now,
            queue: VecDeque::new(),
        });
        let State::Incomplete {
            attempts,
            next_ns,
            queue,
            ..
        } = entry
        else {
            // Reachable but stale: start over.
            *entry = State::Incomplete {
                asked_ns: now,
                attempts: 1,
                next_ns: now + cfg.retry_ns,
                queue: VecDeque::from([packet]),
            };
            self.queued += 1;
            self.queued_peak = self.queued_peak.max(self.queued);
            return Enqueued::Ask;
        };
        queue.push_back(packet);
        self.queued += 1;
        self.queued_peak = self.queued_peak.max(self.queued);
        let fresh = *attempts == 0;
        if fresh {
            *attempts = 1;
            *next_ns = now + cfg.retry_ns;
        }
        if queue.len() > cfg.queue {
            self.queued -= 1;
            let oldest = queue.pop_front().expect("longer than the limit");
            return Enqueued::Overflow(oldest);
        }
        if fresh {
            Enqueued::Ask
        } else {
            Enqueued::Waiting
        }
    }

    /// Records that `ip` on `port` is at `mac` (from an ARP packet or an NDP message).
    ///
    /// An incomplete entry becomes reachable and its queue is returned. A reachable entry is
    /// refreshed. An unknown neighbor is added only when `create` is set (the message was aimed
    /// at us: RFC 826's "merge" rule, and RFC 4861 for solicitations).
    pub fn learn(
        &mut self,
        port: u32,
        ip: IpAddr,
        mac: MacAddr,
        now: u64,
        create: bool,
    ) -> Option<Resolved> {
        let key = (port, ip);
        let reachable = State::Reachable {
            mac,
            learned_ns: now,
        };
        match self.entries.get_mut(&key) {
            Some(State::Incomplete {
                asked_ns,
                attempts,
                queue,
                ..
            }) => {
                let resolved = Resolved {
                    asked_ns: *asked_ns,
                    attempts: *attempts,
                    queue: std::mem::take(queue),
                };
                self.queued -= resolved.queue.len();
                self.entries.insert(key, reachable);
                Some(resolved)
            }
            Some(state) => {
                *state = reachable;
                None
            }
            None => {
                if create {
                    self.make_room(key);
                    self.entries.insert(key, reachable);
                }
                None
            }
        }
    }

    /// Retries and failures due at `now`, in key order.
    pub fn due(&mut self, now: u64, cfg: &NeighborConfig) -> Vec<Due> {
        let mut work = Vec::new();
        let mut failed = Vec::new();
        for (&(port, ip), state) in &mut self.entries {
            if let State::Incomplete {
                attempts, next_ns, ..
            } = state
                && *next_ns <= now
            {
                if *attempts >= cfg.attempts {
                    failed.push((port, ip));
                } else {
                    *attempts += 1;
                    *next_ns = now + cfg.retry_ns;
                    work.push(Due::Retry { port, ip });
                }
            }
        }
        for key in failed {
            if let Some(State::Incomplete {
                attempts, queue, ..
            }) = self.entries.remove(&key)
            {
                self.queued -= queue.len();
                work.push(Due::Failed {
                    port: key.0,
                    ip: key.1,
                    attempts,
                    queue,
                });
            }
        }
        work
    }

    /// The earliest retry or failure deadline.
    pub fn next_deadline(&self) -> Option<u64> {
        self.entries
            .values()
            .filter_map(|s| match s {
                State::Incomplete { next_ns, .. } => Some(*next_ns),
                State::Reachable { .. } => None,
            })
            .min()
    }

    /// Forgets every neighbor of `port` (its link went down); returns the packets dropped.
    pub fn flush_port(&mut self, port: u32) -> usize {
        let keys: Vec<_> = self
            .entries
            .range((port, IpAddr::from([0u8; 4]))..)
            .take_while(|(k, _)| k.0 == port)
            .map(|(k, _)| *k)
            .collect();
        let mut dropped = 0;
        for k in keys {
            if let Some(State::Incomplete { queue, .. }) = self.entries.remove(&k) {
                dropped += queue.len();
            }
        }
        self.queued -= dropped;
        dropped
    }

    /// Entries (reachable and incomplete).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Packets queued right now.
    pub fn queued(&self) -> usize {
        self.queued
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    fn cfg() -> NeighborConfig {
        NeighborConfig {
            retry_ns: S,
            attempts: 3,
            queue: 2,
            lifetime_ns: 300 * S,
        }
    }

    fn q(n: u8) -> Queued {
        Queued {
            packet: vec![n],
            from: Some(0),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 9]);

    #[test]
    fn queue_then_resolve() {
        let (c, mut t) = (cfg(), NeighborTable::default());
        let a = ip("10.0.1.10");
        assert_eq!(t.lookup(0, a, 0, &c), None);
        assert_eq!(t.enqueue(0, a, q(1), 0, &c), Enqueued::Ask);
        assert_eq!(t.enqueue(0, a, q(2), 10, &c), Enqueued::Waiting);
        assert_eq!(
            t.enqueue(0, a, q(3), 20, &c),
            Enqueued::Overflow(q(1)),
            "oldest dropped"
        );
        assert_eq!(t.queued(), 2);
        assert_eq!(t.next_deadline(), Some(S));
        let r = t.learn(0, a, MAC, 400, false).unwrap();
        assert_eq!((r.asked_ns, r.attempts), (0, 1));
        assert_eq!(r.queue, VecDeque::from([q(2), q(3)]));
        assert_eq!(t.queued(), 0);
        assert_eq!(t.queued_peak, 3);
        assert_eq!(t.lookup(0, a, 500, &c), Some(MAC));
        assert_eq!(t.lookup(1, a, 500, &c), None, "per port");
        assert_eq!(t.next_deadline(), None);
    }

    #[test]
    fn retries_per_neighbor_then_fails() {
        let (c, mut t) = (cfg(), NeighborTable::default());
        let (a, b) = (ip("10.0.1.10"), ip("fd00:1::10"));
        assert_eq!(t.enqueue(0, a, q(1), 0, &c), Enqueued::Ask);
        // A second neighbor 10 ms later is asked at once: no shared rate limit.
        assert_eq!(t.enqueue(0, b, q(2), 10, &c), Enqueued::Ask);
        assert_eq!(t.due(S - 1, &c), vec![]);
        assert_eq!(t.due(S, &c), vec![Due::Retry { port: 0, ip: a }]);
        assert_eq!(t.due(S + 10, &c), vec![Due::Retry { port: 0, ip: b }]);
        assert_eq!(t.due(2 * S, &c), vec![Due::Retry { port: 0, ip: a }]);
        assert_eq!(t.next_deadline(), Some(2 * S + 10));
        t.due(2 * S + 10, &c);
        let failed = t.due(3 * S, &c);
        assert_eq!(
            failed,
            vec![Due::Failed {
                port: 0,
                ip: a,
                attempts: 3,
                queue: VecDeque::from([q(1)])
            }]
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn learning_rules_and_expiry() {
        let (c, mut t) = (cfg(), NeighborTable::default());
        let a = ip("10.0.1.10");
        assert_eq!(t.learn(0, a, MAC, 0, false), None);
        assert_eq!(t.lookup(0, a, 1, &c), None, "not aimed at us: not created");
        t.learn(0, a, MAC, 0, true);
        assert_eq!(t.lookup(0, a, 1, &c), Some(MAC));
        assert_eq!(t.lookup(0, a, 300 * S, &c), None, "expired when used");
        assert!(t.is_empty());
        t.learn(0, a, MAC, 0, true);
        // A stale entry starts a fresh resolution when a packet needs it.
        assert_eq!(t.enqueue(0, a, q(1), 400 * S, &c), Enqueued::Ask);
    }

    #[test]
    fn the_table_is_bounded_and_evicts_the_oldest() {
        let (c, mut t) = (cfg(), NeighborTable::default());
        let v4 = |n: usize| IpAddr::from([10, 0, (n >> 8) as u8, n as u8]);
        // The oldest: an incomplete entry with one packet queued, asked at 0.
        assert_eq!(t.enqueue(0, v4(0), q(1), 0, &c), Enqueued::Ask);
        for n in 1..MAX_ENTRIES {
            t.learn(0, v4(n), MAC, n as u64, true);
        }
        assert_eq!((t.len(), t.evicted), (MAX_ENTRIES, 0));
        // Refreshing a known neighbor needs no room.
        t.learn(0, v4(5), MAC, 5_000, true);
        assert_eq!((t.len(), t.evicted), (MAX_ENTRIES, 0));
        // A new one evicts the oldest: the incomplete entry, and its packet with it.
        t.learn(0, v4(MAX_ENTRIES), MAC, 10_000, true);
        assert_eq!(t.len(), MAX_ENTRIES);
        assert_eq!((t.evicted, t.evicted_packets, t.queued()), (1, 1, 0));
        assert_eq!(t.next_deadline(), None);
        // Then the reachable one learned earliest (v4(1), at 1 ns).
        assert_eq!(
            t.enqueue(1, v4(1), q(2), 20_000, &c),
            Enqueued::Ask,
            "a new key"
        );
        assert_eq!((t.len(), t.evicted), (MAX_ENTRIES, 2));
        assert_eq!(t.lookup(0, v4(1), 20_000, &c), None);
        assert_eq!(t.lookup(0, v4(2), 20_000, &c), Some(MAC));
    }

    #[test]
    fn link_down_flushes_one_port() {
        let (c, mut t) = (cfg(), NeighborTable::default());
        t.enqueue(0, ip("10.0.1.10"), q(1), 0, &c);
        t.enqueue(1, ip("10.0.2.10"), q(2), 0, &c);
        t.enqueue(1, ip("fd00:2::10"), q(3), 0, &c);
        t.learn(1, ip("10.0.2.20"), MAC, 0, true);
        assert_eq!(t.flush_port(1), 2);
        assert_eq!(t.len(), 1);
        assert_eq!(t.queued(), 1);
    }
}
