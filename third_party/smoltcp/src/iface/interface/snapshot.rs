//! wasmnet patch (feature `snapshot`): the interface state that a fresh
//! [`Interface`] built from the same configuration cannot rebuild, read and written back.
//!
//! Used for *quiescent* snapshots of a node: no connection, nothing in flight. Everything else
//! (addresses, routes, the hardware address) comes from the node's configuration, and sockets
//! are the embedder's to recreate. Collections keep their internal order (a `LinearMap` is a
//! vector: lookups, eviction and the order of multicast reports follow it), so a restored
//! interface behaves exactly like the saved one, frame for frame.

use alloc::vec::Vec;

#[cfg(feature = "multicast")]
use super::multicast::{GroupState, IgmpReportState, MldReportState};
use super::{Interface, InterfaceInner};
use crate::iface::neighbor::Neighbor;
use crate::time::{Duration, Instant};
use crate::wire::{HardwareAddress, IgmpVersion, IpAddress, Ipv4Address, Ipv6Address};

/// A multicast group's membership state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupPhase {
    /// The join report is still to be sent.
    Joining,
    /// Joined, nothing to send.
    Joined,
    /// The leave report is still to be sent.
    Leaving,
}

/// When the interface answers a pending IGMP query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpReport {
    Inactive,
    /// `v1`: IGMPv1, else v2.
    ToGeneralQuery {
        v1: bool,
        timeout: Instant,
        interval: Duration,
        next_index: usize,
    },
    ToSpecificQuery {
        v1: bool,
        timeout: Instant,
        group: Ipv4Address,
    },
}

/// When the interface answers a pending MLD query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MldReport {
    Inactive,
    ToGeneralQuery { timeout: Instant },
    ToSpecificQuery { group: Ipv6Address, timeout: Instant },
}

/// The interface state a snapshot keeps, in the interface's own order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceState {
    /// The random generator's state (TCP initial sequence numbers, source ports, MLD delays).
    pub rand: u64,
    /// The IPv4 fragment identifier (with `proto-ipv4-fragmentation`).
    pub ipv4_id: Option<u16>,
    /// The neighbor cache: address, hardware address, expiry.
    pub neighbors: Vec<(IpAddress, HardwareAddress, Instant)>,
    /// Addresses with a discovery request in flight, and when the next may be sent.
    pub silent_until: Vec<(IpAddress, Instant)>,
    /// Multicast groups (with `multicast`).
    pub groups: Vec<(IpAddress, GroupPhase)>,
    pub igmp: IgmpReport,
    pub mld: MldReport,
}

fn v1(v: IgmpVersion) -> bool {
    matches!(v, IgmpVersion::Version1)
}

fn version(v1: bool) -> IgmpVersion {
    if v1 {
        IgmpVersion::Version1
    } else {
        IgmpVersion::Version2
    }
}

impl InterfaceInner {
    fn snapshot(&self) -> InterfaceState {
        #[cfg(feature = "proto-ipv4-fragmentation")]
        let ipv4_id = Some(self.ipv4_id);
        #[cfg(not(feature = "proto-ipv4-fragmentation"))]
        let ipv4_id = None;
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        let (neighbors, silent_until) = (
            self.neighbor_cache
                .storage
                .iter()
                .map(|(a, n)| (*a, n.hardware_addr, n.expires_at))
                .collect(),
            self.neighbor_cache
                .silent_until
                .iter()
                .map(|(a, t)| (*a, *t))
                .collect(),
        );
        #[cfg(not(any(feature = "medium-ethernet", feature = "medium-ieee802154")))]
        let (neighbors, silent_until) = (Vec::new(), Vec::new());
        #[cfg(feature = "multicast")]
        let (groups, igmp, mld) = {
            let groups = self
                .multicast
                .groups
                .iter()
                .map(|(a, s)| {
                    (
                        *a,
                        match s {
                            GroupState::Joining => GroupPhase::Joining,
                            GroupState::Joined => GroupPhase::Joined,
                            GroupState::Leaving => GroupPhase::Leaving,
                        },
                    )
                })
                .collect();
            #[cfg(feature = "proto-ipv4")]
            let igmp = match &self.multicast.igmp_report_state {
                IgmpReportState::Inactive => IgmpReport::Inactive,
                IgmpReportState::ToGeneralQuery {
                    version,
                    timeout,
                    interval,
                    next_index,
                } => IgmpReport::ToGeneralQuery {
                    v1: v1(*version),
                    timeout: *timeout,
                    interval: *interval,
                    next_index: *next_index,
                },
                IgmpReportState::ToSpecificQuery {
                    version,
                    timeout,
                    group,
                } => IgmpReport::ToSpecificQuery {
                    v1: v1(*version),
                    timeout: *timeout,
                    group: *group,
                },
            };
            #[cfg(not(feature = "proto-ipv4"))]
            let igmp = IgmpReport::Inactive;
            #[cfg(feature = "proto-ipv6")]
            let mld = match &self.multicast.mld_report_state {
                MldReportState::Inactive => MldReport::Inactive,
                MldReportState::ToGeneralQuery { timeout } => {
                    MldReport::ToGeneralQuery { timeout: *timeout }
                }
                MldReportState::ToSpecificQuery { group, timeout } => MldReport::ToSpecificQuery {
                    group: *group,
                    timeout: *timeout,
                },
            };
            #[cfg(not(feature = "proto-ipv6"))]
            let mld = MldReport::Inactive;
            (groups, igmp, mld)
        };
        #[cfg(not(feature = "multicast"))]
        let (groups, igmp, mld) = (Vec::new(), IgmpReport::Inactive, MldReport::Inactive);
        InterfaceState {
            rand: self.rand.state,
            ipv4_id,
            neighbors,
            silent_until,
            groups,
            igmp,
            mld,
        }
    }

    fn restore(&mut self, s: &InterfaceState) -> Result<(), &'static str> {
        self.rand.state = s.rand;
        #[cfg(feature = "proto-ipv4-fragmentation")]
        if let Some(id) = s.ipv4_id {
            self.ipv4_id = id;
        }
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        {
            let cache = &mut self.neighbor_cache;
            cache.storage.clear();
            for (a, hw, t) in &s.neighbors {
                let n = Neighbor {
                    hardware_addr: *hw,
                    expires_at: *t,
                };
                cache
                    .storage
                    .insert(*a, n)
                    .map_err(|_| "too many neighbors")?;
            }
            cache.silent_until.clear();
            for (a, t) in &s.silent_until {
                cache
                    .silent_until
                    .insert(*a, *t)
                    .map_err(|_| "too many neighbor requests")?;
            }
        }
        #[cfg(feature = "multicast")]
        {
            let m = &mut self.multicast;
            m.groups.clear();
            for (a, p) in &s.groups {
                let state = match p {
                    GroupPhase::Joining => GroupState::Joining,
                    GroupPhase::Joined => GroupState::Joined,
                    GroupPhase::Leaving => GroupState::Leaving,
                };
                m.groups
                    .insert(*a, state)
                    .map_err(|_| "too many multicast groups")?;
            }
            #[cfg(feature = "proto-ipv4")]
            {
                m.igmp_report_state = match s.igmp {
                    IgmpReport::Inactive => IgmpReportState::Inactive,
                    IgmpReport::ToGeneralQuery {
                        v1,
                        timeout,
                        interval,
                        next_index,
                    } => IgmpReportState::ToGeneralQuery {
                        version: version(v1),
                        timeout,
                        interval,
                        next_index,
                    },
                    IgmpReport::ToSpecificQuery { v1, timeout, group } => {
                        IgmpReportState::ToSpecificQuery {
                            version: version(v1),
                            timeout,
                            group,
                        }
                    }
                };
            }
            #[cfg(feature = "proto-ipv6")]
            {
                m.mld_report_state = match s.mld {
                    MldReport::Inactive => MldReportState::Inactive,
                    MldReport::ToGeneralQuery { timeout } => {
                        MldReportState::ToGeneralQuery { timeout }
                    }
                    MldReport::ToSpecificQuery { group, timeout } => {
                        MldReportState::ToSpecificQuery { group, timeout }
                    }
                };
            }
        }
        Ok(())
    }
}

impl Interface {
    /// The interface state a fresh interface with the same configuration cannot rebuild.
    pub fn snapshot_state(&self) -> InterfaceState {
        self.inner.snapshot()
    }

    /// Puts `state` back. Call it on an interface built from the same configuration (its
    /// addresses set, so the solicited-node groups exist); `state` replaces the neighbor cache
    /// and the multicast groups wholesale. Fails, leaving the interface partly restored, only if
    /// `state` does not fit this build's table sizes.
    pub fn restore_state(&mut self, state: &InterfaceState) -> Result<(), &'static str> {
        self.inner.restore(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iface::Config;
    use crate::phy::{Loopback, Medium};
    use crate::wire::{EthernetAddress, IpCidr};

    fn iface(seed: u64) -> (Interface, Loopback) {
        let mut dev = Loopback::new(Medium::Ethernet);
        let mut cfg = Config::new(HardwareAddress::Ethernet(EthernetAddress([
            2, 0, 0, 0, 0, 1,
        ])));
        cfg.random_seed = seed;
        let mut iface = Interface::new(cfg, &mut dev, Instant::ZERO);
        iface.update_ip_addrs(|a| {
            a.push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24)).unwrap();
            a.push(IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64))
                .unwrap();
        });
        (iface, dev)
    }

    #[test]
    fn a_state_round_trips_onto_a_fresh_interface() {
        let (mut a, _) = iface(7);
        let peer = HardwareAddress::Ethernet(EthernetAddress([2, 0, 0, 0, 0, 2]));
        a.inner
            .neighbor_cache
            .fill(IpAddress::v4(10, 0, 0, 2), peer, Instant::from_secs(1));
        a.inner
            .neighbor_cache
            .limit_rate(IpAddress::v4(10, 0, 0, 3), Instant::from_secs(2));
        a.join_multicast_group(IpAddress::v4(224, 0, 0, 251)).unwrap();
        a.inner.rand.rand_u32();
        let saved = a.snapshot_state();
        assert_eq!(saved.neighbors.len(), 1);
        assert!(saved.groups.len() >= 2, "{:?}", saved.groups);

        let (mut b, _) = iface(99);
        assert_ne!(b.snapshot_state(), saved);
        b.restore_state(&saved).unwrap();
        assert_eq!(b.snapshot_state(), saved);
        // Both draw the same numbers from here on.
        assert_eq!(a.inner.rand.rand_u32(), b.inner.rand.rand_u32());
    }
}
