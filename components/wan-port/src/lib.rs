//! wan-port: an L2 WAN port. It terminates one end of a **bridged WAN link**: a
//! network segment on one site is bridged to a segment on another site, like a metro-Ethernet
//! circuit, using VXLAN-style encapsulation (RFC 7348).
//!
//! Port 0 (`access`) faces the site's LAN: whatever Ethernet frame arrives there is
//! encapsulated as `Ethernet / IPv4 / UDP 4789 / VXLAN(VNI) / inner frame` and sent out of
//! port 1 (`wan`) towards the peer WAN port. A frame arriving on the WAN side that is addressed
//! to this port (its MAC, its IPv4 address, UDP port 4789, the VXLAN "I" flag and our VNI) is
//! decapsulated and sent out of the access port. Everything else is dropped and reported
//! (`wan-drop`), never trapped on.
//!
//! The WAN side is an ordinary link, usually the WAN link between two sites: its pcap
//! shows real VXLAN that Wireshark decodes. The port never knows how the WAN link is carried
//! (in-process, UDP, QUIC, WebRTC: the carrier is the site sync's business).
//!
//! An L3 (routed) WAN link needs no device at all: a router port on the WAN link is the WAN
//! port, and its static routes via the peer router are the WAN routes.
//!
//! **MTU.** Encapsulation adds [`OVERHEAD`] bytes (outer Ethernet 14, IPv4 20, UDP 8, VXLAN 8).
//! The access port declares `mtu` (default 1500) and the WAN port `mtu + 54` (room for an
//! 802.1Q tag on the inner frame), so a full-size inner frame fits, like a WAN with
//! jumbo-enough frames. An inner frame whose payload exceeds the access MTU never gets here
//! (the access link drops it first).
//!
//! **Determinism.** The outer IPv4 identification is a per-port counter, and the outer UDP
//! source port is a hash of the inner Ethernet header (RFC 7348 §5: entropy for ECMP), so the
//! same inner traffic always gives the same bytes.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::fmt;
use std::net::Ipv4Addr;

use wasmnet_wire::{EtherType, EthernetFrame, MacAddr};

/// Outer Ethernet + IPv4 + UDP + VXLAN.
pub const OVERHEAD: u32 = 14 + 20 + 8 + 8;
/// IANA's VXLAN port.
pub const VXLAN_PORT: u16 = 4789;
/// The access (LAN) port.
pub const ACCESS: u32 = 0;
/// The WAN port, towards the peer WAN port.
pub const WAN: u32 = 1;

/// The WAN port's configuration.
///
/// Keys: `ip` and `peer-ip` (WAN-side IPv4 addresses, required), `mac` (this port's
/// WAN-side MAC, required), `peer-mac` (the peer's WAN-side MAC; default broadcast),
/// `vni` (0..=16777215, default 1), `mtu` (access MTU, 68..=65000, default 1500) and
/// `udp-port` (default 4789).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub ip: Ipv4Addr,
    pub peer_ip: Ipv4Addr,
    pub mac: MacAddr,
    pub peer_mac: MacAddr,
    pub vni: u32,
    pub mtu: u32,
    pub udp_port: u16,
}

/// A config value that could not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub key: &'static str,
    pub value: Option<String>,
    pub expected: &'static str,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(v) => write!(f, "config {}={v:?}: expected {}", self.key, self.expected),
            None => write!(f, "config {} is required: {}", self.key, self.expected),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Reads the config through `get(key)`.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        fn read<T>(
            get: &impl Fn(&str) -> Option<String>,
            key: &'static str,
            expected: &'static str,
            parse: impl Fn(&str) -> Option<T>,
            default: Option<T>,
        ) -> Result<T, ConfigError> {
            match (get(key), default) {
                (None, Some(d)) => Ok(d),
                (None, None) => Err(ConfigError {
                    key,
                    value: None,
                    expected,
                }),
                (Some(value), _) => parse(&value).ok_or(ConfigError {
                    key,
                    value: Some(value),
                    expected,
                }),
            }
        }
        let ip = |v: &str| v.parse::<Ipv4Addr>().ok();
        let mac = |v: &str| v.parse::<MacAddr>().ok();
        Ok(Self {
            ip: read(&get, "ip", "an IPv4 address", ip, None)?,
            peer_ip: read(&get, "peer-ip", "an IPv4 address", ip, None)?,
            mac: read(
                &get,
                "mac",
                "a unicast MAC address",
                |v| mac(v).filter(|m| m.is_unicast()),
                None,
            )?,
            peer_mac: read(
                &get,
                "peer-mac",
                "a MAC address",
                mac,
                Some(MacAddr::BROADCAST),
            )?,
            vni: read(
                &get,
                "vni",
                "an integer from 0 to 16777215",
                |v| v.parse().ok().filter(|&n| n < 1 << 24),
                Some(1),
            )?,
            mtu: read(
                &get,
                "mtu",
                "an integer from 68 to 65000",
                |v| v.parse().ok().filter(|n| (68..=65_000).contains(n)),
                Some(1500),
            )?,
            udp_port: read(
                &get,
                "udp-port",
                "a UDP port from 1 to 65535",
                |v| v.parse().ok().filter(|&p| p > 0),
                Some(VXLAN_PORT),
            )?,
        })
    }
}

/// Why a frame was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Drop {
    /// Arrived on a port that is down, or an unknown port.
    PortDown,
    /// The WAN frame is not IPv4/UDP to us on the VXLAN port (or is malformed).
    NotForUs,
    /// A VXLAN header without the "I" flag, or with another VNI.
    WrongVni,
    /// The decapsulated payload is not an Ethernet frame.
    BadInner,
}

impl Drop {
    pub fn as_str(self) -> &'static str {
        match self {
            Drop::PortDown => "port-down",
            Drop::NotForUs => "not-for-us",
            Drop::WrongVni => "wrong-vni",
            Drop::BadInner => "bad-inner",
        }
    }
}

/// Counters, reported in the `wan-drop` events and readable for tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub encapsulated: u64,
    pub decapsulated: u64,
    pub dropped: u64,
}

/// What the WAN port tells the outside world.
pub trait Sink {
    fn transmit(&mut self, port: u32, frame: &[u8]);
    /// A structured event: `kind` and its fields.
    fn event(&mut self, kind: &str, fields: &[(String, String)]);
}

/// The WAN port.
pub struct WanPort {
    config: Config,
    up: [bool; 2],
    ip_id: u16,
    counters: Counters,
}

impl WanPort {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            up: [false; 2],
            ip_id: 0,
            counters: Counters::default(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// One line for the log.
    pub fn describe(&self) -> String {
        let c = &self.config;
        format!(
            "vxlan vni {} {} -> {} udp {}, access mtu {}",
            c.vni, c.ip, c.peer_ip, c.udp_port, c.mtu
        )
    }

    pub fn link_state(&mut self, port: u32, up: bool) {
        if let Some(p) = self.up.get_mut(port as usize) {
            *p = up;
        }
    }

    pub fn receive(&mut self, port: u32, frame: &[u8], sink: &mut impl Sink) {
        if !self.up.get(port as usize).copied().unwrap_or(false) {
            return self.drop(Drop::PortDown, port, sink);
        }
        match port {
            ACCESS => {
                let out = self.encapsulate(frame);
                if self.up[WAN as usize] {
                    self.counters.encapsulated += 1;
                    sink.transmit(WAN, &out);
                } else {
                    self.drop(Drop::PortDown, WAN, sink);
                }
            }
            _ => match self.decapsulate(frame) {
                Ok(inner) if self.up[ACCESS as usize] => {
                    self.counters.decapsulated += 1;
                    sink.transmit(ACCESS, inner);
                }
                Ok(_) => self.drop(Drop::PortDown, ACCESS, sink),
                Err(reason) => self.drop(reason, port, sink),
            },
        }
    }

    fn drop(&mut self, reason: Drop, port: u32, sink: &mut impl Sink) {
        self.counters.dropped += 1;
        sink.event(
            "wan-drop",
            &[
                ("reason".to_owned(), reason.as_str().to_owned()),
                ("port".to_owned(), port.to_string()),
                ("dropped".to_owned(), self.counters.dropped.to_string()),
            ],
        );
    }

    /// `Ethernet / IPv4 / UDP / VXLAN / inner`.
    pub fn encapsulate(&mut self, inner: &[u8]) -> Vec<u8> {
        let c = self.config;
        let udp_len = 8 + 8 + inner.len();
        let ip_len = 20 + udp_len;
        let mut out = Vec::with_capacity(14 + ip_len);
        out.extend_from_slice(&c.peer_mac.octets());
        out.extend_from_slice(&c.mac.octets());
        out.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());
        // IPv4: version 4, IHL 5, DF, TTL 64, UDP.
        let id = self.ip_id;
        self.ip_id = self.ip_id.wrapping_add(1);
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(ip_len.min(0xffff) as u16).to_be_bytes());
        ip[4..6].copy_from_slice(&id.to_be_bytes());
        ip[6] = 0x40;
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&c.ip.octets());
        ip[16..20].copy_from_slice(&c.peer_ip.octets());
        let sum = checksum(&ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        out.extend_from_slice(&ip);
        // UDP: an entropy source port from the inner L2 header (RFC 7348 §5), no checksum.
        out.extend_from_slice(&source_port(inner).to_be_bytes());
        out.extend_from_slice(&c.udp_port.to_be_bytes());
        out.extend_from_slice(&(udp_len.min(0xffff) as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        // VXLAN: flags (I), reserved, VNI, reserved.
        out.extend_from_slice(&[0x08, 0, 0, 0]);
        out.extend_from_slice(&(c.vni << 8).to_be_bytes());
        out.extend_from_slice(inner);
        out
    }

    /// The inner frame of a WAN frame for us, or why not.
    pub fn decapsulate<'f>(&self, frame: &'f [u8]) -> Result<&'f [u8], Drop> {
        let c = self.config;
        let eth = EthernetFrame::new_checked(frame).map_err(|_| Drop::NotForUs)?;
        // To this port's MAC, or to broadcast: a peer configured without `peer-mac` sends to
        // broadcast, and the IP and UDP checks below still tell whose frame it is.
        let ours = eth.dst() == c.mac || eth.dst() == MacAddr::BROADCAST;
        if !ours || eth.ethertype() != EtherType::IPV4 {
            return Err(Drop::NotForUs);
        }
        let ip = &frame[eth.header_len()..];
        if ip.len() < 20 || ip[0] >> 4 != 4 {
            return Err(Drop::NotForUs);
        }
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
        let fragmented = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0;
        if ihl < 20 || total < ihl || total > ip.len() || ip[9] != 17 || fragmented {
            return Err(Drop::NotForUs);
        }
        // Only from the peer, to us, with a valid header (RFC 791: a header whose checksum
        // fails is discarded).
        if ip[16..20] != c.ip.octets() || ip[12..16] != c.peer_ip.octets() {
            return Err(Drop::NotForUs);
        }
        if checksum(&ip[..ihl]) != 0 {
            return Err(Drop::NotForUs);
        }
        let udp = &ip[ihl..total];
        if udp.len() < 16 || u16::from_be_bytes([udp[2], udp[3]]) != c.udp_port {
            return Err(Drop::NotForUs);
        }
        let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
        if udp_len < 16 || udp_len > udp.len() {
            return Err(Drop::NotForUs);
        }
        let vxlan = &udp[8..16];
        let vni = u32::from_be_bytes([vxlan[4], vxlan[5], vxlan[6], vxlan[7]]) >> 8;
        if vxlan[0] & 0x08 == 0 || vni != c.vni {
            return Err(Drop::WrongVni);
        }
        let inner = &udp[16..udp_len];
        EthernetFrame::new_checked(inner).map_err(|_| Drop::BadInner)?;
        Ok(inner)
    }
}

/// The Internet checksum of an IPv4 header (with its checksum field zero).
fn checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .chunks(2)
        .map(|w| u32::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A UDP source port in the dynamic range (49152..=65535) from the inner Ethernet header
/// (FNV-1a over destination, source and EtherType).
fn source_port(inner: &[u8]) -> u16 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in inner.iter().take(14) {
        h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    0xc000 | (h as u16 & 0x3fff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn config(ip: &str, peer: &str, mac: &str, peer_mac: &str) -> Config {
        let map = BTreeMap::from([
            ("ip", ip),
            ("peer-ip", peer),
            ("mac", mac),
            ("peer-mac", peer_mac),
            ("vni", "42"),
        ]);
        Config::from_lookup(|k| map.get(k).map(|v| (*v).to_owned())).unwrap()
    }

    fn pair() -> (WanPort, WanPort) {
        let mut a = WanPort::new(config(
            "192.0.2.1",
            "192.0.2.2",
            "02:00:00:00:aa:01",
            "02:00:00:00:aa:02",
        ));
        let mut b = WanPort::new(config(
            "192.0.2.2",
            "192.0.2.1",
            "02:00:00:00:aa:02",
            "02:00:00:00:aa:01",
        ));
        for t in [&mut a, &mut b] {
            t.link_state(ACCESS, true);
            t.link_state(WAN, true);
        }
        (a, b)
    }

    #[derive(Default)]
    struct Out {
        frames: Vec<(u32, Vec<u8>)>,
        events: Vec<String>,
    }

    impl Sink for Out {
        fn transmit(&mut self, port: u32, frame: &[u8]) {
            self.frames.push((port, frame.to_vec()));
        }
        fn event(&mut self, kind: &str, fields: &[(String, String)]) {
            self.events.push(format!("{kind} {fields:?}"));
        }
    }

    fn inner() -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 0x10, 0x02, 0, 0, 0, 0, 0x20, 0x08, 0x00];
        f.extend(std::iter::repeat_n(0xab, 100));
        f
    }

    #[test]
    fn a_frame_crosses_the_wan_link_unchanged() {
        let (mut a, mut b) = pair();
        let mut out = Out::default();
        a.receive(ACCESS, &inner(), &mut out);
        let (port, wire) = out.frames.pop().unwrap();
        assert_eq!(port, WAN);
        assert_eq!(wire.len(), inner().len() + OVERHEAD as usize);
        assert_eq!(checksum(&wire[14..34]), 0, "valid IPv4 header checksum");
        assert_eq!(&wire[36..38], &VXLAN_PORT.to_be_bytes());
        b.receive(WAN, &wire, &mut out);
        assert_eq!(out.frames, [(ACCESS, inner())]);
        assert_eq!(a.counters().encapsulated, 1);
        assert_eq!(b.counters().decapsulated, 1);
        assert!(out.events.is_empty());
    }

    /// Without `peer-mac` a port sends to broadcast, and its peer must take such a frame: the
    /// two-key configuration (`ip`, `peer-ip`, `mac`) has to bridge.
    #[test]
    fn two_ports_without_peer_mac_still_bridge() {
        let port = |ip: &str, peer_ip: &str, mac: &str| {
            let map = BTreeMap::from([("ip", ip), ("peer-ip", peer_ip), ("mac", mac)]);
            let config = Config::from_lookup(|k| map.get(k).map(|v| (*v).to_owned())).unwrap();
            assert_eq!(config.peer_mac, MacAddr::BROADCAST);
            let mut port = WanPort::new(config);
            port.link_state(ACCESS, true);
            port.link_state(WAN, true);
            port
        };
        let mut a = port("192.0.2.1", "192.0.2.2", "02:00:00:00:aa:01");
        let mut b = port("192.0.2.2", "192.0.2.1", "02:00:00:00:aa:02");
        let mut out = Out::default();
        a.receive(ACCESS, &inner(), &mut out);
        let (_, wire) = out.frames.pop().unwrap();
        b.receive(WAN, &wire, &mut out);
        assert_eq!(out.frames, [(ACCESS, inner())]);
        // A broadcast frame for another address pair is still not ours.
        assert_eq!(a.decapsulate(&wire), Err(Drop::NotForUs));
    }

    #[test]
    fn encapsulation_is_deterministic_and_counts_ip_ids() {
        let (mut a, _) = pair();
        let (mut a2, _) = pair();
        let one = a.encapsulate(&inner());
        assert_eq!(one, a2.encapsulate(&inner()));
        let two = a.encapsulate(&inner());
        assert_eq!(u16::from_be_bytes([two[18], two[19]]), 1);
    }

    #[test]
    fn foreign_and_malformed_wan_frames_are_dropped() {
        let (mut a, mut b) = pair();
        let wire = a.encapsulate(&inner());
        // Our own encapsulation is not for us (wrong MAC and IP).
        assert_eq!(a.decapsulate(&wire), Err(Drop::NotForUs));
        let mut wrong_vni = wire.clone();
        wrong_vni[46] ^= 1;
        assert_eq!(b.decapsulate(&wrong_vni), Err(Drop::WrongVni));
        for len in 0..wire.len() - 14 {
            assert!(b.decapsulate(&wire[..len]).is_err(), "truncated to {len}");
        }
        let mut out = Out::default();
        b.receive(WAN, &wrong_vni, &mut out);
        assert!(out.frames.is_empty());
        assert_eq!(out.events.len(), 1);
        assert!(out.events[0].contains("wrong-vni"));
        b.link_state(ACCESS, false);
        b.receive(WAN, &wire, &mut out);
        assert!(out.events[1].contains("port-down"));
    }

    #[test]
    fn only_the_peer_with_a_valid_header_is_decapsulated() {
        let (mut a, b) = pair();
        let wire = a.encapsulate(&inner());
        assert!(b.decapsulate(&wire).is_ok());
        // A bad IPv4 header checksum (RFC 791).
        let mut bad_sum = wire.clone();
        bad_sum[24] ^= 0xff;
        assert_eq!(b.decapsulate(&bad_sum), Err(Drop::NotForUs));
        // Another source than `peer-ip`, with its checksum fixed up.
        let mut forged = wire.clone();
        forged[29] = 99;
        forged[24..26].copy_from_slice(&[0, 0]);
        let sum = checksum(&forged[14..34]);
        forged[24..26].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(checksum(&forged[14..34]), 0);
        assert_eq!(b.decapsulate(&forged), Err(Drop::NotForUs));
    }

    #[test]
    fn config_requires_addresses_and_checks_ranges() {
        let err = Config::from_lookup(|_| None).unwrap_err();
        assert_eq!(err.key, "ip");
        let map = BTreeMap::from([
            ("ip", "10.0.0.1"),
            ("peer-ip", "10.0.0.2"),
            ("mac", "02:00:00:00:00:01"),
            ("vni", "16777216"),
        ]);
        let err = Config::from_lookup(|k| map.get(k).map(|v| (*v).to_owned())).unwrap_err();
        assert_eq!(err.key, "vni");
    }
}
