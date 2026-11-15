//! Shared by the end-to-end tests: the built components and nodes, device configs, and small
//! readers for the journal and the frame log.
//!
//! Everything is built once per test binary with `cargo xtask build`, which needs `wac` and
//! `wasm-tools` on `PATH` (versions in the workspace README).

#![allow(dead_code)] // each test binary uses its own part

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use wasmnet_host::{
    DeviceConfig, DeviceId, FrameRecord, Host, JournalEntry, Network, PortRef, Record,
};
use wasmtime::component::Component;

/// The host and the directory `cargo xtask build` wrote the components and nodes into.
pub struct Built {
    pub host: Host,
    dir: PathBuf,
}

impl Built {
    /// Loads `<name>.wasm`: a component (`switch`, `router`) or a composed node
    /// (`node-http-server`).
    pub fn load(&self, name: &str) -> Component {
        let path = self.dir.join(format!("{name}.wasm"));
        self.host
            .load(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }
}

/// Builds every component and node once, then hands out the same [`Built`].
pub fn built() -> &'static Built {
    static BUILT: OnceLock<Built> = OnceLock::new();
    BUILT.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target =
            std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
        // The xtask binary gets a directory of its own, so it never replaces another
        // workspace's `xtask` in a shared target directory.
        let status = Command::new(env!("CARGO"))
            .current_dir(&root)
            .args(["run", "--quiet", "--package", "xtask", "--target-dir"])
            .arg(target.join("xtask"))
            .args(["--", "build"])
            .status()
            .expect("spawn cargo xtask build");
        assert!(
            status.success(),
            "`cargo xtask build` failed (it needs `wac` and `wasm-tools` on PATH)"
        );
        let dir = target.join("wasm32-wasip2/release");
        Built {
            host: Host::new().expect("host"),
            dir,
        }
    })
}

/// A device config from `key = value` pairs. Nested keys are dotted:
/// `app.http-get.url`, `hosts.web`, `port0.ipv4`.
pub fn config(pairs: &[(&str, &str)]) -> DeviceConfig {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// The fields of every `kind` event `device` journalled, in order.
pub fn events(journal: &[JournalEntry], device: &str, kind: &str) -> Vec<Vec<(String, String)>> {
    journal
        .iter()
        .filter(|e| e.device == device)
        .filter_map(|e| match &e.record {
            Record::Event { kind: k, fields } if k == kind => Some(fields.clone()),
            _ => None,
        })
        .collect()
}

/// The value of `name` among an event's fields.
pub fn field<'a>(fields: &'a [(String, String)], name: &str) -> &'a str {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("no field `{name}` in {fields:?}"))
}

/// The journal as text, for failure messages: `t=<ns> <device> <record>`.
pub fn transcript(journal: &[JournalEntry]) -> String {
    journal
        .iter()
        .map(|e| format!("t={} {} {:?}\n", e.at, e.device, e.record))
        .collect()
}

/// What a test wants to know about one TCP segment on the wire.
#[derive(Debug)]
pub struct Segment {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    /// The IPv4 TTL or the IPv6 hop limit.
    pub hop_limit: u8,
    pub payload: Vec<u8>,
}

/// The frame's TCP segment, if it carries one.
pub fn segment(frame: &[u8]) -> Option<Segment> {
    let packet = SlicedPacket::from_ethernet(frame).ok()?;
    let hop_limit = match packet.net.as_ref()? {
        NetSlice::Ipv4(ip) => ip.header().ttl(),
        NetSlice::Ipv6(ip) => ip.header().hop_limit(),
        _ => return None,
    };
    let TransportSlice::Tcp(tcp) = packet.transport? else {
        return None;
    };
    Some(Segment {
        syn: tcp.syn(),
        ack: tcp.ack(),
        fin: tcp.fin(),
        rst: tcp.rst(),
        hop_limit,
        payload: tcp.payload().to_vec(),
    })
}

/// The EtherType of a frame (`0x0806` is ARP), without looking at VLAN tags.
pub fn ethertype(frame: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]))
}

/// The frames `port` transmitted, in transmit order.
pub fn sent_by(frames: &[FrameRecord], port: PortRef) -> Vec<&FrameRecord> {
    frames.iter().filter(|f| f.from == port).collect()
}

/// The TCP segments `port` transmitted, in transmit order.
pub fn segments_from(frames: &[FrameRecord], port: PortRef) -> Vec<Segment> {
    sent_by(frames, port)
        .into_iter()
        .filter_map(|f| segment(&f.bytes))
        .collect()
}

/// Every link's pcap-ng capture, in link order.
pub fn pcaps(network: &Network) -> Vec<Vec<u8>> {
    network
        .links()
        .into_iter()
        .map(|l| network.pcap(l))
        .collect()
}

/// Frames dropped at any of `devices` (a clean run drops none).
pub fn dropped(network: &Network, devices: &[DeviceId]) -> u64 {
    devices.iter().map(|d| network.dropped(*d)).sum()
}

/// What a test wants to know about one UDP datagram on the wire.
#[derive(Debug)]
pub struct Datagram {
    pub src_port: u16,
    pub dst_port: u16,
    /// The IPv4 TTL or the IPv6 hop limit.
    pub hop_limit: u8,
    pub payload: Vec<u8>,
}

/// The frame's UDP datagram, if it carries one.
pub fn datagram(frame: &[u8]) -> Option<Datagram> {
    let packet = SlicedPacket::from_ethernet(frame).ok()?;
    let hop_limit = match packet.net.as_ref()? {
        NetSlice::Ipv4(ip) => ip.header().ttl(),
        NetSlice::Ipv6(ip) => ip.header().hop_limit(),
        _ => return None,
    };
    let TransportSlice::Udp(udp) = packet.transport? else {
        return None;
    };
    Some(Datagram {
        src_port: udp.source_port(),
        dst_port: udp.destination_port(),
        hop_limit,
        payload: udp.payload().to_vec(),
    })
}

/// The UDP datagrams `port` transmitted, in transmit order.
pub fn datagrams_from(frames: &[FrameRecord], port: PortRef) -> Vec<Datagram> {
    sent_by(frames, port)
        .into_iter()
        .filter_map(|f| datagram(&f.bytes))
        .collect()
}

/// The DHCP message type (option 53: 1 DISCOVER, 2 OFFER, 3 REQUEST, 5 ACK) of every DHCP
/// message `port` transmitted (UDP ports 67 and 68), in transmit order.
pub fn dhcp_types_from(frames: &[FrameRecord], port: PortRef) -> Vec<u8> {
    datagrams_from(frames, port)
        .into_iter()
        .filter(|d| matches!((d.src_port, d.dst_port), (68, 67) | (67, 68) | (67, 67)))
        .filter_map(|d| dhcp_type(&d.payload))
        .collect()
}

/// Option 53 of a BOOTP/DHCP message: after the 236-byte header and the magic cookie.
pub fn dhcp_type(message: &[u8]) -> Option<u8> {
    let mut options = message.get(240..)?;
    while let [code, rest @ ..] = options {
        match *code {
            0 => options = rest,
            255 => return None,
            _ => {
                let (&len, rest) = rest.split_first()?;
                let value = rest.get(..len as usize)?;
                if *code == 53 {
                    return value.first().copied();
                }
                options = &rest[len as usize..];
            }
        }
    }
    None
}

/// A DNS message on UDP port 53, reduced to what a test asserts: whether it is a response, its
/// response code and its first question's name.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsMessage {
    pub response: bool,
    pub rcode: u8,
    pub name: String,
}

/// The DNS messages `port` transmitted (to or from UDP port 53), in transmit order.
pub fn dns_messages_from(frames: &[FrameRecord], port: PortRef) -> Vec<DnsMessage> {
    datagrams_from(frames, port)
        .into_iter()
        .filter(|d| d.src_port == 53 || d.dst_port == 53)
        .filter_map(|d| dns_message(&d.payload))
        .collect()
}

fn dns_message(m: &[u8]) -> Option<DnsMessage> {
    let flags = u16::from_be_bytes([*m.get(2)?, *m.get(3)?]);
    let mut at = 12;
    let mut labels = Vec::new();
    loop {
        let len = *m.get(at)? as usize;
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(m.get(at + 1..at + 1 + len)?).into_owned());
        at += 1 + len;
    }
    Some(DnsMessage {
        response: flags & 0x8000 != 0,
        rcode: (flags & 0xf) as u8,
        name: labels.join("."),
    })
}
