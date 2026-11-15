//! reflector: a test fixture, not a product device. A stepped device that echoes frames back
//! out of the port they came in on.
//!
//! Like a NIC that is not in promiscuous mode, it only accepts frames addressed to its own MAC,
//! to broadcast or to a multicast group. Unicast for anyone else (a switch flooding an unknown
//! destination) is dropped and counted as `filtered`. The echo goes back to the frame's source
//! from the reflector's own MAC. Everything after the addresses is echoed unchanged. Frames too
//! short to carry two addresses and a type are dropped and counted, and so are frames whose
//! source is a group address (echoing those would send to a group).
//!
//! Config (`wasi:config/store`): `mac` (own unicast MAC; default: derived from the seeded RNG).
//!
//! This file is pure logic with no bindings, so it is unit-testable inside wasmtime. The
//! wit-bindgen glue lives in `component.rs`.

#![deny(unsafe_code)]

#[cfg(all(not(test), not(feature = "async-device")))]
mod component;
#[cfg(all(not(test), feature = "async-device"))]
mod component_async;

use wasmnet_wire::MacAddr;
use wasmnet_wire::ethernet::HEADER_LEN;

/// The only port.
pub const PORT: u32 = 0;
/// `async-device` variant only: virtual time each echo waits (on `wasi:clocks`) before it leaves.
pub const ASYNC_DELAY_NS: u64 = 50_000;

/// What happens to one received frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Echo these bytes back.
    Echo(Vec<u8>),
    /// Unicast for another station.
    Filtered,
    /// Malformed: too short, or a group source address.
    Malformed,
}

/// Decides what to do with `frame` for a reflector whose MAC is `own`.
pub fn reflect(frame: &[u8], own: MacAddr) -> Verdict {
    let (Some(dst), Some(src)) = (
        frame.get(0..6).and_then(MacAddr::from_slice),
        frame.get(6..12).and_then(MacAddr::from_slice),
    ) else {
        return Verdict::Malformed;
    };
    if frame.len() < HEADER_LEN || src.is_multicast() {
        return Verdict::Malformed;
    }
    if dst.is_unicast() && dst != own {
        return Verdict::Filtered;
    }
    let mut out = frame.to_vec();
    out[0..6].copy_from_slice(&src.octets());
    out[6..12].copy_from_slice(&own.octets());
    Verdict::Echo(out)
}

/// Reads the optional `mac` config value. `Ok(None)` means "use a seeded MAC".
pub fn mac_from_config(value: Option<String>) -> Result<Option<MacAddr>, String> {
    match value {
        None => Ok(None),
        Some(v) => match v.parse::<MacAddr>() {
            Ok(mac) if mac.is_unicast() => Ok(Some(mac)),
            _ => Err(format!(
                "config mac={v:?}: expected a unicast MAC like 02:00:00:00:00:02"
            )),
        },
    }
}

/// The reflector's state: its MAC and counters.
#[derive(Debug)]
pub struct Reflector {
    mac: MacAddr,
    reflected: u64,
    filtered: u64,
    dropped: u64,
}

impl Reflector {
    pub fn new(mac: MacAddr) -> Self {
        Self {
            mac,
            reflected: 0,
            filtered: 0,
            dropped: 0,
        }
    }

    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    /// Echoes `frame` back out of `port` through `tx(port, frame)`, or drops it.
    pub fn receive(&mut self, port: u32, frame: &[u8], tx: impl FnOnce(u32, Vec<u8>)) {
        match reflect(frame, self.mac) {
            Verdict::Echo(echo) => {
                self.reflected += 1;
                tx(port, echo);
            }
            Verdict::Filtered => self.filtered += 1,
            Verdict::Malformed => self.dropped += 1,
        }
    }

    pub fn reflected(&self) -> u64 {
        self.reflected
    }

    /// Unicast frames for other stations.
    pub fn filtered(&self) -> u64 {
        self.filtered
    }

    /// Malformed frames.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmnet_wire::ethernet::encode_frame;
    use wasmnet_wire::{EtherType, EthernetFrame};

    const OWN: MacAddr = MacAddr::new([0x02, 0, 0, 0, 0, 0xee]);
    const A: MacAddr = MacAddr::new([0x02, 0, 0, 0, 0, 0x0a]);
    const B: MacAddr = MacAddr::new([0x02, 0, 0, 0, 0, 0x0b]);

    fn frame(dst: MacAddr, src: MacAddr, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        encode_frame(&mut f, dst, src, None, EtherType(0x88b5), payload);
        f
    }

    #[test]
    fn unicast_to_us_is_a_plain_swap() {
        let echo = reflect(&frame(OWN, A, b"hello"), OWN);
        assert_eq!(echo, Verdict::Echo(frame(A, OWN, b"hello")));
    }

    #[test]
    fn unicast_for_someone_else_is_filtered() {
        assert_eq!(reflect(&frame(B, A, b"hello"), OWN), Verdict::Filtered);
    }

    #[test]
    fn broadcast_and_multicast_are_answered_from_our_own_mac() {
        for dst in [
            MacAddr::BROADCAST,
            MacAddr::new([0x01, 0, 0x5e, 0, 0, 0xfb]),
        ] {
            let Verdict::Echo(echo) = reflect(&frame(dst, A, b"x"), OWN) else {
                panic!("no echo for {dst}");
            };
            let eth = EthernetFrame::new_checked(&echo[..]).unwrap();
            assert_eq!((eth.dst(), eth.src()), (A, OWN));
            assert_eq!(eth.payload(), b"x");
        }
    }

    #[test]
    fn tagged_frames_keep_their_tag() {
        let mut f = Vec::new();
        let tag = wasmnet_wire::VlanTag::new(3, false, 42);
        encode_frame(&mut f, OWN, A, tag, EtherType::IPV4, &[0x45]);
        let Verdict::Echo(echo) = reflect(&f, OWN) else {
            panic!("no echo");
        };
        assert_eq!(&echo[12..], &f[12..]);
        assert_eq!(EthernetFrame::new_checked(&echo[..]).unwrap().vlan(), tag);
    }

    #[test]
    fn counts_echoes_filtered_and_malformed_frames() {
        let mut r = Reflector::new(OWN);
        let mut out = Vec::new();
        for f in [
            vec![],
            vec![0xff; 13],
            frame(OWN, MacAddr::BROADCAST, b""),
            frame(B, A, b""),
            frame(OWN, A, b""),
        ] {
            r.receive(3, &f, |port, echo| out.push((port, echo)));
        }
        assert_eq!((r.reflected(), r.filtered(), r.dropped()), (1, 1, 3));
        assert_eq!(out, [(3, frame(A, OWN, b""))]);
    }

    #[test]
    fn mac_config_must_be_unicast() {
        assert_eq!(mac_from_config(None), Ok(None));
        assert_eq!(
            mac_from_config(Some("02:00:00:00:00:02".to_owned())),
            Ok(Some(MacAddr::new([2, 0, 0, 0, 0, 2])))
        );
        assert!(mac_from_config(Some("ff:ff:ff:ff:ff:ff".to_owned())).is_err());
        assert!(mac_from_config(Some("x".to_owned())).is_err());
    }

    #[test]
    fn never_panics_on_garbage() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for len in 0..80 {
            let f: Vec<u8> = (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            if let Verdict::Echo(echo) = reflect(&f, OWN) {
                assert_eq!(echo.len(), f.len());
                assert_eq!(&echo[12..], &f[12..]);
            }
        }
    }
}
