//! blaster: a test fixture, not a product device. A stepped device that emits a train of raw
//! Ethernet probe frames.
//!
//! On `poll(now)` it sends every probe that is due, then asks to be polled again at the next
//! send time. It counts the echoes it gets back. By default it sends [`COUNT`] probes, one every
//! [`INTERVAL_NS`] of virtual time from t=0, on port 0 to the broadcast address, from a locally
//! administered MAC derived from its seed. Device config (`wasi:config/store`, see [`Config`])
//! can change the MAC, the destination and the send times.
//!
//! Probe frame (60 bytes, the Ethernet minimum without FCS):
//! `dst=<dst> src=<mac> type=0x88b5` then [`MAGIC`] (8 bytes), sequence number
//! (u32 BE), send time in virtual ns (u64 BE), and zero padding.
//!
//! This file is pure logic with no bindings, so it is unit-testable inside wasmtime. The
//! wit-bindgen glue lives in `component.rs`.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use std::fmt;

use wasmnet_wire::ethernet::encode_frame;
use wasmnet_wire::{EtherType, EthernetFrame, MacAddr, parse_duration};

/// Default number of probes.
pub const COUNT: u32 = 8;
/// Default virtual time between probes: 1 ms.
pub const INTERVAL_NS: u64 = 1_000_000;
/// Upper bound on configured probes, so a typo cannot allocate gigabytes.
pub const MAX_PROBES: u32 = 100_000;
/// IEEE 802 "Local Experimental EtherType 1", reserved for exactly this kind of use.
pub const ETHERTYPE: EtherType = EtherType(0x88b5);
/// Marks a wasmnet probe payload.
pub const MAGIC: [u8; 8] = *b"wasmnet1";
/// The only port.
pub const PORT: u32 = 0;
/// Ethernet minimum frame size without FCS.
const MIN_FRAME: usize = 60;

/// The blaster's configuration.
///
/// Keys (all optional): `mac` (own unicast MAC, default: seeded), `dst` (probe destination MAC,
/// default broadcast), and either `schedule` (comma-separated, non-decreasing send times such
/// as `0ms,1ms,30ms`) or `count` + `interval` + `start` (default 8 probes every 1 ms from 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub mac: Option<MacAddr>,
    pub dst: MacAddr,
    /// Virtual send time of each probe; probe `i` has sequence number `i`.
    pub send_at: Vec<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mac: None,
            dst: MacAddr::BROADCAST,
            send_at: (0..u64::from(COUNT)).map(|i| i * INTERVAL_NS).collect(),
        }
    }
}

/// A config value that could not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub key: &'static str,
    pub value: String,
    pub expected: &'static str,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "config {}={:?}: expected {}",
            self.key, self.value, self.expected
        )
    }
}

impl std::error::Error for ConfigError {}

fn invalid(key: &'static str, value: String, expected: &'static str) -> ConfigError {
    ConfigError {
        key,
        value,
        expected,
    }
}

impl Config {
    /// Reads the config through `get(key)`, falling back to the defaults for absent keys.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        if let Some(v) = get("mac") {
            match v.parse::<MacAddr>() {
                Ok(mac) if mac.is_unicast() => config.mac = Some(mac),
                _ => return Err(invalid("mac", v, "a unicast MAC like 02:00:00:00:00:01")),
            }
        }
        if let Some(v) = get("dst") {
            config.dst = v
                .parse()
                .map_err(|_| invalid("dst", v, "a MAC like 02:00:00:00:00:01"))?;
        }
        let (count, interval, start) = (get("count"), get("interval"), get("start"));
        if let Some(v) = get("schedule") {
            if count.is_some() || interval.is_some() || start.is_some() {
                return Err(invalid("schedule", v, "no count/interval/start next to it"));
            }
            let times: Option<Vec<u64>> = v.split(',').map(|t| parse_duration(t.trim())).collect();
            match times {
                Some(t) if t.is_sorted() && t.len() <= MAX_PROBES as usize => config.send_at = t,
                _ => {
                    return Err(invalid(
                        "schedule",
                        v,
                        "comma-separated, non-decreasing durations (at most 100000)",
                    ));
                }
            }
            return Ok(config);
        }
        let count = match count {
            Some(v) => match v.parse::<u32>() {
                Ok(n) if n <= MAX_PROBES => n,
                _ => return Err(invalid("count", v, "an integer up to 100000")),
            },
            None => COUNT,
        };
        let duration = |key: &'static str, value: Option<String>, default: u64| match value {
            Some(v) => parse_duration(&v).ok_or_else(|| invalid(key, v, "a duration like 1ms")),
            None => Ok(default),
        };
        let interval = duration("interval", interval, INTERVAL_NS)?;
        let start = duration("start", start, 0)?;
        config.send_at = (0..u64::from(count))
            .map(|i| start.saturating_add(i.saturating_mul(interval)))
            .collect();
        Ok(config)
    }
}

/// One probe as carried in a frame payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub seq: u32,
    pub sent_at: u64,
}

impl Probe {
    /// Encodes a probe frame from `src` to `dst`.
    pub fn encode(self, src: MacAddr, dst: MacAddr) -> Vec<u8> {
        let mut payload = Vec::with_capacity(MIN_FRAME);
        payload.extend_from_slice(&MAGIC);
        payload.extend_from_slice(&self.seq.to_be_bytes());
        payload.extend_from_slice(&self.sent_at.to_be_bytes());
        let mut frame = Vec::with_capacity(MIN_FRAME);
        encode_frame(&mut frame, dst, src, None, ETHERTYPE, &payload);
        frame.resize(frame.len().max(MIN_FRAME), 0);
        frame
    }

    /// Decodes a probe from any Ethernet frame. Returns `None` for anything that is not one.
    pub fn decode(frame: &[u8]) -> Option<Self> {
        let eth = EthernetFrame::new_checked(frame).ok()?;
        if eth.ethertype() != ETHERTYPE {
            return None;
        }
        let p = eth.payload();
        if p.get(..8)? != MAGIC {
            return None;
        }
        Some(Self {
            seq: u32::from_be_bytes(p.get(8..12)?.try_into().ok()?),
            sent_at: u64::from_be_bytes(p.get(12..20)?.try_into().ok()?),
        })
    }
}

/// An echo of one of our probes came back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    pub seq: u32,
    /// Round-trip time in virtual ns.
    pub rtt: u64,
}

/// The blaster's state.
#[derive(Debug)]
pub struct Blaster {
    mac: MacAddr,
    dst: MacAddr,
    send_at: Vec<u64>,
    sent: u32,
    echoes: u32,
    ignored: u64,
}

impl Blaster {
    /// A blaster with the default plan (see [`Config::default`]).
    pub fn new(mac: MacAddr) -> Self {
        Self::with_config(mac, Config::default())
    }

    /// A blaster with MAC `mac` and `config`'s destination and send times. Choosing the MAC
    /// (`config.mac` or a seeded one) is the caller's business.
    pub fn with_config(mac: MacAddr, config: Config) -> Self {
        Self {
            mac,
            dst: config.dst,
            send_at: config.send_at,
            sent: 0,
            echoes: 0,
            ignored: 0,
        }
    }

    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    /// Sends every probe due at `now` through `tx(port, frame)` and returns the next deadline.
    pub fn poll(&mut self, now: u64, mut tx: impl FnMut(u32, Vec<u8>)) -> Option<u64> {
        while let Some(&due) = self.send_at.get(self.sent as usize)
            && due <= now
        {
            // Stamp the scheduled time, so a late poll could never skew the train.
            let probe = Probe {
                seq: self.sent,
                sent_at: due,
            };
            tx(PORT, probe.encode(self.mac, self.dst));
            self.sent += 1;
        }
        self.send_at.get(self.sent as usize).copied()
    }

    /// Handles a received frame: an echo of our own probe (addressed to us) is counted and
    /// returned, anything else is ignored and counted.
    pub fn receive(&mut self, now: u64, frame: &[u8]) -> Option<Echo> {
        let to_us = EthernetFrame::new_checked(frame).is_ok_and(|f| f.dst() == self.mac);
        match Probe::decode(frame).filter(|p| to_us && p.seq < self.sent) {
            Some(p) => {
                self.echoes += 1;
                Some(Echo {
                    seq: p.seq,
                    rtt: now.saturating_sub(p.sent_at),
                })
            }
            None => {
                self.ignored += 1;
                None
            }
        }
    }

    /// Probes sent so far.
    pub fn sent(&self) -> u32 {
        self.sent
    }

    /// Echoes received so far.
    pub fn echoes(&self) -> u32 {
        self.echoes
    }

    /// Frames received that were not echoes of our probes.
    pub fn ignored(&self) -> u64 {
        self.ignored
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: MacAddr = MacAddr::new([0x02, 0, 0, 0, 0, 0x0a]);

    fn poll_collect(b: &mut Blaster, now: u64) -> (Vec<Vec<u8>>, Option<u64>) {
        let mut out = Vec::new();
        let next = b.poll(now, |port, f| {
            assert_eq!(port, PORT);
            out.push(f);
        });
        (out, next)
    }

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn emits_count_probes_at_a_fixed_interval() {
        let mut b = Blaster::new(MAC);
        let mut now = 0;
        let mut sent = Vec::new();
        loop {
            let (frames, next) = poll_collect(&mut b, now);
            assert_eq!(frames.len(), 1, "one probe per deadline");
            sent.push((now, Probe::decode(&frames[0]).expect("probe")));
            match next {
                Some(t) => {
                    assert_eq!(t, now + INTERVAL_NS);
                    now = t;
                }
                None => break,
            }
        }
        assert_eq!(sent.len(), COUNT as usize);
        for (i, (at, p)) in sent.iter().enumerate() {
            assert_eq!(p.seq, i as u32);
            assert_eq!(p.sent_at, *at);
            assert_eq!(*at, i as u64 * INTERVAL_NS);
        }
        assert_eq!(poll_collect(&mut b, now + 10 * INTERVAL_NS), (vec![], None));
    }

    #[test]
    fn early_poll_sends_nothing_and_late_poll_catches_up() {
        let mut b = Blaster::new(MAC);
        assert_eq!(poll_collect(&mut b, 0).0.len(), 1);
        let (frames, next) = poll_collect(&mut b, INTERVAL_NS - 1);
        assert!(frames.is_empty());
        assert_eq!(next, Some(INTERVAL_NS));
        let (frames, next) = poll_collect(&mut b, 3 * INTERVAL_NS);
        assert_eq!(frames.len(), 3);
        assert_eq!(next, Some(4 * INTERVAL_NS));
    }

    #[test]
    fn probe_frames_are_minimum_size_from_our_mac() {
        let f = Probe {
            seq: 7,
            sent_at: 0x0102_0304_0506_0708,
        }
        .encode(MAC, MacAddr::BROADCAST);
        assert_eq!(f.len(), 60);
        let eth = EthernetFrame::new_checked(&f[..]).unwrap();
        assert_eq!(eth.dst(), MacAddr::BROADCAST);
        assert_eq!(eth.src(), MAC);
        assert_eq!(eth.ethertype(), ETHERTYPE);
        assert_eq!(&f[14..22], b"wasmnet1");
        assert_eq!(&f[22..26], &[0, 0, 0, 7]);
        assert_eq!(&f[26..34], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(f[34..].iter().all(|&b| b == 0));
    }

    #[test]
    fn counts_echoes_addressed_to_us_and_ignores_the_rest() {
        let mut b = Blaster::new(MAC);
        let (frames, _) = poll_collect(&mut b, 0);
        let mut echo = frames[0].clone();
        // A reflector swaps the addresses: dst = our MAC.
        echo[..6].copy_from_slice(&MAC.octets());
        echo[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x0b]);
        assert_eq!(b.receive(500, &echo), Some(Echo { seq: 0, rtt: 500 }));
        // Our own broadcast probe looped back is not an echo, nor are garbage or unsent seqs.
        assert_eq!(b.receive(600, &frames[0]), None);
        assert_eq!(b.receive(600, &[1, 2, 3]), None);
        let future = Probe { seq: 5, sent_at: 0 }.encode(MacAddr::BROADCAST, MAC);
        assert_eq!(b.receive(600, &future), None);
        assert_eq!((b.echoes(), b.ignored()), (1, 3));
    }

    #[test]
    fn config_defaults_to_the_r1_train() {
        let c = Config::from_lookup(lookup(&[])).unwrap();
        assert_eq!(c, Config::default());
        assert_eq!(c.send_at.len(), COUNT as usize);
        assert_eq!(c.send_at[1], INTERVAL_NS);
    }

    #[test]
    fn config_reads_mac_dst_and_either_schedule_or_count_interval_start() {
        let c = Config::from_lookup(lookup(&[
            ("mac", "02:00:00:00:00:01"),
            ("dst", "02:00:00:00:00:02"),
            ("schedule", "0ms, 1ms,30ms,30ms"),
        ]))
        .unwrap();
        assert_eq!(c.mac, Some(MacAddr::new([2, 0, 0, 0, 0, 1])));
        assert_eq!(c.dst, MacAddr::new([2, 0, 0, 0, 0, 2]));
        assert_eq!(c.send_at, [0, 1_000_000, 30_000_000, 30_000_000]);

        let c = Config::from_lookup(lookup(&[
            ("count", "3"),
            ("interval", "5us"),
            ("start", "1ms"),
        ]))
        .unwrap();
        assert_eq!(c.send_at, [1_000_000, 1_005_000, 1_010_000]);
    }

    #[test]
    fn config_errors_name_the_key() {
        let cases: [(&[(&str, &str)], &str); 8] = [
            (&[("mac", "nope")], "mac"),
            (&[("mac", "01:00:5e:00:00:01")], "mac"),
            (&[("dst", "1:2")], "dst"),
            (&[("count", "-1")], "count"),
            (&[("count", "100001")], "count"),
            (&[("interval", "1.5ms")], "interval"),
            (&[("schedule", "2ms,1ms")], "schedule"),
            (&[("schedule", "1ms"), ("count", "2")], "schedule"),
        ];
        for (pairs, key) in cases {
            assert_eq!(Config::from_lookup(lookup(pairs)).unwrap_err().key, key);
        }
    }

    #[test]
    fn follows_a_configured_schedule_to_a_unicast_destination() {
        let dst = MacAddr::new([2, 0, 0, 0, 0, 2]);
        let config = Config {
            mac: None,
            dst,
            send_at: vec![0, 5, 5, 40],
        };
        let mut b = Blaster::with_config(MAC, config);
        let (frames, next) = poll_collect(&mut b, 0);
        assert_eq!((frames.len(), next), (1, Some(5)));
        assert_eq!(
            EthernetFrame::new_checked(&frames[0][..]).unwrap().dst(),
            dst
        );
        let (frames, next) = poll_collect(&mut b, 5);
        assert_eq!((frames.len(), next), (2, Some(40)));
        let (frames, next) = poll_collect(&mut b, 41);
        assert_eq!((frames.len(), next), (1, None));
        assert_eq!(
            Probe::decode(&frames[0]).unwrap(),
            Probe {
                seq: 3,
                sent_at: 40
            }
        );
    }

    #[test]
    fn decode_never_panics_on_prefixes() {
        let f = Probe { seq: 1, sent_at: 2 }.encode(MAC, MacAddr::BROADCAST);
        for n in 0..f.len() {
            let _ = Probe::decode(&f[..n]);
        }
        assert!(Probe::decode(&f[..33]).is_none());
        assert!(Probe::decode(&f[..34]).is_some());
    }
}
