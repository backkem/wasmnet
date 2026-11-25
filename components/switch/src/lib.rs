//! switch: a stepped device that implements a transparent learning bridge (IEEE 802.1D
//! style, no STP and no VLANs yet).
//!
//! For every received frame it:
//! 1. ages out MAC entries not refreshed within the aging time (virtual time, see [`Config`]);
//! 2. drops it if the ingress port is down or unknown, or the frame is malformed (shorter than an
//!    Ethernet header, or a group source address);
//! 3. learns `source MAC -> ingress port` (a known MAC seen on a new port *moves*);
//! 4. forwards it: a known unicast destination on another port goes out of that port only, one on
//!    the ingress port is filtered (dropped), and broadcast, multicast or unknown unicast is
//!    flooded to every *up* port except the ingress port, in ascending port order. A frame for an
//!    IEEE 802.1D reserved group address (`01:80:c2:00:00:00` to `0f`: STP, LACP, LLDP, ...) is
//!    link-local: filtered, never forwarded.
//!
//! **Blocks and delays between port sets** ([`paths`]): a block keeps two ports apart (a frame
//! from one never leaves by the other, forwarded or flooded), a delay holds the frames between
//! two ports for a while and releases them on the switch's own `poll` deadline. They come from
//! the config (`blocks`, `delays`) or from commands (`wasmnet:control/commands`,
//! [`Switch::command`]: `block`, `unblock`, `partition`, `heal`, `delay`, `paths`) and are
//! journalled as `ports-blocked`, `ports-unblocked`, `ports-healed` and `ports-delayed`. A
//! switch that never had one forwards, counts and journals as before.
//!
//! A port that goes down has its MAC entries flushed. Everything is counted per port
//! ([`PortCounters`]), and table changes are reported as [`Event`]s (`mac-learned`, `mac-moved`,
//! `mac-aged`, `mac-flushed`, `port-up`, `port-down`, `reconfigured`), which the component forwards to the
//! host's `wasmnet:link/log.event`.
//!
//! This file is pure logic with no bindings, so it is unit- and property-tested inside wasmtime.
//! The wit-bindgen glue lives in `component.rs`.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

pub mod paths;

pub use paths::{Change, Paths, PortSet};

use std::collections::BTreeMap;
use std::fmt;

use wasmnet_wire::{EthernetFrame, MacAddr, format_duration, parse_duration};

/// Most ports a switch may have.
pub const MAX_PORTS: u32 = 64;

/// The switch's configuration.
///
/// Keys (all optional): `ports` (1..=64, default 8), `aging` (a duration > 0, default `300s`),
/// `max-entries` (MAC table capacity, 1..=65536, default 1024) and `mtu` (reported per port,
/// default 1500).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub ports: u32,
    /// A MAC entry expires this long after the last frame from that MAC.
    pub aging_ns: u64,
    pub max_entries: usize,
    pub mtu: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ports: 8,
            aging_ns: 300_000_000_000,
            max_entries: 1024,
            mtu: 1500,
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

impl Config {
    /// Reads the config through `get(key)`, falling back to the defaults for absent keys.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        fn read<T>(
            get: &impl Fn(&str) -> Option<String>,
            key: &'static str,
            expected: &'static str,
            parse: impl Fn(&str) -> Option<T>,
            default: T,
        ) -> Result<T, ConfigError> {
            match get(key) {
                None => Ok(default),
                Some(value) => parse(&value).ok_or(ConfigError {
                    key,
                    value,
                    expected,
                }),
            }
        }
        let d = Self::default();
        Ok(Self {
            ports: read(
                &get,
                "ports",
                "an integer from 1 to 64",
                |v| v.parse().ok().filter(|n| (1..=MAX_PORTS).contains(n)),
                d.ports,
            )?,
            aging_ns: read(
                &get,
                "aging",
                "a duration above zero like 300s",
                |v| parse_duration(v).filter(|&ns| ns > 0),
                d.aging_ns,
            )?,
            max_entries: read(
                &get,
                "max-entries",
                "an integer from 1 to 65536",
                |v| v.parse().ok().filter(|n| (1..=65_536).contains(n)),
                d.max_entries,
            )?,
            mtu: read(
                &get,
                "mtu",
                "an integer from 68 to 65535",
                |v| v.parse().ok().filter(|n| (68..=65_535).contains(n)),
                d.mtu,
            )?,
        })
    }
}

/// Per-port counters. `rx_*` count every frame delivered to the port, including dropped ones.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortCounters {
    pub rx_frames: u64,
    pub rx_bytes: u64,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    /// Copies sent out of this port because a frame was flooded.
    pub tx_flooded: u64,
    /// Frames received here whose destination was learned on this same port.
    pub filtered: u64,
    /// Frames received here that were too short or had a group source address.
    pub malformed: u64,
    /// Frames received while the switch considered the port down.
    pub rx_down: u64,
    /// Frames received here not sent to a port this one is blocked from (one per port a flood
    /// left out).
    pub blocked: u64,
    /// Frames received here held for a delay before they left.
    pub delayed: u64,
}

/// A change of the MAC table or of a port, reported to the host as a structured event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A command or the config changed the blocks or delays.
    Paths(Change),
    MacLearned {
        mac: MacAddr,
        port: u32,
    },
    MacMoved {
        mac: MacAddr,
        from: u32,
        to: u32,
    },
    MacAged {
        mac: MacAddr,
        port: u32,
    },
    MacFlushed {
        mac: MacAddr,
        port: u32,
    },
    PortUp {
        port: u32,
    },
    PortDown {
        port: u32,
    },
    /// It took a new configuration in place ([`Switch::reconfigure`]).
    Reconfigured {
        aging_ns: u64,
        max_entries: usize,
    },
}

impl Event {
    /// The stable, kebab-case event kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Event::MacLearned { .. } => "mac-learned",
            Event::MacMoved { .. } => "mac-moved",
            Event::MacAged { .. } => "mac-aged",
            Event::MacFlushed { .. } => "mac-flushed",
            Event::PortUp { .. } => "port-up",
            Event::PortDown { .. } => "port-down",
            Event::Reconfigured { .. } => "reconfigured",
            Event::Paths(Change::Blocked { .. }) => "ports-blocked",
            Event::Paths(Change::Unblocked { .. }) => "ports-unblocked",
            Event::Paths(Change::Healed { .. }) => "ports-healed",
            Event::Paths(Change::Delayed { .. }) => "ports-delayed",
            Event::Paths(Change::Replaced { .. }) => "ports-reconfigured",
        }
    }

    /// The event's fields as key/value strings.
    pub fn fields(&self) -> Vec<(String, String)> {
        let kv = |k: &str, v: String| (k.to_owned(), v);
        match *self {
            Event::MacLearned { mac, port }
            | Event::MacAged { mac, port }
            | Event::MacFlushed { mac, port } => {
                vec![kv("mac", mac.to_string()), kv("port", port.to_string())]
            }
            Event::MacMoved { mac, from, to } => vec![
                kv("mac", mac.to_string()),
                kv("from", from.to_string()),
                kv("to", to.to_string()),
            ],
            Event::PortUp { port } | Event::PortDown { port } => vec![kv("port", port.to_string())],
            Event::Reconfigured {
                aging_ns,
                max_entries,
            } => vec![
                kv("aging", format_duration(aging_ns)),
                kv("max-entries", max_entries.to_string()),
            ],
            Event::Paths(Change::Blocked { from, to, pairs })
            | Event::Paths(Change::Unblocked { from, to, pairs }) => vec![
                kv("from", from.to_string()),
                kv("to", to.to_string()),
                kv("pairs", pairs.to_string()),
            ],
            Event::Paths(Change::Healed { pairs }) => vec![kv("pairs", pairs.to_string())],
            Event::Paths(Change::Replaced { blocks, delays }) => vec![
                kv("blocks", blocks.to_string()),
                kv("delays", delays.to_string()),
            ],
            Event::Paths(Change::Delayed { from, to, delay_ns }) => vec![
                kv("from", from.to_string()),
                kv("to", to.to_string()),
                kv("delay", format_duration(delay_ns)),
            ],
        }
    }
}

/// Why a frame was dropped instead of forwarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// The ingress port does not exist.
    UnknownPort,
    /// The ingress port is down.
    PortDown,
    /// Shorter than an Ethernet header.
    Malformed,
    /// The source address is broadcast or multicast.
    GroupSource,
    /// The destination is learned on a port the ingress port is blocked from.
    Blocked,
}

/// What the switch did with one frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Forwarding {
    /// Sent out of exactly this (learned) port.
    Unicast(u32),
    /// Sent out of these ports (ascending; possibly none if no other port is up).
    Flooded(Vec<u32>),
    /// The destination was learned on the ingress port: nothing to do.
    Filtered,
    Dropped(DropReason),
}

/// Where the switch's output goes: frames to ports and events to the log.
pub trait Sink {
    fn transmit(&mut self, port: u32, frame: &[u8]);
    fn event(&mut self, event: Event);
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    port: u32,
    last_seen: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct Port {
    up: bool,
    counters: PortCounters,
}

/// The switch's state: ports, MAC table and counters.
#[derive(Debug)]
pub struct Switch {
    config: Config,
    ports: Vec<Port>,
    table: BTreeMap<MacAddr, Entry>,
    /// Source MACs that could not be learned because the table was full.
    table_full: u64,
    /// Blocks and delays between ports.
    paths: Paths,
}

impl Switch {
    /// A switch with every port down and an empty table.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ports: vec![Port::default(); config.ports as usize],
            table: BTreeMap::new(),
            table_full: 0,
            paths: Paths::default(),
        }
    }

    /// Sets the blocks and delays (the config's `blocks` and `delays`, [`Paths::from_config`]).
    pub fn with_paths(mut self, paths: Paths) -> Self {
        self.paths = paths;
        self
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Takes `new` in place (`wasmnet:reconfigure`): a new aging time applies to every entry
    /// from now on (an entry older than it ages at the next poll), a new table size to what is
    /// learned from now on (a smaller one keeps the entries it has until they age). The table,
    /// the ports and the counters stay. `Err`: `ports` or `mtu` changed, which only a restart
    /// can do (the ports are declared once).
    pub fn reconfigure(&mut self, new: Config, out: &mut impl Sink) -> Result<(), String> {
        if (new.ports, new.mtu) != (self.config.ports, self.config.mtu) {
            return Err("`ports` and `mtu` change only with a restart".to_owned());
        }
        if new != self.config {
            self.config = new;
            out.event(Event::Reconfigured {
                aging_ns: new.aging_ns,
                max_entries: new.max_entries,
            });
        }
        Ok(())
    }

    /// Takes the `blocks` and `delays` of a configuration applied in place ([`Paths::reconfigure`]):
    /// unchanged values keep the blocks and delays as they are (commands' included), changed ones
    /// replace them all, journalled as `ports-reconfigured {blocks, delays}`. Held frames keep
    /// their release time.
    pub fn reconfigure_paths(&mut self, paths: Paths, out: &mut impl Sink) {
        if let Some(c) = self.paths.reconfigure(paths) {
            out.event(Event::Paths(c));
        }
    }

    /// A whole configuration in place (`wasmnet:reconfigure`): [`Switch::reconfigure`] and then
    /// [`Switch::reconfigure_paths`]. `Err` (other ports or another MTU) changes nothing, the
    /// blocks and delays included.
    pub fn reconfigure_all(
        &mut self,
        new: Config,
        paths: Paths,
        out: &mut impl Sink,
    ) -> Result<(), String> {
        self.reconfigure(new, out)?;
        self.reconfigure_paths(paths, out);
        Ok(())
    }

    /// Handles one frame received on `port` at `now`.
    pub fn receive(
        &mut self,
        now: u64,
        port: u32,
        frame: &[u8],
        sink: &mut impl Sink,
    ) -> Forwarding {
        self.age(now, sink);
        let Some(ingress) = self.ports.get_mut(port as usize) else {
            return Forwarding::Dropped(DropReason::UnknownPort);
        };
        let c = &mut ingress.counters;
        c.rx_frames += 1;
        c.rx_bytes += frame.len() as u64;
        if !ingress.up {
            c.rx_down += 1;
            return Forwarding::Dropped(DropReason::PortDown);
        }
        let (src, dst) = match EthernetFrame::new_checked(frame) {
            Ok(eth) => (eth.src(), eth.dst()),
            Err(_) => {
                c.malformed += 1;
                return Forwarding::Dropped(DropReason::Malformed);
            }
        };
        if src.is_multicast() {
            c.malformed += 1;
            return Forwarding::Dropped(DropReason::GroupSource);
        }
        self.learn(now, src, port, sink);
        // IEEE 802.1D-2004 §7.12.6: the reserved group addresses 01:80:c2:00:00:00 to :0f (STP,
        // pause, LACP, 802.1X, LLDP) are link-local; a bridge never forwards them.
        let d = dst.octets();
        if d[..5] == [0x01, 0x80, 0xc2, 0, 0] && d[5] <= 0x0f {
            self.ports[port as usize].counters.filtered += 1;
            return Forwarding::Filtered;
        }

        let known = dst
            .is_unicast()
            .then(|| self.table.get(&dst).map(|e| e.port))
            .flatten();
        match known {
            Some(egress) if egress == port => {
                self.ports[port as usize].counters.filtered += 1;
                Forwarding::Filtered
            }
            Some(egress) if self.paths.blocked(port, egress) => {
                self.ports[port as usize].counters.blocked += 1;
                Forwarding::Dropped(DropReason::Blocked)
            }
            Some(egress) => {
                self.forward(now, port, egress, frame, false, sink);
                Forwarding::Unicast(egress)
            }
            None => {
                let up: Vec<u32> = (0..self.config.ports)
                    .filter(|&p| p != port && self.ports[p as usize].up)
                    .collect();
                let egress: Vec<u32> = up
                    .iter()
                    .copied()
                    .filter(|&p| !self.paths.blocked(port, p))
                    .collect();
                self.ports[port as usize].counters.blocked += (up.len() - egress.len()) as u64;
                for &p in &egress {
                    self.forward(now, port, p, frame, true, sink);
                }
                Forwarding::Flooded(egress)
            }
        }
    }

    /// Records a carrier change. A port going down flushes the MACs learned on it.
    pub fn link_state(&mut self, now: u64, port: u32, up: bool, sink: &mut impl Sink) {
        self.age(now, sink);
        let Some(p) = self.ports.get_mut(port as usize) else {
            return;
        };
        if p.up == up {
            return;
        }
        p.up = up;
        if up {
            sink.event(Event::PortUp { port });
            return;
        }
        let flushed: Vec<MacAddr> = self
            .table
            .iter()
            .filter(|(_, e)| e.port == port)
            .map(|(&mac, _)| mac)
            .collect();
        for mac in flushed {
            self.table.remove(&mac);
            sink.event(Event::MacFlushed { mac, port });
        }
        sink.event(Event::PortDown { port });
    }

    /// Ages the table to `now`, sends the held frames that are due, and returns when the next
    /// entry expires or the next held frame is due.
    pub fn poll(&mut self, now: u64, sink: &mut impl Sink) -> Option<u64> {
        self.age(now, sink);
        for h in self.paths.due(now) {
            // A port that went down (or a block set meanwhile) loses the frame.
            if self.is_up(h.egress) && !self.paths.blocked(h.ingress, h.egress) {
                self.send(h.egress, &h.frame, h.flooded, sink);
            } else {
                self.paths.held_dropped += 1;
            }
        }
        let aging = self
            .table
            .values()
            .map(|e| e.last_seen.saturating_add(self.config.aging_ns))
            .min();
        match (aging, self.paths.next_release()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Runs one command (`wasmnet:control/commands`): `block <set> <set>`, `unblock <set>
    /// <set>`, `partition <set> <set> [<set>...]`, `heal`, `delay <set> <set> <duration>` and
    /// `paths`. `Ok` says what it did (`unchanged` when nothing changed); `Err` changed nothing.
    pub fn command(
        &mut self,
        _now: u64,
        command: &str,
        argument: &str,
        sink: &mut impl Sink,
    ) -> Result<String, String> {
        let ports = self.config.ports;
        let arg = argument.trim();
        let (changes, done) = match command {
            "block" => (
                self.paths.block(arg, ports, true)?.into_iter().collect(),
                "blocked",
            ),
            "unblock" => (
                self.paths.block(arg, ports, false)?.into_iter().collect(),
                "unblocked",
            ),
            "partition" => (self.paths.partition(arg, ports)?, "partitioned"),
            "heal" if arg.is_empty() => (self.paths.heal().into_iter().collect(), "healed"),
            "delay" => (
                self.paths.delay(arg, ports)?.into_iter().collect(),
                "delayed",
            ),
            "paths" if arg.is_empty() => return Ok(self.paths.listing()),
            "heal" | "paths" => return Err(format!("`{command}` takes no argument")),
            other => {
                return Err(format!(
                    "unknown command `{other}` (block, unblock, partition, heal, delay, paths)"
                ));
            }
        };
        let changes: Vec<Change> = changes;
        if changes.is_empty() {
            return Ok("unchanged".to_owned());
        }
        for c in changes {
            sink.event(Event::Paths(c));
        }
        Ok(done.to_owned())
    }

    /// Every counter, in a stable order (the `counters` export): per port `p<N>-*`, the table's,
    /// and, once a block or a delay existed, `p<N>-blocked`, `p<N>-delayed`, `blocked-pairs`,
    /// `delayed-pairs`, `held` and `held-dropped`.
    pub fn counter_list(&self) -> Vec<(String, u64)> {
        let mut v = vec![
            ("table-entries".to_owned(), self.table.len() as u64),
            ("table-full".to_owned(), self.table_full),
        ];
        let used = self.paths.used;
        for (n, p) in self.ports.iter().enumerate() {
            let c = p.counters;
            let mut list = vec![
                ("rx-frames", c.rx_frames),
                ("rx-bytes", c.rx_bytes),
                ("tx-frames", c.tx_frames),
                ("tx-bytes", c.tx_bytes),
                ("tx-flooded", c.tx_flooded),
                ("filtered", c.filtered),
                ("malformed", c.malformed),
                ("rx-down", c.rx_down),
            ];
            if used {
                list.push(("blocked", c.blocked));
                list.push(("delayed", c.delayed));
            }
            v.extend(list.into_iter().map(|(k, val)| (format!("p{n}-{k}"), val)));
        }
        if used {
            for (k, val) in [
                ("blocked-pairs", self.paths.blocked_pairs() as u64),
                ("delayed-pairs", self.paths.delayed_pairs() as u64),
                ("held", self.paths.held() as u64),
                ("held-dropped", self.paths.held_dropped),
            ] {
                v.push((k.to_owned(), val));
            }
        }
        v
    }

    /// The port `mac` is learned on, if any.
    pub fn lookup(&self, mac: MacAddr) -> Option<u32> {
        self.table.get(&mac).map(|e| e.port)
    }

    /// The MAC table, ordered by MAC: `(mac, port, last seen)`.
    pub fn table(&self) -> impl Iterator<Item = (MacAddr, u32, u64)> + '_ {
        self.table.iter().map(|(&m, e)| (m, e.port, e.last_seen))
    }

    pub fn counters(&self, port: u32) -> Option<PortCounters> {
        self.ports.get(port as usize).map(|p| p.counters)
    }

    pub fn is_up(&self, port: u32) -> bool {
        self.ports.get(port as usize).is_some_and(|p| p.up)
    }

    /// Source MACs not learned because the table was full.
    pub fn table_full(&self) -> u64 {
        self.table_full
    }

    /// A one-line description for logs: `8 ports, aging 300s, 1024 entries`.
    pub fn describe(&self) -> String {
        format!(
            "{} ports, aging {}, {} entries",
            self.config.ports,
            format_duration(self.config.aging_ns),
            self.config.max_entries
        )
    }

    /// Sends a frame from `ingress` out of `egress` now, or holds it for their delay.
    fn forward(
        &mut self,
        now: u64,
        ingress: u32,
        egress: u32,
        frame: &[u8],
        flooded: bool,
        sink: &mut impl Sink,
    ) {
        let delay = self.paths.delay_of(ingress, egress);
        if delay == 0 {
            self.send(egress, frame, flooded, sink);
            return;
        }
        self.ports[ingress as usize].counters.delayed += 1;
        self.paths.hold(
            now.saturating_add(delay),
            paths::Held {
                ingress,
                egress,
                flooded,
                frame: frame.to_vec(),
            },
        );
    }

    fn send(&mut self, port: u32, frame: &[u8], flooded: bool, sink: &mut impl Sink) {
        let c = &mut self.ports[port as usize].counters;
        c.tx_frames += 1;
        c.tx_bytes += frame.len() as u64;
        if flooded {
            c.tx_flooded += 1;
        }
        sink.transmit(port, frame);
    }

    fn learn(&mut self, now: u64, mac: MacAddr, port: u32, sink: &mut impl Sink) {
        if let Some(entry) = self.table.get_mut(&mac) {
            if entry.port != port {
                sink.event(Event::MacMoved {
                    mac,
                    from: entry.port,
                    to: port,
                });
                entry.port = port;
            }
            entry.last_seen = now;
        } else if self.table.len() < self.config.max_entries {
            self.table.insert(
                mac,
                Entry {
                    port,
                    last_seen: now,
                },
            );
            sink.event(Event::MacLearned { mac, port });
        } else {
            self.table_full += 1;
        }
    }

    /// Removes every entry whose age reached the aging time (`now >= last_seen + aging`).
    fn age(&mut self, now: u64, sink: &mut impl Sink) {
        let aging = self.config.aging_ns;
        let expired: Vec<(MacAddr, u32)> = self
            .table
            .iter()
            .filter(|(_, e)| now >= e.last_seen.saturating_add(aging))
            .map(|(&mac, e)| (mac, e.port))
            .collect();
        for (mac, port) in expired {
            self.table.remove(&mac);
            sink.event(Event::MacAged { mac, port });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmnet_wire::EtherType;
    use wasmnet_wire::ethernet::encode_frame;

    /// Collects everything the switch emits.
    #[derive(Default)]
    struct Out {
        tx: Vec<(u32, Vec<u8>)>,
        events: Vec<Event>,
    }

    impl Sink for Out {
        fn transmit(&mut self, port: u32, frame: &[u8]) {
            self.tx.push((port, frame.to_vec()));
        }
        fn event(&mut self, event: Event) {
            self.events.push(event);
        }
    }

    impl Out {
        fn ports(&self) -> Vec<u32> {
            self.tx.iter().map(|(p, _)| *p).collect()
        }
    }

    const AGING: u64 = 1_000;

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([0x02, 0, 0, 0, 0, n])
    }

    fn frame(dst: MacAddr, src: MacAddr) -> Vec<u8> {
        let mut f = Vec::new();
        encode_frame(&mut f, dst, src, None, EtherType(0x88b5), b"payload");
        f
    }

    /// A 4-port switch with every port up.
    fn switch() -> Switch {
        let mut sw = Switch::new(Config {
            ports: 4,
            aging_ns: AGING,
            ..Config::default()
        });
        for p in 0..4 {
            sw.link_state(0, p, true, &mut Out::default());
        }
        sw
    }

    fn rx(sw: &mut Switch, now: u64, port: u32, f: &[u8]) -> (Forwarding, Out) {
        let mut out = Out::default();
        let fwd = sw.receive(now, port, f, &mut out);
        (fwd, out)
    }

    #[test]
    fn a_new_aging_time_applies_in_place_and_ports_need_a_restart() {
        let mut sw = switch();
        rx(&mut sw, 0, 0, &frame(mac(2), mac(1)));
        let mut out = Out::default();
        let longer = Config {
            aging_ns: 10 * AGING,
            ..*sw.config()
        };
        assert_eq!(sw.reconfigure(longer, &mut out), Ok(()));
        assert_eq!(
            out.events,
            [Event::Reconfigured {
                aging_ns: 10 * AGING,
                max_entries: 1024
            }]
        );
        // The table stayed: mac(1) is still known, and now lives ten times as long.
        let (fwd, _) = rx(&mut sw, 5 * AGING, 3, &frame(mac(1), mac(3)));
        assert_eq!(fwd, Forwarding::Unicast(0));
        // The same config again changes nothing; other ports or another MTU need a restart.
        let mut out = Out::default();
        assert_eq!(sw.reconfigure(longer, &mut out), Ok(()));
        assert!(out.events.is_empty());
        for other in [
            Config { ports: 8, ..longer },
            Config {
                mtu: 9000,
                ..longer
            },
        ] {
            assert!(sw.reconfigure(other, &mut Out::default()).is_err());
        }
        assert_eq!(sw.config(), &longer);
    }

    #[test]
    fn floods_unknown_then_forwards_learned_unicast() {
        let mut sw = switch();
        let (fwd, out) = rx(&mut sw, 0, 0, &frame(mac(2), mac(1)));
        assert_eq!(fwd, Forwarding::Flooded(vec![1, 2, 3]));
        assert_eq!(out.ports(), [1, 2, 3]);
        assert_eq!(
            out.events,
            [Event::MacLearned {
                mac: mac(1),
                port: 0
            }]
        );
        // The reply teaches the switch where mac(2) lives and goes straight to port 0.
        let (fwd, out) = rx(&mut sw, 10, 2, &frame(mac(1), mac(2)));
        assert_eq!(fwd, Forwarding::Unicast(0));
        assert_eq!(out.tx, [(0, frame(mac(1), mac(2)))]);
        // Now both directions are unicast, and nothing is flooded.
        let (fwd, _) = rx(&mut sw, 20, 0, &frame(mac(2), mac(1)));
        assert_eq!(fwd, Forwarding::Unicast(2));
        let c = sw.counters(0).unwrap();
        assert_eq!((c.rx_frames, c.tx_frames, c.tx_flooded), (2, 1, 0));
        assert_eq!(sw.counters(3).unwrap().tx_flooded, 1);
    }

    #[test]
    fn broadcast_and_multicast_always_flood_but_never_back_out_of_the_ingress() {
        let mut sw = switch();
        rx(&mut sw, 0, 1, &frame(mac(9), mac(1)));
        for dst in [
            MacAddr::BROADCAST,
            MacAddr::new([0x01, 0x00, 0x5e, 0, 0, 0xfb]),
        ] {
            let (fwd, _) = rx(&mut sw, 5, 1, &frame(dst, mac(1)));
            assert_eq!(fwd, Forwarding::Flooded(vec![0, 2, 3]));
        }
    }

    #[test]
    fn reserved_group_addresses_are_never_forwarded() {
        // IEEE 802.1D-2004 §7.12.6.
        let mut sw = switch();
        for last in [0x00, 0x02, 0x0e, 0x0f] {
            let dst = MacAddr::new([0x01, 0x80, 0xc2, 0, 0, last]);
            let (fwd, out) = rx(&mut sw, 0, 1, &frame(dst, mac(1)));
            assert_eq!((fwd, out.tx.len()), (Forwarding::Filtered, 0), "{dst}");
        }
        // The source is still learned; the next address up is an ordinary group.
        let (fwd, _) = rx(&mut sw, 0, 2, &frame(mac(1), mac(2)));
        assert_eq!(fwd, Forwarding::Unicast(1));
        let (fwd, _) = rx(
            &mut sw,
            0,
            1,
            &frame(MacAddr::new([0x01, 0x80, 0xc2, 0, 0, 0x10]), mac(1)),
        );
        assert_eq!(fwd, Forwarding::Flooded(vec![0, 2, 3]));
    }

    #[test]
    fn a_destination_on_the_ingress_port_is_filtered() {
        let mut sw = switch();
        rx(&mut sw, 0, 3, &frame(MacAddr::BROADCAST, mac(1)));
        rx(&mut sw, 0, 3, &frame(MacAddr::BROADCAST, mac(2)));
        let (fwd, out) = rx(&mut sw, 1, 3, &frame(mac(1), mac(2)));
        assert_eq!((fwd, out.tx.len()), (Forwarding::Filtered, 0));
        assert_eq!(sw.counters(3).unwrap().filtered, 1);
    }

    #[test]
    fn entries_age_out_on_virtual_time_and_unicast_floods_again() {
        let mut sw = switch();
        rx(&mut sw, 100, 1, &frame(MacAddr::BROADCAST, mac(1)));
        assert_eq!(sw.poll(100, &mut Out::default()), Some(100 + AGING));
        // Still fresh one ns before the deadline.
        let (fwd, _) = rx(&mut sw, 100 + AGING - 1, 0, &frame(mac(1), mac(7)));
        assert_eq!(fwd, Forwarding::Unicast(1));
        // mac(7) was learned at 1099 and mac(1) refreshed nothing; at 1100 mac(1) expires.
        let mut out = Out::default();
        assert_eq!(sw.poll(100 + AGING, &mut out), Some(100 + 2 * AGING - 1));
        assert_eq!(
            out.events,
            [Event::MacAged {
                mac: mac(1),
                port: 1
            }]
        );
        let (fwd, _) = rx(&mut sw, 100 + AGING, 0, &frame(mac(1), mac(7)));
        assert_eq!(fwd, Forwarding::Flooded(vec![1, 2, 3]));
    }

    #[test]
    fn receive_ages_first_even_without_a_poll() {
        let mut sw = switch();
        rx(&mut sw, 0, 1, &frame(MacAddr::BROADCAST, mac(1)));
        let (fwd, out) = rx(&mut sw, AGING, 0, &frame(mac(1), mac(2)));
        assert_eq!(fwd, Forwarding::Flooded(vec![1, 2, 3]));
        assert_eq!(
            out.events[0],
            Event::MacAged {
                mac: mac(1),
                port: 1
            }
        );
    }

    #[test]
    fn link_down_excludes_the_port_and_flushes_its_entries() {
        let mut sw = switch();
        rx(&mut sw, 0, 2, &frame(MacAddr::BROADCAST, mac(2)));
        rx(&mut sw, 0, 2, &frame(MacAddr::BROADCAST, mac(3)));
        let mut out = Out::default();
        sw.link_state(5, 2, false, &mut out);
        assert_eq!(
            out.events,
            [
                Event::MacFlushed {
                    mac: mac(2),
                    port: 2
                },
                Event::MacFlushed {
                    mac: mac(3),
                    port: 2
                },
                Event::PortDown { port: 2 },
            ]
        );
        assert_eq!(sw.lookup(mac(2)), None);
        let (fwd, _) = rx(&mut sw, 6, 0, &frame(mac(2), mac(1)));
        assert_eq!(fwd, Forwarding::Flooded(vec![1, 3]));
        // A frame on the down port is dropped, and nothing is learned from it.
        let (fwd, _) = rx(&mut sw, 6, 2, &frame(mac(1), mac(2)));
        assert_eq!(fwd, Forwarding::Dropped(DropReason::PortDown));
        assert_eq!(sw.counters(2).unwrap().rx_down, 1);
        let mut out = Out::default();
        sw.link_state(7, 2, true, &mut out);
        sw.link_state(7, 2, true, &mut out);
        assert_eq!(out.events, [Event::PortUp { port: 2 }]);
    }

    #[test]
    fn a_station_that_moves_is_relearned() {
        let mut sw = switch();
        rx(&mut sw, 0, 1, &frame(MacAddr::BROADCAST, mac(1)));
        let (_, out) = rx(&mut sw, 1, 3, &frame(MacAddr::BROADCAST, mac(1)));
        assert_eq!(
            out.events,
            [Event::MacMoved {
                mac: mac(1),
                from: 1,
                to: 3
            }]
        );
        assert_eq!(sw.lookup(mac(1)), Some(3));
    }

    #[test]
    fn malformed_frames_are_dropped_and_counted() {
        let mut sw = switch();
        let (fwd, _) = rx(&mut sw, 0, 0, &[0xff; 13]);
        assert_eq!(fwd, Forwarding::Dropped(DropReason::Malformed));
        let (fwd, _) = rx(&mut sw, 0, 0, &frame(mac(1), MacAddr::BROADCAST));
        assert_eq!(fwd, Forwarding::Dropped(DropReason::GroupSource));
        let (fwd, _) = rx(&mut sw, 0, 9, &frame(mac(1), mac(2)));
        assert_eq!(fwd, Forwarding::Dropped(DropReason::UnknownPort));
        assert_eq!(sw.counters(0).unwrap().malformed, 2);
        assert_eq!(sw.table().count(), 0);
    }

    #[test]
    fn a_full_table_stops_learning_but_keeps_forwarding() {
        let mut sw = Switch::new(Config {
            ports: 2,
            max_entries: 1,
            ..Config::default()
        });
        for p in 0..2 {
            sw.link_state(0, p, true, &mut Out::default());
        }
        rx(&mut sw, 0, 0, &frame(MacAddr::BROADCAST, mac(1)));
        let (fwd, _) = rx(&mut sw, 0, 1, &frame(mac(1), mac(2)));
        assert_eq!(fwd, Forwarding::Unicast(0));
        assert_eq!((sw.table().count(), sw.table_full()), (1, 1));
    }

    #[test]
    fn config_reads_keys_and_rejects_bad_values() {
        let get = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        assert_eq!(Config::from_lookup(get(&[])).unwrap(), Config::default());
        let c = Config::from_lookup(get(&[
            ("ports", "4"),
            ("aging", "20ms"),
            ("max-entries", "16"),
            ("mtu", "9000"),
        ]))
        .unwrap();
        assert_eq!(
            (c.ports, c.aging_ns, c.max_entries, c.mtu),
            (4, 20_000_000, 16, 9000)
        );
        for (key, value) in [
            ("ports", "0"),
            ("ports", "65"),
            ("aging", "0s"),
            ("aging", "soon"),
            ("max-entries", "0"),
            ("mtu", "10"),
        ] {
            let pairs: &'static [(&'static str, &'static str)] =
                Box::leak(Box::new([(key, value)]));
            assert_eq!(Config::from_lookup(get(pairs)).unwrap_err().key, key);
        }
        assert_eq!(
            Switch::new(Config::default()).describe(),
            "8 ports, aging 300s, 1024 entries"
        );
    }

    #[test]
    fn blocked_ports_exchange_nothing_and_heal() {
        let mut sw = switch();
        let mut out = Out::default();
        // Ports 0 and 1 against 2: a partition into two groups; 3 reaches everyone.
        assert_eq!(
            sw.command(0, "partition", "0+1 2", &mut out).as_deref(),
            Ok("partitioned")
        );
        assert_eq!(out.events[0].kind(), "ports-blocked");
        assert_eq!(
            out.events[0].fields(),
            [
                ("from".to_owned(), "0+1".to_owned()),
                ("to".to_owned(), "2".to_owned()),
                ("pairs".to_owned(), "2".to_owned()),
            ]
        );
        assert_eq!(
            sw.command(0, "block", "2 1", &mut out).as_deref(),
            Ok("unchanged")
        );
        assert_eq!(
            sw.command(0, "paths", "", &mut out).as_deref(),
            Ok("block 0 2\nblock 1 2")
        );
        // A broadcast from 0 floods to 1 and 3 only; one from 2 reaches 3 only.
        let (fwd, o) = rx(&mut sw, 1, 0, &frame(MacAddr::BROADCAST, mac(1)));
        assert_eq!(
            (fwd, o.ports()),
            (Forwarding::Flooded(vec![1, 3]), vec![1, 3])
        );
        let (_, o) = rx(&mut sw, 2, 2, &frame(MacAddr::BROADCAST, mac(3)));
        assert_eq!(o.ports(), [3]);
        // A learned station across the block is unreachable, and the drop is counted.
        let (fwd, o) = rx(&mut sw, 3, 2, &frame(mac(1), mac(3)));
        assert_eq!(fwd, Forwarding::Dropped(DropReason::Blocked));
        assert!(o.ports().is_empty());
        assert_eq!(
            sw.counters(2).unwrap().blocked,
            3,
            "two flood copies and one unicast"
        );
        let counters = sw.counter_list();
        let get = |k: &str| counters.iter().find(|(n, _)| n == k).map(|(_, v)| *v);
        assert_eq!(get("blocked-pairs"), Some(2));
        assert_eq!(get("p2-blocked"), Some(3));
        // Healed: everything as before.
        let mut out = Out::default();
        assert_eq!(sw.command(4, "heal", "", &mut out).as_deref(), Ok("healed"));
        assert_eq!(out.events[0].kind(), "ports-healed");
        let (fwd, _) = rx(&mut sw, 5, 2, &frame(mac(1), mac(3)));
        assert_eq!(fwd, Forwarding::Unicast(0));
        assert_eq!(
            sw.command(5, "heal", "", &mut out).as_deref(),
            Ok("unchanged")
        );
        for (c, a) in [
            ("block", "0"),
            ("block", "0 9"),
            ("heal", "now"),
            ("fly", ""),
            ("partition", "0"),
        ] {
            assert!(sw.command(5, c, a, &mut out).is_err(), "{c} {a}");
        }
    }

    #[test]
    fn a_switch_without_blocks_lists_no_block_counters() {
        let sw = switch();
        assert!(
            sw.counter_list().iter().all(|(k, _)| !k.contains("blocked")
                && !k.contains("held")
                && !k.contains("delayed"))
        );
    }

    #[test]
    fn delayed_frames_leave_on_the_poll_deadline() {
        let mut sw = switch();
        let mut out = Out::default();
        assert_eq!(
            sw.command(0, "delay", "0 1 20ms", &mut out).as_deref(),
            Ok("delayed")
        );
        assert_eq!(out.events[0].kind(), "ports-delayed");
        // A broadcast from 0: to 1 held, to the others at once.
        let f = frame(MacAddr::BROADCAST, mac(1));
        let (_, o) = rx(&mut sw, 1_000, 0, &f);
        assert_eq!(o.ports(), [2, 3]);
        // The next deadline: the learned MAC's expiry first, then the held frame's release.
        assert_eq!(sw.poll(1_000, &mut Out::default()), Some(2_000));
        assert_eq!(sw.poll(2_000, &mut Out::default()), Some(20_001_000));
        let mut o = Out::default();
        sw.poll(20_000_999, &mut o);
        assert!(o.tx.is_empty());
        sw.poll(20_001_000, &mut o);
        assert_eq!(o.ports(), [1]);
        assert_eq!(o.tx[0].1, f);
        assert_eq!(sw.counters(0).unwrap().delayed, 1);
        // A frame held for a port that goes down meanwhile is lost, and counted.
        let (_, _) = rx(&mut sw, 30_000_000, 0, &f);
        sw.link_state(31_000_000, 1, false, &mut Out::default());
        let mut o = Out::default();
        sw.poll(50_000_000, &mut o);
        assert!(o.tx.is_empty());
        let counters = sw.counter_list();
        assert!(counters.contains(&("held-dropped".to_owned(), 1)));
        assert_eq!(
            sw.command(0, "delay", "0 1 0", &mut Out::default())
                .as_deref(),
            Ok("delayed")
        );
        assert_eq!(
            sw.command(0, "paths", "", &mut Out::default()).as_deref(),
            Ok("")
        );
    }

    #[test]
    fn a_configuration_in_place_keeps_or_replaces_blocks_and_delays() {
        let cfg = |b: Option<&str>, d: Option<&str>| Paths::from_config(b, d, 4).unwrap();
        let mut sw = switch().with_paths(cfg(Some("0 1"), Some("0 2 20ms")));
        let same = *sw.config();
        // A command adds a block; a frame from 0 to 2 is held for 20 ms.
        sw.command(0, "block", "2 3", &mut Out::default()).unwrap();
        let f = frame(MacAddr::BROADCAST, mac(1));
        let (_, o) = rx(&mut sw, 1_000, 0, &f);
        assert_eq!(o.ports(), [3], "1 blocked, 2 held");
        // The same blocks and delays in a new configuration (a longer aging time): the command's
        // block stays.
        let mut out = Out::default();
        let longer = Config {
            aging_ns: 10 * AGING,
            ..same
        };
        sw.reconfigure_all(longer, cfg(Some("0 1"), Some("0 2 20ms")), &mut out)
            .unwrap();
        assert_eq!(out.events.len(), 1, "only `reconfigured`");
        assert_eq!(
            sw.command(0, "paths", "", &mut Out::default()).as_deref(),
            Ok("block 0 1\nblock 2 3\ndelay 0 2 20ms")
        );
        // Other ports with other blocks: a restart, and nothing changed.
        let more_ports = Config { ports: 8, ..longer };
        assert!(
            sw.reconfigure_all(more_ports, cfg(Some("0 3"), None), &mut out)
                .is_err()
        );
        assert_eq!(
            sw.command(0, "paths", "", &mut Out::default()).as_deref(),
            Ok("block 0 1\nblock 2 3\ndelay 0 2 20ms")
        );
        // New blocks and no delay: every block and delay is replaced, the command's too.
        let mut out = Out::default();
        sw.reconfigure_all(longer, cfg(Some("0 2"), None), &mut out)
            .unwrap();
        assert_eq!(out.events[0].kind(), "ports-reconfigured");
        assert_eq!(
            out.events[0].fields(),
            [
                ("blocks".to_owned(), "1".to_owned()),
                ("delays".to_owned(), "0".to_owned())
            ]
        );
        assert_eq!(
            sw.command(0, "paths", "", &mut Out::default()).as_deref(),
            Ok("block 0 2")
        );
        // The frame held from 0 for 2 is now across a block: at its release it is dropped and
        // counted, not sent.
        let mut o = Out::default();
        sw.poll(20_001_000, &mut o);
        assert!(o.tx.is_empty());
        assert!(sw.counter_list().contains(&("held-dropped".to_owned(), 1)));
        // And 0 reaches 1 again.
        let (_, o) = rx(&mut sw, 20_002_000, 0, &f);
        assert_eq!(o.ports(), [1, 3]);
    }

    #[test]
    fn blocks_and_delays_from_the_config() {
        let p = Paths::from_config(Some("0+1 2, 3 0"), Some("1 3 5ms"), 4).unwrap();
        let sw = Switch::new(Config {
            ports: 4,
            ..Config::default()
        })
        .with_paths(p);
        let mut sw = sw;
        assert_eq!(
            sw.command(0, "paths", "", &mut Out::default()).as_deref(),
            Ok("block 0 2\nblock 0 3\nblock 1 2\ndelay 1 3 5ms")
        );
    }

    #[test]
    fn event_kinds_and_fields_are_stable() {
        let e = Event::MacMoved {
            mac: mac(1),
            from: 1,
            to: 2,
        };
        assert_eq!(e.kind(), "mac-moved");
        assert_eq!(
            e.fields(),
            [
                ("mac".to_owned(), "02:00:00:00:00:01".to_owned()),
                ("from".to_owned(), "1".to_owned()),
                ("to".to_owned(), "2".to_owned()),
            ]
        );
    }

    // ---- property test: the switch against a tiny, obviously-correct reference model ----

    mod prop {
        use super::*;
        use proptest::prelude::*;
        use proptest::test_runner::{Config as PropConfig, RngSeed};

        const PORTS: u32 = 5;
        const PROP_AGING: u64 = 50;

        /// Station MACs 1..=5, plus broadcast and a multicast group (index 6 and 7).
        fn pool(i: u8) -> MacAddr {
            match i {
                6 => MacAddr::BROADCAST,
                7 => MacAddr::new([0x01, 0x00, 0x5e, 0, 0, 0xfb]),
                n => mac(n + 1),
            }
        }

        #[derive(Clone, Debug)]
        enum Op {
            Frame {
                port: u32,
                src: u8,
                dst: u8,
            },
            Down(u32),
            Up(u32),
            Advance(u64),
            /// Block (or unblock) every pair between two port sets (bit masks).
            Block(u8, u8, bool),
            Heal,
        }

        fn op() -> impl Strategy<Value = Op> {
            prop_oneof![
                8 => (0..PORTS, 0u8..8, 0u8..8).prop_map(|(port, src, dst)| Op::Frame { port, src, dst }),
                1 => (0..PORTS).prop_map(Op::Down),
                1 => (0..PORTS).prop_map(Op::Up),
                2 => (0u64..40).prop_map(Op::Advance),
                1 => (1u8..32, 1u8..32, any::<bool>()).prop_map(|(a, b, add)| Op::Block(a, b, add)),
                1 => Just(Op::Heal),
            ]
        }

        /// The reference: a list of `(mac, port, last_seen)`, the up ports and the blocked
        /// pairs (`(a, b)` with `a < b`).
        struct Model {
            entries: Vec<(MacAddr, u32, u64)>,
            up: Vec<bool>,
            blocked: Vec<(u32, u32)>,
        }

        impl Model {
            fn blocks(&self, a: u32, b: u32) -> bool {
                self.blocked.contains(&(a.min(b), a.max(b)))
            }

            fn age(&mut self, now: u64) {
                self.entries.retain(|&(_, _, seen)| now < seen + PROP_AGING);
            }

            /// The ports a frame must leave by, ascending.
            fn expect(&mut self, now: u64, port: u32, src: MacAddr, dst: MacAddr) -> Vec<u32> {
                self.age(now);
                if !self.up[port as usize] || src.is_multicast() {
                    return vec![];
                }
                match self.entries.iter_mut().find(|e| e.0 == src) {
                    Some(e) => (e.1, e.2) = (port, now),
                    None => self.entries.push((src, port, now)),
                }
                let known = self.entries.iter().find(|e| e.0 == dst && dst.is_unicast());
                match known {
                    Some(&(_, p, _)) if p == port => vec![],
                    Some(&(_, p, _)) if self.blocks(port, p) => vec![],
                    Some(&(_, p, _)) => vec![p],
                    None => (0..PORTS)
                        .filter(|&p| p != port && self.up[p as usize] && !self.blocks(port, p))
                        .collect(),
                }
            }
        }

        proptest! {
            #![proptest_config(PropConfig {
                cases: 512,
                // Deterministic like everything else here; no regression files (no filesystem).
                rng_seed: RngSeed::Fixed(42),
                failure_persistence: None,
                ..PropConfig::default()
            })]

            /// Every frame leaves by exactly the right ports, each at most once, never by the
            /// ingress port and never by a down port, with its bytes unchanged.
            #[test]
            fn frames_go_to_the_right_ports_exactly_once(ops in proptest::collection::vec(op(), 1..200)) {
                let mut sw = Switch::new(Config { ports: PORTS, aging_ns: PROP_AGING, ..Config::default() });
                let mut model = Model { entries: vec![], up: vec![true; PORTS as usize], blocked: vec![] };
                for p in 0..PORTS {
                    sw.link_state(0, p, true, &mut Out::default());
                }
                let mut now = 0;
                for op in ops {
                    match op {
                        Op::Advance(dt) => {
                            now += dt;
                            sw.poll(now, &mut Out::default());
                        }
                        Op::Down(p) | Op::Up(p) => {
                            let up = matches!(op, Op::Up(_));
                            sw.link_state(now, p, up, &mut Out::default());
                            model.age(now);
                            if !up {
                                model.entries.retain(|e| e.1 != p);
                            }
                            model.up[p as usize] = up;
                        }
                        Op::Block(a, b, add) => {
                            let set = |m: u8| (0..PORTS).filter(|p| m & (1 << p) != 0).map(|p| p.to_string()).collect::<Vec<_>>().join("+");
                            let cmd = if add { "block" } else { "unblock" };
                            sw.command(now, cmd, &format!("{} {}", set(a), set(b)), &mut Out::default()).unwrap();
                            for x in (0..PORTS).filter(|p| a & (1 << p) != 0) {
                                for y in (0..PORTS).filter(|p| b & (1 << p) != 0 && *p != x) {
                                    let k = (x.min(y), x.max(y));
                                    model.blocked.retain(|e| *e != k);
                                    if add {
                                        model.blocked.push(k);
                                    }
                                }
                            }
                        }
                        Op::Heal => {
                            sw.command(now, "heal", "", &mut Out::default()).unwrap();
                            model.blocked.clear();
                        }
                        Op::Frame { port, src, dst } => {
                            let f = frame(pool(dst), pool(src));
                            let mut out = Out::default();
                            sw.receive(now, port, &f, &mut out);
                            let got = out.ports();
                            prop_assert!(got.is_sorted() && got.windows(2).all(|w| w[0] != w[1]), "duplicate egress {got:?}");
                            prop_assert!(!got.contains(&port), "sent back out of ingress {port}: {got:?}");
                            prop_assert!(got.iter().all(|&p| sw.is_up(p)), "sent out of a down port: {got:?}");
                            prop_assert!(out.tx.iter().all(|(_, b)| *b == f), "frame bytes changed");
                            prop_assert!(got.iter().all(|&p| !model.blocks(port, p)), "a blocked pair exchanged a frame: {port} -> {got:?}");
                            prop_assert_eq!(got, model.expect(now, port, pool(src), pool(dst)));
                        }
                    }
                }
            }
        }
    }
}
