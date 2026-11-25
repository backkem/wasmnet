//! Which ports may reach which, and how slowly: the switch's blocks and delays between port sets.
//!
//! A *block* keeps two ports apart: a frame that arrives on one never leaves by the other, in
//! either direction, whether it would be forwarded or flooded. A *delay* holds every frame
//! between two ports for a fixed time before it leaves; the switch releases held frames on its
//! own `poll` deadline. Both are kept per unordered pair of ports, so a command that names two
//! port sets changes every pair between them.
//!
//! Port sets are written `<n>`, `<lo>-<hi>` and joined with `+`: `0`, `0-2`, `0-1+4`.
//! Nothing here applies until a block or a delay exists: a switch without them forwards exactly
//! as before.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use wasmnet_wire::{format_duration, parse_duration};

/// Most frames held for delayed release at once; more are dropped and counted.
pub const MAX_HELD: usize = 4096;

/// A set of ports (the switch has at most 64).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortSet(pub u64);

impl PortSet {
    pub fn contains(self, port: u32) -> bool {
        port < 64 && self.0 & (1 << port) != 0
    }

    pub fn ports(self) -> impl Iterator<Item = u32> {
        (0..64).filter(move |&p| self.contains(p))
    }

    /// Parses `0-1+4` against a switch of `ports` ports.
    pub fn parse(text: &str, ports: u32) -> Result<PortSet, String> {
        let bad = || {
            format!(
                "`{text}` is not a port set like `0`, `0-2` or `0-1+4` (ports 0 to {})",
                ports.saturating_sub(1)
            )
        };
        let mut set = 0u64;
        for part in text.split('+') {
            let (lo, hi) = match part.split_once('-') {
                Some((lo, hi)) => (lo, hi),
                None => (part, part),
            };
            let lo: u32 = lo.parse().map_err(|_| bad())?;
            let hi: u32 = hi.parse().map_err(|_| bad())?;
            if lo > hi || hi >= ports {
                return Err(bad());
            }
            for p in lo..=hi {
                set |= 1 << p;
            }
        }
        Ok(PortSet(set))
    }
}

impl fmt::Display for PortSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let words: Vec<String> = self.ports().map(|p| p.to_string()).collect();
        f.write_str(&words.join("+"))
    }
}

/// A frame waiting for its delay to pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    pub ingress: u32,
    pub egress: u32,
    pub flooded: bool,
    pub frame: Vec<u8>,
}

/// What a command changed, for the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Blocked {
        from: PortSet,
        to: PortSet,
        pairs: u32,
    },
    Unblocked {
        from: PortSet,
        to: PortSet,
        pairs: u32,
    },
    Healed {
        pairs: u32,
    },
    Delayed {
        from: PortSet,
        to: PortSet,
        delay_ns: u64,
    },
    /// A new configuration replaced every block and delay: how many pairs of each it has now.
    Replaced {
        blocks: u32,
        delays: u32,
    },
}

/// The blocks, the delays and the frames held for them.
#[derive(Debug, Default)]
pub struct Paths {
    blocked: BTreeSet<(u32, u32)>,
    delays: BTreeMap<(u32, u32), u64>,
    /// By release time, then arrival order.
    held: BTreeMap<(u64, u64), Held>,
    seq: u64,
    /// A block or a delay existed: the switch lists the counters that go with them from then on.
    pub used: bool,
    /// Frames dropped because too many were held, or because their egress port was down when
    /// they were due.
    pub held_dropped: u64,
    /// The config values the blocks and delays came from (`blocks`, `delays`).
    source: (Option<String>, Option<String>),
}

fn pair(a: u32, b: u32) -> (u32, u32) {
    (a.min(b), a.max(b))
}

/// Every pair with one port in `a` and the other in `b` (never a port with itself).
fn pairs(a: PortSet, b: PortSet) -> Vec<(u32, u32)> {
    let mut v: Vec<(u32, u32)> = a
        .ports()
        .flat_map(|x| b.ports().filter(move |&y| y != x).map(move |y| pair(x, y)))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

impl Paths {
    /// The `blocks` and `delays` config keys: comma-separated items, `<set> <set>` and
    /// `<set> <set> <duration>`.
    pub fn from_config(
        blocks: Option<&str>,
        delays: Option<&str>,
        ports: u32,
    ) -> Result<Paths, String> {
        let mut p = Paths {
            source: (blocks.map(str::to_owned), delays.map(str::to_owned)),
            ..Paths::default()
        };
        let items = |v: Option<&str>| -> Vec<String> {
            v.unwrap_or("")
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        };
        for item in items(blocks) {
            p.block(&item, ports, true)
                .map_err(|why| format!("blocks `{item}`: {why}"))?;
        }
        for item in items(delays) {
            p.delay(&item, ports)
                .map_err(|why| format!("delays `{item}`: {why}"))?;
        }
        Ok(p)
    }

    /// Takes the blocks and delays of a new configuration ([`Paths::from_config`]) while the
    /// switch runs. When its `blocks` and `delays` values are those of the configuration in
    /// force, nothing changes, so blocks and delays set by commands since stay. When either
    /// differs, the new configuration's replace every block and delay, those set by commands
    /// too. Held frames keep their release time either way: they leave then if their egress
    /// port is up and not blocked from their ingress port, and are counted as dropped if not.
    pub fn reconfigure(&mut self, new: Paths) -> Option<Change> {
        if new.source == self.source {
            return None;
        }
        self.blocked = new.blocked;
        self.delays = new.delays;
        self.source = new.source;
        self.used = true;
        Some(Change::Replaced {
            blocks: self.blocked.len() as u32,
            delays: self.delays.len() as u32,
        })
    }

    pub fn blocked(&self, a: u32, b: u32) -> bool {
        !self.blocked.is_empty() && self.blocked.contains(&pair(a, b))
    }

    /// The delay between `a` and `b`, 0 when there is none.
    pub fn delay_of(&self, a: u32, b: u32) -> u64 {
        if self.delays.is_empty() {
            return 0;
        }
        self.delays.get(&pair(a, b)).copied().unwrap_or(0)
    }

    pub fn blocked_pairs(&self) -> usize {
        self.blocked.len()
    }

    pub fn delayed_pairs(&self) -> usize {
        self.delays.len()
    }

    pub fn held(&self) -> usize {
        self.held.len()
    }

    fn two_sets(text: &str, ports: u32) -> Result<(PortSet, PortSet), String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        let [a, b] = words.as_slice() else {
            return Err("needs two port sets, like `0+1 2-3`".to_owned());
        };
        Ok((PortSet::parse(a, ports)?, PortSet::parse(b, ports)?))
    }

    /// `block <set> <set>` (`add`) or `unblock <set> <set>`.
    pub fn block(&mut self, text: &str, ports: u32, add: bool) -> Result<Option<Change>, String> {
        let (from, to) = Self::two_sets(text, ports)?;
        let mut n = 0;
        for p in pairs(from, to) {
            let changed = if add {
                self.blocked.insert(p)
            } else {
                self.blocked.remove(&p)
            };
            n += u32::from(changed);
        }
        self.used = true;
        Ok((n > 0).then_some(if add {
            Change::Blocked { from, to, pairs: n }
        } else {
            Change::Unblocked { from, to, pairs: n }
        }))
    }

    /// `partition <set> <set> [<set>...]`: every pair across two different groups is blocked.
    pub fn partition(&mut self, text: &str, ports: u32) -> Result<Vec<Change>, String> {
        let groups = text
            .split_whitespace()
            .map(|w| PortSet::parse(w, ports))
            .collect::<Result<Vec<_>, _>>()?;
        if groups.len() < 2 {
            return Err("partition needs at least two port sets, like `0+1 2`".to_owned());
        }
        let mut changes = Vec::new();
        for (i, a) in groups.iter().enumerate() {
            for b in &groups[i + 1..] {
                if let Some(c) = self.block(&format!("{a} {b}"), ports, true)? {
                    changes.push(c);
                }
            }
        }
        self.used = true;
        Ok(changes)
    }

    /// `heal`: every block goes (delays stay).
    pub fn heal(&mut self) -> Option<Change> {
        let pairs = self.blocked.len() as u32;
        self.blocked.clear();
        (pairs > 0).then_some(Change::Healed { pairs })
    }

    /// `delay <set> <set> <duration>`; `0` removes the delay.
    pub fn delay(&mut self, text: &str, ports: u32) -> Result<Option<Change>, String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        let [a, b, d] = words.as_slice() else {
            return Err("needs two port sets and a duration, like `0 1-2 20ms`".to_owned());
        };
        let (from, to) = (PortSet::parse(a, ports)?, PortSet::parse(b, ports)?);
        let ns = parse_duration(d).ok_or_else(|| format!("`{d}` is not a duration"))?;
        let mut changed = false;
        for p in pairs(from, to) {
            let old = if ns == 0 {
                self.delays.remove(&p)
            } else {
                self.delays.insert(p, ns)
            };
            changed |= old != (ns > 0).then_some(ns);
        }
        self.used = true;
        Ok(changed.then_some(Change::Delayed {
            from,
            to,
            delay_ns: ns,
        }))
    }

    /// Holds a frame until `release`; `false` if too many are held already (it is dropped).
    pub fn hold(&mut self, release: u64, frame: Held) -> bool {
        if self.held.len() >= MAX_HELD {
            self.held_dropped += 1;
            return false;
        }
        self.seq += 1;
        self.held.insert((release, self.seq), frame);
        true
    }

    /// The held frames due at `now`, in release order.
    pub fn due(&mut self, now: u64) -> Vec<Held> {
        let mut out = Vec::new();
        while let Some(entry) = self.held.first_entry() {
            if entry.key().0 > now {
                break;
            }
            out.push(entry.remove());
        }
        out
    }

    /// When the next held frame is due.
    pub fn next_release(&self) -> Option<u64> {
        self.held.keys().next().map(|k| k.0)
    }

    /// `paths`: `block <a> <b>` and `delay <a> <b> <duration>` per pair, in order.
    pub fn listing(&self) -> String {
        let blocks = self.blocked.iter().map(|(a, b)| format!("block {a} {b}"));
        let delays = self
            .delays
            .iter()
            .map(|((a, b), d)| format!("delay {a} {b} {}", format_duration(*d)));
        blocks.chain(delays).collect::<Vec<_>>().join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_sets_parse_and_print() {
        assert_eq!(PortSet::parse("0-1+4", 8), Ok(PortSet(0b10011)));
        assert_eq!(PortSet(0b10011).to_string(), "0+1+4");
        for bad in ["", "8", "2-1", "a", "0+", "1--2", "0-8"] {
            assert!(PortSet::parse(bad, 8).is_err(), "{bad:?}");
        }
        assert!(PortSet::parse("63", 64).is_ok());
    }

    #[test]
    fn blocks_are_per_pair_both_ways_and_heal() {
        let mut p = Paths::default();
        assert_eq!(
            p.block("0+1 2", 4, true),
            Ok(Some(Change::Blocked {
                from: PortSet(0b11),
                to: PortSet(0b100),
                pairs: 2
            }))
        );
        assert!(p.blocked(2, 0) && p.blocked(1, 2) && !p.blocked(0, 1) && !p.blocked(3, 2));
        assert_eq!(p.block("2 0", 4, true), Ok(None), "already blocked");
        assert_eq!(p.listing(), "block 0 2\nblock 1 2");
        assert!(matches!(
            p.block("1 2", 4, false),
            Ok(Some(Change::Unblocked { pairs: 1, .. }))
        ));
        assert_eq!(p.partition("0 1 2-3", 4).unwrap().len(), 3);
        assert_eq!(p.blocked_pairs(), 5, "0-1, 0-2, 0-3, 1-2, 1-3");
        assert_eq!(p.heal(), Some(Change::Healed { pairs: 5 }));
        assert_eq!(p.heal(), None);
        assert!(p.partition("0", 4).is_err());
        assert!(p.block("0", 4, true).is_err());
        assert!(p.used);
    }

    #[test]
    fn delays_hold_frames_until_they_are_due() {
        let mut p = Paths::from_config(Some("0 1"), Some("0 1-2 20ms"), 4).unwrap();
        assert_eq!(p.delay_of(2, 0), 20_000_000);
        assert_eq!(p.delay_of(1, 2), 0);
        let f = |n: u8| Held {
            ingress: 0,
            egress: 2,
            flooded: false,
            frame: vec![n],
        };
        assert!(p.hold(30, f(1)));
        assert!(p.hold(10, f(2)));
        assert!(p.hold(10, f(3)));
        assert_eq!(p.next_release(), Some(10));
        let due: Vec<u8> = p.due(10).into_iter().map(|h| h.frame[0]).collect();
        assert_eq!(due, [2, 3], "by release time, then arrival");
        assert_eq!(p.next_release(), Some(30));
        assert_eq!(
            p.delay("0 1-2 0", 4),
            Ok(Some(Change::Delayed {
                from: PortSet(1),
                to: PortSet(6),
                delay_ns: 0
            }))
        );
        assert_eq!(p.delayed_pairs(), 0);
        assert!(Paths::from_config(Some("0 9"), None, 4).is_err());
        assert!(Paths::from_config(None, Some("0 1"), 4).is_err());
    }
}
