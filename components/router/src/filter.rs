//! The packet filter: an allow list per port for the packets it forwards, stateful on the
//! connection tracking in [`crate::track`].
//!
//! A port with rules forwards a packet that arrived on it when the packet matches one of its
//! rules, or belongs to a flow the router already let through (in either direction: return
//! traffic), or is an ICMP error about such a flow. A port without rules forwards everything,
//! as a router without a filter does, and its packets start flows too, so their answers pass a
//! filtered port. A router that never had a rule tracks nothing. The rule syntax is
//! [`parse_rule`]'s; the design is in `docs/design/nat.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use crate::config::Trace;
use crate::route::Prefix;
use crate::track::{FlowKey, Kind, Timeouts, Track, Tuple, reverse};
use crate::wire::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use crate::{Event, Sink};

/// `first`-mode trace sets stop growing here.
const TRACE_CAP: usize = 4096;
/// The most rules one port holds.
pub const MAX_RULES: usize = 256;

/// A rule's protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleProto {
    Any,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

impl RuleProto {
    fn name(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Icmpv6 => "icmpv6",
        }
    }

    fn matches(self, proto: u8) -> bool {
        match self {
            Self::Any => true,
            Self::Tcp => proto == PROTO_TCP,
            Self::Udp => proto == PROTO_UDP,
            Self::Icmp => proto == PROTO_ICMP,
            Self::Icmpv6 => proto == PROTO_ICMPV6,
        }
    }
}

/// One allow rule: `<proto> [from <prefix>] [to <prefix>] [dport <port>|<low>-<high>]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub proto: RuleProto,
    pub from: Option<Prefix>,
    pub to: Option<Prefix>,
    /// Destination ports, inclusive.
    pub dport: Option<(u16, u16)>,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.proto.name())?;
        if let Some(p) = self.from {
            write!(f, " from {p}")?;
        }
        if let Some(p) = self.to {
            write!(f, " to {p}")?;
        }
        match self.dport {
            Some((lo, hi)) if lo == hi => write!(f, " dport {lo}"),
            Some((lo, hi)) => write!(f, " dport {lo}-{hi}"),
            None => Ok(()),
        }
    }
}

impl Rule {
    /// The rule matches a packet with this tuple (a fragment only matches rules without
    /// `dport`).
    pub fn matches(&self, t: &Tuple) -> bool {
        self.proto.matches(t.proto())
            && self.from.is_none_or(|p| p.contains(t.src()))
            && self.to.is_none_or(|p| p.contains(t.dst()))
            && self
                .dport
                .is_none_or(|(lo, hi)| t.dport().is_some_and(|d| (lo..=hi).contains(&d)))
    }
}

fn prefix(text: &str) -> Result<Prefix, String> {
    let p: Prefix = text
        .parse()
        .map_err(|_| format!("`{text}` is not a prefix like 10.0.1.0/24 or fd00:1::/64"))?;
    if !p.is_canonical() {
        return Err(format!("{text}: host bits are set (use {})", p.masked()));
    }
    Ok(p)
}

/// Parses one rule: `<proto> [from <prefix>] [to <prefix>] [dport <port>|<low>-<high>]`.
/// `proto` is `any`, `tcp`, `udp`, `icmp` or `icmpv6`; `dport` needs `tcp` or `udp`; the
/// prefixes (`10.0.1.0/24`, `fd00:1::/64`, `10.0.1.10/32`) share one family, which must be
/// the protocol's (`icmp` is IPv4, `icmpv6` IPv6).
pub fn parse_rule(text: &str) -> Result<Rule, String> {
    let syntax = || {
        format!(
            "`{text}`: a rule like `tcp to 10.0.1.10/32 dport 80`, `udp from 10.0.2.0/24`, \
             `icmp` or `any from fd00:2::/64`"
        )
    };
    let words: Vec<&str> = text.split_whitespace().collect();
    let (proto, rest) = words.split_first().ok_or_else(syntax)?;
    let proto = match *proto {
        "any" => RuleProto::Any,
        "tcp" => RuleProto::Tcp,
        "udp" => RuleProto::Udp,
        "icmp" => RuleProto::Icmp,
        "icmpv6" => RuleProto::Icmpv6,
        _ => return Err(syntax()),
    };
    let mut rule = Rule {
        proto,
        from: None,
        to: None,
        dport: None,
    };
    let mut it = rest.iter();
    while let Some(word) = it.next() {
        let value = it.next().ok_or_else(syntax)?;
        match *word {
            "from" if rule.from.is_none() => rule.from = Some(prefix(value)?),
            "to" if rule.to.is_none() => rule.to = Some(prefix(value)?),
            "dport" if rule.dport.is_none() => {
                let port = |s: &str| s.parse::<u16>().ok().filter(|&p| p > 0);
                let range = match value.split_once('-') {
                    Some((a, b)) => port(a).zip(port(b)),
                    None => port(value).map(|p| (p, p)),
                };
                rule.dport = Some(
                    range
                        .filter(|(lo, hi)| lo <= hi)
                        .ok_or_else(|| format!("`{value}`: a port 1..=65535 or a range 80-89"))?,
                );
            }
            _ => return Err(syntax()),
        }
    }
    if rule.dport.is_some() && !matches!(proto, RuleProto::Tcp | RuleProto::Udp) {
        return Err(format!("`{text}`: dport needs tcp or udp"));
    }
    let v6 = |p: Option<Prefix>| p.map(|p| matches!(p, Prefix::V6(..)));
    let families: BTreeSet<bool> = [v6(rule.from), v6(rule.to)].into_iter().flatten().collect();
    if families.len() > 1 {
        return Err(format!("`{text}`: from and to are of different families"));
    }
    match (proto, families.first()) {
        (RuleProto::Icmp, Some(true)) => Err(format!("`{text}`: icmp is IPv4 (use icmpv6)")),
        (RuleProto::Icmpv6, Some(false)) => Err(format!("`{text}`: icmpv6 is IPv6 (use icmp)")),
        _ => Ok(rule),
    }
}

/// The filter's counters (`filter-*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FilterCounters {
    /// Flows started (by a rule, or through a port without rules).
    pub new_flows: u64,
    /// Packets that passed as part of a known flow (either direction) or as an error about one.
    pub tracked: u64,
    pub dropped: u64,
    /// Flows that could not be tracked: the table was full (the packet still passed).
    pub table_full: u64,
}

/// The allow lists and the flows they let through.
pub struct Filter {
    rules: BTreeMap<u32, Vec<Rule>>,
    /// Set once any port had a rule: from then on flows are tracked.
    active: bool,
    flows: BTreeMap<FlowKey, Track>,
    timeouts: Timeouts,
    max_flows: usize,
    earliest: Option<u64>,
    trace: Trace,
    traced: BTreeSet<FlowKey>,
    pub trace_suppressed: u64,
    pub counters: FilterCounters,
}

fn endpoint(ip: IpAddr, port: u16, ports: bool) -> String {
    match (ip, ports) {
        (IpAddr::V6(a), true) => format!("[{a}]:{port}"),
        (a, true) => format!("{a}:{port}"),
        (a, false) => a.to_string(),
    }
}

impl Filter {
    pub fn new(
        rules: BTreeMap<u32, Vec<Rule>>,
        timeouts: Timeouts,
        max_flows: usize,
        trace: Trace,
    ) -> Self {
        let rules: BTreeMap<u32, Vec<Rule>> =
            rules.into_iter().filter(|(_, r)| !r.is_empty()).collect();
        Self {
            active: !rules.is_empty(),
            rules,
            flows: BTreeMap::new(),
            timeouts,
            max_flows,
            earliest: None,
            trace,
            traced: BTreeSet::new(),
            trace_suppressed: 0,
            counters: FilterCounters::default(),
        }
    }

    /// Whether the router filters (or did): only then does it list the `filter-*` counters.
    pub fn active(&self) -> bool {
        self.active
    }

    pub fn rule_count(&self) -> usize {
        self.rules.values().map(Vec::len).sum()
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    fn note_deadline(&mut self, d: u64) {
        self.earliest = Some(self.earliest.map_or(d, |e| e.min(d)));
    }

    fn refresh(&mut self, key: FlowKey, now: u64, side: usize, flags: Option<u8>) -> bool {
        let Some(t) = self.flows.get_mut(&key) else {
            return false;
        };
        t.seen(now, side, flags);
        let d = t.deadline(key.0, &self.timeouts);
        self.note_deadline(d);
        true
    }

    /// Whether a packet with tuple `t` that arrived on `port` may be forwarded at `now`.
    /// A refusal is journalled (`filter-drop`, per `trace.filter-drop`).
    pub fn check(&mut self, now: u64, port: u32, t: &Tuple, out: &mut impl Sink) -> bool {
        if !self.active {
            return true;
        }
        let key = t.key;
        let known = match t.kind {
            Kind::Plain => {
                self.refresh(key, now, 0, t.flags) || self.refresh(reverse(key), now, 1, t.flags)
            }
            Kind::Error(inner) => {
                self.flows.contains_key(&inner) || self.flows.contains_key(&reverse(inner))
            }
            Kind::Fragment => false,
        };
        if known {
            self.counters.tracked += 1;
            return true;
        }
        let rules = self.rules.get(&port).map_or(&[][..], Vec::as_slice);
        if !rules.is_empty() && !rules.iter().any(|r| r.matches(t)) {
            self.counters.dropped += 1;
            self.trace_drop(port, t, out);
            return false;
        }
        if t.kind == Kind::Plain {
            if self.flows.len() >= self.max_flows {
                self.counters.table_full += 1;
            } else {
                let mut track = Track::new(now);
                track.seen(now, 0, t.flags);
                let d = track.deadline(key.0, &self.timeouts);
                self.flows.insert(key, track);
                self.note_deadline(d);
                self.counters.new_flows += 1;
            }
        }
        true
    }

    fn trace_drop(&mut self, port: u32, t: &Tuple, out: &mut impl Sink) {
        let report = match self.trace {
            Trace::None => false,
            Trace::All => true,
            Trace::First => {
                if self.traced.contains(&t.key) {
                    false
                } else if self.traced.len() >= TRACE_CAP {
                    self.trace_suppressed += 1;
                    false
                } else {
                    self.traced.insert(t.key)
                }
            }
        };
        if report {
            let (p, src, sport, dst, dport) = t.key;
            out.event(Event::new(
                "filter-drop",
                vec![
                    ("proto".to_owned(), crate::router::proto_name(p)),
                    ("src".to_owned(), endpoint(src, sport, t.ports)),
                    ("dst".to_owned(), endpoint(dst, dport, t.ports)),
                    ("port".to_owned(), port.to_string()),
                ],
            ));
        }
    }

    /// Ends every flow idle past its timeout at `now`.
    pub fn expire(&mut self, now: u64) {
        if self.earliest.is_none_or(|e| e > now) {
            return;
        }
        let timeouts = self.timeouts;
        self.flows.retain(|k, t| t.deadline(k.0, &timeouts) > now);
        self.earliest = self
            .flows
            .iter()
            .map(|(k, t)| t.deadline(k.0, &timeouts))
            .min();
    }

    pub fn next_deadline(&self) -> Option<u64> {
        self.earliest
    }

    /// Adds `rule` to `port`'s list: `Ok("added")`, or `Ok("unchanged")` when it is there.
    pub fn add(&mut self, port: u32, rule: Rule) -> Result<&'static str, String> {
        let list = self.rules.entry(port).or_default();
        if list.contains(&rule) {
            return Ok("unchanged");
        }
        if list.len() >= MAX_RULES {
            return Err(format!("port {port} has {MAX_RULES} rules already"));
        }
        list.push(rule);
        self.active = true;
        Ok("added")
    }

    /// Removes `rule` from `port`'s list: `Ok("removed")` or `Ok("absent")`.
    pub fn remove(&mut self, port: u32, rule: Rule) -> &'static str {
        let Some(list) = self.rules.get_mut(&port) else {
            return "absent";
        };
        let Some(at) = list.iter().position(|r| *r == rule) else {
            return "absent";
        };
        list.remove(at);
        if list.is_empty() {
            self.rules.remove(&port);
        }
        "removed"
    }

    /// Every rule, one per line, `<port> <rule>`, by port then in order.
    pub fn listing(&self) -> String {
        self.rules
            .iter()
            .flat_map(|(p, list)| list.iter().map(move |r| format!("{p} {r}")))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::track::tuple;
    use crate::wire::{self, TCP_ACK, TCP_SYN};
    use std::net::Ipv4Addr;

    #[derive(Default)]
    struct Out(Vec<Event>);

    impl Sink for Out {
        fn transmit(&mut self, _port: u32, _frame: Vec<u8>) {}
        fn event(&mut self, event: Event) {
            self.0.push(event);
        }
    }

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn tcp(src: &str, sport: u16, dst: &str, dport: u16, flags: u8) -> Tuple {
        let seg = wire::tcp_segment(sport, dport, 1, 1, flags, 0);
        tuple(&wire::ipv4(v4(src), v4(dst), PROTO_TCP, 64, 1, &seg)).unwrap()
    }

    #[test]
    fn rules_parse_and_print_back() {
        for text in [
            "tcp to 10.0.1.10/32 dport 80",
            "udp from 10.0.2.0/24 dport 5000-5010",
            "icmp",
            "any from fd00:2::/64 to fd00:1::/64",
            "icmpv6 to fd00:1::10/128",
        ] {
            assert_eq!(parse_rule(text).unwrap().to_string(), text);
        }
        for bad in [
            "",
            "sctp",
            "tcp to 10.0.1.10/24",
            "icmp dport 1",
            "tcp from 10.0.0.0/8 to fd00::/8",
            "icmp from fd00::/8",
            "icmpv6 to 10.0.0.0/8",
            "tcp dport 0",
            "tcp dport 9-8",
            "tcp to",
            "tcp to 10.0.0.0/8 to 10.0.0.0/8",
        ] {
            assert!(parse_rule(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn allows_by_rule_and_return_traffic_only() {
        let mut out = Out::default();
        let rules =
            BTreeMap::from([(1, vec![parse_rule("tcp to 10.0.1.10/32 dport 80").unwrap()])]);
        let mut f = Filter::new(rules, Timeouts::default(), 16, Trace::First);
        // From the outside (port 1): allowed by the rule, then its answer from port 0.
        assert!(f.check(
            0,
            1,
            &tcp("10.0.2.20", 5000, "10.0.1.10", 80, TCP_SYN),
            &mut out
        ));
        assert!(f.check(
            1,
            0,
            &tcp("10.0.1.10", 80, "10.0.2.20", 5000, TCP_SYN | TCP_ACK),
            &mut out
        ));
        // Anything else from the outside is dropped, once journalled.
        assert!(!f.check(
            2,
            1,
            &tcp("10.0.2.20", 5000, "10.0.1.10", 22, TCP_SYN),
            &mut out
        ));
        assert!(!f.check(
            3,
            1,
            &tcp("10.0.2.20", 5000, "10.0.1.10", 22, TCP_SYN),
            &mut out
        ));
        assert_eq!(out.0.len(), 1);
        assert_eq!(out.0[0].kind, "filter-drop");
        // From the inside (no rules): anything, and the answers come back.
        assert!(f.check(
            4,
            0,
            &tcp("10.0.1.10", 40000, "10.0.2.20", 443, TCP_SYN),
            &mut out
        ));
        assert!(f.check(
            5,
            1,
            &tcp("10.0.2.20", 443, "10.0.1.10", 40000, TCP_SYN | TCP_ACK),
            &mut out
        ));
        // An ICMP error about a known flow passes; about an unknown one it does not.
        let quote = wire::ipv4(
            v4("10.0.1.10"),
            v4("10.0.2.20"),
            PROTO_UDP,
            64,
            1,
            &wire::udp_v4(v4("10.0.1.10"), v4("10.0.2.20"), 7000, 53, b"q"),
        );
        let err = |q: &[u8]| {
            tuple(&wire::ipv4(
                v4("10.0.2.1"),
                v4("10.0.1.10"),
                PROTO_ICMP,
                64,
                2,
                &wire::icmpv4(3, 3, [0; 4], &q[..28]),
            ))
            .unwrap()
        };
        assert!(!f.check(6, 1, &err(&quote), &mut out));
        let udp = tuple(&quote).unwrap();
        assert!(f.check(7, 0, &udp, &mut out));
        assert!(f.check(8, 1, &err(&quote), &mut out));
        // Flows expire: the UDP one after 300 s, then its errors are dropped again.
        f.expire(8 + 300_000_000_000);
        assert!(!f.check(9 + 300_000_000_000, 1, &err(&quote), &mut out));
    }

    #[test]
    fn without_rules_it_tracks_nothing() {
        let mut out = Out::default();
        let mut f = Filter::new(BTreeMap::new(), Timeouts::default(), 16, Trace::First);
        assert!(f.check(
            0,
            1,
            &tcp("10.0.2.20", 1, "10.0.1.10", 2, TCP_SYN),
            &mut out
        ));
        assert_eq!(f.flow_count(), 0);
        assert_eq!(f.next_deadline(), None);
        let r = parse_rule("icmp").unwrap();
        assert_eq!(f.add(1, r), Ok("added"));
        assert_eq!(f.add(1, r), Ok("unchanged"));
        assert!(f.active());
        assert_eq!(f.listing(), "1 icmp");
        assert_eq!(f.remove(1, r), "removed");
        assert_eq!(f.remove(1, r), "absent");
    }
}
