//! The node's stub DNS resolver: what `wasi:sockets/ip-name-lookup` falls back to
//! when a name is neither an IP literal nor in the static `hosts.<name>` table.
//!
//! It behaves like a libc stub resolver with `AI_ADDRCONFIG`:
//!
//! * **Queries** go to the node's DNS servers (the `dns` config key, else the ones its DHCP lease
//!   named), one server at a time, over UDP port 53, from a fresh socket per lookup bound to a
//!   random port. An `A` query is sent if the node has an IPv4 address, an `AAAA` query if it has
//!   a global IPv6 address; both go out together (like glibc's parallel A + AAAA). Query ids
//!   and source ports come from a PRNG seeded by the netstack's seeded `wasi:random`, so they
//!   change with the seed and replay exactly.
//! * **Retries**: each try waits `resolver.timeout` (default 5 s), then moves to the next server;
//!   `resolver.attempts` (default 2) rounds over the server list. Every try uses new ids.
//! * **Answers**: every `A`/`AAAA` record in the answer section counts (a CNAME chain is trusted
//!   to be complete, as servers send it). The result lists IPv6 first when the node has a global
//!   IPv6 address (RFC 6724's preference), IPv4 first otherwise. `NXDOMAIN`, or no address of a
//!   wanted family (`NODATA`), is `name-unresolvable`.
//! * **Server failures** move to the next server at once: `SERVFAIL` (→ finally
//!   `temporary-resolver-failure`), `REFUSED` / `NOTIMP` / `FORMERR` (→
//!   `permanent-resolver-failure`), and **ICMP errors**: the socket asks for its errors
//!   (`IP_RECVERR`, the same queue as `wasmnet:sockets-ext/udp`), so a port unreachable from a
//!   host that runs no DNS server ends that server's tries one round trip after the query. When
//!   every server was unreachable that way, the lookup is `name-unresolvable` immediately instead
//!   of after `timeout × attempts`. Running out of tries on timeouts is
//!   `temporary-resolver-failure`.
//! * Truncated (TC) answers are used as they are: there is no TCP fallback (wasmnet's server
//!   never truncates).
//!
//! Journal: `dns-query {name, type, server, id}` per query, `dns-response {name, type, server,
//! id, rcode, answers, rtt-ns}` per matching response, `dns-error {name, server, error}` per ICMP
//! error, and once per lookup `name-resolved {name, addresses, after-ns}` or
//! `name-lookup-failed {name, error, after-ns}`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use wasmnet_wire::dns::{self, Message, RData, rcode, rtype};

use crate::names::LookupError;
use crate::udp::{Family, Net, SockError, SocketId, UdpSockets};
use crate::{Event, Level, Output};

/// Default per-try timeout (glibc's `timeout:5`).
pub const DEFAULT_TIMEOUT_NS: u64 = 5_000_000_000;
/// Default rounds over the server list (glibc's `attempts:2`).
pub const DEFAULT_ATTEMPTS: u32 = 2;
/// mDNS one-shot queries: a try waits 1 s, three tries.
pub const DEFAULT_MDNS_TIMEOUT_NS: u64 = 1_000_000_000;
pub const DEFAULT_MDNS_ATTEMPTS: u32 = 3;
/// Lookups in flight at once.
const MAX_LOOKUPS: usize = 64;

/// A lookup's handle.
pub type LookupId = u64;

/// Resolver counters (part of the netstack's `counters`; 0 without a resolver).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResolverCounters {
    pub lookups: u64,
    pub queries: u64,
    pub responses: u64,
    pub timeouts: u64,
    pub icmp_errors: u64,
    pub resolved: u64,
    pub failed: u64,
    /// Datagrams on a lookup socket that were not a matching response.
    pub ignored: u64,
}

/// How a lookup started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    Done(Result<Vec<IpAddr>, LookupError>),
    Pending(LookupId),
}

/// Why a server did not answer usefully, for the final error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Failure {
    Timeout,
    Unreachable,
    ServFail,
    Refused,
}

#[derive(Debug)]
struct Lookup {
    name: String,
    started: u64,
    servers: Vec<IpAddr>,
    /// 53, or 5353 for mDNS.
    port: u16,
    timeout_ns: u64,
    /// A one-shot mDNS query (RFC 6762 §5.1): answers come from any responder (its unicast
    /// address, port 5353), and nobody answering means the name does not exist.
    mdns: bool,
    qtypes: Vec<u16>,
    prefer_v6: bool,
    /// Tries sent so far (each try: one query per qtype to one server).
    tries: u32,
    max_tries: u32,
    server: usize,
    /// Servers that answered with an ICMP error: skipped from then on.
    dead: Vec<bool>,
    /// The current try: ids per qtype, when it was sent, its deadline.
    ids: Vec<u16>,
    sent_at: u64,
    deadline: Option<u64>,
    /// Answers of the current try, per qtype.
    answers: Vec<Option<Vec<IpAddr>>>,
    failures: Vec<Failure>,
    /// The current try ended with a server failure (so no timeout is counted for it).
    try_failed: bool,
    socket: Option<(Family, SocketId)>,
    result: Option<Result<Vec<IpAddr>, LookupError>>,
}

/// Every lookup in flight.
#[derive(Debug)]
pub struct Resolver {
    lookups: BTreeMap<LookupId, Lookup>,
    next: LookupId,
    rng: u64,
    pub timeout_ns: u64,
    pub attempts: u32,
    /// mDNS: per-try timeout and tries.
    pub mdns_timeout_ns: u64,
    pub mdns_attempts: u32,
    pub counters: ResolverCounters,
}

/// SplitMix64: the resolver's PRNG (ids and ports), seeded from the netstack's seeded RNG.
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn join(addrs: &[IpAddr]) -> String {
    addrs
        .iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

impl Resolver {
    /// `seed` drives the query ids and source ports.
    pub fn new(seed: u64, timeout_ns: u64, attempts: u32) -> Self {
        Self {
            lookups: BTreeMap::new(),
            next: 1,
            rng: seed,
            timeout_ns,
            attempts: attempts.max(1),
            mdns_timeout_ns: DEFAULT_MDNS_TIMEOUT_NS,
            mdns_attempts: DEFAULT_MDNS_ATTEMPTS,
            counters: ResolverCounters::default(),
        }
    }

    /// Starts a DNS lookup of `name` (already checked: not a literal, not in the hosts table).
    /// `v4` / `v6`: the node has an address of that family (`AI_ADDRCONFIG`). `mdns`: a `.local`
    /// name, asked with one-shot multicast queries instead of `servers`.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        name: &str,
        now: u64,
        servers: &[IpAddr],
        v4: bool,
        v6: bool,
        mdns: bool,
        out: &mut Output,
    ) -> Start {
        let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        if !dns::valid_name(&name) {
            return Start::Done(Err(LookupError::InvalidArgument));
        }
        let qtypes: Vec<u16> = [(v4, rtype::A), (v6, rtype::AAAA)]
            .into_iter()
            .filter_map(|(on, t)| on.then_some(t))
            .collect();
        let group = |v4: bool| -> IpAddr {
            if v4 {
                IpAddr::from(dns::MDNS_V4)
            } else {
                IpAddr::from(dns::MDNS_V6)
            }
        };
        // mDNS: one-shot queries to the group, of the family the node has an address of.
        let servers = if mdns {
            vec![group(v4)]
        } else {
            servers.to_vec()
        };
        let why = if servers.is_empty() {
            Some("no DNS server")
        } else if qtypes.is_empty() {
            Some("no address to query from")
        } else if self.lookups.len() >= MAX_LOOKUPS {
            Some("too many lookups in flight")
        } else {
            None
        };
        if let Some(why) = why {
            out.log(Level::Debug, format!("lookup {name}: {why}"));
            return Start::Done(Err(LookupError::NameUnresolvable));
        }
        let id = self.next;
        self.next += 1;
        self.counters.lookups += 1;
        let n = qtypes.len();
        self.lookups.insert(
            id,
            Lookup {
                name,
                started: now,
                port: if mdns { dns::MDNS_PORT } else { dns::PORT },
                timeout_ns: if mdns {
                    self.mdns_timeout_ns
                } else {
                    self.timeout_ns
                },
                mdns,
                servers: servers.clone(),
                qtypes,
                prefer_v6: v6,
                tries: 0,
                max_tries: if mdns {
                    self.mdns_attempts
                } else {
                    self.attempts * servers.len() as u32
                },
                server: 0,
                dead: vec![false; servers.len()],
                ids: Vec::new(),
                sent_at: now,
                deadline: None,
                answers: vec![None; n],
                failures: Vec::new(),
                try_failed: false,
                socket: None,
                result: None,
            },
        );
        Start::Pending(id)
    }

    /// The result of lookup `id`, once there is one (it is then forgotten).
    pub fn take(&mut self, id: LookupId) -> Option<Result<Vec<IpAddr>, LookupError>> {
        let result = self.lookups.get(&id)?.result.clone()?;
        self.lookups.remove(&id);
        Some(result)
    }

    /// The app dropped its call: forget the lookup and close its socket.
    pub fn cancel(&mut self, id: LookupId, now: u64, udp: &mut UdpSockets, net: &mut Net<'_>) {
        if let Some(l) = self.lookups.remove(&id)
            && let Some((_, sock)) = l.socket
        {
            udp.close(sock, now, net.sockets);
        }
    }

    /// The earliest retry or give-up deadline.
    pub fn next_deadline(&self) -> Option<u64> {
        self.lookups
            .values()
            .filter(|l| l.result.is_none())
            .filter_map(|l| l.deadline)
            .min()
    }

    /// Its state for a quiescent snapshot: no lookup at all (finished ones
    /// wait for their caller), so only the generator, the next id and the counters.
    pub fn snapshot_save(&self, w: &mut crate::snapshot::W) {
        use crate::snapshot::Counters;
        w.u64(self.next);
        w.u64(self.rng);
        self.counters.put(w);
    }

    /// Puts [`snapshot_save`](Self::snapshot_save)'s state back.
    pub fn snapshot_restore(&mut self, r: &mut crate::snapshot::R<'_>) -> crate::snapshot::Res<()> {
        use crate::snapshot::Counters;
        self.next = r.u64()?;
        self.rng = r.u64()?;
        self.counters = ResolverCounters::get(r)?;
        Ok(())
    }

    /// No lookup is held, finished or not.
    pub fn is_idle(&self) -> bool {
        self.lookups.is_empty()
    }

    /// Lookups not yet finished.
    pub fn in_flight(&self) -> usize {
        self.lookups.values().filter(|l| l.result.is_none()).count()
    }

    /// Runs every lookup at `now`: reads responses and ICMP errors, then sends due tries. Call
    /// after `Interface::poll`. Returns whether it queued a datagram or finished a lookup (the
    /// stack then polls again at this instant).
    pub fn poll(
        &mut self,
        now: u64,
        udp: &mut UdpSockets,
        net: &mut Net<'_>,
        out: &mut Output,
    ) -> bool {
        let mut progressed = false;
        let ids: Vec<LookupId> = self.lookups.keys().copied().collect();
        for id in ids {
            let Some(mut l) = self.lookups.remove(&id) else {
                continue;
            };
            if l.result.is_none() {
                progressed |= self.drive(&mut l, now, udp, net, out);
            }
            self.lookups.insert(id, l);
        }
        progressed
    }

    fn drive(
        &mut self,
        l: &mut Lookup,
        now: u64,
        udp: &mut UdpSockets,
        net: &mut Net<'_>,
        out: &mut Output,
    ) -> bool {
        let mut progressed = false;
        // Bounded: every round either sends a try (at most `max_tries`) or ends the lookup.
        loop {
            if l.deadline.is_some() {
                self.read(l, now, udp, net, out);
            }
            if l.result.is_none() && l.deadline.is_some_and(|d| d <= now) {
                // Timed out, or a server failure moved the deadline to now: next server.
                if !l.try_failed {
                    self.counters.timeouts += 1;
                    l.failures.push(Failure::Timeout);
                }
                l.server = (l.server + 1) % l.servers.len();
                l.deadline = None;
            }
            if l.result.is_none() && l.deadline.is_none() {
                self.send_try(l, now, udp, net, out);
                if l.result.is_none() && l.deadline != Some(now) {
                    progressed = true;
                    break;
                }
                continue;
            }
            break;
        }
        if l.result.is_some() {
            self.finish(l, now, udp, net, out);
            return true;
        }
        progressed
    }

    /// Reads every datagram and ICMP error that arrived on the lookup's socket.
    fn read(
        &mut self,
        l: &mut Lookup,
        now: u64,
        udp: &mut UdpSockets,
        net: &mut Net<'_>,
        out: &mut Output,
    ) {
        let Some((_, sock)) = l.socket else { return };
        let server = SocketAddr::new(l.servers[l.server], l.port);
        while let Ok(Some(e)) = udp.take_error(sock) {
            if SocketAddr::new(e.orig_dst, e.dport) != server || !e.is_hard() {
                continue;
            }
            self.counters.icmp_errors += 1;
            out.event(Event::new(
                "dns-error",
                &[
                    ("name", l.name.clone()),
                    ("server", server.ip().to_string()),
                    ("error", e.name().to_owned()),
                    ("from", e.from.to_string()),
                ],
            ));
            l.dead[l.server] = true;
            l.failures.push(Failure::Unreachable);
            l.try_failed = true;
            l.deadline = Some(now);
        }
        while let Ok(Some((payload, from))) = udp.receive(sock, net) {
            let Ok(msg) = Message::parse(&payload) else {
                self.counters.ignored += 1;
                continue;
            };
            let slot = l.ids.iter().position(|&id| id == msg.id);
            // mDNS answers come from the responder's own address, port 5353.
            let from_server = if l.mdns {
                from.port() == dns::MDNS_PORT
            } else {
                from == server
            };
            let matches = from_server
                && msg.is_response()
                && slot.is_some_and(|i| {
                    msg.questions
                        .first()
                        .is_some_and(|q| dns::same_name(&q.name, &l.name) && q.qtype == l.qtypes[i])
                });
            let (Some(i), true) = (slot, matches) else {
                self.counters.ignored += 1;
                continue;
            };
            if l.answers[i].is_some() {
                self.counters.ignored += 1;
                continue;
            }
            self.counters.responses += 1;
            let addrs: Vec<IpAddr> = msg
                .answers
                .iter()
                .filter(|r| r.rtype == l.qtypes[i])
                .filter_map(|r| match r.data {
                    RData::A(a) => Some(IpAddr::V4(a)),
                    RData::Aaaa(a) => Some(IpAddr::V6(a)),
                    _ => None,
                })
                .collect();
            out.event(Event::new(
                "dns-response",
                &[
                    ("name", l.name.clone()),
                    ("type", dns::type_name(l.qtypes[i])),
                    ("server", server.ip().to_string()),
                    ("id", msg.id.to_string()),
                    ("rcode", dns::rcode_name(msg.rcode())),
                    ("answers", join(&addrs)),
                    ("rtt-ns", (now - l.sent_at).to_string()),
                ],
            ));
            match msg.rcode() {
                rcode::NOERROR => l.answers[i] = Some(addrs),
                rcode::NXDOMAIN => {
                    l.result = Some(Err(LookupError::NameUnresolvable));
                    return;
                }
                rcode::SERVFAIL => {
                    l.failures.push(Failure::ServFail);
                    l.try_failed = true;
                    l.deadline = Some(now);
                    return;
                }
                _ => {
                    l.failures.push(Failure::Refused);
                    l.try_failed = true;
                    l.deadline = Some(now);
                    return;
                }
            }
        }
        if l.answers.iter().all(Option::is_some) {
            let mut all: Vec<IpAddr> = l.answers.iter().flatten().flatten().copied().collect();
            all.sort_by_key(|a| a.is_ipv4() == l.prefer_v6);
            all.dedup();
            l.result = Some(if all.is_empty() {
                Err(LookupError::NameUnresolvable)
            } else {
                Ok(all)
            });
        }
    }

    /// Sends the next try, or ends the lookup when no try is left.
    fn send_try(
        &mut self,
        l: &mut Lookup,
        now: u64,
        udp: &mut UdpSockets,
        net: &mut Net<'_>,
        out: &mut Output,
    ) {
        // The next live server, from the current one on.
        let live = (0..l.servers.len())
            .map(|k| (l.server + k) % l.servers.len())
            .find(|&s| !l.dead[s]);
        let Some(server) = live.filter(|_| l.tries < l.max_tries) else {
            // mDNS has no negative answer: nobody answering means nobody has the name.
            l.result = Some(Err(if l.mdns {
                LookupError::NameUnresolvable
            } else {
                final_error(&l.failures)
            }));
            return;
        };
        l.server = server;
        l.tries += 1;
        let dst = SocketAddr::new(l.servers[server], l.port);
        let family = Family::of(dst.ip());
        let sock = match self.socket(l, family, now, udp, net) {
            Ok(s) => s,
            Err(_) => {
                // Not routable from here (no address or gateway of that family): skip it.
                l.dead[server] = true;
                l.failures.push(Failure::Unreachable);
                l.try_failed = true;
                l.deadline = Some(now);
                return;
            }
        };
        l.try_failed = false;
        l.ids.clear();
        l.answers.iter_mut().for_each(|a| *a = None);
        for &qtype in &l.qtypes.clone() {
            let id = splitmix(&mut self.rng) as u16;
            l.ids.push(id);
            let query = Message::query(id, &l.name, qtype).encode();
            match udp.send(sock, &query, Some(dst), net) {
                Ok(_) => {
                    self.counters.queries += 1;
                    out.event(Event::new(
                        "dns-query",
                        &[
                            ("name", l.name.clone()),
                            ("type", dns::type_name(qtype)),
                            ("server", dst.ip().to_string()),
                            ("id", id.to_string()),
                        ],
                    ));
                }
                Err(_) => {
                    l.dead[server] = true;
                    l.failures.push(Failure::Unreachable);
                    l.try_failed = true;
                    l.deadline = Some(now);
                    return;
                }
            }
        }
        l.sent_at = now;
        l.deadline = Some(now + l.timeout_ns);
    }

    /// The lookup's socket for `family`: bound to a random port, asking for its ICMP errors. A
    /// socket of the other family is closed at `now` (it may linger with queued datagrams).
    fn socket(
        &mut self,
        l: &mut Lookup,
        family: Family,
        now: u64,
        udp: &mut UdpSockets,
        net: &mut Net<'_>,
    ) -> Result<SocketId, SockError> {
        if let Some((f, s)) = l.socket {
            if f == family {
                return Ok(s);
            }
            udp.close(s, now, net.sockets);
            l.socket = None;
        }
        let sock = udp.create(family);
        let mut bound = Err(SockError::AddressInUse);
        for _ in 0..8 {
            let port = 49_152 + (splitmix(&mut self.rng) % 16_384) as u16;
            bound = udp.bind(sock, SocketAddr::new(family.unspecified(), port), net);
            if bound.is_ok() {
                break;
            }
        }
        if bound.is_err() {
            bound = udp.bind(sock, SocketAddr::new(family.unspecified(), 0), net);
        }
        // mDNS packets carry hop limit 255 (RFC 6762 §11), so a receiver can tell they are on-link.
        let set = bound
            .and_then(|_| udp.set_recv_errors(sock, true))
            .and_then(|_| match l.mdns {
                true => udp.set_multicast_hop_limit(sock, 255),
                false => Ok(()),
            });
        if let Err(e) = set {
            udp.close(sock, now, net.sockets);
            return Err(e);
        }
        l.socket = Some((family, sock));
        Ok(sock)
    }

    fn finish(
        &mut self,
        l: &mut Lookup,
        now: u64,
        udp: &mut UdpSockets,
        net: &mut Net<'_>,
        out: &mut Output,
    ) {
        if let Some((_, sock)) = l.socket.take() {
            udp.close(sock, now, net.sockets);
        }
        l.deadline = None;
        let after = now.saturating_sub(l.started).to_string();
        match &l.result {
            Some(Ok(addrs)) => {
                self.counters.resolved += 1;
                out.event(Event::new(
                    "name-resolved",
                    &[
                        ("name", l.name.clone()),
                        ("addresses", join(addrs)),
                        ("after-ns", after),
                    ],
                ));
            }
            Some(Err(e)) => {
                self.counters.failed += 1;
                out.event(Event::new(
                    "name-lookup-failed",
                    &[
                        ("name", l.name.clone()),
                        ("error", e.name().to_owned()),
                        ("after-ns", after),
                    ],
                ));
            }
            None => {}
        }
    }
}

/// The error once every try is spent: every server unreachable is `name-unresolvable` (nothing
/// listens there); a `REFUSED`-like answer is permanent; anything else is temporary.
fn final_error(failures: &[Failure]) -> LookupError {
    if !failures.is_empty() && failures.iter().all(|f| *f == Failure::Unreachable) {
        LookupError::NameUnresolvable
    } else if failures.contains(&Failure::Refused) {
        LookupError::PermanentFailure
    } else {
        LookupError::TemporaryFailure
    }
}
