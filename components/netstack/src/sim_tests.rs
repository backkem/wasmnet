//! End-to-end tests of the pure stack: several [`Stack`]s on a hub (every frame reaches every
//! other node `latency` later), driven event to event like the host does it. They run inside
//! wasmtime (`cargo xtask test-guest`) and natively (`cargo test --workspace`).

use std::collections::BTreeMap;

use wasmnet_wire::MacAddr;

use crate::{Config, Event, Note, Stack};

const US: u64 = 1_000;
const MS: u64 = 1_000_000;

enum Ev {
    Deliver { to: usize, frame: Vec<u8> },
    Wake(usize),
}

struct Sim {
    nodes: Vec<Stack>,
    latency: u64,
    queue: BTreeMap<(u64, u64), Ev>,
    seq: u64,
    wake: Vec<Option<u64>>,
    /// `(time, sender, frame)`
    frames: Vec<(u64, usize, Vec<u8>)>,
    /// `(time, node, event)`
    events: Vec<(u64, usize, Event)>,
    logs: Vec<(u64, usize, String)>,
    now: u64,
    /// When a node last did anything (stale wakes do not count).
    active: u64,
    /// Deliver every frame due for a node at one instant before polling it once (so two SYNs
    /// can meet in one `Interface::poll`), instead of one poll per frame.
    batch: bool,
    /// Decides, per transmitted frame `(sender, frame)`, whether the hub loses it: a lost frame
    /// is still recorded in `frames`, but nobody receives it.
    lose: Lose,
}

fn node(pairs: &[(&str, &str)], seed: u64) -> Stack {
    let config = Config::from_pairs(pairs.iter().copied()).expect("config");
    let mac = config.mac.expect("tests configure the MAC");
    // Like the component: smoltcp's seed and the ping identifier both come from the seed.
    Stack::new(&config, mac, seed, 0x4200 + seed as u16, 0)
}

impl Sim {
    fn new(nodes: Vec<Stack>, latency: u64) -> Self {
        let n = nodes.len();
        let mut sim = Self {
            nodes,
            latency,
            queue: BTreeMap::new(),
            seq: 0,
            wake: vec![None; n],
            frames: Vec::new(),
            events: Vec::new(),
            logs: Vec::new(),
            now: 0,
            active: 0,
            batch: false,
            lose: None,
        };
        for i in 0..n {
            sim.step(i);
        }
        sim
    }

    fn push(&mut self, at: u64, ev: Ev) {
        self.queue.insert((at, self.seq), ev);
        self.seq += 1;
    }

    fn step(&mut self, i: usize) {
        let now = self.now;
        self.active = now;
        let out = self.nodes[i].poll(now);
        for frame in out.frames {
            let lost = self.lose.as_mut().is_some_and(|lose| lose(i, &frame));
            for to in (0..self.nodes.len()).filter(|&j| j != i && !lost) {
                self.push(
                    now + self.latency,
                    Ev::Deliver {
                        to,
                        frame: frame.clone(),
                    },
                );
            }
            self.frames.push((now, i, frame));
        }
        for note in out.notes {
            match note {
                Note::Event(e) => self.events.push((now, i, e)),
                Note::Log(_, line) => self.logs.push((now, i, line)),
            }
        }
        let next = self.nodes[i].next_wakeup(now);
        if let Some(t) = next {
            assert!(t > now, "a wakeup must lie in the future");
        }
        if next != self.wake[i] {
            self.wake[i] = next;
            if let Some(t) = next {
                self.push(t, Ev::Wake(i));
            }
        }
    }

    /// Runs until nothing is queued (or `limit`). Returns when a node was last active.
    fn run(&mut self, limit: u64) -> u64 {
        while let Some(((at, _), _)) = self.queue.first_key_value() {
            if *at > limit {
                break;
            }
            let ((at, _), ev) = self.queue.pop_first().expect("non-empty");
            self.now = at;
            match ev {
                Ev::Deliver { to, frame } => {
                    self.nodes[to].receive(frame);
                    while self.batch {
                        let same = self
                            .queue
                            .first_key_value()
                            .and_then(|((t, _), ev)| match ev {
                                Ev::Deliver { to: n, .. } if *t == at && *n == to => Some(()),
                                _ => None,
                            });
                        if same.is_none() {
                            break;
                        }
                        if let Some((_, Ev::Deliver { frame, .. })) = self.queue.pop_first() {
                            self.nodes[to].receive(frame);
                        }
                    }
                    self.step(to);
                }
                Ev::Wake(i) if self.wake[i] == Some(at) => {
                    self.wake[i] = None;
                    self.step(i);
                }
                Ev::Wake(_) => {}
            }
        }
        self.active
    }

    fn events(&self, node: usize, kind: &str) -> Vec<(u64, &Event)> {
        self.events
            .iter()
            .filter(|(_, n, e)| *n == node && e.kind == kind)
            .map(|(t, _, e)| (*t, e))
            .collect()
    }
}

fn a(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut v = vec![
        ("mac", "02:00:00:00:00:01"),
        ("ipv4", "10.0.0.1/24"),
        ("ipv6", "2001:db8::1/64"),
    ];
    v.extend_from_slice(extra);
    v
}

fn b() -> Vec<(&'static str, &'static str)> {
    vec![
        ("mac", "02:00:00:00:00:02"),
        ("ipv4", "10.0.0.2/24"),
        ("ipv6", "2001:db8::2/64"),
    ]
}

fn two(extra: &[(&'static str, &'static str)], seed: u64) -> Sim {
    Sim::new(vec![node(&a(extra), seed), node(&b(), seed + 1)], 100 * US)
}

// ---- Pings on the wire, from an app's ICMP echo socket ----

impl Sim {
    /// A new ICMP echo socket of node `i` (as the `ping` app opens one), bound now.
    fn ping_socket(&mut self, i: usize, v6: bool) -> crate::icmp::SocketId {
        let (t, mut net) = self.nodes[i].icmp();
        let family = if v6 { Family::Ipv6 } else { Family::Ipv4 };
        let s = t.create(family);
        let any = if v6 { ip("::") } else { ip("0.0.0.0") };
        t.bind(s, any, 0, &mut net).expect("bind");
        s
    }

    /// At exactly `t` (after every event before it), node `i`'s app sends echo request `seq`
    /// with `size` payload bytes to `to` on socket `s`, and the driver polls at once.
    fn echo_at(
        &mut self,
        t: u64,
        i: usize,
        s: crate::icmp::SocketId,
        seq: u16,
        size: usize,
        to: &str,
    ) {
        self.run(t.saturating_sub(1));
        self.now = t;
        let payload: Vec<u8> = (0..size).map(|n| n as u8).collect();
        let (icmp, mut net) = self.nodes[i].icmp();
        let msg = echo_request(to.contains(':'), seq, &payload);
        assert_eq!(icmp.send(s, &msg, Some(ip(to)), &mut net), Ok(Send::Queued));
        self.kick(i);
    }

    /// The times node `from` sent echo requests (`reply = false`) or replies.
    fn echoes(&self, from: usize, reply: bool) -> Vec<u64> {
        self.icmp_frames(from)
            .iter()
            .filter(|(_, f)| {
                let t = if f[12] == 8 { f[34] } else { f[54] };
                matches!((reply, t), (false, 8 | 128) | (true, 0 | 129))
            })
            .map(|(t, _)| *t)
            .collect()
    }

    /// The replies waiting on socket `s` of node `i`.
    fn replies(&mut self, i: usize, s: crate::icmp::SocketId) -> usize {
        let (icmp, mut net) = self.nodes[i].icmp();
        let mut n = 0;
        while let Ok(Some(_)) = icmp.receive(s, &mut net) {
            n += 1;
        }
        n
    }
}

#[test]
fn ping_v4_resolves_arp_then_every_rtt_is_two_latencies() {
    let mut sim = two(&[], 1);
    let s = sim.ping_socket(0, false);
    for (seq, t) in [(1, 0), (2, 10 * MS), (3, 20 * MS)] {
        sim.echo_at(t, 0, s, seq, 56, "10.0.0.2");
    }
    let end = sim.run(10_000 * MS);
    let arp = sim.events(0, "arp-resolved");
    assert_eq!(arp.len(), 1);
    assert_eq!(arp[0].0, 200 * US);
    assert_eq!(arp[0].1.get("ip"), Some("10.0.0.2"));
    assert_eq!(arp[0].1.get("mac"), Some("02:00:00:00:00:02"));
    assert_eq!(arp[0].1.get("after-ns"), Some("200000"));
    // The first request waits in smoltcp for ARP; each reply leaves one latency after it.
    assert_eq!(sim.echoes(0, false), [200 * US, 10 * MS, 20 * MS]);
    assert_eq!(
        sim.echoes(1, true),
        [300 * US, 10 * MS + 100 * US, 20 * MS + 100 * US]
    );
    assert_eq!(sim.replies(0, s), 3);
    // Nothing left to do: no node wants a wakeup once the last reply is in.
    assert_eq!(end, 20 * MS + 200 * US);
    assert!(sim.queue.is_empty() && sim.wake.iter().all(Option::is_none));
    // Every frame on the wire is at least the Ethernet minimum.
    assert!(sim.frames.iter().all(|(_, _, f)| f.len() >= 60));
}

#[test]
fn ping6_resolves_ndp_then_echoes() {
    let mut sim = two(&[], 1);
    let s = sim.ping_socket(0, true);
    sim.echo_at(5 * MS, 0, s, 1, 56, "2001:db8::2");
    sim.echo_at(15 * MS, 0, s, 2, 56, "2001:db8::2");
    sim.run(10_000 * MS);
    let nd = sim.events(0, "ndp-resolved");
    assert_eq!(nd.len(), 1);
    assert_eq!(nd[0].0, 5 * MS + 200 * US);
    assert_eq!(nd[0].1.get("ip"), Some("2001:db8::2"));
    assert_eq!(nd[0].1.get("mac"), Some("02:00:00:00:00:02"));
    assert_eq!(sim.echoes(1, true), [5 * MS + 300 * US, 15 * MS + 100 * US]);
    assert_eq!(sim.replies(0, s), 2);
    // At t=0 both nodes report their solicited-node groups (MLDv2, ICMPv6 type 143).
    let mld_at_zero = sim
        .frames
        .iter()
        .filter(|(t, _, f)| *t == 0 && f.get(12..14) == Some(&[0x86, 0xdd]) && f.contains(&143))
        .count();
    assert!(mld_at_zero >= 2, "{mld_at_zero}");
}

#[test]
fn a_missing_neighbor_times_out_and_leaves_nothing_behind() {
    let mut sim = two(&[], 1);
    let s = sim.ping_socket(0, false);
    sim.echo_at(0, 0, s, 1, 56, "10.0.0.99");
    // The app gives up after 1 s and closes its socket (as the `ping` app does when done).
    sim.run(1_000 * MS - 1);
    sim.now = 1_000 * MS;
    let (icmp, net) = sim.nodes[0].icmp();
    icmp.close(s, net.sockets);
    sim.kick(0);
    let end = sim.run(100_000 * MS);
    assert!(sim.echoes(0, false).is_empty(), "the request never left");
    // One ARP request for .99, and no re-send at 1 s: the socket was closed first.
    let who_has_99 = sim
        .frames
        .iter()
        .filter(|(_, n, f)| {
            *n == 0 && f.get(12..14) == Some(&[8, 6]) && f.get(38..42) == Some(&[10, 0, 0, 99])
        })
        .count();
    assert_eq!(who_has_99, 1);
    assert_eq!(end, 1_000 * MS);
    assert!(sim.queue.is_empty());
}

#[test]
fn the_largest_ping_fills_exactly_one_mtu_sized_frame() {
    // 1280-byte IP MTU: 40 (IPv6) + 8 (ICMPv6) + 1232 = 1280, frame = 1294.
    let mut cfg_a = a(&[("mtu", "1280")]);
    cfg_a.retain(|(k, _)| *k != "ipv4");
    let mut cfg_b = b();
    cfg_b.push(("mtu", "1280"));
    let mut sim = Sim::new(vec![node(&cfg_a, 1), node(&cfg_b, 2)], 100 * US);
    let s = sim.ping_socket(0, true);
    sim.echo_at(0, 0, s, 1, 1232, "2001:db8::2");
    sim.run(10_000 * MS);
    assert_eq!(sim.replies(0, s), 1);
    let largest = sim.frames.iter().map(|(_, _, f)| f.len()).max();
    assert_eq!(largest, Some(1294));
}

#[test]
fn same_seed_same_frames_and_another_seed_changes_only_the_ping_id() {
    let run = |seed| {
        let mut sim = two(&[], seed);
        let v4 = sim.ping_socket(0, false);
        let v6 = sim.ping_socket(0, true);
        for (seq, t) in [(1, 0), (2, MS)] {
            sim.echo_at(t, 0, v4, seq, 56, "10.0.0.2");
            sim.echo_at(t, 0, v6, seq, 56, "2001:db8::2");
        }
        sim.run(10_000 * MS);
        sim.frames
    };
    let (x, y, z) = (run(7), run(7), run(8));
    assert_eq!(x, y);
    assert_ne!(x, z, "the echo identifier comes from the seed");
    // smoltcp leaves the IPv4 identification at 0 (DF set), so only the ICMP identifier and
    // checksum differ: bytes 38..40 and 36..38 (IPv4) or 58..60 and 56..58 (IPv6).
    let masked = |f: &[(u64, usize, Vec<u8>)]| -> Vec<Vec<u8>> {
        f.iter()
            .map(|(_, _, b)| {
                let mut b = b.clone();
                let at = match (b[12], b[13], b.get(23), b.get(20), b.get(54)) {
                    (8, 0, Some(1), _, Some(_)) => Some(34),
                    (0x86, 0xdd, _, Some(58), Some(128 | 129)) => Some(54),
                    _ => None,
                };
                if let Some(at) = at {
                    b[at + 2..at + 6].fill(0);
                }
                b
            })
            .collect()
    };
    assert_eq!(masked(&x), masked(&z));
    let shape = |f: &[(u64, usize, Vec<u8>)]| -> Vec<(u64, usize, usize)> {
        f.iter().map(|(t, n, b)| (*t, *n, b.len())).collect()
    };
    assert_eq!(shape(&x), shape(&z));
}

#[test]
fn a_bystander_on_the_hub_only_answers_nothing() {
    let c = node(&[("mac", "02:00:00:00:00:03"), ("ipv4", "10.0.0.3/24")], 3);
    let mut sim = Sim::new(vec![node(&a(&[]), 1), node(&b(), 2), c], 100 * US);
    let s = sim.ping_socket(0, false);
    sim.echo_at(0, 0, s, 1, 56, "10.0.0.2");
    sim.run(10_000 * MS);
    assert_eq!(sim.replies(0, s), 1);
    // The bystander sends only its own MLD reports at t=0, never an ARP or echo reply.
    assert!(sim.frames.iter().filter(|(_, n, _)| *n == 2).all(
        |(t, _, f)| *t == 0 && MacAddr::from_slice(&f[..6]).is_some_and(MacAddr::is_multicast)
    ));
}

#[test]
fn neighbor_requests_are_rate_limited_per_address_not_per_interface() {
    // smoltcp 0.14 allowed one ARP request or NS per second per *interface*, so the NS wanted at
    // 100 ms waited until 1.1 s. The vendored smoltcp (third_party/smoltcp, smoltcp issue #2)
    // silences each address for its own second: the NS leaves at 100 ms, right after the ARP
    // request at 0, and both pings wait exactly one resolution (2 x 100 us).
    let mut sim = two(&[], 1);
    let v4 = sim.ping_socket(0, false);
    let v6 = sim.ping_socket(0, true);
    sim.echo_at(0, 0, v4, 1, 56, "10.0.0.2");
    sim.echo_at(100 * MS, 0, v6, 1, 56, "2001:db8::2");
    sim.run(10_000 * MS);
    let nd = sim.events(0, "ndp-resolved");
    assert_eq!(nd.len(), 1);
    assert_eq!(nd[0].0, 100 * MS + 200 * US);
    assert_eq!(sim.echoes(0, false), [200 * US, 100 * MS + 200 * US]);
}

#[test]
fn two_neighbors_resolve_at_the_same_instant() {
    // Pings to two on-link IPv4 neighbors at the same instant, one socket each (two ping
    // sessions): two ARP requests leave together, and neither reply waits for the other
    // (per-address rate limit, smoltcp issue #2). On one socket the second request would wait
    // behind the first in smoltcp's send queue until its neighbor resolved.
    let mut sim = Sim::new(
        vec![node(&a(&[]), 1), node(&b(), 2), node(&c(), 3)],
        100 * US,
    );
    let s = sim.ping_socket(0, false);
    let s2 = sim.ping_socket(0, false);
    sim.echo_at(0, 0, s, 1, 56, "10.0.0.2");
    sim.echo_at(0, 0, s2, 1, 56, "10.0.0.3");
    sim.run(10_000 * MS);
    let arp: Vec<u64> = sim
        .frames
        .iter()
        .filter(|(_, n, f)| *n == 0 && f.get(12..14) == Some(&[8, 6]))
        .map(|(t, _, _)| *t)
        .collect();
    assert_eq!(arp, [0, 0], "two ARP requests at t=0");
    let resolved: Vec<u64> = sim
        .events(0, "arp-resolved")
        .iter()
        .map(|(t, _)| *t)
        .collect();
    assert_eq!(resolved, [200 * US, 200 * US]);
    assert_eq!(sim.replies(0, s) + sim.replies(0, s2), 2);
}

// ---- UDP sockets for apps ----

use std::net::SocketAddr;

use crate::udp::{Family, LINGER_NS, Send, SockError};

fn sa(s: &str) -> SocketAddr {
    s.parse().expect("socket address")
}

impl Sim {
    /// Polls node `i` at the current instant, as the driver does after a socket call wakes it.
    fn kick(&mut self, i: usize) {
        self.step(i);
    }

    /// IPv4 UDP frames node `from` sent, with their transmit times.
    fn udp_frames(&self, from: usize) -> Vec<u64> {
        self.frames
            .iter()
            .filter(|(_, n, f)| {
                *n == from && f.get(12..14) == Some(&[8, 0]) && f.get(23) == Some(&17)
            })
            .map(|(t, _, _)| *t)
            .collect()
    }
}

#[test]
fn udp_echo_round_trip_costs_arp_once_then_two_latencies() {
    let mut sim = two(&[], 1);
    // Server (node 1) on port 7; client (node 0) sends from an ephemeral port.
    let (udp, mut net) = sim.nodes[1].udp();
    let server = udp.create(Family::Ipv4);
    assert_eq!(
        udp.bind(server, sa("0.0.0.0:7"), &mut net),
        Ok(sa("0.0.0.0:7"))
    );
    let (udp, mut net) = sim.nodes[0].udp();
    let client = udp.create(Family::Ipv4);
    assert_eq!(
        udp.send(client, b"ping", Some(sa("10.0.0.2:7")), &mut net),
        Ok(Send::Queued)
    );
    assert_eq!(udp.local_address(client), Ok(sa("0.0.0.0:49152")));
    sim.kick(0);
    assert_eq!(sim.run(300 * US), 300 * US);
    // ARP at 0, reply at 100 us, the datagram leaves at 200 us and arrives at 300 us.
    let (udp, mut net) = sim.nodes[1].udp();
    let got = udp.receive(server, &mut net).unwrap();
    assert_eq!(got, Some((b"ping".to_vec(), sa("10.0.0.1:49152"))));
    assert_eq!(udp.receive(server, &mut net), Ok(None));
    assert_eq!(
        udp.send(server, b"ping", Some(sa("10.0.0.1:49152")), &mut net),
        Ok(Send::Queued)
    );
    sim.kick(1);
    assert_eq!(sim.run(400 * US), 400 * US);
    // The server learned the client's MAC from its ARP request: no ARP, one latency.
    let (udp, mut net) = sim.nodes[0].udp();
    let back = udp.receive(client, &mut net).unwrap();
    assert_eq!(back, Some((b"ping".to_vec(), sa("10.0.0.2:7"))));
    let mut tx = sim.udp_frames(0);
    tx.extend(sim.udp_frames(1));
    assert_eq!(tx, [200 * US, 300 * US]);
    sim.run(10_000 * MS);
    assert!(sim.queue.is_empty() && sim.wake.iter().all(Option::is_none));
}

#[test]
fn udp_to_a_dead_port_draws_an_icmp_port_unreachable_and_no_datagram() {
    let mut sim = two(&[], 1);
    let (udp, mut net) = sim.nodes[0].udp();
    let s = udp.create(Family::Ipv4);
    udp.connect(s, sa("10.0.0.2:9"), &mut net).unwrap();
    assert_eq!(udp.remote_address(s), Ok(sa("10.0.0.2:9")));
    assert_eq!(udp.send(s, b"anyone?", None, &mut net), Ok(Send::Queued));
    sim.kick(0);
    sim.run(10_000 * MS);
    // ICMPv4 type 3 code 3 from the server, quoting our datagram.
    let unreachable = sim
        .frames
        .iter()
        .filter(|(_, n, f)| {
            *n == 1 && f.get(23) == Some(&1) && f.get(34) == Some(&3) && f.get(35) == Some(&3)
        })
        .count();
    assert_eq!(unreachable, 1);
    let (udp, mut net) = sim.nodes[0].udp();
    assert_eq!(udp.receive(s, &mut net), Ok(None));
}

#[test]
fn udp_errors_follow_wasi() {
    let mut sim = two(&[], 1);
    let (udp, mut net) = sim.nodes[0].udp();
    let a = udp.create(Family::Ipv4);
    let six = udp.create(Family::Ipv6);
    // Receive before bind; bind to an address that is not ours; the wrong family.
    assert_eq!(udp.receive(a, &mut net), Err(SockError::InvalidState));
    assert_eq!(
        udp.bind(a, sa("10.0.0.9:7"), &mut net),
        Err(SockError::AddressNotBindable)
    );
    assert_eq!(
        udp.bind(a, sa("[::]:7"), &mut net),
        Err(SockError::InvalidArgument)
    );
    assert_eq!(
        udp.bind(a, sa("10.0.0.1:7"), &mut net),
        Ok(sa("10.0.0.1:7"))
    );
    assert_eq!(
        udp.bind(a, sa("10.0.0.1:8"), &mut net),
        Err(SockError::InvalidState)
    );
    // [::]:7 does not overlap 10.0.0.1:7: an IPv6 socket is V6ONLY (smoltcp issue #7).
    // Without the netstack's own family check this would be `address-in-use`, because smoltcp's
    // matching ignores the family.
    assert_eq!(udp.bind(six, sa("[::]:7"), &mut net), Ok(sa("[::]:7")));
    let other = udp.create(Family::Ipv4);
    assert_eq!(
        udp.bind(other, sa("0.0.0.0:7"), &mut net),
        Err(SockError::AddressInUse)
    );
    // No destination; port 0; unspecified; IPv4-mapped; too large; unroutable.
    assert_eq!(
        udp.send(a, b"x", None, &mut net),
        Err(SockError::InvalidArgument)
    );
    for bad in ["10.0.0.2:0", "0.0.0.0:7"] {
        assert_eq!(
            udp.send(a, b"x", Some(sa(bad)), &mut net),
            Err(SockError::InvalidArgument)
        );
    }
    assert_eq!(
        udp.send(six, b"x", Some(sa("[::ffff:10.0.0.2]:7")), &mut net),
        Err(SockError::InvalidArgument)
    );
    let big = vec![0u8; 1473];
    assert_eq!(
        udp.send(a, &big, Some(sa("10.0.0.2:7")), &mut net),
        Err(SockError::DatagramTooLarge)
    );
    assert_eq!(
        udp.send(a, &big[..1472], Some(sa("10.0.0.2:7")), &mut net),
        Ok(Send::Queued)
    );
    assert_eq!(
        udp.send(a, b"x", Some(sa("192.168.1.1:7")), &mut net),
        Err(SockError::RemoteUnreachable)
    );
    // Connected: another destination is invalid, the same one is fine.
    udp.connect(a, sa("10.0.0.2:7"), &mut net).unwrap();
    assert_eq!(
        udp.send(a, b"x", Some(sa("10.0.0.2:8")), &mut net),
        Err(SockError::InvalidArgument)
    );
    assert_eq!(
        udp.send(a, b"x", Some(sa("10.0.0.2:7")), &mut net),
        Ok(Send::Queued)
    );
    assert_eq!(udp.disconnect(a), Ok(()));
    assert_eq!(udp.disconnect(a), Err(SockError::InvalidState));
    // Options.
    assert_eq!(udp.unicast_hop_limit(a, 64), Ok(64));
    assert_eq!(
        udp.set_unicast_hop_limit(a, 0, &mut net),
        Err(SockError::InvalidArgument)
    );
    udp.set_unicast_hop_limit(a, 9, &mut net).unwrap();
    assert_eq!(udp.unicast_hop_limit(a, 64), Ok(9));
    // Buffer sizes clamp before bind and stay fixed after it.
    let c = udp.create(Family::Ipv4);
    udp.set_buffer_size(c, true, 10, &net).unwrap();
    assert_eq!(udp.buffer_size(c, true), Ok(1472));
    udp.set_buffer_size(c, false, 1 << 30, &net).unwrap();
    assert_eq!(udp.buffer_size(c, false), Ok(1 << 20));
    assert_eq!(
        udp.set_buffer_size(c, false, 0, &net),
        Err(SockError::InvalidArgument)
    );
    udp.set_buffer_size(a, true, 4096, &net).unwrap();
    assert_eq!(udp.buffer_size(a, true), Ok(65_536));
}

#[test]
fn a_full_send_buffer_would_block_until_the_driver_drains_it() {
    let mut sim = two(&[], 1);
    let (udp, mut net) = sim.nodes[0].udp();
    let s = udp.create(Family::Ipv4);
    udp.set_buffer_size(s, false, 3000, &net).unwrap();
    let dst = Some(sa("10.0.0.2:7"));
    let data = vec![7u8; 1400];
    assert_eq!(udp.send(s, &data, dst, &mut net), Ok(Send::Queued));
    assert_eq!(udp.send(s, &data, dst, &mut net), Ok(Send::Queued));
    assert_eq!(udp.send(s, &data, dst, &mut net), Ok(Send::WouldBlock));
    sim.kick(0);
    sim.run(10_000 * MS);
    let (udp, mut net) = sim.nodes[0].udp();
    assert_eq!(udp.send(s, &data, dst, &mut net), Ok(Send::Queued));
    assert_eq!(udp.counters.would_block, 1);
}

#[test]
fn a_dropped_socket_lingers_until_its_datagram_left_or_three_seconds_passed() {
    let mut sim = two(&[], 1);
    // Resolvable: the datagram leaves after ARP and the socket goes away right then.
    let now = sim.now;
    let (udp, mut net) = sim.nodes[0].udp();
    let s = udp.create(Family::Ipv4);
    udp.send(s, b"bye", Some(sa("10.0.0.2:7")), &mut net)
        .unwrap();
    assert_eq!(udp.open(), 1);
    udp.close(s, now, net.sockets);
    sim.kick(0);
    sim.run(10_000 * MS);
    assert_eq!(sim.udp_frames(0).len(), 1);
    let (udp, _) = sim.nodes[0].udp();
    assert_eq!((udp.open(), udp.next_deadline()), (0, None));

    // Unresolvable: smoltcp keeps asking every second until the linger deadline gives up.
    let t0 = sim.now;
    let (udp, mut net) = sim.nodes[0].udp();
    let s = udp.create(Family::Ipv4);
    udp.send(s, b"lost", Some(sa("10.0.0.99:7")), &mut net)
        .unwrap();
    udp.close(s, t0, net.sockets);
    assert_eq!(udp.next_deadline(), Some(t0 + LINGER_NS));
    sim.kick(0);
    let end = sim.run(100_000 * MS);
    assert_eq!(end, t0 + LINGER_NS);
    let (udp, _) = sim.nodes[0].udp();
    assert_eq!(udp.counters.linger_expired, 1);
    assert_eq!(udp.next_deadline(), None);
    let who_has_99 = sim
        .frames
        .iter()
        .filter(|(_, n, f)| *n == 0 && f.get(38..42) == Some(&[10, 0, 0, 99]))
        .count();
    assert_eq!(who_has_99, 3, "ARP at +0 s, +1 s and +2 s");
}

#[test]
fn names_resolve_from_the_hosts_table() {
    let mut s = node(
        &[
            ("mac", "02:00:00:00:00:01"),
            ("ipv4", "10.0.0.1/24"),
            ("hosts.server", "10.0.0.2"),
        ],
        1,
    );
    use crate::resolver::Start;
    assert_eq!(
        s.lookup_start("SERVER", 0).0,
        Start::Done(Ok(vec!["10.0.0.2".parse().unwrap()]))
    );
    // No DNS server: an unknown name fails at once.
    assert_eq!(
        s.lookup_start("client", 0).0,
        Start::Done(Err(crate::names::LookupError::NameUnresolvable))
    );
}

// ---- TCP sockets for apps ----

use crate::tcp::{Accept, Congestion, RecvStep};

/// A TCP segment on the wire: `(time, sender, flags byte, payload length)`.
type Seg = (u64, usize, u8, usize);

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

fn c() -> Vec<(&'static str, &'static str)> {
    vec![("mac", "02:00:00:00:00:03"), ("ipv4", "10.0.0.3/24")]
}

impl Sim {
    /// Every IPv4 TCP segment, in transmit order.
    fn tcp_segments(&self) -> Vec<Seg> {
        self.frames
            .iter()
            .filter(|(_, _, f)| f.get(12..14) == Some(&[8, 0]) && f.get(23) == Some(&6))
            .map(|(t, n, f)| {
                let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
                let tcp_header = usize::from(f[46] >> 4) * 4;
                (*t, *n, f[47], total - 20 - tcp_header)
            })
            .collect()
    }

    /// `(TcpSockets, TcpNet)` of node `i`.
    fn tcp(&mut self, i: usize) -> (&mut crate::tcp::TcpSockets, crate::tcp::TcpNet<'_>) {
        self.nodes[i].tcp()
    }
}

/// Node `i` listens on `0.0.0.0:80` with `backlog`; returns the listener.
fn listen(sim: &mut Sim, i: usize, backlog: u64) -> u32 {
    let (t, mut net) = sim.tcp(i);
    let l = t.create(Family::Ipv4);
    t.set_backlog(l, backlog).unwrap();
    t.bind(l, sa("0.0.0.0:80"), &mut net).unwrap();
    assert_eq!(t.listen(l, &mut net), Ok(sa("0.0.0.0:80")));
    l
}

/// Node `i` connects to `to`; returns the socket.
fn connect(sim: &mut Sim, i: usize, to: &str) -> u32 {
    let now = sim.now;
    let (t, mut net) = sim.tcp(i);
    let s = t.create(Family::Ipv4);
    t.connect(s, sa(to), now, &mut net).unwrap();
    sim.kick(i);
    s
}

/// The connect of node `i`'s socket `s` completed (what the async `connect` waits for).
fn established(sim: &mut Sim, i: usize, s: u32) {
    let now = sim.now;
    let (t, net) = sim.tcp(i);
    assert_eq!(t.connect_poll(s, now, net.sockets), Some(Ok(())));
}

/// Accepts the next connection on listener `l` of node `i`.
fn accept(sim: &mut Sim, i: usize, l: u32) -> u32 {
    let (t, net) = sim.tcp(i);
    match t.accept(l, net.sockets) {
        Some(Accept::Conn(s)) => {
            t.delivered(l);
            s
        }
        other => panic!("no connection to accept: {other:?}"),
    }
}

/// Writes `data` as the send pump would (it must fit) and, with `fin`, closes the direction.
fn write(sim: &mut Sim, i: usize, s: u32, data: &[u8], fin: bool) {
    let (t, net) = sim.tcp(i);
    if !data.is_empty() {
        let room = t.send_room(s, net.sockets).expect("room").expect("open");
        assert!(room >= data.len(), "room {room}");
        t.send(s, data, net.sockets).unwrap();
    }
    if fin {
        t.finish_send(s, net.sockets);
    }
    sim.kick(i);
}

/// Drains what arrived, as the receive pump would: the bytes, and the end if it came.
fn drain(sim: &mut Sim, i: usize, s: u32) -> (Vec<u8>, Option<Result<(), SockError>>) {
    let mut got = Vec::new();
    loop {
        let (t, net) = sim.tcp(i);
        match t.recv_step(s, net.sockets) {
            Some(RecvStep::Data(d)) => {
                t.consume(s, d.len(), net.sockets);
                got.extend(d);
            }
            Some(RecvStep::End(r)) => {
                sim.kick(i);
                return (got, Some(r));
            }
            None => {
                sim.kick(i);
                return (got, None);
            }
        }
    }
}

#[test]
fn tcp_handshake_request_response_and_fin_both_ways() {
    let mut sim = two(&[], 7);
    let l = listen(&mut sim, 0, 2);
    let cl = connect(&mut sim, 1, "10.0.0.1:80");
    assert_eq!(sim.tcp(1).0.local_address(cl), Ok(sa("10.0.0.2:49152")));
    sim.run(MS);
    sim.now = MS;
    // ARP (0 to 200 us), SYN at 200 us, SYN-ACK at 300 us, established at 400 us.
    let now = sim.now;
    let (t, net) = sim.tcp(1);
    assert_eq!(t.connect_poll(cl, now, net.sockets), Some(Ok(())));
    assert_eq!(t.remote_address(cl), Ok(sa("10.0.0.1:80")));
    t.start_send(cl).unwrap();
    assert_eq!(t.start_send(cl), Err(SockError::InvalidState));
    let sv = accept(&mut sim, 0, l);
    let (t, net) = sim.tcp(0);
    assert_eq!(t.accept(l, net.sockets), None);
    assert_eq!(t.remote_address(sv), Ok(sa("10.0.0.2:49152")));

    write(&mut sim, 1, cl, b"GET / HTTP/1.1\r\n\r\n", true);
    sim.run(2 * MS);
    sim.tcp(0).0.start_recv(sv).unwrap();
    let (req, end) = drain(&mut sim, 0, sv);
    assert_eq!(req, b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(end, Some(Ok(())));
    sim.tcp(0).0.start_send(sv).unwrap();
    write(&mut sim, 0, sv, b"HTTP/1.1 200 OK\r\n\r\n", true);
    sim.run(3 * MS);
    sim.tcp(1).0.start_recv(cl).unwrap();
    let (resp, end) = drain(&mut sim, 1, cl);
    assert_eq!(resp, b"HTTP/1.1 200 OK\r\n\r\n");
    assert_eq!(end, Some(Ok(())));
    assert_eq!(sim.tcp(0).0.counters.fins, 1);
    assert_eq!(sim.tcp(1).0.counters.fins, 1);

    let segs = sim.tcp_segments();
    let flags: Vec<(usize, u8)> = segs.iter().map(|s| (s.1, s.2 & 0x17)).collect();
    assert_eq!(
        &flags[..3],
        &[(1, SYN), (0, SYN | ACK), (1, ACK)],
        "{segs:?}"
    );
    assert_eq!((segs[0].0, segs[1].0), (200 * US, 300 * US));
    assert!(segs.iter().any(|s| s.1 == 1 && s.2 & FIN != 0));
    assert!(segs.iter().any(|s| s.1 == 0 && s.2 & FIN != 0));
    assert!(segs.iter().all(|s| s.2 & RST == 0));

    // Every resource dropped: the connections end (TIME-WAIT) and nothing is left behind.
    let now = sim.now;
    for (i, s) in [(0, sv), (1, cl), (0, l)] {
        let (t, net) = sim.tcp(i);
        t.close(s, now, net.sockets);
    }
    sim.kick(0);
    sim.kick(1);
    // Past TIME-WAIT (10 s) and past the stale wakes of cleared handshake timeouts (75 s).
    sim.run(200_000 * MS);
    for i in 0..2 {
        let (t, _) = sim.tcp(i);
        assert_eq!((t.open(), t.orphans()), (0, 0), "node {i}");
    }
    let left: Vec<String> = sim.queue.keys().map(|k| format!("{k:?}")).collect();
    assert!(
        sim.queue.is_empty() && sim.wake.iter().all(Option::is_none),
        "{left:?} {:?} now={}",
        sim.wake,
        sim.now
    );
}

#[test]
fn the_backlog_is_n_listen_sockets_so_two_syns_in_one_poll_both_get_in() {
    for (backlog, connected) in [(1usize, 1usize), (2, 2)] {
        let mut sim = Sim::new(
            vec![node(&a(&[]), 1), node(&b(), 2), node(&c(), 3)],
            100 * US,
        );
        sim.batch = true;
        let l = listen(&mut sim, 0, backlog as u64);
        let one = connect(&mut sim, 1, "10.0.0.1:80");
        let two = connect(&mut sim, 2, "10.0.0.1:80");
        sim.run(10 * MS);
        let now = sim.now;
        let mut results = Vec::new();
        for (i, s) in [(1, one), (2, two)] {
            let (t, net) = sim.tcp(i);
            results.push(t.connect_poll(s, now, net.sockets));
        }
        let ok = results.iter().filter(|r| **r == Some(Ok(()))).count();
        assert_eq!(ok, connected, "backlog {backlog}: {results:?}");
        if connected == 1 {
            assert!(results.contains(&Some(Err(SockError::ConnectionRefused))));
        }
        let (t, net) = sim.tcp(0);
        let mut accepted = 0;
        while let Some(Accept::Conn(_)) = t.accept(l, net.sockets) {
            accepted += 1;
        }
        assert_eq!(accepted, connected);
        assert_eq!(t.counters.backlog_peak, connected as u64);
        // Backlog 1: the second SYN found no LISTEN socket and drew smoltcp's RST.
        let rsts = sim
            .tcp_segments()
            .iter()
            .filter(|s| s.1 == 0 && s.2 & RST != 0)
            .count();
        assert_eq!(rsts, 2 - connected);
    }
}

#[test]
fn a_dropped_receive_stream_is_shut_rd_never_an_rst() {
    let mut sim = two(&[], 3);
    let l = listen(&mut sim, 0, 2);
    let cl = connect(&mut sim, 1, "10.0.0.1:80");
    sim.run(MS);
    sim.now = MS;
    established(&mut sim, 1, cl);
    let sv = accept(&mut sim, 0, l);
    sim.tcp(0).0.start_send(sv).unwrap();
    // The client stops reading right away (it dropped its receive stream).
    let (t, net) = sim.tcp(1);
    t.start_recv(cl).unwrap();
    t.shutdown_read(cl, net.sockets);
    assert_eq!(t.recv_end(cl, net.sockets), None);
    // The server keeps sending 60 000 bytes, as fast as its buffer drains.
    let mut sent = 0;
    while sent < 60_000 {
        let (t, net) = sim.tcp(0);
        if let Some(Ok(room)) = t.send_room(sv, net.sockets) {
            let n = room.min(6_000).min(60_000 - sent);
            t.send(sv, &vec![b'x'; n], net.sockets).unwrap();
            sent += n;
            sim.kick(0);
        }
        let until = sim.now + MS;
        sim.run(until);
    }
    write(&mut sim, 0, sv, b"", true);
    let until = sim.now + 10 * MS;
    sim.run(until);
    let (t, net) = sim.tcp(1);
    assert_eq!(t.recv_end(cl, net.sockets), Some(Ok(())));
    assert_eq!(t.counters.rx_discarded, 60_000);
    assert!(
        sim.tcp_segments().iter().all(|s| s.2 & RST == 0),
        "no RST, ever"
    );
}

#[test]
fn abort_sends_one_rst_and_both_ends_see_a_reset() {
    let mut sim = two(&[], 4);
    let l = listen(&mut sim, 0, 2);
    let cl = connect(&mut sim, 1, "10.0.0.1:80");
    sim.run(MS);
    sim.now = MS;
    established(&mut sim, 1, cl);
    let sv = accept(&mut sim, 0, l);
    sim.tcp(0).0.start_recv(sv).unwrap();
    let (t, net) = sim.tcp(1);
    t.start_send(cl).unwrap();
    t.start_recv(cl).unwrap();
    assert_eq!(t.send_check(cl, net.sockets), None);
    t.abort(cl, net.sockets);
    t.abort(cl, net.sockets);
    assert_eq!(t.counters.aborts, 1);
    // The aborting side: both directions report a reset.
    assert_eq!(
        t.send_check(cl, net.sockets),
        Some(SockError::ConnectionReset)
    );
    assert_eq!(
        t.send_room(cl, net.sockets),
        Some(Err(SockError::ConnectionReset))
    );
    assert_eq!(
        t.recv_step(cl, net.sockets),
        Some(RecvStep::End(Err(SockError::ConnectionReset)))
    );
    sim.kick(1);
    sim.run(2 * MS);
    let rsts: Vec<Seg> = sim
        .tcp_segments()
        .into_iter()
        .filter(|s| s.2 & RST != 0)
        .collect();
    assert_eq!(rsts.len(), 1, "{rsts:?}");
    assert_eq!(rsts[0].1, 1);
    let (t, net) = sim.tcp(0);
    assert_eq!(
        t.recv_step(sv, net.sockets),
        Some(RecvStep::End(Err(SockError::ConnectionReset)))
    );
}

#[test]
fn a_small_receive_buffer_is_the_window_and_fills_up() {
    let mut sim = two(&[], 5);
    let l = listen(&mut sim, 0, 2);
    let now = sim.now;
    let (t, mut net) = sim.tcp(1);
    let cl = t.create(Family::Ipv4);
    t.set_buffer_size(cl, true, 2048).unwrap();
    t.connect(cl, sa("10.0.0.1:80"), now, &mut net).unwrap();
    sim.kick(1);
    sim.run(MS);
    sim.now = MS;
    established(&mut sim, 1, cl);
    let (t, net) = sim.tcp(1);
    assert_eq!(t.buffer_size(cl, true, net.sockets), Ok(2048));
    let sv = accept(&mut sim, 0, l);
    sim.tcp(0).0.start_send(sv).unwrap();
    write(&mut sim, 0, sv, &[1u8; 10_000], false);
    // Long enough for the delayed ACK (10 ms) that lets Nagle send the window's tail.
    let until = sim.now + 50 * MS;
    sim.run(until);
    // The client reads nothing: one window (2048 bytes) crossed, then the window is zero.
    let data: usize = sim
        .tcp_segments()
        .iter()
        .filter(|s| s.1 == 0)
        .map(|s| s.3)
        .sum();
    assert_eq!(data, 2048);
    assert_eq!(sim.tcp(1).0.counters.rx_window_full, 1);
    sim.tcp(1).0.start_recv(cl).unwrap();
    let (bytes, end) = drain(&mut sim, 1, cl);
    assert_eq!((bytes.len(), end), (2048, None));
    let until = sim.now + 10 * MS;
    sim.run(until);
    let (bytes, _) = drain(&mut sim, 1, cl);
    assert!(!bytes.is_empty(), "the window reopened");
}

#[test]
fn tcp_errors_follow_wasi() {
    let mut sim = two(&[], 6);
    let now = sim.now;
    let (t, mut net) = sim.tcp(1);
    let s = t.create(Family::Ipv4);
    for bad in ["0.0.0.0:80", "10.0.0.1:0", "224.0.0.1:80", "[::1]:80"] {
        assert_eq!(
            t.connect(s, sa(bad), now, &mut net),
            Err(SockError::InvalidArgument),
            "{bad}"
        );
    }
    assert_eq!(
        t.connect(s, sa("192.168.9.9:80"), now, &mut net),
        Err(SockError::RemoteUnreachable)
    );
    assert_eq!(
        t.bind(s, sa("10.0.0.9:80"), &mut net),
        Err(SockError::AddressNotBindable)
    );
    t.bind(s, sa("10.0.0.2:8080"), &mut net).unwrap();
    assert_eq!(
        t.bind(s, sa("10.0.0.2:8081"), &mut net),
        Err(SockError::InvalidState)
    );
    let other = t.create(Family::Ipv4);
    assert_eq!(
        t.bind(other, sa("0.0.0.0:8080"), &mut net),
        Err(SockError::AddressInUse)
    );
    assert_eq!(t.local_address(s), Ok(sa("10.0.0.2:8080")));
    assert_eq!(t.remote_address(s), Err(SockError::InvalidState));
    assert_eq!(t.start_send(s), Err(SockError::InvalidState));
    assert!(!t.is_listening(s));
    // Nobody listens on 10.0.0.1:81: the SYN draws an RST, and the connect is refused.
    let refused = t.create(Family::Ipv4);
    t.connect(refused, sa("10.0.0.1:81"), now, &mut net)
        .unwrap();
    sim.kick(1);
    sim.run(5 * MS);
    let now = sim.now;
    let (t, net) = sim.tcp(1);
    assert_eq!(
        t.connect_poll(refused, now, net.sockets),
        Some(Err(SockError::ConnectionRefused))
    );
    assert_eq!(t.counters.connect_failed, 1);
}

// ---- ICMP errors ----

/// The Internet checksum.
fn csum(data: &[u8]) -> u16 {
    let mut acc: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// An ICMPv4 error from `from` (MAC, IP) to node `to_mac`/`to_ip`, quoting `quote` (an IP
/// packet), as a router would send it.
fn icmp_error_frame(
    from: ([u8; 6], [u8; 4]),
    to: ([u8; 6], [u8; 4]),
    t: u8,
    code: u8,
    quote: &[u8],
) -> Vec<u8> {
    let mut icmp = vec![t, code, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(quote);
    let c = csum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let mut ip = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 1, 0, 0];
    ip[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&from.1);
    ip.extend_from_slice(&to.1);
    let c = csum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&icmp);
    let mut f = to.0.to_vec();
    f.extend_from_slice(&from.0);
    f.extend_from_slice(&[8, 0]);
    f.extend_from_slice(&ip);
    f
}

#[test]
fn an_icmp_unreachable_fails_a_connect_in_syn_sent_like_linux() {
    let mut sim = two(&[], 9);
    // Node 0 connects to 10.0.0.2:80 (nobody listens, but the RST never comes: a "router"
    // answers the SYN with host unreachable first).
    let s = connect(&mut sim, 0, "10.0.0.2:80");
    sim.run(200 * US);
    let syn = sim
        .frames
        .iter()
        .find(|(_, n, f)| *n == 0 && f.get(23) == Some(&6))
        .map(|(_, _, f)| f.clone())
        .expect("the SYN left");
    let total = usize::from(u16::from_be_bytes([syn[16], syn[17]]));
    let quote = syn[14..14 + total].to_vec();
    // Before the error: still connecting.
    let now = sim.now;
    let (t, net) = sim.tcp(0);
    assert_eq!(t.connect_poll(s, now, net.sockets), None);
    // The error arrives first, at 200 us (the real RST would come at 300 us).
    let a = ([2, 0, 0, 0, 0, 1], [10, 0, 0, 1]);
    let r = ([2, 0, 0, 0, 0, 2], [10, 0, 0, 2]);
    sim.nodes[0].receive(icmp_error_frame(r, a, 3, 1, &quote));
    sim.kick(0);
    let received = sim.events(0, "icmp-error-received");
    assert_eq!(received.len(), 1);
    let e = received[0].1;
    assert_eq!(e.get("error"), Some("host-unreachable"));
    assert_eq!(e.get("about"), Some("10.0.0.2:80"));
    assert_eq!(e.get("effect"), Some("connect-failed"));
    let now = sim.now;
    let (t, net) = sim.tcp(0);
    assert_eq!(
        t.connect_poll(s, now, net.sockets),
        Some(Err(SockError::RemoteUnreachable))
    );
    assert_eq!(
        (t.counters.connect_failed, t.counters.connect_unreachable),
        (1, 1)
    );
    // An error addressed to someone else is ignored.
    let other = ([2, 0, 0, 0, 0, 3], [10, 0, 0, 3]);
    sim.nodes[0].receive(icmp_error_frame(r, other, 3, 1, &quote));
    sim.kick(0);
    assert_eq!(sim.events(0, "icmp-error-received").len(), 1);
}

#[test]
fn a_udp_socket_that_asks_for_errors_gets_the_port_unreachable() {
    let mut sim = two(&[], 1);
    let (udp, mut net) = sim.nodes[0].udp();
    let quiet = udp.create(Family::Ipv4);
    let s = udp.create(Family::Ipv4);
    assert_eq!(
        udp.take_error(s),
        Err(SockError::InvalidState),
        "not asked for"
    );
    udp.bind(s, sa("0.0.0.0:0"), &mut net).unwrap();
    udp.set_recv_errors(s, true).unwrap();
    assert_eq!(udp.recv_errors(s), Ok(true));
    assert_eq!(udp.take_error(s), Ok(None));
    udp.send(s, b"probe", Some(sa("10.0.0.2:33434")), &mut net)
        .unwrap();
    udp.send(quiet, b"x", Some(sa("10.0.0.2:33435")), &mut net)
        .unwrap();
    sim.kick(0);
    sim.run(10 * MS);
    let (udp, _) = sim.nodes[0].udp();
    let e = udp.take_error(s).unwrap().expect("queued");
    assert_eq!((e.icmp_type, e.code, e.proto), (3, 3, 17));
    assert_eq!(e.from, "10.0.0.2".parse::<std::net::IpAddr>().unwrap());
    assert_eq!((e.orig_dst, e.dport), ("10.0.0.2".parse().unwrap(), 33434));
    assert_eq!(udp.take_error(s), Ok(None));
    assert_eq!(udp.counters.icmp_errors, 1, "the other socket did not ask");
    let effects: Vec<_> = sim
        .events(0, "icmp-error-received")
        .iter()
        .map(|(_, e)| e.get("effect").unwrap_or_default().to_owned())
        .collect();
    assert_eq!(effects, ["queued", "none"]);
}

// ---- Dual stack: both families on one port (smoltcp issue #7) ----

/// Node 1 binds UDP port 7 on `binds` (in that order); node 0 sends one IPv4 and one IPv6
/// datagram to it. Returns what each of node 1's sockets received.
fn udp_dual(binds: &[&str]) -> Vec<Vec<(Vec<u8>, SocketAddr)>> {
    let mut sim = two(&[], 1);
    let (udp, mut net) = sim.nodes[1].udp();
    let servers: Vec<u32> = binds
        .iter()
        .map(|b| {
            let addr = sa(b);
            let s = udp.create(Family::of(addr.ip()));
            assert_eq!(udp.bind(s, addr, &mut net), Ok(addr), "bind {b}");
            s
        })
        .collect();
    // A second socket of the same family on an overlapping address still conflicts.
    let again = udp.create(Family::Ipv4);
    assert_eq!(
        udp.bind(again, sa("0.0.0.0:7"), &mut net),
        Err(SockError::AddressInUse)
    );
    let (udp, mut net) = sim.nodes[0].udp();
    let v4 = udp.create(Family::Ipv4);
    let v6 = udp.create(Family::Ipv6);
    udp.send(v4, b"four", Some(sa("10.0.0.2:7")), &mut net)
        .unwrap();
    udp.send(v6, b"six", Some(sa("[2001:db8::2]:7")), &mut net)
        .unwrap();
    sim.kick(0);
    sim.run(10 * MS);
    let (udp, mut net) = sim.nodes[1].udp();
    let got = servers
        .iter()
        .map(|&s| {
            let mut all = Vec::new();
            while let Some(d) = udp.receive(s, &mut net).unwrap() {
                all.push(d);
            }
            all
        })
        .collect();
    assert_eq!(udp.counters.rx_filtered, 0);
    got
}

#[test]
fn udp_wildcards_of_both_families_share_a_port() {
    let four = vec![(b"four".to_vec(), sa("10.0.0.1:49152"))];
    // Ephemeral ports count up per node, whatever the family.
    let six = vec![(b"six".to_vec(), sa("[2001:db8::1]:49153"))];
    // Either bind order: smoltcp hands both datagrams to whichever socket comes first.
    assert_eq!(
        udp_dual(&["0.0.0.0:7", "[::]:7"]),
        [four.clone(), six.clone()]
    );
    assert_eq!(
        udp_dual(&["[::]:7", "0.0.0.0:7"]),
        [six.clone(), four.clone()]
    );
    // A specific address of one family beside the other family's wildcard.
    assert_eq!(
        udp_dual(&["[::]:7", "10.0.0.2:7"]),
        [six.clone(), four.clone()]
    );
    assert_eq!(udp_dual(&["0.0.0.0:7", "[2001:db8::2]:7"]), [four, six]);
}

#[test]
fn tcp_listeners_of_both_families_share_a_port() {
    for v6_first in [true, false] {
        let mut sim = two(&[], 3);
        let (t, mut net) = sim.tcp(1);
        let mut listeners = Vec::new();
        let order = if v6_first {
            ["[::]:80", "0.0.0.0:80"]
        } else {
            ["0.0.0.0:80", "[::]:80"]
        };
        for addr in order {
            let addr = sa(addr);
            let l = t.create(Family::of(addr.ip()));
            t.set_no_delay(l, true, net.hop_limit, net.sockets).unwrap();
            t.bind(l, addr, &mut net).unwrap();
            assert_eq!(t.listen(l, &mut net), Ok(addr));
            listeners.push((Family::of(addr.ip()), l));
        }
        let again = t.create(Family::Ipv6);
        assert_eq!(
            t.bind(again, sa("[::]:80"), &mut net),
            Err(SockError::AddressInUse)
        );
        let now = sim.now;
        let (t, mut net) = sim.tcp(0);
        let c4 = t.create(Family::Ipv4);
        t.connect(c4, sa("10.0.0.2:80"), now, &mut net).unwrap();
        let c6 = t.create(Family::Ipv6);
        t.connect(c6, sa("[2001:db8::2]:80"), now, &mut net)
            .unwrap();
        sim.kick(0);
        sim.run(10 * MS);
        established(&mut sim, 0, c4);
        established(&mut sim, 0, c6);
        for (family, l) in listeners {
            let s = accept(&mut sim, 1, l);
            let (t, net) = sim.tcp(1);
            assert_eq!(t.accept(l, net.sockets), None, "one connection each");
            let peer = t.remote_address(s).unwrap();
            assert_eq!(Family::of(peer.ip()), family, "v6_first={v6_first}");
            // The connection carries the options of the listener that owns it.
            assert_eq!(t.options(s).map(|o| o.no_delay), Ok(true));
            t.start_send(s).unwrap();
            write(&mut sim, 1, s, b"hello", true);
        }
        sim.run(20 * MS);
        for c in [c4, c6] {
            sim.tcp(0).0.start_recv(c).unwrap();
            let (got, end) = drain(&mut sim, 0, c);
            assert_eq!((got.as_slice(), end), (&b"hello"[..], Some(Ok(()))));
        }
        // No RST in either family (before #7 the stray connection was reset).
        let rst = sim.frames.iter().filter(|(_, _, f)| match f.get(12..14) {
            Some([8, 0]) => f.get(23) == Some(&6) && f.get(47).is_some_and(|x| x & RST != 0),
            Some([0x86, 0xdd]) => f.get(20) == Some(&6) && f.get(67).is_some_and(|x| x & RST != 0),
            _ => false,
        });
        assert_eq!(rst.count(), 0, "v6_first={v6_first}");
    }
}

// ---- DHCP client and DNS resolver ----

use std::net::{IpAddr, Ipv4Addr};

use wasmnet_wire::dhcp::{self, MessageType, opt};
use wasmnet_wire::dns::{self, rtype};

use crate::names::LookupError;
use crate::resolver::Start;
use crate::udp::SocketId;

/// A DHCP client (node 0) and a static node (node 1, 10.0.0.2) whose test code plays the DHCP
/// and DNS servers through ordinary UDP sockets.
fn dhcp_pair(seed: u64) -> (Sim, SocketId) {
    let client = node(
        &[
            ("mac", "02:00:00:00:00:01"),
            ("ipv4", "dhcp"),
            ("hostname", "alice"),
        ],
        seed,
    );
    let server = node(
        &[("mac", "02:00:00:00:00:02"), ("ipv4", "10.0.0.2/24")],
        seed + 1,
    );
    let mut sim = Sim::new(vec![client, server], 100 * US);
    let (udp, mut net) = sim.nodes[1].udp();
    let s67 = udp.create(Family::Ipv4);
    udp.bind(s67, sa("0.0.0.0:67"), &mut net).unwrap();
    (sim, s67)
}

impl Sim {
    /// The next datagram on node `i`'s socket `s`.
    fn recv(&mut self, i: usize, s: SocketId) -> (Vec<u8>, SocketAddr) {
        let (udp, mut net) = self.nodes[i].udp();
        udp.receive(s, &mut net).unwrap().expect("a datagram")
    }

    fn send(&mut self, i: usize, s: SocketId, data: &[u8], to: &str) {
        let (udp, mut net) = self.nodes[i].udp();
        assert_eq!(udp.send(s, data, Some(sa(to)), &mut net), Ok(Send::Queued));
        self.kick(i);
    }
}

/// The server's answer to `req`: OFFER or ACK of 10.0.0.50 with a 60 s lease.
fn dhcp_reply(req: &dhcp::Message, kind: MessageType) -> Vec<u8> {
    let mut m = dhcp::Message::reply_to(req, kind);
    m.yiaddr = Ipv4Addr::new(10, 0, 0, 50);
    m.set_option(opt::SERVER_ID, &[10, 0, 0, 2]);
    m.set_option(opt::LEASE_TIME, &60u32.to_be_bytes());
    m.set_option(opt::SUBNET_MASK, &[255, 255, 255, 0]);
    m.set_option(opt::ROUTER, &[10, 0, 0, 254]);
    m.set_option(opt::DNS_SERVERS, &[10, 0, 0, 2]);
    m.set_option(opt::DOMAIN_NAME, b"internal");
    m.encode()
}

/// Runs DORA to the end (the client is bound at 400 us).
fn bind(sim: &mut Sim, s67: SocketId) {
    sim.run(100 * US);
    let (bytes, from) = sim.recv(1, s67);
    assert_eq!(from, sa("0.0.0.0:68"), "the DISCOVER comes from 0.0.0.0");
    let discover = dhcp::Message::parse(&bytes).unwrap();
    assert_eq!(discover.message_type(), Some(MessageType::Discover));
    assert_eq!(
        discover.text_option(opt::HOSTNAME).as_deref(),
        Some("alice")
    );
    let offer = dhcp_reply(&discover, MessageType::Offer);
    sim.send(1, s67, &offer, "255.255.255.255:68");
    sim.run(300 * US);
    let request = dhcp::Message::parse(&sim.recv(1, s67).0).unwrap();
    assert_eq!(request.message_type(), Some(MessageType::Request));
    assert_eq!(request.xid, discover.xid);
    assert_eq!(
        request.addr_option(opt::REQUESTED_IP),
        Some(Ipv4Addr::new(10, 0, 0, 50))
    );
    let ack = dhcp_reply(&request, MessageType::Ack);
    sim.send(1, s67, &ack, "255.255.255.255:68");
    sim.run(400 * US);
}

fn counters(s: &Stack) -> BTreeMap<String, u64> {
    s.counters().into_iter().collect()
}

#[test]
fn dhcp_dora_binds_the_address_the_route_and_the_dns_servers() {
    let (mut sim, s67) = dhcp_pair(5);
    assert_eq!(sim.nodes[0].dhcp_lease(), None);
    bind(&mut sim, s67);
    let bound = sim.events(0, "dhcp-bound");
    assert_eq!(bound.len(), 1);
    let (t, e) = bound[0];
    assert_eq!(t, 400 * US);
    assert_eq!(e.get("ip"), Some("10.0.0.50/24"));
    assert_eq!(e.get("router"), Some("10.0.0.254"));
    assert_eq!(e.get("dns"), Some("10.0.0.2"));
    assert_eq!(e.get("server"), Some("10.0.0.2"));
    assert_eq!(e.get("domain"), Some("internal"));
    assert_eq!(e.get("lease-s"), Some("60"));
    assert_eq!(
        sim.nodes[0].dns_servers(),
        vec!["10.0.0.2".parse::<IpAddr>().unwrap()]
    );
    // The broadcast DISCOVER and REQUEST left from 0.0.0.0 (IPv4 source at bytes 26..30).
    let from_zero = sim
        .frames
        .iter()
        .filter(|(_, n, f)| *n == 0 && f.get(12..14) == Some(&[8, 0]))
        .filter(|(_, _, f)| f.get(26..30) == Some(&[0, 0, 0, 0]))
        .count();
    assert_eq!(from_zero, 2);

    // T1 = 30 s after the ACK: the renewal is unicast to the server (after an ARP: broadcasts
    // taught the client nothing), and its ACK renews the lease.
    sim.run(30_001 * MS);
    let (bytes, from) = sim.recv(1, s67);
    assert_eq!(from, sa("10.0.0.50:68"));
    let renew = dhcp::Message::parse(&bytes).unwrap();
    assert_eq!(renew.ciaddr, Ipv4Addr::new(10, 0, 0, 50));
    let ack = dhcp_reply(&renew, MessageType::Ack);
    sim.send(1, s67, &ack, "10.0.0.50:68");
    sim.run(30_002 * MS);
    let renewed = sim.events(0, "dhcp-renewed");
    assert_eq!(renewed.len(), 1);
    assert_eq!(renewed[0].1.get("ip"), Some("10.0.0.50"));
    let c = counters(&sim.nodes[0]);
    assert_eq!(
        (c["dhcp-bound"], c["dhcp-renewed"], c["dhcp-lost"]),
        (1, 1, 0)
    );
}

#[test]
fn a_name_resolves_through_dns_with_the_lease_domain() {
    let (mut sim, s67) = dhcp_pair(5);
    bind(&mut sim, s67);
    let (udp, mut net) = sim.nodes[1].udp();
    let s53 = udp.create(Family::Ipv4);
    udp.bind(s53, sa("0.0.0.0:53"), &mut net).unwrap();

    let t0 = MS;
    sim.run(t0);
    sim.now = t0;
    // `web` has no dot: the lease's domain makes it `web.internal`. IPv4 only: one A query.
    let (start, _) = sim.nodes[0].lookup_start("web", t0);
    let Start::Pending(id) = start else {
        panic!("{start:?}")
    };
    sim.kick(0);
    // The client resolves the server's MAC first (ARP), then the query arrives.
    sim.run(t0 + 300 * US);
    let (bytes, from) = sim.recv(1, s53);
    assert!(from.port() >= 49_152, "a random source port: {from}");
    let q = dns::Message::parse(&bytes).unwrap();
    assert_eq!(q.questions[0].name, "web.internal");
    assert_eq!(q.questions[0].qtype, rtype::A);
    let mut r = dns::Message::response_to(&q, dns::rcode::NOERROR);
    r.answers.push(dns::Record {
        name: "web.internal".into(),
        rtype: rtype::A,
        class: dns::CLASS_IN,
        ttl: 60,
        data: dns::RData::A(Ipv4Addr::new(10, 0, 0, 80)),
    });
    sim.send(1, s53, &r.encode(), &from.to_string());
    sim.run(t0 + 400 * US);
    assert_eq!(
        sim.nodes[0].lookup_take(id),
        Some(Ok(vec!["10.0.0.80".parse().unwrap()]))
    );
    let resolved = sim.events(0, "name-resolved");
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].1.get("addresses"), Some("10.0.0.80"));
    assert_eq!(resolved[0].1.get("after-ns"), Some("400000"));
    let queries = sim.events(0, "dns-query");
    assert_eq!(queries[0].1.get("id"), Some(r.id.to_string().as_str()));

    // NXDOMAIN is name-unresolvable.
    let t1 = 2 * MS;
    sim.run(t1);
    sim.now = t1;
    let Start::Pending(id) = sim.nodes[0].lookup_start("nope.internal", t1).0 else {
        panic!()
    };
    sim.kick(0);
    sim.run(t1 + 100 * US);
    let (bytes, from) = sim.recv(1, s53);
    let q = dns::Message::parse(&bytes).unwrap();
    let r = dns::Message::response_to(&q, dns::rcode::NXDOMAIN);
    sim.send(1, s53, &r.encode(), &from.to_string());
    sim.run(t1 + 200 * US);
    assert_eq!(
        sim.nodes[0].lookup_take(id),
        Some(Err(LookupError::NameUnresolvable))
    );
}

#[test]
fn a_port_unreachable_fails_the_lookup_after_one_round_trip() {
    // Node 1 runs no DNS server: its stack answers the query with an ICMP port unreachable.
    let client = node(&a(&[("dns", "10.0.0.2")]), 3);
    let mut sim = Sim::new(vec![client, node(&b(), 4)], 100 * US);
    sim.run(MS);
    sim.now = MS;
    let Start::Pending(id) = sim.nodes[0].lookup_start("web.internal", MS).0 else {
        panic!()
    };
    sim.kick(0);
    sim.run(1_500 * MS);
    // A + AAAA (node 0 has a global IPv6 address) after the ARP; both draw an error.
    assert_eq!(
        sim.nodes[0].lookup_take(id),
        Some(Err(LookupError::NameUnresolvable))
    );
    let failed = sim.events(0, "name-lookup-failed");
    assert_eq!(failed.len(), 1);
    assert_eq!(
        failed[0].1.get("after-ns"),
        Some("400000"),
        "ARP + one round trip, not 2 x 5 s"
    );
    assert_eq!(sim.events(0, "dns-query").len(), 2);
    assert!(!sim.events(0, "dns-error").is_empty());
    let c = counters(&sim.nodes[0]);
    assert_eq!((c["dns-timeouts"], c["dns-failed"]), (0, 1));
}

#[test]
fn a_silent_server_times_out_after_every_attempt() {
    let client = node(
        &a(&[
            ("dns", "10.0.0.2"),
            ("resolver.timeout", "100ms"),
            ("resolver.attempts", "3"),
        ]),
        3,
    );
    let mut sim = Sim::new(vec![client, node(&b(), 4)], 100 * US);
    // A bound socket that never answers.
    let (udp, mut net) = sim.nodes[1].udp();
    let s53 = udp.create(Family::Ipv4);
    udp.bind(s53, sa("0.0.0.0:53"), &mut net).unwrap();
    let Start::Pending(id) = sim.nodes[0].lookup_start("web.internal", 0).0 else {
        panic!()
    };
    sim.kick(0);
    sim.run(2_000 * MS);
    assert_eq!(
        sim.nodes[0].lookup_take(id),
        Some(Err(LookupError::TemporaryFailure))
    );
    let failed = sim.events(0, "name-lookup-failed");
    assert_eq!(failed[0].0, 300 * MS, "three tries of 100 ms");
    let ids: std::collections::BTreeSet<String> = sim
        .events(0, "dns-query")
        .iter()
        .map(|(_, e)| e.get("id").unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 6, "fresh ids on every try (A and AAAA)");
    assert_eq!(sim.nodes[0].lookup_take(id), None, "taken once");
}

// ---- multicast and mDNS ----

/// `(time, sender, ip-proto, ttl, dst)` of every IPv4 frame on the hub.
fn v4_frames(sim: &Sim) -> Vec<(u64, usize, u8, u8, Ipv4Addr)> {
    sim.frames
        .iter()
        .filter(|(_, _, f)| f.get(12..14) == Some(&[8, 0]))
        .map(|(t, n, f)| {
            let d: [u8; 4] = f[30..34].try_into().unwrap();
            (*t, *n, f[23], f[22], Ipv4Addr::from(d))
        })
        .collect()
}

#[test]
fn a_join_reports_the_group_and_a_datagram_to_it_is_received() {
    let mut sim = two(&[], 1);
    let group: IpAddr = "224.0.0.251".parse().unwrap();
    let (udp, mut net) = sim.nodes[1].udp();
    let s = udp.create(Family::Ipv4);
    udp.bind(s, sa("0.0.0.0:5353"), &mut net).unwrap();
    udp.join(s, group, 0).unwrap();
    assert_eq!(udp.join(s, group, 0), Err(SockError::AddressInUse));
    assert_eq!(
        udp.join(s, "10.0.0.1".parse().unwrap(), 0),
        Err(SockError::InvalidArgument)
    );
    assert_eq!(
        udp.join(s, "ff02::fb".parse().unwrap(), 0),
        Err(SockError::InvalidArgument),
        "a group of the other family"
    );
    assert_eq!(
        udp.join(s, "224.0.0.252".parse().unwrap(), 7),
        Err(SockError::InvalidArgument)
    );
    sim.kick(1);
    sim.run(MS);
    // The IGMPv2 membership report (type 0x16) to the group itself, TTL 1, at once.
    let igmp: Vec<_> = v4_frames(&sim)
        .into_iter()
        .filter(|f| f.1 == 1 && f.2 == 2)
        .collect();
    assert_eq!(igmp.len(), 1);
    assert_eq!(
        (igmp[0].0, igmp[0].3, igmp[0].4),
        (0, 1, Ipv4Addr::new(224, 0, 0, 251))
    );
    assert_eq!(sim.events(1, "multicast-joined").len(), 1);

    // Node 0 sends to the group (no membership needed): node 1's socket gets it.
    let (udp, mut net) = sim.nodes[0].udp();
    let c = udp.create(Family::Ipv4);
    udp.set_multicast_hop_limit(c, 255).unwrap();
    assert_eq!(
        udp.send(c, b"hi", Some(sa("224.0.0.251:5353")), &mut net),
        Ok(Send::Queued)
    );
    sim.kick(0);
    sim.run(2 * MS);
    let got = sim.recv(1, s);
    assert_eq!(got, (b"hi".to_vec(), sa("10.0.0.1:49152")));
    let sent: Vec<_> = v4_frames(&sim)
        .into_iter()
        .filter(|f| f.1 == 0 && f.2 == 17)
        .collect();
    assert_eq!(sent.len(), 1, "no ARP for a group: one frame");
    assert_eq!(sent[0].3, 255, "the multicast hop limit");

    // Leaving: an IGMPv2 leave to all-routers (224.0.0.2).
    let (udp, _) = sim.nodes[1].udp();
    udp.leave(s, group, 0).unwrap();
    assert_eq!(udp.leave(s, group, 0), Err(SockError::InvalidArgument));
    sim.kick(1);
    sim.run(3 * MS);
    let leave: Vec<_> = v4_frames(&sim)
        .into_iter()
        .filter(|f| f.1 == 1 && f.2 == 2 && f.4 == Ipv4Addr::new(224, 0, 0, 2))
        .collect();
    assert_eq!(leave.len(), 1);
    assert_eq!(sim.events(1, "multicast-left").len(), 1);
    let c = counters(&sim.nodes[1]);
    assert_eq!(
        (
            c["multicast-joins"],
            c["multicast-leaves"],
            c["multicast-groups"]
        ),
        (1, 1, 0)
    );
}

#[test]
fn each_datagram_leaves_with_its_own_hop_limit() {
    let mut sim = two(&[], 1);
    let (udp, mut net) = sim.nodes[0].udp();
    let s = udp.create(Family::Ipv4);
    udp.set_unicast_hop_limit(s, 7, &mut net).unwrap();
    udp.set_multicast_hop_limit(s, 255).unwrap();
    // A unicast datagram waits for ARP; a datagram to a group queued behind it must not take
    // its hop limit from it (smoltcp keeps one per socket): it waits until the queue drained.
    assert_eq!(
        udp.send(s, b"one", Some(sa("10.0.0.2:9")), &mut net),
        Ok(Send::Queued)
    );
    assert_eq!(
        udp.send(s, b"two", Some(sa("224.0.0.9:9")), &mut net),
        Ok(Send::WouldBlock)
    );
    assert_eq!(udp.counters.hop_limit_waits, 1);
    sim.kick(0);
    sim.run(MS);
    let (udp, mut net) = sim.nodes[0].udp();
    assert_eq!(
        udp.send(s, b"two", Some(sa("224.0.0.9:9")), &mut net),
        Ok(Send::Queued)
    );
    sim.kick(0);
    sim.run(2 * MS);
    let ttls: Vec<(u8, Ipv4Addr)> = v4_frames(&sim)
        .into_iter()
        .filter(|f| f.1 == 0 && f.2 == 17)
        .map(|f| (f.3, f.4))
        .collect();
    assert_eq!(
        ttls,
        [
            (7, Ipv4Addr::new(10, 0, 0, 2)),
            (255, Ipv4Addr::new(224, 0, 0, 9))
        ]
    );
}

#[test]
fn multicast_loopback_delivers_to_the_node_itself_unless_turned_off() {
    let mut sim = two(&[], 1);
    let group: IpAddr = "224.0.0.251".parse().unwrap();
    let (udp, mut net) = sim.nodes[0].udp();
    let s = udp.create(Family::Ipv4);
    udp.bind(s, sa("0.0.0.0:5353"), &mut net).unwrap();
    udp.join(s, group, 1).unwrap();
    assert_eq!(udp.multicast_loopback(s), Ok(true));
    assert_eq!(
        udp.send(s, b"me too", Some(sa("224.0.0.251:5353")), &mut net),
        Ok(Send::Queued)
    );
    sim.kick(0);
    sim.run(MS);
    assert_eq!(sim.recv(0, s), (b"me too".to_vec(), sa("10.0.0.1:5353")));
    let (udp, mut net) = sim.nodes[0].udp();
    udp.set_multicast_loopback(s, false).unwrap();
    assert_eq!(
        udp.send(s, b"not me", Some(sa("224.0.0.251:5353")), &mut net),
        Ok(Send::Queued)
    );
    sim.kick(0);
    sim.run(2 * MS);
    let (udp, mut net) = sim.nodes[0].udp();
    assert_eq!(udp.receive(s, &mut net), Ok(None));
    assert_eq!(udp.counters.multicast_looped, 1);
    // Both datagrams were on the wire once each; the loop-back copy never was.
    let on_wire = v4_frames(&sim)
        .into_iter()
        .filter(|f| f.1 == 0 && f.2 == 17)
        .count();
    assert_eq!(on_wire, 2);
}

#[test]
fn the_interface_lists_its_addresses() {
    let s = node(&a(&[]), 1);
    let i = s.interface();
    assert_eq!((i.index, i.name.as_str(), i.mtu), (1, "eth0", 1500));
    let addrs: Vec<String> = i
        .addresses
        .iter()
        .map(|(a, p)| format!("{a}/{p}"))
        .collect();
    assert_eq!(
        addrs,
        ["10.0.0.1/24", "fe80::ff:fe00:1/64", "2001:db8::1/64"]
    );
}

#[test]
fn a_local_name_resolves_with_a_one_shot_mdns_query() {
    let mut sim = two(&[], 1);
    let (udp, mut net) = sim.nodes[1].udp();
    let s = udp.create(Family::Ipv4);
    udp.bind(s, sa("0.0.0.0:5353"), &mut net).unwrap();
    udp.join(s, "224.0.0.251".parse().unwrap(), 0).unwrap();
    sim.kick(1);
    sim.run(MS);
    sim.now = MS;
    // No DNS server configured: `.local` still goes to mDNS. Node 0 has IPv4 and a global IPv6
    // address, so it asks for A and AAAA.
    let (start, _) = sim.nodes[0].lookup_start("Node1.local.", MS);
    let Start::Pending(id) = start else {
        panic!("{start:?}")
    };
    sim.kick(0);
    sim.run(MS + 100 * US);
    let (q1, from) = sim.recv(1, s);
    let (q2, _) = sim.recv(1, s);
    assert!(
        from.port() >= 49_152,
        "a one-shot query comes from an ephemeral port"
    );
    let q1 = dns::Message::parse(&q1).unwrap();
    let q2 = dns::Message::parse(&q2).unwrap();
    assert_eq!(q1.questions[0].name, "node1.local");
    assert_eq!(
        (q1.questions[0].qtype, q2.questions[0].qtype),
        (rtype::A, rtype::AAAA)
    );
    let mcast: Vec<_> = v4_frames(&sim)
        .into_iter()
        .filter(|f| f.1 == 0 && f.2 == 17)
        .collect();
    assert_eq!(mcast.len(), 2);
    assert!(mcast.iter().all(|f| f.3 == 255 && f.4 == dns::MDNS_V4));
    // The responder answers a legacy (port != 5353) query by unicast, id and question copied.
    for (q, data) in [
        (&q1, dns::RData::A(Ipv4Addr::new(10, 0, 0, 2))),
        (&q2, dns::RData::Aaaa("2001:db8::2".parse().unwrap())),
    ] {
        let mut r = dns::Message::response_to(q, dns::rcode::NOERROR);
        r.answers.push(dns::Record {
            name: "node1.local".into(),
            rtype: q.questions[0].qtype,
            class: dns::CLASS_IN,
            ttl: 10,
            data,
        });
        let (udp, mut net) = sim.nodes[1].udp();
        udp.send(s, &r.encode(), Some(from), &mut net).unwrap();
    }
    sim.kick(1);
    // Node 1 learns node 0's MAC first (multicast taught it nothing): ARP, then the answers.
    sim.run(MS + 400 * US);
    assert_eq!(
        sim.nodes[0].lookup_take(id),
        Some(Ok(vec![
            "2001:db8::2".parse().unwrap(),
            "10.0.0.2".parse().unwrap()
        ]))
    );

    // Nobody has `ghost.local`: three tries a second apart, then name-unresolvable.
    let t = 10 * MS;
    sim.run(t);
    sim.now = t;
    let Start::Pending(id) = sim.nodes[0].lookup_start("ghost.local", t).0 else {
        panic!()
    };
    sim.kick(0);
    sim.run(t + 5_000 * MS);
    assert_eq!(
        sim.nodes[0].lookup_take(id),
        Some(Err(LookupError::NameUnresolvable))
    );
    let failed = sim.events(0, "name-lookup-failed");
    assert_eq!(failed.last().unwrap().0, t + 3_000 * MS);
}

// ---- ICMP echo sockets ----

fn ip(s: &str) -> IpAddr {
    s.parse().expect("ip address")
}

/// An echo request as an app writes it: identifier 0xffff (the stack overwrites it), no
/// checksum, `seq`, and `payload`.
fn echo_request(v6: bool, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut m = vec![if v6 { 128 } else { 8 }, 0, 0, 0, 0xff, 0xff];
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(payload);
    m
}

impl Sim {
    fn icmp(&mut self, i: usize) -> (&mut crate::icmp::IcmpSockets, crate::udp::Net<'_>) {
        self.nodes[i].icmp()
    }

    /// The echo requests and replies node `from` sent (either family), with their times.
    fn icmp_frames(&self, from: usize) -> Vec<(u64, Vec<u8>)> {
        self.frames
            .iter()
            .filter(|(_, n, f)| {
                let v4 = f.get(12..14) == Some(&[8, 0]) && f.get(23) == Some(&1);
                let v6 = f.get(12..14) == Some(&[0x86, 0xdd])
                    && f.get(20) == Some(&58)
                    && matches!(f.get(54), Some(128 | 129));
                *n == from && (v4 || v6)
            })
            .map(|(t, _, f)| (*t, f.clone()))
            .collect()
    }
}

#[test]
fn an_icmp_socket_pings_both_families_with_identifiers_the_stack_picks() {
    let mut sim = two(&[], 1);
    let (t, mut net) = sim.icmp(0);
    let v4 = t.create(Family::Ipv4);
    let v6 = t.create(Family::Ipv6);
    assert_eq!(
        t.identifier(v4),
        Err(SockError::InvalidState),
        "not bound yet"
    );
    // The rover starts at the node's seeded identifier (0x4200 + seed in these tests).
    assert_eq!(t.bind(v4, ip("0.0.0.0"), 0, &mut net), Ok(0x4201));
    let payload: Vec<u8> = (0..56).collect();
    let req = echo_request(false, 1, &payload);
    assert_eq!(
        t.send(v4, &req, Some(ip("10.0.0.2")), &mut net),
        Ok(Send::Queued)
    );
    // An unbound socket binds on its first send, with the next identifier.
    let req6 = echo_request(true, 7, &payload);
    assert_eq!(
        t.send(v6, &req6, Some(ip("2001:db8::2")), &mut net),
        Ok(Send::Queued)
    );
    assert_eq!(t.identifier(v6), Ok(0x4202));
    assert_eq!(t.local_address(v6), Ok(ip("::")));
    sim.kick(0);
    sim.run(10 * MS);
    let (t, mut net) = sim.icmp(0);
    let (reply, from) = t.receive(v4, &mut net).unwrap().expect("v4 reply");
    assert_eq!(from, ip("10.0.0.2"));
    assert_eq!(reply[0], 0, "an echo reply");
    assert_eq!(
        &reply[4..8],
        &[0x42, 0x01, 0, 1],
        "our identifier, the app's sequence"
    );
    assert_eq!(&reply[8..], &payload[..]);
    assert_eq!(t.receive(v4, &mut net), Ok(None));
    let (reply, from) = t.receive(v6, &mut net).unwrap().expect("v6 reply");
    assert_eq!(from, ip("2001:db8::2"));
    assert_eq!((reply[0], &reply[4..8]), (129, &[0x42, 0x02, 0, 7][..]));
    assert_eq!(t.receive(v6, &mut net), Ok(None));
    assert_eq!((t.counters.requests, t.counters.replies), (2, 2));
    // The requests on the wire carry the stack's identifier and a checksum the peer accepted
    // (smoltcp answers only valid requests).
    let sent = sim.icmp_frames(0);
    assert_eq!(sent.len(), 2);
    assert_eq!(&sent[0].1[14 + 20 + 4..14 + 20 + 8], &[0x42, 0x01, 0, 1]);
    // The debug API lists them by id (inspection's `icmp:<id>`).
    let ids: Vec<u32> = sim.nodes[0].icmp_sockets().iter().map(|s| s.id).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&1));
    assert!(!ids.contains(&9));
    // Dropping a socket frees its identifier; the rover moves on regardless.
    let (t, mut net) = sim.icmp(0);
    t.close(v4, net.sockets);
    let again = t.create(Family::Ipv4);
    assert_eq!(t.bind(again, ip("10.0.0.1"), 0, &mut net), Ok(0x4203));
    assert_eq!(t.open(), 2);
}

#[test]
fn icmp_socket_errors_follow_linux() {
    let mut sim = two(&[], 2);
    let (t, mut net) = sim.icmp(0);
    let s = t.create(Family::Ipv4);
    let other = t.create(Family::Ipv6);
    let ok = echo_request(false, 1, b"x");
    assert_eq!(
        t.receive(s, &mut net),
        Err(SockError::InvalidState),
        "unbound"
    );
    // Explicit identifiers conflict within a family only.
    assert_eq!(t.bind(s, ip("0.0.0.0"), 77, &mut net), Ok(77));
    assert_eq!(
        t.bind(s, ip("0.0.0.0"), 78, &mut net),
        Err(SockError::InvalidState)
    );
    let s2 = t.create(Family::Ipv4);
    assert_eq!(
        t.bind(s2, ip("0.0.0.0"), 77, &mut net),
        Err(SockError::AddressInUse)
    );
    assert_eq!(t.bind(other, ip("::"), 77, &mut net), Ok(77));
    assert_eq!(
        t.bind(s2, ip("10.0.0.9"), 0, &mut net),
        Err(SockError::AddressNotBindable)
    );
    assert_eq!(
        t.bind(s2, ip("::"), 0, &mut net),
        Err(SockError::InvalidArgument)
    );
    let invalid = [
        vec![8, 0, 0, 0, 0, 0, 0],    // shorter than a header
        vec![0, 0, 0, 0, 0, 0, 0, 1], // an echo reply
        vec![8, 1, 0, 0, 0, 0, 0, 1], // code 1
        echo_request(true, 1, b""),   // the other family's request
    ];
    for m in invalid {
        assert_eq!(
            t.send(s, &m, Some(ip("10.0.0.2")), &mut net),
            Err(SockError::InvalidArgument)
        );
    }
    assert_eq!(
        t.send(s, &ok, None, &mut net),
        Err(SockError::InvalidArgument),
        "no destination"
    );
    assert_eq!(
        t.send(s, &ok, Some(ip("2001:db8::2")), &mut net),
        Err(SockError::InvalidArgument)
    );
    assert_eq!(
        t.send(s, &ok, Some(ip("192.168.1.1")), &mut net),
        Err(SockError::RemoteUnreachable),
        "no gateway"
    );
    let big = echo_request(false, 1, &[0; 1500 - 20 - 8 + 1]);
    assert_eq!(
        t.send(s, &big, Some(ip("10.0.0.2")), &mut net),
        Err(SockError::DatagramTooLarge)
    );
    let fits = echo_request(false, 1, &[0; 1500 - 20 - 8]);
    assert_eq!(
        t.send(s, &fits, Some(ip("10.0.0.2")), &mut net),
        Ok(Send::Queued)
    );
    assert_eq!(
        t.set_unicast_hop_limit(s, 0),
        Err(SockError::InvalidArgument)
    );
    assert_eq!(t.disconnect(s), Err(SockError::InvalidState));
    assert_eq!(
        t.connect(s, ip("0.0.0.0"), &mut net),
        Err(SockError::InvalidArgument)
    );
    assert_eq!(
        t.take_error(s),
        Err(SockError::InvalidState),
        "errors not asked for"
    );
}

#[test]
fn a_connected_icmp_socket_uses_its_peer_and_its_hop_limit() {
    let mut sim = two(&[], 3);
    let (t, mut net) = sim.icmp(0);
    let s = t.create(Family::Ipv4);
    t.connect(s, ip("10.0.0.2"), &mut net).unwrap();
    assert_eq!(t.remote_address(s), Ok(ip("10.0.0.2")));
    assert_eq!(t.unicast_hop_limit(s, net.hop_limit), Ok(64));
    t.set_unicast_hop_limit(s, 3).unwrap();
    let first = echo_request(false, 1, b"hi");
    assert_eq!(t.send(s, &first, None, &mut net), Ok(Send::Queued));
    // A different hop limit waits for the queued request to leave (smoltcp #9).
    t.set_unicast_hop_limit(s, 4).unwrap();
    let second = echo_request(false, 2, b"hi");
    assert_eq!(t.send(s, &second, None, &mut net), Ok(Send::WouldBlock));
    sim.kick(0);
    sim.run(MS);
    let (t, mut net) = sim.icmp(0);
    assert_eq!(t.send(s, &second, None, &mut net), Ok(Send::Queued));
    sim.kick(0);
    sim.run(10 * MS);
    let ttls: Vec<u8> = sim.icmp_frames(0).iter().map(|(_, f)| f[22]).collect();
    assert_eq!(ttls, [3, 4]);
    let (t, mut net) = sim.icmp(0);
    assert!(t.receive(s, &mut net).unwrap().is_some());
    assert!(t.receive(s, &mut net).unwrap().is_some());
    assert_eq!(t.counters.would_block, 1);
}

#[test]
fn an_icmp_socket_that_asks_for_errors_gets_them_with_the_sequence_number() {
    let mut sim = two(&[], 4);
    let (t, mut net) = sim.icmp(0);
    let s = t.create(Family::Ipv4);
    let quiet = t.create(Family::Ipv4);
    t.bind(s, ip("0.0.0.0"), 0, &mut net).unwrap();
    t.set_recv_errors(s, true).unwrap();
    assert_eq!(t.recv_errors(s), Ok(true));
    let (five, six) = (echo_request(false, 5, b"x"), echo_request(false, 6, b"x"));
    t.send(s, &five, Some(ip("10.0.0.2")), &mut net).unwrap();
    t.send(quiet, &six, Some(ip("10.0.0.2")), &mut net).unwrap();
    sim.kick(0);
    sim.run(200 * US);
    let requests = sim.icmp_frames(0);
    assert_eq!(requests.len(), 2);
    // A "router" reports both requests' destination unreachable.
    let a = ([2, 0, 0, 0, 0, 1], [10, 0, 0, 1]);
    let r = ([2, 0, 0, 0, 0, 2], [10, 0, 0, 2]);
    for (_, f) in &requests {
        let quote = f[14..14 + 20 + 8].to_vec();
        sim.nodes[0].receive(icmp_error_frame(r, a, 3, 1, &quote));
    }
    sim.kick(0);
    let (t, _) = sim.icmp(0);
    let e = t.take_error(s).unwrap().expect("queued");
    assert_eq!((e.icmp_type, e.code, e.proto, e.dport), (3, 1, 1, 5));
    assert_eq!((e.from, e.orig_dst), (ip("10.0.0.2"), ip("10.0.0.2")));
    assert_eq!(t.take_error(s), Ok(None));
    assert_eq!(t.counters.errors_queued, 1, "the quiet socket did not ask");
    let effects: Vec<_> = sim
        .events(0, "icmp-error-received")
        .iter()
        .map(|(_, e)| e.get("effect").unwrap_or_default().to_owned())
        .collect();
    assert_eq!(effects, ["queued", "none"]);
    let (t, _) = sim.icmp(0);
    t.set_recv_errors(s, false).unwrap();
    assert_eq!(t.take_error(s), Err(SockError::InvalidState));
}

// ---- Quiescent snapshots ----

/// Builds the two-node world, makes the server's state non-trivial (sockets created, a refused
/// connect fills both neighbor caches and draws from smoltcp's generator, MLD reports go out),
/// and runs it to `at`. The same calls in the same order give the same world every time.
fn snapshot_world(at: u64) -> (Sim, u32, u32) {
    let mut sim = two(&[], 11);
    let l4 = listen(&mut sim, 0, 3);
    let (t, mut net) = sim.tcp(0);
    let l6 = t.create(Family::Ipv6);
    t.bind(l6, sa("[::]:80"), &mut net).unwrap();
    t.listen(l6, &mut net).unwrap();
    // An idle socket that never binds, and a bound one.
    let _idle = t.create(Family::Ipv4);
    let bound = t.create(Family::Ipv4);
    t.bind(bound, sa("10.0.0.1:8080"), &mut net).unwrap();
    let (u, mut net) = sim.nodes[0].udp();
    let dns = u.create(Family::Ipv4);
    u.bind(dns, sa("0.0.0.0:53"), &mut net).unwrap();
    sim.kick(0);
    // A connect to a closed port: ARP both ways, a SYN, an RST.
    let refused = connect(&mut sim, 1, "10.0.0.1:81");
    sim.run(at);
    let (t, net) = sim.tcp(1);
    assert!(matches!(
        t.connect_poll(refused, at, net.sockets),
        Some(Err(_))
    ));
    sim.now = at;
    (sim, l4, l6)
}

/// From `at` on: a client connects to the server over IPv4, sends a request, gets the
/// response, and both close. Returns the server's frames `(time, bytes)` after `at`.
fn snapshot_script(sim: &mut Sim, l4: u32, at: u64) -> Vec<(u64, Vec<u8>)> {
    let cl = connect(sim, 1, "10.0.0.1:80");
    sim.run(at + MS);
    sim.now = at + MS;
    established(sim, 1, cl);
    let sv = accept(sim, 0, l4);
    sim.tcp(1).0.start_send(cl).unwrap();
    write(sim, 1, cl, b"GET / HTTP/1.1\r\n\r\n", true);
    sim.run(at + 2 * MS);
    sim.now = at + 2 * MS;
    sim.tcp(0).0.start_recv(sv).unwrap();
    let (req, _) = drain(sim, 0, sv);
    assert_eq!(req, b"GET / HTTP/1.1\r\n\r\n");
    sim.tcp(0).0.start_send(sv).unwrap();
    write(sim, 0, sv, b"HTTP/1.1 200 OK\r\n\r\n", true);
    sim.run(at + 200 * MS);
    sim.frames
        .iter()
        .filter(|(t, n, _)| *n == 0 && *t > at)
        .map(|(t, _, f)| (*t, f.clone()))
        .collect()
}

#[test]
fn a_quiescent_server_restores_onto_a_fresh_stack_and_sends_the_same_frames() {
    const AT: u64 = 5 * MS;
    // The original: saved at AT, then the script.
    let (mut sim, l4, _) = snapshot_world(AT);
    let state = sim.nodes[0].save().expect("quiescent");
    let wake = sim.nodes[0].next_wakeup(AT);
    let original = snapshot_script(&mut sim, l4, AT);
    // SYN-ACK, then the response with our FIN (the ACK of the request rides on it).
    assert!(original.len() >= 2, "{}", original.len());

    // The same world, its server replaced at AT by a fresh stack (another seed: nothing of the
    // old generator survives but what the state carries) with the state restored.
    let (mut sim, l4, l6) = snapshot_world(AT);
    let config = Config::from_pairs(a(&[]).iter().copied()).unwrap();
    let mut fresh = Stack::new(&config, config.mac.unwrap(), 999, 0x4200 + 11, AT);
    fresh.restore(&state).expect("restore");
    assert_eq!(
        fresh.save().expect("round trip"),
        state,
        "save(restore(s)) == s"
    );
    assert_eq!(fresh.next_wakeup(AT), wake);
    assert_eq!(fresh.tcp().0.listeners(), [l4, l6]);
    sim.nodes[0] = fresh;
    sim.wake[0] = None;
    if let Some(t) = wake {
        sim.wake[0] = Some(t);
        sim.push(t, Ev::Wake(0));
    }
    let restored = snapshot_script(&mut sim, l4, AT);
    assert_eq!(restored, original);
}

#[test]
fn a_snapshot_is_refused_while_a_connection_is_open_or_onto_a_used_stack() {
    const AT: u64 = 5 * MS;
    let (mut sim, l4, _) = snapshot_world(AT);
    let state = sim.nodes[0].save().expect("quiescent");
    let cl = connect(&mut sim, 1, "10.0.0.1:80");
    sim.run(AT + MS);
    let err = sim.nodes[0].save().expect_err("a connection is queued");
    assert!(err.contains("queued"), "{err}");
    sim.now = AT + MS;
    established(&mut sim, 1, cl);
    let _ = accept(&mut sim, 0, l4);
    let err = sim.nodes[0].save().expect_err("a connection is open");
    assert!(err.contains("connected"), "{err}");
    // A used stack (it has sockets) refuses a state; another node's config too.
    let err = sim.nodes[0].restore(&state).expect_err("not fresh");
    assert!(err.contains("MAC") || err.contains("fresh"), "{err}");
    let config = Config::from_pairs(b().iter().copied()).unwrap();
    let mut other = Stack::new(&config, config.mac.unwrap(), 1, 1, AT);
    let err = other.restore(&state).expect_err("another node");
    assert!(err.contains("MAC"), "{err}");
    assert!(other.restore(b"garbage").is_err());
    assert!(other.restore(&state[..state.len() / 2]).is_err());
}

#[test]
fn receive_datagram_reports_the_hop_limit_each_reply_arrived_with() {
    // The peer's smoltcp answers with its default hop limit, 64, in both families; the stack
    // reads it off each reply's frame.
    let mut sim = two(&[], 1);
    let v4 = sim.ping_socket(0, false);
    let v6 = sim.ping_socket(0, true);
    sim.echo_at(0, 0, v4, 1, 8, "10.0.0.2");
    sim.echo_at(0, 0, v6, 1, 8, "2001:db8::2");
    sim.run(10_000 * MS);
    let (t, mut net) = sim.icmp(0);
    let (_, from, hop) = t.receive_datagram(v4, &mut net).unwrap().expect("v4 reply");
    assert_eq!((from, hop), (ip("10.0.0.2"), Some(64)));
    let (_, _, hop) = t.receive_datagram(v6, &mut net).unwrap().expect("v6 reply");
    assert_eq!(hop, Some(64));
    assert_eq!(t.receive_datagram(v4, &mut net), Ok(None));
    // A reply that crossed routers says so: one forged with TTL 61 (ident and seq of a request
    // the socket sent, a valid checksum) reports 61.
    let ident = t.identifier(v4).unwrap();
    assert_eq!(
        t.send(
            v4,
            &echo_request(false, 2, b"x"),
            Some(ip("10.0.0.2")),
            &mut net
        ),
        Ok(Send::Queued)
    );
    let mut icmp = vec![0, 0, 0, 0];
    icmp.extend_from_slice(&ident.to_be_bytes());
    icmp.extend_from_slice(&[0, 2, b'x']);
    let c = csum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let mut ipv4 = vec![
        0x45, 0, 0, 0, 0, 1, 0, 0, 61, 1, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1,
    ];
    ipv4[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    let c = csum(&ipv4);
    ipv4[10..12].copy_from_slice(&c.to_be_bytes());
    ipv4.extend_from_slice(&icmp);
    let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 8, 0];
    frame.extend_from_slice(&ipv4);
    sim.nodes[0].receive(frame);
    sim.kick(0);
    let (t, mut net) = sim.icmp(0);
    let got: Vec<Option<u8>> = std::iter::from_fn(|| t.receive_datagram(v4, &mut net).unwrap())
        .map(|(_, _, hop)| hop)
        .collect();
    assert!(got.contains(&Some(61)), "{got:?}");
    // Closing the sockets forgets whatever was noted for them: a quiescent stack keeps nothing.
    t.close(v4, net.sockets);
    t.close(v6, net.sockets);
    assert!(t.is_empty());
}

#[test]
fn the_neighbor_table_is_bounded_and_evicts_the_oldest() {
    use crate::stack::MAX_TABLE;
    let mut s = node(&[("mac", "02:00:00:00:00:01"), ("ipv4", "10.0.0.1/8")], 1);
    // ARP requests for our address from MAX_TABLE + 5 senders, one per nanosecond.
    let sender = |i: usize| [10, 1, (i >> 8) as u8, i as u8];
    for i in 0..MAX_TABLE + 5 {
        let mac = [2, 1, 0, 0, (i >> 8) as u8, i as u8];
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&mac);
        f.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1]);
        f.extend_from_slice(&mac);
        f.extend_from_slice(&sender(i));
        f.extend_from_slice(&[0; 6]);
        f.extend_from_slice(&[10, 0, 0, 1]);
        s.receive(f);
        s.poll(i as u64);
    }
    let known = s.neighbors();
    assert_eq!(known.len(), MAX_TABLE);
    // The five seen first were evicted.
    for i in [0, 4] {
        assert!(
            !known.contains_key(&std::net::IpAddr::from(sender(i))),
            "{i}"
        );
    }
    assert!(known.contains_key(&std::net::IpAddr::from(sender(5))));
    assert_eq!(counters(&s).get("neighbors-evicted"), Some(&5));
    // A stack that never filled its tables lists it at 0.
    let quiet = node(&[("mac", "02:00:00:00:00:02"), ("ipv4", "10.0.0.2/8")], 2);
    assert_eq!(counters(&quiet).get("neighbors-evicted"), Some(&0));
}

#[test]
fn a_socket_closed_when_a_lookup_changes_family_lingers_from_then() {
    // The first server is IPv4 and never resolves (its queries stay queued behind ARP); after
    // its timeout the lookup moves to the IPv6 server and closes the IPv4 socket, which lingers
    // for LINGER_NS from that instant.
    let client = node(
        &a(&[
            ("dns", "10.0.0.99,2001:db8::2"),
            ("resolver.timeout", "100ms"),
            ("resolver.attempts", "1"),
        ]),
        3,
    );
    let mut sim = Sim::new(vec![client, node(&b(), 4)], 100 * US);
    let t0 = 500 * MS;
    sim.run(t0);
    sim.now = t0;
    let Start::Pending(_) = sim.nodes[0].lookup_start("web.internal", t0).0 else {
        panic!()
    };
    sim.kick(0);
    sim.run(t0 + 150 * MS);
    let (udp, _) = sim.nodes[0].udp();
    assert_eq!(udp.next_deadline(), Some(t0 + 100 * MS + LINGER_NS));
}

// ---- TCP congestion control (`tcp.congestion`) ----

/// One IPv4 TCP segment on the hub.
#[derive(Clone, Copy, Debug)]
struct TcpSeg {
    at: u64,
    from: usize,
    seq: u32,
    ack: u32,
    flags: u8,
    len: u32,
}

type Lose = Option<Box<dyn FnMut(usize, &[u8]) -> bool>>;

impl Sim {
    /// Every IPv4 TCP segment with its sequence and acknowledgment numbers, in transmit order
    /// (lost ones included).
    fn tcp_segs(&self) -> Vec<TcpSeg> {
        self.frames
            .iter()
            .filter(|(_, _, f)| f.get(12..14) == Some(&[8, 0]) && f.get(23) == Some(&6))
            .map(|(at, from, f)| {
                let ip_header = usize::from(f[14] & 0x0f) * 4;
                let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
                let t = &f[14 + ip_header..];
                let word = |i: usize| u32::from_be_bytes([t[i], t[i + 1], t[i + 2], t[i + 3]]);
                TcpSeg {
                    at: *at,
                    from: *from,
                    seq: word(4),
                    ack: word(8),
                    flags: t[13],
                    len: (total - ip_header - usize::from(t[12] >> 4) * 4) as u32,
                }
            })
            .collect()
    }

    /// Node 0's data segments as `(time, bytes in flight just after it left, retransmission)`.
    /// Bytes in flight are the highest byte node 0 sent minus the highest acknowledgment of
    /// node 1's that had reached node 0 by then (one hub latency after node 1 sent it).
    fn flights(&self) -> Vec<(u64, u32, bool)> {
        let segs = self.tcp_segs();
        let isn = segs
            .iter()
            .find(|s| s.from == 0 && s.flags & SYN != 0)
            .expect("node 0's SYN-ACK")
            .seq;
        let mut sent = 0u32;
        let mut out = Vec::new();
        for s in segs.iter().filter(|s| s.from == 0 && s.len > 0) {
            let end = s.seq.wrapping_sub(isn) + s.len;
            let retransmit = end <= sent;
            sent = sent.max(end);
            let acked = segs
                .iter()
                .filter(|a| a.from == 1 && a.flags & ACK != 0 && a.at + self.latency <= s.at)
                .map(|a| a.ack.wrapping_sub(isn))
                .max()
                .unwrap_or(0);
            out.push((s.at, sent - acked, retransmit));
        }
        out
    }
}

/// Node 1's app reads its socket `cl` from `from` on, every millisecond, until the stream ends
/// (or 60 s); then the simulation runs one more second (the ACK of node 0's FIN and whatever
/// else is left). Returns what it read and how the stream ended.
fn read_stream(sim: &mut Sim, cl: u32, from: u64) -> (Vec<u8>, Option<Result<(), SockError>>) {
    sim.tcp(1).0.start_recv(cl).unwrap();
    let mut got = Vec::new();
    let mut at = from.max(sim.now);
    let end = loop {
        sim.run(at);
        sim.now = sim.now.max(at);
        let (bytes, end) = drain(sim, 1, cl);
        got.extend(bytes);
        if end.is_some() || at >= 60_000 * MS {
            break end;
        }
        at += MS;
    };
    sim.run(at + 1_000 * MS);
    (got, end)
}

/// A finished bulk transfer: the simulation, what node 1's app read, and how its stream ended
/// (`None`: it had not ended by 60 s).
struct Transfer {
    sim: Sim,
    data: Vec<u8>,
    got: Vec<u8>,
    end: Option<Result<(), SockError>>,
}

/// Node 0 (with `extra` config) sends `len` bytes to node 1, with the hub losing what `lose`
/// picks. Node 0's send buffer and node 1's receive buffer hold the whole transfer, so while
/// node 1 reads only the congestion window limits the flight. Node 1's app starts reading at
/// `read_from` and from then on reads every millisecond, until its stream ends.
fn transfer(
    extra: &[(&'static str, &'static str)],
    len: usize,
    lose: Lose,
    read_from: u64,
) -> Transfer {
    let mut sim = two(extra, 3);
    sim.lose = lose;
    let (t, mut net) = sim.tcp(0);
    let l = t.create(Family::Ipv4);
    t.set_buffer_size(l, false, len as u64).unwrap();
    t.bind(l, sa("0.0.0.0:80"), &mut net).unwrap();
    t.listen(l, &mut net).unwrap();
    let now = sim.now;
    let (t, mut net) = sim.tcp(1);
    let cl = t.create(Family::Ipv4);
    t.set_buffer_size(cl, true, len as u64).unwrap();
    t.connect(cl, sa("10.0.0.1:80"), now, &mut net).unwrap();
    sim.kick(1);
    sim.run(MS);
    sim.now = MS;
    established(&mut sim, 1, cl);
    let sv = accept(&mut sim, 0, l);
    sim.tcp(0).0.start_send(sv).unwrap();
    let data: Vec<u8> = (0..len).map(|n| (n % 251) as u8).collect();
    write(&mut sim, 0, sv, &data, true);
    let (got, end) = read_stream(&mut sim, cl, read_from);
    Transfer {
        sim,
        data,
        got,
        end,
    }
}

/// [`transfer`] with node 1 reading from the start; node 1 got every byte, in order, and then
/// the end of the stream.
fn bulk_send(extra: &[(&'static str, &'static str)], len: usize, lose: Lose) -> Sim {
    let t = transfer(extra, len, lose, 0);
    assert_eq!(
        t.end,
        Some(Ok(())),
        "node 1 got {} of {len} bytes",
        t.got.len()
    );
    assert!(
        t.got == t.data,
        "node 1 got {} of {len} bytes, in order",
        t.got.len()
    );
    t.sim
}

/// Bulk data: 200 kB, about 140 full segments.
const BULK: usize = 200_000;
/// A full segment at the 1500-byte MTU (smoltcp sends no TCP options on data segments).
const SEG: u32 = 1460;

/// Loses node 0's `n`th data segment (counting from 1), once.
fn lose_data_segment(n: usize) -> Lose {
    lose_data_segments(&[n])
}

/// Loses each of node 0's data segments numbered in `ns` (counting from 1, retransmissions
/// included), once.
fn lose_data_segments(ns: &[usize]) -> Lose {
    let ns = ns.to_vec();
    let mut seen = 0;
    Some(Box::new(move |from, f: &[u8]| {
        // An IPv4 TCP segment with a payload (not the SYN-ACK, whose options also make it
        // longer than 40 bytes).
        let data = from == 0
            && f.get(12..14) == Some(&[8, 0])
            && f.get(23) == Some(&6)
            && f.len() >= 54
            && usize::from(u16::from_be_bytes([f[16], f[17]]))
                > usize::from(f[14] & 0x0f) * 4 + usize::from(f[46] >> 4) * 4;
        if data {
            seen += 1;
        }
        data && ns.contains(&seen)
    }))
}

#[test]
fn reno_is_the_default_and_none_can_be_chosen() {
    for (extra, want) in [
        (&[][..], Congestion::Reno),
        (&[("tcp.congestion", "none")][..], Congestion::None),
    ] {
        let mut sim = two(extra, 1);
        assert_eq!(sim.tcp(0).0.congestion(), want);
    }
}

#[test]
fn reno_starts_slow_and_grows_the_flight_every_round_trip() {
    let sim = bulk_send(&[], BULK, None);
    let flights = sim.flights();
    assert!(
        flights.iter().all(|f| !f.2),
        "nothing was lost: {flights:?}"
    );
    // On the hub every segment of a round trip leaves at one instant, one round trip
    // (200 us) after the ACKs that opened the window left the receiver: the largest flight
    // of each instant is that round trip's congestion window in use.
    let mut rounds: Vec<(u64, u32)> = Vec::new();
    for &(at, flight, _) in &flights {
        match rounds.last_mut() {
            Some((t, peak)) if *t == at => *peak = (*peak).max(flight),
            _ => rounds.push((at, flight)),
        }
    }
    let peaks: Vec<u32> = rounds.iter().map(|r| r.1).collect();
    println!(
        "reno: {} data segments, flight per round trip {peaks:?}",
        flights.len()
    );
    assert!(
        rounds.windows(2).all(|w| w[1].0 - w[0].0 == 200 * US),
        "{rounds:?}"
    );
    // The first round trip: smoltcp's initial window, 2048 bytes (a full segment and 588).
    assert_eq!(peaks[0], 2048);
    // Slow start: one segment more per ACK, and the receiver acknowledges every second full
    // segment, so the window grows by half each round trip, up to the last round (the rest).
    let (last, growing) = peaks.split_last().unwrap();
    for w in growing.windows(2) {
        assert!(w[1] >= w[0] + w[0] / 3, "{peaks:?}");
    }
    assert!(*last <= growing.last().unwrap() * 2, "{peaks:?}");
}

#[test]
fn none_puts_the_whole_window_on_the_wire_at_once() {
    let sim = bulk_send(&[("tcp.congestion", "none")], BULK, None);
    let flights = sim.flights();
    let first = flights[0].0;
    // No congestion window: everything the peer's window takes (here: all of it) leaves at
    // the first instant, as it did before the stack had congestion control.
    let burst: Vec<_> = flights.iter().filter(|f| f.0 == first).collect();
    assert_eq!(burst.len(), flights.len(), "{flights:?}");
    assert_eq!(burst.last().unwrap().1, BULK as u32);
}

#[test]
fn reno_recovers_a_lost_segment_by_fast_retransmit_and_halves_the_flight() {
    let sim = bulk_send(&[], BULK, lose_data_segment(60));
    let flights = sim.flights();
    let lost_at = flights[59].0;
    let retransmits: Vec<_> = flights.iter().filter(|f| f.2).collect();
    // One retransmission, on the third duplicate ACK: within two round trips, never after a
    // retransmission timeout (at least 1 s).
    assert_eq!(retransmits.len(), 1, "{retransmits:?}");
    let retx_at = retransmits[0].0;
    assert!(
        retx_at - lost_at <= 2 * MS,
        "retransmitted {} ns after the loss",
        retx_at - lost_at
    );
    // The largest flight before the loss, against the largest in the round trip after the
    // retransmission was acknowledged (200 us after it left): about half.
    let before = flights
        .iter()
        .filter(|f| f.0 <= lost_at)
        .map(|f| f.1)
        .max()
        .unwrap();
    let recovered = retx_at + 200 * US;
    let after = flights
        .iter()
        .filter(|f| f.0 > recovered && f.0 <= recovered + 200 * US)
        .map(|f| f.1)
        .max()
        .unwrap_or(0);
    println!("reno loss: flight {before} before, {after} after the recovery");
    assert!(
        after > 0 && after <= before / 2 + 3 * SEG && after < before,
        "{before} -> {after}"
    );
}

#[test]
fn reno_repairs_two_losses_in_one_window_without_a_timeout() {
    // Segments 137 and 139 of 142 leave in the last round trip and are both lost. The three
    // segments behind the first hole bring three duplicate ACKs that retransmit it; no new
    // data follows, so nothing else would reveal the second hole. The ACK of the first
    // retransmission stops at the second hole (a partial ACK), which is retransmitted at once (NewReno, RFC 6582), instead of after a
    // retransmission timeout of at least 1 s.
    let sim = bulk_send(&[], BULK, lose_data_segments(&[137, 139]));
    let flights = sim.flights();
    assert_eq!(flights.len(), 142 + 2);
    let lost_at = flights[136].0;
    assert_eq!(flights[138].0, lost_at, "both left in one round trip");
    let retransmits: Vec<_> = flights.iter().filter(|f| f.2).collect();
    assert_eq!(retransmits.len(), 2, "{retransmits:?}");
    // The first on the duplicate ACKs, the second one round trip later on the partial ACK.
    assert!(retransmits[0].0 - lost_at <= 2 * MS, "{retransmits:?}");
    assert_eq!(
        retransmits[1].0 - retransmits[0].0,
        200 * US,
        "{retransmits:?}"
    );
}

#[test]
fn none_retransmits_on_duplicate_acks_too_with_everything_already_sent() {
    // Fast retransmit is smoltcp's, whatever the controller: without one, every segment left
    // at the first instant, and the lost one goes again one round trip later, on the
    // duplicate ACKs of the segments behind it.
    let sim = bulk_send(&[("tcp.congestion", "none")], BULK, lose_data_segment(60));
    let flights = sim.flights();
    let retransmits: Vec<_> = flights.iter().filter(|f| f.2).collect();
    assert_eq!(retransmits.len(), 1, "{retransmits:?}");
    assert_eq!(retransmits[0].0, flights[0].0 + 200 * US);
}

#[test]
fn the_same_seed_gives_the_same_segments_under_every_controller() {
    for c in ["reno", "none"] {
        let extra: &[(&str, &str)] = &[("tcp.congestion", c)];
        let a = bulk_send(extra, 50_000, lose_data_segment(10));
        let b = bulk_send(extra, 50_000, lose_data_segment(10));
        assert!(a.frames == b.frames, "{c}: the frames differ");
    }
}

/// Loses node 0's first data segment with exactly `len` bytes of payload.
fn lose_first_segment_of(len: usize) -> Lose {
    let mut done = false;
    Some(Box::new(move |from, f: &[u8]| {
        let payload =
            (from == 0 && f.get(12..14) == Some(&[8, 0]) && f.get(23) == Some(&6) && f.len() >= 54)
                .then(|| {
                    usize::from(u16::from_be_bytes([f[16], f[17]]))
                        - usize::from(f[14] & 0x0f) * 4
                        - usize::from(f[46] >> 4) * 4
                });
        let hit = !done && payload == Some(len);
        done |= hit;
        hit
    }))
}

#[test]
fn a_fin_past_the_receive_window_waits_for_the_bytes_before_it() {
    // Node 1's receive buffer is 2 bytes smaller than the stream, and its app reads nothing
    // until 10 s. Node 0 (Nagle off) sends 18 800 bytes, then four chunks of 300 bytes, the
    // last with its FIN; the window cuts the last chunk 2 bytes short, so it leaves without
    // the FIN. The first chunk is lost: the three after it bring three duplicate ACKs, and the
    // fast retransmission (all 1200 bytes from the hole, whatever the window) carries the FIN
    // past the window's right edge. Node 1 must keep the 1198 bytes that fit and drop the FIN;
    // once its app reads, the last 2 bytes and the FIN come again, and the stream ends
    // complete. The same under both controllers.
    const LEN: usize = 20_000;
    const CHUNK: usize = 300;
    let mut short = Vec::new();
    for c in ["reno", "none"] {
        let mut sim = two(&[("tcp.congestion", c)], 3);
        sim.lose = lose_first_segment_of(CHUNK);
        let (t, mut net) = sim.tcp(0);
        let l = t.create(Family::Ipv4);
        t.set_buffer_size(l, false, LEN as u64).unwrap();
        t.bind(l, sa("0.0.0.0:80"), &mut net).unwrap();
        t.listen(l, &mut net).unwrap();
        let now = sim.now;
        let (t, mut net) = sim.tcp(1);
        let cl = t.create(Family::Ipv4);
        t.set_buffer_size(cl, true, LEN as u64 - 2).unwrap();
        t.connect(cl, sa("10.0.0.1:80"), now, &mut net).unwrap();
        sim.kick(1);
        sim.run(MS);
        sim.now = MS;
        established(&mut sim, 1, cl);
        let sv = accept(&mut sim, 0, l);
        let (t, net) = sim.tcp(0);
        let hops = net.hop_limit;
        t.set_no_delay(sv, true, hops, net.sockets).unwrap();
        t.start_send(sv).unwrap();
        let data: Vec<u8> = (0..LEN).map(|n| (n % 251) as u8).collect();
        let head = LEN - 4 * CHUNK;
        write(&mut sim, 0, sv, &data[..head], false);
        for (i, chunk) in data[head..].chunks(CHUNK).enumerate() {
            let at = (30 + i as u64) * MS;
            sim.run(at);
            sim.now = at;
            write(&mut sim, 0, sv, chunk, i == 3);
        }
        let (got, end) = read_stream(&mut sim, cl, 10_000 * MS);
        if end != Some(Ok(())) || got != data {
            short.push((c, got.len(), end));
        }
        // The FIN did go past the window once: a fast retransmission of the 4 chunks.
        let segs = sim.tcp_segs();
        assert!(
            segs.iter()
                .any(|s| s.from == 0 && s.flags & FIN != 0 && s.len as usize == 4 * CHUNK),
            "{c}: no FIN past the window"
        );
    }
    assert!(
        short.is_empty(),
        "(controller, bytes read, end) of the streams that ended short of {LEN} bytes: {short:?}"
    );
}

#[test]
fn no_loss_ends_a_stream_short_or_hangs_it_while_the_reader_has_stopped() {
    // The receive buffer holds the whole stream but its scaled window counts in steps of 4
    // bytes, so with the app not reading the window's right edge moves back and forth by a few
    // bytes as data arrives, and closes at the end. Two things can go wrong there. A segment
    // sent against an older, larger window is cut at the edge; when it carries the FIN, the
    // FIN must be dropped with the cut bytes (or the stream ends short). And a retransmitted
    // last segment whose data the receiver already has is dropped whole at the closed window,
    // FIN included; the receiver's ACKs of all the data then count as duplicate ACKs, and the
    // fast retransmit they start must send the FIN alone (or the stream never ends). Every
    // loss position, each run read only from 10 s on, under both controllers.
    let mut bad = Vec::new();
    for c in ["reno", "none"] {
        for n in 1..=142 {
            let t = transfer(
                &[("tcp.congestion", c)],
                BULK,
                lose_data_segment(n),
                10_000 * MS,
            );
            if t.end != Some(Ok(())) || t.got != t.data {
                bad.push((c, n, t.got.len(), t.end));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "(controller, lost segment, bytes read, end) of the transfers that ended short of \
         {BULK} bytes or did not end: {bad:?}"
    );
}
