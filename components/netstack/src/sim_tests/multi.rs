//! A node with several ports, among single-port nodes on separate segments: each segment is a
//! hub, and a frame reaches every other port on its segment `latency` later.
//!
//! The lab, with H the node under test:
//!
//! ```text
//!   segment 0: H eth0 10.0.1.1 fd00:1::1   A 10.0.1.2 fd00:1::2   D 10.0.1.254 fd00:1::fe
//!   segment 1: H eth1 10.0.2.1 fd00:2::1   B 10.0.2.2 fd00:2::2   G 10.0.2.254 fd00:2::fe
//! ```
//!
//! D and G stand in for routers: plain hosts that answer ARP and NDP, so a frame H sends
//! through them shows which port and next hop H chose.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use super::{MS, US, echo_request, ip, node, sa};
use crate::tcp::Accept;
use crate::udp::{Family, Send, SockError};
use crate::{Event, Note, Stack};

const H: usize = 0;
const A: usize = 1;
const B: usize = 2;
const G: usize = 3;
const D: usize = 4;

enum Ev {
    Deliver {
        to: usize,
        port: usize,
        frame: Vec<u8>,
    },
    Wake(usize),
}

struct Lab {
    nodes: Vec<Stack>,
    /// The segment of each `(node, port)`.
    seg: BTreeMap<(usize, usize), usize>,
    latency: u64,
    queue: BTreeMap<(u64, u64), Ev>,
    seq: u64,
    wake: Vec<Option<u64>>,
    /// `(time, node, port, frame)`
    frames: Vec<(u64, usize, usize, Vec<u8>)>,
    /// `(time, node, event)`
    events: Vec<(u64, usize, Event)>,
    now: u64,
}

fn h_config(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut v = vec![
        ("mac", "02:00:00:00:01:01"),
        ("ipv4", "10.0.1.1/24"),
        ("ipv6", "fd00:1::1/64"),
        ("port1.mac", "02:00:00:00:02:01"),
        ("port1.ipv4", "10.0.2.1/24"),
        ("port1.ipv6", "fd00:2::1/64"),
    ];
    v.extend_from_slice(extra);
    v
}

impl Lab {
    /// The lab, with H configured by `h_config(extra)`.
    fn new(extra: &[(&'static str, &'static str)]) -> Self {
        let nodes = vec![
            node(&h_config(extra), 1),
            node(
                &[
                    ("mac", "02:00:00:00:01:02"),
                    ("ipv4", "10.0.1.2/24"),
                    ("ipv6", "fd00:1::2/64"),
                    // A host on segment 0 whose gateway is H: H must not forward for it.
                    ("ipv4-gateway", "10.0.1.1"),
                ],
                2,
            ),
            node(
                &[
                    ("mac", "02:00:00:00:02:02"),
                    ("ipv4", "10.0.2.2/24"),
                    ("ipv6", "fd00:2::2/64"),
                ],
                3,
            ),
            node(
                &[
                    ("mac", "02:00:00:00:02:fe"),
                    ("ipv4", "10.0.2.254/24"),
                    ("ipv6", "fd00:2::fe/64"),
                ],
                4,
            ),
            node(
                &[
                    ("mac", "02:00:00:00:01:fe"),
                    ("ipv4", "10.0.1.254/24"),
                    ("ipv6", "fd00:1::fe/64"),
                ],
                5,
            ),
        ];
        let seg = BTreeMap::from([
            ((H, 0), 0),
            ((A, 0), 0),
            ((D, 0), 0),
            ((H, 1), 1),
            ((B, 0), 1),
            ((G, 0), 1),
        ]);
        let n = nodes.len();
        let mut lab = Self {
            nodes,
            seg,
            latency: 100 * US,
            queue: BTreeMap::new(),
            seq: 0,
            wake: vec![None; n],
            frames: Vec::new(),
            events: Vec::new(),
            now: 0,
        };
        for i in 0..n {
            lab.step(i);
        }
        lab
    }

    fn push(&mut self, at: u64, ev: Ev) {
        self.queue.insert((at, self.seq), ev);
        self.seq += 1;
    }

    fn step(&mut self, i: usize) {
        let now = self.now;
        let out = self.nodes[i].poll(now);
        for (port, frame) in out.frames {
            let port = port as usize;
            let seg = self.seg.get(&(i, port)).copied();
            let peers: Vec<(usize, usize)> = self
                .seg
                .iter()
                .filter(|&(&(n, p), &s)| Some(s) == seg && (n, p) != (i, port))
                .map(|(&k, _)| k)
                .collect();
            for (to, p) in peers {
                self.push(
                    now + self.latency,
                    Ev::Deliver {
                        to,
                        port: p,
                        frame: frame.clone(),
                    },
                );
            }
            self.frames.push((now, i, port, frame));
        }
        for note in out.notes {
            if let Note::Event(e) = note {
                self.events.push((now, i, e));
            }
        }
        let next = self.nodes[i].next_wakeup(now);
        if next != self.wake[i] {
            self.wake[i] = next;
            if let Some(t) = next {
                self.push(t, Ev::Wake(i));
            }
        }
    }

    fn run(&mut self, limit: u64) {
        while let Some(((at, _), _)) = self.queue.first_key_value() {
            if *at > limit {
                break;
            }
            let ((at, _), ev) = self.queue.pop_first().expect("non-empty");
            self.now = at;
            match ev {
                Ev::Deliver { to, port, frame } => {
                    self.nodes[to].receive_on(port, frame);
                    self.step(to);
                }
                Ev::Wake(i) if self.wake[i] == Some(at) => {
                    self.wake[i] = None;
                    self.step(i);
                }
                Ev::Wake(_) => {}
            }
        }
        self.now = self.now.max(limit);
    }

    /// The frames node `i` sent on `port`.
    fn sent(&self, i: usize, port: usize) -> Vec<&[u8]> {
        self.frames
            .iter()
            .filter(|(_, n, p, _)| *n == i && *p == port)
            .map(|(.., f)| f.as_slice())
            .collect()
    }

    fn udp_bind(&mut self, i: usize, at: &str) -> u32 {
        let (udp, mut net) = self.nodes[i].udp();
        let family = if at.starts_with('[') {
            Family::Ipv6
        } else {
            Family::Ipv4
        };
        let s = udp.create(family);
        udp.bind(s, sa(at), &mut net).expect("bind");
        s
    }

    fn udp_send(
        &mut self,
        i: usize,
        s: u32,
        data: &[u8],
        to: SocketAddr,
    ) -> Result<Send, SockError> {
        let (udp, mut net) = self.nodes[i].udp();
        let r = udp.send(s, data, Some(to), &mut net);
        self.step(i);
        r
    }

    fn udp_recv_all(&mut self, i: usize, s: u32) -> Vec<(Vec<u8>, SocketAddr)> {
        let (udp, mut net) = self.nodes[i].udp();
        std::iter::from_fn(|| udp.receive(s, &mut net).unwrap()).collect()
    }
}

/// The IPv4 source and destination of an IPv4 frame.
fn v4(f: &[u8]) -> Option<(IpAddr, IpAddr)> {
    (f.get(12..14)? == [8, 0]).then(|| {
        let src: [u8; 4] = f[26..30].try_into().unwrap();
        let dst: [u8; 4] = f[30..34].try_into().unwrap();
        (IpAddr::from(src), IpAddr::from(dst))
    })
}

/// The IPv6 source and destination of an IPv6 frame.
fn v6(f: &[u8]) -> Option<(IpAddr, IpAddr)> {
    (f.get(12..14)? == [0x86, 0xdd]).then(|| {
        let src: [u8; 16] = f[22..38].try_into().unwrap();
        let dst: [u8; 16] = f[38..54].try_into().unwrap();
        (IpAddr::from(src), IpAddr::from(dst))
    })
}

/// The target address of an ARP request.
fn arp_request_for(f: &[u8]) -> Option<IpAddr> {
    (f.get(12..14)? == [8, 6] && f.get(21) == Some(&1)).then(|| {
        let t: [u8; 4] = f[38..42].try_into().unwrap();
        IpAddr::from(t)
    })
}

fn mac_of(f: &[u8]) -> [u8; 6] {
    f[..6].try_into().unwrap()
}

#[test]
fn a_two_port_node_answers_on_each_port_and_never_forwards() {
    let mut lab = Lab::new(&[]);
    // A and B ping H's address on their own segment.
    for (i, to) in [(A, "10.0.1.1"), (B, "10.0.2.1")] {
        let (icmp, mut net) = lab.nodes[i].icmp();
        let s = icmp.create(Family::Ipv4);
        icmp.bind(s, ip("0.0.0.0"), 0, &mut net).unwrap();
        let msg = echo_request(false, 1, b"hello");
        assert_eq!(icmp.send(s, &msg, Some(ip(to)), &mut net), Ok(Send::Queued));
        lab.step(i);
        lab.run(lab.now + 10 * MS);
        let (icmp, mut net) = lab.nodes[i].icmp();
        let reply = icmp.receive(s, &mut net).unwrap().expect("a reply");
        assert_eq!(reply.1, ip(to));
    }
    // Every reply left by the port its request came in on, from that port's address.
    let replies = |port: usize| -> Vec<(IpAddr, IpAddr)> {
        lab.sent(H, port)
            .into_iter()
            .filter(|f| f.get(23) == Some(&1) && f.get(34) == Some(&0))
            .filter_map(v4)
            .collect()
    };
    assert_eq!(replies(0), [(ip("10.0.1.1"), ip("10.0.1.2"))]);
    assert_eq!(replies(1), [(ip("10.0.2.1"), ip("10.0.2.2"))]);
    // Each port learned its own neighbour.
    let h = &lab.nodes[H];
    assert!(h.neighbors_on(0).unwrap().contains_key(&ip("10.0.1.2")));
    assert!(!h.neighbors_on(0).unwrap().contains_key(&ip("10.0.2.2")));
    assert!(h.neighbors_on(1).unwrap().contains_key(&ip("10.0.2.2")));
    assert!(!h.neighbors_on(1).unwrap().contains_key(&ip("10.0.1.2")));
    assert!(h.neighbors_on(2).is_none());

    // A sends to B through H, its gateway, and to H's eth1 address on eth0: a host forwards
    // nothing and accepts a packet only on the port that holds its destination.
    let before = lab.sent(H, 1).len();
    let (icmp, mut net) = lab.nodes[A].icmp();
    let s = icmp.create(Family::Ipv4);
    icmp.bind(s, ip("0.0.0.0"), 0, &mut net).unwrap();
    for (seq, to) in [(1, "10.0.2.2"), (2, "10.0.2.1")] {
        let msg = echo_request(false, seq, b"through");
        assert_eq!(icmp.send(s, &msg, Some(ip(to)), &mut net), Ok(Send::Queued));
    }
    lab.step(A);
    lab.run(lab.now + 10 * MS);
    let (icmp, mut net) = lab.nodes[A].icmp();
    assert_eq!(icmp.receive(s, &mut net), Ok(None));
    assert_eq!(lab.sent(H, 1).len(), before, "H sent nothing on eth1");
    assert!(
        lab.sent(H, 0)
            .iter()
            .filter_map(|f| v4(f))
            .all(|(_, dst)| dst == ip("10.0.1.2")),
        "H answered nothing for the other port"
    );
    // A's packets did reach H on eth0.
    assert!(lab.frames.iter().any(|(_, n, _, f)| *n == A
        && v4(f) == Some((ip("10.0.1.2"), ip("10.0.2.2")))
        && mac_of(f) == [2, 0, 0, 0, 1, 1]));
}

#[test]
fn udp_wildcard_and_specific_binds_across_ports() {
    let mut lab = Lab::new(&[]);
    let any = lab.udp_bind(H, "0.0.0.0:7");
    let only1 = lab.udp_bind(H, "10.0.2.1:8");
    let a = lab.udp_bind(A, "0.0.0.0:4000");
    let b = lab.udp_bind(B, "0.0.0.0:4000");
    lab.udp_send(A, a, b"from a", sa("10.0.1.1:7")).unwrap();
    lab.udp_send(B, b, b"from b", sa("10.0.2.1:7")).unwrap();
    lab.run(lab.now + 10 * MS);
    // The wildcard socket hears both ports.
    let got = lab.udp_recv_all(H, any);
    assert_eq!(
        got,
        [
            (b"from a".to_vec(), sa("10.0.1.2:4000")),
            (b"from b".to_vec(), sa("10.0.2.2:4000")),
        ]
    );
    assert_eq!(lab.nodes[H].udp().0.local_address(any), Ok(sa("0.0.0.0:7")));
    // Its answers leave by the route's port, from that port's address.
    for (to, _) in &got {
        let _ = to;
    }
    lab.udp_send(H, any, b"to a", sa("10.0.1.2:4000")).unwrap();
    lab.udp_send(H, any, b"to b", sa("10.0.2.2:4000")).unwrap();
    lab.run(lab.now + 10 * MS);
    assert_eq!(
        lab.udp_recv_all(A, a),
        [(b"to a".to_vec(), sa("10.0.1.1:7"))]
    );
    assert_eq!(
        lab.udp_recv_all(B, b),
        [(b"to b".to_vec(), sa("10.0.2.1:7"))]
    );
    let udp_on = |port: usize| -> Vec<(IpAddr, IpAddr)> {
        lab.sent(H, port)
            .into_iter()
            .filter(|f| f.get(23) == Some(&17))
            .filter_map(v4)
            .collect()
    };
    assert_eq!(udp_on(0), [(ip("10.0.1.1"), ip("10.0.1.2"))]);
    assert_eq!(udp_on(1), [(ip("10.0.2.1"), ip("10.0.2.2"))]);

    // A socket bound to eth1's address hears eth1 only, and sends by eth1's routes only.
    lab.udp_send(B, b, b"to eth1", sa("10.0.2.1:8")).unwrap();
    lab.udp_send(A, a, b"to eth0", sa("10.0.1.1:8")).unwrap();
    lab.run(lab.now + 10 * MS);
    assert_eq!(
        lab.udp_recv_all(H, only1),
        [(b"to eth1".to_vec(), sa("10.0.2.2:4000"))]
    );
    assert_eq!(
        lab.udp_send(H, only1, b"x", sa("10.0.1.2:4000")),
        Err(SockError::RemoteUnreachable)
    );
    // A socket can only bind the node's own addresses.
    let (udp, mut net) = lab.nodes[H].udp();
    let s = udp.create(Family::Ipv4);
    assert_eq!(
        udp.bind(s, sa("10.0.3.1:9"), &mut net),
        Err(SockError::AddressNotBindable)
    );
}

#[test]
fn tcp_listens_on_every_port_and_connects_by_the_route() {
    let mut lab = Lab::new(&[]);
    let now = lab.now;
    let (t, mut net) = lab.nodes[H].tcp();
    let l = t.create(Family::Ipv4);
    assert_eq!(t.listen(l, &mut net).map(|a| a.port()), Ok(49152));
    let l80 = t.create(Family::Ipv4);
    t.bind(l80, sa("0.0.0.0:80"), &mut net).unwrap();
    t.listen(l80, &mut net).unwrap();
    let only1 = t.create(Family::Ipv4);
    t.bind(only1, sa("10.0.2.1:82"), &mut net).unwrap();
    t.listen(only1, &mut net).unwrap();
    let _ = (l, now);
    lab.step(H);
    let mut clients = Vec::new();
    for (i, to) in [(A, "10.0.1.1:80"), (B, "10.0.2.1:80"), (A, "10.0.1.1:82")] {
        let now = lab.now;
        let (t, mut net) = lab.nodes[i].tcp();
        let s = t.create(Family::Ipv4);
        t.connect(s, sa(to), now, &mut net).unwrap();
        lab.step(i);
        clients.push((i, s));
    }
    lab.run(lab.now + 50 * MS);
    let now = lab.now;
    let outcome = |lab: &mut Lab, i: usize, s: u32| {
        let (t, net) = lab.nodes[i].tcp();
        t.connect_poll(s, now, net.sockets)
    };
    assert_eq!(outcome(&mut lab, A, clients[0].1), Some(Ok(())));
    assert_eq!(outcome(&mut lab, B, clients[1].1), Some(Ok(())));
    // Nobody listens on eth0's port 82: refused.
    assert_eq!(
        outcome(&mut lab, A, clients[2].1),
        Some(Err(SockError::ConnectionRefused))
    );
    // The wildcard listener accepted on both ports, each with its port's address.
    let (t, net) = lab.nodes[H].tcp();
    let mut accepted = Vec::new();
    while let Some(Accept::Conn(c)) = t.accept(l80, net.sockets) {
        t.delivered(l80);
        accepted.push((t.local_address(c).unwrap(), t.remote_address(c).unwrap()));
    }
    accepted.sort();
    assert_eq!(
        accepted,
        [
            (sa("10.0.1.1:80"), sa("10.0.1.2:49152")),
            (sa("10.0.2.1:80"), sa("10.0.2.2:49152")),
        ]
    );

    // H connects to B: by eth1, from eth1's address.
    let (t, mut net) = lab.nodes[B].tcp();
    let lb = t.create(Family::Ipv4);
    t.bind(lb, sa("0.0.0.0:81"), &mut net).unwrap();
    t.listen(lb, &mut net).unwrap();
    lab.step(B);
    let now = lab.now;
    let (t, mut net) = lab.nodes[H].tcp();
    let c = t.create(Family::Ipv4);
    t.connect(c, sa("10.0.2.2:81"), now, &mut net).unwrap();
    assert_eq!(t.local_address(c).map(|a| a.ip()), Ok(ip("10.0.2.1")));
    lab.step(H);
    lab.run(lab.now + 50 * MS);
    let now = lab.now;
    let (t, net) = lab.nodes[H].tcp();
    assert_eq!(t.connect_poll(c, now, net.sockets), Some(Ok(())));
    let syns_on_eth0 = lab
        .sent(H, 0)
        .into_iter()
        .filter(|f| f.get(23) == Some(&6) && v4(f).is_some_and(|(_, d)| d == ip("10.0.2.2")))
        .count();
    assert_eq!(syns_on_eth0, 0);
    // No route: a destination beyond both prefixes, with no gateway.
    let (t, mut net) = lab.nodes[H].tcp();
    let d = t.create(Family::Ipv4);
    assert_eq!(
        t.connect(d, sa("192.0.2.1:80"), now, &mut net),
        Err(SockError::RemoteUnreachable)
    );
}

#[test]
fn static_routes_pick_the_port_the_next_hop_and_the_source_address() {
    let mut lab = Lab::new(&[
        ("ipv4-gateway", "10.0.1.254"),
        (
            "routes",
            "10.9.0.0/16 via 10.0.2.254, fd00:9::/32 via fd00:2::fe, \
             172.16.0.0/12 via 10.0.2.254, 192.168.0.0/16 via 10.0.2.254",
        ),
    ]);
    {
        let (_, net) = lab.nodes[H].udp();
        let r = net.routing;
        for (dst, port) in [
            ("10.9.1.1", Some(1)),
            ("10.0.2.77", Some(1)),
            ("10.0.1.9", Some(0)),
            ("8.8.8.8", Some(0)),
            ("fd00:9::5", Some(1)),
            ("fd00:1::7", Some(0)),
            ("2001:db8::1", None),
            ("224.0.0.251", Some(0)),
        ] {
            assert_eq!(r.route(ip(dst), 0, None), port, "{dst}");
        }
        // A socket tied to eth1 only has eth1's routes.
        assert_eq!(r.route(ip("8.8.8.8"), 0, Some(1)), None);
        assert_eq!(r.route(ip("10.9.0.1"), 0, Some(1)), Some(1));
        // A link-local destination: its scope picks the port; without one, the lowest.
        assert_eq!(r.route(ip("fe80::99"), 2, None), Some(1));
        assert_eq!(r.route(ip("fe80::99"), 1, None), Some(0));
        assert_eq!(r.route(ip("fe80::99"), 0, None), Some(0));
        assert_eq!(r.route(ip("fe80::99"), 3, None), None);
    }
    let s4 = lab.udp_bind(H, "0.0.0.0:0");
    let s6 = lab.udp_bind(H, "[::]:0");
    lab.udp_send(H, s4, b"far", sa("10.9.1.1:53")).unwrap();
    lab.udp_send(H, s4, b"default", sa("8.8.8.8:53")).unwrap();
    lab.udp_send(H, s6, b"far6", sa("[fd00:9::5]:53")).unwrap();
    // eth1's fourth route: smoltcp's table holds every one of them.
    lab.udp_send(H, s4, b"fourth", sa("192.168.5.5:53"))
        .unwrap();
    lab.run(lab.now + 10 * MS);
    let g = [2, 0, 0, 0, 2, 0xfe];
    let d = [2, 0, 0, 0, 1, 0xfe];
    // The next hop is resolved on its own port only.
    let arp = |port| -> Vec<IpAddr> {
        lab.sent(H, port)
            .into_iter()
            .filter_map(arp_request_for)
            .collect()
    };
    assert_eq!(arp(0), [ip("10.0.1.254")]);
    assert_eq!(arp(1), [ip("10.0.2.254")]);
    let udp = |port: usize| -> Vec<([u8; 6], IpAddr, IpAddr)> {
        lab.sent(H, port)
            .into_iter()
            .filter_map(|f| {
                let is_udp = f.get(23) == Some(&17) || f.get(20) == Some(&17);
                let (src, dst) = v4(f).or_else(|| v6(f))?;
                is_udp.then_some((mac_of(f), src, dst))
            })
            .collect()
    };
    assert_eq!(
        udp(1),
        [
            (g, ip("10.0.2.1"), ip("10.9.1.1")),
            // smoltcp sends socket by socket: both of the IPv4 socket's datagrams first.
            (g, ip("10.0.2.1"), ip("192.168.5.5")),
            (g, ip("fd00:2::1"), ip("fd00:9::5")),
        ]
    );
    assert_eq!(udp(0), [(d, ip("10.0.1.1"), ip("8.8.8.8"))]);
    assert!(lab.nodes[H].describe().contains(
        "routes 10.9.0.0/16 via 10.0.2.254 port 1, fd00:9::/32 via fd00:2::fe port 1, \
         172.16.0.0/12 via 10.0.2.254 port 1, 192.168.0.0/16 via 10.0.2.254 port 1, \
         default via 10.0.1.254 port 0"
    ));
}

#[test]
fn a_multicast_join_on_one_port_only() {
    let mut lab = Lab::new(&[]);
    let h = lab.udp_bind(H, "0.0.0.0:5000");
    let (udp, _) = lab.nodes[H].udp();
    // Interface index 2 is eth1; 3 names no port.
    assert_eq!(
        udp.join(h, ip("239.1.2.3"), 3),
        Err(SockError::InvalidArgument)
    );
    udp.join(h, ip("239.1.2.3"), 2).unwrap();
    lab.step(H);
    lab.run(lab.now + MS);
    let igmp = |port: usize| {
        lab.sent(H, port)
            .into_iter()
            .filter(|f| f.get(12..14) == Some(&[8, 0]) && f.get(23) == Some(&2))
            .count()
    };
    assert_eq!((igmp(0), igmp(1)), (0, 1));
    let joined = lab
        .events
        .iter()
        .find(|(_, n, e)| *n == H && e.kind == "multicast-joined");
    assert_eq!(joined.map(|(.., e)| e.get("port")), Some(Some("eth1")));
    // Datagrams to the group from each segment: only eth1's arrive.
    let a = lab.udp_bind(A, "0.0.0.0:4000");
    let b = lab.udp_bind(B, "0.0.0.0:4000");
    lab.udp_send(A, a, b"on eth0", sa("239.1.2.3:5000"))
        .unwrap();
    lab.udp_send(B, b, b"on eth1", sa("239.1.2.3:5000"))
        .unwrap();
    lab.run(lab.now + 10 * MS);
    assert_eq!(
        lab.udp_recv_all(H, h),
        [(b"on eth1".to_vec(), sa("10.0.2.2:4000"))]
    );
    // Sending to a group: by the socket's interface, else the family's default port (here the
    // lowest port with an IPv4 address).
    let before = (lab.sent(H, 0).len(), lab.sent(H, 1).len());
    lab.udp_send(H, h, b"default", sa("239.9.9.9:5000"))
        .unwrap();
    let (udp, _) = lab.nodes[H].udp();
    udp.set_multicast_interface(h, 2).unwrap();
    assert_eq!(
        udp.set_multicast_interface(h, 3),
        Err(SockError::InvalidArgument)
    );
    lab.udp_send(H, h, b"eth1", sa("239.9.9.9:5000")).unwrap();
    lab.run(lab.now + MS);
    assert_eq!(
        (
            lab.sent(H, 0).len() - before.0,
            lab.sent(H, 1).len() - before.1
        ),
        (1, 1)
    );
}

#[test]
fn the_interfaces_and_counters_name_every_port() {
    let mut lab = Lab::new(&[("port1.mtu", "9000")]);
    let all = lab.nodes[H].interfaces();
    assert_eq!(
        all.iter()
            .map(|i| (i.index, i.name.as_str(), i.mtu))
            .collect::<Vec<_>>(),
        [(1, "eth0", 1500), (2, "eth1", 9000)]
    );
    assert!(all[1].addresses.contains(&(ip("10.0.2.1"), 24)));
    assert_eq!(lab.nodes[H].interface(), all[0]);
    let a = lab.udp_bind(A, "0.0.0.0:4000");
    lab.udp_send(A, a, b"x", sa("10.0.1.1:9")).unwrap();
    lab.run(lab.now + 10 * MS);
    let h = &lab.nodes[H];
    let ports: BTreeMap<String, u64> = h.port_counters().into_iter().collect();
    let total: BTreeMap<String, u64> = h.counters().into_iter().collect();
    assert_eq!(
        ports["eth0.rx-frames"] + ports["eth1.rx-frames"],
        total["rx-frames"]
    );
    assert_eq!(ports["eth0.arp-resolved"], 0);
    assert!(ports["eth0.rx-frames"] > 0);
    // A node with one port lists no per-port counters, so its list is what it always was.
    assert!(lab.nodes[A].port_counters().is_empty());
    assert_eq!(lab.nodes[A].interfaces().len(), 1);
}

#[test]
fn a_two_port_snapshot_restores_onto_a_fresh_stack() {
    let config = crate::Config::from_pairs(h_config(&[])).unwrap();
    let macs = [
        "02:00:00:00:01:01".parse().unwrap(),
        "02:00:00:00:02:01".parse().unwrap(),
    ];
    let mut s = Stack::with_macs(&config, &macs, 9, 0x4200, 0);
    let _ = s.poll(0);
    let (udp, mut net) = s.udp();
    let u = udp.create(Family::Ipv4);
    udp.bind(u, sa("0.0.0.0:53"), &mut net).unwrap();
    let (t, mut net) = s.tcp();
    let l = t.create(Family::Ipv6);
    t.bind(l, sa("[fd00:2::1]:80"), &mut net).unwrap();
    t.listen(l, &mut net).unwrap();
    let _ = s.poll(1_000);
    let saved = s.save().expect("quiescent");
    let mut fresh = Stack::with_macs(&config, &macs, 9, 0x4200, 1_000);
    fresh.restore(&saved).expect("restore");
    assert_eq!(fresh.save().unwrap(), saved);
    // A stack of another shape refuses it.
    let one = crate::Config::from_pairs([("mac", "02:00:00:00:01:01")]).unwrap();
    let mut single = Stack::new(&one, macs[0], 9, 0x4200, 0);
    let err = single.restore(&saved).unwrap_err();
    assert!(err.contains("2 ports"), "{err}");
}

#[test]
fn a_one_shot_mdns_query_asks_on_every_port() {
    let mut lab = Lab::new(&[]);
    let now = lab.now;
    let (start, _) = lab.nodes[H].lookup_start("printer.local", now);
    assert!(matches!(start, crate::resolver::Start::Pending(_)));
    lab.step(H);
    lab.run(lab.now + 10 * MS);
    let queries = |port: usize, group: &str| {
        lab.sent(H, port)
            .into_iter()
            .filter(|f| v4(f).or_else(|| v6(f)).is_some_and(|(_, d)| d == ip(group)))
            .count()
    };
    // The A and the AAAA question (both by IPv4, as on a node with one port), on each port.
    assert_eq!(
        (queries(0, "224.0.0.251"), queries(1, "224.0.0.251")),
        (2, 2)
    );
}
