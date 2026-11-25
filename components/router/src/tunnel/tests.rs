//! The tunnel's settings and state machine, without a router.

use std::net::SocketAddr;

use super::*;

const MS: u64 = 1_000_000;
const S: u64 = 1_000_000_000;

fn e(s: &str) -> SocketAddrV4 {
    s.parse().unwrap()
}

fn spec(extra: &[(&str, &str)]) -> Spec {
    let mut pairs = vec![("id", "7"), ("local", "fd00:ff::a/128")];
    pairs.extend_from_slice(extra);
    Spec::from_pairs(pairs).unwrap()
}

fn kinds(out: &[Action]) -> Vec<&str> {
    out.iter()
        .filter_map(|a| match a {
            Action::Event(e) => Some(e.kind),
            _ => None,
        })
        .collect()
}

/// The decoded messages sent, with their destination.
fn sent(out: &[Action]) -> Vec<(SocketAddrV4, stun::Message)> {
    out.iter()
        .filter_map(|a| match a {
            Action::Send { to, datagram } => Some((*to, stun::parse(datagram).unwrap())),
            _ => None,
        })
        .collect()
}

fn txid_of(m: &stun::Message) -> stun::TransactionId {
    match m {
        stun::Message::Request { txid, .. } | stun::Message::Success { txid, .. } => *txid,
        stun::Message::Error { txid } => *txid,
    }
}

#[test]
fn settings_parse_with_defaults_and_refuse_mistakes() {
    let s = spec(&[]);
    assert_eq!(
        (
            s.udp,
            s.mtu,
            s.probe_ns,
            s.rounds,
            s.keepalive_ns,
            s.dead_ns,
            s.mss_clamp
        ),
        (6081, 1464, 100 * MS, 20, 25 * S, 80 * S, true)
    );
    let s = spec(&[
        ("peer", "203.0.113.2:6081,203.0.113.3:7000"),
        ("mss-clamp", "false"),
    ]);
    assert_eq!(s.peers, vec![e("203.0.113.2:6081"), e("203.0.113.3:7000")]);
    assert!(!s.mss_clamp);
    for bad in [
        vec![("local", "fd00:ff::a/128")],
        vec![("id", "7")],
        vec![("id", "0"), ("local", "fd00:ff::a/128")],
        vec![("id", "16777216"), ("local", "fd00:ff::a/128")],
        vec![("id", "7"), ("local", "fe80::1/128")],
        vec![("id", "7"), ("local", "fd00:ff::a")],
        vec![
            ("id", "7"),
            ("local", "fd00:ff::a/128"),
            ("peer", "203.0.113.2"),
        ],
        vec![
            ("id", "7"),
            ("local", "fd00:ff::a/128"),
            ("peer", "0.0.0.0:1"),
        ],
        vec![("id", "7"), ("local", "fd00:ff::a/128"), ("mtu", "1000")],
        vec![
            ("id", "7"),
            ("local", "fd00:ff::a/128"),
            ("keepalive", "10s"),
            ("dead", "5s"),
        ],
        vec![("id", "7"), ("local", "fd00:ff::a/128"), ("colour", "red")],
        vec![("id", "7"), ("id", "8"), ("local", "fd00:ff::a/128")],
    ] {
        assert!(Spec::from_pairs(bad.clone()).is_err(), "{bad:?}");
    }
    assert!(Spec::from_words(&["id", "7", "local"]).is_err());
    assert_eq!(
        Spec::from_words(&["id", "7", "local", "10.255.0.1/32"])
            .unwrap()
            .local,
        ("10.255.0.1".parse().unwrap(), 32)
    );
    assert!(valid_name("to-b") && valid_name("relay2"));
    assert!(!valid_name("2b") && !valid_name("To-b") && !valid_name("") && !valid_name("a b"));
}

#[test]
fn probes_every_candidate_until_a_response_brings_it_up() {
    let mut t = Tunnel::new("to-b", spec(&[("peer", "203.0.113.2:6081")]), 0);
    assert_eq!(t.state(), State::Probing);
    let mut out = Vec::new();
    t.poll(0, &mut out);
    let s = sent(&out);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].0, e("203.0.113.2:6081"));
    let stun::Message::Request { txid, username } = &s[0].1 else {
        panic!("a request")
    };
    assert_eq!(username.as_deref(), Some("7"));
    assert_eq!(t.deadline(), Some(100 * MS));
    // A response from the peer: up, with the reflexive endpoint it reports.
    out.clear();
    let mapped = Some(SocketAddr::from(([203, 0, 113, 1], 6081)));
    t.on_response(3 * MS, e("203.0.113.2:6081"), txid, mapped, &mut out);
    assert_eq!(kinds(&out), ["tunnel-reflexive", "tunnel-up"]);
    assert!(out.contains(&Action::Carrier(true)));
    assert_eq!(t.state(), State::Up);
    assert_eq!(t.peer(), Some(e("203.0.113.2:6081")));
    assert_eq!(t.reflexive(), Some(e("203.0.113.1:6081")));
    // A response to a transaction it never sent is ignored.
    out.clear();
    let mut forged = *txid;
    forged[11] = 99;
    t.on_response(4 * MS, e("198.51.100.9:1"), &forged, None, &mut out);
    assert!(out.is_empty());
}

#[test]
fn keepalives_hold_it_up_and_silence_takes_it_down() {
    let s = spec(&[
        ("peer", "203.0.113.2:6081"),
        ("keepalive", "1s"),
        ("dead", "3s"),
    ]);
    let mut t = Tunnel::new("to-b", s, 0);
    let mut out = Vec::new();
    t.poll(0, &mut out);
    let tx = txid_of(&sent(&out)[0].1);
    t.on_response(MS, e("203.0.113.2:6081"), &tx, None, &mut out);
    // A keepalive one second later, to the peer only.
    out.clear();
    assert_eq!(t.deadline(), Some(S + MS));
    t.poll(S + MS, &mut out);
    let s = sent(&out);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].0, e("203.0.113.2:6081"));
    // Data keeps it alive; silence for 3 s takes it down and it probes again.
    t.on_data(2 * S, e("203.0.113.2:6081"), 100, &mut out);
    out.clear();
    t.poll(4 * S, &mut out);
    assert_eq!(t.state(), State::Up);
    out.clear();
    t.poll(5 * S, &mut out);
    assert_eq!(kinds(&out), ["tunnel-down"]);
    assert!(out.contains(&Action::Carrier(false)));
    assert_eq!(t.state(), State::Probing);
    assert_eq!(t.peer(), None);
    // The same poll starts the first new round.
    assert_eq!(sent(&out).len(), 1);
}

#[test]
fn runs_out_of_rounds_and_a_new_candidate_restarts_it() {
    let mut t = Tunnel::new(
        "to-b",
        spec(&[("peer", "203.0.113.2:6081"), ("rounds", "3")]),
        0,
    );
    let mut out = Vec::new();
    for n in 0..4 {
        t.poll(n * 100 * MS, &mut out);
    }
    assert_eq!(sent(&out).len(), 3);
    assert_eq!(kinds(&out), ["tunnel-failed"]);
    assert_eq!(t.state(), State::Failed);
    assert_eq!(t.deadline(), None);
    out.clear();
    assert!(t.add_candidate(S, e("203.0.113.9:6081"), "command", &mut out));
    assert!(!t.add_candidate(S, e("203.0.113.9:6081"), "command", &mut out));
    assert_eq!(t.state(), State::Probing);
    assert_eq!(t.deadline(), Some(S));
    out.clear();
    t.poll(S, &mut out);
    assert_eq!(sent(&out).len(), 2, "both candidates");
}

#[test]
fn a_request_is_answered_and_teaches_a_candidate() {
    // No candidates: idle until probed, like a relay's end.
    let mut t = Tunnel::new("to-a", spec(&[]), 0);
    assert_eq!((t.state(), t.deadline()), (State::Idle, None));
    let mut out = Vec::new();
    let tx = [1, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 1];
    t.on_request(MS, e("203.0.113.1:1024"), &tx, &mut out);
    let s = sent(&out);
    assert_eq!(s[0].0, e("203.0.113.1:1024"));
    assert_eq!(
        s[0].1,
        stun::Message::Success {
            txid: tx,
            mapped: Some(SocketAddr::from(([203, 0, 113, 1], 1024)))
        }
    );
    assert_eq!(kinds(&out), ["tunnel-candidate"]);
    // A triggered check goes to it at once; its response brings the tunnel up.
    assert_eq!(t.deadline(), Some(MS));
    out.clear();
    t.poll(MS, &mut out);
    let s = sent(&out);
    assert_eq!(s.len(), 1);
    t.on_response(
        2 * MS,
        e("203.0.113.1:1024"),
        &txid_of(&s[0].1),
        None,
        &mut out,
    );
    assert_eq!(t.state(), State::Up);
}

#[test]
fn roams_to_the_peers_new_endpoint() {
    let mut t = Tunnel::new("to-b", spec(&[("peer", "203.0.113.2:1024")]), 0);
    let mut out = Vec::new();
    t.poll(0, &mut out);
    let tx = txid_of(&sent(&out)[0].1);
    t.on_response(MS, e("203.0.113.2:1024"), &tx, None, &mut out);
    // The peer's NAT gave it a new mapping: its next check arrives from there.
    out.clear();
    t.on_request(
        5 * S,
        e("203.0.113.2:1025"),
        &[1, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 9],
        &mut out,
    );
    assert_eq!(kinds(&out), ["tunnel-roamed"]);
    assert_eq!(t.peer(), Some(e("203.0.113.2:1025")));
    assert_eq!(t.c.roamed, 1);
    // Keepalives follow the peer.
    out.clear();
    t.poll(26 * S, &mut out);
    assert_eq!(sent(&out)[0].0, e("203.0.113.2:1025"));
    // Data from yet another endpoint moves it too.
    out.clear();
    t.on_data(27 * S, e("203.0.113.2:1026"), 60, &mut out);
    assert_eq!(t.peer(), Some(e("203.0.113.2:1026")));
}

#[test]
fn a_reflector_tells_the_reflexive_endpoint_and_is_asked_until_it_answers() {
    let mut t = Tunnel::new("to-b", spec(&[("reflector", "203.0.113.50:6081")]), 0);
    assert_eq!(t.state(), State::Probing);
    let mut out = Vec::new();
    t.poll(0, &mut out);
    let s = sent(&out);
    assert_eq!(s.len(), 1);
    let stun::Message::Request { txid, username } = &s[0].1 else {
        panic!()
    };
    assert_eq!(*username, None, "a plain Binding request");
    out.clear();
    t.on_response(
        MS,
        e("203.0.113.50:6081"),
        txid,
        Some(SocketAddr::from(([203, 0, 113, 1], 6081))),
        &mut out,
    );
    assert_eq!(kinds(&out), ["tunnel-reflexive"]);
    assert_eq!(t.state(), State::Probing, "a reflector is not a peer");
    // Nothing left to ask: idle until a candidate comes.
    out.clear();
    t.poll(100 * MS, &mut out);
    assert!(sent(&out).is_empty());
    assert_eq!(t.state(), State::Idle);
    assert!(
        t.listing()
            .contains("state idle peer - reflexive 203.0.113.1:6081 candidates -")
    );
}

#[test]
fn candidates_are_bounded() {
    let mut t = Tunnel::new("to-b", spec(&[]), 0);
    let mut out = Vec::new();
    for n in 0..20u16 {
        t.on_request(
            MS,
            SocketAddrV4::new([203, 0, 113, 2].into(), 2000 + n),
            &[0; 12],
            &mut out,
        );
    }
    assert_eq!(t.candidates().len(), MAX_CANDIDATES);
}

#[test]
fn the_peer_is_always_a_candidate_so_a_tunnel_that_goes_down_probes_it_again() {
    let s = spec(&[("keepalive", "1s"), ("dead", "3s")]);
    let mut t = Tunnel::new("to-b", s, 0);
    let mut out = Vec::new();
    for n in 0..MAX_CANDIDATES as u16 {
        t.on_request(
            MS,
            SocketAddrV4::new([203, 0, 113, 2].into(), 2000 + n),
            &[0; 12],
            &mut out,
        );
    }
    assert_eq!(t.candidates().len(), MAX_CANDIDATES);
    // Data from a ninth endpoint brings it up: it takes the oldest candidate's place.
    let peer = e("203.0.113.2:9999");
    t.on_data(2 * MS, peer, 60, &mut out);
    assert_eq!(t.peer(), Some(peer));
    assert_eq!(t.candidates().len(), MAX_CANDIDATES);
    assert!(t.candidates().contains(&peer));
    assert!(!t.candidates().contains(&e("203.0.113.2:2000")));
    // Silence takes it down; the next round checks the old peer among the others.
    out.clear();
    t.poll(4 * S, &mut out);
    assert_eq!(t.state(), State::Probing);
    assert!(sent(&out).iter().any(|(to, _)| *to == peer));
}
