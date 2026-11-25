//! Keyed tunnels without a router: two ends exchange their datagrams directly, and an attacker
//! replays, reflects and forges them.

use std::net::SocketAddr;

use super::*;

const MS: u64 = 1_000_000;
const S: u64 = 1_000_000_000;

const K1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const K2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn e(s: &str) -> SocketAddrV4 {
    s.parse().unwrap()
}

/// Where each end is seen from the other (no NAT here), and where an attacker sends from.
const A: &str = "203.0.113.1:4500";
const B: &str = "203.0.113.2:4500";
const EVIL: &str = "198.51.100.66:4500";

fn end(name: &str, local: &str, key: Option<&str>, peer: Option<&str>) -> Tunnel {
    let mut pairs = vec![
        ("id", "7"),
        ("local", local),
        ("keepalive", "1s"),
        ("dead", "4s"),
    ];
    if let Some(k) = key {
        pairs.push(("key", k));
    }
    if let Some(p) = peer {
        pairs.push(("peer", p));
    }
    Tunnel::new(name, Spec::from_pairs(pairs).unwrap(), 0)
}

fn kinds(out: &[Action]) -> Vec<&'static str> {
    out.iter()
        .filter_map(|a| match a {
            Action::Event(e) => Some(e.kind),
            _ => None,
        })
        .collect()
}

fn reasons(out: &[Action]) -> Vec<String> {
    out.iter()
        .filter_map(|a| match a {
            Action::Event(e) if e.kind == "tunnel-auth-failed" => e
                .fields
                .iter()
                .find(|(k, _)| k == "reason")
                .map(|(_, v)| v.clone()),
            _ => None,
        })
        .collect()
}

/// Hands datagram `d` from `from` to tunnel `t`, as the router does; returns an inner packet
/// that came out.
fn deliver(
    now: u64,
    t: &mut Tunnel,
    from: SocketAddrV4,
    d: &[u8],
    out: &mut Vec<Action>,
) -> Option<Vec<u8>> {
    if stun::is_stun(d) {
        let (m, s) = stun::parse_signed(d).ok()?;
        match m {
            stun::Message::Request { txid, .. } => {
                t.on_request_signed(now, from, &txid, d, &s, out);
            }
            stun::Message::Success { txid, mapped } => {
                t.on_response_signed(now, from, &txid, mapped, d, &s, out);
            }
            stun::Message::Error { .. } => {}
        }
        None
    } else {
        t.on_esp(now, from, d, out)
    }
}

/// The datagrams in `out`, to `to`.
fn sends(out: &[Action], to: &str) -> Vec<Vec<u8>> {
    out.iter()
        .filter_map(|x| match x {
            Action::Send { to: t, datagram } if *t == e(to) => Some(datagram.clone()),
            _ => None,
        })
        .collect()
}

/// Runs both ends' timers at `now` and carries their datagrams back and forth until quiet.
/// Returns everything each end did, and every datagram A and B sent (for replays).
struct Run {
    a_out: Vec<Action>,
    b_out: Vec<Action>,
    from_a: Vec<Vec<u8>>,
    from_b: Vec<Vec<u8>>,
}

fn step(now: u64, a: &mut Tunnel, b: &mut Tunnel) -> Run {
    let mut r = Run {
        a_out: Vec::new(),
        b_out: Vec::new(),
        from_a: Vec::new(),
        from_b: Vec::new(),
    };
    let mut fresh_a = Vec::new();
    let mut fresh_b = Vec::new();
    a.poll(now, &mut fresh_a);
    b.poll(now, &mut fresh_b);
    for _ in 0..20 {
        let to_b = sends(&fresh_a, B);
        let to_a = sends(&fresh_b, A);
        r.a_out.append(&mut fresh_a);
        r.b_out.append(&mut fresh_b);
        if to_a.is_empty() && to_b.is_empty() {
            break;
        }
        for d in to_b {
            deliver(now, b, e(A), &d, &mut fresh_b);
            r.from_a.push(d);
        }
        for d in to_a {
            deliver(now, a, e(B), &d, &mut fresh_a);
            r.from_b.push(d);
        }
    }
    r
}

fn up_pair(ka: Option<&str>, kb: Option<&str>) -> (Tunnel, Tunnel, Run) {
    let mut a = end("to-b", "fd00:ff::a/128", ka, Some(B));
    let mut b = end("to-a", "fd00:ff::b/128", kb, None);
    let mut r = step(0, &mut a, &mut b);
    let more = step(MS, &mut a, &mut b);
    r.a_out.extend(more.a_out);
    r.b_out.extend(more.b_out);
    r.from_a.extend(more.from_a);
    r.from_b.extend(more.from_b);
    (a, b, r)
}

fn packet(n: u8) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0, 0, 4, 59, 64];
    p.extend([0xfd; 30]); // 42 bytes: plus 2, a multiple of 4
    p.extend([n; 4]);
    p
}

#[test]
fn keyed_settings_default_to_esp_s_port_and_a_smaller_mtu() {
    let s = Spec::from_pairs([("id", "7"), ("local", "fd00:ff::a/128"), ("key", K1)]).unwrap();
    assert_eq!((s.udp, s.mtu), (esp::PORT, KEYED_MTU));
    assert_eq!(KEYED_MTU, 1438);
    assert!(s.key.is_some());
    let plain = Spec::from_pairs([("id", "7"), ("local", "fd00:ff::a/128")]).unwrap();
    assert_eq!((plain.udp, plain.mtu, plain.key), (6081, 1464, None));
    assert!(Spec::from_pairs([("id", "7"), ("local", "fd00::a/128"), ("key", "beef")]).is_err());
    let err =
        Spec::from_pairs([("id", "7"), ("local", "fd00::a/128"), ("key", &K1[1..])]).unwrap_err();
    assert!(!err.contains("111"), "the key is never echoed: {err}");
}

#[test]
fn keyed_ends_come_up_and_carry_data_once() {
    let (mut a, mut b, r) = up_pair(Some(K1), Some(K1));
    assert_eq!(a.state(), State::Up, "{:?}", kinds(&r.a_out));
    assert_eq!(b.state(), State::Up, "{:?}", kinds(&r.b_out));
    assert!(reasons(&r.a_out).is_empty() && reasons(&r.b_out).is_empty());
    // Every check and answer between them was signed.
    for d in r.from_a.iter().chain(&r.from_b) {
        let (_, s) = stun::parse_signed(d).unwrap();
        assert!(s.integrity.is_some() && s.sa.is_some());
    }
    let mut out = Vec::new();
    let d = a.seal(&packet(1), &mut out).expect("a proven peer");
    assert_eq!(
        d.len(),
        esp::HEADER + packet(1).len() + 2 + esp::ICV,
        "no padding"
    );
    assert_eq!(deliver(2 * MS, &mut b, e(A), &d, &mut out), Some(packet(1)));
    // Replayed: refused, counted, journalled once; the peer stays.
    assert_eq!(deliver(3 * MS, &mut b, e(A), &d, &mut out), None);
    assert_eq!(deliver(3 * MS, &mut b, e(EVIL), &d, &mut out), None);
    assert_eq!((b.c.replayed, b.c.auth_failed), (2, 2));
    assert_eq!(reasons(&out), ["replayed"]);
    assert_eq!(b.peer(), Some(e(A)));
    // The other way, too.
    let d = b.seal(&packet(2), &mut out).unwrap();
    assert_eq!(deliver(4 * MS, &mut a, e(B), &d, &mut out), Some(packet(2)));
    // A fresh packet from a new endpoint (a NAT rebinding) moves the peer; only that does.
    let d = a.seal(&packet(3), &mut out).unwrap();
    let mut moved = Vec::new();
    assert!(deliver(5 * MS, &mut b, e("203.0.113.1:9999"), &d, &mut moved).is_some());
    assert_eq!(kinds(&moved), ["tunnel-roamed"]);
}

#[test]
fn an_attacker_neither_roams_nor_brings_up_a_keyed_tunnel() {
    let (_, mut b, r) = up_pair(Some(K1), Some(K1));
    let mut out = Vec::new();
    // A captured check of A's, replayed from the attacker: stale counter.
    let check = r
        .from_a
        .iter()
        .find(|d| matches!(stun::parse(d), Ok(stun::Message::Request { .. })))
        .unwrap()
        .clone();
    deliver(2 * MS, &mut b, e(EVIL), &check, &mut out);
    // A check without integrity, and one signed with another key.
    let plain = stun::request(&[1; 12], Some("7"));
    deliver(2 * MS, &mut b, e(EVIL), &plain, &mut out);
    let forged = stun::request_signed(&[2; 12], "7", (0x8000_0001, 1), &[0x41; 64]);
    deliver(2 * MS, &mut b, e(EVIL), &forged, &mut out);
    // An answer nobody asked for, signed right (a captured one of B's own, sent to B).
    let answer = r
        .from_a
        .iter()
        .find(|d| matches!(stun::parse(d), Ok(stun::Message::Success { .. })))
        .unwrap()
        .clone();
    deliver(2 * MS, &mut b, e(EVIL), &answer, &mut out);
    // Garbage ESP to B's SPI.
    let spi = b.crypto.as_ref().unwrap().cur.spi;
    let mut junk = spi.to_be_bytes().to_vec();
    junk.extend([0u8; 44]);
    junk[7] = 9;
    assert_eq!(deliver(2 * MS, &mut b, e(EVIL), &junk, &mut out), None);
    assert_eq!(
        reasons(&out),
        ["replayed", "unsigned", "integrity", "unexpected", "esp"]
    );
    assert!(!kinds(&out).contains(&"tunnel-roamed"));
    assert_eq!(b.peer(), Some(e(A)));
    // Nothing was answered: no datagram leaves B for the attacker.
    assert!(sends(&out, EVIL).is_empty());
    // Reflected: A's own check sent back to A.
    let mut a = end("to-b", "fd00:ff::a/128", Some(K1), Some(B));
    let mut out = Vec::new();
    a.poll(0, &mut out);
    let own = sends(&out, B).remove(0);
    let mut back = Vec::new();
    deliver(MS, &mut a, e(EVIL), &own, &mut back);
    assert_eq!(reasons(&back), ["reflected"]);
}

#[test]
fn a_wrong_key_or_a_keyless_end_never_comes_up_and_says_why() {
    let (a, b, r) = up_pair(Some(K1), Some(K2));
    assert_ne!(a.state(), State::Up);
    assert_ne!(b.state(), State::Up);
    assert_eq!(reasons(&r.b_out), ["integrity"]);
    assert!(b.c.auth_failed >= 1);
    // Keyed A, keyless B: B refuses A's signed checks; A refuses B's unsigned ones.
    let (a, b, r) = up_pair(Some(K1), None);
    assert_ne!(a.state(), State::Up);
    assert_ne!(b.state(), State::Up);
    assert_eq!(reasons(&r.b_out), ["keyed-peer"]);
    let (a, b, r) = up_pair(None, Some(K1));
    assert_ne!(a.state(), State::Up);
    assert_ne!(b.state(), State::Up);
    assert_eq!(reasons(&r.b_out), ["unsigned"]);
    // Cleartext is never taken by a keyed tunnel: the router refuses Geneve for it (see the
    // router's tests); here, a keyed tunnel never seals without a proven peer.
    let mut lone = end("to-b", "fd00:ff::a/128", Some(K1), Some(B));
    assert!(lone.seal(&packet(1), &mut Vec::new()).is_none());
}

#[test]
fn a_key_replaced_on_a_live_tunnel_keeps_it_up_and_retires_the_old_key() {
    let (mut a, mut b, _) = up_pair(Some(K1), Some(K1));
    let old_spi_b = b.crypto.as_ref().unwrap().cur.spi;
    let mut out = Vec::new();
    // A first: it signs with K2 at once, still sends under K1 (B has not proven K2).
    assert_eq!(
        a.replace_key(S, key::Key::parse(K2).unwrap(), &mut out),
        Ok(true)
    );
    assert_eq!(kinds(&out), ["tunnel-key-replaced"]);
    let r = step(S, &mut a, &mut b);
    assert_eq!(reasons(&r.b_out), ["integrity"], "B does not have K2 yet");
    let in_flight = a.seal(&packet(1), &mut out).unwrap();
    assert_eq!(esp::spi_of(&in_flight), Some(old_spi_b), "under K1");
    assert_eq!(
        deliver(S, &mut b, e(A), &in_flight, &mut out),
        Some(packet(1))
    );
    // B too: its check under K2 checks at A, A answers under K2; both confirm K2.
    assert_eq!(
        b.replace_key(S + MS, key::Key::parse(K2).unwrap(), &mut out),
        Ok(true)
    );
    let r = step(S + MS, &mut a, &mut b);
    assert!(
        kinds(&r.a_out).contains(&"tunnel-key-confirmed"),
        "{:?}",
        kinds(&r.a_out)
    );
    assert!(
        kinds(&r.b_out).contains(&"tunnel-key-confirmed"),
        "{:?}",
        kinds(&r.b_out)
    );
    assert!(a.crypto.as_ref().unwrap().prev.is_none());
    assert_eq!((a.state(), b.state()), (State::Up, State::Up));
    let d = a.seal(&packet(2), &mut out).unwrap();
    assert_ne!(esp::spi_of(&d), Some(old_spi_b), "under K2 now");
    assert_eq!(
        deliver(S + 2 * MS, &mut b, e(A), &d, &mut out),
        Some(packet(2))
    );
    // A packet sealed under K1 that arrives after K2 was confirmed: dropped.
    let mut late = Vec::new();
    assert_eq!(
        deliver(S + 3 * MS, &mut b, e(A), &in_flight, &mut late),
        None
    );
    // Setting the same key again changes nothing; a keyless tunnel gets none.
    assert_eq!(
        a.replace_key(S, key::Key::parse(K2).unwrap(), &mut out),
        Ok(false)
    );
    let mut plain = end("p", "fd00:ff::c/128", None, None);
    assert!(
        plain
            .replace_key(S, key::Key::parse(K2).unwrap(), &mut out)
            .is_err()
    );
}

#[test]
fn a_previous_key_retires_after_dead_if_the_peer_never_proves_the_new_one() {
    let (mut a, mut b, _) = up_pair(Some(K1), Some(K1));
    let mut out = Vec::new();
    a.replace_key(S, key::Key::parse(K2).unwrap(), &mut out)
        .unwrap();
    assert!(a.deadline().unwrap() <= S + 4 * S);
    a.poll(S + 4 * S, &mut out);
    assert!(kinds(&out).contains(&"tunnel-key-retired"));
    assert!(a.seal(&packet(1), &mut out).is_none(), "B never proved K2");
    let _ = &mut b;
}

#[test]
fn a_restarted_end_starts_a_new_epoch_and_old_packets_stay_dead() {
    let (mut a, mut b, _) = up_pair(Some(K1), Some(K1));
    let mut out = Vec::new();
    // The third packet of B's first epoch (a sequence number the new epoch has not reached).
    for n in 1..=2 {
        b.seal(&packet(n), &mut out).unwrap();
    }
    let old = b.seal(&packet(3), &mut out).unwrap();
    // B restarts at 2 s: a new tunnel, the same key, a new epoch and SPI.
    b = Tunnel::new(
        "to-a",
        Spec::from_pairs([
            ("id", "7"),
            ("local", "fd00:ff::b/128"),
            ("keepalive", "1s"),
            ("dead", "4s"),
            ("key", K1),
            ("peer", A),
        ])
        .unwrap(),
        2 * S,
    );
    step(2 * S, &mut a, &mut b);
    let fresh = b.seal(&packet(2), &mut out).expect("B learnt A's SA again");
    assert_eq!(
        deliver(2 * S, &mut a, e(B), &fresh, &mut out),
        Some(packet(2))
    );
    // B's packet from before the restart: its epoch's SA is gone at A.
    let mut late = Vec::new();
    assert_eq!(deliver(2 * S, &mut a, e(B), &old, &mut late), None);
    assert_eq!(reasons(&late), ["esp"]);
}

#[test]
fn an_sa_that_used_every_sequence_number_sends_no_more() {
    let (mut a, _, _) = up_pair(Some(K1), Some(K1));
    if let Some(p) = a.crypto.as_mut().and_then(|c| c.cur.peer.as_mut()) {
        p.seq = u32::MAX - 1;
    }
    let mut out = Vec::new();
    assert!(a.seal(&packet(1), &mut out).is_some());
    assert!(a.seal(&packet(2), &mut out).is_none());
    assert!(a.seal(&packet(3), &mut out).is_none());
    assert_eq!(kinds(&out), ["tunnel-key-exhausted"]);
}

#[test]
fn keyed_listings_name_the_key_by_its_id_only() {
    let (a, _, _) = up_pair(Some(K1), Some(K1));
    let line = a.listing();
    let id = key::Key::parse(K1).unwrap().id();
    assert!(line.ends_with(&format!(" key {id}")), "{line}");
    assert!(!line.contains("1111"), "{line}");
    let plain = end("p", "fd00:ff::c/128", None, None);
    assert!(!plain.listing().contains(" key "));
    let _ = SocketAddr::V4(e(A));
}
