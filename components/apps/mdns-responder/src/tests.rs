use std::net::{IpAddr, SocketAddr};

use super::*;

fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
    p.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn responder(name: &str) -> Responder {
    Responder::new(Config::from_pairs(pairs(&[("hostname", name)])).unwrap())
}

fn addrs() -> Vec<IpAddr> {
    ["10.0.0.10", "fe80::10", "fd00::10"]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect()
}

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Runs the timers until the responder is ready; returns every packet and note.
fn boot(r: &mut Responder) -> (Vec<(u64, Packet)>, Vec<Note>) {
    let mut packets = Vec::new();
    let mut notes = Vec::new();
    while let Some(at) = r.next_deadline() {
        let (p, n) = r.tick(at, &addrs());
        packets.extend(p.into_iter().map(|p| (at, p)));
        notes.extend(n);
    }
    (packets, notes)
}

#[test]
fn config_keys_and_errors() {
    let c = Config::from_pairs(pairs(&[
        ("hostname", "Alice"),
        ("families", "ipv6"),
        ("ttl", "60s"),
        ("link-local", "true"),
        ("start", "1s"),
    ]))
    .unwrap();
    assert_eq!(c.hostname, "alice");
    assert!(!c.ipv4 && c.ipv6 && c.link_local);
    assert_eq!((c.ttl, c.start_ns), (60, 1_000_000_000));
    for (p, needle) in [
        (pairs(&[]), "hostname"),
        (pairs(&[("hostname", "a.b")]), "one label"),
        (pairs(&[("hostname", "a"), ("families", "ipx")]), "families"),
        (pairs(&[("hostname", "a"), ("ttl", "0s")]), "ttl"),
        (pairs(&[("hostname", "a"), ("colour", "red")]), "unknown"),
    ] {
        let err = Config::from_pairs(p).unwrap_err().to_string();
        assert!(err.contains(needle), "{err}");
    }
}

#[test]
fn it_probes_three_times_then_announces_twice() {
    let mut r = responder("alice");
    let start = r.next_deadline().unwrap();
    assert!(start < 250 * MS, "a 0-249 ms delay derived from the name");
    let (packets, notes) = boot(&mut r);
    // Each step goes to both groups.
    let times: Vec<u64> = packets.iter().step_by(2).map(|(t, _)| t - start).collect();
    assert_eq!(
        times,
        [0, 250 * MS, 500 * MS, 750 * MS, 1_750 * MS],
        "probes 250 ms apart, the announcements 250 ms after the last probe, then 1 s apart"
    );
    let probe = &packets[0].1.message;
    assert!(!probe.is_response());
    assert_eq!(probe.questions[0].name, "alice.local");
    assert_eq!(probe.questions[0].qtype, rtype::ANY);
    assert!(
        probe.questions[0].unicast_response(),
        "QU on the first probe"
    );
    assert!(!packets[2].1.message.questions[0].unicast_response());
    assert_eq!(
        probe.authorities.len(),
        2,
        "A and AAAA; link-local left out"
    );
    let announce = &packets[6].1.message;
    assert!(announce.is_response() && announce.authoritative());
    assert!(announce.answers.iter().all(Record::cache_flush));
    assert_eq!(announce.id, 0);
    assert!(r.is_ready());
    let kinds: Vec<&str> = notes.iter().map(|n| n.0).collect();
    assert_eq!(kinds, ["mdns-probing", "mdns-announced"]);
    // Wire format round trip: what goes out parses back the same.
    assert_eq!(Message::parse(&announce.encode()).unwrap(), *announce);
}

#[test]
fn answers_legacy_qu_and_multicast_queries() {
    let mut r = responder("alice");
    boot(&mut r);
    let now = 5_000 * MS;
    // A one-shot (legacy) query from an ephemeral port: unicast back, id and question kept.
    let q = Message::query(0x1234, "ALICE.local", rtype::A);
    let (p, notes) = r.on_packet(now, sa("10.0.0.20:50000"), false, &q.encode(), &addrs());
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].to, Dest::Unicast(sa("10.0.0.20:50000")));
    let m = &p[0].message;
    assert_eq!((m.id, m.questions.len()), (0x1234, 1));
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].data, RData::A("10.0.0.10".parse().unwrap()));
    assert_eq!(m.answers[0].ttl, LEGACY_TTL);
    assert!(!m.answers[0].cache_flush());
    assert!(m.additionals.is_empty());
    assert!(
        notes[0]
            .1
            .contains(&("mode".to_owned(), "legacy-unicast".to_owned()))
    );

    // A multicast query from port 5353: answered to the group, the other family as additional.
    let q = Message::query(0, "alice.local", rtype::AAAA);
    let (p, _) = r.on_packet(now, sa("[fe80::20]:5353"), true, &q.encode(), &addrs());
    assert_eq!(p[0].to, Dest::Group { v6: true });
    assert_eq!(p[0].message.id, 0);
    assert_eq!(p[0].message.answers[0].data.text(), "fd00::10");
    assert_eq!(p[0].message.additionals[0].data.text(), "10.0.0.10");
    // The QU bit: unicast to the querier's port 5353.
    let mut q = Message::query(0, "alice.local", rtype::A);
    q.questions[0].qclass |= MDNS_CLASS_BIT;
    let (p, _) = r.on_packet(now, sa("10.0.0.20:5353"), false, &q.encode(), &addrs());
    assert_eq!(p[0].to, Dest::Unicast(sa("10.0.0.20:5353")));
    // Known-answer suppression: the querier already has the A record.
    let mut q = Message::query(0, "alice.local", rtype::A);
    q.answers.push(Record {
        name: "alice.local".into(),
        rtype: rtype::A,
        class: CLASS_IN,
        ttl: 100,
        data: RData::A("10.0.0.10".parse().unwrap()),
    });
    let (p, _) = r.on_packet(now, sa("10.0.0.20:5353"), false, &q.encode(), &addrs());
    assert!(p.is_empty());
    // Other names, other types, garbage: nothing.
    for q in [
        Message::query(0, "bob.local", rtype::A).encode(),
        Message::query(0, "alice.local", rtype::MX).encode(),
        b"junk".to_vec(),
    ] {
        assert!(
            r.on_packet(now, sa("10.0.0.20:5353"), false, &q, &addrs())
                .0
                .is_empty()
        );
    }
}

#[test]
fn a_conflict_while_probing_picks_the_next_name() {
    let mut alice = responder("alice");
    boot(&mut alice);
    let mut carol = responder("alice");
    let t = 10_000 * MS;
    // Carol's first probe (QU) reaches alice, who owns the name: she defends it by unicast.
    let (probe, _) = carol.tick(
        t + carol.next_deadline().unwrap(),
        &["10.0.0.30".parse().unwrap()],
    );
    let (defence, _) = alice.on_packet(
        t,
        sa("10.0.0.30:5353"),
        false,
        &probe[0].message.encode(),
        &addrs(),
    );
    assert_eq!(defence[0].to, Dest::Unicast(sa("10.0.0.30:5353")));
    let (_, notes) = carol.on_packet(
        t,
        sa("10.0.0.10:5353"),
        false,
        &defence[0].message.encode(),
        &["10.0.0.30".parse().unwrap()],
    );
    let kinds: Vec<&str> = notes.iter().map(|n| n.0).collect();
    assert_eq!(kinds, ["mdns-conflict", "mdns-renamed"]);
    assert_eq!(carol.name, "alice-2.local");
    assert_eq!(carol.next_deadline(), Some(t), "it probes again at once");
    let (probe, notes) = carol.tick(t, &["10.0.0.30".parse().unwrap()]);
    assert_eq!(probe[0].message.questions[0].name, "alice-2.local");
    assert!(notes[0].1.contains(&("attempt".to_owned(), "2".to_owned())));
}

#[test]
fn new_addresses_are_announced_again() {
    let mut r = responder("web");
    // No usable address yet (a lease to come): the probe waits.
    let at = r.next_deadline().unwrap();
    let (p, _) = r.tick(at, &["fe80::1".parse().unwrap()]);
    assert!(p.is_empty());
    boot(&mut r);
    let now = 9_000 * MS;
    let mut more = addrs();
    more.push("10.0.0.99".parse().unwrap());
    let (p, notes) = r.tick(now, &more);
    assert_eq!(p.len(), 2);
    assert_eq!(p[0].message.answers.len(), 3);
    assert_eq!(notes[0].0, "mdns-announced");
}

#[test]
fn two_hosts_probing_for_one_name_break_the_tie() {
    // RFC 6762 §8.2: both start probing `alice.local` at the same instant (the delay follows the
    // name). Every packet reaches the other host 100 µs later.
    let only_v4 = || {
        Responder::new(
            Config::from_pairs(pairs(&[("hostname", "alice"), ("families", "ipv4")])).unwrap(),
        )
    };
    let mut hosts = [only_v4(), only_v4()];
    let addr: [Vec<IpAddr>; 2] = [
        vec!["10.0.0.10".parse().unwrap()],
        vec!["10.0.0.20".parse().unwrap()],
    ];
    let lat = 100_000;
    // (time, order) -> (receiver, payload)
    let mut queue: std::collections::BTreeMap<(u64, u64), (usize, Vec<u8>)> = Default::default();
    let mut order = 0;
    let mut notes: Vec<(usize, Note)> = Vec::new();
    loop {
        let timer = (0..2)
            .filter_map(|i| hosts[i].next_deadline().map(|t| (t, i)))
            .min();
        let frame = queue.first_key_value().map(|(k, _)| k.0);
        let (now, packets, sender) = match (timer, frame) {
            (None, None) => break,
            (t, Some(f)) if t.is_none_or(|(t, _)| f <= t) => {
                let (_, (to, payload)) = queue.pop_first().unwrap();
                let from = SocketAddr::new(addr[1 - to][0], MDNS_PORT);
                let (p, n) = hosts[to].on_packet(f, from, false, &payload, &addr[to]);
                notes.extend(n.into_iter().map(|n| (to, n)));
                (f, p, to)
            }
            (Some((t, i)), _) => {
                let (p, n) = hosts[i].tick(t, &addr[i]);
                notes.extend(n.into_iter().map(|n| (i, n)));
                (t, p, i)
            }
            (None, Some(_)) => unreachable!(),
        };
        assert!(now < 30 * 1_000 * MS, "they never settle: {notes:?}");
        for p in packets {
            queue.insert((now + lat, order), (1 - sender, p.message.encode()));
            order += 1;
        }
    }
    assert!(hosts.iter().all(Responder::is_ready));
    // 10.0.0.10 sorts before 10.0.0.20: the first host loses and renames once; the second keeps
    // the name.
    assert_eq!(hosts[0].name, "alice-2.local");
    assert_eq!(hosts[1].name, "alice.local");
    let count = |host: usize, kind: &str| {
        notes
            .iter()
            .filter(|(h, n)| *h == host && n.0 == kind)
            .count()
    };
    assert!(count(0, "mdns-probe-lost") >= 1, "{notes:?}");
    assert_eq!(count(1, "mdns-probe-lost"), 0, "{notes:?}");
    assert_eq!(count(0, "mdns-renamed"), 1, "{notes:?}");
    assert_eq!(count(1, "mdns-renamed"), 0, "{notes:?}");
}

#[test]
fn a_response_with_our_own_data_is_no_conflict() {
    // RFC 6762 §9: a conflict is the same name and type with other rdata.
    let mut r = responder("alice");
    boot(&mut r);
    let response = |data: &str| {
        let mut m = Message {
            flags: 0x8400,
            ..Message::default()
        };
        m.answers.push(Record {
            name: "alice.local".into(),
            rtype: rtype::A,
            class: CLASS_IN | MDNS_CLASS_BIT,
            ttl: 120,
            data: RData::A(data.parse().unwrap()),
        });
        m.encode()
    };
    let now = 9_000 * MS;
    let (_, notes) = r.on_packet(
        now,
        sa("10.0.0.30:5353"),
        false,
        &response("10.0.0.10"),
        &addrs(),
    );
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(r.name, "alice.local");
    let (_, notes) = r.on_packet(
        now,
        sa("10.0.0.30:5353"),
        false,
        &response("10.0.0.30"),
        &addrs(),
    );
    assert_eq!(notes[0].0, "mdns-conflict");
    assert_eq!(r.name, "alice-2.local");
}

#[test]
fn a_host_name_has_no_underscore() {
    assert!(Config::from_pairs(pairs(&[("hostname", "a_b")])).is_err());
}
