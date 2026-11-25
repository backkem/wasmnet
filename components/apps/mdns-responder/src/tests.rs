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

// ---- Services (DNS-SD) -------------------------------------------------------------------------

fn with_services(extra: &[(&str, &str)]) -> Responder {
    let mut p = vec![("hostname", "alpha")];
    p.extend_from_slice(extra);
    Responder::new(Config::from_pairs(pairs(&p)).unwrap())
}

const WEB: [(&str, &str); 4] = [
    ("service.web.instance", "Alpha Web"),
    ("service.web.type", "_http._tcp"),
    ("service.web.port", "80"),
    ("service.web.txt", "path=/,secure"),
];

fn ptr_data(r: &Record) -> String {
    match &r.data {
        RData::Ptr(n) => n.clone(),
        other => panic!("not a PTR: {other:?}"),
    }
}

fn types_of(rs: &[Record]) -> Vec<u16> {
    rs.iter().map(|r| r.rtype).collect()
}

fn s(v: &str) -> String {
    v.to_owned()
}

/// Runs the timers up to the first probe of a service.
fn up_to_service_probe(r: &mut Responder) {
    loop {
        let at = r.next_deadline().unwrap();
        let (p, _) = r.tick(at, &addrs());
        let service_probe = p.iter().any(|p| {
            p.message
                .questions
                .iter()
                .any(|q| q.name.starts_with("Alpha Web"))
        });
        if service_probe {
            return;
        }
    }
}

#[test]
fn service_config_keys_and_errors() {
    let mut p = WEB.to_vec();
    p.extend([
        ("service.files.instance", "Alpha, the files"),
        ("service.files.type", "_HTTP._tcp"),
        ("service.files.port", "8080"),
        ("service.files.txt", "note=a\\, b, empty=, flag"),
        ("service.files.until", "20s"),
        ("service-ttl", "10s"),
    ]);
    let r = with_services(&p);
    let c = &r.config;
    assert_eq!(c.service_ttl, 10);
    // In id order: files, web.
    assert_eq!(c.services[0].id, "files");
    assert_eq!(c.services[0].service_type, "_http._tcp", "stored lowercase");
    assert_eq!(c.services[0].until_ns, Some(20_000 * MS));
    assert_eq!(
        c.services[0].txt,
        [
            (s("note"), Some(b"a, b".to_vec())),
            (s("empty"), Some(Vec::new())),
            (s("flag"), None),
        ]
    );
    assert_eq!(c.services[1].port, 80);
    assert_eq!(services::split_txt("a\\\\,b\\x"), [s("a\\"), s("b\\x")]);
    let one = |extra: &[(&'static str, &'static str)]| {
        let mut p = vec![
            ("service.a.instance", "A"),
            ("service.a.type", "_http._tcp"),
            ("service.a.port", "1"),
        ];
        for (k, v) in extra {
            match p.iter_mut().find(|(k2, _)| k2 == k) {
                Some(e) => e.1 = v,
                None => p.push((k, v)),
            }
        }
        p
    };
    for (p, needle) in [
        (
            vec![
                ("service.a.instance", "A"),
                ("service.a.type", "_http._tcp"),
            ],
            "port",
        ),
        (one(&[("service.a.type", "http")]), "_<name>._tcp"),
        (one(&[("service.a.port", "0")]), "1 to 65535"),
        (one(&[("service.a.colour", "red")]), "unknown"),
        (one(&[("service.a.b.instance", "x")]), "unknown"),
        (one(&[("service.a.txt", "k=1,K=2")]), "no key twice"),
        (one(&[("service.a.instance", "a\u{7}")]), "control"),
        (
            one(&[
                ("service.b.instance", "a"),
                ("service.b.type", "_http._tcp"),
                ("service.b.port", "2"),
            ]),
            "no other service",
        ),
    ] {
        let mut all = vec![("hostname", "alpha")];
        all.extend(p);
        let err = Config::from_pairs(pairs(&all)).unwrap_err().to_string();
        assert!(err.contains(needle), "{err}");
    }
}

#[test]
fn services_probe_after_the_host_name_then_announce_with_rfc_6763_records() {
    let mut r = with_services(&WEB);
    let (packets, notes) = boot(&mut r);
    assert!(r.is_ready() && r.services_ready());
    // Host: 3 probes and 2 announcements; the service: 3 probes and 2 announcements, each to
    // both groups. The service starts after the host name's first announcement.
    let svc: Vec<(u64, &Message)> = packets
        .iter()
        .step_by(2)
        .map(|(t, p)| (*t, &p.message))
        .filter(|(_, m)| {
            m.questions.iter().any(|q| q.name.starts_with("Alpha"))
                || m.answers.iter().any(|r| r.rtype == rtype::SRV)
        })
        .collect();
    assert_eq!(packets.len(), 20);
    assert_eq!(svc.len(), 5);
    let host_announced = packets[6].0;
    assert!(packets[6].1.message.is_response());
    assert!(
        svc[0].0 >= host_announced,
        "after the host name's announcement"
    );
    let probe = svc[0].1;
    assert_eq!(probe.questions[0].name, "Alpha Web._http._tcp.local");
    assert_eq!(probe.questions[0].qtype, rtype::ANY);
    assert!(
        probe.questions[0].unicast_response(),
        "QU on the first probe"
    );
    assert!(!svc[1].1.questions[0].unicast_response());
    assert_eq!(types_of(&probe.authorities), [rtype::SRV, rtype::TXT]);
    let t0 = svc[0].0;
    assert_eq!(
        svc.iter().map(|(t, _)| t - t0).collect::<Vec<_>>(),
        [0, 250 * MS, 500 * MS, 750 * MS, 1_750 * MS]
    );
    let a = svc[3].1;
    assert!(a.is_response() && a.authoritative());
    assert_eq!(
        types_of(&a.answers),
        [rtype::PTR, rtype::PTR, rtype::SRV, rtype::TXT]
    );
    assert_eq!(a.answers[0].name, "_http._tcp.local");
    assert_eq!(ptr_data(&a.answers[0]), "Alpha Web._http._tcp.local");
    assert_eq!(a.answers[1].name, dns::DNS_SD_SERVICES);
    assert_eq!(ptr_data(&a.answers[1]), "_http._tcp.local");
    assert!(!a.answers[0].cache_flush(), "PTRs are shared");
    assert!(a.answers[2].cache_flush() && a.answers[3].cache_flush());
    assert_eq!(a.answers[2].data.text(), "0 0 80 alpha.local");
    assert_eq!(a.answers[2].ttl, 120);
    assert_eq!(
        a.answers[3].data,
        RData::Txt(vec![b"path=/".to_vec(), b"secure".to_vec()])
    );
    assert_eq!(a.answers[3].ttl, 4500);
    assert_eq!(
        types_of(&a.additionals),
        [rtype::A, rtype::AAAA],
        "both families: no NSEC"
    );
    assert_eq!(Message::parse(&a.encode()).unwrap(), *a);
    let kinds: Vec<&str> = notes.iter().map(|n| n.0).collect();
    assert_eq!(
        kinds,
        [
            "mdns-probing",
            "mdns-announced",
            "mdns-service-probing",
            "mdns-service-announced"
        ]
    );
    assert!(notes[3].1.contains(&(s("target"), s("alpha.local"))));
}

#[test]
fn a_host_with_one_family_says_so_with_nsec() {
    let mut r = with_services(&WEB);
    let v4: Vec<IpAddr> = vec!["10.0.0.10".parse().unwrap()];
    let mut last = None;
    while let Some(at) = r.next_deadline() {
        let (p, _) = r.tick(at, &v4);
        if let Some(p) = p.into_iter().find(|p| p.message.is_response()) {
            last = Some(p.message);
        }
    }
    let a = last.unwrap();
    assert_eq!(types_of(&a.additionals), [rtype::A, rtype::NSEC]);
    assert_eq!(
        a.additionals[1].data,
        RData::Nsec {
            next: "alpha.local".into(),
            types: vec![rtype::A]
        }
    );
}

fn mdns_query(name: &str, t: u16) -> Message {
    let mut q = Message::query(0, name, t);
    q.flags = 0;
    q
}

#[test]
fn service_questions_are_answered() {
    let mut r = with_services(&WEB);
    boot(&mut r);
    let now = 10_000 * MS;
    let ask = |r: &mut Responder, from: &str, q: Message| {
        r.on_packet(now, sa(from), false, &q.encode(), &addrs())
    };

    // The meta-query: a shared answer, so held back 20-120 ms, then to the group.
    let (p, notes) = ask(
        &mut r,
        "10.0.0.20:5353",
        mdns_query(dns::DNS_SD_SERVICES, rtype::PTR),
    );
    assert!(p.is_empty(), "held back");
    assert_eq!(notes[0].0, "mdns-answered");
    let at = r.next_deadline().unwrap();
    assert!((now + 20 * MS..=now + 120 * MS).contains(&at), "{at}");
    let (p, _) = r.tick(at, &addrs());
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].to, Dest::Group { v6: false });
    assert_eq!(ptr_data(&p[0].message.answers[0]), "_http._tcp.local");

    // Browsing the type: the PTR, and SRV, TXT and the addresses as additional records.
    ask(
        &mut r,
        "10.0.0.20:5353",
        mdns_query("_http._tcp.local", rtype::PTR),
    );
    let at = r.next_deadline().unwrap();
    let (p, _) = r.tick(at, &addrs());
    let m = &p[0].message;
    assert_eq!(types_of(&m.answers), [rtype::PTR]);
    assert_eq!(
        types_of(&m.additionals),
        [rtype::SRV, rtype::TXT, rtype::A, rtype::AAAA]
    );

    // Known-answer suppression: the browser holds the PTR with more than half its TTL left.
    let mut q = mdns_query("_http._tcp.local", rtype::PTR);
    q.answers.push(Record {
        name: "_http._tcp.local".into(),
        rtype: rtype::PTR,
        class: CLASS_IN,
        ttl: 3000,
        data: RData::Ptr("Alpha Web._http._tcp.local".into()),
    });
    let (p, notes) = ask(&mut r, "10.0.0.20:5353", q.clone());
    assert!(p.is_empty() && notes.is_empty() && r.next_deadline().is_none());
    // Less than half left: answered.
    q.answers[0].ttl = 2000;
    ask(&mut r, "10.0.0.20:5353", q);
    let (p, _) = r.tick(r.next_deadline().unwrap(), &addrs());
    assert_eq!(p.len(), 1);

    // Resolving the instance with the QU bit: SRV and TXT unicast at once.
    let mut q = mdns_query("alpha WEB._http._tcp.local", rtype::ANY);
    q.questions[0].qclass |= MDNS_CLASS_BIT;
    let (p, _) = ask(&mut r, "10.0.0.20:5353", q);
    assert_eq!(p[0].to, Dest::Unicast(sa("10.0.0.20:5353")));
    assert_eq!(types_of(&p[0].message.answers), [rtype::SRV, rtype::TXT]);
    assert_eq!(types_of(&p[0].message.additionals), [rtype::A, rtype::AAAA]);

    // A one-shot querier: its id and question, TTLs of at most 10 s, no cache-flush bits.
    let q = Message::query(0x4242, "Alpha Web._http._tcp.local", rtype::SRV);
    let (p, _) = ask(&mut r, "10.0.0.20:40000", q);
    let m = &p[0].message;
    assert_eq!((m.id, m.questions.len()), (0x4242, 1));
    assert!(
        m.answers
            .iter()
            .chain(&m.additionals)
            .all(|r| r.ttl <= LEGACY_TTL && !r.cache_flush())
    );

    // A type the instance does not have: NSEC (RFC 6762 §6.1).
    let (p, _) = ask(
        &mut r,
        "10.0.0.20:5353",
        mdns_query("Alpha Web._http._tcp.local", rtype::A),
    );
    assert_eq!(
        p[0].message.answers[0].data,
        RData::Nsec {
            next: "Alpha Web._http._tcp.local".into(),
            types: vec![rtype::TXT, rtype::SRV]
        }
    );
    // Another type, another instance: nothing.
    for q in [
        mdns_query("_ipp._tcp.local", rtype::PTR),
        mdns_query("Beta Web._http._tcp.local", rtype::SRV),
    ] {
        let (p, notes) = ask(&mut r, "10.0.0.20:5353", q);
        assert!(p.is_empty() && notes.is_empty());
    }
}

/// A response that claims `instance` with `target` as its SRV's host.
fn claim(instance: &str, target: &str) -> Vec<u8> {
    let mut m = Message {
        flags: 0x8400,
        ..Message::default()
    };
    m.answers.push(Record {
        name: dns::instance_name(instance, "_http._tcp", "local"),
        rtype: rtype::SRV,
        class: CLASS_IN | MDNS_CLASS_BIT,
        ttl: 120,
        data: RData::Srv {
            priority: 0,
            weight: 0,
            port: 80,
            target: target.into(),
        },
    });
    m.encode()
}

#[test]
fn a_conflicting_instance_name_is_renamed() {
    let mut r = with_services(&WEB);
    up_to_service_probe(&mut r);
    let now = r.next_deadline().unwrap() - 1;
    let from = sa("10.0.0.30:5353");
    // The owner of `Alpha Web` defends it: a conflict, while probing.
    let (_, notes) = r.on_packet(
        now,
        from,
        false,
        &claim("Alpha Web", "gamma.local"),
        &addrs(),
    );
    let kinds: Vec<&str> = notes.iter().map(|n| n.0).collect();
    assert_eq!(kinds, ["mdns-service-conflict", "mdns-service-renamed"]);
    assert!(notes[1].1.contains(&(s("to"), s("Alpha Web (2)"))));
    assert_eq!(r.next_deadline(), Some(now), "probes again at once");
    let (p, notes) = r.tick(now, &addrs());
    assert_eq!(
        p[0].message.questions[0].name,
        "Alpha Web (2)._http._tcp.local"
    );
    assert!(notes[0].1.contains(&(s("attempt"), s("2"))));
    boot(&mut r);
    assert!(r.service_live("Alpha Web (2)"));
    // Our own data again, or a goodbye: no conflict. Someone else's: the next name.
    let later = 20_000 * MS;
    let own = claim("Alpha Web (2)", "alpha.local");
    let (_, notes) = r.on_packet(later, from, false, &own, &addrs());
    assert!(notes.is_empty(), "{notes:?}");
    let mut bye = Message::parse(&claim("Alpha Web (2)", "gamma.local")).unwrap();
    bye.answers[0].ttl = 0;
    let (_, notes) = r.on_packet(later, from, false, &bye.encode(), &addrs());
    assert!(notes.is_empty(), "{notes:?}");
    let theirs = claim("Alpha Web (2)", "gamma.local");
    let (_, notes) = r.on_packet(later, from, false, &theirs, &addrs());
    assert_eq!(notes[1].0, "mdns-service-renamed");
    assert_eq!(r.service_instances()[0].0, "Alpha Web (3)");
}

#[test]
fn a_renamed_long_instance_stays_within_63_bytes() {
    let long = "é".repeat(31); // 62 bytes
    let mut r = with_services(&[
        ("service.x.instance", &long),
        ("service.x.type", "_http._tcp"),
        ("service.x.port", "80"),
    ]);
    boot(&mut r);
    let theirs = claim(&long, "gamma.local");
    r.on_packet(20_000 * MS, sa("10.0.0.30:5353"), false, &theirs, &addrs());
    let renamed = r.service_instances()[0].0.clone();
    assert!(
        renamed.len() <= 63 && renamed.ends_with(" (2)"),
        "{renamed}"
    );
    assert!(dns::valid_instance(&renamed));
}

#[test]
fn two_hosts_probing_for_one_instance_break_the_tie() {
    // Their proposal: an SRV and a TXT of one string; records sort by type first (TXT 16, SRV 33),
    // then by data, so the TXT decides: ours begins with the length byte 6 (`path=/`).
    let probe_from = |txt: &str| {
        let mut q = Message::default();
        q.questions.push(Question {
            name: "Alpha Web._http._tcp.local".into(),
            qtype: rtype::ANY,
            qclass: CLASS_IN,
        });
        let srv = Message::parse(&claim("Alpha Web", "zulu.local"))
            .unwrap()
            .answers[0]
            .clone();
        q.authorities.push(Record {
            class: CLASS_IN,
            ..srv
        });
        q.authorities.push(Record {
            name: "Alpha Web._http._tcp.local".into(),
            rtype: rtype::TXT,
            class: CLASS_IN,
            ttl: 4500,
            data: RData::Txt(vec![txt.as_bytes().to_vec()]),
        });
        q.encode()
    };
    let from = sa("10.0.0.40:5353");
    // A string of 7 bytes sorts after ours: we lose and wait a second.
    let mut r = with_services(&WEB);
    up_to_service_probe(&mut r);
    let now = r.next_deadline().unwrap() - 1;
    let (_, notes) = r.on_packet(now, from, false, &probe_from("zzzzzzz"), &addrs());
    assert_eq!(notes[0].0, "mdns-service-probe-lost");
    // No service probe until a second has passed, then the first again (with QU).
    loop {
        let at = r.next_deadline().unwrap();
        let (p, _) = r.tick(at, &addrs());
        let probes: Vec<&Question> = p
            .iter()
            .flat_map(|p| &p.message.questions)
            .filter(|q| q.name.starts_with("Alpha Web"))
            .collect();
        if at < now + TIEBREAK_DEFER_NS {
            assert!(probes.is_empty(), "at {at}");
        } else {
            assert_eq!(at, now + TIEBREAK_DEFER_NS);
            assert!(probes[0].unicast_response());
            break;
        }
    }
    // An empty string sorts before ours: we win and go on.
    let mut r = with_services(&WEB);
    up_to_service_probe(&mut r);
    let (_, notes) = r.on_packet(now, from, false, &probe_from(""), &addrs());
    assert!(notes.is_empty(), "{notes:?}");
}

#[test]
fn a_withdrawn_service_says_goodbye() {
    let mut p = WEB.to_vec();
    p.extend([
        ("service.files.instance", "Alpha Files"),
        ("service.files.type", "_ftp._tcp"),
        ("service.files.port", "21"),
        ("service.files.until", "30s"),
    ]);
    let mut r = with_services(&p);
    let (packets, notes) = boot(&mut r);
    let (at, bye) = packets.last().unwrap();
    assert_eq!(*at, 30_000 * MS);
    let m = &bye.message;
    assert!(m.answers.iter().all(|r| r.ttl == 0));
    assert_eq!(
        types_of(&m.answers),
        [rtype::PTR, rtype::SRV, rtype::TXT, rtype::PTR],
        "and the type's meta PTR: no other _ftp._tcp service is left"
    );
    assert_eq!(ptr_data(&m.answers[3]), "_ftp._tcp.local");
    assert_eq!(notes.last().unwrap().0, "mdns-service-withdrawn");
    assert_eq!(r.service_instances(), [(s("Alpha Web"), s("_http._tcp"))]);
    // It answers for it no more.
    let q = mdns_query("_ftp._tcp.local", rtype::PTR);
    let (p, notes) = r.on_packet(
        31_000 * MS,
        sa("10.0.0.20:5353"),
        false,
        &q.encode(),
        &addrs(),
    );
    assert!(p.is_empty() && notes.is_empty());
}

#[test]
fn services_follow_a_renamed_host() {
    let mut r = with_services(&WEB);
    boot(&mut r);
    // Someone else owns `alpha.local`: the host renames, the service waits, then is announced
    // again with the new target.
    let mut m = Message {
        flags: 0x8400,
        ..Message::default()
    };
    m.answers.push(Record {
        name: "alpha.local".into(),
        rtype: rtype::A,
        class: CLASS_IN | MDNS_CLASS_BIT,
        ttl: 120,
        data: RData::A("10.0.0.99".parse().unwrap()),
    });
    r.on_packet(
        20_000 * MS,
        sa("10.0.0.99:5353"),
        false,
        &m.encode(),
        &addrs(),
    );
    assert_eq!(r.name, "alpha-2.local");
    let (_, notes) = boot(&mut r);
    let announced: Vec<&Note> = notes
        .iter()
        .filter(|n| n.0 == "mdns-service-announced")
        .collect();
    assert_eq!(announced.len(), 1);
    assert!(announced[0].1.contains(&(s("target"), s("alpha-2.local"))));
}

#[test]
fn without_services_nothing_changes() {
    let mut r = responder("alice");
    let (packets, _) = boot(&mut r);
    assert_eq!(packets.len(), 10);
    assert!(r.next_deadline().is_none());
    let q = mdns_query(dns::DNS_SD_SERVICES, rtype::PTR);
    let (p, n) = r.on_packet(
        5_000 * MS,
        sa("10.0.0.20:5353"),
        false,
        &q.encode(),
        &addrs(),
    );
    assert!(p.is_empty() && n.is_empty());
}
