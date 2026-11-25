use super::*;

const S: u64 = SECOND;
const NAME: &str = "Alpha Web._http._tcp.local";

fn rec(name: &str, rtype: u16, ttl: u32, flush: bool, data: RData) -> Record {
    Record {
        name: name.into(),
        rtype,
        class: if flush {
            CLASS_IN | MDNS_CLASS_BIT
        } else {
            CLASS_IN
        },
        ttl,
        data,
    }
}

fn ptr(ttl: u32) -> Record {
    rec(
        "_http._tcp.local",
        rtype::PTR,
        ttl,
        false,
        RData::Ptr(NAME.into()),
    )
}

fn srv(port: u16, ttl: u32) -> Record {
    rec(
        NAME,
        rtype::SRV,
        ttl,
        true,
        RData::Srv {
            priority: 0,
            weight: 0,
            port,
            target: "alpha.local".into(),
        },
    )
}

fn txt() -> Record {
    rec(
        NAME,
        rtype::TXT,
        4500,
        true,
        RData::Txt(vec![b"path=/".to_vec()]),
    )
}

fn a() -> Record {
    rec(
        "alpha.local",
        rtype::A,
        120,
        true,
        RData::A("10.0.0.10".parse().unwrap()),
    )
}

fn response(answers: Vec<Record>, additionals: Vec<Record>) -> Vec<u8> {
    Message {
        flags: 0x8400,
        answers,
        additionals,
        ..Message::default()
    }
    .encode()
}

/// Ticks until `until` (exclusive); returns each query's time and message, and every event.
type Timed<T> = Vec<(u64, T)>;

fn run(b: &mut Browser, until: u64) -> (Timed<Message>, Timed<Event>) {
    let mut queries = Vec::new();
    let mut events = Vec::new();
    while let Some(at) = b.next_deadline().filter(|t| *t < until) {
        let (q, e) = b.tick(at);
        queries.extend(q.into_iter().map(|q| (at, q)));
        events.extend(e.into_iter().map(|e| (at, e)));
    }
    (queries, events)
}

#[test]
fn browsing_backs_off_from_one_second_to_an_hour() {
    let mut b = Browser::new(7);
    b.browse(0, "_http._tcp");
    let first = b.next_deadline().unwrap();
    assert!((20 * MS..=120 * MS).contains(&first), "{first}");
    let (queries, events) = run(&mut b, 30 * 3_600 * S);
    assert!(events.is_empty());
    let q = &queries[0].1;
    assert_eq!(q.questions[0].name, "_http._tcp.local");
    assert_eq!(q.questions[0].qtype, rtype::PTR);
    assert!(!q.questions[0].unicast_response() && !q.is_response() && q.id == 0);
    let gaps: Vec<u64> = queries.windows(2).map(|w| (w[1].0 - w[0].0) / S).collect();
    assert_eq!(
        &gaps[..13],
        [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 3600]
    );
    assert!(gaps[13..].iter().all(|g| *g == 3600), "{gaps:?}");
    // Another seed, another delay; browsing twice changes nothing.
    let mut c = Browser::new(8);
    c.browse(0, "_http._tcp");
    c.browse(0, "_http._tcp");
    assert_ne!(c.next_deadline(), Some(first));
    assert_eq!(c.tick(c.next_deadline().unwrap()).0[0].questions.len(), 1);
}

#[test]
fn an_instance_is_found_and_held_as_a_known_answer() {
    let mut b = Browser::new(1);
    b.browse(0, "_http._tcp");
    let (q, _) = run(&mut b, 200 * MS);
    assert!(q[0].1.answers.is_empty(), "nothing known yet");
    let events = b.on_message(
        500 * MS,
        &response(vec![ptr(4500)], vec![srv(80, 120), txt(), a()]),
    );
    assert_eq!(
        events,
        [Event::Found {
            service_type: "_http._tcp".into(),
            instance: "Alpha Web".into(),
            name: NAME.into(),
        }]
    );
    assert_eq!(b.instances("_http._tcp"), [NAME]);
    // The same answer again is no news.
    assert!(
        b.on_message(600 * MS, &response(vec![ptr(4500)], vec![]))
            .is_empty()
    );
    // The next query lists it, with its TTL left.
    let (q, _) = run(&mut b, 2 * S);
    let known = &q[0].1.answers;
    assert_eq!(known.len(), 1);
    assert_eq!(known[0].data, RData::Ptr(NAME.into()));
    assert!((4498..=4500).contains(&known[0].ttl), "{}", known[0].ttl);
    // At 80 % of its TTL it is asked for again, and is no known answer (less than half left).
    let (q, _) = run(&mut b, 3_700 * S);
    let late = q.last().unwrap();
    assert!(late.0 >= 3_600 * S && late.1.answers.is_empty(), "{late:?}");
}

#[test]
fn a_record_is_refreshed_at_80_to_95_percent_then_expires() {
    let mut b = Browser::new(3);
    b.browse(0, "_http._tcp");
    run(&mut b, 200 * MS);
    let t0 = S;
    b.on_message(t0, &response(vec![ptr(100)], vec![]));
    let (queries, events) = run(&mut b, t0 + 101 * S);
    // Browse queries go on (at 1, 3, 7, 15, 31, 63 s ...) beside the refreshes.
    let refreshes: Vec<u64> = queries
        .iter()
        .map(|(t, _)| t - t0)
        .filter(|t| *t >= 80 * S)
        .collect();
    assert_eq!(refreshes.len(), 4, "{refreshes:?}");
    for (i, t) in refreshes.iter().enumerate() {
        let pct = 80 + 5 * i as u64;
        assert!((pct * S..=(pct + 2) * S).contains(t), "refresh {i} at {t}");
    }
    assert_eq!(
        events,
        [(
            t0 + 100 * S,
            Event::Removed {
                service_type: "_http._tcp".into(),
                instance: "Alpha Web".into(),
                name: NAME.into(),
                reason: Removal::Expired,
            }
        )]
    );
    assert!(b.instances("_http._tcp").is_empty());
}

#[test]
fn an_answered_refresh_keeps_the_instance() {
    let mut b = Browser::new(3);
    b.browse(0, "_http._tcp");
    run(&mut b, 200 * MS);
    b.on_message(S, &response(vec![ptr(100)], vec![]));
    let (_, events) = run(&mut b, 82 * S);
    assert!(events.is_empty());
    b.on_message(82 * S, &response(vec![ptr(100)], vec![]));
    let (_, events) = run(&mut b, 150 * S);
    assert!(events.is_empty(), "{events:?}");
    assert_eq!(b.instances("_http._tcp").len(), 1);
}

#[test]
fn a_goodbye_removes_the_instance_a_second_later() {
    let mut b = Browser::new(3);
    b.browse(0, "_http._tcp");
    b.on_message(S, &response(vec![ptr(4500)], vec![]));
    b.on_message(10 * S, &response(vec![ptr(0)], vec![]));
    let (_, events) = run(&mut b, 20 * S);
    assert_eq!(
        events,
        [(
            11 * S,
            Event::Removed {
                service_type: "_http._tcp".into(),
                instance: "Alpha Web".into(),
                name: NAME.into(),
                reason: Removal::Goodbye,
            }
        )]
    );
}

#[test]
fn an_instance_resolves_from_the_cache_or_by_asking() {
    // From the additional records of the browse answer: no query needed.
    let mut b = Browser::new(5);
    b.browse(0, "_http._tcp");
    b.on_message(
        S,
        &response(vec![ptr(4500)], vec![srv(80, 120), txt(), a()]),
    );
    b.resolve(2 * S, NAME);
    let (q, events) = b.tick(2 * S);
    assert!(
        q.iter()
            .all(|q| q.questions.iter().all(|q| q.qtype == rtype::PTR))
    );
    let Event::Resolved(r) = &events[0] else {
        panic!("{events:?}")
    };
    assert_eq!(
        (r.instance.as_str(), r.host.as_str(), r.port),
        ("Alpha Web", "alpha.local", 80)
    );
    assert_eq!(r.addresses, ["10.0.0.10".parse::<IpAddr>().unwrap()]);
    assert_eq!(r.attributes_text(), "path=/");

    // With nothing cached: SRV and TXT first, then the host's addresses, retried with back-off.
    let mut b = Browser::new(5);
    b.resolve(0, NAME);
    let (q, events) = b.tick(0);
    assert!(events.is_empty());
    let asked: Vec<u16> = q[0].questions.iter().map(|q| q.qtype).collect();
    assert_eq!(asked, [rtype::SRV, rtype::TXT]);
    assert_eq!(b.next_deadline(), Some(S));
    let events = b.on_message(10 * MS, &response(vec![srv(80, 120), txt()], vec![]));
    assert!(events.is_empty(), "no address yet");
    let (q, _) = b.tick(S);
    let asked: Vec<(String, u16)> = q[0]
        .questions
        .iter()
        .map(|q| (q.name.clone(), q.qtype))
        .collect();
    assert_eq!(
        asked,
        [
            ("alpha.local".into(), rtype::A),
            ("alpha.local".into(), rtype::AAAA)
        ]
    );
    assert_eq!(b.next_deadline(), Some(3 * S), "then 2 s later");
    let events = b.on_message(S + 10 * MS, &response(vec![a()], vec![]));
    assert!(matches!(&events[..], [Event::Resolved(r)] if r.port == 80));
    // Complete: no more questions for it; a second identical answer is no news.
    let (q, _) = run(&mut b, 50 * S);
    assert!(q.is_empty(), "{q:?}");
    assert!(
        b.on_message(51 * S, &response(vec![a()], vec![]))
            .is_empty()
    );
}

#[test]
fn a_cache_flush_replaces_old_data() {
    let mut b = Browser::new(5);
    b.resolve(0, NAME);
    b.on_message(MS, &response(vec![srv(80, 120), txt(), a()], vec![]));
    // Later the instance moves to port 8080 (cache-flush bit set): the old SRV goes a second
    // later, and the resolution is reported again.
    let events = b.on_message(10 * S, &response(vec![srv(8080, 120)], vec![]));
    assert!(
        events.is_empty(),
        "both SRVs for a second: the first still wins the order"
    );
    let (_, events) = run(&mut b, 12 * S);
    assert!(
        matches!(&events[..], [(t, Event::Resolved(r))] if *t == 11 * S && r.port == 8080),
        "{events:?}"
    );
}

#[test]
fn queries_garbage_and_unicast_answers() {
    let mut b = Browser::new(5);
    b.browse(0, "_http._tcp");
    // A query (another browser's, with its known answers) teaches nothing.
    let mut q = Message::query(0, "_http._tcp.local", rtype::PTR);
    q.flags = 0;
    q.answers.push(ptr(4500));
    assert!(b.on_message(S, &q.encode()).is_empty());
    assert!(b.on_message(S, b"junk").is_empty());
    // A legacy unicast answer (an id, the question echoed, a short TTL) counts.
    let mut r = Message::parse(&response(vec![ptr(10)], vec![])).unwrap();
    r.id = 0x1234;
    r.questions.push(question("_http._tcp.local", rtype::PTR));
    assert_eq!(b.on_message(S, &r.encode()).len(), 1);
}
