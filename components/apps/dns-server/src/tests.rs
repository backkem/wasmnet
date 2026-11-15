use super::*;

fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
    p.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn server() -> Server {
    Server::new(
        Config::from_pairs(pairs(&[
            ("zone", "internal"),
            ("records.web", "10.0.1.10, fd00:1::10"),
            ("records.infra.internal", "10.0.1.2"),
            ("records.a.deep", "10.0.1.20"),
            ("cname.www", "web"),
            ("cname.out", "example.com."),
            ("ttl", "30s"),
        ]))
        .unwrap(),
    )
}

fn ask(s: &Server, name: &str, qtype: u16) -> Message {
    let q = Message::query(0x1234, name, qtype).encode();
    let (r, note) = s.answer("10.0.2.100:50000", &q);
    assert_eq!(note.unwrap().0, "dns-served");
    Message::parse(&r.unwrap()).unwrap()
}

#[test]
fn config_qualifies_names_and_rejects_mistakes() {
    let c = server().config;
    assert_eq!(c.zones, ["internal"]);
    assert_eq!(c.ttl, 30);
    assert_eq!(c.records["web.internal"].len(), 2);
    assert_eq!(
        c.records["www.internal"],
        [RData::Cname("web.internal".into())]
    );
    assert_eq!(
        c.records["out.internal"],
        [RData::Cname("example.com".into())]
    );
    assert_eq!(c.record_count(), 6);
    for (p, needle) in [
        (pairs(&[("records.web", "10.0.0.1")]), "zone"),
        (
            pairs(&[("zone", "internal"), ("records.web", "nope")]),
            "IP addresses",
        ),
        (
            pairs(&[("zone", "internal"), ("records.a b", "10.0.0.1")]),
            "record name",
        ),
        (
            pairs(&[
                ("zone", "internal"),
                ("records.w", "10.0.0.1"),
                ("cname.w", "x"),
            ]),
            "only record",
        ),
        (pairs(&[("zone", "internal"), ("ttl", "1500ms")]), "ttl"),
        (pairs(&[("zone", "internal"), ("colour", "red")]), "unknown"),
    ] {
        let err = Config::from_pairs(p).unwrap_err().to_string();
        assert!(err.contains(needle), "{err}");
    }
}

#[test]
fn answers_a_aaaa_and_cname_chains_authoritatively() {
    let s = server();
    let r = ask(&s, "WEB.internal", rtype::A);
    assert!(r.is_response() && r.authoritative() && !r.recursion_available());
    assert!(r.recursion_desired(), "RD is copied");
    assert_eq!((r.id, r.rcode()), (0x1234, rcode::NOERROR));
    assert_eq!(r.answers.len(), 1);
    assert_eq!(r.answers[0].data, RData::A("10.0.1.10".parse().unwrap()));
    assert_eq!(r.answers[0].ttl, 30);
    let r = ask(&s, "web.internal", rtype::AAAA);
    assert_eq!(r.answers[0].data.text(), "fd00:1::10");
    let r = ask(&s, "web.internal", rtype::ANY);
    assert_eq!(r.answers.len(), 2);

    let r = ask(&s, "www.internal", rtype::A);
    let data: Vec<String> = r.answers.iter().map(|a| a.data.text()).collect();
    assert_eq!(data, ["web.internal", "10.0.1.10"]);
    // A CNAME out of the zone is answered alone.
    let r = ask(&s, "out.internal", rtype::A);
    assert_eq!(r.answers.len(), 1);
    assert_eq!(r.rcode(), rcode::NOERROR);
    // The SOA at the apex.
    let r = ask(&s, "internal", rtype::SOA);
    assert!(matches!(r.answers[0].data, RData::Soa { .. }));
}

#[test]
fn negative_answers_carry_the_soa() {
    let s = server();
    let r = ask(&s, "nope.internal", rtype::A);
    assert_eq!(r.rcode(), rcode::NXDOMAIN);
    assert!(r.answers.is_empty());
    assert_eq!(r.authorities[0].rtype, rtype::SOA);
    assert_eq!(r.authorities[0].name, "internal");
    // NODATA: the name exists (it has an A record), but no MX.
    let r = ask(&s, "infra.internal", rtype::MX);
    assert_eq!(r.rcode(), rcode::NOERROR);
    assert!(r.answers.is_empty() && !r.authorities.is_empty());
    // An empty non-terminal exists too.
    assert_eq!(ask(&s, "deep.internal", rtype::A).rcode(), rcode::NOERROR);
    assert_eq!(ask(&s, "a.deep.internal", rtype::A).answers.len(), 1);
}

#[test]
fn refused_notimp_formerr_and_silence() {
    let s = server();
    let r = ask(&s, "example.com", rtype::A);
    assert_eq!(r.rcode(), rcode::REFUSED);
    assert!(!r.authoritative());
    let mut q = Message::query(7, "web.internal", rtype::A);
    q.flags |= 2 << 11; // opcode STATUS
    let (r, _) = s.answer("x", &q.encode());
    assert_eq!(Message::parse(&r.unwrap()).unwrap().rcode(), rcode::NOTIMP);
    let mut two = Message::query(8, "web.internal", rtype::A);
    two.questions.push(two.questions[0].clone());
    let (r, _) = s.answer("x", &two.encode());
    assert_eq!(Message::parse(&r.unwrap()).unwrap().rcode(), rcode::FORMERR);
    // A header with garbage after it: FORMERR with the same id.
    let mut junk = Message::query(9, "web.internal", rtype::A).encode();
    junk.truncate(14);
    let (r, _) = s.answer("x", &junk);
    let r = Message::parse(&r.unwrap()).unwrap();
    assert_eq!((r.id, r.rcode()), (9, rcode::FORMERR));
    // Responses and short garbage: no answer at all.
    let resp = Message::response_to(&Message::query(1, "web.internal", rtype::A), 0);
    assert_eq!(s.answer("x", &resp.encode()), (None, None));
    assert_eq!(s.answer("x", b"hi"), (None, None));
}
