//! End to end: DNS-SD service discovery over Multicast DNS (RFC 6763 over RFC 6762).
//!
//! On one switch:
//!
//! * `alpha` (a web server, IPv4 and IPv6) advertises `Alpha Web`, an `_http._tcp` service on
//!   port 80;
//! * `beta` (IPv4 only) advertises two: `Beta Web` on port 80 and `Beta Files` on port 8080,
//!   which it withdraws at 20 s with goodbye packets;
//! * `gamma` starts at 6 s and advertises an `Alpha Web` of its own; `alpha` defends the name,
//!   so `gamma` renames its instance `Alpha Web (2)`. Its cable is pulled at 30 s, so it can say
//!   no goodbye: its records run out by their 10 s TTL;
//! * `browser` browses `_http._tcp`, sees every instance with its port and TXT, resolves
//!   them, and fetches `GET /` from `Alpha Web` by the address and port it resolved.
//!
//! The captures are checked for the records RFC 6763 prescribes, decoded from the frames. The
//! same seed gives the same bytes on every link.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{built, config, datagram, events, field, transcript};
use wasmnet_host::{FrameRecord, JournalEntry, Network, PortRef, Record as Journalled};
use wasmnet_wire::dns::{self, Message, RData, Record, rtype};

const US: u64 = 1_000;
const S: u64 = 1_000_000_000;

struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcaps: Vec<Vec<u8>>,
    ports: Ports,
}

#[derive(Clone, Copy)]
struct Ports {
    alpha: PortRef,
    beta: PortRef,
    gamma: PortRef,
    browser: PortRef,
}

fn discovery(seed: u64) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let sw = network
        .device_with_config(
            "sw",
            &b.load("switch"),
            config(&[("ports", "5"), ("aging", "60s")]),
        )
        .unwrap();
    let alpha = network
        .device_with_config(
            "alpha",
            &b.load("node-mdns-web"),
            config(&[
                ("mac", "02:00:00:00:00:10"),
                ("ipv4", "10.0.0.10/24"),
                ("ipv6", "fd00::10/64"),
                ("app.http-server.listen", "10.0.0.10:80,[fd00::10]:80"),
                ("app.http-server.route.index.path", "/"),
                ("app.http-server.route.index.body", "hello from alpha"),
                ("app.mdns-responder.hostname", "alpha"),
                ("app.mdns-responder.service.web.instance", "Alpha Web"),
                ("app.mdns-responder.service.web.type", "_http._tcp"),
                ("app.mdns-responder.service.web.port", "80"),
                ("app.mdns-responder.service.web.txt", "path=/"),
            ]),
        )
        .unwrap();
    let beta = network
        .device_with_config(
            "beta",
            &b.load("node-mdns-web"),
            config(&[
                ("mac", "02:00:00:00:00:11"),
                ("ipv4", "10.0.0.11/24"),
                ("app.http-server.listen", "10.0.0.11:80"),
                ("app.mdns-responder.hostname", "beta"),
                ("app.mdns-responder.families", "ipv4"),
                ("app.mdns-responder.service.web.instance", "Beta Web"),
                ("app.mdns-responder.service.web.type", "_http._tcp"),
                ("app.mdns-responder.service.web.port", "80"),
                ("app.mdns-responder.service.web.txt", "path=/,v=1"),
                ("app.mdns-responder.service.files.instance", "Beta Files"),
                ("app.mdns-responder.service.files.type", "_http._tcp"),
                ("app.mdns-responder.service.files.port", "8080"),
                ("app.mdns-responder.service.files.txt", "path=/files"),
                ("app.mdns-responder.service.files.until", "20s"),
            ]),
        )
        .unwrap();
    let gamma = network
        .device_with_config(
            "gamma",
            &b.load("node-mdns-responder"),
            config(&[
                ("mac", "02:00:00:00:00:12"),
                ("ipv4", "10.0.0.12/24"),
                ("app.mdns-responder.hostname", "gamma"),
                ("app.mdns-responder.families", "ipv4"),
                ("app.mdns-responder.start", "6s"),
                ("app.mdns-responder.ttl", "10s"),
                ("app.mdns-responder.service-ttl", "10s"),
                ("app.mdns-responder.service.web.instance", "Alpha Web"),
                ("app.mdns-responder.service.web.type", "_http._tcp"),
                ("app.mdns-responder.service.web.port", "81"),
            ]),
        )
        .unwrap();
    let browser = network
        .device_with_config(
            "browser",
            &b.load("node-service-browse"),
            config(&[
                ("mac", "02:00:00:00:00:20"),
                ("ipv4", "10.0.0.20/24"),
                ("ipv6", "fd00::20/64"),
                ("app.service-browse.type", "_http._tcp"),
                ("app.service-browse.fetch", "Alpha Web"),
                ("app.service-browse.start", "500ms"),
            ]),
        )
        .unwrap();
    let mut gamma_link = None;
    for (dev, port) in [(alpha, 1), (beta, 2), (gamma, 3), (browser, 4)] {
        let link = network
            .link(dev.port(0), sw.port(port))
            .unwrap()
            .latency(50 * US)
            .id();
        if dev == gamma {
            gamma_link = Some(link);
        }
    }
    network.schedule_link_state(gamma_link.unwrap(), 30 * S, false);
    let ports = Ports {
        alpha: alpha.port(0),
        beta: beta.port(0),
        gamma: gamma.port(0),
        browser: browser.port(0),
    };
    network
        .run_until(50 * S)
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    Run {
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        ports,
    }
}

/// The mDNS messages `port` sent (UDP from port 5353), decoded, with their time.
fn mdns_from(frames: &[FrameRecord], port: PortRef) -> Vec<(u64, Message, u8)> {
    frames
        .iter()
        .filter(|f| f.from == port)
        .filter_map(|f| {
            let d = datagram(&f.bytes)?;
            (d.src_port == dns::MDNS_PORT || d.dst_port == dns::MDNS_PORT)
                .then(|| {
                    Message::parse(&d.payload)
                        .ok()
                        .map(|m| (f.sent_at, m, d.hop_limit))
                })
                .flatten()
        })
        .collect()
}

fn has(records: &[Record], name: &str, t: u16, data: &RData) -> bool {
    records
        .iter()
        .any(|r| dns::same_name(&r.name, name) && r.rtype == t && &r.data == data)
}

fn ptr(n: &str) -> RData {
    RData::Ptr(n.into())
}

fn srv(port: u16, target: &str) -> RData {
    RData::Srv {
        priority: 0,
        weight: 0,
        port,
        target: target.into(),
    }
}

fn txt(strings: &[&str]) -> RData {
    RData::Txt(strings.iter().map(|s| s.as_bytes().to_vec()).collect())
}

/// What the browser reported, as `(kind, instance, other fields)`.
fn browser_saw(run: &Run, kind: &str) -> Vec<Vec<(String, String)>> {
    events(&run.journal, "browser", kind)
}

fn check(run: &Run, seed: u64) {
    let log = transcript(&run.journal);
    let ctx = |what: &str| format!("seed={seed}: {what}\n{log}");

    // ---- The advertisers ------------------------------------------------------------------
    let announced = |dev: &str| -> Vec<String> {
        events(&run.journal, dev, "mdns-service-announced")
            .iter()
            .map(|e| field(e, "instance").to_owned())
            .collect()
    };
    assert_eq!(announced("alpha"), ["Alpha Web"], "{}", ctx("alpha"));
    assert_eq!(
        announced("beta"),
        ["Beta Files", "Beta Web"],
        "{}",
        ctx("beta (id order)")
    );
    assert_eq!(announced("gamma"), ["Alpha Web (2)"], "{}", ctx("gamma"));
    let renamed = events(&run.journal, "gamma", "mdns-service-renamed");
    assert_eq!(renamed.len(), 1, "{}", ctx("one rename"));
    assert_eq!(field(&renamed[0], "from"), "Alpha Web");
    assert_eq!(field(&renamed[0], "to"), "Alpha Web (2)");
    assert!(
        events(&run.journal, "alpha", "mdns-service-conflict").is_empty(),
        "{}",
        ctx("alpha keeps its name")
    );
    let withdrawn = events(&run.journal, "beta", "mdns-service-withdrawn");
    assert_eq!(withdrawn.len(), 1, "{}", ctx("beta withdraws"));
    assert_eq!(field(&withdrawn[0], "instance"), "Beta Files");

    // ---- The browser -------------------------------------------------------------------------
    let mut found: Vec<String> = browser_saw(run, "dnssd-found")
        .iter()
        .map(|e| {
            assert_eq!(field(e, "type"), "_http._tcp");
            field(e, "instance").to_owned()
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        ["Alpha Web", "Alpha Web (2)", "Beta Files", "Beta Web"],
        "{}",
        ctx("every instance is found once")
    );
    let resolved = browser_saw(run, "dnssd-resolved");
    let first = |instance: &str| {
        resolved
            .iter()
            .find(|e| field(e, "instance") == instance)
            .unwrap_or_else(|| panic!("{}", ctx(&format!("{instance} never resolved"))))
    };
    for (instance, host, port, txt, addresses) in [
        (
            "Alpha Web",
            "alpha.local",
            "80",
            "path=/",
            "10.0.0.10,fd00::10",
        ),
        ("Beta Web", "beta.local", "80", "path=/,v=1", "10.0.0.11"),
        (
            "Beta Files",
            "beta.local",
            "8080",
            "path=/files",
            "10.0.0.11",
        ),
        ("Alpha Web (2)", "gamma.local", "81", "", "10.0.0.12"),
    ] {
        let r = first(instance);
        assert_eq!(field(r, "host"), host, "{}", ctx(instance));
        assert_eq!(field(r, "port"), port, "{}", ctx(instance));
        assert_eq!(field(r, "txt"), txt, "{}", ctx(instance));
        assert_eq!(field(r, "addresses"), addresses, "{}", ctx(instance));
    }
    // The fetch, by the resolved address and port.
    let fetched = browser_saw(run, "dnssd-fetched");
    assert_eq!(fetched.len(), 1, "{}", ctx("one fetch"));
    assert_eq!(field(&fetched[0], "instance"), "Alpha Web");
    assert_eq!(field(&fetched[0], "address"), "10.0.0.10");
    assert_eq!(field(&fetched[0], "port"), "80");
    assert_eq!(field(&fetched[0], "status"), "200", "{}", ctx("fetch"));
    assert_eq!(field(&fetched[0], "body-bytes"), "16");
    // Withdrawn by goodbye, gone by TTL.
    let removed: Vec<(String, String, u64)> = run
        .journal
        .iter()
        .filter(|e| e.device == "browser")
        .filter_map(|e| {
            let Journalled::Event { kind, fields } = &e.record else {
                return None;
            };
            if kind != "dnssd-removed" {
                return None;
            }
            Some((
                field(fields, "instance").to_owned(),
                field(fields, "reason").to_owned(),
                e.at,
            ))
        })
        .collect();
    assert_eq!(removed.len(), 2, "{}", ctx("two removals"));
    assert_eq!(
        (removed[0].0.as_str(), removed[0].1.as_str()),
        ("Beta Files", "goodbye")
    );
    assert!(
        (20 * S..22 * S).contains(&removed[0].2),
        "{}",
        ctx("a goodbye takes a second")
    );
    assert_eq!(
        (removed[1].0.as_str(), removed[1].1.as_str()),
        ("Alpha Web (2)", "expired")
    );
    assert!(
        (30 * S..41 * S).contains(&removed[1].2),
        "{}",
        ctx("gone within its 10 s TTL of the last refresh")
    );

    // ---- On the wire ------------------------------------------------------------------------
    let p = run.ports;
    let alpha = mdns_from(&run.frames, p.alpha);
    assert!(
        alpha.iter().all(|(_, _, hop)| *hop == 255),
        "{}",
        ctx("hop limit 255")
    );
    // Alpha's announcement holds RFC 6763's four records and the host's addresses.
    let announcement = alpha
        .iter()
        .map(|(_, m, _)| m)
        .find(|m| m.is_response() && m.answers.iter().any(|r| r.rtype == rtype::SRV))
        .unwrap_or_else(|| panic!("{}", ctx("alpha announces its service")));
    let inst = "Alpha Web._http._tcp.local";
    assert!(has(
        &announcement.answers,
        dns::DNS_SD_SERVICES,
        rtype::PTR,
        &ptr("_http._tcp.local")
    ));
    assert!(has(
        &announcement.answers,
        "_http._tcp.local",
        rtype::PTR,
        &ptr(inst)
    ));
    assert!(has(
        &announcement.answers,
        inst,
        rtype::SRV,
        &srv(80, "alpha.local")
    ));
    assert!(has(
        &announcement.answers,
        inst,
        rtype::TXT,
        &txt(&["path=/"])
    ));
    assert!(has(
        &announcement.additionals,
        "alpha.local",
        rtype::A,
        &RData::A("10.0.0.10".parse().unwrap())
    ));
    let srv_record = announcement
        .answers
        .iter()
        .find(|r| r.rtype == rtype::SRV)
        .unwrap();
    assert!(srv_record.cache_flush() && srv_record.ttl == 120);
    // Beta has no IPv6 address, and says so with an NSEC for its host name.
    let beta = mdns_from(&run.frames, p.beta);
    assert!(
        beta.iter().any(|(_, m, _)| has(
            &m.additionals,
            "beta.local",
            rtype::NSEC,
            &RData::Nsec {
                next: "beta.local".into(),
                types: vec![rtype::A]
            }
        )),
        "{}",
        ctx("beta's NSEC")
    );
    // Beta's goodbye: Beta Files' records with TTL 0, at 20 s.
    let goodbye = beta
        .iter()
        .find(|(_, m, _)| m.is_response() && m.answers.iter().all(|r| r.ttl == 0))
        .unwrap_or_else(|| panic!("{}", ctx("beta says goodbye")));
    assert_eq!(goodbye.0, 20 * S);
    let files = "Beta Files._http._tcp.local";
    assert!(has(
        &goodbye.1.answers,
        "_http._tcp.local",
        rtype::PTR,
        &ptr(files)
    ));
    assert!(has(
        &goodbye.1.answers,
        files,
        rtype::SRV,
        &srv(8080, "beta.local")
    ));
    // Beta Web is still there, so the type stays in the meta-query's answer.
    assert!(
        !goodbye
            .1
            .answers
            .iter()
            .any(|r| r.name == dns::DNS_SD_SERVICES)
    );
    // Gamma probed for `Alpha Web`, then for `Alpha Web (2)`.
    let probes: Vec<String> = mdns_from(&run.frames, p.gamma)
        .iter()
        .filter(|(_, m, _)| !m.is_response() && !m.authorities.is_empty())
        .flat_map(|(_, m, _)| m.questions.iter().map(|q| q.name.clone()))
        .filter(|n| n.contains("._http._tcp."))
        .collect();
    assert_eq!(
        probes.first().map(String::as_str),
        Some(inst),
        "{}",
        ctx("gamma's probes")
    );
    assert!(probes.iter().any(|n| n == "Alpha Web (2)._http._tcp.local"));
    // Alpha defended it with its SRV, by unicast (the first probe asks for it, QU).
    let defence = alpha.iter().find(|(_, m, _)| {
        m.is_response()
            && m.answers.iter().any(|r| r.rtype == rtype::SRV)
            && events(&run.journal, "alpha", "mdns-answered")
                .iter()
                .any(|e| field(e, "mode") == "unicast")
    });
    assert!(
        defence.is_some(),
        "{}",
        ctx("alpha defends its instance name")
    );
    // The browser's queries: PTR questions for the type, later ones with known answers.
    let queries: Vec<Message> = mdns_from(&run.frames, p.browser)
        .into_iter()
        .map(|(_, m, _)| m)
        .filter(|m| !m.is_response())
        .collect();
    assert!(queries.iter().all(|q| {
        q.questions
            .iter()
            .all(|q| q.qclass & dns::MDNS_CLASS_BIT == 0)
    }));
    assert!(queries.iter().any(|q| {
        q.questions
            .iter()
            .any(|q| q.name == "_http._tcp.local" && q.qtype == rtype::PTR)
    }));
    assert!(
        queries.iter().any(|q| !q.answers.is_empty()
            && q.answers
                .iter()
                .all(|r| r.rtype == rtype::PTR && r.name == "_http._tcp.local")),
        "{}",
        ctx("known answers")
    );
}

#[test]
fn services_are_advertised_browsed_resolved_and_fetched() {
    let run = discovery(42);
    check(&run, 42);
}

#[test]
fn service_discovery_is_deterministic() {
    let (a, b) = (discovery(42), discovery(42));
    assert_eq!(
        a.pcaps, b.pcaps,
        "seed=42: the captures differ between runs"
    );
    assert_eq!(a.journal, b.journal, "seed=42: the journals differ");
    let other = discovery(7);
    check(&other, 7);
    let again = discovery(7);
    assert_eq!(
        other.pcaps, again.pcaps,
        "seed=7: the captures differ between runs"
    );
}
