use super::*;

fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
    p.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn config() -> Config {
    Config::from_pairs(pairs(&[
        ("server-id", "10.0.1.2"),
        ("pool.a.subnet", "10.0.1.0/24"),
        ("pool.a.range", "10.0.1.100-10.0.1.101"),
        ("pool.a.router", "10.0.1.1"),
        ("pool.a.dns", "10.0.1.2"),
        ("pool.a.domain", "internal"),
        ("pool.a.reserve", "02:00:00:00:01:10=10.0.1.10"),
        ("pool.b.subnet", "10.0.2.0/24"),
        ("pool.b.range", "10.0.2.100-10.0.2.199"),
        ("pool.b.router", "10.0.2.1"),
        ("pool.b.lease", "10s"),
    ]))
    .unwrap()
}

const S: u64 = 1_000_000_000;

fn mac(last: u8) -> MacAddr {
    MacAddr([2, 0, 0, 0, 2, last])
}

fn request(kind: MessageType, m: MacAddr, xid: u32) -> Message {
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&m.octets());
    let mut msg = Message {
        op: dhcp::BOOTREQUEST,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid,
        secs: 0,
        flags: 0,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr,
        options: Vec::new(),
    };
    msg.set_option(opt::MESSAGE_TYPE, &[kind.to_u8()]);
    msg
}

fn ask(s: &mut Server, now: u64, m: &Message) -> (Option<Reply>, Vec<Note>) {
    s.handle(now, &m.encode())
}

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

#[test]
fn config_keys_and_errors() {
    let c = config();
    assert_eq!(c.pools.len(), 2);
    let (a, b) = (&c.pools[0], &c.pools[1]);
    assert_eq!(
        (a.name.as_str(), a.prefix, a.lease_s),
        ("a", 24, DEFAULT_LEASE_S)
    );
    assert_eq!(b.lease_s, 10);
    assert_eq!(
        a.reserved.get(&MacAddr([2, 0, 0, 0, 1, 0x10])),
        Some(&ip("10.0.1.10"))
    );
    assert_eq!(c.listen, "0.0.0.0:67".parse().unwrap());
    let base = [("server-id", "10.0.1.2"), ("pool.a.subnet", "10.0.1.0/24")];
    for (extra, needle) in [
        (
            &[("pool.a.range", "10.0.2.1-10.0.2.9")][..],
            "inside the subnet",
        ),
        (
            &[("pool.a.range", "10.0.1.9-10.0.1.1")][..],
            "inside the subnet",
        ),
        (&[("pool.a.range", "x")][..], "range"),
        (
            &[
                ("pool.a.range", "10.0.1.1-10.0.1.9"),
                ("pool.a.lease", "1500ms"),
            ][..],
            "lease",
        ),
        (
            &[
                ("pool.a.range", "10.0.1.1-10.0.1.9"),
                ("pool.a.reserve", "02:00:00:00:00:01=10.9.0.1"),
            ][..],
            "reserve",
        ),
        (
            &[
                ("pool.a.range", "10.0.1.1-10.0.1.9"),
                ("pool.a.colour", "red"),
            ][..],
            "unknown",
        ),
        (&[][..], "pool.a.range"),
    ] {
        let mut p = pairs(&base);
        p.extend(pairs(extra));
        let err = Config::from_pairs(p).unwrap_err().to_string();
        assert!(err.contains(needle), "{extra:?}: {err}");
    }
    let err = Config::from_pairs(pairs(&[("pool.a.subnet", "10.0.1.0/24")]))
        .unwrap_err()
        .to_string();
    assert!(err.contains("server-id"), "{err}");
}

#[test]
fn dora_on_link_broadcasts_and_leases_the_lowest_free_address() {
    let mut s = Server::new(config());
    let d = request(MessageType::Discover, mac(1), 7);
    let (offer, notes) = ask(&mut s, 0, &d);
    let offer = offer.unwrap();
    assert_eq!(offer.to, "255.255.255.255:68".parse().unwrap());
    let o = &offer.message;
    assert_eq!(
        (o.op, o.xid, o.yiaddr),
        (dhcp::BOOTREPLY, 7, ip("10.0.1.100"))
    );
    assert_eq!(o.message_type(), Some(MessageType::Offer));
    assert_eq!(o.addr_option(opt::SERVER_ID), Some(ip("10.0.1.2")));
    assert_eq!(o.addr_option(opt::SUBNET_MASK), Some(ip("255.255.255.0")));
    assert_eq!(o.addrs_option(opt::ROUTER), vec![ip("10.0.1.1")]);
    assert_eq!(o.addrs_option(opt::DNS_SERVERS), vec![ip("10.0.1.2")]);
    assert_eq!(o.text_option(opt::DOMAIN_NAME).as_deref(), Some("internal"));
    assert_eq!(o.u32_option(opt::LEASE_TIME), Some(3600));
    assert_eq!(notes[0].0, "dhcp-offer");

    // A second client gets the next address while the first offer is held.
    let (o2, _) = ask(&mut s, 1, &request(MessageType::Discover, mac(2), 8));
    assert_eq!(o2.unwrap().message.yiaddr, ip("10.0.1.101"));
    // The range is full: a third client gets nothing.
    let (o3, notes) = ask(&mut s, 2, &request(MessageType::Discover, mac(3), 9));
    assert!(o3.is_none());
    assert_eq!(notes[0].0, "dhcp-pool-exhausted");

    let mut r = request(MessageType::Request, mac(1), 7);
    r.set_option(opt::SERVER_ID, &[10, 0, 1, 2]);
    r.set_option(opt::REQUESTED_IP, &[10, 0, 1, 100]);
    let (ack, notes) = ask(&mut s, 3, &r);
    let ack = ack.unwrap();
    assert_eq!(ack.message.message_type(), Some(MessageType::Ack));
    assert_eq!(ack.message.yiaddr, ip("10.0.1.100"));
    assert_eq!(notes[0].0, "dhcp-ack");
    assert!(notes[0].1.contains(&("phase".to_owned(), "new".to_owned())));
    assert_eq!(s.leased(3)[0], (ip("10.0.1.100"), mac(1), true));

    // Client 2 selected another server: its offer is withdrawn, no answer.
    let mut other = request(MessageType::Request, mac(2), 8);
    other.set_option(opt::SERVER_ID, &[10, 0, 1, 99]);
    other.set_option(opt::REQUESTED_IP, &[10, 0, 1, 101]);
    let (none, notes) = ask(&mut s, 4, &other);
    assert!(none.is_none());
    assert_eq!(notes[0].0, "dhcp-ignored");
    // So client 3 now gets 10.0.1.101.
    let (o3, _) = ask(&mut s, 5, &request(MessageType::Discover, mac(3), 9));
    assert_eq!(o3.unwrap().message.yiaddr, ip("10.0.1.101"));
}

#[test]
fn reservations_relays_renewals_and_naks() {
    let mut s = Server::new(config());
    // web's reservation on the server's own subnet.
    let web = MacAddr([2, 0, 0, 0, 1, 0x10]);
    let (o, _) = ask(&mut s, 0, &request(MessageType::Discover, web, 1));
    assert_eq!(o.unwrap().message.yiaddr, ip("10.0.1.10"));

    // A relayed DISCOVER from subnet B: pool b, the reply goes to the relay's port 67.
    let mut d = request(MessageType::Discover, mac(1), 2);
    d.giaddr = ip("10.0.2.1");
    d.hops = 1;
    let (o, notes) = ask(&mut s, 0, &d);
    let o = o.unwrap();
    assert_eq!(o.to, "10.0.2.1:67".parse().unwrap());
    assert_eq!(o.message.giaddr, ip("10.0.2.1"));
    assert_eq!(o.message.yiaddr, ip("10.0.2.100"));
    assert_eq!(o.message.u32_option(opt::LEASE_TIME), Some(10));
    assert!(
        notes[0]
            .1
            .contains(&("relay".to_owned(), "10.0.2.1".to_owned()))
    );

    let mut r = request(MessageType::Request, mac(1), 2);
    r.giaddr = ip("10.0.2.1");
    r.set_option(opt::SERVER_ID, &[10, 0, 1, 2]);
    r.set_option(opt::REQUESTED_IP, &[10, 0, 2, 100]);
    assert_eq!(
        ask(&mut s, S, &r).0.unwrap().message.message_type(),
        Some(MessageType::Ack)
    );

    // Renewal (ciaddr set) through the relay at T1 = 5 s: ACK, the lease runs 10 s from now.
    let mut renew = request(MessageType::Request, mac(1), 3);
    renew.ciaddr = ip("10.0.2.100");
    renew.giaddr = ip("10.0.2.1");
    let (ack, notes) = ask(&mut s, 6 * S, &renew);
    assert_eq!(ack.unwrap().message.yiaddr, ip("10.0.2.100"));
    assert!(
        notes[0]
            .1
            .contains(&("phase".to_owned(), "renew".to_owned()))
    );
    // A direct (unrelayed) renewal is answered unicast to ciaddr.
    renew.giaddr = Ipv4Addr::UNSPECIFIED;
    let (ack, _) = ask(&mut s, 7 * S, &renew);
    assert_eq!(ack.unwrap().to, "10.0.2.100:68".parse().unwrap());

    // Another client renewing an address that is not its own: NAK, broadcast.
    let mut thief = request(MessageType::Request, mac(9), 4);
    thief.ciaddr = ip("10.0.2.100");
    let (nak, notes) = ask(&mut s, 7 * S, &thief);
    let nak = nak.unwrap();
    assert_eq!(nak.message.message_type(), Some(MessageType::Nak));
    assert_eq!(nak.to, "255.255.255.255:68".parse().unwrap());
    assert_eq!(notes[0].0, "dhcp-nak");

    // INIT-REBOOT with an address from the wrong subnet: NAK.
    let mut reboot = request(MessageType::Request, mac(5), 5);
    reboot.set_option(opt::REQUESTED_IP, &[192, 168, 0, 5]);
    assert_eq!(
        ask(&mut s, 7 * S, &reboot)
            .0
            .unwrap()
            .message
            .message_type(),
        Some(MessageType::Nak)
    );

    // The lease expires 10 s after the last renewal (17 s): then its address is free again.
    let (o, _) = ask(&mut s, 18 * S, &{
        let mut d = request(MessageType::Discover, mac(7), 6);
        d.giaddr = ip("10.0.2.1");
        d
    });
    assert_eq!(o.unwrap().message.yiaddr, ip("10.0.2.100"));

    // RELEASE frees, DECLINE parks the address, INFORM gets options only.
    let mut inform = request(MessageType::Inform, mac(8), 7);
    inform.ciaddr = ip("10.0.1.50");
    let (ack, _) = ask(&mut s, 20 * S, &inform);
    let ack = ack.unwrap();
    assert_eq!(ack.to, "10.0.1.50:68".parse().unwrap());
    assert_eq!(ack.message.yiaddr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(ack.message.u32_option(opt::LEASE_TIME), None);
    assert!(ack.message.option(opt::ROUTER).is_some());
}

/// Leases `want` to `m` with DISCOVER and REQUEST (selecting) at `now`.
fn lease(s: &mut Server, now: u64, m: MacAddr, want: Ipv4Addr) {
    let (o, _) = ask(s, now, &request(MessageType::Discover, m, 1));
    assert_eq!(o.unwrap().message.yiaddr, want);
    let mut r = request(MessageType::Request, m, 1);
    r.set_option(opt::SERVER_ID, &[10, 0, 1, 2]);
    r.set_option(opt::REQUESTED_IP, &want.octets());
    let (ack, _) = ask(s, now, &r);
    assert_eq!(ack.unwrap().message.message_type(), Some(MessageType::Ack));
}

#[test]
fn a_decline_only_parks_the_clients_own_address() {
    // RFC 2131 §4.3.3.
    let mut s = Server::new(config());
    lease(&mut s, 0, mac(1), ip("10.0.1.100"));
    let decline = |m: MacAddr, a: [u8; 4]| {
        let mut d = request(MessageType::Decline, m, 9);
        d.set_option(opt::REQUESTED_IP, &a);
        d
    };
    // Another client cannot take client 1's lease away, nor park a free or foreign address.
    for (m, a) in [
        (mac(2), [10, 0, 1, 100]),
        (mac(2), [10, 0, 1, 101]),
        (mac(2), [192, 168, 0, 1]),
    ] {
        let (r, notes) = ask(&mut s, S, &decline(m, a));
        assert!(r.is_none());
        assert_eq!(notes[0].0, "dhcp-ignored", "{a:?}");
    }
    assert_eq!(s.leased(S), [(ip("10.0.1.100"), mac(1), true)]);
    // So client 2 still gets the free address.
    let (o, _) = ask(&mut s, S, &request(MessageType::Discover, mac(2), 3));
    assert_eq!(o.unwrap().message.yiaddr, ip("10.0.1.101"));
    // Client 1 declines its own address: parked, no longer leased.
    let (r, notes) = ask(&mut s, 2 * S, &decline(mac(1), [10, 0, 1, 100]));
    assert!(r.is_none());
    assert_eq!(notes[0].0, "dhcp-decline");
    assert!(s.leased(2 * S).iter().all(|(a, ..)| *a != ip("10.0.1.100")));
}

#[test]
fn init_reboot_naks_addresses_the_pool_would_not_assign() {
    // RFC 2131 §4.3.2.
    let mut s = Server::new(config());
    let reboot = |m: MacAddr, a: [u8; 4]| {
        let mut r = request(MessageType::Request, m, 5);
        r.set_option(opt::REQUESTED_IP, &a);
        r
    };
    for a in [[10, 0, 1, 50], [10, 0, 1, 0], [10, 0, 1, 255]] {
        let (r, notes) = ask(&mut s, 0, &reboot(mac(1), a));
        assert_eq!(
            r.unwrap().message.message_type(),
            Some(MessageType::Nak),
            "{a:?}"
        );
        assert_eq!(notes[0].0, "dhcp-nak");
    }
    // In range: ACK; the reserved address outside the range: ACK for its owner only.
    let (r, _) = ask(&mut s, 0, &reboot(mac(1), [10, 0, 1, 100]));
    assert_eq!(r.unwrap().message.message_type(), Some(MessageType::Ack));
    let web = MacAddr([2, 0, 0, 0, 1, 0x10]);
    let (r, _) = ask(&mut s, 0, &reboot(web, [10, 0, 1, 10]));
    assert_eq!(r.unwrap().message.message_type(), Some(MessageType::Ack));
    let (r, _) = ask(&mut s, 0, &reboot(mac(3), [10, 0, 1, 10]));
    assert_eq!(r.unwrap().message.message_type(), Some(MessageType::Nak));
}

#[test]
fn garbage_and_server_messages_are_ignored() {
    let mut s = Server::new(config());
    let (r, notes) = s.handle(0, b"not dhcp");
    assert!(r.is_none());
    assert_eq!(notes[0].1[2], ("reason".to_owned(), "malformed".to_owned()));
    let mut reply = request(MessageType::Offer, mac(1), 1);
    reply.op = dhcp::BOOTREPLY;
    assert!(ask(&mut s, 0, &reply).0.is_none());
    let mut bootp = request(MessageType::Discover, mac(1), 1);
    bootp.options.clear();
    assert!(ask(&mut s, 0, &bootp).0.is_none());
}
