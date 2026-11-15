//! Property tests of the hand-rolled DHCP and DNS (and mDNS) codecs: encoding then decoding
//! gives back what was encoded, and decoding arbitrary bytes never panics (compression pointers
//! included). Fixed seeds and no persistence files, so they run inside wasmtime like every other
//! guest test and replay the same cases every time.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use proptest::collection::vec;
use proptest::prelude::*;

use crate::dhcp;
use crate::dns::{self, MDNS_CLASS_BIT, Message, Question, RData, Record, rtype};

fn config(cases: u32, seed: u64) -> proptest::test_runner::Config {
    proptest::test_runner::Config {
        cases,
        rng_seed: proptest::test_runner::RngSeed::Fixed(seed),
        failure_persistence: None,
        ..proptest::test_runner::Config::default()
    }
}

// ---- DNS -------------------------------------------------------------------------------------

/// A name of 1 to 4 labels (mixed case: compression must keep it), or `local` names (mDNS).
fn name() -> impl Strategy<Value = String> {
    (vec("[a-zA-Z0-9][a-zA-Z0-9-]{0,11}", 1..4), any::<bool>()).prop_map(|(labels, local)| {
        let mut n = labels.join(".");
        if local {
            n.push_str(".local");
        }
        n
    })
}

fn rdata() -> impl Strategy<Value = (u16, RData)> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|o| (rtype::A, RData::A(Ipv4Addr::from(o)))),
        any::<[u8; 16]>().prop_map(|o| (rtype::AAAA, RData::Aaaa(Ipv6Addr::from(o)))),
        name().prop_map(|n| (rtype::CNAME, RData::Cname(n))),
        name().prop_map(|n| (rtype::PTR, RData::Ptr(n))),
        (name(), name(), any::<[u32; 5]>()).prop_map(|(m, r, v)| (
            rtype::SOA,
            RData::Soa {
                mname: m,
                rname: r,
                serial: v[0],
                refresh: v[1],
                retry: v[2],
                expire: v[3],
                minimum: v[4],
            }
        )),
        vec(any::<u8>(), 0..40).prop_map(|b| (rtype::TXT, RData::Other(b))),
    ]
}

/// A record; the class may carry mDNS's cache-flush bit.
fn record() -> impl Strategy<Value = Record> {
    (name(), rdata(), any::<bool>(), any::<u32>()).prop_map(|(name, (rtype, data), flush, ttl)| {
        Record {
            name,
            rtype,
            class: dns::CLASS_IN | if flush { MDNS_CLASS_BIT } else { 0 },
            ttl,
            data,
        }
    })
}

/// A question; the class may carry mDNS's QU bit.
fn question() -> impl Strategy<Value = Question> {
    (name(), any::<u16>(), any::<bool>()).prop_map(|(name, qtype, qu)| Question {
        name,
        qtype,
        qclass: dns::CLASS_IN | if qu { MDNS_CLASS_BIT } else { 0 },
    })
}

fn message() -> impl Strategy<Value = Message> {
    (
        any::<u16>(),
        any::<u16>(),
        vec(question(), 0..3),
        vec(record(), 0..4),
        vec(record(), 0..3),
        vec(record(), 0..3),
    )
        .prop_map(
            |(id, flags, questions, answers, authorities, additionals)| Message {
                id,
                flags,
                questions,
                answers,
                authorities,
                additionals,
            },
        )
}

/// A header and a few bytes that are mostly labels and compression pointers: the pointer walk.
fn pointer_soup() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<[u8; 12]>(),
        vec(
            prop_oneof![Just(0xc0u8), Just(0u8), 1u8..64, any::<u8>()],
            0..80,
        ),
    )
        .prop_map(|(head, body)| {
            let mut b = head.to_vec();
            b.extend(body);
            b
        })
}

proptest! {
    #![proptest_config(config(512, 1035))]

    #[test]
    fn dns_encode_then_decode_is_the_identity(m in message()) {
        let bytes = m.encode();
        prop_assert_eq!(Message::parse(&bytes), Ok(m));
    }

    #[test]
    fn dns_decode_of_arbitrary_bytes_never_panics_and_reencodes(bytes in vec(any::<u8>(), 0..300)) {
        if let Ok(m) = Message::parse(&bytes) {
            prop_assert_eq!(Message::parse(&m.encode()), Ok(m));
        }
    }

    #[test]
    fn dns_compression_pointers_are_walked_safely(bytes in pointer_soup()) {
        if let Ok(m) = Message::parse(&bytes) {
            prop_assert_eq!(Message::parse(&m.encode()), Ok(m));
        }
    }

    #[test]
    fn mdns_class_bits_survive(q in question(), r in record()) {
        let m = Message { questions: alloc::vec![q.clone()], answers: alloc::vec![r.clone()], ..Message::default() };
        let back = Message::parse(&m.encode()).unwrap();
        prop_assert_eq!(back.questions[0].unicast_response(), q.qclass & MDNS_CLASS_BIT != 0);
        prop_assert_eq!(back.answers[0].cache_flush(), r.class & MDNS_CLASS_BIT != 0);
        prop_assert_eq!(back.questions[0].class(), dns::CLASS_IN);
    }
}

// ---- DHCP ------------------------------------------------------------------------------------

fn dhcp_message() -> impl Strategy<Value = dhcp::Message> {
    (
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>()),
        (any::<u32>(), any::<u16>(), any::<u16>()),
        any::<[u32; 4]>(),
        any::<[u8; 16]>(),
        // Option codes 1..=254 (0 and 255 are PAD and END), data up to 255 bytes.
        vec((1u8..255, vec(any::<u8>(), 0..64)), 0..12),
    )
        .prop_map(
            |((op, htype, hlen, hops), (xid, secs, flags), a, chaddr, options)| dhcp::Message {
                op,
                htype,
                hlen,
                hops,
                xid,
                secs,
                flags,
                ciaddr: Ipv4Addr::from(a[0]),
                yiaddr: Ipv4Addr::from(a[1]),
                siaddr: Ipv4Addr::from(a[2]),
                giaddr: Ipv4Addr::from(a[3]),
                chaddr,
                options,
            },
        )
}

proptest! {
    #![proptest_config(config(512, 2131))]

    #[test]
    fn dhcp_encode_then_decode_is_the_identity(m in dhcp_message()) {
        let bytes = m.encode();
        prop_assert!(bytes.len() >= dhcp::MIN_LEN);
        prop_assert_eq!(dhcp::Message::parse(&bytes), Ok(m));
    }

    #[test]
    fn dhcp_decode_of_arbitrary_bytes_never_panics_and_reencodes(
        head in vec(any::<u8>(), 236..=236),
        cookie in any::<bool>(),
        tail in vec(any::<u8>(), 0..120),
    ) {
        let mut bytes = head;
        if cookie {
            bytes.extend_from_slice(&dhcp::MAGIC);
        }
        bytes.extend(tail);
        if let Ok(m) = dhcp::Message::parse(&bytes) {
            prop_assert_eq!(dhcp::Message::parse(&m.encode()), Ok(m.clone()));
            // The accessors never panic either.
            let _ = (m.message_type(), m.client_mac(), m.text_option(dhcp::opt::HOSTNAME));
            let _ = (m.addr_option(dhcp::opt::SERVER_ID), m.addrs_option(dhcp::opt::DNS_SERVERS));
            let _ = m.u32_option(dhcp::opt::LEASE_TIME);
        }
    }
}
