//! Geneve (RFC 8926), the tunnel's data encapsulation: an 8-byte header in a UDP datagram,
//! then the inner IP packet.
//!
//! ```text
//!  0                   1                   2                   3
//! |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//! |        Virtual Network Identifier (VNI)       |    Reserved   |
//! |                    Variable-Length Options                    |
//! ```
//!
//! Sent: version 0, no options, O and C clear, protocol `0x86DD` (IPv6) or `0x0800` (IPv4),
//! the tunnel id as VNI. Received: version 0 only; options are skipped unless the C bit says
//! one is critical, which this side cannot honour, so the packet is dropped (RFC 8926 §3.5);
//! control packets (O bit) and other protocols are dropped as well.

/// Geneve's well-known UDP port.
pub const PORT: u16 = 6081;
/// The fixed header.
pub const HEADER: usize = 8;
pub const PROTO_IPV4: u16 = 0x0800;
pub const PROTO_IPV6: u16 = 0x86DD;
/// The largest VNI.
pub const MAX_VNI: u32 = (1 << 24) - 1;

/// Why a datagram is not a Geneve data packet this side accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("shorter than its header and options")]
    Short,
    #[error("a version other than 0")]
    Version,
    #[error("a critical option")]
    Critical,
    #[error("a control packet")]
    Control,
    #[error("an inner protocol other than IPv4 or IPv6")]
    Protocol,
}

/// A decoded data packet: its VNI and the inner packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub vni: u32,
    pub proto: u16,
    pub inner: &'a [u8],
}

/// The protocol type for an inner packet, by its version nibble.
pub fn proto_of(inner: &[u8]) -> u16 {
    match inner.first().map(|b| b >> 4) {
        Some(6) => PROTO_IPV6,
        _ => PROTO_IPV4,
    }
}

/// The datagram for `inner` on tunnel `vni` (`vni` above 24 bits is cut to 24).
pub fn encap(vni: u32, inner: &[u8]) -> Vec<u8> {
    let [p0, p1] = proto_of(inner).to_be_bytes();
    let [_, v0, v1, v2] = (vni & MAX_VNI).to_be_bytes();
    let mut d = Vec::with_capacity(HEADER + inner.len());
    d.extend_from_slice(&[0, 0, p0, p1, v0, v1, v2, 0]);
    d.extend_from_slice(inner);
    d
}

/// Decodes a data packet.
pub fn decap(d: &[u8]) -> Result<Packet<'_>, Error> {
    if d.len() < HEADER {
        return Err(Error::Short);
    }
    if d[0] >> 6 != 0 {
        return Err(Error::Version);
    }
    let options = usize::from(d[0] & 0x3f) * 4;
    let inner = d.get(HEADER + options..).ok_or(Error::Short)?;
    if d[1] & 0x40 != 0 {
        return Err(Error::Critical);
    }
    if d[1] & 0x80 != 0 {
        return Err(Error::Control);
    }
    let proto = u16::from_be_bytes([d[2], d[3]]);
    if proto != PROTO_IPV4 && proto != PROTO_IPV6 {
        return Err(Error::Protocol);
    }
    Ok(Packet {
        vni: u32::from_be_bytes([0, d[4], d[5], d[6]]),
        proto,
        inner,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn the_header_is_rfc_8926s() {
        let v6 = [0x60, 0, 0, 0, 0, 0, 59, 64];
        let d = encap(0x00_1234, &v6);
        assert_eq!(d[..8], [0x00, 0x00, 0x86, 0xdd, 0x00, 0x12, 0x34, 0x00]);
        assert_eq!(
            decap(&d),
            Ok(Packet {
                vni: 0x1234,
                proto: PROTO_IPV6,
                inner: &v6
            })
        );
        let v4 = [0x45, 0, 0, 20];
        let d = encap(7, &v4);
        assert_eq!(d[2..4], [0x08, 0x00]);
        assert_eq!(decap(&d).unwrap().inner, &v4);
    }

    #[test]
    fn options_are_skipped_unless_critical() {
        // One 4-byte option word (Opt Len = 1), then the inner packet.
        let mut d = vec![
            0x01, 0x00, 0x86, 0xdd, 0, 0, 7, 0, 0xab, 0xcd, 0x01, 0x00, 0x60,
        ];
        assert_eq!(decap(&d).unwrap().inner, &[0x60]);
        d[1] = 0x40;
        assert_eq!(decap(&d), Err(Error::Critical));
        d[1] = 0x80;
        assert_eq!(decap(&d), Err(Error::Control));
        d[1] = 0;
        d[0] = 0x41;
        assert_eq!(decap(&d), Err(Error::Version));
        assert_eq!(decap(&[0, 0, 0x86, 0xdd, 0, 0, 7]), Err(Error::Short));
        assert_eq!(decap(&[0x3f, 0, 0x86, 0xdd, 0, 0, 7, 0]), Err(Error::Short));
        assert_eq!(decap(&[0, 0, 0x88, 0xb5, 0, 0, 7, 0]), Err(Error::Protocol));
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 1024,
            rng_seed: proptest::test_runner::RngSeed::Fixed(8926),
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]

        #[test]
        fn round_trips(vni in 0..=MAX_VNI, v6 in any::<bool>(), body in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut inner = vec![if v6 { 0x60 } else { 0x45 }];
            inner.extend_from_slice(&body);
            let d = encap(vni, &inner);
            let p = decap(&d).unwrap();
            prop_assert_eq!((p.vni, p.inner), (vni, &inner[..]));
            prop_assert_eq!(p.proto, if v6 { PROTO_IPV6 } else { PROTO_IPV4 });
        }

        #[test]
        fn arbitrary_bytes_never_panic(d in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = decap(&d);
        }
    }
}
