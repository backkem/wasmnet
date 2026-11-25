//! Zero-copy Ethernet II / 802.3 frame view with optional single 802.1Q tag.
//!
//! Frames on `wasmnet:link` carry no preamble and no FCS: `dst(6) src(6) [tpid(2) tci(2)] type(2) payload`.
//! Parsing never panics. Anything short or malformed comes back as a [`FrameError`].

use crate::mac::MacAddr;
use alloc::vec::Vec;
use core::fmt;

const MAC_LEN: usize = 6;
const TYPE_OFFSET: usize = 2 * MAC_LEN;
const VLAN_TAG_LEN: usize = 4;
/// `dst + src + ethertype`.
pub const HEADER_LEN: usize = TYPE_OFFSET + 2;
/// `dst + src + 802.1Q tag + ethertype`.
pub const TAGGED_HEADER_LEN: usize = HEADER_LEN + VLAN_TAG_LEN;

/// The 16-bit type/length field. Values `<= 1500` are 802.3 lengths, values `>= 0x0600` are EtherTypes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EtherType(pub u16);

impl EtherType {
    pub const IPV4: EtherType = EtherType(0x0800);
    pub const ARP: EtherType = EtherType(0x0806);
    pub const VLAN: EtherType = EtherType(0x8100);
    pub const IPV6: EtherType = EtherType(0x86dd);
    pub const QINQ: EtherType = EtherType(0x88a8);

    /// Largest value that is an IEEE 802.3 length rather than an EtherType.
    pub const MAX_8023_LENGTH: u16 = 1500;
    /// Smallest value that is an EtherType.
    pub const MIN_ETHERTYPE: u16 = 0x0600;

    /// True when this field is an 802.3 length (e.g. LLC frames such as STP BPDUs).
    pub const fn is_length(self) -> bool {
        self.0 <= Self::MAX_8023_LENGTH
    }
}

impl fmt::Debug for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EtherType(0x{:04x})", self.0)
    }
}

/// An IEEE 802.1Q tag control field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VlanTag {
    pcp: u8,
    dei: bool,
    vid: u16,
}

impl VlanTag {
    /// `pcp` must fit in 3 bits and `vid` in 12 bits. Otherwise this returns `None`.
    pub const fn new(pcp: u8, dei: bool, vid: u16) -> Option<Self> {
        if pcp > 0b111 || vid > 0x0fff {
            None
        } else {
            Some(Self { pcp, dei, vid })
        }
    }

    pub const fn from_tci(tci: u16) -> Self {
        Self {
            pcp: (tci >> 13) as u8,
            dei: tci & 0x1000 != 0,
            vid: tci & 0x0fff,
        }
    }

    pub const fn tci(self) -> u16 {
        ((self.pcp as u16) << 13) | ((self.dei as u16) << 12) | self.vid
    }

    /// Priority code point (0..=7).
    pub const fn pcp(self) -> u8 {
        self.pcp
    }

    /// Drop-eligible indicator.
    pub const fn dei(self) -> bool {
        self.dei
    }

    /// VLAN identifier (0..=4095).
    pub const fn vid(self) -> u16 {
        self.vid
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    #[error("frame truncated: {len} bytes, need at least {needed}")]
    Truncated { len: usize, needed: usize },
    /// 1501..=1535 is neither an 802.3 length nor an EtherType.
    #[error("invalid type/length field 0x{0:04x}")]
    InvalidTypeField(u16),
    #[error("802.3 length field says {declared} bytes but only {available} follow the header")]
    LengthMismatch { declared: usize, available: usize },
}

/// A validated, zero-copy view over one Ethernet frame.
///
/// Only the outermost 802.1Q tag is decoded. A QinQ (`0x88a8`) or stacked tag shows up as the
/// [`ethertype`](Self::ethertype) with the inner tag at the start of the payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EthernetFrame<T: AsRef<[u8]>> {
    buf: T,
    tagged: bool,
}

impl<T: AsRef<[u8]>> EthernetFrame<T> {
    /// Validates `buf` and wraps it. All accessors are infallible afterwards.
    pub fn new_checked(buf: T) -> Result<Self, FrameError> {
        let bytes = buf.as_ref();
        let len = bytes.len();
        let outer = read_u16(bytes, TYPE_OFFSET).ok_or(FrameError::Truncated {
            len,
            needed: HEADER_LEN,
        })?;
        let tagged = outer == EtherType::VLAN.0;
        let header_len = if tagged {
            TAGGED_HEADER_LEN
        } else {
            HEADER_LEN
        };
        let type_field = read_u16(bytes, header_len - 2).ok_or(FrameError::Truncated {
            len,
            needed: header_len,
        })?;

        let available = len - header_len;
        if type_field <= EtherType::MAX_8023_LENGTH {
            let declared = usize::from(type_field);
            if declared > available {
                return Err(FrameError::LengthMismatch {
                    declared,
                    available,
                });
            }
        } else if type_field < EtherType::MIN_ETHERTYPE {
            return Err(FrameError::InvalidTypeField(type_field));
        }
        Ok(Self { buf, tagged })
    }

    pub fn into_inner(self) -> T {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_ref()
    }

    pub fn dst(&self) -> MacAddr {
        self.mac_at(0)
    }

    pub fn src(&self) -> MacAddr {
        self.mac_at(MAC_LEN)
    }

    /// The 802.1Q tag, if the frame carries one.
    pub fn vlan(&self) -> Option<VlanTag> {
        if self.tagged {
            read_u16(self.as_bytes(), TYPE_OFFSET + 2).map(VlanTag::from_tci)
        } else {
            None
        }
    }

    /// The inner type/length field (after any 802.1Q tag).
    pub fn ethertype(&self) -> EtherType {
        EtherType(read_u16(self.as_bytes(), self.header_len() - 2).unwrap_or_default())
    }

    pub fn header_len(&self) -> usize {
        if self.tagged {
            TAGGED_HEADER_LEN
        } else {
            HEADER_LEN
        }
    }

    /// Bytes after the header. For 802.3 frames this is trimmed to the declared length, which drops
    /// any minimum-size padding. For Ethernet II it is everything that follows, padding included.
    pub fn payload(&self) -> &[u8] {
        let rest = self.as_bytes().get(self.header_len()..).unwrap_or_default();
        let ty = self.ethertype();
        if ty.is_length() {
            rest.get(..usize::from(ty.0)).unwrap_or(rest)
        } else {
            rest
        }
    }

    fn mac_at(&self, offset: usize) -> MacAddr {
        self.as_bytes()
            .get(offset..)
            .and_then(MacAddr::from_slice)
            .unwrap_or(MacAddr::ZERO)
    }
}

impl<T: AsRef<[u8]>> fmt::Debug for EthernetFrame<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthernetFrame")
            .field("dst", &self.dst())
            .field("src", &self.src())
            .field("vlan", &self.vlan())
            .field("ethertype", &self.ethertype())
            .field("payload_len", &self.payload().len())
            .finish()
    }
}

/// Appends one frame (no FCS, no padding) to `out`.
pub fn encode_frame(
    out: &mut Vec<u8>,
    dst: MacAddr,
    src: MacAddr,
    vlan: Option<VlanTag>,
    ethertype: EtherType,
    payload: &[u8],
) {
    out.reserve(TAGGED_HEADER_LEN + payload.len());
    out.extend_from_slice(&dst.0);
    out.extend_from_slice(&src.0);
    if let Some(tag) = vlan {
        out.extend_from_slice(&EtherType::VLAN.0.to_be_bytes());
        out.extend_from_slice(&tag.tci().to_be_bytes());
    }
    out.extend_from_slice(&ethertype.0.to_be_bytes());
    out.extend_from_slice(payload);
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const DST: MacAddr = MacAddr::BROADCAST;
    const SRC: MacAddr = MacAddr::new([0x02, 0, 0, 0, 0, 0x01]);

    fn frame(vlan: Option<VlanTag>, ty: EtherType, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        encode_frame(&mut v, DST, SRC, vlan, ty, payload);
        v
    }

    #[test]
    fn parses_untagged_ipv4() {
        let bytes = frame(None, EtherType::IPV4, &[0x45, 0, 0, 20]);
        let f = EthernetFrame::new_checked(&bytes[..]).expect("valid frame");
        assert_eq!(f.dst(), DST);
        assert_eq!(f.src(), SRC);
        assert_eq!(f.vlan(), None);
        assert_eq!(f.ethertype(), EtherType::IPV4);
        assert_eq!(f.header_len(), 14);
        assert_eq!(f.payload(), &[0x45, 0, 0, 20]);
    }

    #[test]
    fn parses_802_1q_tag() {
        let tag = VlanTag::new(5, true, 42).expect("in range");
        let bytes = frame(Some(tag), EtherType::IPV6, b"hi");
        assert_eq!(&bytes[12..16], &[0x81, 0x00, 0xb0, 0x2a]);
        let f = EthernetFrame::new_checked(bytes.as_slice()).expect("valid frame");
        assert_eq!(f.vlan(), Some(tag));
        assert_eq!((tag.pcp(), tag.dei(), tag.vid()), (5, true, 42));
        assert_eq!(f.ethertype(), EtherType::IPV6);
        assert_eq!(f.header_len(), 18);
        assert_eq!(f.payload(), b"hi");
    }

    #[test]
    fn owned_buffers_work_too() {
        let f = EthernetFrame::new_checked(frame(None, EtherType::ARP, &[1, 2, 3])).expect("valid");
        assert_eq!(f.ethertype(), EtherType::ARP);
        assert_eq!(f.into_inner().len(), 17);
    }

    #[test]
    fn vlan_tag_bounds() {
        assert!(VlanTag::new(8, false, 1).is_none());
        assert!(VlanTag::new(0, false, 4096).is_none());
        let t = VlanTag::new(7, false, 4095).expect("max values");
        assert_eq!(VlanTag::from_tci(t.tci()), t);
    }

    #[test]
    fn ieee_802_3_length_trims_padding() {
        // STP-style LLC frame: length 3, then zero padding up to a 60-byte minimum frame.
        let mut bytes = frame(None, EtherType(3), &[0x42, 0x42, 0x03]);
        bytes.resize(60, 0);
        let f = EthernetFrame::new_checked(&bytes[..]).expect("valid 802.3 frame");
        assert!(f.ethertype().is_length());
        assert_eq!(f.payload(), &[0x42, 0x42, 0x03]);
    }

    #[test]
    fn rejects_bad_input_without_panicking() {
        assert_eq!(
            EthernetFrame::new_checked(&[][..]),
            Err(FrameError::Truncated { len: 0, needed: 14 })
        );
        let tagged = frame(Some(VlanTag::from_tci(1)), EtherType::IPV4, &[]);
        assert_eq!(
            EthernetFrame::new_checked(&tagged[..16]),
            Err(FrameError::Truncated {
                len: 16,
                needed: 18
            })
        );
        assert_eq!(
            EthernetFrame::new_checked(frame(None, EtherType(0x05ff), &[])),
            Err(FrameError::InvalidTypeField(0x05ff))
        );
        assert_eq!(
            EthernetFrame::new_checked(frame(None, EtherType(10), &[0; 4])),
            Err(FrameError::LengthMismatch {
                declared: 10,
                available: 4
            })
        );
    }

    #[test]
    fn every_prefix_of_a_valid_frame_is_handled() {
        let bytes = frame(Some(VlanTag::from_tci(7)), EtherType::IPV4, &[9; 8]);
        for n in 0..=bytes.len() {
            let parsed = EthernetFrame::new_checked(&bytes[..n]);
            assert_eq!(parsed.is_ok(), n >= TAGGED_HEADER_LEN, "prefix {n}");
        }
    }

    #[test]
    fn garbage_never_panics() {
        // Deterministic xorshift garbage: every accessor must be total on every accepted input.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for round in 0..2000usize {
            let len = round % 40;
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = state as u8;
            }
            if round % 3 == 0 && len >= 14 {
                buf[12..14].copy_from_slice(&[0x81, 0x00]);
            }
            if let Ok(f) = EthernetFrame::new_checked(&buf[..]) {
                let _ = (f.dst(), f.src(), f.vlan(), f.ethertype());
                assert!(f.header_len() + f.payload().len() <= len);
                let _ = alloc::format!("{f:?}");
            }
        }
    }
}
