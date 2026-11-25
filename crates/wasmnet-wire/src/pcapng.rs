//! Minimal, deterministic pcap-ng **encoder** (no clock, no I/O).
//! A strict reader for checking its output lives in `wasmnet_host::pcap`.
//!
//! Writes one little-endian section: a Section Header Block, one Interface Description Block per
//! interface (linktype 1 = Ethernet, `if_tsresol` = 9 so timestamps are nanoseconds), and
//! Enhanced Packet Blocks (optionally with an `epb_flags` direction). Timestamps are always
//! passed in by the caller (virtual nanoseconds), and no host name, OS or wall-clock option is
//! ever emitted, so the same inputs always give byte-identical output.
//! Spec: <https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-03.html>.

use alloc::vec::Vec;

const SHB_TYPE: u32 = 0x0A0D_0D0A;
const IDB_TYPE: u32 = 0x0000_0001;
const EPB_TYPE: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const LINKTYPE_ETHERNET: u16 = 1;

const OPT_ENDOFOPT: u16 = 0;
const OPT_SHB_USERAPPL: u16 = 4;
const OPT_IF_NAME: u16 = 2;
const OPT_IF_DESCRIPTION: u16 = 3;
const OPT_IF_TSRESOL: u16 = 9;
const OPT_EPB_FLAGS: u16 = 2;
/// `if_tsresol` value: high bit clear, so the resolution is 10^-9 s.
const TSRESOL_NANOS: u8 = 9;

/// Index of an interface within the section, in the order interfaces were added.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct InterfaceId(pub u32);

/// Direction of a packet relative to the capturing interface, recorded as the `epb_flags`
/// inbound/outbound bits so Wireshark can show and filter on it (`frame.packet_flags_direction`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Direction {
    /// The interface received the packet.
    Inbound,
    /// The interface sent the packet.
    Outbound,
}

impl Direction {
    /// The `epb_flags` word: bits 0-1 are `01` for inbound and `10` for outbound.
    pub const fn epb_flags(self) -> u32 {
        match self {
            Direction::Inbound => 0b01,
            Direction::Outbound => 0b10,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PcapNgError {
    #[error("interface {0} was never added to this section")]
    UnknownInterface(u32),
    #[error("option value of {0} bytes does not fit in a pcap-ng option (max 65535)")]
    OptionTooLong(usize),
    #[error("block of {0} bytes does not fit in a pcap-ng block length (u32)")]
    BlockTooLarge(usize),
    #[error("too many interfaces in one section")]
    TooManyInterfaces,
}

/// Accumulates a pcap-ng capture in memory.
///
/// Use [`take_bytes`](Self::take_bytes) to stream completed blocks to a sink without holding the
/// whole capture. The concatenation of every drained chunk is the full file.
#[derive(Clone, Debug)]
pub struct PcapNgEncoder {
    buf: Vec<u8>,
    /// Snap length per interface (`0` = unlimited), indexed by [`InterfaceId`].
    snaplens: Vec<u32>,
}

impl PcapNgEncoder {
    /// Starts a new section. `user_appl` is recorded as `shb_userappl` and is omitted when empty.
    pub fn new(user_appl: &str) -> Result<Self, PcapNgError> {
        let mut enc = Self {
            buf: Vec::new(),
            snaplens: Vec::new(),
        };
        enc.block(SHB_TYPE, |b| {
            put_u32(b, BYTE_ORDER_MAGIC);
            put_u16(b, 1); // major
            put_u16(b, 0); // minor
            b.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unspecified
            let mut opts = Options::new(b);
            opts.add_str(OPT_SHB_USERAPPL, user_appl)?;
            opts.finish();
            Ok(())
        })?;
        Ok(enc)
    }

    /// Adds an Ethernet interface (an IDB with `if_tsresol` = 9). `snaplen` 0 means "no limit".
    /// `name` is recorded as `if_name` and is omitted when empty.
    pub fn add_ethernet_interface(
        &mut self,
        name: &str,
        snaplen: u32,
    ) -> Result<InterfaceId, PcapNgError> {
        self.add_described_interface(name, snaplen, "")
    }

    /// Like [`add_ethernet_interface`](Self::add_ethernet_interface), and also records
    /// `description` as `if_description`, after `if_name`. An empty description is omitted, so
    /// it writes exactly the bytes `add_ethernet_interface` does.
    pub fn add_described_interface(
        &mut self,
        name: &str,
        snaplen: u32,
        description: &str,
    ) -> Result<InterfaceId, PcapNgError> {
        let id = u32::try_from(self.snaplens.len()).map_err(|_| PcapNgError::TooManyInterfaces)?;
        self.block(IDB_TYPE, |b| {
            put_u16(b, LINKTYPE_ETHERNET);
            put_u16(b, 0); // reserved
            put_u32(b, snaplen);
            let mut opts = Options::new(b);
            opts.add_str(OPT_IF_NAME, name)?;
            opts.add_str(OPT_IF_DESCRIPTION, description)?;
            opts.add(OPT_IF_TSRESOL, &[TSRESOL_NANOS])?;
            opts.finish();
            Ok(())
        })?;
        self.snaplens.push(snaplen);
        Ok(InterfaceId(id))
    }

    /// Appends an Enhanced Packet Block. `timestamp_ns` is virtual time in nanoseconds.
    /// The frame is truncated to the interface's snap length, and the original length is kept.
    pub fn write_packet(
        &mut self,
        iface: InterfaceId,
        timestamp_ns: u64,
        frame: &[u8],
    ) -> Result<(), PcapNgError> {
        self.write_epb(iface, timestamp_ns, frame, frame.len(), None)
    }

    /// Like [`write_packet`](Self::write_packet), and also records the packet's [`Direction`]
    /// relative to `iface` as an `epb_flags` option.
    pub fn write_packet_directed(
        &mut self,
        iface: InterfaceId,
        timestamp_ns: u64,
        frame: &[u8],
        direction: Direction,
    ) -> Result<(), PcapNgError> {
        self.write_epb(iface, timestamp_ns, frame, frame.len(), Some(direction))
    }

    /// Like [`write_packet_directed`](Self::write_packet_directed) for a packet of which only
    /// the first bytes are at hand (`data`, already cut by an earlier capture): `original_len`
    /// is the packet's full length (taken as `data.len()` if shorter). The data is cut to the
    /// interface's snap length as well.
    pub fn write_packet_prefix(
        &mut self,
        iface: InterfaceId,
        timestamp_ns: u64,
        data: &[u8],
        original_len: usize,
        direction: Direction,
    ) -> Result<(), PcapNgError> {
        self.write_epb(iface, timestamp_ns, data, original_len, Some(direction))
    }

    fn write_epb(
        &mut self,
        iface: InterfaceId,
        timestamp_ns: u64,
        frame: &[u8],
        original_len: usize,
        direction: Option<Direction>,
    ) -> Result<(), PcapNgError> {
        let snaplen = *self
            .snaplens
            .get(iface.0 as usize)
            .ok_or(PcapNgError::UnknownInterface(iface.0))?;
        let original = original_len.max(frame.len());
        let original_len =
            u32::try_from(original).map_err(|_| PcapNgError::BlockTooLarge(original))?;
        // `frame.len() <= original_len`, so it fits in a u32 too.
        let have = frame.len() as u32;
        let captured_len = if snaplen == 0 {
            have
        } else {
            have.min(snaplen)
        };
        let data = frame.get(..captured_len as usize).unwrap_or(frame);
        self.block(EPB_TYPE, |b| {
            put_u32(b, iface.0);
            put_u32(b, (timestamp_ns >> 32) as u32);
            put_u32(b, timestamp_ns as u32);
            put_u32(b, captured_len);
            put_u32(b, original_len);
            b.extend_from_slice(data);
            pad4(b);
            let mut opts = Options::new(b);
            if let Some(dir) = direction {
                opts.add(OPT_EPB_FLAGS, &dir.epb_flags().to_le_bytes())?;
            }
            opts.finish();
            Ok(())
        })
    }

    /// Everything encoded so far that has not been taken.
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Drains the encoded bytes. Later blocks continue the same section.
    pub fn take_bytes(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.buf)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Frames a block: `type, total_len, body (padded to 4), total_len`. Leaves `buf` untouched on error.
    fn block(
        &mut self,
        block_type: u32,
        body: impl FnOnce(&mut Vec<u8>) -> Result<(), PcapNgError>,
    ) -> Result<(), PcapNgError> {
        let start = self.buf.len();
        put_u32(&mut self.buf, block_type);
        put_u32(&mut self.buf, 0); // patched below
        let result = body(&mut self.buf).and_then(|()| {
            pad4(&mut self.buf);
            let total = self.buf.len() - start + 4;
            u32::try_from(total).map_err(|_| PcapNgError::BlockTooLarge(total))
        });
        match result {
            Ok(total) => {
                put_u32(&mut self.buf, total);
                self.buf[start + 4..start + 8].copy_from_slice(&total.to_le_bytes());
                Ok(())
            }
            Err(e) => {
                self.buf.truncate(start);
                Err(e)
            }
        }
    }
}

/// Writes a TLV option list. `opt_endofopt` is emitted only if at least one option was written.
struct Options<'a> {
    buf: &'a mut Vec<u8>,
    any: bool,
}

impl<'a> Options<'a> {
    fn new(buf: &'a mut Vec<u8>) -> Self {
        Self { buf, any: false }
    }

    fn add(&mut self, code: u16, value: &[u8]) -> Result<(), PcapNgError> {
        let len =
            u16::try_from(value.len()).map_err(|_| PcapNgError::OptionTooLong(value.len()))?;
        put_u16(self.buf, code);
        put_u16(self.buf, len);
        self.buf.extend_from_slice(value);
        pad4(self.buf);
        self.any = true;
        Ok(())
    }

    fn add_str(&mut self, code: u16, value: &str) -> Result<(), PcapNgError> {
        if value.is_empty() {
            Ok(())
        } else {
            self.add(code, value.as_bytes())
        }
    }

    fn finish(self) {
        if self.any {
            put_u16(self.buf, OPT_ENDOFOPT);
            put_u16(self.buf, 0);
        }
    }
}

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn pad4(buf: &mut Vec<u8>) {
    let rem = buf.len() % 4;
    if rem != 0 {
        buf.resize(buf.len() + 4 - rem, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Reference capture: SHB("wasmnet") + IDB("a-b", snaplen 0) +
    /// EPB(t = 0x1_0000_0002 ns, 5 bytes).
    #[rustfmt::skip]
    const EXPECTED: &[u8] = &[
        // --- SHB, 44 bytes
        0x0a, 0x0d, 0x0d, 0x0a,  44, 0, 0, 0,
        0x4d, 0x3c, 0x2b, 0x1a,  1, 0,  0, 0,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        4, 0, 7, 0,  b'w', b'a', b's', b'm', b'n', b'e', b't', 0,
        0, 0, 0, 0,
        44, 0, 0, 0,
        // --- IDB, 40 bytes
        1, 0, 0, 0,  40, 0, 0, 0,
        1, 0,  0, 0,  0, 0, 0, 0,
        2, 0, 3, 0,  b'a', b'-', b'b', 0,
        9, 0, 1, 0,  9, 0, 0, 0,
        0, 0, 0, 0,
        40, 0, 0, 0,
        // --- EPB, 40 bytes
        6, 0, 0, 0,  40, 0, 0, 0,
        0, 0, 0, 0,
        1, 0, 0, 0,  2, 0, 0, 0,
        5, 0, 0, 0,  5, 0, 0, 0,
        0xde, 0xad, 0xbe, 0xef, 0x01, 0, 0, 0,
        40, 0, 0, 0,
    ];

    fn reference_capture() -> PcapNgEncoder {
        let mut enc = PcapNgEncoder::new("wasmnet").expect("shb");
        let eth0 = enc.add_ethernet_interface("a-b", 0).expect("idb");
        enc.write_packet(eth0, 0x1_0000_0002, &[0xde, 0xad, 0xbe, 0xef, 0x01])
            .expect("epb");
        enc
    }

    /// Walks the block structure and returns `(type, total_len)` per block, checking framing.
    fn walk(bytes: &[u8]) -> Vec<(u32, usize)> {
        let le32 = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let len = le32(at + 4) as usize;
            assert_eq!(len % 4, 0, "block at {at} not 32-bit aligned");
            assert_eq!(
                le32(at + len - 4) as usize,
                len,
                "trailing length mismatch at {at}"
            );
            out.push((le32(at), len));
            at += len;
        }
        assert_eq!(at, bytes.len());
        out
    }

    #[test]
    fn reference_bytes() {
        assert_eq!(reference_capture().bytes(), EXPECTED);
    }

    #[test]
    fn deterministic_for_same_inputs() {
        assert_eq!(
            reference_capture().into_bytes(),
            reference_capture().into_bytes()
        );
    }

    #[test]
    fn block_framing_and_streaming() {
        let mut enc = PcapNgEncoder::new("").expect("shb");
        let a = enc.add_ethernet_interface("", 0).expect("idb a");
        let b = enc.add_ethernet_interface("sw1:p3", 1514).expect("idb b");
        let mut file = enc.take_bytes();
        for (i, len) in [0usize, 1, 2, 3, 4, 60, 1514].into_iter().enumerate() {
            let frame = vec![i as u8; len];
            enc.write_packet(if i % 2 == 0 { a } else { b }, i as u64 * 1_000, &frame)
                .expect("epb");
        }
        file.extend(enc.take_bytes());
        let blocks = walk(&file);
        let types: Vec<u32> = blocks.iter().map(|&(t, _)| t).collect();
        assert_eq!(types, [SHB_TYPE, IDB_TYPE, IDB_TYPE, 6, 6, 6, 6, 6, 6, 6]);
        // SHB without options is exactly 28 bytes and has no opt_endofopt.
        assert_eq!(blocks[0].1, 28);
        // IDB with only if_tsresol: 16 header + 8 option + 4 endofopt + 4 trailer.
        assert_eq!(blocks[1].1, 32);
    }

    #[test]
    fn snaplen_truncates_but_keeps_original_length() {
        let mut enc = PcapNgEncoder::new("").expect("shb");
        let i = enc.add_ethernet_interface("", 4).expect("idb");
        let start = enc.bytes().len();
        enc.write_packet(i, 7, &[1, 2, 3, 4, 5, 6]).expect("epb");
        let epb = &enc.bytes()[start..];
        assert_eq!(&epb[20..24], &4u32.to_le_bytes()); // captured
        assert_eq!(&epb[24..28], &6u32.to_le_bytes()); // original
        assert_eq!(&epb[28..32], &[1, 2, 3, 4]);
        assert_eq!(epb.len(), 36);
    }

    #[test]
    fn a_prefix_keeps_the_original_length_and_still_obeys_the_snap_length() {
        let mut enc = PcapNgEncoder::new("").expect("shb");
        let whole = enc.add_ethernet_interface("", 0).expect("idb");
        let snapped = enc.add_ethernet_interface("", 2).expect("idb");
        let start = enc.bytes().len();
        enc.write_packet_prefix(whole, 7, &[1, 2, 3, 4], 1514, Direction::Inbound)
            .expect("epb");
        let epb = &enc.bytes()[start..];
        assert_eq!(&epb[20..24], &4u32.to_le_bytes()); // captured
        assert_eq!(&epb[24..28], &1514u32.to_le_bytes()); // original
        let start = enc.bytes().len();
        enc.write_packet_prefix(snapped, 7, &[1, 2, 3, 4], 0, Direction::Inbound)
            .expect("epb");
        let epb = &enc.bytes()[start..];
        assert_eq!(&epb[20..24], &2u32.to_le_bytes());
        assert_eq!(
            &epb[24..28],
            &4u32.to_le_bytes(),
            "never shorter than the data"
        );
    }

    #[test]
    fn a_description_follows_the_name_and_an_empty_one_changes_nothing() {
        let mut plain = PcapNgEncoder::new("").expect("shb");
        plain.add_ethernet_interface("a-b", 0).expect("idb");
        let mut empty = PcapNgEncoder::new("").expect("shb");
        empty.add_described_interface("a-b", 0, "").expect("idb");
        assert_eq!(plain.bytes(), empty.bytes());

        let mut enc = PcapNgEncoder::new("").expect("shb");
        let start = enc.bytes().len();
        enc.add_described_interface("a-b", 64, "end").expect("idb");
        let idb = &enc.bytes()[start..];
        // 16 header + 8 if_name + 8 if_description + 8 if_tsresol + 4 endofopt + 4 trailer.
        assert_eq!(idb.len(), 48);
        assert_eq!(&idb[12..16], &64u32.to_le_bytes());
        assert_eq!(&idb[24..32], &[3, 0, 3, 0, b'e', b'n', b'd', 0]);
    }

    #[test]
    fn directed_packets_carry_epb_flags() {
        let mut enc = PcapNgEncoder::new("").expect("shb");
        let i = enc.add_ethernet_interface("", 0).expect("idb");
        let start = enc.bytes().len();
        enc.write_packet_directed(i, 9, &[0xaa; 5], Direction::Outbound)
            .expect("epb");
        let epb = &enc.bytes()[start..];
        // 28 header + 8 data (5 padded) + 8 epb_flags + 4 endofopt + 4 trailer.
        assert_eq!(epb.len(), 52);
        assert_eq!(&epb[4..8], &52u32.to_le_bytes());
        assert_eq!(&epb[36..40], &[2, 0, 4, 0]);
        assert_eq!(&epb[40..44], &2u32.to_le_bytes());
        assert_eq!(&epb[44..48], &[0, 0, 0, 0]);
        assert_eq!(Direction::Inbound.epb_flags(), 1);
        let blocks = walk(enc.bytes());
        assert_eq!(blocks.last(), Some(&(EPB_TYPE, 52)));
    }

    #[test]
    fn errors_leave_output_untouched() {
        let mut enc = PcapNgEncoder::new("").expect("shb");
        let before = enc.bytes().to_vec();
        assert_eq!(
            enc.write_packet(InterfaceId(0), 0, &[1]),
            Err(PcapNgError::UnknownInterface(0))
        );
        let long = "x".repeat(70_000);
        assert_eq!(
            enc.add_ethernet_interface(&long, 0),
            Err(PcapNgError::OptionTooLong(70_000))
        );
        assert_eq!(enc.bytes(), before.as_slice());
    }
}
