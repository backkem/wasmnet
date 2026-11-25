//! A small, strict pcap-ng **reader** for tests and tools.
//!
//! It is written independently of the encoder in `wasmnet-wire` so that it can check the
//! encoder's output. It accepts one little-endian section with Section Header, Interface
//! Description and Enhanced Packet Blocks, and skips any other block type. Every length, padding
//! and option is checked. Anything a strict reader such as Wireshark would reject is an error.

/// The direction of a packet relative to its capturing interface: what [`Packet::direction`]
/// holds (`wasmnet-wire`'s type, which the encoder writes).
pub use wasmnet_wire::Direction;

const SHB: u32 = 0x0A0D_0D0A;
const IDB: u32 = 0x0000_0001;
const EPB: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

/// Why a capture is invalid, and where.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid pcap-ng at byte {offset}: {reason}")]
pub struct PcapError {
    pub offset: usize,
    pub reason: String,
}

/// One Interface Description Block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub linktype: u16,
    pub snaplen: u32,
    /// `if_name`, if present.
    pub name: Option<String>,
    /// `if_tsresol` (6 = microseconds when absent).
    pub tsresol: u8,
}

/// One Enhanced Packet Block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub interface: u32,
    /// Raw timestamp in the interface's `if_tsresol` units (nanoseconds for wasmnet captures).
    pub timestamp: u64,
    pub original_len: u32,
    pub data: Vec<u8>,
    /// From `epb_flags`, if present.
    pub direction: Option<Direction>,
}

/// A parsed capture.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capture {
    /// `shb_userappl`, if present.
    pub user_appl: Option<String>,
    pub interfaces: Vec<Interface>,
    pub packets: Vec<Packet>,
}

/// Parses and validates a complete pcap-ng file.
pub fn parse(bytes: &[u8]) -> Result<Capture, PcapError> {
    if bytes.is_empty() {
        return Err(PcapError {
            offset: 0,
            reason: "empty file".to_owned(),
        });
    }
    let mut cap = Capture::default();
    let mut at = 0;
    while at < bytes.len() {
        let err = |off: usize, reason: &str| PcapError {
            offset: off,
            reason: reason.to_owned(),
        };
        let block_type = le32(bytes, at).ok_or_else(|| err(at, "truncated block header"))?;
        let len = le32(bytes, at + 4).ok_or_else(|| err(at, "truncated block header"))? as usize;
        if len < 12 || !len.is_multiple_of(4) {
            return Err(err(at, &format!("bad block length {len}")));
        }
        let end = at
            .checked_add(len)
            .filter(|&e| e <= bytes.len())
            .ok_or_else(|| err(at, &format!("block of {len} bytes runs past the end")))?;
        if le32(bytes, end - 4) != Some(len as u32) {
            return Err(err(end - 4, "trailing block length does not match"));
        }
        let body = &bytes[at + 8..end - 4];
        if at == 0 && block_type != SHB {
            return Err(err(0, "file does not start with a Section Header Block"));
        }
        match block_type {
            SHB if at == 0 => cap.user_appl = parse_shb(body).map_err(|r| err(at, &r))?,
            SHB => return Err(err(at, "multiple sections are not supported")),
            IDB => cap
                .interfaces
                .push(parse_idb(body).map_err(|r| err(at, &r))?),
            EPB => {
                let p = parse_epb(body, &cap.interfaces).map_err(|r| err(at, &r))?;
                cap.packets.push(p);
            }
            _ => {}
        }
        at = end;
    }
    Ok(cap)
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Walks a TLV option list, returning `(code, value)` pairs. Requires 4-byte padding and, if any
/// option is present, a terminating `opt_endofopt` that ends the list exactly.
fn options(mut b: &[u8]) -> Result<Vec<(u16, &[u8])>, String> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let code = le16(b, 0).ok_or("truncated option header")?;
        let len = usize::from(le16(b, 2).ok_or("truncated option header")?);
        if code == 0 {
            if len != 0 || b.len() != 4 {
                return Err("opt_endofopt is not the last 4 bytes of the option list".into());
            }
            return Ok(out);
        }
        let padded = 4 + len.div_ceil(4) * 4;
        let value = b
            .get(4..4 + len)
            .ok_or("option value runs past the block")?;
        if b.len() < padded {
            return Err("option padding runs past the block".into());
        }
        out.push((code, value));
        b = &b[padded..];
    }
    if out.is_empty() {
        Ok(out)
    } else {
        Err("option list without opt_endofopt".into())
    }
}

fn utf8(v: &[u8]) -> Result<String, String> {
    String::from_utf8(v.to_vec()).map_err(|_| "option string is not UTF-8".to_owned())
}

fn parse_shb(body: &[u8]) -> Result<Option<String>, String> {
    if le32(body, 0) != Some(BYTE_ORDER_MAGIC) {
        return Err("bad byte-order magic (only little-endian is supported)".into());
    }
    if (le16(body, 4), le16(body, 6)) != (Some(1), Some(0)) {
        return Err("unsupported version (want 1.0)".into());
    }
    let opts = options(body.get(16..).ok_or("truncated SHB")?)?;
    opts.iter()
        .find(|(c, _)| *c == 4)
        .map(|(_, v)| utf8(v))
        .transpose()
}

fn parse_idb(body: &[u8]) -> Result<Interface, String> {
    let linktype = le16(body, 0).ok_or("truncated IDB")?;
    let snaplen = le32(body, 4).ok_or("truncated IDB")?;
    let mut iface = Interface {
        linktype,
        snaplen,
        name: None,
        tsresol: 6,
    };
    for (code, value) in options(&body[8..])? {
        match code {
            2 => iface.name = Some(utf8(value)?),
            9 => {
                if value.len() != 1 {
                    return Err("if_tsresol must be 1 byte".into());
                }
                iface.tsresol = value[0];
            }
            _ => {}
        }
    }
    Ok(iface)
}

fn parse_epb(body: &[u8], interfaces: &[Interface]) -> Result<Packet, String> {
    let interface = le32(body, 0).ok_or("truncated EPB")?;
    let iface = interfaces
        .get(interface as usize)
        .ok_or_else(|| format!("EPB refers to unknown interface {interface}"))?;
    let ts_high = u64::from(le32(body, 4).ok_or("truncated EPB")?);
    let ts_low = u64::from(le32(body, 8).ok_or("truncated EPB")?);
    let captured = le32(body, 12).ok_or("truncated EPB")? as usize;
    let original_len = le32(body, 16).ok_or("truncated EPB")?;
    if captured > original_len as usize {
        return Err("captured length exceeds original length".into());
    }
    if iface.snaplen != 0 && captured > iface.snaplen as usize {
        return Err("captured length exceeds the interface snaplen".into());
    }
    // Checked: `captured` comes from the file, and `usize` is 32 bits on wasm32.
    let data = 20usize
        .checked_add(captured)
        .and_then(|end| body.get(20..end))
        .ok_or("packet data runs past the block")?;
    let padded = captured
        .div_ceil(4)
        .checked_mul(4)
        .and_then(|p| p.checked_add(20))
        .ok_or("packet padding runs past the block")?;
    let rest = body
        .get(padded..)
        .ok_or("packet padding runs past the block")?;
    let mut direction = None;
    for (code, value) in options(rest)? {
        if code == 2 {
            let flags =
                u32::from_le_bytes(value.try_into().map_err(|_| "epb_flags must be 4 bytes")?);
            direction = match flags & 0b11 {
                0b01 => Some(Direction::Inbound),
                0b10 => Some(Direction::Outbound),
                _ => None,
            };
        }
    }
    Ok(Packet {
        interface,
        timestamp: (ts_high << 32) | ts_low,
        original_len,
        data: data.to_vec(),
        direction,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmnet_wire::PcapNgEncoder;

    fn sample() -> Vec<u8> {
        let mut enc = PcapNgEncoder::new("wasmnet").unwrap();
        let a = enc.add_ethernet_interface("a:0", 0).unwrap();
        let b = enc.add_ethernet_interface("b:0", 4).unwrap();
        enc.write_packet_directed(a, 5, &[1, 2, 3], Direction::Outbound)
            .unwrap();
        enc.write_packet(b, 0x1_0000_0007, &[9; 6]).unwrap();
        enc.into_bytes()
    }

    #[test]
    fn reads_what_the_encoder_writes() {
        let cap = parse(&sample()).unwrap();
        assert_eq!(cap.user_appl.as_deref(), Some("wasmnet"));
        assert_eq!(cap.interfaces.len(), 2);
        assert_eq!(cap.interfaces[0].name.as_deref(), Some("a:0"));
        assert_eq!(
            (cap.interfaces[1].linktype, cap.interfaces[1].tsresol),
            (1, 9)
        );
        assert_eq!(cap.packets[0].data, [1, 2, 3]);
        assert_eq!(cap.packets[0].direction, Some(Direction::Outbound));
        assert_eq!(cap.packets[1].timestamp, 0x1_0000_0007);
        assert_eq!(
            (cap.packets[1].data.len(), cap.packets[1].original_len),
            (4, 6)
        );
        assert_eq!(cap.packets[1].direction, None);
    }

    #[test]
    fn rejects_corruption_anywhere() {
        let good = sample();
        assert!(parse(&[]).is_err());
        // A prefix is valid exactly when it ends on a block boundary.
        let mut boundaries = vec![];
        let mut at = 0;
        while at < good.len() {
            at += le32(&good, at + 4).unwrap() as usize;
            boundaries.push(at);
        }
        for n in 1..good.len() {
            assert_eq!(
                parse(&good[..n]).is_ok(),
                boundaries.contains(&n),
                "prefix {n}"
            );
        }
        // Breaking the trailing length of the first block is caught.
        let mut bad = good.clone();
        let shb_len = le32(&good, 4).unwrap() as usize;
        bad[shb_len - 4] ^= 0xff;
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn a_huge_captured_length_is_an_error() {
        // Interface 0 has no snaplen; the EPB claims u32::MAX captured bytes.
        let iface = Interface {
            linktype: 1,
            snaplen: 0,
            name: None,
            tsresol: 6,
        };
        let mut epb = vec![0u8; 12];
        epb.extend_from_slice(&u32::MAX.to_le_bytes());
        epb.extend_from_slice(&u32::MAX.to_le_bytes());
        epb.extend_from_slice(&[0; 8]);
        assert!(parse_epb(&epb, &[iface]).is_err());
    }
}
