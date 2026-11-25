//! DHCPv4 / BOOTP messages (RFC 2131, RFC 2132, RFC 951): parse and encode.
//!
//! Shared by the `dhcp-server` app (it builds replies), the router's RFC 1542 relay (it reads and
//! patches requests and replies in place, see the field offsets) and packet decoders. The
//! netstack's DHCP *client* is smoltcp's `socket-dhcpv4`, which has its own codec.
//!
//! A [`Message`] keeps the fixed BOOTP header fields and the options in wire order. `sname` and
//! `file` are not interpreted (option overload, option 52, is not supported): they are kept as
//! zeros when encoding. Encoding pads the message to [`MIN_LEN`] bytes, the BOOTP minimum
//! (RFC 1542 §2.1), so old relays and Wireshark see a normal-sized message.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::MacAddr;

/// The server (and relay) port.
pub const SERVER_PORT: u16 = 67;
/// The client port.
pub const CLIENT_PORT: u16 = 68;
/// `op` of a client's message.
pub const BOOTREQUEST: u8 = 1;
/// `op` of a server's (or relay's) message.
pub const BOOTREPLY: u8 = 2;
/// The options magic cookie, 99.130.83.99.
pub const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// The `flags` broadcast bit: the client cannot receive unicast before it is configured.
pub const FLAG_BROADCAST: u16 = 0x8000;
/// The fixed header (236 bytes) and the magic cookie.
pub const HEADER_LEN: usize = 240;
/// The smallest message a BOOTP agent must accept; encoded messages are padded to it.
pub const MIN_LEN: usize = 300;

/// Byte offsets of the fixed header fields, for agents that patch a message in place (the
/// router's relay).
pub mod offset {
    pub const OP: usize = 0;
    pub const HOPS: usize = 3;
    pub const XID: usize = 4;
    pub const FLAGS: usize = 10;
    pub const CIADDR: usize = 12;
    pub const YIADDR: usize = 16;
    pub const SIADDR: usize = 20;
    pub const GIADDR: usize = 24;
    pub const CHADDR: usize = 28;
}

/// Option codes (RFC 2132) used in wasmnet.
pub mod opt {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS_SERVERS: u8 = 6;
    pub const HOSTNAME: u8 = 12;
    pub const DOMAIN_NAME: u8 = 15;
    pub const BROADCAST_ADDRESS: u8 = 28;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAMETER_LIST: u8 = 55;
    pub const MESSAGE: u8 = 56;
    pub const MAX_SIZE: u8 = 57;
    pub const RENEWAL_TIME: u8 = 58;
    pub const REBINDING_TIME: u8 = 59;
    pub const CLIENT_ID: u8 = 61;
    pub const END: u8 = 255;
}

/// A message that could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DhcpError {
    #[error("DHCP message shorter than its 240-byte header")]
    Truncated,
    #[error("DHCP magic cookie missing")]
    BadCookie,
    #[error("DHCP option {0} runs past the end of the message")]
    BadOption(u8),
}

/// Option 53, the DHCP message type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            _ => return None,
        })
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
        }
    }

    /// Lowercase name: `discover`, `offer`, `request`, `decline`, `ack`, `nak`, `release`,
    /// `inform`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Offer => "offer",
            Self::Request => "request",
            Self::Decline => "decline",
            Self::Ack => "ack",
            Self::Nak => "nak",
            Self::Release => "release",
            Self::Inform => "inform",
        }
    }

    /// Parses [`name`](Self::name) (case-insensitive).
    pub fn from_name(name: &str) -> Option<Self> {
        (1..=8)
            .filter_map(Self::from_u8)
            .find(|t| t.name().eq_ignore_ascii_case(name))
    }
}

/// A DHCP (BOOTP) message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    /// Options in wire order (no pad, no end).
    pub options: Vec<(u8, Vec<u8>)>,
}

fn v4(b: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3])
}

impl Message {
    /// An empty reply to `request` (same xid, flags, giaddr and chaddr; RFC 2131 Table 3).
    pub fn reply_to(request: &Message, kind: MessageType) -> Self {
        let mut m = Message {
            op: BOOTREPLY,
            htype: request.htype,
            hlen: request.hlen,
            hops: 0,
            xid: request.xid,
            secs: 0,
            flags: request.flags,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: request.giaddr,
            chaddr: request.chaddr,
            options: Vec::new(),
        };
        m.set_option(opt::MESSAGE_TYPE, &[kind.to_u8()]);
        m
    }

    /// Parses a UDP payload.
    pub fn parse(b: &[u8]) -> Result<Self, DhcpError> {
        if b.len() < HEADER_LEN {
            return Err(DhcpError::Truncated);
        }
        if b[236..240] != MAGIC {
            return Err(DhcpError::BadCookie);
        }
        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&b[28..44]);
        let mut options = Vec::new();
        let mut rest = &b[HEADER_LEN..];
        while let Some((&code, tail)) = rest.split_first() {
            match code {
                opt::PAD => rest = tail,
                opt::END => break,
                _ => {
                    let len = usize::from(*tail.first().ok_or(DhcpError::BadOption(code))?);
                    let data = tail.get(1..1 + len).ok_or(DhcpError::BadOption(code))?;
                    options.push((code, data.to_vec()));
                    rest = &tail[1 + len..];
                }
            }
        }
        Ok(Message {
            op: b[0],
            htype: b[1],
            hlen: b[2],
            hops: b[3],
            xid: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            secs: u16::from_be_bytes([b[8], b[9]]),
            flags: u16::from_be_bytes([b[10], b[11]]),
            ciaddr: v4(b, 12),
            yiaddr: v4(b, 16),
            siaddr: v4(b, 20),
            giaddr: v4(b, 24),
            chaddr,
            options,
        })
    }

    /// The UDP payload: header, cookie, options, END, padded with zeros to [`MIN_LEN`]. An option
    /// longer than 255 bytes is truncated to 255.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(MIN_LEN);
        b.extend_from_slice(&[self.op, self.htype, self.hlen, self.hops]);
        b.extend_from_slice(&self.xid.to_be_bytes());
        b.extend_from_slice(&self.secs.to_be_bytes());
        b.extend_from_slice(&self.flags.to_be_bytes());
        for a in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            b.extend_from_slice(&a.octets());
        }
        b.extend_from_slice(&self.chaddr);
        b.resize(236, 0); // sname (64) and file (128): unused
        b.extend_from_slice(&MAGIC);
        for (code, data) in &self.options {
            let data = &data[..data.len().min(255)];
            b.push(*code);
            b.push(data.len() as u8);
            b.extend_from_slice(data);
        }
        b.push(opt::END);
        if b.len() < MIN_LEN {
            b.resize(MIN_LEN, 0);
        }
        b
    }

    /// The first option `code`.
    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, d)| d.as_slice())
    }

    /// Replaces option `code` (or appends it).
    pub fn set_option(&mut self, code: u8, data: &[u8]) {
        match self.options.iter_mut().find(|(c, _)| *c == code) {
            Some((_, d)) => *d = data.to_vec(),
            None => self.options.push((code, data.to_vec())),
        }
    }

    /// Option 53.
    pub fn message_type(&self) -> Option<MessageType> {
        MessageType::from_u8(*self.option(opt::MESSAGE_TYPE)?.first()?)
    }

    /// `chaddr` as an Ethernet address (htype 1, hlen 6).
    pub fn client_mac(&self) -> Option<MacAddr> {
        (self.htype == 1 && self.hlen == 6).then(|| MacAddr::from_slice(&self.chaddr))?
    }

    /// A one-address option (`server-id`, `requested-ip`, `subnet-mask`).
    pub fn addr_option(&self, code: u8) -> Option<Ipv4Addr> {
        let d = self.option(code)?;
        (d.len() == 4).then(|| v4(d, 0))
    }

    /// A list-of-addresses option (`router`, `dns-servers`); malformed is empty.
    pub fn addrs_option(&self, code: u8) -> Vec<Ipv4Addr> {
        match self.option(code) {
            Some(d) if d.len() % 4 == 0 => d.chunks(4).map(|c| v4(c, 0)).collect(),
            _ => Vec::new(),
        }
    }

    /// A 32-bit option (lease, T1, T2), in seconds.
    pub fn u32_option(&self, code: u8) -> Option<u32> {
        let d: [u8; 4] = self.option(code)?.try_into().ok()?;
        Some(u32::from_be_bytes(d))
    }

    /// A text option (`hostname`, `domain-name`, `message`), if it is printable ASCII.
    pub fn text_option(&self, code: u8) -> Option<String> {
        let d = self.option(code)?;
        let d = d.strip_suffix(&[0]).unwrap_or(d);
        (d.iter().all(|b| b.is_ascii_graphic() || *b == b' '))
            .then(|| d.iter().map(|&b| char::from(b)).collect())
    }

    pub fn broadcast(&self) -> bool {
        self.flags & FLAG_BROADCAST != 0
    }
}

/// The prefix length of a contiguous subnet mask, or `None`.
pub fn mask_prefix(mask: Ipv4Addr) -> Option<u8> {
    let m = u32::from(mask);
    let ones = m.leading_ones();
    (m.checked_shl(ones).unwrap_or(0) == 0).then_some(ones as u8)
}

/// The subnet mask of a prefix length (0..=32).
pub fn prefix_mask(prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(
        u32::MAX
            .checked_shl(32 - u32::from(prefix.min(32)))
            .unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discover() -> Message {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&[2, 0, 0, 0, 2, 0x10]);
        Message {
            op: BOOTREQUEST,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0x1234_5678,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            options: alloc::vec![
                (opt::MESSAGE_TYPE, alloc::vec![1]),
                (opt::PARAMETER_LIST, alloc::vec![1, 3, 6]),
                (opt::HOSTNAME, b"alice".to_vec()),
            ],
        }
    }

    #[test]
    fn round_trip_and_accessors() {
        let m = discover();
        let bytes = m.encode();
        assert_eq!(bytes.len(), MIN_LEN);
        assert_eq!(&bytes[236..240], &MAGIC);
        assert_eq!(
            bytes[offset::XID..offset::XID + 4],
            [0x12, 0x34, 0x56, 0x78]
        );
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.message_type(), Some(MessageType::Discover));
        assert_eq!(back.client_mac(), Some(MacAddr([2, 0, 0, 0, 2, 0x10])));
        assert_eq!(back.text_option(opt::HOSTNAME).as_deref(), Some("alice"));
        assert!(!back.broadcast());

        let mut offer = Message::reply_to(&m, MessageType::Offer);
        offer.yiaddr = Ipv4Addr::new(10, 0, 2, 100);
        offer.set_option(opt::SERVER_ID, &[10, 0, 1, 2]);
        offer.set_option(opt::DNS_SERVERS, &[10, 0, 1, 2, 10, 0, 1, 3]);
        offer.set_option(opt::LEASE_TIME, &10u32.to_be_bytes());
        let o = Message::parse(&offer.encode()).unwrap();
        assert_eq!((o.op, o.xid), (BOOTREPLY, m.xid));
        assert_eq!(o.message_type(), Some(MessageType::Offer));
        assert_eq!(
            o.addr_option(opt::SERVER_ID),
            Some(Ipv4Addr::new(10, 0, 1, 2))
        );
        assert_eq!(o.addrs_option(opt::DNS_SERVERS).len(), 2);
        assert_eq!(o.u32_option(opt::LEASE_TIME), Some(10));
        assert_eq!(MessageType::from_name("ACK"), Some(MessageType::Ack));
        assert_eq!(MessageType::Nak.name(), "nak");
    }

    #[test]
    fn malformed_messages_are_errors_not_panics() {
        let bytes = discover().encode();
        assert_eq!(Message::parse(&bytes[..239]), Err(DhcpError::Truncated));
        let mut bad = bytes.clone();
        bad[236] = 0;
        assert_eq!(Message::parse(&bad), Err(DhcpError::BadCookie));
        let mut cut = bytes[..HEADER_LEN].to_vec();
        cut.extend_from_slice(&[opt::HOSTNAME, 10, b'a']);
        assert_eq!(Message::parse(&cut), Err(DhcpError::BadOption(12)));
        // No END option and padding: fine.
        let mut open = bytes[..HEADER_LEN].to_vec();
        open.extend_from_slice(&[0, 0, opt::MESSAGE_TYPE, 1, 3]);
        assert_eq!(
            Message::parse(&open).unwrap().message_type(),
            Some(MessageType::Request)
        );
    }

    #[test]
    fn masks() {
        assert_eq!(mask_prefix(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(mask_prefix(Ipv4Addr::new(255, 255, 0, 255)), None);
        assert_eq!(mask_prefix(Ipv4Addr::UNSPECIFIED), Some(0));
        assert_eq!(mask_prefix(Ipv4Addr::BROADCAST), Some(32));
        assert_eq!(prefix_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_mask(0), Ipv4Addr::UNSPECIFIED);
        assert_eq!(prefix_mask(32), Ipv4Addr::BROADCAST);
    }
}
