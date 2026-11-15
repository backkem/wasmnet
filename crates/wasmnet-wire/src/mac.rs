//! 48-bit IEEE 802 MAC addresses.

use core::fmt;
use core::str::FromStr;

/// A 48-bit Ethernet MAC address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// `ff:ff:ff:ff:ff:ff`
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    /// `00:00:00:00:00:00`
    pub const ZERO: MacAddr = MacAddr([0; 6]);

    /// Bit 0 of the first octet: the I/G (individual/group) bit.
    const GROUP_BIT: u8 = 0x01;
    /// Bit 1 of the first octet: the U/L (universal/local) bit.
    const LOCAL_BIT: u8 = 0x02;

    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Builds a MAC from the first 6 bytes of `bytes`. Returns `None` if there are fewer than 6.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let octets: [u8; 6] = bytes.get(..6)?.try_into().ok()?;
        Some(Self(octets))
    }

    /// A deterministic, **locally administered unicast** address derived from `seed`.
    ///
    /// The same seed always yields the same address on every platform. The seed is mixed with
    /// SplitMix64, so nearby seeds (node 0, node 1, …) give unrelated addresses. The U/L bit is set
    /// and the I/G bit is cleared, so the result never collides with a vendor (OUI) address and is
    /// never multicast.
    pub const fn local_from_seed(seed: u64) -> Self {
        let x = splitmix64(seed).to_be_bytes();
        let first = (x[2] | Self::LOCAL_BIT) & !Self::GROUP_BIT;
        Self([first, x[3], x[4], x[5], x[6], x[7]])
    }

    /// True for group addresses (multicast *and* broadcast).
    pub const fn is_multicast(self) -> bool {
        self.0[0] & Self::GROUP_BIT != 0
    }

    pub const fn is_broadcast(self) -> bool {
        let o = self.0;
        o[0] == 0xff && o[1] == 0xff && o[2] == 0xff && o[3] == 0xff && o[4] == 0xff && o[5] == 0xff
    }

    pub const fn is_unicast(self) -> bool {
        !self.is_multicast()
    }

    pub const fn is_locally_administered(self) -> bool {
        self.0[0] & Self::LOCAL_BIT != 0
    }
}

/// SplitMix64 finalizer (Steele, Lea & Flood 2014): a cheap, well-mixed bijection on `u64`.
const fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(mac: MacAddr) -> Self {
        mac.0
    }
}

impl fmt::Display for MacAddr {
    /// Lowercase, colon separated: `02:00:5e:10:00:01`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// `MacAddr::from_str` failed: the text is not six colon-separated two-digit hex octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid MAC address (want six colon-separated hex octets like 02:00:5e:10:00:01)")]
pub struct ParseMacError;

impl FromStr for MacAddr {
    type Err = ParseMacError;

    /// Parses `02:00:5e:10:00:01` (either case; exactly two hex digits per octet).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut parts = s.split(':');
        for octet in &mut octets {
            let part = parts.next().ok_or(ParseMacError)?;
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ParseMacError);
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| ParseMacError)?;
        }
        match parts.next() {
            Some(_) => Err(ParseMacError),
            None => Ok(Self(octets)),
        }
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use std::collections::BTreeSet;

    #[test]
    fn display_is_lowercase_colon_hex() {
        let mac = MacAddr::new([0x02, 0x00, 0x5e, 0xab, 0xcd, 0x0f]);
        assert_eq!(mac.to_string(), "02:00:5e:ab:cd:0f");
        assert_eq!(MacAddr::BROADCAST.to_string(), "ff:ff:ff:ff:ff:ff");
        assert_eq!(alloc::format!("{mac:?}"), "MacAddr(02:00:5e:ab:cd:0f)");
    }

    #[test]
    fn classification() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_multicast());
        // IPv4 mDNS group 224.0.0.251 maps to 01:00:5e:00:00:fb.
        let mdns4 = MacAddr::new([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
        assert!(mdns4.is_multicast() && !mdns4.is_broadcast());
        // IPv6 mDNS group ff02::fb maps to 33:33:00:00:00:fb.
        assert!(MacAddr::new([0x33, 0x33, 0, 0, 0, 0xfb]).is_multicast());
        let unicast = MacAddr::new([0x00, 0x1b, 0x21, 0x01, 0x02, 0x03]);
        assert!(unicast.is_unicast() && !unicast.is_locally_administered());
        assert!(!MacAddr::ZERO.is_multicast());
    }

    #[test]
    fn seeded_addresses_are_stable_local_unicast_and_distinct() {
        // Pinned value: changing the derivation changes every network's pcaps, so pin it.
        // SplitMix64(0) = 0xe220a8397b1dcdaf (reference value); bytes 2..8 with U/L set, I/G cleared.
        assert_eq!(MacAddr::local_from_seed(0).to_string(), "aa:39:7b:1d:cd:af");
        assert_eq!(MacAddr::local_from_seed(42), MacAddr::local_from_seed(42));

        let mut seen = BTreeSet::new();
        for seed in 0..4096u64 {
            let mac = MacAddr::local_from_seed(seed);
            assert!(mac.is_locally_administered(), "{mac}");
            assert!(mac.is_unicast(), "{mac}");
            assert!(seen.insert(mac), "collision at seed {seed}: {mac}");
        }
    }

    #[test]
    fn parses_what_it_displays() {
        let mac = MacAddr::new([0x02, 0x00, 0x5e, 0xab, 0xcd, 0x0f]);
        assert_eq!("02:00:5e:ab:cd:0f".parse(), Ok(mac));
        assert_eq!("02:00:5E:AB:CD:0F".parse(), Ok(mac));
        assert_eq!(mac.to_string().parse(), Ok(mac));
        for bad in [
            "",
            "02:00:5e:ab:cd",
            "02:00:5e:ab:cd:0f:00",
            "2:00:5e:ab:cd:0f",
            "02-00-5e-ab-cd-0f",
            "02:00:5e:ab:cd:+f",
            "0g:00:00:00:00:00",
        ] {
            assert_eq!(bad.parse::<MacAddr>(), Err(ParseMacError), "{bad:?}");
        }
    }

    #[test]
    fn from_slice_rejects_short_input() {
        assert_eq!(MacAddr::from_slice(&[1, 2, 3, 4, 5]), None);
        assert_eq!(
            MacAddr::from_slice(&[1, 2, 3, 4, 5, 6, 7]),
            Some(MacAddr::new([1, 2, 3, 4, 5, 6]))
        );
    }
}
