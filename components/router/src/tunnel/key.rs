//! A tunnel's key and what is derived from it.
//!
//! The controller supplies one 32-byte key per tunnel (the same at both ends); the router never
//! invents or negotiates one. Everything a keyed tunnel uses is derived from it with HKDF-SHA256
//! (RFC 5869), salt [`SALT`], a label per purpose:
//!
//! | label | output | used for |
//! |---|---|---|
//! | `stun-password` | 32 bytes, as 64 lowercase hex digits | the STUN short-term password: `MESSAGE-INTEGRITY-SHA256` of checks and their answers |
//! | `spi` + epoch + transit address | 4 bytes, top bit set | the SPI this end receives ESP on |
//! | `esp` + receiver's SPI + sender's epoch | 36 bytes: key and salt | the ChaCha20-Poly1305 SA (RFC 7634) of one direction |
//! | `key-id` | 4 bytes, as 8 hex digits | the key's name in listings and events (never the key) |
//!
//! An end's *epoch* is the instant its key was set (virtual nanoseconds, strictly increasing per
//! tunnel). Each direction has keys of its own: the receiver's SPI and the sender's epoch are in
//! the label, so a packet reflected back to its sender fails, and so does one from an earlier
//! incarnation of the sender (a restart starts a new epoch).

use std::fmt;
use std::net::IpAddr;

use hkdf::Hkdf;
use sha2::Sha256;

/// The key length.
pub const LEN: usize = 32;
/// HKDF's salt for every derivation.
pub const SALT: &[u8] = b"wasmnet-tunnel-1";

/// A tunnel key. Its `Debug` shows only its id.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; LEN]);

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({})", self.id())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Key {
    pub fn from_bytes(b: [u8; LEN]) -> Key {
        Key(b)
    }

    /// 64 hex digits.
    pub fn parse(text: &str) -> Result<Key, String> {
        // Never echoes the text: it may be a key with a typo.
        let bad = || {
            format!(
                "key: not 64 hex digits ({} characters)",
                text.chars().count()
            )
        };
        if text.len() != 2 * LEN || !text.is_ascii() {
            return Err(bad());
        }
        let mut k = [0u8; LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
        }
        Ok(Key(k))
    }

    /// `L` bytes of HKDF-SHA256 for `label`.
    fn derive<const L: usize>(&self, label: &[&[u8]]) -> [u8; L] {
        let info: Vec<u8> = label.concat();
        let mut out = [0u8; L];
        Hkdf::<Sha256>::new(Some(SALT), &self.0)
            .expand(&info, &mut out)
            .expect("at most 255 * 32 bytes");
        out
    }

    /// The key's name: 8 hex digits, the same at both ends, that reveal nothing of the key.
    pub fn id(&self) -> String {
        hex(&self.derive::<4>(&[b"key-id"]))
    }

    /// The STUN short-term password (64 hex digits): its bytes are the HMAC key of
    /// `MESSAGE-INTEGRITY-SHA256` (RFC 8489 §9.1: the OpaqueString of an ASCII password is
    /// itself).
    pub fn stun_password(&self) -> Vec<u8> {
        hex(&self.derive::<32>(&[b"stun-password"])).into_bytes()
    }

    /// The SPI an end with transit address `local` receives on in `epoch`: top bit set, so an
    /// ESP packet never starts like STUN or Geneve.
    pub fn spi(&self, epoch: u64, local: IpAddr) -> u32 {
        let addr = match local {
            IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
            IpAddr::V6(a) => a.octets(),
        };
        let b = self.derive::<4>(&[b"spi", &epoch.to_be_bytes(), &addr]);
        u32::from_be_bytes(b) | 0x8000_0000
    }

    /// The SA of the direction toward SPI `spi` from a sender in `epoch`: 32 bytes of key and
    /// 4 of salt (RFC 7634's 36-byte KEYMAT).
    pub fn esp(&self, spi: u32, epoch: u64) -> [u8; 36] {
        self.derive::<36>(&[b"esp", &spi.to_be_bytes(), &epoch.to_be_bytes()])
    }
}

/// HKDF-SHA256 itself, for its RFC 5869 vectors.
#[cfg(test)]
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("short");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hkdf_matches_rfc_5869_test_case_1() {
        let ikm = [0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let mut okm = [0u8; 42];
        hkdf_sha256(&ikm, &salt, &info, &mut okm);
        assert_eq!(
            okm.to_vec(),
            unhex(
                "3cb25f25faacd57a90434f64d0362f2a 2d2d0a90cf1a5a4c5db02d56ecc4c5bf \
                 34007208d5b887185865"
            )
        );
    }

    #[test]
    fn derivations_are_fixed_distinct_and_per_direction() {
        let k = Key::parse(&"ab".repeat(32)).unwrap();
        let other = Key::parse(&"cd".repeat(32)).unwrap();
        assert_ne!(k.id(), other.id());
        assert_eq!(k.id().len(), 8);
        assert_eq!(k.stun_password().len(), 64);
        let a: IpAddr = "fd00:ff::a".parse().unwrap();
        let b: IpAddr = "fd00:ff::b".parse().unwrap();
        let (sa, sb) = (k.spi(5, a), k.spi(5, b));
        assert_ne!(sa, sb, "each end has its own SPI");
        assert!(sa & 0x8000_0000 != 0 && sb & 0x8000_0000 != 0);
        assert_ne!(k.spi(6, a), sa, "a new epoch, a new SPI");
        assert_eq!(k.spi(5, a), sa, "deterministic");
        // Two directions, two keys; a new sender epoch, a new key.
        assert_ne!(k.esp(sa, 7), k.esp(sb, 7));
        assert_ne!(k.esp(sa, 7), k.esp(sa, 8));
        assert_ne!(k.esp(sa, 7), other.esp(sa, 7));
        assert!(format!("{k:?}").starts_with("Key("));
        assert!(!format!("{k:?}").contains("abab"), "never the key itself");
    }

    #[test]
    fn keys_are_64_hex_digits() {
        assert!(Key::parse(&"0f".repeat(32)).is_ok());
        assert!(Key::parse(&"0F".repeat(32)).is_ok());
        for bad in [
            "",
            "0f",
            &"0f".repeat(33),
            &"zz".repeat(32),
            &"é".repeat(32),
        ] {
            assert!(Key::parse(bad).is_err(), "{bad:?}");
        }
    }
}
