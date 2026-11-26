//! store-adapter: a test fixture and the worked example of "keep your own WIT, put an adapter
//! in front".
//!
//! A device keeps its data through a contract of its own, `wasmnet-test:bytes-store`
//! (`wit/test-store/store.wit`): records under **byte** keys, and objects keyed by a 32-byte hash
//! with ranged reads. This component exports that contract and serves it over the device's disks
//! (`wasi:keyvalue` plus `wasmnet:keyvalue-ext`, `crates/wasmnet-disk`): records on the disk
//! `state`, objects on the disk `objects`. Composed in front of the device (`wac plug`), it lets
//! the device keep its own imports and never name the disk.
//!
//! The disks take string keys, so byte keys are encoded, in a way that keeps their order and
//! their prefixes: a scan of a byte prefix is a scan of the encoded prefix, and keys come back in
//! byte order. Two encodings are here, both order- and prefix-preserving:
//!
//! - [`Encoding::Hex`]: two lowercase hex digits per byte (always twice the length);
//! - [`Encoding::Latin1`]: each byte as the code point of the same number (bytes below 0x80 stay
//!   one byte of UTF-8, the others take two: 1 to 2 times the length, and readable for ASCII
//!   keys). UTF-8 orders code points as their numbers, and is a prefix code, so both properties
//!   hold.
//!
//! The adapter uses [`CHOSEN`], measured in `docs/design/disk.md`.

/// How byte keys become the disk's string keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Hex,
    Latin1,
}

/// The encoding the adapter uses.
pub const CHOSEN: Encoding = Encoding::Latin1;

const HEX: &[u8; 16] = b"0123456789abcdef";

impl Encoding {
    /// `bytes` as a key.
    pub fn encode(self, bytes: &[u8]) -> String {
        match self {
            Self::Hex => {
                let mut s = String::with_capacity(2 * bytes.len());
                for b in bytes {
                    s.push(HEX[usize::from(b >> 4)] as char);
                    s.push(HEX[usize::from(b & 15)] as char);
                }
                s
            }
            Self::Latin1 => bytes.iter().map(|b| char::from(*b)).collect(),
        }
    }

    /// A key back as bytes; `None` for a key this encoding did not make.
    pub fn decode(self, key: &str) -> Option<Vec<u8>> {
        match self {
            Self::Hex => {
                let digit = |c: u8| match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    _ => None,
                };
                let k = key.as_bytes();
                if !k.len().is_multiple_of(2) {
                    return None;
                }
                k.chunks(2)
                    .map(|p| Some(digit(p[0])? << 4 | digit(p[1])?))
                    .collect()
            }
            Self::Latin1 => key.chars().map(|c| u8::try_from(c).ok()).collect(),
        }
    }
}

#[cfg(not(test))]
mod component;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Both encodings round-trip, keep the order of keys and keep prefixes.
        #[test]
        fn order_and_prefixes_are_kept(a in prop::collection::vec(any::<u8>(), 0..24), b in prop::collection::vec(any::<u8>(), 0..24)) {
            for e in [Encoding::Hex, Encoding::Latin1] {
                let (ea, eb) = (e.encode(&a), e.encode(&b));
                prop_assert_eq!(e.decode(&ea), Some(a.clone()));
                prop_assert_eq!(a.cmp(&b), ea.as_bytes().cmp(eb.as_bytes()));
                prop_assert_eq!(b.starts_with(&a), eb.starts_with(&ea));
            }
        }
    }

    #[test]
    fn sizes() {
        let hash = [0xabu8; 32];
        assert_eq!(Encoding::Hex.encode(&hash).len(), 64);
        assert_eq!(Encoding::Latin1.encode(&hash).len(), 64);
        assert_eq!(Encoding::Latin1.encode(b"gossip/").len(), 7);
        assert_eq!(Encoding::Hex.decode("abc"), None);
        assert_eq!(Encoding::Latin1.decode("\u{100}"), None);
    }

    /// What each encoding costs: bytes per key and time per encode and decode, for 32-byte
    /// hashes (uniform bytes) and for ASCII-prefixed keys. `--ignored --nocapture`.
    #[test]
    #[ignore = "a measurement"]
    fn encoding_cost() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let hashes: Vec<Vec<u8>> = (0..10_000)
            .map(|_| (0..4).flat_map(|_| next().to_le_bytes()).collect())
            .collect();
        let named: Vec<Vec<u8>> = (0..10_000u64)
            .map(|i| [b"state/peer/".as_slice(), &i.to_be_bytes()].concat())
            .collect();
        for (what, keys) in [("32-byte hashes", &hashes), ("ascii prefix + u64", &named)] {
            for e in [Encoding::Hex, Encoding::Latin1] {
                let t = std::time::Instant::now();
                let enc: Vec<String> = keys.iter().map(|k| e.encode(k)).collect();
                let te = t.elapsed();
                let t = std::time::Instant::now();
                let n: usize = enc.iter().map(|k| e.decode(k).map_or(0, |v| v.len())).sum();
                let td = t.elapsed();
                let bytes: usize = enc.iter().map(String::len).sum();
                let raw: usize = keys.iter().map(Vec::len).sum();
                assert_eq!(n, raw);
                println!(
                    "{what}, {e:?}: {:.2} bytes per byte, encode {:.0} ns, decode {:.0} ns per key",
                    bytes as f64 / raw as f64,
                    te.as_nanos() as f64 / keys.len() as f64,
                    td.as_nanos() as f64 / keys.len() as f64
                );
            }
        }
    }
}
