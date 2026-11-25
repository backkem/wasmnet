//! ESP (RFC 4303) in UDP (RFC 3948) with ChaCha20-Poly1305 (RFC 7634): a keyed tunnel's data.
//!
//! ```text
//!  0                   1                   2                   3
//! |               Security Parameters Index (SPI)                 |
//! |                      Sequence Number                          |
//! |                 IV (64 bits: the sequence number)             |
//! |   inner packet ... | padding | pad length | next header       |  encrypted
//! |                 ICV (128 bits, the Poly1305 tag)              |
//! ```
//!
//! Tunnel mode: the inner IP packet is the payload, next header 4 (IPv4) or 41 (IPv6). The
//! padding brings the encrypted part to a multiple of 4 bytes, with the bytes 1, 2, 3 as RFC 4303
//! asks. The nonce is the SA's 4-byte salt and the IV; the IV is the 32-bit sequence number
//! zero-extended, so it never repeats under one key (a sequence number is never reused: an SA
//! that has sent 2^32 - 1 packets sends no more). The additional data is the SPI and the
//! sequence number (no extended sequence numbers). A receiver checks the sequence number against
//! its [`Window`] before it decrypts and records it after the tag checked.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

/// IPsec NAT traversal's UDP port (RFC 3948), a keyed tunnel's default.
pub const PORT: u16 = 4500;
/// SPI, sequence number and IV.
pub const HEADER: usize = 16;
/// The Poly1305 tag.
pub const ICV: usize = 16;
/// What ESP adds to an inner packet whose length plus 2 is a multiple of 4: the header, the pad
/// length and next header bytes, and the tag (other lengths add 1 to 3 bytes of padding).
pub const OVERHEAD: usize = HEADER + 2 + ICV;
/// Next header values of tunnel mode.
pub const NEXT_IPV4: u8 = 4;
pub const NEXT_IPV6: u8 = 41;

/// Why a datagram is not an ESP packet this SA accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("shorter than ESP's header, trailer and tag, or not 4-byte aligned")]
    Short,
    #[error("the sequence number was seen, or is older than the replay window")]
    Replayed,
    #[error("the tag does not check: another key, or altered")]
    Tag,
    #[error("malformed padding or next header")]
    Trailer,
}

/// One direction's security association: the cipher and the salt.
#[derive(Clone)]
pub struct Sa {
    cipher: ChaCha20Poly1305,
    salt: [u8; 4],
}

impl std::fmt::Debug for Sa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sa")
    }
}

impl Sa {
    /// From RFC 7634's 36-byte KEYMAT: the key, then the salt.
    pub fn new(keymat: &[u8; 36]) -> Sa {
        let mut salt = [0u8; 4];
        salt.copy_from_slice(&keymat[32..]);
        Sa {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&keymat[..32])),
            salt,
        }
    }

    fn nonce(&self, iv: &[u8; 8]) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.salt);
        n[4..].copy_from_slice(iv);
        n
    }
}

/// The SPI of an ESP packet (the first four bytes).
pub fn spi_of(d: &[u8]) -> Option<u32> {
    d.get(..4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn seq_of(d: &[u8]) -> Option<u32> {
    d.get(4..8)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// The encrypted part of `inner`: the packet, padding to a multiple of 4, pad length, next
/// header.
pub fn plaintext(inner: &[u8]) -> Vec<u8> {
    let pad = (4 - (inner.len() + 2) % 4) % 4;
    let next = match inner.first().map(|b| b >> 4) {
        Some(6) => NEXT_IPV6,
        _ => NEXT_IPV4,
    };
    let mut p = Vec::with_capacity(inner.len() + pad + 2 + ICV);
    p.extend_from_slice(inner);
    p.extend((1..=pad).map(|b| b as u8));
    p.push(pad as u8);
    p.push(next);
    p
}

/// Seals `plaintext` (already padded, see [`plaintext`]) with an explicit IV.
fn seal_iv(sa: &Sa, spi: u32, seq: u32, iv: [u8; 8], mut plaintext: Vec<u8>) -> Vec<u8> {
    let mut aad = [0u8; 8];
    aad[..4].copy_from_slice(&spi.to_be_bytes());
    aad[4..].copy_from_slice(&seq.to_be_bytes());
    let tag = sa
        .cipher
        .encrypt_in_place_detached(Nonce::from_slice(&sa.nonce(&iv)), &aad, &mut plaintext)
        .expect("ChaCha20-Poly1305 seals any length below 256 GiB");
    let mut d = Vec::with_capacity(HEADER + plaintext.len() + ICV);
    d.extend_from_slice(&aad);
    d.extend_from_slice(&iv);
    d.extend_from_slice(&plaintext);
    d.extend_from_slice(&tag);
    d
}

/// The ESP packet for `inner` under `sa` toward `spi`, sequence number `seq` (1 or more).
pub fn seal(sa: &Sa, spi: u32, seq: u32, inner: &[u8]) -> Vec<u8> {
    seal_iv(sa, spi, seq, u64::from(seq).to_be_bytes(), plaintext(inner))
}

/// Opens an ESP packet under `sa`, checking its sequence number against `window` first and
/// recording it there once the tag checked. Returns the inner packet and its next header.
pub fn open(sa: &Sa, window: &mut Window, d: &[u8]) -> Result<(Vec<u8>, u8), Error> {
    if d.len() < HEADER + 4 + ICV || !(d.len() - HEADER - ICV).is_multiple_of(4) {
        return Err(Error::Short);
    }
    let seq = seq_of(d).ok_or(Error::Short)?;
    if !window.fresh(seq) {
        return Err(Error::Replayed);
    }
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&d[8..16]);
    let mut body = d[HEADER..d.len() - ICV].to_vec();
    let tag = Tag::from_slice(&d[d.len() - ICV..]);
    sa.cipher
        .decrypt_in_place_detached(Nonce::from_slice(&sa.nonce(&iv)), &d[..8], &mut body, tag)
        .map_err(|_| Error::Tag)?;
    window.accept(seq);
    let (next, pad) = (body[body.len() - 1], usize::from(body[body.len() - 2]));
    let inner_len = body.len().checked_sub(2 + pad).ok_or(Error::Trailer)?;
    let padding_ok = body[inner_len..inner_len + pad]
        .iter()
        .enumerate()
        .all(|(i, b)| usize::from(*b) == i + 1);
    let version = body.first().map(|b| b >> 4);
    let next_ok = matches!((next, version), (NEXT_IPV4, Some(4)) | (NEXT_IPV6, Some(6)));
    if !padding_ok || !next_ok || inner_len == 0 {
        return Err(Error::Trailer);
    }
    body.truncate(inner_len);
    Ok((body, next))
}

/// The anti-replay window of one inbound SA (RFC 4303 §3.4.3): the highest sequence number
/// accepted and which of the [`Window::SIZE`] below it were.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    top: u32,
    /// Bit `i`: `top - i` was accepted.
    seen: u128,
}

impl Window {
    /// How far back a late packet is still accepted.
    pub const SIZE: u32 = 128;

    /// Whether `seq` may be accepted: not 0, not seen, not older than the window.
    pub fn fresh(&self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.top {
            return true;
        }
        let back = self.top - seq;
        back < Self::SIZE && self.seen & (1u128 << back) == 0
    }

    /// Records `seq` (which [`fresh`](Self::fresh) allowed).
    pub fn accept(&mut self, seq: u32) {
        if seq > self.top {
            let shift = seq - self.top;
            self.seen = if shift >= Self::SIZE {
                0
            } else {
                self.seen << shift
            };
            self.seen |= 1;
            self.top = seq;
        } else {
            self.seen |= 1u128 << (self.top - seq);
        }
    }

    /// The highest sequence number accepted.
    pub fn top(&self) -> u32 {
        self.top
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn keymat(key: &str, salt: &str) -> [u8; 36] {
        let mut k = [0u8; 36];
        k[..32].copy_from_slice(&unhex(key));
        k[32..].copy_from_slice(&unhex(salt));
        k
    }

    #[test]
    fn the_rfc_7634_esp_example_seals_and_opens() {
        // RFC 7634 Appendix A: an ICMP packet in tunnel mode, SPI 0x01020304, sequence 5, an
        // explicit IV, no ESN.
        let sa = Sa::new(&keymat(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "a0a1a2a3",
        ));
        let icmp = unhex(
            "45 00 00 54 a6 f2 00 00 40 01 e7 78 c6 33 64 05
             c0 00 02 05 08 00 5b 7a 3a 08 00 00 55 3b ec 10
             00 07 36 27 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13
             14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23
             24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33
             34 35 36 37",
        );
        let p = plaintext(&icmp);
        assert_eq!(p[p.len() - 8..], unhex("34 35 36 37 01 02 02 04"));
        let iv = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let d = seal_iv(&sa, 0x0102_0304, 5, iv, p);
        assert_eq!(d[..16], unhex("01020304 00000005 1011121314151617"));
        let ciphertext = unhex(
            "24 03 94 28 b9 7f 41 7e 3c 13 75 3a 4f 05 08 7b
             67 c3 52 e6 a7 fa b1 b9 82 d4 66 ef 40 7a e5 c6
             14 ee 80 99 d5 28 44 eb 61 aa 95 df ab 4c 02 f7
             2a a7 1e 7c 4c 4f 64 c9 be fe 2f ac c6 38 e8 f3
             cb ec 16 3f ac 46 9b 50 27 73 f6 fb 94 e6 64 da
             91 65 b8 28 29 f6 41 e0",
        );
        assert_eq!(d[16..16 + 88], ciphertext[..]);
        assert_eq!(
            d[16 + 88..],
            unhex("76 aa a8 26 6b 7f b0 f7 b1 1b 36 99 07 e1 ad 43")[..]
        );
        let mut w = Window::default();
        assert_eq!(open(&sa, &mut w, &d), Ok((icmp, NEXT_IPV4)));
        assert_eq!(open(&sa, &mut w, &d), Err(Error::Replayed));
    }

    #[test]
    fn chacha20_poly1305_matches_rfc_8439_2_8_2() {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&unhex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        )));
        let mut text = b"Ladies and Gentlemen of the class of '99: If I could offer you only \
                         one tip for the future, sunscreen would be it."
            .to_vec();
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&unhex("070000004041424344454647")),
                &unhex("50515253c0c1c2c3c4c5c6c7"),
                &mut text,
            )
            .unwrap();
        assert_eq!(text[..4], [0xd3, 0x1a, 0x8d, 0x34]);
        assert_eq!(tag.to_vec(), unhex("1ae10b594f09e26a7e902ecbd0600691"));
    }

    #[test]
    fn a_packet_round_trips_and_every_alteration_is_refused() {
        let sa = Sa::new(&[7; 36]);
        let other = Sa::new(&[8; 36]);
        for inner in [vec![0x45; 20], vec![0x60; 41], vec![0x45; 1437]] {
            let d = seal(&sa, 0x8000_0001, 9, &inner);
            assert!((d.len() - HEADER - ICV).is_multiple_of(4));
            assert!(d.len() <= inner.len() + OVERHEAD + 3);
            let mut w = Window::default();
            let (back, next) = open(&sa, &mut w, &d).unwrap();
            assert_eq!(back, inner);
            assert_eq!(
                next,
                if inner[0] == 0x60 {
                    NEXT_IPV6
                } else {
                    NEXT_IPV4
                }
            );
            // Another key, a flipped bit anywhere, the header changed: the tag fails, and the
            // window does not move.
            assert_eq!(open(&other, &mut Window::default(), &d), Err(Error::Tag));
            for at in [0, 5, 9, 20, d.len() - 1] {
                let mut bad = d.clone();
                bad[at] ^= 1;
                let mut w = Window::default();
                assert_eq!(open(&sa, &mut w, &bad), Err(Error::Tag), "byte {at}");
                assert_eq!(w, Window::default());
            }
        }
        assert_eq!(
            open(&sa, &mut Window::default(), &[0x80; 35]),
            Err(Error::Short)
        );
        assert_eq!(
            open(&sa, &mut Window::default(), &[0x80; 39]),
            Err(Error::Short)
        );
        // Sequence number 0 is never valid.
        let d = seal(&sa, 1, 0, &[0x45; 20]);
        assert_eq!(open(&sa, &mut Window::default(), &d), Err(Error::Replayed));
    }

    #[test]
    fn the_window_takes_late_packets_once_and_drops_old_ones() {
        let mut w = Window::default();
        for s in [1, 3, 2, 10] {
            assert!(w.fresh(s), "{s}");
            w.accept(s);
        }
        assert!(!w.fresh(2) && !w.fresh(10), "seen");
        assert!(w.fresh(9) && w.fresh(4), "late, within the window");
        // A jump past the window forgets everything below it.
        w.accept(10 + Window::SIZE);
        assert!(!w.fresh(10), "now older than the window");
        assert!(w.fresh(11), "the oldest still inside it");
        assert!(!w.fresh(10 + Window::SIZE));
        // Exactly the window's width, and one more.
        let mut w = Window::default();
        w.accept(200);
        assert!(w.fresh(200 - Window::SIZE + 1));
        assert!(!w.fresh(200 - Window::SIZE));
        // At the top of the sequence space: nothing wraps around to small numbers.
        let mut w = Window::default();
        w.accept(u32::MAX - 1);
        assert!(w.fresh(u32::MAX));
        w.accept(u32::MAX);
        assert!(!w.fresh(u32::MAX) && !w.fresh(u32::MAX - 1));
        assert!(w.fresh(u32::MAX - 2));
        assert!(!w.fresh(1) && !w.fresh(0), "no wrap to the start");
        assert_eq!(w.top(), u32::MAX);
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 1024,
            rng_seed: proptest::test_runner::RngSeed::Fixed(4303),
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]

        #[test]
        fn arbitrary_bytes_never_panic(d in proptest::collection::vec(any::<u8>(), 0..96)) {
            let sa = Sa::new(&[3; 36]);
            let _ = open(&sa, &mut Window::default(), &d);
        }

        #[test]
        fn the_window_accepts_each_number_once(seqs in proptest::collection::vec(1u32..400, 1..200)) {
            let mut w = Window::default();
            let mut taken = std::collections::BTreeSet::new();
            for s in seqs {
                if w.fresh(s) {
                    prop_assert!(taken.insert(s), "{} twice", s);
                    w.accept(s);
                }
                prop_assert!(!w.fresh(s));
            }
        }
    }
}
