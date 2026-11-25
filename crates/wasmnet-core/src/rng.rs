//! Seeded, platform-independent PRNG behind every `wasi:random` import.
//!
//! xoshiro256** seeded through SplitMix64. It is *not* cryptographically secure, which
//! is the point: a simulation needs replayable entropy, not secrecy.

use std::convert::Infallible;

use rand_core::TryRng;

/// Derives the seed for one entropy `stream` of one `component` from the sim seed.
///
/// Stable across platforms and Rust versions (FNV-1a over the names, then SplitMix64),
/// so a seed printed by a failing run replays anywhere.
pub fn derive_seed(sim_seed: u64, component: &str, stream: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    // The 0xff separator keeps ("ab", "c") and ("a", "bc") apart; 0xff never occurs in UTF-8.
    for b in component.bytes().chain([0xff]).chain(stream.bytes()) {
        h = (h ^ u64::from(b)).wrapping_mul(FNV_PRIME);
    }
    let mut state = sim_seed ^ h;
    splitmix64(&mut state)
}

/// A device's entropy, as every backend serves it: `wasi:random/random` from the seed stream
/// `random`, `wasi:random/insecure` from `insecure`, and `wasi:random/insecure-seed` from the
/// first two values of `insecure-seed`. One derivation for every backend, so a device draws the
/// same numbers from the same seed wherever it runs.
#[derive(Clone, Debug)]
pub struct DeviceEntropy {
    /// `wasi:random/random`.
    pub secure: SimRng,
    /// `wasi:random/insecure`.
    pub insecure: SimRng,
    /// `wasi:random/insecure-seed` as the guest receives it: the `(low, high)` halves of
    /// [`insecure_seed_u128`](Self::insecure_seed_u128).
    pub insecure_seed: (u64, u64),
}

impl DeviceEntropy {
    /// The entropy of device `device` in a network seeded with `sim_seed`.
    pub fn new(sim_seed: u64, device: &str) -> Self {
        let rng = |stream| SimRng::from_seed(derive_seed(sim_seed, device, stream));
        let mut seed = rng("insecure-seed");
        let (high, low) = (seed.next_u64(), seed.next_u64());
        Self {
            secure: rng("random"),
            insecure: rng("insecure"),
            insecure_seed: (low, high),
        }
    }

    /// The insecure seed as one 128-bit value (`high << 64 | low`), for a WASI host that keeps
    /// it whole and hands the guest its low half first.
    pub fn insecure_seed_u128(&self) -> u128 {
        let (low, high) = self.insecure_seed;
        (u128::from(high) << 64) | u128::from(low)
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// xoshiro256** generator.
#[derive(Clone, Debug)]
pub struct SimRng {
    s: [u64; 4],
}

impl SimRng {
    /// Expands a 64-bit seed into the full state with SplitMix64 (never all-zero).
    pub fn from_seed(seed: u64) -> Self {
        let mut sm = seed;
        Self {
            s: std::array::from_fn(|_| splitmix64(&mut sm)),
        }
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        let s = &mut self.s;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }
}

impl TryRng for SimRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok((self.next_u64() >> 32) as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_seed_separates_inputs() {
        let base = derive_seed(42, "probe", "secure");
        assert_eq!(base, derive_seed(42, "probe", "secure"));
        assert_ne!(base, derive_seed(43, "probe", "secure"));
        assert_ne!(base, derive_seed(42, "probe", "insecure"));
        assert_ne!(base, derive_seed(42, "probe2", "secure"));
        assert_ne!(derive_seed(42, "ab", "c"), derive_seed(42, "a", "bc"));
    }

    #[test]
    fn a_devices_entropy_is_its_named_streams() {
        let e = DeviceEntropy::new(42, "web");
        let stream = |s| SimRng::from_seed(derive_seed(42, "web", s));
        assert_eq!(e.secure.clone().next_u64(), stream("random").next_u64());
        assert_eq!(e.insecure.clone().next_u64(), stream("insecure").next_u64());
        let mut seed = stream("insecure-seed");
        let (high, low) = (seed.next_u64(), seed.next_u64());
        // The guest gets the low half first, as a WASI host holding the u128 hands it out.
        assert_eq!(e.insecure_seed, (low, high));
        assert_eq!(
            e.insecure_seed_u128(),
            (u128::from(high) << 64) | u128::from(low)
        );
    }

    #[test]
    fn xoshiro_matches_reference_vector() {
        // xoshiro256** for state [1, 2, 3, 4], worked by hand from the reference algorithm.
        let mut rng = SimRng { s: [1, 2, 3, 4] };
        assert_eq!(rng.next_u64(), 11520);
        assert_eq!(rng.next_u64(), 0);
        assert_eq!(rng.next_u64(), 1509978240);
    }

    #[test]
    fn fill_bytes_matches_u64_stream() {
        let mut a = SimRng::from_seed(7);
        let mut b = SimRng::from_seed(7);
        let mut buf = [0u8; 12];
        a.try_fill_bytes(&mut buf).unwrap();
        assert_eq!(buf[..8], b.next_u64().to_le_bytes());
        assert_eq!(buf[8..], b.next_u64().to_le_bytes()[..4]);
    }
}
