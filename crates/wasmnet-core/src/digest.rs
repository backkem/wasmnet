//! Causal digests of events and records.
//!
//! A digest names one occurrence (an event, a frame transmission, a journal record) by its
//! causal history alone: it is computed from the partition-invariant [`EventKey`] or [`Tag`],
//! so it is the same in every rerun, on every site of a split network, and in every run whose
//! causal history of that occurrence is unchanged. 128 bits; shown as the first 48.
//!
//! By convention a digest is written with a prefix naming what it identifies: `ev:` an event
//! ([`event`]), `fr:` a frame transmission, `rec:` a journal record and `op:` an operator event
//! (the last three through [`record`], from the occurrence's [`Tag`]). The prefix is not part of
//! the digest.

use sha2::{Digest as _, Sha256};

use crate::clock::{Ctx, EventKey, KEY_DEPTH, KeyLevel, Tag};

/// A 128-bit causal digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(pub [u8; 16]);

impl Digest {
    /// The display form: the first 48 bits as 12 lowercase hex digits.
    pub fn short(&self) -> String {
        hex(&self.0[..6])
    }

    /// All 128 bits as 32 lowercase hex digits.
    pub fn full(&self) -> String {
        hex(&self.0)
    }

    /// Whether `prefix` (hex, any length up to 32) is a prefix of this digest.
    pub fn matches(&self, prefix: &str) -> bool {
        !prefix.is_empty() && self.full().starts_with(&prefix.to_ascii_lowercase())
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.short())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn level(h: &mut Sha256, l: &KeyLevel) {
    h.update(l.at.to_be_bytes());
    h.update([l.origin.code()]);
    h.update(l.slot.to_be_bytes());
    h.update(l.round.to_be_bytes());
    h.update(l.device.to_be_bytes());
    h.update(l.idx.to_be_bytes());
    h.update(l.pre.to_be_bytes());
}

fn key_body(h: &mut Sha256, key: &EventKey) {
    for l in &key.levels {
        level(h, l);
    }
    // The creator's counter only where it is part of the order: the last level of a key cut
    // at the truncation depth.
    if key.levels.len() == KEY_DEPTH
        && let Some(last) = key.levels.last()
    {
        h.update(last.counter.to_be_bytes());
    }
}

fn finish(h: Sha256) -> Digest {
    let out = h.finalize();
    let mut d = [0u8; 16];
    d.copy_from_slice(&out[..16]);
    Digest(d)
}

/// The digest of an event (`ev:`).
pub fn event(key: &EventKey) -> Digest {
    let mut h = Sha256::new();
    h.update(b"wasmnet-ev/1");
    key_body(&mut h, key);
    finish(h)
}

fn ctx_body(h: &mut Sha256, ctx: &Ctx) {
    h.update([ctx.origin.code()]);
    h.update(ctx.slot.to_be_bytes());
    h.update(ctx.round.to_be_bytes());
    h.update(ctx.device.to_be_bytes());
    match &ctx.cause {
        Some(k) => {
            h.update([1]);
            key_body(h, k);
        }
        None => h.update([0]),
    }
}

/// The digest of a record (`fr:`, `rec:`, `op:`): its tag.
pub fn record(tag: &Tag) -> Digest {
    let mut h = Sha256::new();
    h.update(b"wasmnet-tag/1");
    ctx_body(&mut h, &tag.ctx);
    h.update(tag.n.to_be_bytes());
    finish(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{HOST_DEVICE, Origin};

    fn key(at: u64, idx: u32, counter: u64) -> EventKey {
        EventKey {
            levels: vec![KeyLevel {
                at,
                origin: Origin::Popped,
                slot: 0,
                round: 1,
                device: 2,
                idx,
                counter,
                pre: 0,
            }],
        }
    }

    #[test]
    fn digests_ignore_the_creator_counter_and_see_the_pre_bit() {
        assert_eq!(event(&key(5, 0, 1)), event(&key(5, 0, 99)));
        assert_ne!(event(&key(5, 0, 1)), event(&key(5, 1, 1)));
        assert_ne!(event(&key(5, 0, 1)), event(&key(5, 0, 1).pre(1)));
        let d = event(&key(5, 0, 1));
        assert_eq!(d.short().len(), 12);
        assert!(d.matches(&d.short()) && d.matches(&d.full()));
        // Same bytes in another domain differ.
        let tag = Tag {
            ctx: Ctx {
                origin: Origin::Setup,
                cause: None,
                slot: 0,
                round: 0,
                device: HOST_DEVICE,
            },
            n: 0,
        };
        assert_ne!(record(&tag).0, event(&key(0, 0, 0)).0);
    }
}
