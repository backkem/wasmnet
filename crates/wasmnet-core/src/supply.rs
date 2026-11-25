//! Components a controller supplies as bytes, named by their digest
//! (`docs/design/topology-and-infra.md`, "Components a controller supplies").
//!
//! A controller granted [`crate::DeviceOptions::infra_supply`] hands the host a component's
//! bytes (`wasmnet:infra/components.supply`) and gets back their SHA-256 as a reference,
//! `sha256:<64 lowercase hex digits>`, which a spec's `component` may then be. Before the bytes
//! are kept, the embedder's [`Admission`] callback judges them; they live in the controller's
//! own store (in the device table, [`crate::Infra`]) while it holds them or a device or a queued
//! request names them, within its [`SupplyLimits`]. The network compiles them through the
//! runtime ([`crate::Runtime::compile_supplied`]) once per digest.

use std::sync::Arc;

use sha2::{Digest as _, Sha256};

/// The prefix of a digest reference. A component name that starts with it is always a digest
/// reference, never a catalog name.
pub const DIGEST_PREFIX: &str = "sha256:";

/// What a controller's store of supplied components may hold
/// ([`crate::DeviceOptions::infra_supply`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SupplyLimits {
    /// The largest component, in bytes.
    pub max_bytes: u64,
    /// How many components the store may keep at once.
    pub max_components: u32,
    /// How many bytes the store may keep at once, all its components together.
    pub max_total: u64,
}

impl Default for SupplyLimits {
    /// 16 MiB per component, 8 components, 64 MiB in all.
    fn default() -> Self {
        Self {
            max_bytes: 16 << 20,
            max_components: 8,
            max_total: 64 << 20,
        }
    }
}

impl SupplyLimits {
    /// Sets [`max_bytes`](Self::max_bytes).
    pub const fn max_bytes(mut self, bytes: u64) -> Self {
        self.max_bytes = bytes;
        self
    }

    /// Sets [`max_components`](Self::max_components).
    pub const fn max_components(mut self, components: u32) -> Self {
        self.max_components = components;
        self
    }

    /// Sets [`max_total`](Self::max_total).
    pub const fn max_total(mut self, bytes: u64) -> Self {
        self.max_total = bytes;
        self
    }
}

/// A component a controller supplies, as the embedder's [`Admission`] callback sees it.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Supplied<'a> {
    /// The controller that supplies it.
    pub controller: &'a str,
    /// Its digest reference, `sha256:<hex>`, computed by the network from `bytes`.
    pub digest: &'a str,
    /// The component's bytes.
    pub bytes: &'a [u8],
}

/// The embedder's verdict on a supplied component ([`crate::Network::set_supply_admission`]):
/// `Ok` keeps it, `Err(reason)` refuses it (the controller's `denied(reason)`). Called in the
/// controller's own processing context, at its `supply` call; its verdict must depend only on
/// what it is given for the network to stay a function of its inputs.
pub type Admission = Arc<dyn Fn(&Supplied<'_>) -> Result<(), String> + Send + Sync>;

/// One component a controller's store keeps (`wasmnet:infra/components.list`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct StoredComponent {
    /// `sha256:<hex>`.
    pub digest: String,
    pub size: u64,
    /// The controller holds it (from `supply` until `release`).
    pub held: bool,
    /// Devices in the table and requests still queued that name it.
    pub users: u32,
}

/// The digest reference of `bytes`: `sha256:` and the SHA-256 in 64 lowercase hex digits.
pub fn reference_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(DIGEST_PREFIX.len() + 64);
    out.push_str(DIGEST_PREFIX);
    for b in Sha256::digest(bytes) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Whether `component` is a digest reference (it starts with [`DIGEST_PREFIX`]).
pub fn is_reference(component: &str) -> bool {
    component.starts_with(DIGEST_PREFIX)
}

/// Checks a digest reference's syntax: `sha256:` and exactly 64 lowercase hex digits.
pub fn check_reference(reference: &str) -> Result<(), String> {
    let hex = reference.strip_prefix(DIGEST_PREFIX).unwrap_or("");
    if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(format!(
            "`{reference}` is not a digest reference: `sha256:` and 64 lowercase hex digits"
        ))
    }
}

/// One component in a controller's store.
#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub bytes: Arc<[u8]>,
    /// The controller holds it (`supply` until `release`).
    pub held: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_name_the_bytes() {
        let r = reference_of(b"abc");
        assert_eq!(
            r,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(is_reference(&r));
        assert!(check_reference(&r).is_ok());
        assert!(!is_reference("node:http-server"));
        for bad in [
            "sha256:",
            "sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            "sha256:ba7816bf",
            "sha512:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ] {
            assert!(check_reference(bad).is_err(), "{bad}");
        }
    }
}
