//! Shared, I/O-free helpers for frames and pcap, plus the DHCP and DNS message codecs.
//!
//! This crate is `no_std` (+ `alloc`) and has no clock, no RNG and no I/O: every timestamp and
//! seed is passed in by the caller, so everything here is deterministic by construction.
//! It is used by the native host (pcap taps) and by components (frame parsing), and its unit
//! tests run inside Wasmtime via `cargo test --target wasm32-wasip2 -p wasmnet-wire`.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod dhcp;
pub mod dns;
pub mod duration;
pub mod ethernet;
pub mod mac;
pub mod pcap;
pub mod pcapng;

#[cfg(test)]
mod proptests;

pub use duration::{format_duration, parse_duration};
pub use ethernet::{EtherType, EthernetFrame, FrameError, VlanTag};
pub use mac::{MacAddr, ParseMacError};
pub use pcapng::{Direction, InterfaceId, PcapNgEncoder, PcapNgError};

#[cfg(test)]
mod tests {
    /// Proof-of-venue: when this crate's tests are built for `wasm32-wasip2`, this test only exists
    /// in the Wasm build and its output line shows that the harness ran inside a Wasm runtime.
    #[test]
    #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
    fn running_inside_wasm32_wasip2() {
        assert_eq!(core::mem::size_of::<usize>(), 4);
    }
}
