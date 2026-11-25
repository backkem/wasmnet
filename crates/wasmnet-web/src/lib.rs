//! wasmnet-web: the browser backend of [`wasmnet_core`].
//!
//! # The split
//!
//! The simulation stays Rust: [`wasmnet_core`] (virtual clock, event queue, executor, patch
//! panel, pcap taps, journal) compiles to `wasm32-unknown-unknown` inside this crate's `cdylib`.
//! Only the devices live in JavaScript: the page instantiates components transpiled by jco and
//! serves their imports, partly from this module's device-side exports (`wn_transmit`, `wn_log`,
//! clocks, entropy, config, timers). This crate drives the devices through a small host
//! interface, [`JsHost`], which the wasm32 module implements with imports from JavaScript.
//!
//! This crate decides nothing the wasmtime backend also decides: a device's entropy, `argv`,
//! `wasmnet:infra` answers, command and reconfiguration answers and `app-exit` records come from
//! the core, as there (`docs/design/browser.md`, "What each backend does itself"). It only
//! routes calls between JavaScript and the core.
//!
//! On top sits a network API shaped like the native host's ([`Network`]): a network with a seed,
//! devices with flat `key = value` config, links with a latency, a run, the journal, each link's
//! pcap-ng capture and the outcome. The same API crosses the wasm32 boundary as plain functions
//! over bytes (the `wn_*` exports; the encoding is [`codec`]).
//!
//! # The stepping protocol
//!
//! jco runs a component's async work (`start()`, an app's `run`, a timer's wake-up) on JavaScript
//! promises, outside the network's actor polls. So JavaScript drives a run in steps and lets its
//! own event loop settle between them; virtual time moves only when JavaScript is idle:
//!
//! ```text
//! step(now)                                   // the first round: start(), apps, link-state
//! loop {
//!     settle the JavaScript event loop        // the guests' async work runs
//!     if take_dirty() { step(now); continue }  // JavaScript woke a device: same instant
//!     match next_event_time() {
//!         None => break,                      // quiescent
//!         Some(t) if t > deadline => break,   // only when running to a deadline
//!         Some(t) => step(t),
//!     }
//! }
//! finish(deadline)                            // the outcome
//! ```
//!
//! [`Network::step`] answers `false` once a device crashed; then stop and call
//! [`Network::finish`], which reports the failure.
//!
//! # Live and best-effort
//!
//! A browser run repeats itself: virtual time, seeded entropy and the event queue are the same
//! as natively, and the timing of everything the network sees is exact. But the order of work
//! inside one instant follows the JavaScript component runtime, not wasmtime, so a browser run's
//! bytes (pcaps, journal) are not the native run's. Byte-identical runs are a property of the
//! native host.
//!
//! # Module map
//!
//! [`host`] (what JavaScript provides), [`infra`] (`wasmnet:infra` calls across the boundary),
//! [`runtime`] (the [`wasmnet_core::Runtime`] backend and
//! the per-device [`Registry`]), [`network`] (the network API), [`codec`] (the boundary's byte
//! encoding), and `ffi` (the wasm32 exports and imports, compiled for `wasm32` only; its module
//! docs are the boundary's reference).

#![deny(unsafe_code)]

pub mod codec;
pub mod host;
pub mod infra;
pub mod network;
pub mod runtime;

#[cfg(target_arch = "wasm32")]
mod ffi;

pub use host::{CallEnd, Instance, JsHost};
pub use network::{Network, RunOutcome};
pub use runtime::{Entropy, JsRuntime, Registry};
