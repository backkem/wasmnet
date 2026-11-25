//! Per-device configuration, served read-only to the device (through `wasi:config/store` in
//! the wasmtime backend).
//!
//! The network gives every device a flat `key -> value` string map before it is instantiated. It
//! never changes during a run. Its iteration order is sorted by key, so even a device that
//! iterates its whole config behaves deterministically.

use std::collections::BTreeMap;

/// A device's configuration: flat string keys (`aging`, `port0.ip`) to string values.
pub type DeviceConfig = BTreeMap<String, String>;

/// A device's `argv`, as `wasi:cli/environment` serves it on every backend: its name in the
/// network first (`argv[0]`), then its arguments ([`crate::DeviceOptions::args`]).
pub fn argv<S: AsRef<str>>(name: &str, args: &[S]) -> Vec<String> {
    std::iter::once(name.to_owned())
        .chain(args.iter().map(|a| a.as_ref().to_owned()))
        .collect()
}
