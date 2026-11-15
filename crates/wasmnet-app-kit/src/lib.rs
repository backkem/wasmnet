//! wasmnet-app-kit: what the apps under `components/apps` share, so each app keeps only its own
//! logic.
//!
//! * [`app_bindings!`]: the apps' `wit_bindgen::generate!` call (world `wasmnet:app/app`, the
//!   standard WASI 0.3 socket and clock bindings from the `wasip3` crate, `wasi:config`,
//!   `wasmnet:link/log` and `wasmnet:sockets-ext`), plus an `event` helper for structured log
//!   events.
//! * [`app_pairs`]: an app's own config keys (`app.<name>.<key>`, prefix stripped).
//! * [`to_std`] and [`to_wit`]: socket addresses between `std::net` and `wasi:sockets`.
//! * [`error_name`]: a `wasi:sockets` error code in kebab case, as the apps log it.
//! * [`Fnv`]: the FNV-1a body hash the HTTP apps log.
//!
//! Everything here is pure (no imports are called), so it compiles natively and in guests.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use wasip3::sockets::types::{IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress};

/// The bindings of an app (world `wasmnet:app/app`) in the invoking module: the standard WASI
/// 0.3 socket and clock interfaces come from the `wasip3` crate; `wasi:config/store`,
/// `wasmnet:link/log` and `wasmnet:sockets-ext` are generated here. Also defines
/// `event(kind, fields)`, which journals a structured event through `wasmnet:link/log`.
///
/// For a crate in `components/apps/<name>` (the WIT paths are relative to it) that depends on
/// `wit-bindgen` and `wasip3`.
#[macro_export]
macro_rules! app_bindings {
    () => {
        wit_bindgen::generate!({
            world: "wasmnet:app/app",
            path: [
                "../../../wit/deps/clocks",
                "../../../wit/deps/random",
                "../../../wit/deps/filesystem",
                "../../../wit/deps/sockets",
                "../../../wit/deps/cli",
                "../../../wit/deps/config",
                "../../../wit/link",
                "../../../wit/sockets-ext",
                "../../../wit/app",
            ],
            generate_all,
            with: {
                // The standard WASI 0.3 bindings; `wasi:config`, `wasmnet:link/log` and
                // `wasmnet:sockets-ext` are ours.
                "wasi:sockets/types@0.3.0": wasip3::sockets::types,
                "wasi:sockets/ip-name-lookup@0.3.0": wasip3::sockets::ip_name_lookup,
                "wasi:clocks/types@0.3.0": wasip3::clocks::types,
                "wasi:clocks/monotonic-clock@0.3.0": wasip3::clocks::monotonic_clock,
            },
        });

        /// Journals a structured event (`kind` and its fields) through `wasmnet:link/log`.
        #[allow(dead_code)]
        fn event(kind: &str, fields: &[(&str, ::std::string::String)]) {
            let fields: ::std::vec::Vec<(::std::string::String, ::std::string::String)> = fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect();
            wasmnet::link::log::event(kind, &fields);
        }
    };
}

/// The pairs under `app.<app>.` from a device's whole config, with that prefix stripped: an
/// app reads only its own keys.
pub fn app_pairs(all: Vec<(String, String)>, app: &str) -> Vec<(String, String)> {
    let prefix = format!("app.{app}.");
    all.into_iter()
        .filter_map(|(k, v)| k.strip_prefix(&prefix).map(|k| (k.to_owned(), v)))
        .collect()
}

/// A `wasi:sockets` address as a `std::net` one.
pub fn to_std(a: IpSocketAddress) -> SocketAddr {
    match a {
        IpSocketAddress::Ipv4(v4) => {
            let (a, b, c, d) = v4.address;
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), v4.port))
        }
        IpSocketAddress::Ipv6(v6) => {
            let (a, b, c, d, e, f, g, h) = v6.address;
            let ip = Ipv6Addr::new(a, b, c, d, e, f, g, h);
            SocketAddr::V6(SocketAddrV6::new(ip, v6.port, v6.flow_info, v6.scope_id))
        }
    }
}

/// A `std::net` address as a `wasi:sockets` one.
pub fn to_wit(a: SocketAddr) -> IpSocketAddress {
    match a {
        SocketAddr::V4(v4) => {
            let [a, b, c, d] = v4.ip().octets();
            IpSocketAddress::Ipv4(Ipv4SocketAddress {
                port: v4.port(),
                address: (a, b, c, d),
            })
        }
        SocketAddr::V6(v6) => {
            let [a, b, c, d, e, f, g, h] = v6.ip().segments();
            IpSocketAddress::Ipv6(Ipv6SocketAddress {
                port: v6.port(),
                flow_info: v6.flowinfo(),
                address: (a, b, c, d, e, f, g, h),
                scope_id: v6.scope_id(),
            })
        }
    }
}

/// A `wasi:sockets` error code in kebab case, from its `Debug` text: `ErrorCode::ConnectionReset`
/// becomes `connection-reset`.
pub fn error_name(debug: &str) -> String {
    let name = debug.strip_prefix("ErrorCode::").unwrap_or(debug);
    let mut out = String::with_capacity(name.len() + 4);
    let mut prev_lower = false;
    for ch in name.chars() {
        if ch.is_ascii_uppercase() && prev_lower {
            out.push('-');
        }
        prev_lower = ch.is_ascii_lowercase();
        out.push(ch.to_ascii_lowercase());
    }
    out
}

/// FNV-1a, 64 bit: the body hash the HTTP apps log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fnv(pub u64);

impl Default for Fnv {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Fnv {
    pub fn update(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 ^= u64::from(*b);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    /// The hash as 16 lowercase hex digits.
    pub fn hex(&self) -> String {
        format!("{:016x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_app_reads_its_own_keys() {
        let all = vec![
            ("ipv4".to_owned(), "10.0.0.1/24".to_owned()),
            ("app.web.listen".to_owned(), "0.0.0.0:80".to_owned()),
            ("app.webx.listen".to_owned(), "x".to_owned()),
        ];
        assert_eq!(
            app_pairs(all, "web"),
            [("listen".to_owned(), "0.0.0.0:80".to_owned())]
        );
    }

    #[test]
    fn addresses_round_trip() {
        for a in ["10.0.0.1:80", "[fe80::1%3]:5353"] {
            let a: SocketAddr = a.parse().unwrap();
            assert_eq!(to_std(to_wit(a)), a);
        }
    }

    #[test]
    fn error_names_and_the_body_hash() {
        assert_eq!(error_name("ErrorCode::ConnectionReset"), "connection-reset");
        assert_eq!(error_name("Timeout"), "timeout");
        let mut h = Fnv::default();
        assert_eq!(h.hex(), "cbf29ce484222325");
        h.update(b"a");
        assert_eq!(h.hex(), "af63dc4c8601ec8c");
    }
}
