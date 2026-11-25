//! wasmnet-app-kit: what an app needs besides its own logic, for the apps under
//! `components/apps` and for an app crate in another repository alike.
//!
//! * [`app_bindings!`]: an app's bindings (world `wasmnet:app/app`: the standard WASI 0.3
//!   socket and clock bindings from the `wasip3` crate, `wasi:config`, `wasmnet:link/log`,
//!   `wasmnet:sockets-ext` and the `wasi:cli/run` export), plus an `event` helper for
//!   structured log events. They are generated once, in [`bindings`], so the app's crate needs
//!   no WIT files and no `wit_bindgen::generate!` of its own.
//! * [`wasip3`] and [`wit_bindgen`]: the two crates the bindings are made with, re-exported at
//!   the versions they need.
//! * [`WIT_DIR`]: where this repository's WIT packages are, for build scripts and composition
//!   tools.
//! * [`app_pairs`]: an app's own config keys (`app.<name>.<key>`, prefix stripped).
//! * [`to_std`] and [`to_wit`]: socket addresses between `std::net` and `wasi:sockets`.
//! * [`error_name`]: a `wasi:sockets` error code in kebab case, as the apps log it.
//! * [`Fnv`]: the FNV-1a body hash the HTTP apps log.
//!
//! Everything but [`bindings`] and [`event`] is pure (no imports are called). The crate
//! compiles natively too, where a call to an import panics.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use wasip3::sockets::types::{IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress};

// The generated bindings and their export macro name this crate by its path, here as in an
// app's crate.
extern crate self as wasmnet_app_kit;

/// The `wasip3` crate the bindings are generated against: the standard WASI 0.3 interfaces
/// (`wasip3::sockets`, `wasip3::clocks`, `wasip3::random`, `wasip3::cli`).
pub use wasip3;
/// The `wit-bindgen` runtime the bindings use (streams, futures, `spawn_local`).
pub use wit_bindgen;

/// The directory of this repository's WIT packages (`wit/`), as an absolute path fixed when
/// this crate is compiled: `wasmnet:app`, `wasmnet:link`, `wasmnet:sockets-ext`,
/// `wasmnet:netstack` and the others, with the vendored WASI packages under `deps/`. For the
/// build scripts and composition tools of a crate that depends on this one by path or by git
/// (cargo checks the whole repository out, so the directory is there either way).
pub const WIT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../wit");

/// The bindings of world `wasmnet:app/app`, generated once here so that an app crate anywhere
/// gets them without the WIT files; [`app_bindings!`] brings them into an app's glue module.
///
/// The standard WASI 0.3 socket and clock interfaces are the `wasip3` crate's;
/// `wasi:config/store`, `wasmnet:link/log` and `wasmnet:sockets-ext` are generated here, and so
/// is the export of `wasi:cli/run` (`export_app!`).
#[allow(unsafe_code)] // raw ABI glue
#[allow(rustdoc::all)] // the WIT packages' own doc comments
pub mod bindings {
    wit_bindgen::generate!({
        world: "wasmnet:app/app",
        path: [
            "../../wit/deps/clocks",
            "../../wit/deps/random",
            "../../wit/deps/filesystem",
            "../../wit/deps/sockets",
            "../../wit/deps/cli",
            "../../wit/deps/config",
            "../../wit/link",
            "../../wit/sockets-ext",
            "../../wit/app",
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
        // The export macro is invoked from the app's crate.
        pub_export_macro: true,
        export_macro_name: "export_app",
        default_bindings_module: "wasmnet_app_kit::bindings",
        runtime_path: "wasmnet_app_kit::wit_bindgen::rt",
    });
}

/// Journals a structured event (`kind` and its fields) through `wasmnet:link/log`.
pub fn event(kind: &str, fields: &[(&str, String)]) {
    let fields: Vec<(String, String)> = fields
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    bindings::wasmnet::link::log::event(kind, &fields);
}

/// The bindings of an app (world `wasmnet:app/app`) in the invoking module. It works in an app
/// crate anywhere: the crate needs no WIT files, only this one as its dependency
/// `wasmnet-app-kit`.
///
/// Brings in the modules `wasi` (`wasi::config::store`), `wasmnet` (`wasmnet::link::log`,
/// `wasmnet::sockets_ext`) and `exports` (`exports::wasi::cli::run::Guest`, the trait an app
/// implements), the `export!` macro that exports the implementing type, and
/// [`event(kind, fields)`](event), which journals a structured event. The standard WASI 0.3
/// socket and clock interfaces come from the `wasip3` crate ([`wasip3`](crate::wasip3) here,
/// the version the bindings use).
///
/// ```ignore
/// wasmnet_app_kit::app_bindings!();
///
/// use wasmnet::link::log::{self, Level};
///
/// struct App;
///
/// impl exports::wasi::cli::run::Guest for App {
///     async fn run() -> Result<(), ()> {
///         log::log(Level::Info, "hello");
///         Ok(())
///     }
/// }
///
/// export!(App);
/// ```
#[macro_export]
macro_rules! app_bindings {
    () => {
        #[allow(unused_imports)]
        use $crate::bindings::{export_app as export, exports, wasi, wasmnet};
        #[allow(unused_imports)]
        use $crate::event;
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
