//! An embedder's own build of the page's simulator module, with its extensions in it.
//!
//! The page runs `wasmnet_web.wasm`, this crate built for `wasm32-unknown-unknown`. An embedder
//! whose devices need its own extensions (portable interfaces, cable kinds, extension options
//! and ops, a component resolver or catalog) builds that module itself instead: a `cdylib`
//! crate of its own that depends on `wasmnet-web` (whose exports it carries over unchanged)
//! and on its extensions, and names an installer with [`install!`](crate::install!):
//!
//! ```ignore
//! // Cargo.toml: [lib] crate-type = ["cdylib"]; wasmnet-web, and the extension's crate.
//! fn install(network: &mut wasmnet_web::install::PageNetwork) {
//!     network.add_extension(my_extension::MyExtension::default());
//! }
//! wasmnet_web::install!(install);
//! ```
//!
//! `cargo build --release --target wasm32-unknown-unknown -p <that crate>` makes the module; the
//! page loads it in place of `wasmnet_web.wasm`, and the binding calls its `wn_install` export
//! before it creates a network. The installer then runs on every network the module creates,
//! right after it is made and before any device (like a wasmtime host extension's `install`).
//! Portable interfaces need nothing more in the page: the binding links them from their names
//! ([`crate::Registry::import`]).

/// The network a page's module creates: what an installer gets.
#[cfg(target_arch = "wasm32")]
pub type PageNetwork = wasmnet_core::Network<'static, crate::JsRuntime<crate::ffi::Js>>;

/// What runs on every network the page's module creates ([`set_installer`]).
#[cfg(target_arch = "wasm32")]
pub type Installer = fn(&mut PageNetwork);

#[cfg(target_arch = "wasm32")]
thread_local! {
    static INSTALLER: std::cell::Cell<Option<Installer>> = const { std::cell::Cell::new(None) };
}

/// Sets the installer every network the page creates from now on runs.
#[cfg(target_arch = "wasm32")]
pub fn set_installer(installer: Installer) {
    INSTALLER.set(Some(installer));
}

/// Runs the installer, if one is set, on a network just created.
#[cfg(target_arch = "wasm32")]
pub(crate) fn run(network: &mut PageNetwork) {
    if let Some(install) = INSTALLER.get() {
        install(network);
    }
}

/// Defines the module's `wn_install` export, which sets `$installer`
/// (`fn(&mut PageNetwork)`) as the installer: the page calls it before it creates a network.
#[macro_export]
macro_rules! install {
    ($installer:path) => {
        /// Sets this module's installer (the page calls it before it creates a network).
        #[cfg(target_arch = "wasm32")]
        #[allow(unsafe_code)]
        #[unsafe(no_mangle)]
        pub extern "C" fn wn_install() {
            $crate::install::set_installer($installer);
        }
    };
}
