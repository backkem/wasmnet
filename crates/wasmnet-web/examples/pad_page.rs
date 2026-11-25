//! The page's simulator module with the test fixture `wasmnet-pad` in it: an embedder's own
//! build of the module ([`wasmnet_web::install`]). It carries every export of `wasmnet-web`,
//! plus `wn_install`, which installs the fixture's extension into every network it creates.

#[cfg(target_arch = "wasm32")]
fn install(network: &mut wasmnet_web::install::PageNetwork) {
    network.add_extension(wasmnet_pad::Pad::default());
}

#[cfg(target_arch = "wasm32")]
wasmnet_web::install!(install);
