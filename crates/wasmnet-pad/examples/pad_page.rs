//! The page's simulator module with the test fixture `wasmnet-pad` in it: an embedder's own
//! build of the module ([`wasmnet_web::install`]). It carries every export of `wasmnet-web`,
//! plus:
//!
//! - `wn_install`: installs the fixture's extension into every network the module creates
//!   (the device `lonely` gets no server: its first call faults it);
//! - `wn_pad_notes`: the names of a device's notes, read from the extension between steps
//!   (`wasmnet_web::install::with_network`), for `Network.callExport`;
//! - `wn_pad_stamp`: a number the page's own import `pad_page.stamp` answers, for an embedder's
//!   imports on the module (`NetworkOptions.imports`).
//! - `wn_pad_run`: an embedder's own run loop, one instant at a time to a deadline.

#[cfg(target_arch = "wasm32")]
fn install(network: &mut wasmnet_web::install::PageNetwork) {
    network.add_extension(wasmnet_pad::Pad::default().without("lonely"));
}

#[cfg(target_arch = "wasm32")]
wasmnet_web::install!(install);

// The device's name in, its notes' names out (comma-separated).
wasmnet_web::export!(wn_pad_notes, |input: &[u8]| {
    let device = std::str::from_utf8(input).map_err(|e| e.to_string())?;
    wasmnet_web::install::with_network(|net| {
        let pad = net
            .extension::<wasmnet_pad::Pad>()
            .ok_or("this network has no pad")?;
        let names: Vec<String> = pad.notes(device).into_keys().collect();
        Ok(names.join(",").into_bytes())
    })
    .ok_or_else(|| "the network is busy".to_owned())?
});

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "pad_page")]
#[allow(unsafe_code)]
unsafe extern "C" {
    /// The page's own import: answers a number.
    fn stamp(n: u32) -> u32;
}

// Four bytes (a little-endian u32) in, the page's `stamp` of it out.
wasmnet_web::export!(wn_pad_stamp, |input: &[u8]| {
    let n = u32::from_le_bytes(input.try_into().map_err(|_| "four bytes".to_owned())?);
    // SAFETY: an import the page provides, taking and answering a number.
    #[allow(unsafe_code)]
    let stamped = unsafe { stamp(n) };
    Ok(stamped.to_le_bytes().to_vec())
});

// An embedder's own run loop: a deadline (a little-endian u64, ns) in; the network runs one
// instant at a time up to it, then to the deadline itself; the instants it stopped at out (a
// little-endian u32). JavaScript does not settle between instants here, so this suits stepped
// devices; the page calls it `promising` (a device's export it reaches may suspend).
wasmnet_web::export!(wn_pad_run, |input: &[u8]| {
    let until = u64::from_le_bytes(input.try_into().map_err(|_| "eight bytes".to_owned())?);
    wasmnet_web::install::with_network(|net| {
        let mut instants = 0u32;
        while let Some(t) = net.next_event_time().filter(|t| *t <= until) {
            net.run_until(t).map_err(|e| e.to_string())?;
            instants += 1;
        }
        net.run_until(until).map_err(|e| e.to_string())?;
        Ok(instants.to_le_bytes().to_vec())
    })
    .ok_or_else(|| "the network is busy".to_owned())?
});
