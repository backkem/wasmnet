//! wasmnet-disk-page: the page's simulator module with disks in it, an embedder's own build of
//! the module ([`wasmnet_web::install`](mod@wasmnet_web::install)). It carries every export of `wasmnet-web`, plus:
//!
//! - `wn_install`: adds [`wasmnet_disk::Disks`] to every network the module creates;
//! - `wn_disk_digest`: `device` NUL `disk` in, the disk's SHA-256 out (32 bytes), read from the
//!   extension between steps (`wasmnet_web::install::with_network`);
//! - `wn_disk_export`: the same in, the disk's `wasmnet-disk/1` image out;
//! - `wn_disk_load`: `device` NUL `disk` NUL then an image in: loads it into the declared disk.

#[cfg(target_arch = "wasm32")]
fn install(network: &mut wasmnet_web::install::PageNetwork) {
    network.add_extension(wasmnet_disk::Disks::default());
}

#[cfg(target_arch = "wasm32")]
wasmnet_web::install!(install);

/// `device` NUL `disk` (NUL rest): the names and the rest.
#[allow(dead_code)]
fn names(input: &[u8]) -> Result<(&str, &str, &[u8]), String> {
    let mut parts = input.splitn(3, |b| *b == 0);
    fn text(b: Option<&[u8]>) -> Result<&str, String> {
        std::str::from_utf8(b.ok_or("want `device` NUL `disk`")?).map_err(|e| e.to_string())
    }
    let device = text(parts.next())?;
    let disk = text(parts.next())?;
    Ok((device, disk, parts.next().unwrap_or_default()))
}

#[allow(dead_code)]
fn with_disks<R>(f: impl FnOnce(&wasmnet_disk::Disks) -> Result<R, String>) -> Result<R, String> {
    #[cfg(target_arch = "wasm32")]
    {
        wasmnet_web::install::with_network(|net| {
            f(net
                .extension::<wasmnet_disk::Disks>()
                .ok_or("this network has no disks")?)
        })
        .ok_or_else(|| "the network is busy".to_owned())?
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = f;
        Err("a page module only".to_owned())
    }
}

wasmnet_web::export!(wn_disk_digest, |input: &[u8]| {
    let (device, disk, _) = names(input)?;
    with_disks(|d| {
        d.digest(device, disk)
            .map(|h| h.to_vec())
            .ok_or_else(|| format!("no disk `{disk}` on `{device}`"))
    })
});

wasmnet_web::export!(wn_disk_export, |input: &[u8]| {
    let (device, disk, _) = names(input)?;
    with_disks(|d| {
        d.export_vec(device, disk)
            .ok_or_else(|| format!("no disk `{disk}` on `{device}`"))
    })
});

wasmnet_web::export!(wn_disk_load, |input: &[u8]| {
    let (device, disk, image) = names(input)?;
    with_disks(|d| d.load(device, disk, image).map(|()| Vec::new()))
});
