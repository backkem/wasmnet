//! Measurements of the engine, natively (ignored; `cargo test --release -p wasmnet-disk --test
//! measure -- --ignored --nocapture --test-threads 1`): digest and export throughput, and the
//! memory a disk holds per stored byte for large and small records (bytes requested from the
//! allocator, counted by this test binary's own allocator). They need RAM, not disk: nothing is
//! written to a file.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use std::path::{Path, PathBuf};
use std::process::Command;

use wasmnet_disk::{DiskOptions, DiskSpec, Disks, image};
use wasmnet_host::{DeviceOptions, Host, Network};

wasmnet_host::portable_adapter!({
    name: DiskAdapter,
    path: ["../../wit/deps/keyvalue", "../../wit/keyvalue-ext"],
    world: "wasmnet:keyvalue-ext/disk-user",
});

struct Counting;
static HELD: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator, counting what is held.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        HELD.fetch_add(l.size(), Ordering::Relaxed);
        // SAFETY: the caller's layout, passed on.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        HELD.fetch_sub(l.size(), Ordering::Relaxed);
        // SAFETY: the caller's pointer and layout, passed on.
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// A network whose device `dev` declares the disk `disk` with room for `quota` bytes (the device
/// is set up, never run).
fn network(host: &Host, quota: u64) -> Network<'_> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let target: PathBuf =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let ok = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["build", "--release", "--target", "wasm32-wasip2"])
        .args(["-p", "wasmnet-clock-probe", "--example", "disk-probe"])
        .status()
        .expect("spawn cargo")
        .success();
    assert!(ok);
    let probe = host
        .load(target.join("wasm32-wasip2/release/examples/disk_probe.wasm"))
        .unwrap();
    let mut net = Network::new(host, 1);
    net.add_extension(Disks::new().total(quota));
    let mut options = DeviceOptions::default();
    options
        .ext
        .set(DiskOptions::new(vec![DiskSpec::new("disk").quota(quota)]));
    net.device_with_options("dev", &probe, Default::default(), options)
        .unwrap();
    net
}

fn host() -> Host {
    Host::builder().extension(DiskAdapter).build().unwrap()
}

/// An image of `n` records of `size` bytes, written in one pass.
fn image_of(n: usize, size: usize) -> Vec<u8> {
    let keys: Vec<String> = (0..n).map(|i| format!("k/{i:012}")).collect();
    let value = vec![0x5a; size];
    let mut out = Vec::with_capacity(n * (size + 30) + 64);
    image::write(
        keys.iter().map(|k| (k.as_str(), value.as_slice())),
        &mut |b| out.extend_from_slice(b),
    );
    out
}

#[test]
#[ignore = "a measurement"]
fn digest_export_and_memory() {
    for (what, n, size) in [
        ("64 KiB values", 4096usize, 64 << 10),
        ("4 KiB values", 65_536, 4096),
        ("64 B values", 1_000_000, 64),
    ] {
        let img = image_of(n, size);
        let data = (n * (14 + size)) as f64;
        let host = host();
        let net = network(&host, 4 << 30);
        let d = net.extension::<Disks>().unwrap();
        let before = HELD.load(Ordering::Relaxed);
        d.load("dev", "disk", &img).unwrap();
        let held = HELD.load(Ordering::Relaxed) - before;
        drop(img);
        let t = Instant::now();
        let digest = d.digest("dev", "disk").unwrap();
        let td = t.elapsed().as_secs_f64();
        let t = Instant::now();
        // Exported into memory (a copy of every byte): what writing it anywhere costs at least.
        let mut out = Vec::with_capacity(data as usize + 30 * n);
        d.export("dev", "disk", &mut |b| out.extend_from_slice(b));
        let te = t.elapsed().as_secs_f64();
        let mib = data / f64::from(1 << 20);
        println!(
            "{what}: {mib:.0} MiB of keys and values; digest {:.2} s ({:.0} MiB/s), export {:.2} s ({:.0} MiB/s); memory {:.2} bytes per stored byte ({})",
            td,
            mib / td,
            te,
            mib / te,
            held as f64 / data,
            wasmnet_disk::digest_hex(&digest)[..8].to_owned(),
        );
    }
}

#[test]
#[ignore = "a measurement: about 1 GiB of RAM"]
fn digest_of_a_full_network() {
    let img = image_of(16_384, 64 << 10);
    let host = host();
    let net = network(&host, 2 << 30);
    let d = net.extension::<Disks>().unwrap();
    d.load("dev", "disk", &img).unwrap();
    drop(img);
    let t = Instant::now();
    d.digest("dev", "disk").unwrap();
    println!(
        "1 GiB in 64 KiB values: digest {:.2} s",
        t.elapsed().as_secs_f64()
    );
}
