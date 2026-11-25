//! Fetches a pinned set of components, as an embedder's build script or xtask would.
//!
//! ```text
//! cargo run -p wasmnet-artifacts --example fetch -- SOURCE PINS OUT
//! ```
//!
//! SOURCE is a directory written by `cargo xtask artifacts` (or a copy of one), or
//! `oci://<registry>/<repository>` (`oci://ghcr.io/backkem/wasmnet/components`). PINS is a file
//! of `<sha256>  <name>` lines, such as lines copied from a set's `SHA256SUMS`. The files land
//! in OUT, each checked against its pin. When SOURCE is a directory with a `manifest.toml`,
//! the example also checks that the netstack (if pinned) serves the WASI 0.3 socket
//! interfaces, the way an embedder checks the versions its apps were built against.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use wasmnet_artifacts::{Manifest, Source, fetch, parse_sums};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [source, pins, out] = args.as_slice() else {
        eprintln!("usage: fetch SOURCE PINS OUT");
        return ExitCode::FAILURE;
    };
    match run(source, Path::new(pins), Path::new(out)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fetch: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(source: &str, pins: &Path, out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let pins = parse_sums(&std::fs::read_to_string(pins)?)?;
    let source = match source.strip_prefix("oci://") {
        Some(rest) => {
            let (registry, repository) = rest
                .split_once('/')
                .ok_or("oci://<registry>/<repository>")?;
            Source::oci(registry, repository)
        }
        None => Source::Dir(PathBuf::from(source)),
    };
    for path in fetch(&source, &pins, out)? {
        println!("{}", path.display());
    }
    if let Source::Dir(dir) = &source
        && let Ok(text) = std::fs::read_to_string(dir.join("manifest.toml"))
    {
        let manifest = Manifest::parse(&text)?;
        if pins.iter().any(|p| p.name == "netstack.wasm")
            && let Some(netstack) = manifest.file("netstack.wasm")
        {
            netstack.check_exports(&[
                "wasi:sockets/types@0.3.0",
                "wasi:sockets/ip-name-lookup@0.3.0",
            ])?;
            println!("netstack.wasm serves wasi:sockets@0.3.0");
        }
    }
    Ok(())
}
