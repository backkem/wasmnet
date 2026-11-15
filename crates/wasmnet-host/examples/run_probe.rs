//! Runs a command component under a deterministic sim and prints its imports and output.
//!
//! ```sh
//! cargo build --target wasm32-wasip2 -p wasmnet-clock-probe --release
//! cargo run -p wasmnet-host --example run_probe -- target/wasm32-wasip2/release/clock-probe.wasm 42
//! ```

use std::error::Error;
use std::io::Write as _;

use wasmnet_host::{Host, SimConfig};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: run_probe <component.wasm> [seed]")?;
    let seed = args.next().map(|s| s.parse()).transpose()?.unwrap_or(42);

    let host = Host::new()?;
    let component = host.load(&path)?;
    println!("imports of {path}:");
    for name in host.imports(&component) {
        println!("  {name}");
    }

    let sim = host.sim(SimConfig::seeded(seed));
    let out = sim.run_command("probe", &component, &[])?;
    println!(
        "--- seed={seed} success={} virtual t={}..{}ns ---",
        out.success, out.started_at, out.finished_at
    );
    std::io::stdout().write_all(&out.stdout)?;
    std::io::stderr().write_all(&out.stderr)?;
    Ok(())
}
