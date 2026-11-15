//! Two hosts, one switch, one HTTP GET, every frame captured.
//!
//! ```text
//!   client (http-get) ──100 µs── switch ──150 µs── server (http-server)
//!     10.0.0.2                                        10.0.0.1
//! ```
//!
//! ```sh
//! cargo xtask build                           # the components and the composed nodes
//! cargo run -p wasmnet-host --example http    # [seed]
//! ```
//!
//! Prints the journal (what every device reported, stamped with virtual time) and writes one
//! pcap-ng per link into `target/http/`. Open one in Wireshark: ARP, SYN, SYN-ACK, `GET /`.
//! Run it twice with the same seed and the files are byte-identical.

use std::error::Error;
use std::path::{Path, PathBuf};

use wasmnet_host::{DeviceConfig, Host, Network, Outcome, Record};

/// A device config from `key = value` pairs (nested keys are dotted).
fn config(pairs: &[(&str, &str)]) -> DeviceConfig {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let seed = match std::env::args().nth(1) {
        Some(s) => s.parse()?,
        None => 42,
    };
    // The workspace root: this crate lives in `crates/wasmnet-host`.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or("no workspace root")?;
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let built = target.join("wasm32-wasip2/release");

    let host = Host::new()?;
    let load = |name: &str| {
        let path = built.join(name);
        host.load(&path)
            .map_err(|e| format!("{}: {e}\n(run `cargo xtask build` first)", path.display()))
    };
    let switch = load("switch.wasm")?;
    let http_server = load("node-http-server.wasm")?;
    let http_get = load("node-http-get.wasm")?;

    let mut network = Network::new(&host, seed);
    let sw = network.device_with_config("sw", &switch, config(&[("ports", "4")]))?;
    let server = network.device_with_config(
        "server",
        &http_server,
        config(&[
            ("mac", "02:00:00:00:00:01"),
            ("ipv4", "10.0.0.1/24"),
            ("app.http-server.listen", "0.0.0.0:80"),
        ]),
    )?;
    let client = network.device_with_config(
        "client",
        &http_get,
        config(&[
            ("mac", "02:00:00:00:00:02"),
            ("ipv4", "10.0.0.2/24"),
            ("hosts.web", "10.0.0.1"),
            ("app.http-get.url", "http://web/"),
            ("app.http-get.start", "1ms"),
        ]),
    )?;
    network.link(server.port(0), sw.port(1))?.latency(150_000);
    network.link(client.port(0), sw.port(2))?.latency(100_000);

    let outcome = network.run_until_quiescent()?;

    for entry in network.journal() {
        let (t, device) = (entry.at, &entry.device);
        match entry.record {
            Record::Event { kind, fields } => {
                let fields: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
                println!("{t:>12} ns  {device:<7} {kind} {}", fields.join(" "));
            }
            Record::Log { message, .. } => println!("{t:>12} ns  {device:<7} {message}"),
            _ => {}
        }
    }
    if let Outcome::Quiescent { at, daemons, .. } = &outcome {
        println!("quiescent at t={at} ns; still serving: {daemons:?}");
    }

    let out = target.join("http");
    std::fs::create_dir_all(&out)?;
    for link in network.links() {
        // A link is named after its ends (`client:0-sw:2`); `:` is not a file-name character
        // everywhere.
        let name = network.link_name(link).replace(':', ".");
        let path = out.join(format!("{name}.pcapng"));
        std::fs::write(&path, network.pcap(link))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}
