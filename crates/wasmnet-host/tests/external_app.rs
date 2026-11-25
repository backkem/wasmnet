//! End to end: an app crate outside this repository's tree.
//!
//! `tests/fixtures/external-app` is a small app crate with one dependency, `wasmnet-app-kit`,
//! and no WIT files. The test copies it to a temporary directory, as a crate in another
//! repository would be, and takes the steps such a crate takes:
//!
//! * it builds for `wasm32-wasip2` with the kit's bindings, and the component validates;
//! * `wac` composes it with the netstack into a node, from that directory;
//! * the node runs in a network: its datagram reaches an echo server and comes back.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use support::{built, config, events, field, transcript};
use wasmnet_host::Network;

/// Runs `cmd` to success.
fn run(cmd: &mut Command) {
    let status = cmd.status().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(status.success(), "{cmd:?} failed: {status}");
}

/// A path as TOML and cargo take it on every platform: forward slashes.
fn slashed(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// The fixture as a crate of its own in a fresh temporary directory: its files, with the
/// dependency on `wasmnet-app-kit` pointing at this checkout by absolute path, and this
/// workspace's lockfile, so it resolves the same versions without asking a registry.
fn external_crate(root: &Path) -> PathBuf {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/external-app");
    let dir = std::env::temp_dir().join(format!("wasmnet-external-app-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src")).unwrap();

    let manifest = fs::read_to_string(fixture.join("Cargo.toml")).unwrap();
    let relative = r#"path = "../../../../wasmnet-app-kit""#;
    assert!(manifest.contains(relative), "the fixture's dependency line");
    let kit = root.join("crates/wasmnet-app-kit");
    let absolute = format!(r#"path = "{}""#, slashed(&kit));
    fs::write(
        dir.join("Cargo.toml"),
        manifest.replace(relative, &absolute),
    )
    .unwrap();
    for file in ["src/lib.rs", "node.wac"] {
        fs::copy(fixture.join(file), dir.join(file)).unwrap();
    }
    fs::copy(root.join("Cargo.lock"), dir.join("Cargo.lock")).unwrap();
    dir
}

#[test]
fn an_app_in_another_directory_builds_composes_and_runs() {
    let b = built();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the workspace root, two levels up");
    let dir = external_crate(root);
    assert!(
        !dir.starts_with(root),
        "{} is outside {}",
        dir.display(),
        root.display()
    );

    // Its build output goes under this workspace's target directory, so a second run is quick;
    // the crate itself stays outside.
    let target = b.target.join("external-app");
    run(Command::new(env!("CARGO"))
        .current_dir(&dir)
        .args(["build", "--release", "--target", "wasm32-wasip2"])
        .arg("--target-dir")
        .arg(&target));
    let app = target.join("wasm32-wasip2/release/hello.wasm");
    run(Command::new("wasm-tools").arg("validate").arg(&app));

    let node = dir.join("node-hello.wasm");
    run(Command::new("wac")
        .current_dir(&dir)
        .args(["compose", "node.wac", "--dep"])
        .arg(format!("wasmnet:netstack={}", b.path("netstack").display()))
        .arg("--dep")
        .arg(format!("app:hello={}", app.display()))
        .arg("-o")
        .arg(&node));
    run(Command::new("wasm-tools").arg("validate").arg(&node));

    let mut network = Network::new(&b.host, 42);
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "4")]))
        .unwrap();
    let server = network
        .device_with_config(
            "server",
            &b.load("node-udp-echo-server"),
            config(&[("ipv4", "10.0.0.1/24")]),
        )
        .unwrap();
    let hello = network
        .device_with_config(
            "hello",
            &b.host.load(&node).unwrap(),
            config(&[
                ("ipv4", "10.0.0.2/24"),
                ("app.hello.peer", "10.0.0.1:7"),
                ("app.hello.text", "from outside"),
            ]),
        )
        .unwrap();
    network
        .link(server.port(0), sw.port(1))
        .unwrap()
        .latency(150_000);
    network
        .link(hello.port(0), sw.port(2))
        .unwrap()
        .latency(100_000);
    network.run_until_quiescent().unwrap();
    let journal = network.journal();
    let log = transcript(&journal);

    assert_eq!(network.apps(hello), ["hello"], "{log}");
    let echoed = events(&journal, "hello", "hello-echoed");
    assert_eq!(echoed.len(), 1, "{log}");
    assert_eq!(field(&echoed[0], "from"), "10.0.0.1:7", "{log}");
    assert_eq!(field(&echoed[0], "text"), "from outside", "{log}");
    // ARP both ways, then the datagram and its echo: four crossings of 250 us.
    assert_eq!(field(&echoed[0], "rtt-ns"), "1000000", "{log}");
    let exit = events(&journal, "hello", "app-exit");
    assert_eq!(exit.len(), 1, "{log}");
    assert_eq!(field(&exit[0], "status"), "ok", "{log}");

    fs::remove_dir_all(&dir).unwrap();
}
