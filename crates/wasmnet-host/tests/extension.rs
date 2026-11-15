//! The host extension point with a dummy extension.
//!
//! `ext-probe` (`components/clock-probe/examples/ext_probe.rs`) imports `wasmnet-test:ext/probe`,
//! which wasmnet-host does not serve. The `Probe` extension below serves it: a per-store call
//! counter (state inserted by `init_store`) and a `counter` resource in the store's table. This
//! is the shape a real extension (such as a JIT import) takes, without any of its knowledge
//! here.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use wasmnet_host::{Error, Host, HostExtension, HostState, SimConfig};
use wasmtime::component::{HasData, Linker, Resource, ResourceTable};

mod bindings {
    wasmtime::component::bindgen!({
        inline: r#"
            package wasmnet-test:ext@0.1.0;
            interface probe {
                resource counter {
                    constructor(start: u32);
                    bump: func() -> u32;
                }
                calls: func() -> u64;
                device: func() -> string;
            }
            world ext-probe {
                import probe;
            }
        "#,
        world: "wasmnet-test:ext/ext-probe",
        with: { "wasmnet-test:ext/probe.counter": super::Counter },
    });
}

use bindings::wasmnet_test::ext::probe;

/// The `counter` resource's host representation.
pub struct Counter(u32);

/// Per-store state of the extension.
struct ProbeState {
    calls: u64,
    device: String,
}

/// What the generated host traits are implemented on: the extension's state and the store's
/// resource table, borrowed together from `HostState`.
struct ProbeView<'a> {
    state: &'a mut ProbeState,
    table: &'a mut ResourceTable,
}

impl ProbeView<'_> {
    fn call(&mut self) -> u64 {
        self.state.calls += 1;
        self.state.calls
    }
}

struct ProbeData;

impl HasData for ProbeData {
    type Data<'a> = ProbeView<'a>;
}

impl probe::HostCounter for ProbeView<'_> {
    fn new(&mut self, start: u32) -> Resource<Counter> {
        self.call();
        self.table.push(Counter(start)).expect("table")
    }

    fn bump(&mut self, counter: Resource<Counter>) -> u32 {
        self.call();
        let c = self.table.get_mut(&counter).expect("live counter");
        c.0 += 1;
        c.0
    }

    fn drop(&mut self, counter: Resource<Counter>) -> wasmtime::Result<()> {
        self.table.delete(counter)?;
        Ok(())
    }
}

impl probe::Host for ProbeView<'_> {
    fn calls(&mut self) -> u64 {
        self.call()
    }

    fn device(&mut self) -> String {
        self.call();
        self.state.device.clone()
    }
}

/// The dummy extension.
struct Probe;

impl HostExtension for Probe {
    fn name(&self) -> &str {
        "wasmnet-test:ext/probe"
    }

    fn add_to_linker(&self, linker: &mut Linker<HostState>) -> wasmtime::Result<()> {
        probe::add_to_linker::<HostState, ProbeData>(linker, |s| {
            let (state, table) = s
                .extension_and_table::<ProbeState>()
                .expect("Probe::init_store ran for this store");
            ProbeView { state, table }
        })
    }

    fn init_store(&self, state: &mut HostState) -> wasmtime::Result<()> {
        let device = state.device_name().to_owned();
        state.insert_extension(ProbeState { calls: 0, device });
        Ok(())
    }
}

fn ext_probe() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let status = Command::new(env!("CARGO"))
            .current_dir(&root)
            .args(["build", "--release", "--target", "wasm32-wasip2"])
            .args(["-p", "wasmnet-clock-probe", "--example", "ext-probe"])
            .status()
            .expect("spawn cargo to build ext-probe");
        assert!(status.success(), "building ext-probe failed");
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target"));
        target.join("wasm32-wasip2/release/examples/ext-probe.wasm")
    })
}

#[test]
fn an_extension_serves_its_imports_with_per_store_state() {
    let host = Host::new()
        .expect("host")
        .with_extension(Probe)
        .expect("link the probe");
    assert_eq!(host.extensions(), ["wasmnet-test:ext/probe"]);
    let component = host.load(ext_probe()).expect("ext-probe");
    for name in ["first", "second"] {
        let sim = host.sim(SimConfig::seeded(7));
        let out = sim.run_command(name, &component, &[]).expect("run");
        assert!(out.success);
        // Constructor, two bumps and `calls` itself: the count starts over in every store.
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("bump 11 12\ncalls 4\ndevice {name}\n")
        );
    }
}

#[test]
fn without_the_extension_the_import_is_missing() {
    let host = Host::new().expect("host");
    assert!(host.extensions().is_empty());
    let component = host.load(ext_probe()).expect("ext-probe");
    let err = host
        .sim(SimConfig::seeded(7))
        .run_command("probe", &component, &[])
        .expect_err("nothing serves wasmnet-test:ext/probe");
    assert!(
        format!("{err:?}").contains("wasmnet-test:ext/probe"),
        "the error names the import: {err:?}"
    );
}

#[test]
fn an_extension_cannot_shadow_an_existing_import() {
    let host = Host::new()
        .expect("host")
        .with_extension(Probe)
        .expect("once");
    match host.with_extension(Probe) {
        Err(e @ Error::Runtime { .. }) => {
            let e = wasmnet_host::wasmtime_error(&e).expect("a wasmtime error");
            assert!(format!("{e:?}").contains("wasmnet-test:ext/probe"), "{e:?}")
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("linking the same interface twice must fail"),
    }
}
