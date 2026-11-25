//! What a portable call costs on wasmtime, against hand-written bindings of the same interface
//! (`wasmnet-test:pad/notes`): the generated adapter (`portable_adapter!`, the extension serving
//! `Value`s) and a `HostExtension` written by hand with `bindgen!` that keeps the bytes itself.
//! Both run the same probe: `reps` appends of `size` bytes, against one.
//!
//! Ignored by default; run it optimised:
//! `cargo test --config 'profile.dev.opt-level=3' -p wasmnet-host --test portable_cost -- --ignored --nocapture`.

mod support;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use support::{built, config, events};
use wasmnet_host::wasmtime::component::{HasData, Linker, Resource};
use wasmnet_host::{DeviceOptions, Host, HostExtension, HostState, Nanos, Network};

const MS: Nanos = 1_000_000;

wasmnet_host::portable_adapter!({
    name: PadAdapter,
    path: "../../wit/test-pad",
    world: "wasmnet-test:pad/user",
});

mod hand {
    wasmnet_host::wasmtime::component::bindgen!({
        path: "../../wit/test-pad",
        world: "wasmnet-test:pad/user",
        imports: { default: trappable },
        with: { "wasmnet-test:pad/notes.note": super::NoteRep },
        wasmtime_crate: wasmnet_host::wasmtime,
    });
}
use hand::wasmnet_test::pad::notes;

/// A note handle: its index in the store's notes.
pub struct NoteRep;

/// The notes of one store, kept by the hand-written extension.
#[derive(Default)]
struct Notes {
    names: Vec<String>,
    bytes: BTreeMap<String, Vec<u8>>,
}

struct View<'a>(&'a mut HostState);
struct Data;
impl HasData for Data {
    type Data<'a> = View<'a>;
}
type R<T> = wasmnet_host::wasmtime::Result<T>;

impl View<'_> {
    fn notes(&mut self) -> &mut Notes {
        self.0.extension_mut::<Notes>().expect("init_store")
    }
    fn name(&mut self, r: &Resource<NoteRep>) -> String {
        self.notes().names[r.rep() as usize].clone()
    }
}

impl notes::Host for View<'_> {
    fn names(&mut self) -> R<Vec<String>> {
        Ok(self.notes().bytes.keys().cloned().collect())
    }
    fn totals(&mut self) -> R<(u32, u64)> {
        let n = self.notes();
        Ok((
            n.bytes.len() as u32,
            n.bytes.values().map(|b| b.len() as u64).sum(),
        ))
    }
}

impl notes::HostNote for View<'_> {
    fn new(&mut self, name: String) -> R<Resource<NoteRep>> {
        let n = self.notes();
        n.bytes.entry(name.clone()).or_default();
        n.names.push(name);
        Ok(Resource::new_own((n.names.len() - 1) as u32))
    }
    fn append(&mut self, r: Resource<NoteRep>, bytes: Vec<u8>) -> R<Result<u64, notes::Error>> {
        let name = self.name(&r);
        let b = self.notes().bytes.entry(name).or_default();
        b.extend_from_slice(&bytes);
        Ok(Ok(b.len() as u64))
    }
    fn read(&mut self, r: Resource<NoteRep>, offset: u64, len: u32) -> R<Vec<u8>> {
        let name = self.name(&r);
        let Some(b) = self.notes().bytes.get(&name) else {
            return Ok(Vec::new());
        };
        let s = (offset as usize).min(b.len());
        Ok(b[s..(s + len as usize).min(b.len())].to_vec())
    }
    fn info(&mut self, r: Resource<NoteRep>) -> R<notes::Info> {
        let name = self.name(&r);
        let size = self.notes().bytes.get(&name).map_or(0, |b| b.len() as u64);
        Ok(notes::Info {
            name,
            size,
            appends: 0,
            state: if size == 0 {
                notes::State::Empty
            } else {
                notes::State::Written
            },
        })
    }
    fn find(&mut self, name: String) -> R<Option<Resource<NoteRep>>> {
        let n = self.notes();
        if !n.bytes.contains_key(&name) {
            return Ok(None);
        }
        n.names.push(name);
        Ok(Some(Resource::new_own((n.names.len() - 1) as u32)))
    }
    fn drop(&mut self, _r: Resource<NoteRep>) -> R<()> {
        Ok(())
    }
}

/// The interface written by hand: what a wasmtime-only host extension does today.
struct Hand;
impl HostExtension for Hand {
    fn name(&self) -> &str {
        "hand-written notes"
    }
    fn add_to_linker(&self, l: &mut Linker<HostState>) -> R<()> {
        notes::add_to_linker::<HostState, Data>(l, |s| View(s))
    }
    fn init_store(&self, state: &mut HostState) -> R<()> {
        state.insert_extension(Notes::default());
        Ok(())
    }
}

fn probe_path() -> std::path::PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let ok = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["build", "--release", "--target", "wasm32-wasip2"])
        .args(["-p", "wasmnet-clock-probe", "--example", "pad-probe"])
        .status()
        .expect("spawn cargo")
        .success();
    assert!(ok, "building pad-probe failed");
    built()
        .target
        .join("wasm32-wasip2/release/examples/pad_probe.wasm")
}

fn host(portable: bool) -> &'static Host {
    static P: OnceLock<Host> = OnceLock::new();
    static H: OnceLock<Host> = OnceLock::new();
    if portable {
        P.get_or_init(|| Host::builder().extension(PadAdapter).build().unwrap())
    } else {
        H.get_or_init(|| Host::builder().extension(Hand).build().unwrap())
    }
}

fn run(portable: bool, size: u64, reps: u64) -> Duration {
    let h = host(portable);
    let probe = h.load(probe_path()).unwrap();
    let mut best = Duration::MAX;
    for _ in 0..5 {
        let mut net = Network::new(h, 1);
        if portable {
            net.add_extension(wasmnet_pad::Pad::default());
        }
        let cfg = config(&[
            ("period", "1000ms"),
            ("big", &size.to_string()),
            ("reps", &reps.to_string()),
        ]);
        net.device_with_options(
            "c",
            &probe,
            cfg,
            DeviceOptions::default().fuel_per_instant(1 << 40),
        )
        .unwrap();
        let t = Instant::now();
        net.run_until(MS).unwrap();
        best = best.min(t.elapsed());
        assert_eq!(events(&net.journal(), "c", "pad-big").len(), 1);
    }
    best
}

#[test]
#[ignore]
fn a_portable_call_costs_what_a_hand_written_one_does() {
    for size in [4u64 << 20, 16 << 20] {
        for portable in [false, true] {
            let (one, many) = (run(portable, size, 1), run(portable, size, 9));
            println!(
                "{} MiB, {}: 1 append {one:?}, 9 appends {many:?}: {:?} per append",
                size >> 20,
                if portable {
                    "generated adapter + portable server"
                } else {
                    "hand-written bindings"
                },
                (many - one) / 8
            );
        }
    }
}
