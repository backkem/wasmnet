//! Every crate's `-C metadata` from what the crate is, not from the machine that builds it.
//!
//! rustc derives a crate's identity, its `StableCrateId`, from the `-C metadata` values it is
//! given. The identity is in every mangled symbol name, and rustc's split of a crate's
//! functions into codegen units depends on it, so it reaches the code too: which functions
//! LLVM inlines, their signatures after optimisation, their order and the data layout.
//!
//! Cargo's value for a crate is a hash that depends on the host that builds:
//!
//! - a workspace crate's value includes its path relative to the workspace root, written with
//!   the platform's separator (`components\switch` on Windows, `components/switch` elsewhere);
//!   a crate directly in the root (no separator) gets the same value on both;
//! - a crate compiled for the host (a build script, a proc macro) gets a value that differs
//!   per host even when it is a crates.io crate with no dependencies;
//! - and every crate's value mixes in its dependencies' values, so a component, which depends
//!   on `wit-bindgen` (a proc macro and a build script), differs as a whole.
//!
//! So the same revision, toolchain and tools gave different components on Linux and on
//! Windows. `build` therefore runs rustc through this program (`RUSTC_WRAPPER`, which cargo
//! supports on stable), which replaces cargo's value with a hash of what identifies the crate
//! in one build: its package's name and version, its crate name and types, the target, its
//! `--cfg`s (the features) and its edition. Nothing else of the command line changes.
//!
//! Two crates that agree on all of those in one build would get the same identity, and rustc
//! refuses to link two crates with the same `StableCrateId`: that fails the build, it does not
//! miscompile. It needs the same package name and version from two sources.

use std::ffi::OsString;
use std::process::{Command, ExitCode};

use crate::Result;

/// Set on the cargo command that builds the components: when `xtask` runs with it, it is
/// that build's rustc wrapper, not the command line tool.
pub const WRAPPER_ENV: &str = "WASMNET_XTASK_RUSTC_WRAPPER";

/// A `RUSTC_WRAPPER` that was already set (a compiler cache, say): the wrapper runs it in
/// turn, with the rewritten command line.
pub const INNER_ENV: &str = "WASMNET_XTASK_INNER_RUSTC_WRAPPER";

/// The scheme's name, hashed into every value and into the name of the flags file
/// (`remap.rs`), so that a target directory never mixes crates built by cargo's values and by
/// these: cargo does not notice a new `RUSTC_WRAPPER`, but it does notice new flags.
pub const SCHEME: &str = "wasmnet-xtask-metadata/1";

/// The value for one rustc command line (`args` without the program), or `None` when cargo
/// passed no `-C metadata` (a `-vV` or `--print` query).
pub fn neutral(args: &[String], package: &str, version: &str) -> Option<String> {
    let has_metadata = args
        .iter()
        .enumerate()
        .any(|(i, a)| metadata_at(args, i).is_some() || a.starts_with("-Cmetadata="));
    if !has_metadata {
        return None;
    }
    let mut key = format!("{SCHEME}\npackage {package} {version}\n");
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--crate-name" | "--crate-type" | "--target" | "--cfg" | "--edition" => {
                if let Some(value) = args.get(i + 1) {
                    key.push_str(&format!("{arg} {value}\n"));
                }
                i += 1;
            }
            "--test" => key.push_str("--test\n"),
            _ => {
                for flag in ["--crate-type=", "--target=", "--cfg=", "--edition="] {
                    if arg.starts_with(flag) {
                        key.push_str(arg);
                        key.push('\n');
                    }
                }
            }
        }
        i += 1;
    }
    let hash = wasmnet_artifacts::sha256_hex(key.as_bytes());
    Some(hash[..16].to_owned())
}

/// `Some(position of the value)` when `args[i]` is `-C` followed by `metadata=...`.
fn metadata_at(args: &[String], i: usize) -> Option<usize> {
    (args[i] == "-C" && args.get(i + 1).is_some_and(|v| v.starts_with("metadata=")))
        .then_some(i + 1)
}

/// `args` with every `-C metadata=...` (or `-Cmetadata=...`) set to `value`.
pub fn rewrite(args: &mut [String], value: &str) {
    for i in 0..args.len() {
        if let Some(at) = metadata_at(args, i) {
            args[at] = format!("metadata={value}");
        } else if args[i].starts_with("-Cmetadata=") {
            args[i] = format!("-Cmetadata={value}");
        }
    }
}

/// Runs as cargo's rustc wrapper: `args` is the program cargo would have run (rustc, or a
/// workspace wrapper) and its arguments.
pub fn wrap(mut args: Vec<String>) -> Result<ExitCode> {
    if args.is_empty() {
        return Err(format!("{WRAPPER_ENV} is set, but no rustc to run").into());
    }
    let program = args.remove(0);
    let package = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    if let Some(value) = neutral(&args, &package, &version) {
        rewrite(&mut args, &value);
    }
    let inner: Option<OsString> = std::env::var_os(INNER_ENV).filter(|w| !w.is_empty());
    let mut cmd = match inner {
        Some(wrapper) => {
            let mut cmd = Command::new(wrapper);
            cmd.arg(&program);
            cmd
        }
        None => Command::new(&program),
    };
    let status = cmd.args(&args).status()?;
    Ok(match status.code() {
        Some(0) => ExitCode::SUCCESS,
        Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        None => ExitCode::FAILURE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &str) -> Vec<String> {
        args.split(' ').map(str::to_owned).collect()
    }

    const SWITCH: &str = "--crate-name switch --edition=2024 components/switch/src/lib.rs \
        --crate-type cdylib -C opt-level=3 -C metadata=6b58fd129ee18f38 --out-dir /a/target \
        --target wasm32-wasip2 --extern wit_bindgen=/a/target/libwit_bindgen-f1.rlib";

    #[test]
    fn paths_and_cargos_value_do_not_reach_it() {
        let here = strings(SWITCH);
        let there = strings(
            &SWITCH
                .replace("components/switch", "components\\switch")
                .replace("/a/target", "C:\\b\\target")
                .replace("6b58fd129ee18f38", "0123456789abcdef")
                .replace("-f1.rlib", "-f2.rlib"),
        );
        let a = neutral(&here, "wasmnet-switch", "0.1.0").unwrap();
        assert_eq!(Some(a.clone()), neutral(&there, "wasmnet-switch", "0.1.0"));
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn what_identifies_a_crate_does() {
        let base = neutral(&strings(SWITCH), "wasmnet-switch", "0.1.0");
        let other_version = neutral(&strings(SWITCH), "wasmnet-switch", "0.1.1");
        let other_package = neutral(&strings(SWITCH), "wasmnet-router", "0.1.0");
        let rlib = neutral(
            &strings(&SWITCH.replace("cdylib", "rlib")),
            "wasmnet-switch",
            "0.1.0",
        );
        let host = neutral(
            &strings(&SWITCH.replace(" --target wasm32-wasip2", "")),
            "wasmnet-switch",
            "0.1.0",
        );
        let feature = neutral(
            &strings(&format!("{SWITCH} --cfg feature=\"std\"")),
            "wasmnet-switch",
            "0.1.0",
        );
        let all = [base, other_version, other_package, rlib, host, feature];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn both_spellings_are_rewritten() {
        let mut args = strings("--crate-name x -C metadata=aa -Cmetadata=bb -C opt-level=3");
        rewrite(&mut args, "cc");
        assert_eq!(
            args,
            strings("--crate-name x -C metadata=cc -Cmetadata=cc -C opt-level=3")
        );
    }

    #[test]
    fn a_query_is_left_alone() {
        assert_eq!(neutral(&strings("-vV"), "", ""), None);
        let print = strings("- --crate-name ___ --print=file-names --crate-type bin");
        assert_eq!(neutral(&print, "", ""), None);
    }
}
