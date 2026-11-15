//! `cargo xtask` for this workspace (run from its root).
//!
//! ```text
//! cargo xtask build        build every component under components/ (and components/apps/)
//!                          for wasm32-wasip2 (release), compose every compositions/<node>.wac
//!                          into node-<node>.wasm with wac, and `wasm-tools validate` all of them
//! cargo xtask test-guest   run every component's own tests (and wasmnet-wire's) as
//!                          wasm32-wasip2 binaries inside wasmtime
//! cargo xtask web [--no-build] [--test]
//!                          the browser example in web/dist: `build`, the simulator for
//!                          wasm32-unknown-unknown, then `npm ci` and `npm run build` in web/;
//!                          --no-build skips both Rust builds, --test also runs `npm test`
//!                          (headless Chromium)
//! ```
//!
//! Build outputs land in `target/wasm32-wasip2/release/` (or under `$CARGO_TARGET_DIR`).
//! `build` needs `wac` and `wasm-tools` on `PATH`, `test-guest` needs `wasmtime`, `web` needs
//! Node 24 and npm, and a Chromium for `--test` (the versions are in the workspace README).

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const TARGET: &str = "wasm32-wasip2";

/// The workspace root.
fn root() -> PathBuf {
    let xtask = Path::new(env!("CARGO_MANIFEST_DIR"));
    xtask.parent().unwrap_or(xtask).to_path_buf()
}

fn target_dir(root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from)
}

/// A component crate: its name (the directory's, which its artifact and its place in a
/// composition carry), its package (`wasmnet-<name>`), whether it is an app
/// (`components/apps/<name>`), and whether it has a library target (`src/lib.rs`, where a
/// component keeps its tested logic).
struct Crate {
    name: String,
    package: String,
    app: bool,
    lib: bool,
}

/// The package name in a `Cargo.toml` (`name = "..."` under `[package]`).
fn package_name(manifest: &Path) -> Result<String> {
    let text = fs::read_to_string(manifest)?;
    let mut in_package = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
        } else if in_package
            && let Some(rest) = line.strip_prefix("name")
            && let Some(value) = rest.trim_start().strip_prefix('=')
        {
            return Ok(value.trim().trim_matches('"').to_owned());
        }
    }
    Err(format!("{}: no [package] name", manifest.display()).into())
}

/// Every crate directly under `dir` (one with a `Cargo.toml`), sorted by directory.
fn crates_in(dir: &Path, app: bool) -> Result<Vec<Crate>> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();
    dirs.sort();
    dirs.iter()
        .map(|d| {
            let name = d.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            Ok(Crate {
                name: name.to_owned(),
                package: package_name(&d.join("Cargo.toml"))?,
                app,
                lib: d.join("src").join("lib.rs").is_file(),
            })
        })
        .collect()
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        return Err(format!("{cmd:?} failed: {status}").into());
    }
    Ok(())
}

/// The output of crate `name`: a `[[bin]]` keeps its dashes, a `cdylib` uses underscores.
fn output(dir: &Path, name: &str) -> Option<PathBuf> {
    [name.to_owned(), name.replace('-', "_")]
        .iter()
        .map(|stem| dir.join(format!("{stem}.wasm")))
        .filter_map(|p| Some((fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
}

/// Every component crate: `components/<name>`, then `components/apps/<name>`.
fn components(root: &Path) -> Result<Vec<Crate>> {
    let mut crates = crates_in(&root.join("components"), false)?;
    crates.extend(crates_in(&root.join("components").join("apps"), true)?);
    Ok(crates)
}

/// Tests run as wasm inside wasmtime: the `wasm32-wasip2` runner in `.cargo/config.toml`.
fn test_guest() -> Result<()> {
    let root = root();
    let mut cmd = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    cmd.current_dir(&root)
        .args(["test", "--target", TARGET, "-p", "wasmnet-wire"]);
    for c in components(&root)?.iter().filter(|c| c.lib) {
        cmd.args(["-p", &c.package]);
    }
    run(&mut cmd)
}

fn build() -> Result<()> {
    let root = root();
    let crates = components(&root)?;

    let mut cmd = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    cmd.current_dir(&root)
        .args(["build", "--release", "--target", TARGET]);
    for c in &crates {
        cmd.args(["-p", &c.package]);
    }
    run(&mut cmd)?;

    let out = target_dir(&root).join(TARGET).join("release");
    let deps = target_dir(&root).join("wac-deps");
    if deps.exists() {
        fs::remove_dir_all(&deps)?;
    }
    let mut built = Vec::new();
    for c in &crates {
        let path = output(&out, &c.name)
            .ok_or_else(|| format!("{}: no .wasm in {}", c.name, out.display()))?;
        // wac's `--deps-dir` layout: `wasmnet:<component>` and `app:<app>`.
        let namespace = if c.app { "app" } else { "wasmnet" };
        fs::create_dir_all(deps.join(namespace))?;
        fs::copy(&path, deps.join(namespace).join(format!("{}.wasm", c.name)))?;
        println!("  {:<20} {}", c.name, path.display());
        built.push(path);
    }

    let mut wacs: Vec<PathBuf> = fs::read_dir(root.join("compositions"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "wac"))
        .collect();
    wacs.sort();
    for wac in &wacs {
        let stem = wac.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
        let node = out.join(format!("node-{stem}.wasm"));
        run(Command::new("wac")
            .arg("compose")
            .arg(wac)
            .arg("--deps-dir")
            .arg(&deps)
            .arg("-o")
            .arg(&node))?;
        println!("  {:<20} {}", format!("node-{stem}"), node.display());
        built.push(node);
    }

    let mut invalid = 0;
    for path in &built {
        let out = Command::new("wasm-tools")
            .arg("validate")
            .arg(path)
            .output()?;
        if !out.status.success() {
            println!(
                "  INVALID {}: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
            invalid += 1;
        }
    }
    if invalid > 0 {
        return Err(format!("{invalid} invalid component(s)").into());
    }
    println!(
        "xtask build: {} component(s) and {} node(s), all {} valid",
        crates.len(),
        wacs.len(),
        built.len()
    );
    Ok(())
}

/// `npm` (`npm.cmd` on Windows, where Command does not search for `.cmd` files).
fn npm() -> Command {
    Command::new(if cfg!(windows) { "npm.cmd" } else { "npm" })
}

/// The browser example: the Rust inputs, then the page (web/package.json's scripts).
fn web(args: &[String]) -> Result<()> {
    let mut no_build = false;
    let mut test = false;
    for a in args {
        match a.as_str() {
            "--no-build" => no_build = true,
            "--test" => test = true,
            other => return Err(format!("web: unknown option {other}").into()),
        }
    }
    let root = root();
    let web = root.join("web");
    if npm().arg("--version").output().is_err() {
        return Err("web: needs Node 24 and npm on PATH".into());
    }
    if !no_build {
        build()?;
        run(
            Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
                .current_dir(&root)
                .args([
                    "build",
                    "--release",
                    "-p",
                    "wasmnet-web",
                    "--target",
                    "wasm32-unknown-unknown",
                ]),
        )?;
    }
    // A fresh install when there is none, or when the lockfile changed since the last one.
    let installed = web.join("node_modules").join(".package-lock.json");
    let modified = |p: &Path| fs::metadata(p).and_then(|m| m.modified()).ok();
    let stale = match (
        modified(&installed),
        modified(&web.join("package-lock.json")),
    ) {
        (Some(i), Some(l)) => l > i,
        _ => true,
    };
    if stale {
        run(npm().current_dir(&web).arg("ci"))?;
    }
    run(npm().current_dir(&web).args(["run", "build"]))?;
    if test {
        run(npm().current_dir(&web).arg("test"))?;
    }
    println!("xtask web: the page is in {}", web.join("dist").display());
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("build") if args.len() == 1 => build(),
        Some("test-guest") if args.len() == 1 => test_guest(),
        Some("web") => web(&args[1..]),
        _ => Err(
            "usage: cargo xtask build | cargo xtask test-guest | cargo xtask web [--no-build] [--test]"
                .into(),
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}
