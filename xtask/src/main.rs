//! `cargo xtask` for this workspace (run from its root).
//!
//! ```text
//! cargo xtask build [--only NAME[,NAME...]] [--out-dir DIR]
//!                          build every component under components/ (and components/apps/)
//!                          for wasm32-wasip2 (release), compose every compositions/<node>.wac
//!                          into node-<node>.wasm with wac, and `wasm-tools validate` all of
//!                          them. --only builds the named components and nodes (a node's
//!                          parts with it); --out-dir also copies what was asked for into DIR,
//!                          as <name>.wasm
//! cargo xtask build --list every component and node by name, without building
//! cargo xtask test-guest   run every component's own tests (and wasmnet-wire's) as
//!                          wasm32-wasip2 binaries inside wasmtime
//! cargo xtask tools [--check] [PACKAGE...]
//!                          the pinned command-line tools (tools.toml), one <package>@<version>
//!                          per line, as `cargo install --locked` takes them; --check compares
//!                          them, and the Rust toolchain, with what is on PATH
//! cargo xtask artifacts [--out DIR] [--rebuild MANIFEST]
//!                          the published components, apps and nodes (not the test fixtures)
//!                          in DIR (default target/artifacts), with manifest.toml (revision,
//!                          toolchain, tools, and each file's SHA-256, size and interfaces)
//!                          and SHA256SUMS; --rebuild then compares with a manifest built
//!                          elsewhere from the same revision
//! cargo xtask artifacts --verify DIR | --compare A B
//!                          check a set against its manifest; compare two manifests' hashes
//! cargo xtask check-tree [--commits BASE..HEAD]
//!                          no local path, AI coding tool session link or merge conflict
//!                          marker in the tree, nor in the messages and added lines of the
//!                          commits in the range
//! cargo xtask web [--no-build] [--test]
//!                          the browser example in web/dist: `build`, the simulator for
//!                          wasm32-unknown-unknown, then `npm ci` and `npm run build` in web/;
//!                          --no-build skips both Rust builds, --test also runs `npm test`
//!                          (headless Chromium)
//! ```
//!
//! Build outputs land in `target/wasm32-wasip2/release/` (or under `$CARGO_TARGET_DIR`).
//! `build` maps every source path out of the components' bytes (`remap.rs`), so the same
//! source, toolchain and tools give the same bytes in any checkout on the same platform.
//! `build` needs `wac` and `wasm-tools` on `PATH`, `test-guest` needs `wasmtime`, `web` needs
//! Node 24 and npm, and a Chromium for `--test`. The tools' versions are in `tools.toml`; the
//! components and nodes are listed in `components/README.md`.

mod artifacts;
mod leaks;
mod remap;

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

pub(crate) type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub(crate) const TARGET: &str = "wasm32-wasip2";

/// The workspace root.
pub(crate) fn root() -> PathBuf {
    let xtask = Path::new(env!("CARGO_MANIFEST_DIR"));
    xtask.parent().unwrap_or(xtask).to_path_buf()
}

pub(crate) fn target_dir(root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from)
}

/// A component crate: its name (the directory's, which its artifact and its place in a
/// composition carry), its package (`wasmnet-<name>`), whether it is an app
/// (`components/apps/<name>`), and whether it has a library target (`src/lib.rs`, where a
/// component keeps its tested logic).
pub(crate) struct Crate {
    name: String,
    package: String,
    app: bool,
    lib: bool,
}

impl Crate {
    /// Its namespace in a composition and in wac's `--deps-dir` layout: `app` or `wasmnet`.
    fn namespace(&self) -> &'static str {
        if self.app { "app" } else { "wasmnet" }
    }

    /// How a composition names it: `wasmnet:<component>` or `app:<app>`.
    fn reference(&self) -> String {
        format!("{}:{}", self.namespace(), self.name)
    }
}

/// A composed node: `compositions/<stem>.wac`, built into `node-<stem>.wasm`.
pub(crate) struct Node {
    /// `node-<stem>`.
    name: String,
    wac: PathBuf,
    /// The components it instantiates, as the composition names them ([`Crate::reference`]).
    parts: Vec<String>,
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
pub(crate) fn components(root: &Path) -> Result<Vec<Crate>> {
    let mut crates = crates_in(&root.join("components"), false)?;
    crates.extend(crates_in(&root.join("components").join("apps"), true)?);
    Ok(crates)
}

/// The components a composition instantiates: every `new wasmnet:<name>` and `new app:<name>`
/// outside its `//` comments, in order, each once.
fn wac_parts(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    for line in text.lines() {
        let mut rest = line.split("//").next().unwrap_or_default();
        while let Some(at) = rest.find("new ") {
            rest = rest[at + 4..].trim_start();
            let reference: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | ':'))
                .collect();
            if reference.contains(':') && !parts.contains(&reference) {
                parts.push(reference);
            }
        }
    }
    parts
}

/// Every composed node: `compositions/<stem>.wac`, sorted.
pub(crate) fn nodes(root: &Path) -> Result<Vec<Node>> {
    let mut wacs: Vec<PathBuf> = fs::read_dir(root.join("compositions"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "wac"))
        .collect();
    wacs.sort();
    wacs.into_iter()
        .map(|wac| {
            let stem = wac.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
            Ok(Node {
                name: format!("node-{stem}"),
                parts: wac_parts(&fs::read_to_string(&wac)?),
                wac,
            })
        })
        .collect()
}

/// Tests run as wasm inside wasmtime: the `wasm32-wasip2` runner in `.cargo/config.toml`.
fn test_guest() -> Result<()> {
    let root = root();
    let mut cmd = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    cmd.current_dir(&root).args([
        "test",
        "--target",
        TARGET,
        "-p",
        "wasmnet-wire",
        "-p",
        "wasmnet-app-kit",
    ]);
    for c in components(&root)?.iter().filter(|c| c.lib) {
        cmd.args(["-p", &c.package]);
    }
    run(&mut cmd)
}

/// What `build` was asked for.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct BuildArgs {
    /// `--only`: the components and nodes to build, by name; empty for all of them.
    only: Vec<String>,
    /// `--out-dir`: where to copy what was asked for.
    out_dir: Option<PathBuf>,
    /// `--list`: print the names instead of building.
    list: bool,
}

fn build_args(args: &[String]) -> Result<BuildArgs> {
    let mut parsed = BuildArgs::default();
    let mut args = args.iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--only" => {
                let names = args.next().ok_or("build: --only needs names")?;
                let names = names.split(',').filter(|n| !n.is_empty());
                parsed.only.extend(names.map(str::to_owned));
            }
            "--out-dir" => {
                let dir = args.next().ok_or("build: --out-dir needs a directory")?;
                parsed.out_dir = Some(PathBuf::from(dir));
            }
            "--list" => parsed.list = true,
            other => return Err(format!("build: unknown option {other}").into()),
        }
    }
    Ok(parsed)
}

/// What one build covers.
struct Selection<'a> {
    /// The crates to build: the named ones and the parts of the named nodes.
    crates: Vec<&'a Crate>,
    /// The nodes to compose.
    nodes: Vec<&'a Node>,
    /// The crates that were asked for by name (all of them without `--only`): what
    /// `--out-dir` gets, with the nodes.
    named: BTreeSet<&'a str>,
}

/// The components and nodes `only` names (everything when it is empty), and the parts those
/// nodes are composed from.
fn select<'a>(crates: &'a [Crate], nodes: &'a [Node], only: &[String]) -> Result<Selection<'a>> {
    if only.is_empty() {
        return Ok(Selection {
            crates: crates.iter().collect(),
            nodes: nodes.iter().collect(),
            named: crates.iter().map(|c| c.name.as_str()).collect(),
        });
    }
    let mut named = BTreeSet::new();
    let mut parts = BTreeSet::new();
    let mut composed = BTreeSet::new();
    for name in only {
        if let Some(c) = crates.iter().find(|c| &c.name == name) {
            named.insert(c.name.as_str());
        } else if let Some(n) = nodes.iter().find(|n| &n.name == name) {
            composed.insert(n.name.as_str());
            for part in &n.parts {
                let c = crates
                    .iter()
                    .find(|c| &c.reference() == part)
                    .ok_or_else(|| format!("{}: no component `{part}`", n.wac.display()))?;
                parts.insert(c.name.as_str());
            }
        } else {
            return Err(format!(
                "build: no component or node `{name}` (`cargo xtask build --list` names them)"
            )
            .into());
        }
    }
    Ok(Selection {
        crates: crates
            .iter()
            .filter(|c| named.contains(c.name.as_str()) || parts.contains(c.name.as_str()))
            .collect(),
        nodes: nodes
            .iter()
            .filter(|n| composed.contains(n.name.as_str()))
            .collect(),
        named,
    })
}

/// `build --list`: every component and node by name, with the package or the parts behind it.
fn list(crates: &[Crate], nodes: &[Node]) {
    for c in crates {
        let kind = if c.app { "app" } else { "component" };
        println!("{:<22} {kind:<10} {}", c.name, c.package);
    }
    for n in nodes {
        println!("{:<22} {:<10} {}", n.name, "node", n.parts.join(" + "));
    }
}

/// What one build made: each file, and the name `--out-dir` gives it (none for a part nobody
/// named).
type Built = Vec<(PathBuf, Option<String>)>;

fn build(args: &BuildArgs) -> Result<Built> {
    let root = root();
    let crates = components(&root)?;
    let nodes = nodes(&root)?;
    if args.list {
        list(&crates, &nodes);
        return Ok(Vec::new());
    }
    let selected = select(&crates, &nodes, &args.only)?;

    // No build path in the bytes (remap.rs): the same source gives the same components in any
    // checkout. The flags are the components' alone, so RUSTFLAGS from the environment would
    // not reach them anyway; say so rather than drop them silently. The mappings cover every
    // component, whatever was selected: one set of flags, so that a partial build and a full one
    // share what cargo built.
    let packages: Vec<&str> = crates.iter().map(|c| c.package.as_str()).collect();
    let argfile = remap::argfile(&root, &target_dir(&root), &packages)?;
    for var in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
        if std::env::var_os(var).is_some_and(|v| !v.is_empty()) {
            println!("xtask build: {var} is not used for the components");
        }
    }
    let mut cmd = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    cmd.current_dir(&root)
        .args(["build", "--release", "--target", TARGET])
        .env("CARGO_ENCODED_RUSTFLAGS", format!("@{}", argfile.display()));
    for c in &selected.crates {
        cmd.args(["-p", &c.package]);
    }
    run(&mut cmd)?;

    let out = target_dir(&root).join(TARGET).join("release");
    let deps = target_dir(&root).join("wac-deps");
    // A full build starts from an empty directory; a partial one replaces only its own parts.
    if args.only.is_empty() && deps.exists() {
        fs::remove_dir_all(&deps)?;
    }
    let mut built: Built = Vec::new();
    for c in &selected.crates {
        let path = output(&out, &c.name)
            .ok_or_else(|| format!("{}: no .wasm in {}", c.name, out.display()))?;
        // wac's `--deps-dir` layout: `wasmnet:<component>` and `app:<app>`.
        fs::create_dir_all(deps.join(c.namespace()))?;
        fs::copy(
            &path,
            deps.join(c.namespace()).join(format!("{}.wasm", c.name)),
        )?;
        println!("  {:<20} {}", c.name, path.display());
        let named = selected.named.contains(c.name.as_str());
        built.push((path, named.then(|| format!("{}.wasm", c.name))));
    }

    for n in &selected.nodes {
        let node = out.join(format!("{}.wasm", n.name));
        run(Command::new("wac")
            .arg("compose")
            .arg(&n.wac)
            .arg("--deps-dir")
            .arg(&deps)
            .arg("-o")
            .arg(&node))?;
        println!("  {:<20} {}", n.name, node.display());
        built.push((node, Some(format!("{}.wasm", n.name))));
    }

    let mut invalid = 0;
    for (path, _) in &built {
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
        selected.crates.len(),
        selected.nodes.len(),
        built.len()
    );

    if let Some(dir) = &args.out_dir {
        fs::create_dir_all(dir)?;
        let mut copied = 0;
        for (path, name) in &built {
            if let Some(name) = name {
                fs::copy(path, dir.join(name))?;
                copied += 1;
            }
        }
        println!("xtask build: {copied} file(s) copied to {}", dir.display());
    }
    Ok(built)
}

/// The pinned versions in `tools.toml`: the Rust toolchain, and the command-line tools by
/// their crates.io package.
pub(crate) struct Tools {
    rust: String,
    cargo_install: Vec<(String, String)>,
}

impl Tools {
    /// The pinned version of the tool installed by `package`.
    fn version(&self, package: &str) -> Option<&str> {
        let (_, version) = self.cargo_install.iter().find(|(p, _)| p == package)?;
        Some(version)
    }
}

/// Reads `tools.toml`: `rust = "<version>"` first, then `<package> = "<version>"` lines under
/// `[cargo-install]`.
pub(crate) fn tools(text: &str) -> Result<Tools> {
    let mut section = "";
    let mut rust = None;
    let mut cargo_install = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[') {
            section = name.trim_end_matches(']');
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("tools.toml: `{line}` is not `name = \"version\"`"))?;
        let (key, value) = (key.trim(), value.trim().trim_matches('"').to_owned());
        match (section, key) {
            ("", "rust") => rust = Some(value),
            ("cargo-install", package) => cargo_install.push((package.to_owned(), value)),
            _ => return Err(format!("tools.toml: unknown key `{key}` in [{section}]").into()),
        }
    }
    Ok(Tools {
        rust: rust.ok_or("tools.toml: no `rust`")?,
        cargo_install,
    })
}

/// The version in a program's `--version` line, its second word (`wasmtime 50.0.1 (...)`), if
/// the program is on `PATH`.
fn reported_version(program: &str, dir: &Path) -> Option<String> {
    let out = Command::new(program)
        .current_dir(dir)
        .arg("--version")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    Some(text.split_whitespace().nth(1)?.to_owned())
}

/// `tools`: the pinned command-line tools as `<package>@<version>` lines (all of them, or the
/// named packages); with `--check`, a comparison with what is installed instead.
fn tools_command(args: &[String]) -> Result<()> {
    let root = root();
    let pins = tools(&fs::read_to_string(root.join("tools.toml"))?)?;
    let check = args.iter().any(|a| a == "--check");
    let wanted: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| *a != "--check")
        .collect();
    for w in &wanted {
        if w.starts_with('-') {
            return Err(format!("tools: unknown option {w}").into());
        }
        if pins.version(w).is_none() {
            return Err(format!("tools: `{w}` is not in tools.toml").into());
        }
    }
    let selected = pins
        .cargo_install
        .iter()
        .filter(|(p, _)| wanted.is_empty() || wanted.contains(&p.as_str()));
    if !check {
        for (package, version) in selected {
            println!("{package}@{version}");
        }
        return Ok(());
    }
    // The program a package installs: `wasmtime-cli` gives `wasmtime`, `wac-cli` gives `wac`.
    let mut programs = vec![("rustc", pins.rust.as_str())];
    programs.extend(selected.map(|(p, v)| (p.trim_end_matches("-cli"), v.as_str())));
    let wrong = tool_problems(&root, &programs);
    for (program, version) in &programs {
        if !wrong.iter().any(|w| w.starts_with(&format!("{program} "))) {
            println!("  ok       {program} {version}");
        }
    }
    for w in &wrong {
        println!("  {w}");
    }
    if !wrong.is_empty() {
        return Err(format!("{} tool(s) not at the pinned version", wrong.len()).into());
    }
    Ok(())
}

/// The programs (name, pinned version) that are missing or at another version, one line each.
fn tool_problems(root: &Path, programs: &[(&str, &str)]) -> Vec<String> {
    programs
        .iter()
        .filter_map(|(program, version)| match reported_version(program, root) {
            Some(found) if found == *version => None,
            Some(found) => Some(format!("{program} {found}: tools.toml pins {version}")),
            None => Some(format!("{program} missing: tools.toml pins {version}")),
        })
        .collect()
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
        build(&BuildArgs::default())?;
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

const USAGE: &str = "usage: cargo xtask build [--only NAME[,NAME...]] [--out-dir DIR] | \
cargo xtask build --list | cargo xtask test-guest | cargo xtask tools [--check] [PACKAGE...] | \
cargo xtask artifacts [--out DIR] [--rebuild MANIFEST] | cargo xtask artifacts --verify DIR | \
cargo xtask artifacts --compare A B | cargo xtask check-tree [--commits BASE..HEAD] | \
cargo xtask web [--no-build] [--test]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("build") => build_args(&args[1..]).and_then(|args| build(&args).map(drop)),
        Some("artifacts") => artifacts::command(&args[1..]),
        Some("check-tree") => leaks::command(&args[1..]),
        Some("test-guest") if args.len() == 1 => test_guest(),
        Some("tools") => tools_command(&args[1..]),
        Some("web") => web(&args[1..]),
        _ => Err(USAGE.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn a_composition_names_its_parts() {
        let wac = "// node = new app:commented { ... }\n\
                   package wasmnet:node-x;\n\
                   let net = new wasmnet:netstack { ... };\n\
                   let a = new app:http-server { ... }; let b = new app:dns-server {\n\
                   };\n\
                   let again = new app:http-server { ... }; // new app:late\n";
        assert_eq!(
            wac_parts(wac),
            ["wasmnet:netstack", "app:http-server", "app:dns-server"]
        );
    }

    #[test]
    fn build_options() {
        let args = build_args(&strings(&[
            "--only",
            "netstack,switch",
            "--out-dir",
            "out",
            "--only",
            "node-ping",
        ]))
        .unwrap();
        assert_eq!(args.only, ["netstack", "switch", "node-ping"]);
        assert_eq!(args.out_dir.as_deref(), Some(Path::new("out")));
        assert!(!args.list);
        assert_eq!(build_args(&[]).unwrap(), BuildArgs::default());
        assert!(build_args(&strings(&["--only"])).is_err());
        assert!(build_args(&strings(&["--release"])).is_err());
    }

    /// The names in a selection: the crates built, the nodes composed, the crates named.
    fn names(s: &Selection) -> (Vec<String>, Vec<String>, Vec<String>) {
        (
            s.crates.iter().map(|c| c.name.clone()).collect(),
            s.nodes.iter().map(|n| n.name.clone()).collect(),
            s.named.iter().map(|n| (*n).to_owned()).collect(),
        )
    }

    #[test]
    fn a_named_node_brings_its_parts_and_nothing_else() {
        let root = root();
        let (crates, nodes) = (components(&root).unwrap(), nodes(&root).unwrap());

        let all = select(&crates, &nodes, &[]).unwrap();
        assert_eq!(all.crates.len(), crates.len());
        assert_eq!(all.nodes.len(), nodes.len());
        assert_eq!(all.named.len(), crates.len());

        let some = select(&crates, &nodes, &strings(&["node-http-server", "switch"])).unwrap();
        let (built, composed, named) = names(&some);
        assert_eq!(built, ["netstack", "switch", "http-server"]);
        assert_eq!(composed, ["node-http-server"]);
        assert_eq!(named, ["switch"], "the node's parts were not asked for");

        let unknown = select(&crates, &nodes, &strings(&["node-nowhere"]));
        assert!(unknown.is_err_and(|e| e.to_string().contains("node-nowhere")));
    }

    #[test]
    fn the_tools_file_is_read() {
        let pins = tools(
            "# a comment\nrust = \"1.2.3\"\n\n[cargo-install]\nwasm-tools = \"4.5.6\" # why\n",
        )
        .unwrap();
        assert_eq!(pins.rust, "1.2.3");
        assert_eq!(pins.version("wasm-tools"), Some("4.5.6"));
        assert_eq!(pins.version("wac-cli"), None);
        assert!(
            tools("[cargo-install]\nwac-cli = \"1\"\n").is_err(),
            "no rust"
        );
        assert!(
            tools("rust = \"1\"\nnode = \"24\"\n").is_err(),
            "unknown key"
        );
    }

    /// The versions written after `<package>@` in `text`.
    fn mentions(text: &str, package: &str) -> Vec<String> {
        let marker = format!("{package}@");
        text.match_indices(&marker)
            .map(|(at, _)| {
                text[at + marker.len()..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect::<String>()
                    .trim_end_matches('.')
                    .to_owned()
            })
            .filter(|version| !version.is_empty())
            .collect()
    }

    /// Every Markdown and workflow file of the repository, outside build output and vendored
    /// trees.
    fn prose(dir: &Path, found: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if path.is_dir() {
                if !matches!(
                    name,
                    "target" | "node_modules" | "third_party" | ".git" | "dist"
                ) {
                    prose(&path, found);
                }
            } else if name.ends_with(".md") || name.ends_with(".yml") {
                found.push(path);
            }
        }
    }

    /// `tools.toml` is where the versions are: the toolchain file, the manifests, the install
    /// lines in the prose and the workflows agree with it.
    #[test]
    fn the_tool_versions_are_the_same_everywhere() {
        let root = root();
        let read = |path: &str| fs::read_to_string(root.join(path)).unwrap();
        let pins = tools(&read("tools.toml")).unwrap();
        let wasmtime = pins
            .version("wasmtime-cli")
            .expect("wasmtime-cli is pinned");

        let toolchain = read("rust-toolchain.toml");
        assert!(
            toolchain.contains(&format!("channel = \"{}\"", pins.rust)),
            "rust-toolchain.toml pins Rust {}",
            pins.rust
        );
        // The wasmtime that runs the component tests is the wasmtime the host embeds.
        let manifest = read("Cargo.toml");
        for krate in ["wasmtime", "wasmtime-wasi"] {
            assert!(
                manifest.contains(&format!("{krate} = {{ version = \"={wasmtime}\"")),
                "Cargo.toml pins {krate} {wasmtime}"
            );
        }

        // Wherever a file writes `<package>@<version>`, it is the pinned version.
        let mut files = Vec::new();
        prose(&root, &mut files);
        for file in &files {
            let text = fs::read_to_string(file).unwrap();
            for (package, version) in &pins.cargo_install {
                for mention in mentions(&text, package) {
                    assert_eq!(
                        &mention,
                        version,
                        "{}: {package}@{mention}, tools.toml pins {version}",
                        file.display()
                    );
                }
            }
        }
        // The install line is in both places a newcomer reads, and the README's status line
        // names the same versions.
        for file in ["README.md", "CONTRIBUTING.md"] {
            let text = read(file);
            for (package, _) in &pins.cargo_install {
                assert!(
                    !mentions(&text, package).is_empty(),
                    "{file} installs {package}"
                );
            }
        }
        let status = format!("Rust {} and wasmtime {wasmtime}", pins.rust);
        let readme: Vec<String> = read("README.md")
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        assert!(readme.join(" ").contains(&status), "README.md: {status}");
        // The workflows install what `cargo xtask tools` prints, not versions of their own.
        for file in files
            .iter()
            .filter(|f| f.extension().is_some_and(|x| x == "yml"))
        {
            let text = fs::read_to_string(file).unwrap();
            assert!(text.contains("cargo xtask tools"), "{}", file.display());
            for (package, _) in &pins.cargo_install {
                assert!(mentions(&text, package).is_empty(), "{}", file.display());
            }
        }
    }

    /// The cells of the Markdown table rows in `text` whose first cell is a name in backticks.
    fn table_rows(text: &str) -> Vec<Vec<String>> {
        text.lines()
            .filter(|l| l.starts_with("| `"))
            .map(|l| {
                l.trim_matches('|')
                    .split('|')
                    .map(|cell| cell.trim().replace('`', ""))
                    .collect()
            })
            .collect()
    }

    /// `components/README.md` lists exactly the components and nodes there are, with their
    /// packages and parts.
    #[test]
    fn the_component_list_is_current() {
        let root = root();
        let (crates, nodes) = (components(&root).unwrap(), nodes(&root).unwrap());
        let readme = fs::read_to_string(root.join("components/README.md")).unwrap();
        let rows = table_rows(&readme);
        let row = |name: &str| {
            rows.iter()
                .find(|r| r[0] == name)
                .unwrap_or_else(|| panic!("components/README.md has no row for `{name}`"))
        };
        for c in &crates {
            let r = row(&c.name);
            assert_eq!(r[1], c.package, "the package of `{}`", c.name);
            assert_eq!(r[2], format!("{}.wasm", c.name));
        }
        for n in &nodes {
            let parts: Vec<&str> = n
                .parts
                .iter()
                .map(|p| p.split_once(':').unwrap().1)
                .collect();
            assert_eq!(
                row(&n.name)[1],
                parts.join(", "),
                "the parts of `{}`",
                n.name
            );
        }
        assert_eq!(
            rows.len(),
            crates.len() + nodes.len(),
            "components/README.md lists something that is not there"
        );
    }
}
