//! `artifacts`: the published components of this revision, with a manifest of their hashes.
//!
//! ```text
//! cargo xtask artifacts [--out DIR]      build the published set into DIR (default
//!                                        target/artifacts): every file, manifest.toml, SHA256SUMS
//! cargo xtask artifacts --rebuild FILE   the same, then compare with the manifest FILE (built
//!                                        elsewhere from the same revision): the hashes must match
//! cargo xtask artifacts --verify DIR     check DIR against DIR/manifest.toml and DIR/SHA256SUMS
//! cargo xtask artifacts --compare A B    compare two manifests' files (two platforms' builds)
//! ```
//!
//! Published: every component and app except the test fixtures ([`FIXTURES`]), and every node
//! composed only of published parts. The format is `wasmnet_artifacts::Manifest`'s.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use wasmnet_artifacts::{File, Kind, Manifest, sha256_hex};
use wasmparser::{Parser, Payload};

use crate::{BuildArgs, Result, TARGET, leaks};

/// The components that exist for this repository's own tests (`components/README.md`'s "Test
/// fixtures"): built, never published.
pub const FIXTURES: &[&str] = &[
    "blaster",
    "clock-probe",
    "infra-script",
    "reflector",
    "udp-punch",
];

/// The tools whose versions decide the bytes: they must be the pinned ones.
const BUILD_TOOLS: &[&str] = &["wasm-tools", "wac-cli"];

/// The names a component imports and exports at its top level (not those of the modules and
/// components nested in it), each sorted.
pub fn interfaces(bytes: &[u8]) -> Result<(Vec<String>, Vec<String>)> {
    let (mut imports, mut exports) = (Vec::new(), Vec::new());
    let mut depth = 0usize;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::Version { .. } => depth += 1,
            Payload::End(_) => depth = depth.saturating_sub(1),
            Payload::ComponentImportSection(reader) if depth == 1 => {
                for import in reader {
                    imports.push(import?.name.full_name().into_owned());
                }
            }
            Payload::ComponentExportSection(reader) if depth == 1 => {
                for export in reader {
                    exports.push(export?.name.full_name().into_owned());
                }
            }
            _ => {}
        }
    }
    imports.sort();
    exports.sort();
    Ok((imports, exports))
}

/// The commit of the working tree and whether it has changes; `unknown` without git, or when
/// the git repository around `root` is another one (a copy of the source inside some other
/// checkout).
fn revision(root: &Path) -> (String, bool) {
    let git = |args: &[&str]| {
        Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
    };
    let ours = git(&["rev-parse", "--show-toplevel"]).is_some_and(|top| {
        let same = |p: &Path| fs::canonicalize(p).ok();
        same(Path::new(&top)).is_some() && same(Path::new(&top)) == same(root)
    });
    if !ours {
        return ("unknown".to_owned(), true);
    }
    match git(&["rev-parse", "HEAD"]) {
        Some(rev) => (
            rev,
            git(&["status", "--porcelain"]).is_none_or(|s| !s.is_empty()),
        ),
        None => ("unknown".to_owned(), true),
    }
}

/// The host triple of the Rust toolchain (`rustc -vV`'s `host:` line).
fn rust_host(root: &Path) -> Result<String> {
    let out = Command::new("rustc")
        .current_dir(root)
        .arg("-vV")
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "rustc -vV: no host line".into())
}

/// Where a build could stray from the pinned one: other tool versions, or a release profile
/// changed from the environment.
fn check_environment(root: &Path, pins: &crate::Tools) -> Result<()> {
    let mut programs = vec![("rustc", pins.rust.as_str())];
    for tool in BUILD_TOOLS {
        let version = pins.version(tool).ok_or("tools.toml lacks a build tool")?;
        programs.push((tool.trim_end_matches("-cli"), version));
    }
    let wrong = crate::tool_problems(root, &programs);
    if !wrong.is_empty() {
        return Err(format!("artifacts: {} (see tools.toml)", wrong.join("; ")).into());
    }
    let profile: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| k.starts_with("CARGO_PROFILE_RELEASE_"))
        .collect();
    if !profile.is_empty() {
        return Err(format!(
            "artifacts: {} would change the release profile the set is built with",
            profile.join(", ")
        )
        .into());
    }
    Ok(())
}

/// Bytes that must not be in a published file: the workspace's path, the cargo home, the
/// user's home, and anything [`leaks::scan`] finds in the file's printable strings.
fn embedded_paths(name: &str, bytes: &[u8], root: &Path) -> Vec<String> {
    let mut needles: Vec<String> = Vec::new();
    let mut add = |p: &Path| {
        let s = p.to_string_lossy().into_owned();
        if s.len() > 3 {
            needles.push(s.replace('\\', "/"));
            needles.push(s.replace('/', "\\"));
        }
    };
    add(root);
    for var in ["CARGO_HOME", "HOME", "USERPROFILE"] {
        if let Some(dir) = std::env::var_os(var) {
            add(Path::new(&dir));
        }
    }
    let mut found = Vec::new();
    for needle in &needles {
        if bytes
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
        {
            found.push(format!("{name} contains the local path {needle}"));
        }
    }
    // Printable runs, one per line, for the generic patterns; and source paths that kept a
    // backslash (a separator the remapping missed).
    let mut strings = String::new();
    for run in bytes.split(|b| !(0x20..0x7f).contains(b)) {
        if run.len() >= 6 {
            strings.push_str(&String::from_utf8_lossy(run));
            strings.push('\n');
        }
    }
    for f in leaks::scan(&strings) {
        found.push(format!("{name}: {} in its strings", f.what));
    }
    for line in strings.lines() {
        if line.contains(".rs") && line.contains('\\') {
            found.push(format!("{name}: a source path with backslashes: {line}"));
            break;
        }
    }
    found
}

/// What `artifacts` was asked to do.
#[derive(Debug, PartialEq)]
enum Mode {
    Write {
        out: Option<PathBuf>,
        rebuild: Option<PathBuf>,
    },
    Verify(PathBuf),
    Compare(PathBuf, PathBuf),
}

fn mode(args: &[String]) -> Result<Mode> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["--verify", dir] => return Ok(Mode::Verify(dir.into())),
        ["--compare", a, b] => return Ok(Mode::Compare(a.into(), b.into())),
        ["--verify", ..] => return Err("artifacts: --verify DIR".into()),
        ["--compare", ..] => return Err("artifacts: --compare A B".into()),
        _ => {}
    }
    let (mut out, mut rebuild) = (None, None);
    let mut rest = args.iter();
    while let Some(a) = rest.next() {
        let slot = match *a {
            "--out" => &mut out,
            "--rebuild" => &mut rebuild,
            other => return Err(format!("artifacts: unknown option {other}").into()),
        };
        let value = rest.next().ok_or(format!("artifacts: {a} needs a path"))?;
        *slot = Some(PathBuf::from(value));
    }
    Ok(Mode::Write { out, rebuild })
}

pub fn command(args: &[String]) -> Result<()> {
    match mode(args)? {
        Mode::Write { out, rebuild } => {
            let root = crate::root();
            let out = out.unwrap_or_else(|| crate::target_dir(&root).join("artifacts"));
            let manifest = write(&root, &out)?;
            if let Some(path) = rebuild {
                let theirs = read_manifest(&path)?;
                if theirs.revision != manifest.revision {
                    return Err(format!(
                        "artifacts: {} was built from {}, this tree is {}: check that out first",
                        path.display(),
                        theirs.revision,
                        manifest.revision
                    )
                    .into());
                }
                compare(&theirs, &manifest)?;
                println!(
                    "xtask artifacts: the rebuild gives the bytes {} lists",
                    path.display()
                );
            }
            Ok(())
        }
        Mode::Verify(dir) => verify(&dir),
        Mode::Compare(a, b) => compare(&read_manifest(&a)?, &read_manifest(&b)?),
    }
}

fn read_manifest(path: &Path) -> Result<Manifest> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Manifest::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?)
}

/// Builds the published set and writes it, with its manifest, into `out`.
fn write(root: &Path, out: &Path) -> Result<Manifest> {
    let pins = crate::tools(&fs::read_to_string(root.join("tools.toml"))?)?;
    check_environment(root, &pins)?;
    let crates = crate::components(root)?;
    let nodes = crate::nodes(root)?;
    let published = |c: &crate::Crate| !FIXTURES.contains(&c.name.as_str());
    let mut only: Vec<String> = crates
        .iter()
        .filter(|c| published(c))
        .map(|c| c.name.clone())
        .collect();
    let mut node_parts = Vec::new();
    for n in &nodes {
        let parts: Option<Vec<&crate::Crate>> = n
            .parts
            .iter()
            .map(|p| crates.iter().find(|c| &c.reference() == p))
            .collect();
        if let Some(parts) = parts.filter(|ps| ps.iter().all(|c| published(c))) {
            only.push(n.name.clone());
            node_parts.push((
                n.name.clone(),
                parts.iter().map(|c| c.name.clone()).collect(),
            ));
        }
    }
    let built = crate::build(&BuildArgs {
        only,
        ..BuildArgs::default()
    })?;

    let (rev, dirty) = revision(root);
    let mut manifest = Manifest::new(rev);
    manifest.dirty = dirty;
    manifest.target = TARGET.to_owned();
    manifest.host = rust_host(root)?;
    manifest.rust = pins.rust.clone();
    manifest.tools = pins.cargo_install.clone();

    // A directory of its own: the files of an earlier set go first.
    fs::create_dir_all(out)?;
    for entry in fs::read_dir(out)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".wasm") || name == "manifest.toml" || name == "SHA256SUMS" {
            fs::remove_file(entry.path())?;
        }
    }
    let mut leaked = Vec::new();
    for (path, name) in &built {
        let Some(name) = name else { continue };
        let bytes = fs::read(path)?;
        leaked.extend(embedded_paths(name, &bytes, root));
        let stem = name.trim_end_matches(".wasm");
        let parts = node_parts.iter().find(|(n, _)| n == stem).map(|(_, p)| p);
        let kind = match (parts, crates.iter().find(|c| c.name == stem)) {
            (Some(_), _) => Kind::Node,
            (None, Some(c)) if c.app => Kind::App,
            _ => Kind::Component,
        };
        let mut file = File::new(name, kind, sha256_hex(&bytes), bytes.len() as u64);
        (file.imports, file.exports) = interfaces(&bytes)?;
        if file.exports.is_empty() {
            return Err(format!("artifacts: {name} exports nothing: not a component?").into());
        }
        file.parts = parts.cloned().unwrap_or_default();
        fs::write(out.join(name), &bytes)?;
        manifest.files.push(file);
    }
    if !leaked.is_empty() {
        return Err(format!(
            "artifacts: build paths left in the bytes:\n  {}",
            leaked.join("\n  ")
        )
        .into());
    }
    manifest.files.sort_by(|a, b| a.name.cmp(&b.name));
    fs::write(out.join("manifest.toml"), manifest.to_toml()?)?;
    fs::write(out.join("SHA256SUMS"), manifest.sha256sums())?;
    for f in &manifest.files {
        println!("  {}  {:>8}  {}", f.sha256, f.size, f.name);
    }
    println!(
        "xtask artifacts: {} file(s) of {}{} in {}",
        manifest.files.len(),
        manifest.revision,
        if manifest.dirty {
            " (with changes)"
        } else {
            ""
        },
        out.display()
    );
    Ok(manifest)
}

/// `--verify`: every file the manifest lists, with its size and hash; SHA256SUMS says the
/// same; no `.wasm` the manifest does not list.
fn verify(dir: &Path) -> Result<()> {
    let manifest = read_manifest(&dir.join("manifest.toml"))?;
    let mut problems: Vec<String> = manifest
        .check_dir(dir)
        .iter()
        .map(ToString::to_string)
        .collect();
    match fs::read_to_string(dir.join("SHA256SUMS")) {
        Ok(sums) if sums == manifest.sha256sums() => {}
        Ok(_) => problems.push("SHA256SUMS differs from manifest.toml".to_owned()),
        Err(e) => problems.push(format!("SHA256SUMS: {e}")),
    }
    for entry in fs::read_dir(dir)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".wasm") && manifest.file(&name).is_none() {
            problems.push(format!("{name} is not in the manifest"));
        }
    }
    for p in &problems {
        println!("  {p}");
    }
    if problems.is_empty() {
        println!(
            "xtask artifacts: {} file(s) of {} match their manifest",
            manifest.files.len(),
            manifest.revision
        );
        Ok(())
    } else {
        Err(format!(
            "artifacts: {} problem(s) in {}",
            problems.len(),
            dir.display()
        )
        .into())
    }
}

/// The files two manifests disagree on: hash, or presence.
fn differences(a: &Manifest, b: &Manifest) -> Vec<String> {
    let mut names: Vec<&str> = a
        .files
        .iter()
        .chain(&b.files)
        .map(|f| f.name.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
        .into_iter()
        .filter_map(|name| match (a.file(name), b.file(name)) {
            (Some(x), Some(y)) if x.sha256 == y.sha256 => None,
            (Some(x), Some(y)) => Some(format!("{name}: {} != {}", x.sha256, y.sha256)),
            (Some(_), None) => Some(format!("{name}: only in the first")),
            (None, _) => Some(format!("{name}: only in the second")),
        })
        .collect()
}

fn compare(a: &Manifest, b: &Manifest) -> Result<()> {
    println!(
        "  first:  {} on {} (Rust {})\n  second: {} on {} (Rust {})",
        a.revision, a.host, a.rust, b.revision, b.host, b.rust
    );
    let diff = differences(a, b);
    for d in &diff {
        println!("  {d}");
    }
    if diff.is_empty() {
        println!(
            "xtask artifacts: the same {} file(s), byte for byte",
            a.files.len()
        );
        Ok(())
    } else {
        Err(format!("artifacts: {} of the files differ", diff.len()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn options() {
        assert_eq!(
            mode(&[]).unwrap(),
            Mode::Write {
                out: None,
                rebuild: None
            }
        );
        assert_eq!(
            mode(&strings(&["--rebuild", "m.toml", "--out", "o"])).unwrap(),
            Mode::Write {
                out: Some("o".into()),
                rebuild: Some("m.toml".into())
            }
        );
        assert_eq!(
            mode(&strings(&["--verify", "d"])).unwrap(),
            Mode::Verify("d".into())
        );
        assert_eq!(
            mode(&strings(&["--compare", "a", "b"])).unwrap(),
            Mode::Compare("a".into(), "b".into())
        );
        assert!(mode(&strings(&["--compare", "a"])).is_err());
        assert!(mode(&strings(&["--verify", "d", "--out", "o"])).is_err());
        assert!(mode(&strings(&["--release"])).is_err());
    }

    #[test]
    fn manifests_are_compared_file_by_file() {
        let file = |name: &str, hash: char| {
            File::new(name, Kind::Component, hash.to_string().repeat(64), 1)
        };
        let mut a = Manifest::new("r");
        a.files = vec![file("a.wasm", 'a'), file("b.wasm", 'b')];
        let mut b = a.clone();
        assert!(differences(&a, &b).is_empty());
        b.files = vec![file("a.wasm", 'c'), file("c.wasm", 'c')];
        assert_eq!(differences(&a, &b).len(), 3);
    }

    #[test]
    fn the_fixtures_are_components_and_listed_as_such() {
        let root = crate::root();
        let crates = crate::components(&root).unwrap();
        let readme = fs::read_to_string(root.join("components/README.md")).unwrap();
        let section = readme
            .split("## Test fixtures")
            .nth(1)
            .and_then(|s| s.split("\n## ").next())
            .expect("components/README.md has a Test fixtures section");
        for name in FIXTURES {
            assert!(
                crates.iter().any(|c| c.name == *name),
                "no component `{name}`"
            );
            assert!(
                section.contains(&format!("| `{name}` |")),
                "`{name}` is not under Test fixtures"
            );
        }
        let listed = section.lines().filter(|l| l.starts_with("| `")).count();
        assert_eq!(
            listed,
            FIXTURES.len(),
            "Test fixtures lists another component"
        );
    }

    #[test]
    fn a_path_in_the_bytes_is_caught() {
        let root = crate::root();
        let mut bytes = b"\0asm\x01\0\0\0 panicked at ".to_vec();
        bytes.extend_from_slice(root.join("src").join("lib.rs").to_string_lossy().as_bytes());
        assert!(!embedded_paths("x.wasm", &bytes, &root).is_empty());
        let clean = b"\0asm components/router/src/nat.rs /deps/wit-bindgen-0.61.1/src/lib.rs";
        assert!(embedded_paths("x.wasm", clean, &root).is_empty());
        let backslash = b"\0asm components\\router\\src\\nat.rs";
        assert!(!embedded_paths("x.wasm", backslash, &root).is_empty());
    }

    #[test]
    fn the_revision_is_this_checkouts_own() {
        let root = crate::root();
        let (rev, _) = revision(&root);
        // A checkout without git (an unpacked archive) has no revision either.
        if rev != "unknown" {
            assert_eq!(rev.len(), 40, "{rev}");
        }
        // A directory inside the checkout is not a checkout of its own.
        assert_eq!(revision(&root.join("docs")), ("unknown".to_owned(), true));
    }

    #[test]
    fn an_empty_component_names_nothing() {
        assert_eq!(interfaces(b"\0asm\x0d\0\x01\0").unwrap(), (vec![], vec![]));
        assert!(interfaces(b"not wasm").is_err());
    }
}
