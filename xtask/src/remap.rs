//! Build paths out of the component bytes.
//!
//! rustc writes the source path of every place that can panic into the binary. Cargo passes
//! a workspace crate's files as paths relative to the workspace root, with the platform's
//! separator (`components\router\src\nat.rs` on Windows), and a crates.io crate's files as
//! absolute paths into the cargo home (`<home>/.cargo/registry/src/...`), which name the
//! user and the machine. Both would make the same source give different bytes in different
//! places, and the second would publish a local path.
//!
//! So `build` hands rustc one `--remap-path-prefix` per source directory of every crate the
//! components are built from: a workspace directory becomes its relative path with `/`
//! separators, any other crate's directory `/deps/<name>-<version>/...`. A directory, not a
//! crate root, because rustc keeps the rest of a path as it found it, separators included,
//! and appends it to the mapping's target. The flags go through an argument file in the
//! target directory, named by the hash of its contents and of the metadata scheme
//! (`metadata.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::{Result, TARGET};

/// One mapping: paths under `from` are written as `to` followed by the rest of the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub from: PathBuf,
    pub to: String,
}

/// `path` with `/` between its components, whatever the platform's separator.
fn slashed(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The mappings for one crate whose sources are in `dir`: one per directory there that holds
/// a `.rs` file (below `target`, `.git` and `node_modules` nothing is compiled).
///
/// `root` is the workspace root: a crate under it is written relative to it, as cargo passes
/// it; any other crate as `/deps/<name>-<version>`.
pub fn crate_mappings(root: &Path, dir: &Path, name: &str, version: &str) -> Vec<Mapping> {
    let (from_base, to_base) = match dir.strip_prefix(root) {
        Ok(rel) => (rel.to_path_buf(), slashed(rel)),
        Err(_) => (dir.to_path_buf(), format!("/deps/{name}-{version}")),
    };
    let mut mappings = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        let mut has_rs = false;
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name();
            if path.is_dir() {
                if !matches!(file_name.to_str(), Some("target" | ".git" | "node_modules")) {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|x| x == "rs") {
                has_rs = true;
            }
        }
        if has_rs {
            let rel = d.strip_prefix(dir).unwrap_or(Path::new(""));
            let to = match slashed(rel) {
                r if r.is_empty() => format!("{to_base}/"),
                r => format!("{to_base}/{r}/"),
            };
            mappings.push(Mapping {
                from: from_base.join(rel),
                to,
            });
        }
    }
    mappings
}

/// rustc tries the mappings last to first and takes the first whose `from` is a prefix of the
/// path, so a deeper directory comes after the directories it is in.
pub fn sort(mappings: &mut [Mapping]) {
    mappings.sort_by(|a, b| {
        let depth = |m: &Mapping| m.from.components().count();
        depth(a)
            .cmp(&depth(b))
            .then_with(|| a.from.cmp(&b.from))
            .then_with(|| a.to.cmp(&b.to))
    });
}

/// The packages `wanted` (workspace packages, by name) and everything they depend on for
/// `wasm32-wasip2`, as `(name, version, directory)`, from `cargo metadata`.
fn packages(root: &Path, wanted: &[&str]) -> Result<Vec<(String, String, PathBuf)>> {
    let out = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .current_dir(root)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--filter-platform",
            TARGET,
        ])
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    let meta: Value = serde_json::from_slice(&out.stdout)?;
    let mut by_id: BTreeMap<&str, &Value> = BTreeMap::new();
    for p in meta["packages"]
        .as_array()
        .ok_or("cargo metadata: no packages")?
    {
        by_id.insert(p["id"].as_str().unwrap_or_default(), p);
    }
    let mut deps: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in meta["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata: no resolve")?
    {
        let normal = node["deps"].as_array().into_iter().flatten().filter(|d| {
            // What the component links: normal dependencies (`kind` null), not build or dev
            // ones, which run on the host.
            d["dep_kinds"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|k| k["kind"].is_null()))
        });
        deps.insert(
            node["id"].as_str().unwrap_or_default(),
            normal.filter_map(|d| d["pkg"].as_str()).collect(),
        );
    }
    let members: BTreeSet<&str> = meta["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut todo: Vec<&str> = members
        .iter()
        .copied()
        .filter(|id| {
            by_id
                .get(id)
                .and_then(|p| p["name"].as_str())
                .is_some_and(|n| wanted.contains(&n))
        })
        .collect();
    let mut seen = BTreeSet::new();
    while let Some(id) = todo.pop() {
        if seen.insert(id) {
            todo.extend(deps.get(id).into_iter().flatten().copied());
        }
    }
    let mut found = Vec::new();
    for id in seen {
        let p = by_id.get(id).ok_or("cargo metadata: unknown package")?;
        let manifest = PathBuf::from(p["manifest_path"].as_str().unwrap_or_default());
        let dir = manifest
            .parent()
            .ok_or("cargo metadata: bad manifest path")?;
        found.push((
            p["name"].as_str().unwrap_or_default().to_owned(),
            p["version"].as_str().unwrap_or_default().to_owned(),
            dir.to_path_buf(),
        ));
    }
    Ok(found)
}

/// Writes the argument file for building `wanted` (package names) into `target`, and
/// returns its path: what `CARGO_ENCODED_RUSTFLAGS` gets as `@<path>`.
pub fn argfile(root: &Path, target: &Path, wanted: &[&str]) -> Result<PathBuf> {
    let mut mappings = Vec::new();
    for (name, version, dir) in packages(root, wanted)? {
        mappings.extend(crate_mappings(root, &dir, &name, &version));
    }
    sort(&mut mappings);
    let text: String = mappings
        .iter()
        .map(|m| format!("--remap-path-prefix={}={}\n", m.from.display(), m.to))
        .collect();
    // Named for the metadata scheme too: a build with another scheme (or none) has other
    // flags, so cargo rebuilds its crates instead of reusing them (metadata.rs).
    let named = format!("{}\n{text}", crate::metadata::SCHEME);
    let hash = wasmnet_artifacts::sha256_hex(named.as_bytes());
    let dir = target.join("remap");
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.args", &hash[..16]));
    if !path.is_file() {
        fs::write(&path, text)?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_slashed_on_every_platform() {
        let p: PathBuf = ["components", "router", "src"].iter().collect();
        assert_eq!(slashed(&p), "components/router/src");
        assert_eq!(slashed(Path::new("")), "");
    }

    #[test]
    fn every_source_directory_of_a_crate_is_mapped() {
        let root = crate::root();
        let dir = root.join("components").join("router");
        let mappings = crate_mappings(&root, &dir, "wasmnet-router", "0.0.0");
        let find = |to: &str| mappings.iter().find(|m| m.to == to);
        let src = find("components/router/src/").expect("src");
        assert_eq!(src.from, Path::new("components").join("router").join("src"));
        let tunnel = find("components/router/src/tunnel/").expect("a module directory");
        assert_eq!(tunnel.from, src.from.join("tunnel"));

        let elsewhere = Path::new("/elsewhere/wit-bindgen-0.61.1");
        let outside = crate_mappings(Path::new("/root"), elsewhere, "wit-bindgen", "0.61.1");
        assert!(outside.is_empty(), "nothing on disk there");
    }

    #[test]
    fn deeper_mappings_come_last() {
        let m = |from: &str| Mapping {
            from: PathBuf::from(from),
            to: String::new(),
        };
        let mut list = vec![m("a/b/c"), m("a"), m("z"), m("a/b")];
        sort(&mut list);
        let order: Vec<String> = list.iter().map(|m| slashed(&m.from)).collect();
        assert_eq!(order, ["a", "z", "a/b", "a/b/c"]);
    }
}
