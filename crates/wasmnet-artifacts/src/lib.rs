//! wasmnet-artifacts: the component artifacts of one revision of this repository, their
//! manifest, and fetching a pinned set of them with every hash checked.
//!
//! `cargo xtask artifacts` builds the published components (the netstack, the fabric devices,
//! the apps and the composed nodes) and writes them to a directory with two descriptions:
//!
//! * `manifest.toml` ([`Manifest`], format [`FORMAT`]): the source revision, the Rust toolchain
//!   and tool versions, and for every file its SHA-256, size, kind, and the interfaces it
//!   imports and exports with their versions;
//! * `SHA256SUMS`: the same hashes in the format `sha256sum -c` reads ([`parse_sums`]).
//!
//! An embedder pins the files it needs as [`Pin`]s (lines copied from `SHA256SUMS` into its own
//! repository) and gets them with [`fetch`] from a [`Source`]: a directory (such a set, built
//! locally or downloaded) or an OCI registry, where every file is a blob named by its SHA-256.
//! Nothing is written under its name until its bytes match the pin, so the pins in the
//! embedder's repository are the only thing it has to trust. A build script can call it:
//!
//! ```no_run
//! use wasmnet_artifacts::{Source, fetch, parse_sums};
//! # fn main() -> Result<(), wasmnet_artifacts::Error> {
//! // Lines copied from a set's SHA256SUMS into the embedder's repository.
//! const PINS: &str = "\
//! 3657490e6697450060272816c2d7ff252bea01abadabb41514e3d44b8e84b03e  netstack.wasm
//! ";
//! let pins = parse_sums(PINS)?;
//! let source = match std::env::var_os("WASMNET_ARTIFACTS_DIR") {
//!     Some(dir) => Source::Dir(dir.into()),
//!     None => Source::oci("ghcr.io", "backkem/wasmnet/components"),
//! };
//! let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
//! for path in fetch(&source, &pins, &out.join("components"))? {
//!     println!("cargo::rerun-if-changed={}", path.display());
//! }
//! # Ok(()) }
//! ```
//!
//! [`fetch`] downloads with the `curl` program, which Windows, macOS and most Linux systems
//! ship; [`fetch_with`] takes any other downloader. Nothing has been published to a registry
//! yet: `docs/design/artifacts.md` says where a revision's set is meant to live and how it
//! gets there.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest as _, Sha256};

/// The manifest format this crate reads and writes. Keys may be added within a format; a
/// change to what an existing key means changes the format's name.
pub const FORMAT: &str = "wasmnet-artifacts/1";

/// What went wrong.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The manifest or a list of pins could not be read.
    #[error("line {line}: {message}")]
    Parse {
        /// The line, from 1.
        line: usize,
        /// What was wrong with it.
        message: String,
    },
    /// A value that cannot be written or pinned: a name that is not a plain file name, a hash
    /// that is not 64 lowercase hex digits, a string a manifest cannot hold.
    #[error("{0}")]
    Invalid(String),
    /// A file's bytes are not the ones pinned.
    #[error("{name}: SHA-256 is {actual}, expected {expected}")]
    Mismatch {
        /// The file's name.
        name: String,
        /// The pinned hash.
        expected: String,
        /// The hash of what was found.
        actual: String,
    },
    /// A file has the right name and the wrong size.
    #[error("{name}: {actual} bytes, expected {expected}")]
    Size {
        /// The file's name.
        name: String,
        /// The size in the manifest.
        expected: u64,
        /// The size found.
        actual: u64,
    },
    /// A component does not export what it was expected to.
    #[error("{name} does not export {}", missing.join(", "))]
    Interfaces {
        /// The file's name.
        name: String,
        /// The interfaces it lacks, with their versions.
        missing: Vec<String>,
    },
    /// A component imports more than it was allowed to.
    #[error("{name} imports {}, which is not allowed", extra.join(", "))]
    Imports {
        /// The file's name.
        name: String,
        /// The imports outside what was allowed.
        extra: Vec<String>,
    },
    /// A file could not be read or written.
    #[error("{}: {source}", path.display())]
    Io {
        /// The path.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
    /// A download failed.
    #[error("{url}: {message}")]
    Download {
        /// What was asked for.
        url: String,
        /// Why it failed.
        message: String,
    },
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The SHA-256 of `bytes`, as 64 lowercase hex digits.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn check_sha256(hex: &str) -> Result<(), Error> {
    if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "`{hex}` is not a SHA-256 (64 lowercase hex digits)"
        )))
    }
}

/// A file name in a set: letters, digits, `.`, `_` and `-`, not starting with a dot, so that
/// it cannot name a path outside the directory it is written to.
fn check_name(name: &str) -> Result<(), Error> {
    let plain = !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if plain {
        Ok(())
    } else {
        Err(Error::Invalid(format!("`{name}` is not a plain file name")))
    }
}

/// What a file in a set is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Kind {
    /// The netstack or a fabric device (`netstack.wasm`, `switch.wasm`, ...).
    Component,
    /// An app, which runs only composed with a netstack (`http-server.wasm`, ...).
    App,
    /// A composed node: the netstack and its apps (`node-http-server.wasm`, ...).
    Node,
}

impl Kind {
    /// Its name in a manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Component => "component",
            Kind::App => "app",
            Kind::Node => "node",
        }
    }

    fn parse(s: &str) -> Option<Kind> {
        [Kind::Component, Kind::App, Kind::Node]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

/// One file of a set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct File {
    /// Its file name (`netstack.wasm`).
    pub name: String,
    /// What it is.
    pub kind: Kind,
    /// Its SHA-256, 64 lowercase hex digits.
    pub sha256: String,
    /// Its size in bytes.
    pub size: u64,
    /// A node's parts, by component name (`netstack`, `http-server`); empty otherwise.
    pub parts: Vec<String>,
    /// The names it exports at its top level, sorted: interfaces with their versions
    /// (`wasi:sockets/types@0.3.0`, `wasmnet:link/device@0.1.0`) and a node's plain names for
    /// its apps (`app-http-server`).
    pub exports: Vec<String>,
    /// The names it imports at its top level, sorted, as `exports`.
    pub imports: Vec<String>,
}

impl File {
    /// A file with no parts, exports or imports yet.
    pub fn new(name: impl Into<String>, kind: Kind, sha256: impl Into<String>, size: u64) -> Self {
        File {
            name: name.into(),
            kind,
            sha256: sha256.into(),
            size,
            parts: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
        }
    }

    /// Its pin: name and hash.
    pub fn pin(&self) -> Pin {
        Pin {
            name: self.name.clone(),
            sha256: self.sha256.clone(),
        }
    }

    /// Checks that it exports every name in `wanted` (`wasi:sockets/types@0.3.0`): what an
    /// embedder whose apps were built against those versions needs from a netstack.
    pub fn check_exports(&self, wanted: &[&str]) -> Result<(), Error> {
        Self::check(&self.name, &self.exports, wanted)
    }

    /// Checks that it imports nothing outside `allowed`.
    pub fn check_imports_within(&self, allowed: &[&str]) -> Result<(), Error> {
        let extra: Vec<&str> = self
            .imports
            .iter()
            .map(String::as_str)
            .filter(|i| !allowed.contains(i))
            .collect();
        if extra.is_empty() {
            Ok(())
        } else {
            Err(Error::Imports {
                name: self.name.clone(),
                extra: extra.iter().map(|i| (*i).to_owned()).collect(),
            })
        }
    }

    fn check(name: &str, have: &[String], wanted: &[&str]) -> Result<(), Error> {
        let missing: Vec<String> = wanted
            .iter()
            .filter(|w| !have.iter().any(|h| h == *w))
            .map(|w| (*w).to_owned())
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(Error::Interfaces {
                name: name.to_owned(),
                missing,
            })
        }
    }
}

/// A set's description: `manifest.toml`.
///
/// It is TOML, written in one fixed order so that the same set always gives the same bytes:
///
/// ```toml
/// format = "wasmnet-artifacts/1"
/// revision = "f5406540e3b9..."   # the commit the set was built from
/// dirty = false                  # whether the working tree had changes
/// target = "wasm32-wasip2"
/// host = "x86_64-unknown-linux-gnu"
/// rust = "1.98.1"
///
/// [tools]
/// wac-cli = "0.12.0"
///
/// [[file]]
/// name = "netstack.wasm"
/// kind = "component"
/// sha256 = "3657490e..."
/// size = 1278543
/// exports = [
///   "wasi:sockets/types@0.3.0",
/// ]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Manifest {
    /// The source revision (a commit hash), or `unknown`.
    pub revision: String,
    /// Whether the working tree differed from that revision.
    pub dirty: bool,
    /// The compilation target (`wasm32-wasip2`).
    pub target: String,
    /// The Rust host triple the set was built on: builds on different operating systems are
    /// not guaranteed to give the same bytes.
    pub host: String,
    /// The Rust toolchain's version.
    pub rust: String,
    /// The command-line tools, by package, with their versions, sorted.
    pub tools: Vec<(String, String)>,
    /// The files, sorted by name.
    pub files: Vec<File>,
}

impl Manifest {
    /// An empty manifest of `revision`.
    pub fn new(revision: impl Into<String>) -> Self {
        Manifest {
            revision: revision.into(),
            dirty: false,
            target: String::new(),
            host: String::new(),
            rust: String::new(),
            tools: Vec::new(),
            files: Vec::new(),
        }
    }

    /// The file named `name`.
    pub fn file(&self, name: &str) -> Option<&File> {
        self.files.iter().find(|f| f.name == name)
    }

    /// Every file's pin.
    pub fn pins(&self) -> Vec<Pin> {
        self.files.iter().map(File::pin).collect()
    }

    /// The manifest as text, files sorted by name and lists sorted.
    pub fn to_toml(&self) -> Result<String, Error> {
        let mut out = String::new();
        kv(&mut out, "format", FORMAT)?;
        kv(&mut out, "revision", &self.revision)?;
        writeln!(out, "dirty = {}", self.dirty).ok();
        kv(&mut out, "target", &self.target)?;
        kv(&mut out, "host", &self.host)?;
        kv(&mut out, "rust", &self.rust)?;
        let mut tools = self.tools.clone();
        tools.sort();
        out.push_str("\n[tools]\n");
        for (package, version) in &tools {
            check_key(package)?;
            writeln!(out, "{package} = {}", quote(version)?).ok();
        }
        let mut files: Vec<&File> = self.files.iter().collect();
        files.sort_by(|a, b| a.name.cmp(&b.name));
        for f in files {
            check_name(&f.name)?;
            check_sha256(&f.sha256)?;
            out.push_str("\n[[file]]\n");
            writeln!(out, "name = {}", quote(&f.name)?).ok();
            writeln!(out, "kind = {}", quote(f.kind.as_str())?).ok();
            writeln!(out, "sha256 = {}", quote(&f.sha256)?).ok();
            writeln!(out, "size = {}", f.size).ok();
            if !f.parts.is_empty() {
                // A node's parts keep the composition's order.
                let parts: Result<Vec<String>, Error> = f.parts.iter().map(|p| quote(p)).collect();
                writeln!(out, "parts = [{}]", parts?.join(", ")).ok();
            }
            for (key, list) in [("exports", &f.exports), ("imports", &f.imports)] {
                let mut list = list.clone();
                list.sort();
                if list.is_empty() {
                    writeln!(out, "{key} = []").ok();
                    continue;
                }
                writeln!(out, "{key} = [").ok();
                for item in &list {
                    writeln!(out, "  {},", quote(item)?).ok();
                }
                out.push_str("]\n");
            }
        }
        Ok(out)
    }

    /// The hashes as `SHA256SUMS` (`<sha256>  <name>` lines, sorted by name), the format
    /// `sha256sum -c` and [`parse_sums`] read.
    pub fn sha256sums(&self) -> String {
        let mut files: Vec<&File> = self.files.iter().collect();
        files.sort_by(|a, b| a.name.cmp(&b.name));
        files
            .iter()
            .map(|f| format!("{}  {}\n", f.sha256, f.name))
            .collect()
    }

    /// Reads a manifest. Keys it does not know are skipped (a later version of the format may
    /// add some); a different format is refused.
    pub fn parse(text: &str) -> Result<Manifest, Error> {
        let mut manifest = Manifest::new("");
        let mut format = None;
        let mut section = Section::Top;
        let mut lines = text.lines().enumerate().map(|(i, l)| (i + 1, l));
        while let Some((n, raw)) = lines.next() {
            let err = |message: String| Error::Parse { line: n, message };
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if line == "[tools]" {
                section = Section::Tools;
                continue;
            }
            if line == "[[file]]" {
                manifest.files.push(File::new("", Kind::Component, "", 0));
                section = Section::File;
                continue;
            }
            if line.starts_with('[') {
                section = Section::Unknown;
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| err(format!("`{line}` is not `key = value`")))?;
            let key = key.trim();
            let mut value = value.trim().to_owned();
            // A list may go on over several lines, up to its `]`.
            if value.starts_with('[') {
                while !strip_comment(&value).trim_end().ends_with(']') {
                    let (_, more) = lines
                        .next()
                        .ok_or_else(|| err(format!("`{key}`: the list has no `]`")))?;
                    value.push(' ');
                    value.push_str(strip_comment(more).trim());
                }
            }
            let value = Value::parse(&value).map_err(|m| err(format!("`{key}`: {m}")))?;
            match section {
                Section::Top => match key {
                    "format" => format = Some(value.string(key).map_err(err)?),
                    "revision" => manifest.revision = value.string(key).map_err(err)?,
                    "dirty" => manifest.dirty = value.bool(key).map_err(err)?,
                    "target" => manifest.target = value.string(key).map_err(err)?,
                    "host" => manifest.host = value.string(key).map_err(err)?,
                    "rust" => manifest.rust = value.string(key).map_err(err)?,
                    _ => {}
                },
                Section::Tools => manifest
                    .tools
                    .push((key.to_owned(), value.string(key).map_err(err)?)),
                Section::File => {
                    let f = manifest.files.last_mut().expect("in a [[file]]");
                    match key {
                        "name" => f.name = value.string(key).map_err(err)?,
                        "kind" => {
                            let kind = value.string(key).map_err(err)?;
                            f.kind = Kind::parse(&kind)
                                .ok_or_else(|| err(format!("unknown kind `{kind}`")))?;
                        }
                        "sha256" => f.sha256 = value.string(key).map_err(err)?,
                        "size" => f.size = value.int(key).map_err(err)?,
                        "parts" => f.parts = value.list(key).map_err(err)?,
                        "exports" => f.exports = value.list(key).map_err(err)?,
                        "imports" => f.imports = value.list(key).map_err(err)?,
                        _ => {}
                    }
                }
                Section::Unknown => {}
            }
        }
        match format.as_deref() {
            Some(FORMAT) => {}
            Some(other) => {
                return Err(Error::Invalid(format!(
                    "format `{other}`: this reader knows `{FORMAT}`"
                )));
            }
            None => return Err(Error::Invalid("no `format`: not a set's manifest".into())),
        }
        for f in &manifest.files {
            check_name(&f.name)?;
            check_sha256(&f.sha256)?;
        }
        manifest.tools.sort();
        manifest.files.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(manifest)
    }

    /// Checks the files of the manifest in `dir`: each is there, with its size and hash.
    /// Returns every problem found (none when the set is whole); files the manifest does not
    /// list are not looked at.
    pub fn check_dir(&self, dir: &Path) -> Vec<Error> {
        let mut problems = Vec::new();
        for f in &self.files {
            let path = dir.join(&f.name);
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    problems.push(io(&path)(e));
                    continue;
                }
            };
            if bytes.len() as u64 != f.size {
                problems.push(Error::Size {
                    name: f.name.clone(),
                    expected: f.size,
                    actual: bytes.len() as u64,
                });
            }
            if let Err(e) = f.pin().check(&bytes) {
                problems.push(e);
            }
        }
        problems
    }
}

/// `key = "value"` on a line of its own.
fn kv(out: &mut String, key: &str, value: &str) -> Result<(), Error> {
    writeln!(out, "{key} = {}", quote(value)?).ok();
    Ok(())
}

enum Section {
    Top,
    Tools,
    File,
    Unknown,
}

/// The text before a `#` that is outside a string.
fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_string = !in_string,
            '#' if !in_string => return &line[..i],
            _ => {}
        }
    }
    line
}

/// `s` as a TOML basic string. Strings that would need escapes are refused: nothing in a set
/// needs them, and the reader stays small.
fn quote(s: &str) -> Result<String, Error> {
    if s.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
        return Err(Error::Invalid(format!(
            "{s:?}: a manifest string cannot hold quotes, backslashes or control characters"
        )));
    }
    Ok(format!("\"{s}\""))
}

/// A bare TOML key.
fn check_key(key: &str) -> Result<(), Error> {
    if !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(Error::Invalid(format!("`{key}` is not a bare key")))
    }
}

enum Value {
    Str(String),
    Int(u64),
    Bool(bool),
    List(Vec<String>),
}

impl Value {
    fn parse(text: &str) -> Result<Value, String> {
        let text = strip_comment(text).trim();
        if let Some(inner) = text.strip_prefix('[') {
            let inner = inner
                .strip_suffix(']')
                .ok_or("a list ends with `]`")?
                .trim();
            let mut items = Vec::new();
            for item in inner.split(',').map(str::trim).filter(|i| !i.is_empty()) {
                match Value::parse(item)? {
                    Value::Str(s) => items.push(s),
                    _ => return Err(format!("`{item}`: lists hold strings")),
                }
            }
            return Ok(Value::List(items));
        }
        if let Some(inner) = text.strip_prefix('"') {
            let inner = inner.strip_suffix('"').ok_or("a string ends with `\"`")?;
            if inner.contains(['"', '\\']) {
                return Err("escapes are not supported".into());
            }
            return Ok(Value::Str(inner.to_owned()));
        }
        match text {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => text
                .parse()
                .map(Value::Int)
                .map_err(|_| format!("`{text}` is not a string, number, boolean or list")),
        }
    }

    fn string(self, key: &str) -> Result<String, String> {
        match self {
            Value::Str(s) => Ok(s),
            _ => Err(format!("`{key}` is a string")),
        }
    }

    fn int(self, key: &str) -> Result<u64, String> {
        match self {
            Value::Int(i) => Ok(i),
            _ => Err(format!("`{key}` is a number")),
        }
    }

    fn bool(self, key: &str) -> Result<bool, String> {
        match self {
            Value::Bool(b) => Ok(b),
            _ => Err(format!("`{key}` is true or false")),
        }
    }

    fn list(self, key: &str) -> Result<Vec<String>, String> {
        match self {
            Value::List(l) => Ok(l),
            _ => Err(format!("`{key}` is a list of strings")),
        }
    }
}

/// A file an embedder depends on: its name in a set and its SHA-256, pinned in the
/// embedder's own repository.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Pin {
    /// The file name (`netstack.wasm`).
    pub name: String,
    /// Its SHA-256, 64 lowercase hex digits.
    pub sha256: String,
}

impl Pin {
    /// A pin; refuses a name that is not a plain file name and a hash that is not a SHA-256.
    pub fn new(name: impl Into<String>, sha256: impl Into<String>) -> Result<Pin, Error> {
        let pin = Pin {
            name: name.into(),
            sha256: sha256.into(),
        };
        check_name(&pin.name)?;
        check_sha256(&pin.sha256)?;
        Ok(pin)
    }

    /// Checks `bytes` against the pin.
    pub fn check(&self, bytes: &[u8]) -> Result<(), Error> {
        let actual = sha256_hex(bytes);
        if actual == self.sha256 {
            Ok(())
        } else {
            Err(Error::Mismatch {
                name: self.name.clone(),
                expected: self.sha256.clone(),
                actual,
            })
        }
    }
}

/// Reads pins in the `SHA256SUMS` format: `<sha256>  <name>` (or `<sha256> *<name>`) per
/// line; blank lines and lines starting with `#` are skipped.
pub fn parse_sums(text: &str) -> Result<Vec<Pin>, Error> {
    let mut pins = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let err = |message: String| Error::Parse {
            line: i + 1,
            message,
        };
        let (hash, name) = line
            .split_once(' ')
            .ok_or_else(|| err(format!("`{line}` is not `<sha256>  <name>`")))?;
        let name = name.trim_start_matches([' ', '*']);
        pins.push(Pin::new(name, hash).map_err(|e| err(e.to_string()))?);
    }
    Ok(pins)
}

/// Where a set's files come from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source {
    /// A directory holding the files under their names: what `cargo xtask artifacts` writes,
    /// or a copy of it.
    Dir(PathBuf),
    /// An OCI registry repository (`ghcr.io`, `backkem/wasmnet/components`) that holds the files
    /// as blobs, named by their SHA-256: a pinned file is fetched by its hash, so no tag or
    /// registry manifest has to be trusted. Pulls are anonymous, with the token a registry
    /// such as `ghcr.io` gives at `https://<registry>/token` ([`oci`]).
    Oci {
        /// The registry's host name.
        registry: String,
        /// The repository in it.
        repository: String,
    },
}

impl Source {
    /// An OCI source.
    pub fn oci(registry: impl Into<String>, repository: impl Into<String>) -> Source {
        Source::Oci {
            registry: registry.into(),
            repository: repository.into(),
        }
    }
}

/// URLs and the token reply of the OCI distribution API, for anonymous pulls.
pub mod oci {
    /// The anonymous token for pulling from `repository`, as `ghcr.io` serves it. The reply is
    /// JSON with a `token` ([`token_from_json`]).
    pub fn token_url(registry: &str, repository: &str) -> String {
        format!("https://{registry}/token?scope=repository:{repository}:pull&service={registry}")
    }

    /// The blob with SHA-256 `sha256`.
    pub fn blob_url(registry: &str, repository: &str, sha256: &str) -> String {
        format!("https://{registry}/v2/{repository}/blobs/sha256:{sha256}")
    }

    /// The registry manifest of a tag (`reference`: a revision's commit hash) or digest, which
    /// lists the files of a set as layers. Only needed to learn the hashes of a revision one
    /// has not pinned yet.
    pub fn manifest_url(registry: &str, repository: &str, reference: &str) -> String {
        format!("https://{registry}/v2/{repository}/manifests/{reference}")
    }

    /// The `token` (or `access_token`) of a token reply.
    pub fn token_from_json(body: &str) -> Option<String> {
        ["\"token\"", "\"access_token\""].iter().find_map(|key| {
            let rest = &body[body.find(key)? + key.len()..];
            let rest = rest.trim_start().strip_prefix(':')?.trim_start();
            let rest = rest.strip_prefix('"')?;
            let token = &rest[..rest.find('"')?];
            (!token.is_empty() && !token.contains('\\')).then(|| token.to_owned())
        })
    }
}

/// A downloader for [`fetch_with`]: `get(url, bearer)` returns the body of an `https` GET with
/// `bearer` (if given) as the bearer token, or why it failed. [`curl`] is one.
pub type Downloader<'a> = dyn FnMut(&str, Option<&str>) -> Result<Vec<u8>, String> + 'a;

/// Downloads `url` with the `curl` program, with `bearer` as the bearer token if given; only
/// `https` is followed, redirects included.
pub fn curl(url: &str, bearer: Option<&str>) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--retry",
        "3",
    ]);
    if let Some(token) = bearer {
        cmd.arg("--header")
            .arg(format!("Authorization: Bearer {token}"));
    }
    let out = cmd
        .arg(url)
        .output()
        .map_err(|e| format!("running curl: {e}"))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// Gets the pinned files from `source` into the directory `into` with [`curl`] as the
/// downloader, and returns their paths in the order of `pins`. See [`fetch_with`].
pub fn fetch(source: &Source, pins: &[Pin], into: &Path) -> Result<Vec<PathBuf>, Error> {
    fetch_with(source, pins, into, &mut curl)
}

/// Gets the pinned files from `source` into the directory `into`, and returns their paths in
/// the order of `pins`.
///
/// A file already in `into` with the pinned hash is kept, so a second call reads and
/// downloads nothing. Every other file is read (from a [`Source::Dir`]) or downloaded (from a
/// [`Source::Oci`], with `get(url, bearer)`), checked against its pin, and only then written
/// under its name; a file that does not match is an error and leaves nothing behind.
pub fn fetch_with(
    source: &Source,
    pins: &[Pin],
    into: &Path,
    get: &mut Downloader<'_>,
) -> Result<Vec<PathBuf>, Error> {
    fs::create_dir_all(into).map_err(io(into))?;
    let mut token: Option<String> = None;
    let mut paths = Vec::with_capacity(pins.len());
    for pin in pins {
        check_name(&pin.name)?;
        check_sha256(&pin.sha256)?;
        let path = into.join(&pin.name);
        paths.push(path.clone());
        if fs::read(&path).is_ok_and(|bytes| pin.check(&bytes).is_ok()) {
            continue;
        }
        let bytes = match source {
            Source::Dir(dir) => {
                let from = dir.join(&pin.name);
                fs::read(&from).map_err(io(&from))?
            }
            Source::Oci {
                registry,
                repository,
            } => {
                if token.is_none() {
                    let url = oci::token_url(registry, repository);
                    let reply = get(&url, None).map_err(|message| Error::Download {
                        url: url.clone(),
                        message,
                    })?;
                    let reply = String::from_utf8_lossy(&reply);
                    token = Some(oci::token_from_json(&reply).ok_or_else(|| Error::Download {
                        url: url.clone(),
                        message: "the reply has no token".into(),
                    })?);
                }
                let url = oci::blob_url(registry, repository, &pin.sha256);
                get(&url, token.as_deref()).map_err(|message| Error::Download { url, message })?
            }
        };
        pin.check(&bytes)?;
        // Written beside its final name and renamed, so a reader never sees half a file.
        let partial = into.join(format!(".{}.partial", pin.name));
        fs::write(&partial, &bytes).map_err(io(&partial))?;
        fs::rename(&partial, &path).map_err(io(&path))?;
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    fn sample() -> Manifest {
        let mut m = Manifest::new("0123456789abcdef0123456789abcdef01234567");
        m.target = "wasm32-wasip2".into();
        m.host = "x86_64-unknown-linux-gnu".into();
        m.rust = "1.98.1".into();
        m.tools = vec![
            ("wasm-tools".into(), "1.261.0".into()),
            ("wac-cli".into(), "0.12.0".into()),
        ];
        let mut node = File::new("node-x.wasm", Kind::Node, "b".repeat(64), 20);
        node.parts = vec!["netstack".into(), "x".into()];
        node.exports = vec!["wasmnet:link/device@0.1.0".into(), "app-x".into()];
        let mut netstack = File::new("netstack.wasm", Kind::Component, HELLO, 5);
        netstack.exports = vec![
            "wasi:sockets/types@0.3.0".into(),
            "wasi:sockets/ip-name-lookup@0.3.0".into(),
        ];
        netstack.imports = vec!["wasmnet:link/wire@0.1.0".into()];
        m.files = vec![node, netstack];
        m
    }

    #[test]
    fn hashes_are_lowercase_hex() {
        assert_eq!(sha256_hex(b"hello"), HELLO);
    }

    #[test]
    fn a_manifest_reads_back_as_written() {
        let m = sample();
        let text = m.to_toml().unwrap();
        assert!(text.starts_with("format = \"wasmnet-artifacts/1\"\n"));
        // Sorted: files by name, tools by package, lists by value; parts keep their order.
        assert!(text.find("netstack.wasm").unwrap() < text.find("node-x.wasm").unwrap());
        assert!(text.find("wac-cli").unwrap() < text.find("wasm-tools").unwrap());
        assert!(text.contains("parts = [\"netstack\", \"x\"]"));
        let back = Manifest::parse(&text).unwrap();
        let mut expected = m.clone();
        expected.files.sort_by(|a, b| a.name.cmp(&b.name));
        expected.tools.sort();
        for f in &mut expected.files {
            f.exports.sort();
            f.imports.sort();
        }
        assert_eq!(back, expected);
        assert_eq!(
            back.to_toml().unwrap(),
            text,
            "the same set gives the same bytes"
        );
        assert_eq!(
            m.sha256sums(),
            format!("{HELLO}  netstack.wasm\n{}  node-x.wasm\n", "b".repeat(64))
        );
    }

    #[test]
    fn a_reader_skips_what_it_does_not_know_and_refuses_another_format() {
        let text = sample().to_toml().unwrap();
        let more = text.replace(
            "rust = \"1.98.1\"\n",
            "rust = \"1.98.1\"  # a comment\nlater = \"key\"\n[later-table]\nx = 1\n",
        );
        assert_eq!(
            Manifest::parse(&more).unwrap(),
            Manifest::parse(&text).unwrap()
        );
        let other = text.replace("wasmnet-artifacts/1", "wasmnet-artifacts/2");
        assert!(Manifest::parse(&other).is_err_and(|e| e.to_string().contains("/2")));
        assert!(Manifest::parse("revision = \"x\"\n").is_err());
        let bad_hash = text.replace(HELLO, "nothex");
        assert!(Manifest::parse(&bad_hash).is_err());
        let traversal = text.replace("\"netstack.wasm\"", "\"../netstack.wasm\"");
        assert!(Manifest::parse(&traversal).is_err());
        let open = "format = \"wasmnet-artifacts/1\"\n[[file]]\nexports = [\n  \"a\",\n";
        assert!(Manifest::parse(open).is_err_and(|e| matches!(e, Error::Parse { line: 3, .. })));
    }

    #[test]
    fn strings_that_need_escapes_are_refused() {
        let mut m = sample();
        m.revision = "a\"b".into();
        assert!(m.to_toml().is_err());
    }

    #[test]
    fn interfaces_are_checked_with_their_versions() {
        let m = sample();
        let netstack = m.file("netstack.wasm").unwrap();
        assert!(
            netstack
                .check_exports(&["wasi:sockets/types@0.3.0"])
                .is_ok()
        );
        let err = netstack
            .check_exports(&["wasi:sockets/types@0.3.1", "wasmnet:sockets-ext/tcp@0.1.0"])
            .unwrap_err();
        assert!(matches!(&err, Error::Interfaces { missing, .. } if missing.len() == 2));
        assert!(
            netstack
                .check_imports_within(&["wasmnet:link/wire@0.1.0"])
                .is_ok()
        );
        assert!(netstack.check_imports_within(&[]).is_err());
    }

    #[test]
    fn sums_are_read_like_sha256sum_does() {
        let text = format!("# pinned\n{HELLO}  netstack.wasm\n\n{HELLO} *switch.wasm\n");
        let pins = parse_sums(&text).unwrap();
        assert_eq!(
            pins,
            [
                Pin::new("netstack.wasm", HELLO).unwrap(),
                Pin::new("switch.wasm", HELLO).unwrap()
            ]
        );
        assert!(
            parse_sums("abc  x.wasm\n").is_err_and(|e| matches!(e, Error::Parse { line: 1, .. }))
        );
        assert!(parse_sums(&format!("{HELLO}  ../x.wasm\n")).is_err());
        assert!(parse_sums(&format!("{HELLO}  .hidden\n")).is_err());
        assert!(Pin::new("x.wasm", HELLO.to_uppercase()).is_err());
    }

    #[test]
    fn oci_urls_and_tokens() {
        assert_eq!(
            oci::token_url("ghcr.io", "o/r/c"),
            "https://ghcr.io/token?scope=repository:o/r/c:pull&service=ghcr.io"
        );
        assert_eq!(
            oci::blob_url("ghcr.io", "o/r/c", HELLO),
            format!("https://ghcr.io/v2/o/r/c/blobs/sha256:{HELLO}")
        );
        assert_eq!(
            oci::manifest_url("ghcr.io", "o/r/c", "abc"),
            "https://ghcr.io/v2/o/r/c/manifests/abc"
        );
        assert_eq!(
            oci::token_from_json(r#"{"token":"djE6"}"#).as_deref(),
            Some("djE6")
        );
        assert_eq!(
            oci::token_from_json(r#"{ "access_token" : "x", "expires_in": 300 }"#).as_deref(),
            Some("x")
        );
        assert_eq!(oci::token_from_json(r#"{"errors":[]}"#), None);
        assert_eq!(oci::token_from_json(r#"{"token":""}"#), None);
    }
}
