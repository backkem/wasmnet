//! A precompiled-component cache on disk.
//!
//! Compiling a composed node (about 1 MiB of Wasm) with Cranelift costs seconds in a debug build
//! of the host and dominates a network run. The cache stores what `Component::serialize`
//! produces under `<dir>/<content>-<engine>.cwasm`:
//!
//! * `<content>`: the SHA-256 of the component's bytes (the first 32 hex digits);
//! * `<engine>`: a hash of [`Engine::precompile_compatibility_hash`] (wasmtime's version and
//!   every compilation-relevant setting, such as fuel metering), so a different engine never
//!   picks up a stale artifact.
//!
//! The content key of a component file is remembered by path, length and modification time (in
//! the process, and in `<dir>/keys/` across processes), so a hit for an unchanged file neither
//! reads nor hashes it: hashing a large component (hundreds of MB) cost 1-4% of a run's wall
//! time. A rebuilt file has a new stamp and is hashed again.
//!
//! A hit loads the native code with `Component::deserialize_file`; a miss (or an unreadable
//! artifact) compiles and writes it (to a temporary name, then renamed, so a concurrent reader
//! never sees half a file). The directory stays within its budget ([`MAX_CACHE_BYTES`] unless
//! [`CompileCache::with_budget`] says otherwise): after a write, the least recently used
//! artifacts (by modification time, refreshed on every hit) are deleted.
//!
//! **Where it lives is the caller's choice**: nothing is cached unless the host is given a
//! directory. [`default_cache_dir`] is the platform's per-user cache directory. Several
//! processes may share one directory: a compile holds `<artifact>.cwasm.lock`, so a second
//! process that wants the same artifact waits for it instead of compiling it again, and pruning
//! holds `prune.lock`. A lock older than two hours is a crashed holder's and is taken over.
//!
//! **Determinism is unaffected**: Cranelift's output is a pure function of the input and the
//! engine config, so a deserialized component runs the same machine code, consumes the same
//! fuel and produces the same frames as a freshly compiled one.

use std::collections::BTreeMap;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use wasmtime::Engine;
use wasmtime::component::Component;

use crate::Result;

/// How the cache was used so far (wall-clock numbers are for humans only, never in a
/// simulation's output).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Components loaded from a precompiled artifact.
    pub hits: u64,
    /// Components compiled (and then stored).
    pub misses: u64,
    /// Wall time spent loading or compiling components.
    pub load_time: Duration,
}

/// The cache directory and its counters: precompiled components on disk, keyed by component
/// bytes and engine configuration. Public so other engines an embedder runs share the same
/// directory.
#[derive(Debug)]
pub struct CompileCache {
    dir: PathBuf,
    /// Bytes the directory may hold before least recently used artifacts go.
    budget: u64,
    hits: AtomicU64,
    misses: AtomicU64,
    nanos: AtomicU64,
    /// Content keys of component files by path, with the stamp they were computed for.
    known: Mutex<BTreeMap<PathBuf, (Stamp, String)>>,
}

/// What tells a component file's bytes apart without reading them: its length and its
/// modification time (nanoseconds since the epoch). Builds write new files, so a changed
/// component has a new stamp; a stamp seen before maps to the content key computed then.
type Stamp = (u64, u128);

fn stamp(path: &Path) -> Option<Stamp> {
    let meta = fs::metadata(path).ok()?;
    let at = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some((meta.len(), at.as_nanos()))
}

/// The content part of a cache key: the first 32 hex digits of the bytes' SHA-256.
fn content_key(bytes: &[u8]) -> String {
    Sha256::digest(bytes)[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The engine part of a cache key.
fn engine_key(engine: &Engine) -> String {
    let mut h = DefaultHasher::new();
    engine.precompile_compatibility_hash().hash(&mut h);
    format!("{:016x}", h.finish())
}

impl CompileCache {
    /// A cache in `dir` (created on first use) with the default budget, [`MAX_CACHE_BYTES`].
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            budget: MAX_CACHE_BYTES,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            nanos: AtomicU64::new(0),
            known: Mutex::new(BTreeMap::new()),
        }
    }

    /// The same cache with a size budget of `bytes` (see [`prune_dir`] for how it is kept).
    pub fn with_budget(mut self, bytes: u64) -> Self {
        self.budget = bytes;
        self
    }

    /// The cache's directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The cache's size budget in bytes.
    pub fn budget(&self) -> u64 {
        self.budget
    }

    /// Where the content key of the component at `path` is remembered across processes:
    /// `<dir>/keys/<first 32 hex digits of the path's SHA-256>`, holding `len mtime key path`.
    fn key_file(&self, path: &Path) -> PathBuf {
        let name = content_key(path.as_os_str().as_encoded_bytes());
        self.dir.join("keys").join(name)
    }

    /// The content key remembered for `path` at `stamp`, if any (this process's, else the
    /// cache directory's).
    fn remembered(&self, path: &Path, stamp: Stamp) -> Option<String> {
        if let Ok(known) = self.known.lock()
            && let Some((s, key)) = known.get(path)
            && *s == stamp
        {
            return Some(key.clone());
        }
        let text = fs::read_to_string(self.key_file(path)).ok()?;
        let mut f = text.split_whitespace();
        let len: u64 = f.next()?.parse().ok()?;
        let at: u128 = f.next()?.parse().ok()?;
        let key = f.next()?;
        if (len, at) != stamp || key.len() != 32 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        if let Ok(mut known) = self.known.lock() {
            known.insert(path.to_path_buf(), (stamp, key.to_owned()));
        }
        Some(key.to_owned())
    }

    /// Remembers `key` as the content key of `path` at `stamp` (a cache that cannot be written
    /// is only slower: errors are ignored).
    fn remember(&self, path: &Path, stamp: Stamp, key: &str) {
        if let Ok(mut known) = self.known.lock() {
            known.insert(path.to_path_buf(), (stamp, key.to_owned()));
        }
        let file = self.key_file(path);
        let text = format!("{} {} {key} {}\n", stamp.0, stamp.1, path.display());
        if let Some(dir) = file.parent()
            && fs::create_dir_all(dir).is_ok()
        {
            let tmp = file.with_extension(format!("tmp{}", std::process::id()));
            if fs::write(&tmp, text).is_ok() && fs::rename(&tmp, &file).is_err() {
                let _ = fs::remove_file(&tmp);
            }
        }
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            load_time: Duration::from_nanos(self.nanos.load(Ordering::Relaxed)),
        }
    }

    /// The artifact path for a component with content key `content`.
    fn artifact(&self, engine: &Engine, content: &str) -> PathBuf {
        self.dir
            .join(format!("{content}-{}.cwasm", engine_key(engine)))
    }

    /// Loads `path`, from the cache when possible. A component whose content key is remembered
    /// for its current stamp and whose artifact exists is neither read nor hashed (a large
    /// component can be hundreds of MB).
    pub fn load(&self, engine: &Engine, path: &Path) -> Result<Component> {
        let start = Instant::now();
        let stamp = stamp(path);
        if let Some(content) = stamp.and_then(|s| self.remembered(path, s))
            && let Some(c) = deserialize(engine, &self.artifact(engine, &content))
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            touch(&self.artifact(engine, &content));
            self.nanos
                .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
            return Ok(c);
        }
        let bytes = fs::read(path).map_err(|e| {
            crate::runtime_error(wasmtime::format_err!("reading {}: {e}", path.display()))
        })?;
        let content = content_key(&bytes);
        if let Some(s) = stamp {
            self.remember(path, s, &content);
        }
        let artifact = self.artifact(engine, &content);
        self.through(engine, &artifact, &bytes, start)
    }

    /// Loads the component `bytes` from the cache when possible, else compiles and stores it:
    /// for bytes that come from no file (a component a controller supplied). The artifact is
    /// named by the bytes' full SHA-256 (64 hex digits, unlike a file's 32), computed here, and
    /// the engine's key: whoever chooses the bytes chooses only the artifact of those bytes.
    pub fn load_bytes(&self, engine: &Engine, bytes: &[u8]) -> Result<Component> {
        let start = Instant::now();
        let content: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let artifact = self.artifact(engine, &content);
        self.through(engine, &artifact, bytes, start)
    }

    /// `artifact` if it loads, else `bytes` compiled (once across processes) and stored there.
    fn through(
        &self,
        engine: &Engine,
        artifact: &Path,
        bytes: &[u8],
        start: Instant,
    ) -> Result<Component> {
        let artifact = artifact.to_path_buf();
        let component = match deserialize(engine, &artifact) {
            Some(c) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                touch(&artifact);
                c
            }
            None => {
                // One compile per artifact across processes: wait for another's, or hold the
                // artifact's lock while compiling. (A cache that cannot be locked or written is
                // only slower: errors are ignored.)
                let lock = FileLock::take(&artifact.with_extension("cwasm.lock"), || {
                    artifact.is_file()
                });
                match deserialize(engine, &artifact) {
                    Some(c) => {
                        self.hits.fetch_add(1, Ordering::Relaxed);
                        touch(&artifact);
                        c
                    }
                    None => {
                        let c =
                            Component::from_binary(engine, bytes).map_err(crate::runtime_error)?;
                        self.misses.fetch_add(1, Ordering::Relaxed);
                        if let Ok(serialized) = c.serialize()
                            && store(&artifact, &serialized).is_ok()
                        {
                            drop(lock);
                            if let Some(_prune) = FileLock::try_take(&self.dir.join("prune.lock")) {
                                prune(&self.dir, self.budget, &artifact);
                            }
                        }
                        c
                    }
                }
            }
        };
        self.nanos
            .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        Ok(component)
    }
}

/// The cache's default size budget: past it, the least recently used artifacts go. A composed
/// node compiles to about 5 MiB, but a component with a whole guest system compiled in is far
/// bigger (from tens of MiB to 1 GiB), and one test run may load many of them: the budget
/// holds all of them at once, and a few generations of the small ones. The budget also
/// grows to `LARGEST_KEPT` times the largest artifact: a fresh big artifact never pushes out
/// the one generation before it, nor itself.
pub const MAX_CACHE_BYTES: u64 = 8 << 30;

/// The platform's per-user cache directory for compiled components, or `None` when the
/// environment does not name one:
///
/// * Windows: `%LOCALAPPDATA%\wasmnet\compile-cache`;
/// * macOS: `$HOME/Library/Caches/wasmnet/compile-cache`;
/// * elsewhere: `$XDG_CACHE_HOME/wasmnet/compile-cache`, or `$HOME/.cache/wasmnet/compile-cache`.
///
/// The host never caches unless asked: `Host::new()?.with_cache_dir(dir)` with this (or any
/// other) directory turns the cache on.
pub fn default_cache_dir() -> Option<PathBuf> {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let base = if cfg!(windows) {
        var("LOCALAPPDATA")?
    } else if cfg!(target_os = "macos") {
        var("HOME")?.join("Library").join("Caches")
    } else {
        var("XDG_CACHE_HOME").or_else(|| var("HOME").map(|h| h.join(".cache")))?
    };
    Some(base.join("wasmnet").join("compile-cache"))
}

/// Prunes `dir` to `budget` bytes now (least recently used first; skipped while another
/// process prunes); returns the artifacts and bytes left.
pub fn prune_dir(dir: &Path, budget: u64) -> (usize, u64) {
    if let Some(_lock) = FileLock::try_take(&dir.join("prune.lock")) {
        prune(dir, budget, Path::new(""));
    }
    artifacts(dir)
        .iter()
        .fold((0, 0), |(n, b), (_, len, _)| (n + 1, b + len))
}

/// A lock file (`create_new`, removed on drop). One older than [`STALE_LOCK`] is a crashed
/// holder's and is taken over.
struct FileLock(PathBuf);

const STALE_LOCK: Duration = Duration::from_secs(2 * 3600);

/// What a lock file says about its holder: `pid <pid> host <host>`.
fn lock_owner() -> String {
    format!("pid {} host {}", std::process::id(), host_name())
}

/// This machine's name: a PID only means something on its own host (and containers are
/// hosts of their own).
fn host_name() -> String {
    let name = if cfg!(windows) {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    } else {
        fs::read_to_string("/proc/sys/kernel/hostname")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_default()
    };
    name.trim().to_owned()
}

/// `true` if the lock file at `path` names a holder on this host whose process no longer runs.
/// A lock without a host (or empty: an older one) counts as this host's when it names a PID;
/// another host's, or a process this platform cannot look up, is not known to be gone.
fn lock_holder_gone(path: &Path) -> bool {
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    let mut words = text.split_whitespace();
    let (mut pid, mut host) = (None, None);
    while let Some(w) = words.next() {
        match w {
            "pid" => pid = words.next().and_then(|p| p.parse::<u32>().ok()),
            "host" => host = words.next(),
            _ => {}
        }
    }
    let Some(pid) = pid else {
        return false;
    };
    if host.is_some_and(|h| h != host_name()) || pid == std::process::id() {
        return false;
    }
    process_runs(pid) == Some(false)
}

/// Whether process `pid` runs on this host: `None` if this platform cannot tell.
fn process_runs(pid: u32) -> Option<bool> {
    if cfg!(target_os = "linux") {
        return Some(Path::new("/proc").join(pid.to_string()).exists());
    }
    if cfg!(windows) {
        let out = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .ok()?;
        return out
            .status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).contains(&format!("\"{pid}\"")));
    }
    None
}

impl FileLock {
    fn create(path: &Path) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        use std::io::Write;
        let _ = writeln!(f, "{}", lock_owner());
        Ok(Self(path.to_path_buf()))
    }

    /// A lock older than [`STALE_LOCK`], or one whose holder's process no longer runs on this
    /// host (a killed holder: stale at once).
    fn stale(path: &Path) -> bool {
        fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > STALE_LOCK)
            || lock_holder_gone(path)
    }

    /// Takes the lock without waiting, if it is free (or stale).
    fn try_take(path: &Path) -> Option<Self> {
        match Self::create(path) {
            Ok(l) => Some(l),
            Err(_) if Self::stale(path) => {
                let _ = fs::remove_file(path);
                Self::create(path).ok()
            }
            Err(_) => None,
        }
    }

    /// Takes the lock, waiting while another process holds it; returns `None` without the lock
    /// once `done()` says the holder's work is there, or if the lock cannot be made at all.
    fn take(path: &Path, done: impl Fn() -> bool) -> Option<Self> {
        loop {
            match Self::create(path) {
                Ok(l) => return Some(l),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if done() {
                        return None;
                    }
                    if Self::stale(path) {
                        let _ = fs::remove_file(path);
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
                Err(_) => return None,
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
/// How many of the largest artifact the budget always has room for.
pub const LARGEST_KEPT: u64 = 2;

/// Marks an artifact as just used (its modification time orders eviction).
fn touch(path: &Path) {
    if let Ok(f) = fs::File::options().append(true).open(path) {
        let _ = f.set_modified(std::time::SystemTime::now());
    }
}

/// Deletes the least recently used artifacts until the directory fits in `budget` bytes, or
/// in `LARGEST_KEPT` times its largest artifact if that is more. `keep` (the artifact just
/// written) is never deleted.
fn prune(dir: &Path, budget: u64, keep: &Path) {
    let mut files = artifacts(dir);
    let mut total: u64 = files.iter().map(|(_, len, _)| len).sum();
    let largest = files.iter().map(|(_, len, _)| *len).max().unwrap_or(0);
    let budget = budget.max(largest.saturating_mul(LARGEST_KEPT));
    files.sort();
    for (_, len, path) in files {
        if total <= budget {
            break;
        }
        // (A file another process has mapped may refuse to go on Windows: it stays.)
        if path != keep && fs::remove_file(&path).is_ok() {
            total -= len;
        }
    }
}

/// The artifacts in `dir`: (last use, bytes, path).
fn artifacts(dir: &Path) -> Vec<(std::time::SystemTime, u64, PathBuf)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| {
            let e = e.ok()?;
            let meta = e.metadata().ok()?;
            let path = e.path();
            (path.extension()? == "cwasm").then_some((meta.modified().ok()?, meta.len(), path))
        })
        .collect()
}

/// Writes `bytes` to `path` atomically (a temporary file, then a rename).
fn store(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("cwasm.tmp{}", std::process::id()));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Loads a precompiled artifact, if there is a usable one.
#[allow(unsafe_code)]
fn deserialize(engine: &Engine, artifact: &Path) -> Option<Component> {
    if !artifact.is_file() {
        return None;
    }
    // SAFETY: `deserialize_file` trusts the file to be native code that `Component::serialize`
    // produced. Only `CompileCache::load` writes into the cache directory (a per-user directory
    // the embedder chose), always the output of `serialize` for an engine with the same
    // compatibility hash (part of the file name), and wasmtime checks the artifact's own
    // version and configuration header before using it. A corrupt file fails that check and is
    // recompiled.
    match unsafe { Component::deserialize_file(engine, artifact) } {
        Ok(c) => Some(c),
        Err(_) => {
            let _ = fs::remove_file(artifact);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_keeps_the_newest_artifacts_within_the_budget() {
        let dir = std::env::temp_dir().join(format!("wasmnet-cache-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let t0 = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        for (i, name) in ["old", "mid", "new"].iter().enumerate() {
            let path = dir.join(format!("{name}.cwasm"));
            fs::write(&path, [0u8; 100]).unwrap();
            let f = fs::File::options().append(true).open(&path).unwrap();
            f.set_modified(t0 + Duration::from_secs(i as u64)).unwrap();
        }
        fs::write(dir.join("other.txt"), [0u8; 1000]).unwrap();
        let left = || {
            let mut names: Vec<String> = fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        prune(&dir, 250, &dir.join("new.cwasm"));
        assert_eq!(left(), ["mid.cwasm", "new.cwasm", "other.txt"]);
        // The artifact just written is never evicted, even when it is the oldest.
        let newer = dir.join("newer.cwasm");
        fs::write(&newer, [0u8; 100]).unwrap();
        let f = fs::File::options().append(true).open(&newer).unwrap();
        f.set_modified(t0 + Duration::from_secs(3)).unwrap();
        prune(&dir, 150, &dir.join("mid.cwasm"));
        assert_eq!(left(), ["mid.cwasm", "newer.cwasm", "other.txt"]);
        // A big artifact raises the budget to twice its size: it never evicts its predecessor.
        let big = dir.join("big.cwasm");
        fs::write(&big, [0u8; 400]).unwrap();
        prune(&dir, 150, &big);
        assert_eq!(
            left(),
            ["big.cwasm", "mid.cwasm", "newer.cwasm", "other.txt"]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn budgets_and_the_default_directory() {
        assert_eq!(CompileCache::new("unused").budget(), MAX_CACHE_BYTES);
        assert_eq!(CompileCache::new("unused").with_budget(1000).budget(), 1000);
        if let Some(dir) = default_cache_dir() {
            assert!(
                dir.ends_with(Path::new("wasmnet").join("compile-cache")),
                "{dir:?}"
            );
            assert!(dir.is_absolute(), "{dir:?}");
        }
    }

    #[test]
    fn a_lock_is_exclusive_until_dropped() {
        let path = std::env::temp_dir().join(format!("wasmnet-lock-test-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let a = FileLock::try_take(&path).expect("free");
        assert!(FileLock::try_take(&path).is_none());
        // A waiter returns without the lock once the holder's work is done.
        assert!(FileLock::take(&path, || true).is_none());
        drop(a);
        assert!(FileLock::try_take(&path).is_some());
        assert!(!path.exists());
    }

    /// A lock whose holder's process has exited is stale at once (a killed compile no longer
    /// blocks the artifact for two hours); a live holder's or another host's is not.
    #[test]
    fn a_lock_of_a_dead_process_is_stale() {
        let path = std::env::temp_dir().join(format!("wasmnet-dead-lock-{}", std::process::id()));
        let mut child = std::process::Command::new("git")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let gone = child.id();
        child.wait().unwrap();
        fs::write(&path, format!("pid {gone} host {}\n", host_name())).unwrap();
        assert!(FileLock::stale(&path));
        let taken = FileLock::try_take(&path).expect("a dead holder's lock is taken over");
        assert!(!FileLock::stale(&path), "this process holds it now");
        drop(taken);
        fs::write(&path, format!("pid {gone} host another-machine\n")).unwrap();
        assert!(!FileLock::stale(&path));
        assert!(FileLock::try_take(&path).is_none());
        fs::write(&path, "").unwrap();
        assert!(
            !FileLock::stale(&path),
            "an empty (older) lock waits for its age"
        );
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn keys_depend_on_bytes_and_engine() {
        let engine = Engine::default();
        let cache = CompileCache::new("unused");
        let a = cache.artifact(&engine, &content_key(b"one"));
        let b = cache.artifact(&engine, &content_key(b"two"));
        assert_ne!(a, b);
        assert_eq!(a, cache.artifact(&engine, &content_key(b"one")));
        let mut fuel = wasmtime::Config::new();
        fuel.consume_fuel(true);
        let other = Engine::new(&fuel).unwrap();
        assert_ne!(a, cache.artifact(&other, &content_key(b"one")));
        let name = a.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.ends_with(".cwasm") && name.len() == 32 + 1 + 16 + 6,
            "{name}"
        );
    }

    /// Bytes without a file (a supplied component) are compiled once and then loaded, under
    /// their full SHA-256: other bytes never get their artifact.
    #[test]
    fn bytes_are_cached_by_their_full_digest() {
        let dir = std::env::temp_dir().join(format!("wasmnet-bytes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        let engine = Engine::new(&config).unwrap();
        let cache = CompileCache::new(&dir);
        // The smallest component: its header, no sections.
        let empty = b"\0asm\x0d\0\x01\0";
        cache.load_bytes(&engine, empty).expect("compiles");
        cache.load_bytes(&engine, empty).expect("loads");
        let stats = cache.stats();
        assert_eq!((stats.misses, stats.hits), (1, 1));
        let names: Vec<String> = artifacts(&dir)
            .into_iter()
            .map(|(_, _, p)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        let full: String = Sha256::digest(empty)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(names, [format!("{full}-{}.cwasm", engine_key(&engine))]);
        assert!(cache.load_bytes(&engine, b"not a component").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A component's content key is remembered by path and stamp, in this process and in the
    /// cache directory; a new stamp (a rebuilt file) is never served the old key.
    #[test]
    fn content_keys_are_remembered_by_stamp() {
        let dir = std::env::temp_dir().join(format!("wasmnet-keys-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("node.wasm");
        fs::write(&file, b"first").unwrap();
        let s1 = stamp(&file).unwrap();
        let cache = CompileCache::new(dir.join("cache"));
        assert_eq!(cache.remembered(&file, s1), None);
        cache.remember(&file, s1, &content_key(b"first"));
        assert_eq!(cache.remembered(&file, s1), Some(content_key(b"first")));
        // Another process: from the key file.
        let fresh = CompileCache::new(dir.join("cache"));
        assert_eq!(fresh.remembered(&file, s1), Some(content_key(b"first")));
        // Rebuilt with the same length: a new stamp, nothing remembered for it.
        fs::write(&file, b"secnd").unwrap();
        let later = std::time::SystemTime::now() + Duration::from_secs(5);
        fs::File::options()
            .append(true)
            .open(&file)
            .unwrap()
            .set_modified(later)
            .unwrap();
        let s2 = stamp(&file).unwrap();
        assert_ne!(s1, s2);
        assert_eq!(fresh.remembered(&file, s2), None);
        // A damaged key file is ignored.
        fs::write(fresh.key_file(&file), "5 x zz").unwrap();
        assert_eq!(
            CompileCache::new(dir.join("cache")).remembered(&file, s1),
            None
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
