//! Fetching a pinned set: from a directory, and from an OCI registry through a stand-in
//! downloader that answers as `ghcr.io` does.

use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;

use wasmnet_artifacts::{Error, File, Kind, Manifest, Pin, Source, fetch, fetch_with, sha256_hex};

/// A fresh directory for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("artifacts-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A set of two files in `dir`, as `cargo xtask artifacts` would write it.
fn set(dir: &std::path::Path) -> Manifest {
    let mut m = Manifest::new("0123456789abcdef0123456789abcdef01234567");
    for (name, bytes) in [
        ("netstack.wasm", &b"\0asm netstack"[..]),
        ("switch.wasm", b"\0asm switch"),
    ] {
        fs::write(dir.join(name), bytes).unwrap();
        m.files.push(File::new(
            name,
            Kind::Component,
            sha256_hex(bytes),
            bytes.len() as u64,
        ));
    }
    fs::write(dir.join("manifest.toml"), m.to_toml().unwrap()).unwrap();
    fs::write(dir.join("SHA256SUMS"), m.sha256sums()).unwrap();
    m
}

#[test]
fn from_a_directory() {
    let (src, out) = (scratch("dir-src"), scratch("dir-out"));
    let m = set(&src);
    assert!(m.check_dir(&src).is_empty());

    let pins = wasmnet_artifacts::parse_sums(&fs::read_to_string(src.join("SHA256SUMS")).unwrap())
        .unwrap();
    let paths = fetch(&Source::Dir(src.clone()), &pins, &out).unwrap();
    assert_eq!(paths, [out.join("netstack.wasm"), out.join("switch.wasm")]);
    assert!(m.check_dir(&out).is_empty());

    // A file that differs from its pin is refused, and nothing is written under its name.
    fs::write(src.join("switch.wasm"), b"\0asm tampered").unwrap();
    fs::remove_file(out.join("switch.wasm")).unwrap();
    let err = fetch(&Source::Dir(src.clone()), &pins, &out).unwrap_err();
    assert!(
        matches!(err, Error::Mismatch { ref name, .. } if name == "switch.wasm"),
        "{err}"
    );
    assert!(!out.join("switch.wasm").exists());
    let problems = m.check_dir(&src);
    assert_eq!(problems.len(), 2, "size and hash: {problems:?}");
}

#[test]
fn from_an_oci_registry() {
    let out = scratch("oci-out");
    let netstack = b"\0asm netstack".to_vec();
    let pin = Pin::new("netstack.wasm", sha256_hex(&netstack)).unwrap();
    let asked = RefCell::new(Vec::new());
    let mut registry = |url: &str, bearer: Option<&str>| -> Result<Vec<u8>, String> {
        asked
            .borrow_mut()
            .push((url.to_owned(), bearer.map(str::to_owned)));
        if url.starts_with("https://ghcr.io/token?") {
            return Ok(br#"{"token":"anon"}"#.to_vec());
        }
        match (
            url.strip_prefix("https://ghcr.io/v2/o/r/blobs/sha256:"),
            bearer,
        ) {
            (Some(hash), Some("anon")) if hash == pin.sha256 => Ok(netstack.clone()),
            (Some(_), Some("anon")) => Err("404".into()),
            _ => Err("401".into()),
        }
    };
    let source = Source::oci("ghcr.io", "o/r");
    let paths = fetch_with(&source, std::slice::from_ref(&pin), &out, &mut registry).unwrap();
    assert_eq!(fs::read(&paths[0]).unwrap(), netstack);
    assert_eq!(
        *asked.borrow(),
        [
            (
                "https://ghcr.io/token?scope=repository:o/r:pull&service=ghcr.io".to_owned(),
                None
            ),
            (
                format!("https://ghcr.io/v2/o/r/blobs/sha256:{}", pin.sha256),
                Some("anon".to_owned())
            ),
        ]
    );

    // Already there with the pinned hash: nothing is downloaded.
    asked.borrow_mut().clear();
    fetch_with(&source, std::slice::from_ref(&pin), &out, &mut registry).unwrap();
    assert!(asked.borrow().is_empty());

    // A registry that serves other bytes under the digest is caught.
    let other = Pin::new("other.wasm", sha256_hex(b"other")).unwrap();
    let mut lying = |url: &str, _: Option<&str>| -> Result<Vec<u8>, String> {
        Ok(if url.contains("/token?") {
            br#"{"token":"t"}"#.to_vec()
        } else {
            b"evil".to_vec()
        })
    };
    let err = fetch_with(&source, &[other], &out, &mut lying).unwrap_err();
    assert!(matches!(err, Error::Mismatch { .. }), "{err}");
    assert!(!out.join("other.wasm").exists());

    // A download error names the URL.
    let missing = Pin::new("gone.wasm", sha256_hex(b"gone")).unwrap();
    let err = fetch_with(&source, &[missing], &out, &mut registry).unwrap_err();
    assert!(
        err.to_string().contains("/blobs/sha256:") && err.to_string().contains("404"),
        "{err}"
    );
}
