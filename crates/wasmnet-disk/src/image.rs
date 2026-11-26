//! The canonical image of a disk, format `wasmnet-disk/1`: what [`crate::Disks::export`] writes,
//! what [`crate::Disks::digest`] hashes (SHA-256 of the image) and what
//! [`crate::Disks::load`] and [`crate::DiskSpec::initial`] read.
//!
//! ```text
//! magic    "wasmnet-disk/1\n"                          15 bytes
//! entry    u32 key length, key (UTF-8), u64 value length, value      per entry, keys ascending
//! end      u32 0xFFFF_FFFF, u64 entries, u64 key and value bytes
//! ```
//!
//! Integers are big-endian. Keys are unique and strictly ascending by their bytes, at most
//! [`MAX_KEY`] bytes; values at most [`MAX_VALUE`]. The image
//! is written and hashed in one pass over the disk, entry by entry, without a copy of it, and
//! read the same way. Two disks with the same entries have the same image, whatever happened to
//! them, on every backend.

use std::io::{self, Write};

use crate::{MAX_KEY, MAX_VALUE};

/// The image's first bytes.
pub const MAGIC: &[u8] = b"wasmnet-disk/1\n";

const END: u32 = u32::MAX;

/// Why bytes are not a `wasmnet-disk/1` image.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a wasmnet-disk/1 image: {what} at byte {at}")]
pub struct ImageError {
    /// Where the reader stopped.
    pub at: usize,
    /// What was wrong there.
    pub what: String,
}

/// Writes the image of `entries` (ascending by key, as a disk holds them) to `out`, a piece at a
/// time.
pub fn write<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    out: &mut dyn FnMut(&[u8]),
) {
    out(MAGIC);
    let (mut count, mut bytes) = (0u64, 0u64);
    for (k, v) in entries {
        out(&(k.len() as u32).to_be_bytes());
        out(k.as_bytes());
        out(&(v.len() as u64).to_be_bytes());
        out(v);
        count += 1;
        bytes += (k.len() + v.len()) as u64;
    }
    out(&END.to_be_bytes());
    out(&count.to_be_bytes());
    out(&bytes.to_be_bytes());
}

/// [`write()`] into an [`io::Write`] (a file, a socket), stopping at its first error.
pub fn write_to<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    w: &mut dyn Write,
) -> io::Result<()> {
    let mut result = Ok(());
    write(entries, &mut |b| {
        if result.is_ok() {
            result = w.write_all(b);
        }
    });
    result
}

/// The entries of an image, in order, read in one pass and checked as they come; after the
/// last one the reader checks the end record (counts, nothing after it). Borrows the image's
/// bytes: no entry is copied until the caller copies it.
pub struct Entries<'a> {
    bytes: &'a [u8],
    at: usize,
    count: u64,
    total: u64,
    last: Option<&'a str>,
    done: bool,
}

/// Reads `bytes` as an image.
pub fn read(bytes: &[u8]) -> Result<Entries<'_>, ImageError> {
    if !bytes.starts_with(MAGIC) {
        return Err(ImageError {
            at: 0,
            what: "no magic line".to_owned(),
        });
    }
    Ok(Entries {
        bytes,
        at: MAGIC.len(),
        count: 0,
        total: 0,
        last: None,
        done: false,
    })
}

impl<'a> Entries<'a> {
    fn fail<T>(&mut self, what: impl Into<String>) -> Option<Result<T, ImageError>> {
        self.done = true;
        Some(Err(ImageError {
            at: self.at,
            what: what.into(),
        }))
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes(b.try_into().expect("four bytes")))
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_be_bytes(b.try_into().expect("eight bytes")))
    }
}

impl<'a> Iterator for Entries<'a> {
    type Item = Result<(&'a str, &'a [u8]), ImageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let Some(klen) = self.u32() else {
            return self.fail("no end record");
        };
        if klen == END {
            let (Some(count), Some(total)) = (self.u64(), self.u64()) else {
                return self.fail("a short end record");
            };
            if count != self.count || total != self.total {
                return self.fail(format!(
                    "the end record says {count} entries and {total} bytes, the image has {} and {}",
                    self.count, self.total
                ));
            }
            if self.at != self.bytes.len() {
                return self.fail("bytes after the end record");
            }
            self.done = true;
            return None;
        }
        if klen as usize > MAX_KEY {
            return self.fail(format!("a key of {klen} bytes (at most {MAX_KEY})"));
        }
        let Some(kb) = self.take(klen as usize) else {
            return self.fail("a short key");
        };
        let Ok(key) = std::str::from_utf8(kb) else {
            return self.fail("a key that is not UTF-8");
        };
        if self.last.is_some_and(|l| l >= key) {
            return self.fail(format!("key `{key}` out of order"));
        }
        let Some(vlen) = self.u64() else {
            return self.fail("a short value length");
        };
        if vlen > MAX_VALUE as u64 {
            return self.fail(format!("a value of {vlen} bytes (at most {MAX_VALUE})"));
        }
        let Some(value) = self.take(vlen as usize) else {
            return self.fail("a short value");
        };
        self.last = Some(key);
        self.count += 1;
        self.total += u64::from(klen) + vlen;
        Some(Ok((key, value)))
    }
}

/// Every entry of an image, checked, as owned pairs.
pub fn entries(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ImageError> {
    read(bytes)?
        .map(|e| e.map(|(k, v)| (k.to_owned(), v.to_vec())))
        .collect()
}

/// The image of owned pairs (ascending and unique by key, as [`entries`] gives them).
pub fn of(pairs: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    write(
        pairs.iter().map(|(k, v)| (k.as_str(), v.as_slice())),
        &mut |b| out.extend_from_slice(b),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_image_round_trips_and_is_checked() {
        let pairs = vec![
            ("a".to_owned(), b"1".to_vec()),
            ("b/c".to_owned(), Vec::new()),
        ];
        let img = of(&pairs);
        assert!(img.starts_with(MAGIC));
        assert_eq!(entries(&img).unwrap(), pairs);
        assert_eq!(entries(&of(&[])).unwrap(), Vec::new());
        // Out of order, truncated, trailing bytes, wrong counts.
        let bad = of(&[("b".to_owned(), vec![]), ("a".to_owned(), vec![])]);
        assert!(entries(&bad).unwrap_err().what.contains("out of order"));
        assert!(entries(&img[..img.len() - 1]).is_err());
        let mut long = img.clone();
        long.push(0);
        assert!(entries(&long).unwrap_err().what.contains("after the end"));
        let mut wrong = img.clone();
        let n = wrong.len();
        wrong[n - 9] ^= 1;
        assert!(
            entries(&wrong)
                .unwrap_err()
                .what
                .contains("end record says")
        );
        assert!(read(b"wasmnet-disk/0\n").is_err());
    }
}
