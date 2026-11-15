//! Deterministic CBOR: unsigned and negative integers, byte and text strings, arrays, maps,
//! booleans and null, in the deterministic encoding of RFC 8949 §4.2 (shortest heads, definite
//! lengths, map keys sorted by their encoded bytes). [`decode`] accepts exactly that encoding and
//! nothing else (no indefinite lengths, tags or floats), so every value has one byte form.
//!
//! `no_std`, no dependencies. wasmnet uses it for the device specs of its infrastructure API
//! (`wasmnet:infra`). [`build`] writes values straight to bytes, and [`write_head`] and
//! [`write_map`] are the primitives a fuller CBOR profile can build on.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// A decoded value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    /// The negative integer `-1 - n`.
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// In encoded-key order once encoded (the encoder sorts).
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn text(s: impl Into<String>) -> Value {
        Value::Text(s.into())
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::Uint(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The value of text key `key` in a map.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// The deterministic encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    /// Appends the deterministic encoding to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        match self {
            Value::Uint(n) => write_head(out, 0, *n),
            Value::Nint(n) => write_head(out, 1, *n),
            Value::Bytes(b) => {
                write_head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(s) => {
                write_head(out, 3, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Array(items) => {
                write_head(out, 4, items.len() as u64);
                for i in items {
                    i.write(out);
                }
            }
            Value::Map(entries) => write_map(
                out,
                entries
                    .iter()
                    .map(|(k, v)| (k.encode(), v.encode()))
                    .collect(),
            ),
            Value::Bool(false) => out.push(0xf4),
            Value::Bool(true) => out.push(0xf5),
            Value::Null => out.push(0xf6),
        }
    }
}

/// Appends a head: major type `major` with argument `n`, in its shortest form.
pub fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// Appends a map of already-encoded `(key, value)` pairs: sorted by their encoded keys (RFC 8949
/// §4.2.1), and of equal keys only the last (a map's keys are unique).
pub fn write_map(out: &mut Vec<u8>, mut pairs: Vec<(Vec<u8>, Vec<u8>)>) {
    // A stable sort keeps equal keys in their given order; the last of each run wins.
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut kept: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(pairs.len());
    for p in pairs {
        match kept.last_mut() {
            Some(last) if last.0 == p.0 => *last = p,
            _ => kept.push(p),
        }
    }
    write_head(out, 5, kept.len() as u64);
    for (k, v) in kept {
        out.extend_from_slice(&k);
        out.extend_from_slice(&v);
    }
}

/// Why bytes are not a value of this subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    /// A head that is not the shortest, an indefinite length, a tag, a float or a reserved code.
    NotDeterministic,
    BadUtf8,
    TooDeep,
    TrailingBytes,
    /// Map keys out of order or repeated.
    MapOrder,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            DecodeError::Truncated => "truncated CBOR",
            DecodeError::NotDeterministic => "CBOR outside the deterministic subset",
            DecodeError::BadUtf8 => "CBOR text that is not UTF-8",
            DecodeError::TooDeep => "CBOR nested too deeply",
            DecodeError::TrailingBytes => "bytes after the CBOR value",
            DecodeError::MapOrder => "CBOR map keys out of order or repeated",
        })
    }
}

impl core::error::Error for DecodeError {}

/// Decodes exactly one value that fills `bytes`.
pub fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut at = 0;
    let v = item(bytes, &mut at, 0)?;
    if at != bytes.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(v)
}

const MAX_DEPTH: u32 = 32;
/// The most items an array or map reserves room for up front. A count is only bounded by the
/// rest of the input, and every nesting level would reserve that much again; past this the
/// vector grows as items actually decode.
const PREALLOC: usize = 64;

fn take<'a>(b: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], DecodeError> {
    let end = at.checked_add(n).ok_or(DecodeError::Truncated)?;
    let s = b.get(*at..end).ok_or(DecodeError::Truncated)?;
    *at = end;
    Ok(s)
}

fn read_head(b: &[u8], at: &mut usize) -> Result<(u8, u64, u8), DecodeError> {
    let first = take(b, at, 1)?[0];
    let (major, info) = (first >> 5, first & 0x1f);
    let n = match info {
        0..=23 => u64::from(info),
        24 => {
            let v = u64::from(take(b, at, 1)?[0]);
            if v < 24 {
                return Err(DecodeError::NotDeterministic);
            }
            v
        }
        25 => {
            let s = take(b, at, 2)?;
            let v = u64::from(u16::from_be_bytes([s[0], s[1]]));
            if v <= 0xff {
                return Err(DecodeError::NotDeterministic);
            }
            v
        }
        26 => {
            let s = take(b, at, 4)?;
            let v = u64::from(u32::from_be_bytes([s[0], s[1], s[2], s[3]]));
            if v <= 0xffff {
                return Err(DecodeError::NotDeterministic);
            }
            v
        }
        27 => {
            let s = take(b, at, 8)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            let v = u64::from_be_bytes(a);
            if v <= 0xffff_ffff {
                return Err(DecodeError::NotDeterministic);
            }
            v
        }
        _ => return Err(DecodeError::NotDeterministic),
    };
    Ok((major, n, info))
}

fn item(b: &[u8], at: &mut usize, depth: u32) -> Result<Value, DecodeError> {
    if depth > MAX_DEPTH {
        return Err(DecodeError::TooDeep);
    }
    let (major, n, info) = read_head(b, at)?;
    let len = |n: u64| usize::try_from(n).map_err(|_| DecodeError::Truncated);
    Ok(match major {
        0 => Value::Uint(n),
        1 => Value::Nint(n),
        2 => Value::Bytes(take(b, at, len(n)?)?.to_vec()),
        3 => {
            let s = take(b, at, len(n)?)?;
            Value::Text(String::from(
                core::str::from_utf8(s).map_err(|_| DecodeError::BadUtf8)?,
            ))
        }
        4 => {
            // Each item is at least one byte: a length beyond the input is truncated.
            if n > (b.len() - *at) as u64 {
                return Err(DecodeError::Truncated);
            }
            let mut items = Vec::with_capacity((n as usize).min(PREALLOC));
            for _ in 0..n {
                items.push(item(b, at, depth + 1)?);
            }
            Value::Array(items)
        }
        5 => {
            if n > (b.len() - *at) as u64 {
                return Err(DecodeError::Truncated);
            }
            let mut entries = Vec::with_capacity((n as usize).min(PREALLOC));
            let mut last: Option<&[u8]> = None;
            for _ in 0..n {
                let k0 = *at;
                let k = item(b, at, depth + 1)?;
                let key_bytes = &b[k0..*at];
                if last.is_some_and(|l| l >= key_bytes) {
                    return Err(DecodeError::MapOrder);
                }
                last = Some(key_bytes);
                let v = item(b, at, depth + 1)?;
                entries.push((k, v));
            }
            Value::Map(entries)
        }
        7 => match info {
            20 => Value::Bool(false),
            21 => Value::Bool(true),
            22 => Value::Null,
            _ => return Err(DecodeError::NotDeterministic),
        },
        _ => return Err(DecodeError::NotDeterministic),
    })
}

/// Values written straight to bytes, for engines that reply to reads without building a
/// [`Value`]: the same bytes `Value::encode` gives.
pub mod build {
    use alloc::vec::Vec;

    use super::{write_head, write_map};

    pub fn uint(n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        write_head(&mut out, 0, n);
        out
    }

    pub fn bytes(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(b.len() + 9);
        write_head(&mut out, 2, b.len() as u64);
        out.extend_from_slice(b);
        out
    }

    pub fn text(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() + 9);
        write_head(&mut out, 3, s.len() as u64);
        out.extend_from_slice(s.as_bytes());
        out
    }

    pub fn boolean(b: bool) -> Vec<u8> {
        alloc::vec![if b { 0xf5 } else { 0xf4 }]
    }

    pub fn null() -> Vec<u8> {
        alloc::vec![0xf6]
    }

    /// An array of already-encoded items.
    pub fn array(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        write_head(&mut out, 4, items.len() as u64);
        for i in items {
            out.extend_from_slice(i);
        }
        out
    }

    /// A map of text keys to already-encoded values (keys sorted by their encoding).
    pub fn map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        write_map(
            &mut out,
            entries.iter().map(|(k, v)| (text(k), v.clone())).collect(),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trips_in_the_deterministic_form() {
        let v = Value::Map(vec![
            (Value::text("to"), Value::Uint(1)),
            (
                Value::text("a"),
                Value::Array(vec![Value::Null, Value::Bool(true)]),
            ),
            (Value::text("b"), Value::Bytes(vec![1, 2, 3])),
            (Value::text("n"), Value::Nint(4)),
            (Value::text("big"), Value::Uint(1 << 40)),
        ]);
        let bytes = v.encode();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.get("to"), Some(&Value::Uint(1)));
        assert_eq!(back.get("big"), Some(&Value::Uint(1 << 40)));
        assert_eq!(back.encode(), bytes);
        let Value::Map(entries) = back else { panic!() };
        let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_text().unwrap()).collect();
        assert_eq!(keys, ["a", "b", "n", "to", "big"]);
    }

    #[test]
    fn nested_counts_do_not_reserve_memory_they_never_use() {
        // Every level claims as many items as the input has bytes left (16 MiB), and the first
        // item is invalid. Reserving each count up front would ask for gigabytes per level.
        let pad = 16 << 20;
        let mut b = Vec::new();
        for _ in 0..MAX_DEPTH {
            b.push(0x9a);
            b.extend_from_slice(&(pad as u32).to_be_bytes());
        }
        b.resize(b.len() + pad, 0xff);
        assert!(decode(&b).is_err());
        // A map claims as many entries.
        let mut m = vec![0xba];
        m.extend_from_slice(&(pad as u32).to_be_bytes());
        m.resize(m.len() + pad, 0xff);
        assert!(decode(&m).is_err());
    }

    #[test]
    fn known_encodings() {
        assert_eq!(build::uint(0), [0x00]);
        assert_eq!(build::uint(23), [0x17]);
        assert_eq!(build::uint(24), [0x18, 24]);
        assert_eq!(build::uint(500), [0x19, 0x01, 0xf4]);
        assert_eq!(build::null(), [0xf6]);
        assert_eq!(Value::text("c4").encode(), [0x62, b'c', b'4']);
        assert_eq!(Value::Nint(0).encode(), [0x20]);
        for n in [
            0u64,
            23,
            24,
            255,
            256,
            65_535,
            65_536,
            u32::MAX as u64 + 1,
            u64::MAX,
        ] {
            assert_eq!(build::uint(n), Value::Uint(n).encode());
        }
        assert_eq!(build::text("a+start"), Value::text("a+start").encode());
        assert_eq!(build::bytes(&[1, 2]), Value::Bytes(vec![1, 2]).encode());
        assert_eq!(build::boolean(true), Value::Bool(true).encode());
        // Keys sorted by encoding: "b" before "aa".
        assert_eq!(
            build::map(&[("aa", build::uint(1)), ("b", build::uint(2))])[1..3],
            [0x61, b'b']
        );
    }

    #[test]
    fn equal_keys_keep_the_last() {
        let v = Value::Map(vec![
            (Value::text("k"), Value::Uint(1)),
            (Value::text("k"), Value::Uint(2)),
        ]);
        assert_eq!(v.encode(), [0xa1, 0x61, b'k', 0x02]);
    }

    #[test]
    fn rejects_non_deterministic_and_malformed_input() {
        assert_eq!(decode(&[0x18, 5]), Err(DecodeError::NotDeterministic));
        assert_eq!(decode(&[0x9f]), Err(DecodeError::NotDeterministic));
        assert_eq!(decode(&[0x01, 0x02]), Err(DecodeError::TrailingBytes));
        assert_eq!(decode(&[0x62, b'a']), Err(DecodeError::Truncated));
        assert_eq!(
            decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(DecodeError::Truncated)
        );
        assert_eq!(
            decode(&[0xa2, 0x61, b'b', 0, 0x61, b'a', 0]),
            Err(DecodeError::MapOrder)
        );
        assert_eq!(decode(&[0xc1, 0x00]), Err(DecodeError::NotDeterministic));
        assert_eq!(decode(&[0x62, 0xff, 0xfe]), Err(DecodeError::BadUtf8));
        assert_eq!(decode(&[]), Err(DecodeError::Truncated));
    }
}
