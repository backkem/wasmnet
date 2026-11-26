//! wit-bindgen glue: `wasmnet-test:bytes-store/{state,objects}` over the disks `state` and
//! `objects`.

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::RefCell;

use crate::CHOSEN;

wit_bindgen::generate!({
    path: ["../../wit/deps/keyvalue", "../../wit/keyvalue-ext", "../../wit/test-store"],
    world: "wasmnet-test:bytes-store/adapter",
    generate_all,
});

use exports::wasmnet_test::bytes_store::{objects, state};
use wasi::keyvalue::store;
use wasmnet::keyvalue_ext::ordered;

thread_local! {
    static BUCKETS: RefCell<Vec<(&'static str, store::Bucket)>> = const { RefCell::new(Vec::new()) };
}

/// The disk `name`, opened once.
fn with_disk<T>(
    name: &'static str,
    f: impl FnOnce(&store::Bucket) -> Result<T, state::Error>,
) -> Result<T, state::Error> {
    BUCKETS.with_borrow_mut(|b| {
        if !b.iter().any(|(n, _)| *n == name) {
            let bucket = store::open(name)
                .map_err(|e| state::Error::Failed(format!("open {name}: {e:?}")))?;
            b.push((name, bucket));
        }
        let (_, bucket) = b.iter().find(|(n, _)| *n == name).expect("opened above");
        f(bucket)
    })
}

fn error(e: ordered::Error) -> state::Error {
    match e {
        ordered::Error::TooLarge(_) => state::Error::TooLarge,
        ordered::Error::Full(_) => state::Error::Full,
        ordered::Error::Failed(t) => state::Error::Failed(t),
        ordered::Error::NoSuchStore => state::Error::Failed("no such disk".to_owned()),
    }
}

fn std_error(e: store::Error) -> state::Error {
    state::Error::Failed(format!("{e:?}"))
}

fn key(k: &str) -> Result<Vec<u8>, state::Error> {
    CHOSEN
        .decode(k)
        .ok_or_else(|| state::Error::Failed(format!("a key this adapter did not write: {k:?}")))
}

struct Component;

impl state::Guest for Component {
    fn get(k: Vec<u8>) -> Result<Option<Vec<u8>>, state::Error> {
        with_disk("state", |b| b.get(&CHOSEN.encode(&k)).map_err(std_error))
    }

    fn write(changes: Vec<state::Change>) -> Result<(), state::Error> {
        let changes: Vec<ordered::Change> = changes
            .into_iter()
            .map(|c| match c {
                state::Change::Set((k, v)) => ordered::Change::Set((CHOSEN.encode(&k), v)),
                state::Change::Delete(k) => ordered::Change::Delete(CHOSEN.encode(&k)),
            })
            .collect();
        with_disk("state", |b| ordered::write(b, &changes).map_err(error))
    }

    fn scan(
        prefix: Vec<u8>,
        after: Option<Vec<u8>>,
        limit: u32,
    ) -> Result<Vec<state::Entry>, state::Error> {
        let after = after.map(|a| CHOSEN.encode(&a));
        with_disk("state", |b| {
            ordered::scan(b, &CHOSEN.encode(&prefix), after.as_deref(), limit, true)
                .map_err(error)?
                .into_iter()
                .map(|e| {
                    Ok(state::Entry {
                        key: key(&e.key)?,
                        value: e.value.unwrap_or_default(),
                    })
                })
                .collect()
        })
    }
}

impl objects::Guest for Component {
    fn keep(hash: Vec<u8>, bytes: Vec<u8>) -> Result<(), state::Error> {
        if hash.len() != 32 {
            return Err(state::Error::Failed("a hash has 32 bytes".to_owned()));
        }
        let set = ordered::Change::Set((CHOSEN.encode(&hash), bytes));
        with_disk("objects", |b| ordered::write(b, &[set]).map_err(error))
    }

    fn read(hash: Vec<u8>, offset: u64, len: u32) -> Result<Option<Vec<u8>>, state::Error> {
        with_disk("objects", |b| {
            ordered::get_range(b, &CHOSEN.encode(&hash), offset, len).map_err(error)
        })
    }

    fn remove(hash: Vec<u8>) -> Result<(), state::Error> {
        with_disk("objects", |b| {
            b.delete(&CHOSEN.encode(&hash)).map_err(std_error)
        })
    }

    fn held(after: Option<Vec<u8>>, limit: u32) -> Result<Vec<objects::Object>, state::Error> {
        let after = after.map(|a| CHOSEN.encode(&a));
        with_disk("objects", |b| {
            ordered::scan(b, "", after.as_deref(), limit, false)
                .map_err(error)?
                .into_iter()
                .map(|e| {
                    Ok(objects::Object {
                        hash: key(&e.key)?,
                        size: e.size,
                    })
                })
                .collect()
        })
    }
}

export!(Component);
