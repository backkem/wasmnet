//! wit-bindgen glue: a stepped device with no ports that exports `wasmnet:link/device` and
//! makes the script's calls through `wasmnet:infra/devices`.

// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::RefCell;

use crate::{Script, Step, Verb};

wit_bindgen::generate!({
    inline: "
        package wasmnet:infra-script;
        world infra-script {
            include wasmnet:link/stepped-device@0.1.0;
            import wasmnet:infra/devices@0.1.2;
        }
    ",
    path: ["../../wit/deps/config", "../../wit/link", "../../wit/infra"],
    generate_all,
    with: { "wasi:config/store@0.2.0-rc.1": generate },
});

use exports::wasmnet::link::device;
use wasi::config::store;
use wasmnet::infra::devices;
use wasmnet::link::log::{self, Level};
use wasmnet::link::types::PortInfo;

thread_local! {
    static STATE: RefCell<Option<Script>> = const { RefCell::new(None) };
}

fn create() -> Script {
    let pairs = store::get_all().unwrap_or_else(|e| {
        log::log(
            Level::Error,
            &format!("infra-script: wasi:config get-all: {e:?}"),
        );
        panic!("infra-script: wasi:config get-all failed")
    });
    Script::from_pairs(pairs).unwrap_or_else(|e| {
        log::log(Level::Error, &e.to_string());
        panic!("infra-script: {e}")
    })
}

fn with<R>(f: impl FnOnce(&mut Script) -> R) -> R {
    STATE.with(|s| f(s.borrow_mut().get_or_insert_with(create)))
}

/// Makes one step's call; its result for the journal, and any fields it adds.
fn run(step: &Step) -> (String, Vec<(String, String)>) {
    let id = Some(step.request_id.as_str());
    let name = step.name.as_str();
    let answer = match &step.verb {
        Verb::Apply { spec } => {
            devices::apply(id, name, &[], spec).map(|a| if a.changed { "ok" } else { "unchanged" })
        }
        Verb::Control { command, argument } => {
            devices::control(id, name, command, argument).map(|_| "ok")
        }
        Verb::Start => devices::start(id, name).map(|_| "ok"),
        Verb::Stop => devices::stop(id, name, 0).map(|_| "ok"),
        Verb::Remove => devices::remove(id, name).map(|r| if r { "ok" } else { "unchanged" }),
        Verb::Logs { stream, tail } => {
            return match devices::logs(name, stream, 0, *tail) {
                Ok(lines) => {
                    let text: Vec<&str> = lines.iter().map(|l| l.line.as_str()).collect();
                    let fields = vec![
                        ("lines".to_owned(), lines.len().to_string()),
                        ("text".to_owned(), text.join(" | ")),
                    ];
                    ("ok".to_owned(), fields)
                }
                Err(e) => (format!("{e:?}"), Vec::new()),
            };
        }
    };
    match answer {
        Ok(r) => (r.to_owned(), Vec::new()),
        Err(e) => (format!("{e:?}"), Vec::new()),
    }
}

struct Component;

impl device::Guest for Component {
    fn ports() -> Vec<PortInfo> {
        with(|_| Vec::new())
    }

    fn receive(_now: u64, _port: u32, _frame: Vec<u8>) {}

    fn poll(now: u64) -> Option<u64> {
        // The calls are made outside the borrow: they never re-enter this device, but keeping
        // them out of it costs nothing.
        let due = with(|s| s.due(now));
        for step in &due {
            let (result, extra) = run(step);
            let mut fields = vec![
                ("step".to_owned(), step.n.to_string()),
                ("verb".to_owned(), step.verb.name().to_owned()),
                ("name".to_owned(), step.name.clone()),
                ("result".to_owned(), result),
            ];
            fields.extend(extra);
            log::event("infra-script", &fields);
        }
        with(|s| s.next_deadline())
    }

    fn link_state(_now: u64, _port: u32, _up: bool) {}
}

export!(Component);
