//! wit-bindgen glue: a stepped device with no ports that exports `wasmnet:link/device` and
//! `wasmnet:control/commands` (`set`, `variables`, `args`, `env`) and makes the script's calls
//! through `wasmnet:infra/devices`, `components` and `events` (its rules: read the followed
//! devices' events, then arm a wake on them).

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
            import wasmnet:infra/events@0.1.2;
            import wasmnet:infra/components@0.1.2;
            export wasmnet:control/commands@0.1.0;
        }
    ",
    path: [
        "../../wit/deps/config",
        "../../wit/link",
        "../../wit/infra",
        "../../wit/control",
    ],
    generate_all,
    with: { "wasi:config/store@0.2.0-rc.1": generate },
});

use exports::wasmnet::control::commands;
use exports::wasmnet::link::device;
use wasi::config::store;
use wasmnet::infra::{components, devices, events};
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
    // A `control` argument's variables are filled in now, from what `set` was told so far.
    let expanded = match &step.verb {
        Verb::Control { argument, .. } => match with(|s| s.expand(argument)) {
            Ok(a) => Some(a),
            Err(name) => return (format!("unset {name}"), Vec::new()),
        },
        _ => None,
    };
    let id = Some(step.request_id.as_str());
    let name = step.name.as_str();
    if let Some(when) = &step.when {
        let answer = devices::control_answer(&when.request_id).ok().flatten();
        let text = answer.as_ref().and_then(|a| a.answer.as_ref().ok());
        if !when.holds(text.map(String::as_str)) {
            return ("skipped".to_owned(), Vec::new());
        }
    }
    let answer = match &step.verb {
        Verb::Answer => {
            return match devices::control_answer(name) {
                Ok(None) => ("pending".to_owned(), Vec::new()),
                Ok(Some(a)) => {
                    let (result, text) = match a.answer {
                        Ok(t) => ("ok", t),
                        Err(t) => ("err", t),
                    };
                    let text = text.lines().collect::<Vec<_>>().join(" | ");
                    let fields = vec![
                        ("at".to_owned(), a.at.to_string()),
                        ("text".to_owned(), text),
                    ];
                    (result.to_owned(), fields)
                }
                Err(e) => (format!("{e:?}"), Vec::new()),
            };
        }
        Verb::Apply { spec } => {
            devices::apply(id, name, &[], spec).map(|a| if a.changed { "ok" } else { "unchanged" })
        }
        Verb::Control { command, argument } => {
            let argument = expanded.as_deref().unwrap_or(argument);
            devices::control(id, name, command, argument).map(|_| "ok")
        }
        Verb::Start => devices::start(id, name).map(|_| "ok"),
        Verb::Stop => devices::stop(id, name, 0).map(|_| "ok"),
        Verb::Remove => devices::remove(id, name).map(|r| if r { "ok" } else { "unchanged" }),
        Verb::Wire { cable } => devices::wire(id, name, cable).map(|_| "ok"),
        Verb::Unwire { port } => devices::unwire(id, name, *port).map(|_| "ok"),
        Verb::Events { kinds, since } => {
            return match events::read(name, kinds, *since, 256) {
                Ok(p) => {
                    let seqs: Vec<String> = p.events.iter().map(|e| e.seq.to_string()).collect();
                    let kinds: Vec<&str> = p.events.iter().map(|e| e.kind.as_str()).collect();
                    let fields = vec![
                        ("count".to_owned(), p.events.len().to_string()),
                        ("seqs".to_owned(), seqs.join(",")),
                        ("kinds".to_owned(), kinds.join(",")),
                        ("next".to_owned(), p.next.to_string()),
                        ("missed".to_owned(), p.missed.to_string()),
                    ];
                    ("ok".to_owned(), fields)
                }
                Err(e) => (format!("{e:?}"), Vec::new()),
            };
        }
        Verb::Supply { bytes } => {
            let digest = (name != "-").then_some(name);
            return match components::supply(digest, bytes) {
                Ok(d) => ("ok".to_owned(), vec![("digest".to_owned(), d)]),
                Err(e) => (format!("{e:?}"), Vec::new()),
            };
        }
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

/// The rules' part of a poll: reads the followed devices' new events, makes the call of every
/// rule each one sets off (journalled as `infra-script` with `step` `on.<n>`, `device`, `seq`
/// and `event`), and arms `events.arm` on what it follows, so the next such event polls this
/// device again. A device that cannot be read yet (not created) is left out until a later
/// poll; a gap is journalled as `infra-script-missed {device, missed}`.
fn react() {
    // An armed wait that is ready at once means more to read: a few rounds, then the next poll.
    for _ in 0..8 {
        let followed = with(|s| s.followed());
        if followed.is_empty() {
            return;
        }
        let mut follows = Vec::new();
        for (device, kinds, since) in followed {
            let Ok(page) = events::read(&device, &kinds, since, 256) else {
                continue;
            };
            if page.missed > 0 {
                log::event(
                    "infra-script-missed",
                    &[
                        ("device".to_owned(), device.clone()),
                        ("missed".to_owned(), page.missed.to_string()),
                    ],
                );
            }
            for e in &page.events {
                let steps = with(|s| s.reactions(&device, e.seq, &e.kind, &e.fields));
                for step in &steps {
                    let (result, extra) = run(step);
                    let mut fields = vec![
                        ("step".to_owned(), format!("on.{}", step.n)),
                        ("verb".to_owned(), step.verb.name().to_owned()),
                        ("name".to_owned(), step.name.clone()),
                        ("result".to_owned(), result),
                        ("device".to_owned(), device.clone()),
                        ("seq".to_owned(), e.seq.to_string()),
                        ("event".to_owned(), e.kind.clone()),
                    ];
                    fields.extend(extra);
                    log::event("infra-script", &fields);
                }
            }
            with(|s| s.advance(&device, page.next));
            follows.push(events::Follow {
                name: device,
                kinds,
                since: page.next,
            });
        }
        match events::arm(None, &follows) {
            Ok(Some(_)) => continue,
            Ok(None) => return,
            Err(e) => {
                log::log(Level::Warn, &format!("infra-script: arm: {e:?}"));
                return;
            }
        }
    }
}

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
        react();
        with(|s| s.next_deadline())
    }

    fn link_state(_now: u64, _port: u32, _up: bool) {}
}

impl commands::Guest for Component {
    fn invoke(_now: u64, command: String, argument: String) -> Result<String, String> {
        match command.as_str() {
            "set" => {
                let done = with(|s| s.set(&argument))?;
                let mut words = argument.split_whitespace();
                let fields = [
                    ("variable".to_owned(), words.next().unwrap_or("").to_owned()),
                    ("value".to_owned(), words.next().unwrap_or("").to_owned()),
                ];
                if done == "set" {
                    log::event("infra-script-set", &fields);
                }
                Ok(done.to_owned())
            }
            "variables" if argument.trim().is_empty() => Ok(with(|s| s.variables())),
            // What `wasi:cli/environment` gives this device, one entry per line.
            "args" if argument.trim().is_empty() => {
                Ok(std::env::args().collect::<Vec<_>>().join("\n"))
            }
            "env" if argument.trim().is_empty() => Ok(std::env::vars()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("\n")),
            other => Err(format!(
                "unknown command `{other}` (set, variables, args, env)"
            )),
        }
    }
}

export!(Component);
