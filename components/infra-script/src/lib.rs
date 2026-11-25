//! infra-script: a test fixture, not a product device. A controller with a script: a stepped
//! device with no ports that makes `wasmnet:infra/devices` calls at set virtual times, so a test
//! can drive the infra API from inside the network without writing a controller.
//!
//! Config (`wasi:config/store`): one key per step, `step.<n>`, whose value is
//!
//! ```text
//! <at> [id=<request-id>] <verb> <name> [<rest>]
//! ```
//!
//! * `<at>`: a duration (`250ms`): the virtual time the call is made at, in the device's poll
//!   at that instant. Steps run in order of `(at, n)`.
//! * `id=<request-id>`: the call's request id (default `step-<n>`). Two steps with the same id
//!   and arguments exercise a retry.
//! * `<verb> <name> [<rest>]`: `apply <name> <spec>` (the CBOR spec as hex, no labels),
//!   `control <name> <command> [<argument>]` (the argument is the rest of the line, trimmed),
//!   `start <name>`, `stop <name>` (no grace period), `remove <name>`, or
//!   `logs <name> [stdout|stderr] [<tail>]` (the device's journalled output lines, default
//!   `stderr` and every line).
//!
//! Every step's result is journalled as `infra-script {step, verb, name, result}`: `result` is
//! `ok`, `unchanged` (an `apply` that changed nothing, a `remove` of nothing) or the error. A
//! `logs` step adds `lines` (how many) and `text` (the lines, joined with ` | `).
//! Unknown keys and malformed steps are configuration errors (the glue logs and traps).
//!
//! This file is pure logic with no bindings, unit-tested inside wasmtime. The wit-bindgen glue
//! lives in `component.rs`.

#![deny(unsafe_code)]

#[cfg(not(test))]
mod component;

use wasmnet_wire::parse_duration;

/// What a step asks of the infra API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verb {
    Apply {
        spec: Vec<u8>,
    },
    Control {
        command: String,
        argument: String,
    },
    Start,
    Stop,
    Remove,
    /// `devices.logs` on `stream` (`stdout` or `stderr`), the last `tail` lines (0: all).
    Logs {
        stream: String,
        tail: u32,
    },
}

impl Verb {
    pub fn name(&self) -> &'static str {
        match self {
            Verb::Apply { .. } => "apply",
            Verb::Control { .. } => "control",
            Verb::Start => "start",
            Verb::Stop => "stop",
            Verb::Remove => "remove",
            Verb::Logs { .. } => "logs",
        }
    }
}

/// One scripted call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub n: u32,
    pub at: u64,
    pub request_id: String,
    pub verb: Verb,
    /// The device it is about.
    pub name: String,
}

/// A step that could not be parsed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("config {key}: unknown key")]
    Unknown { key: String },
    #[error("config {key}={value:?}: {why}")]
    Invalid {
        key: String,
        value: String,
        why: String,
    },
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Parses one step's value.
pub fn parse_step(n: u32, text: &str) -> Result<Step, String> {
    let syntax = "`<at> [id=<id>] apply|control|start|stop|remove|logs <name> [<rest>]`";
    let text = text.trim();
    let (at, rest) = text.split_once(char::is_whitespace).ok_or(syntax)?;
    let at = parse_duration(at).ok_or_else(|| format!("`{at}` is not a duration"))?;
    let mut rest = rest.trim_start();
    let mut request_id = format!("step-{n}");
    if let Some(id) = rest.strip_prefix("id=") {
        let (id, after) = id.split_once(char::is_whitespace).ok_or(syntax)?;
        request_id = id.to_owned();
        rest = after.trim_start();
    }
    let (verb, rest) = rest.split_once(char::is_whitespace).ok_or(syntax)?;
    let rest = rest.trim_start();
    let (name, rest) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    let rest = rest.trim();
    if name.is_empty() {
        return Err(syntax.to_owned());
    }
    let verb = match verb {
        "apply" => Verb::Apply {
            spec: hex(rest).ok_or("apply: the spec must be hex")?,
        },
        "control" => {
            let (command, argument) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            if command.is_empty() {
                return Err("control: needs a command".to_owned());
            }
            Verb::Control {
                command: command.to_owned(),
                argument: argument.trim().to_owned(),
            }
        }
        "start" | "stop" | "remove" if !rest.is_empty() => {
            return Err(format!("{verb}: takes only a name"));
        }
        "start" => Verb::Start,
        "stop" => Verb::Stop,
        "remove" => Verb::Remove,
        "logs" => {
            let mut words = rest.split_whitespace();
            let stream = match words.next() {
                None => "stderr",
                Some(s @ ("stdout" | "stderr")) => s,
                Some(s) => return Err(format!("logs: `{s}` is not stdout or stderr")),
            };
            let tail = match words.next() {
                None => 0,
                Some(t) => t
                    .parse()
                    .map_err(|_| format!("logs: `{t}` is not a line count"))?,
            };
            if words.next().is_some() {
                return Err("logs: `logs <name> [stdout|stderr] [<tail>]`".to_owned());
            }
            Verb::Logs {
                stream: stream.to_owned(),
                tail,
            }
        }
        _ => return Err(syntax.to_owned()),
    };
    Ok(Step {
        n,
        at,
        request_id,
        verb,
        name: name.to_owned(),
    })
}

/// The script: every step, in the order they run, and how far it got.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Script {
    steps: Vec<Step>,
    next: usize,
}

impl Script {
    /// Parses the device's whole config (`get-all`).
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut steps = Vec::new();
        for (key, value) in pairs {
            let (key, value): (String, String) = (key.into(), value.into());
            let n = key
                .strip_prefix("step.")
                .filter(|n| !n.is_empty() && (n.len() == 1 || !n.starts_with('0')))
                .and_then(|n| n.parse::<u32>().ok())
                .ok_or_else(|| ConfigError::Unknown { key: key.clone() })?;
            let step = parse_step(n, &value).map_err(|why| ConfigError::Invalid {
                key: key.clone(),
                value: value.clone(),
                why,
            })?;
            steps.push(step);
        }
        steps.sort_by_key(|s| (s.at, s.n));
        Ok(Self { steps, next: 0 })
    }

    /// The steps due at `now` that have not run yet, in order (they count as run).
    pub fn due(&mut self, now: u64) -> Vec<Step> {
        let start = self.next;
        while self.steps.get(self.next).is_some_and(|s| s.at <= now) {
            self.next += 1;
        }
        self.steps[start..self.next].to_vec()
    }

    /// When the next step is due.
    pub fn next_deadline(&self) -> Option<u64> {
        self.steps.get(self.next).map(|s| s.at)
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn steps_parse_and_run_in_time_order() {
        let mut s = Script::from_pairs([
            (
                "step.2",
                "20ms control r1 route-replace 10.0.3.0/24 via 10.0.2.3",
            ),
            ("step.0", "0ms apply r1 a1636b"),
            ("step.1", "20ms id=again control r1 routes"),
            ("step.10", "5ms stop r1"),
        ])
        .unwrap();
        assert_eq!(s.len(), 4);
        assert_eq!(s.next_deadline(), Some(0));
        let first = s.due(0);
        assert_eq!(first.len(), 1);
        assert_eq!(
            first[0].verb,
            Verb::Apply {
                spec: vec![0xa1, 0x63, 0x6b]
            }
        );
        assert_eq!(first[0].request_id, "step-0");
        assert_eq!(s.next_deadline(), Some(5 * MS));
        assert!(s.due(4 * MS).is_empty());
        assert_eq!(s.due(30 * MS).len(), 3, "everything due by then");
        let mut again = Script::from_pairs([
            (
                "step.2",
                "20ms control r1 route-replace 10.0.3.0/24 via 10.0.2.3",
            ),
            ("step.1", "20ms id=again control r1 routes"),
        ])
        .unwrap();
        let both = again.due(20 * MS);
        assert_eq!(
            (both[0].n, both[1].n),
            (1, 2),
            "same instant: by step number"
        );
        assert_eq!(both[0].request_id, "again");
        assert_eq!(
            both[0].verb,
            Verb::Control {
                command: "routes".into(),
                argument: String::new()
            }
        );
        assert_eq!(
            both[1].verb,
            Verb::Control {
                command: "route-replace".into(),
                argument: "10.0.3.0/24 via 10.0.2.3".into()
            }
        );
        assert_eq!(again.next_deadline(), None);
    }

    #[test]
    fn logs_steps_name_a_stream_and_a_tail() {
        let logs = |text| parse_step(0, text).map(|s| s.verb);
        assert_eq!(
            logs("1ms logs r1"),
            Ok(Verb::Logs {
                stream: "stderr".into(),
                tail: 0
            })
        );
        assert_eq!(
            logs("1ms logs r1 stdout 3"),
            Ok(Verb::Logs {
                stream: "stdout".into(),
                tail: 3
            })
        );
        for bad in [
            "1ms logs r1 stdin",
            "1ms logs r1 stderr x",
            "1ms logs r1 stderr 1 2",
        ] {
            assert!(parse_step(0, bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn bad_steps_and_keys_are_config_errors() {
        for bad in [
            "",
            "soon apply r1 00",
            "1ms apply r1 0g",
            "1ms apply r1 000",
            "1ms fly r1",
            "1ms control r1",
            "1ms stop r1 now",
            "1ms id=x",
        ] {
            assert!(parse_step(0, bad).is_err(), "{bad:?}");
        }
        assert!(matches!(
            Script::from_pairs([("steps.0", "1ms stop r1")]),
            Err(ConfigError::Unknown { .. })
        ));
        assert!(matches!(
            Script::from_pairs([("step.01", "1ms stop r1")]),
            Err(ConfigError::Unknown { .. })
        ));
        assert!(matches!(
            Script::from_pairs([("step.0", "1ms stop")]),
            Err(ConfigError::Invalid { .. })
        ));
    }
}
