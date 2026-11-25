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
//!   `wire <name> <cable>` (the cable's CBOR as hex), `unwire <name> <port>`,
//!   `logs <name> [stdout|stderr] [<tail>]` (the device's journalled output lines, default
//!   `stderr` and every line), or `answer <request-id>` (the answer to the command sent with
//!   that request id: `devices.control-answer`).
//! * `when=<request-id>~<text>` or `when=<request-id>!<text>` (after `id=`, if any): the step
//!   runs only if the answer to the command sent with that request id has come, is `ok`, and
//!   contains (`~`) or does not contain (`!`) `<text>` (no spaces); otherwise its result is
//!   `skipped`. That is a controller acting on what a device answered.
//!   `when=<request-id>.<key>=<value>` asks instead for a line of the answer with the word
//!   `<key>` followed by the word `<value>`, as in a `<key> <value>` listing (the router's
//!   `tunnels`: `when=t1.state=up`).
//! * `{<variable>}` in a `control` step's argument is replaced, when the step runs, by the value
//!   the variable was given through the fixture's own command `set` (below); a variable not set
//!   yet makes the step's result `unset <variable>`, and nothing is sent.
//!
//! The fixture takes commands (`wasmnet:control/commands`), which is how an embedder hands it
//! what it learnt elsewhere (from another controller, for instance): `set <variable> <value>`
//! (a name of `a-z`, `0-9` and `-`; a value without spaces) answers `set` or `unchanged` and
//! journals `infra-script-set {variable, value}`; `variables` lists them, `<variable> <value>`
//! per line.
//!
//! Every step's result is journalled as `infra-script {step, verb, name, result}`: `result` is
//! `ok`, `unchanged` (an `apply` that changed nothing, a `remove` of nothing) or the error. A
//! `logs` step adds `lines` (how many) and `text` (the lines, joined with ` | `); an `answer`
//! step adds `at` and `text` (the answer's lines, joined with ` | `), and its `result` is `ok`,
//! `err` (the device refused), `pending` or the error.
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
    /// `devices.control-answer` for the step's name, a request id.
    Answer,
    /// `devices.wire` with a cable (CBOR).
    Wire {
        cable: Vec<u8>,
    },
    /// `devices.unwire` of a port.
    Unwire {
        port: u32,
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
            Verb::Answer => "answer",
            Verb::Wire { .. } => "wire",
            Verb::Unwire { .. } => "unwire",
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
    /// The device it is about (for `answer`, the request id).
    pub name: String,
    /// It runs only if this holds.
    pub when: Option<When>,
}

/// A step's condition on the answer to an earlier command (`when=`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct When {
    /// The request id the command was sent with.
    pub request_id: String,
    pub test: Test,
}

/// What a condition asks of an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Test {
    /// It contains the text (`~`).
    Contains(String),
    /// It does not (`!`).
    Lacks(String),
    /// A line has the word `key` followed by the word `value` (`.<key>=<value>`).
    Pair(String, String),
}

impl When {
    /// Whether the condition holds for `answer`: the answer's `ok` text, if it came and was
    /// `ok`. No answer (yet), or a refusal, never satisfies it.
    pub fn holds(&self, answer: Option<&str>) -> bool {
        let Some(a) = answer else { return false };
        match &self.test {
            Test::Contains(t) => a.contains(t.as_str()),
            Test::Lacks(t) => !a.contains(t.as_str()),
            Test::Pair(k, v) => a.lines().any(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                words.windows(2).any(|w| w[0] == k && w[1] == v)
            }),
        }
    }
}

/// A variable's name: `a-z`, `0-9` and `-`, 1 to 32 characters.
fn valid_variable(n: &str) -> bool {
    (1..=32).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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
    let syntax = "`<at> [id=<id>] [when=<id>~|!<text>|when=<id>.<key>=<value>] \
                  apply|control|start|stop|remove|logs|answer|wire|unwire <name> [<rest>]`";
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
    let mut when = None;
    if let Some(cond) = rest.strip_prefix("when=") {
        let shape = "when: `<request-id>~<text>`, `<request-id>!<text>` or \
                     `<request-id>.<key>=<value>`";
        let (cond, after) = cond.split_once(char::is_whitespace).ok_or(syntax)?;
        when = Some(match cond.find(['~', '!']) {
            Some(at) => {
                let (id, text) = (&cond[..at], &cond[at + 1..]);
                if id.is_empty() || text.is_empty() {
                    return Err(shape.to_owned());
                }
                let text = text.to_owned();
                When {
                    request_id: id.to_owned(),
                    test: if cond.as_bytes()[at] == b'~' {
                        Test::Contains(text)
                    } else {
                        Test::Lacks(text)
                    },
                }
            }
            None => {
                let (id, pair) = cond.split_once('.').ok_or(shape)?;
                let (key, value) = pair.split_once('=').ok_or(shape)?;
                if id.is_empty() || key.is_empty() || value.is_empty() {
                    return Err(shape.to_owned());
                }
                When {
                    request_id: id.to_owned(),
                    test: Test::Pair(key.to_owned(), value.to_owned()),
                }
            }
        });
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
        "wire" => Verb::Wire {
            cable: hex(rest).ok_or("wire: the cable must be hex")?,
        },
        "unwire" => Verb::Unwire {
            port: rest
                .parse()
                .map_err(|_| format!("unwire: `{rest}` is not a port"))?,
        },
        "answer" if !rest.is_empty() => {
            return Err("answer: takes only a request id".to_owned());
        }
        "answer" => Verb::Answer,
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
        when,
    })
}

/// The script: every step, in the order they run, and how far it got.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Script {
    steps: Vec<Step>,
    next: usize,
    /// Set by the `set` command, used as `{<variable>}` in `control` arguments.
    variables: std::collections::BTreeMap<String, String>,
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
        Ok(Self {
            steps,
            next: 0,
            variables: Default::default(),
        })
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

    /// `set <variable> <value>`: `Ok("set")`, `Ok("unchanged")` or why not.
    pub fn set(&mut self, argument: &str) -> Result<&'static str, String> {
        let words: Vec<&str> = argument.split_whitespace().collect();
        let [name, value] = words.as_slice() else {
            return Err("set needs `<variable> <value>` (a value without spaces)".to_owned());
        };
        if !valid_variable(name) {
            return Err(format!(
                "`{name}`: a variable is a-z, 0-9 and -, 1 to 32 characters"
            ));
        }
        let old = self
            .variables
            .insert((*name).to_owned(), (*value).to_owned());
        Ok(if old.as_deref() == Some(*value) {
            "unchanged"
        } else {
            "set"
        })
    }

    /// Every variable, `<variable> <value>` per line, by name.
    pub fn variables(&self) -> String {
        self.variables
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// `text` with every `{<variable>}` replaced by its value; `Err(name)` names the first
    /// variable not set. Other braces are left as they are.
    pub fn expand(&self, text: &str) -> Result<String, String> {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(open) = rest.find('{') {
            let Some(close) = rest[open..].find('}') else {
                break;
            };
            let name = &rest[open + 1..open + close];
            out.push_str(&rest[..open]);
            if valid_variable(name) {
                out.push_str(self.variables.get(name).ok_or_else(|| name.to_owned())?);
            } else {
                out.push_str(&rest[open..=open + close]);
            }
            rest = &rest[open + close + 1..];
        }
        out.push_str(rest);
        Ok(out)
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
    fn answers_and_conditions_on_them() {
        let s = parse_step(0, "5ms answer q").unwrap();
        assert_eq!((s.verb, s.name.as_str(), s.when), (Verb::Answer, "q", None));
        let s = parse_step(1, "5ms id=x when=q!10.0.3.0/24 control r1 route-add y").unwrap();
        let when = s.when.expect("a condition");
        assert_eq!(
            when,
            When {
                request_id: "q".into(),
                test: Test::Lacks("10.0.3.0/24".into()),
            }
        );
        assert_eq!(s.request_id, "x");
        assert!(when.holds(Some("10.0.1.0/24 port 1")));
        assert!(!when.holds(Some("10.0.3.0/24 via 10.0.2.2")));
        assert!(!when.holds(None), "no answer yet: never");
        let has = parse_step(2, "5ms when=q~port answer q")
            .unwrap()
            .when
            .unwrap();
        assert!(has.holds(Some("a port")));
        let pair = parse_step(3, "5ms when=t1.state=up control r1 route-add x")
            .unwrap()
            .when
            .unwrap();
        assert_eq!(pair.test, Test::Pair("state".into(), "up".into()));
        assert!(pair.holds(Some("to-a id 8 state idle\nto-b id 7 state up peer -")));
        assert!(!pair.holds(Some("to-b id 7 state probing up 1")));
        for bad in [
            "5ms answer q extra",
            "5ms when=q answer q",
            "5ms when=~x answer q",
            "5ms when=q~ answer q",
            "5ms when=q.state answer q",
            "5ms when=.state=up answer q",
            "5ms when=q.=up answer q",
        ] {
            assert!(parse_step(0, bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn wire_and_unwire_steps() {
        assert_eq!(
            parse_step(0, "5ms wire r1 a1").unwrap().verb,
            Verb::Wire { cable: vec![0xa1] }
        );
        assert_eq!(
            parse_step(0, "5ms unwire r1 2").unwrap().verb,
            Verb::Unwire { port: 2 }
        );
        for bad in ["5ms wire r1 zz", "5ms unwire r1 x", "5ms unwire r1"] {
            assert!(parse_step(0, bad).is_err(), "{bad:?}");
        }
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

#[cfg(test)]
mod variable_tests {
    use super::*;

    #[test]
    fn variables_are_set_by_command_and_expanded_in_arguments() {
        let mut s = Script::default();
        assert_eq!(s.expand("to-b {peer}"), Err("peer".to_owned()));
        assert_eq!(s.set("peer 203.0.113.2:6081"), Ok("set"));
        assert_eq!(s.set("peer 203.0.113.2:6081"), Ok("unchanged"));
        assert_eq!(
            s.expand("to-b {peer}").as_deref(),
            Ok("to-b 203.0.113.2:6081")
        );
        assert_eq!(s.expand("{not a name} {").as_deref(), Ok("{not a name} {"));
        assert_eq!(s.variables(), "peer 203.0.113.2:6081");
        for bad in ["peer", "Peer x", "peer a b", ""] {
            assert!(s.set(bad).is_err(), "{bad:?}");
        }
    }
}
