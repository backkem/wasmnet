//! A ready-made admission for components controllers supply ([`ImportPolicy`]): which imports
//! a supplied component may have (`docs/design/topology-and-infra.md`).
//!
//! The host links the same imports for every device, so a policy only narrows what a supplied
//! component may use. It reads the component's imports by parsing it, without compiling
//! anything, so it costs little and runs before the bytes are kept or compiled.

use wasmparser::{Encoding, Parser, Payload};

/// The names a component imports at its top level (instances, functions, types), in the order
/// it declares them, with their versions (`wasi:clocks/monotonic-clock@0.3.0`). An import that
/// implements an interface under a name of its own (`implements`) also lists that interface.
/// Fails for bytes that are not a well-formed component: a core module, a truncated file, a
/// malformed section.
pub fn component_imports(bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    // How deep in nested modules and components the parser is: the top level is 1.
    let mut depth = 0usize;
    let mut started = false;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| format!("not a well-formed component: {e}"))?;
        match payload {
            Payload::Version { encoding, .. } => {
                depth += 1;
                if !started {
                    if encoding != Encoding::Component {
                        return Err("a core module, not a component".to_owned());
                    }
                    started = true;
                }
            }
            Payload::End(_) => depth = depth.saturating_sub(1),
            Payload::ComponentImportSection(reader) if depth == 1 => {
                for import in reader {
                    let import = import.map_err(|e| format!("not a well-formed component: {e}"))?;
                    names.push(import.name.full_name().into_owned());
                    if let Some(interface) = import.name.full_implements() {
                        names.push(interface.into_owned());
                    }
                }
            }
            _ => {}
        }
    }
    if !started {
        return Err("not a well-formed component: empty".to_owned());
    }
    Ok(names)
}

/// Which imports a supplied component may have: an allow list of patterns, checked against
/// every top-level import of the component ([`component_imports`]).
///
/// A pattern is an import name with or without its version (`wasi:config/store` allows
/// `wasi:config/store@0.2.0-rc.1`), or a prefix ending in `*` (`wasi:clocks/*` allows every
/// interface of `wasi:clocks`, `wasi:*` all of WASI). Anything no pattern allows refuses the
/// component, with the import named.
///
/// ```
/// use wasmnet_host::ImportPolicy;
/// let policy = ImportPolicy::new(["wasi:*", "wasmnet:link/*"]);
/// assert!(policy.allows("wasi:clocks/monotonic-clock@0.3.0"));
/// assert!(!policy.allows("wasmnet:infra/devices@0.1.2"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportPolicy {
    patterns: Vec<String>,
}

impl ImportPolicy {
    /// A policy that allows the imports `patterns` match.
    pub fn new<S: Into<String>>(patterns: impl IntoIterator<Item = S>) -> Self {
        Self {
            patterns: patterns.into_iter().map(Into::into).collect(),
        }
    }

    /// What an ordinary device or composed node imports and nothing more: WASI's clocks,
    /// random, CLI (environment, stdio, exit) and I/O, `wasi:config/store`, and
    /// `wasmnet:link`. No `wasmnet:infra` (a spec grants none anyway), no host extension's
    /// imports, no sockets or filesystem (which this host does not serve).
    pub fn devices() -> Self {
        Self::new([
            "wasi:clocks/*",
            "wasi:random/*",
            "wasi:cli/*",
            "wasi:io/*",
            "wasi:config/store",
            "wasmnet:link/*",
        ])
    }

    /// The same policy that also allows `patterns`.
    pub fn and<S: Into<String>>(mut self, patterns: impl IntoIterator<Item = S>) -> Self {
        self.patterns.extend(patterns.into_iter().map(Into::into));
        self
    }

    /// Whether some pattern allows the import `name`.
    pub fn allows(&self, name: &str) -> bool {
        let bare = name.split_once('@').map_or(name, |(n, _)| n);
        self.patterns.iter().any(|p| match p.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => p == name || p == bare,
        })
    }

    /// Accepts a component whose every import the policy allows; refuses one that is not a
    /// well-formed component, or names the first import it does not allow.
    pub fn check(&self, bytes: &[u8]) -> Result<(), String> {
        for name in component_imports(bytes)? {
            if !self.allows(&name) {
                return Err(format!(
                    "it imports `{name}`, which this network does not allow"
                ));
            }
        }
        Ok(())
    }

    /// The policy as a network's admission callback
    /// ([`Network::set_supply_admission`](crate::sim::Network::set_supply_admission)).
    pub fn admission(
        self,
    ) -> impl Fn(&wasmnet_core::Supplied<'_>) -> Result<(), String> + Send + Sync + 'static {
        move |supplied| self.check(supplied.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_match_names_with_or_without_versions() {
        let p = ImportPolicy::new(["wasi:config/store", "wasmnet:link/*"]);
        assert!(p.allows("wasi:config/store@0.2.0-rc.1"));
        assert!(p.allows("wasi:config/store"));
        assert!(!p.allows("wasi:config/store-more@0.2.0"));
        assert!(p.allows("wasmnet:link/wire@0.1.0"));
        assert!(!p.allows("wasmnet:linker/x"));
        assert!(!ImportPolicy::devices().allows("wasi:sockets/types@0.3.0"));
        assert!(
            ImportPolicy::devices()
                .and(["wasi:sockets/*"])
                .allows("wasi:sockets/types@0.3.0")
        );
    }

    #[test]
    fn malformed_bytes_and_core_modules_are_refused() {
        assert!(component_imports(b"").is_err());
        assert!(component_imports(b"not wasm").is_err());
        // A core module's header (version 1).
        assert!(component_imports(b"\0asm\x01\0\0\0").is_err());
        // An empty component (version 0x0d, layer 1): no imports.
        assert_eq!(
            component_imports(b"\0asm\x0d\0\x01\0").unwrap(),
            Vec::<String>::new()
        );
    }
}
