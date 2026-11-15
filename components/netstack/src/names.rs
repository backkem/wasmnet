//! `wasi:sockets/ip-name-lookup` for the node: IP literals and the static `hosts.<name>`
//! table from the node's config, like an `/etc/hosts`. A name in neither is looked up in DNS by the
//! [`crate::resolver`], when the node has DNS servers: the order of nsswitch's `files dns`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::config::is_host_name;

/// The `ip-name-lookup` error codes this resolver produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupError {
    InvalidArgument,
    NameUnresolvable,
    /// DNS: the servers timed out or answered `SERVFAIL`.
    TemporaryFailure,
    /// DNS: the servers refused the query.
    PermanentFailure,
}

impl LookupError {
    /// The WASI error-code name, for the journal.
    pub fn name(self) -> &'static str {
        match self {
            LookupError::InvalidArgument => "invalid-argument",
            LookupError::NameUnresolvable => "name-unresolvable",
            LookupError::TemporaryFailure => "temporary-resolver-failure",
            LookupError::PermanentFailure => "permanent-resolver-failure",
        }
    }
}

/// Resolves `name`: an IP literal is returned as is (an IPv4-mapped IPv6 literal as its IPv4
/// address, as WASI requires), a configured name (ASCII, case-insensitive, one trailing dot
/// allowed) gives its addresses in the configured order. Never succeeds with zero addresses.
pub fn resolve(
    hosts: &BTreeMap<String, Vec<IpAddr>>,
    name: &str,
) -> Result<Vec<IpAddr>, LookupError> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        return Ok(vec![ip]);
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    // No empty label and none over 63 bytes (RFC 1035 §2.3.4): the resolver must be able to put
    // the name in a query.
    let labels_fit = name.split('.').all(|l| (1..=63).contains(&l.len()));
    if !is_host_name(name) || !labels_fit {
        return Err(LookupError::InvalidArgument);
    }
    match hosts.get(&name.to_ascii_lowercase()) {
        Some(addrs) if !addrs.is_empty() => Ok(addrs.clone()),
        _ => Err(LookupError::NameUnresolvable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_names_and_errors() {
        let hosts = BTreeMap::from([(
            "server.internal".to_owned(),
            vec!["10.0.0.1".parse().unwrap(), "fd00::1".parse().unwrap()],
        )]);
        let ips = |v: &[&str]| -> Vec<IpAddr> { v.iter().map(|s| s.parse().unwrap()).collect() };
        assert_eq!(resolve(&hosts, "10.0.0.9"), Ok(ips(&["10.0.0.9"])));
        assert_eq!(resolve(&hosts, "fe80::1"), Ok(ips(&["fe80::1"])));
        assert_eq!(resolve(&hosts, "::ffff:10.0.0.7"), Ok(ips(&["10.0.0.7"])));
        assert_eq!(
            resolve(&hosts, "Server.INTERNAL."),
            Ok(ips(&["10.0.0.1", "fd00::1"]))
        );
        assert_eq!(
            resolve(&hosts, "other.internal"),
            Err(LookupError::NameUnresolvable)
        );
        assert_eq!(resolve(&hosts, ""), Err(LookupError::InvalidArgument));
        assert_eq!(resolve(&hosts, "a b"), Err(LookupError::InvalidArgument));
        assert_eq!(resolve(&hosts, "[::1]"), Err(LookupError::InvalidArgument));
        // Names no DNS query can carry.
        assert_eq!(resolve(&hosts, "a..b"), Err(LookupError::InvalidArgument));
        let long = format!("{}.lan", "a".repeat(64));
        assert_eq!(resolve(&hosts, &long), Err(LookupError::InvalidArgument));
    }
}
