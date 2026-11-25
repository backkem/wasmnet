# Configuration reference

This page lists every configuration key of every device and app in this workspace. The keys
listed are the ones the components' parsers accept; each section links the parser that is the
source of truth.

## How configuration reaches a device

A device gets its configuration once, before it is instantiated, as a flat map of string keys
to string values: `DeviceConfig`, a `BTreeMap<String, String>`
([crates/wasmnet-core/src/config.rs](../../crates/wasmnet-core/src/config.rs)). The map never
changes while the network runs. The device reads it through `wasi:config/store`, either one
key at a time (`get`) or all at once (`get-all`, in key order).

```rust
let server = network.device_with_config(
    "server",
    &http_server,
    config(&[
        ("mac", "02:00:00:00:00:01"),
        ("ipv4", "10.0.0.1/24"),
        ("app.http-server.listen", "0.0.0.0:80"),
    ]),
)?;
```

(from [crates/wasmnet-host/examples/http.rs](../../crates/wasmnet-host/examples/http.rs))

There is no nesting and no array type. Nested settings are dotted keys (`port0.ipv4`,
`pool.lan.range`), and a list is one value with comma-separated items (`10.0.0.1,fd00::1`).
List items are trimmed of surrounding spaces.

### Nodes: the netstack plus apps

A node is the netstack composed with one or more apps by a `compositions/<name>.wac` file,
built as `node-<name>.wasm`. The node has one config. It holds the netstack's keys, plus each app's keys under `app.<app>.`:

* The netstack skips every key that starts with `app.` and rejects every other key it does not
  know.
* Each app reads only the keys under its own prefix (`app_pairs` strips `app.<app>.`) and
  rejects an unknown key under that prefix. Keys of apps that are not in the node are ignored
  by everyone.

| Composition | Apps |
|---|---|
| [`dhcp-dns.wac`](../../compositions/dhcp-dns.wac) | `dhcp-server`, `dns-server` |
| [`http-get.wac`](../../compositions/http-get.wac) | `http-get` |
| [`http-lb.wac`](../../compositions/http-lb.wac) | `http-lb` |
| [`http-server.wac`](../../compositions/http-server.wac) | `http-server` |
| [`mdns-responder.wac`](../../compositions/mdns-responder.wac) | `mdns-responder` |
| [`mdns-web.wac`](../../compositions/mdns-web.wac) | `http-server`, `mdns-responder` |
| [`ping.wac`](../../compositions/ping.wac) | `ping` |
| [`replicas.wac`](../../compositions/replicas.wac) | `replicas` |
| [`traceroute.wac`](../../compositions/traceroute.wac) | `traceroute` |
| [`traceroute-ping.wac`](../../compositions/traceroute-ping.wac) | `traceroute`, `ping` |
| [`udp-echo-client.wac`](../../compositions/udp-echo-client.wac) | `udp-echo-client` |
| [`udp-echo-server.wac`](../../compositions/udp-echo-server.wac) | `udp-echo-server` |

### Invalid configuration

* **Devices** (netstack, switch, router, wan-port, blaster, reflector) log the error at level
  `error` through `wasmnet:link/log` and then trap: the device crashes when it is created.
* **Apps** log the error at level `error` and return an error from `wasi:cli/run`. The node
  and its other apps keep running.

Error messages name the key, the value and what was expected, for example
`config app.ping.count="0": expected 1..=1000`.

## Shared value syntax

### Durations

Parsed by `parse_duration` in
[crates/wasmnet-wire/src/duration.rs](../../crates/wasmnet-wire/src/duration.rs). A duration
is a non-negative decimal integer followed by an optional unit:

| Unit | Meaning |
|---|---|
| `s` | seconds |
| `ms` | milliseconds |
| `us` | microseconds |
| (none) | nanoseconds |
| `ns` | nanoseconds |

Examples: `3s`, `20ms`, `250us`, `7ns`, `42` (42 ns), `0ms`. There are no fractions (`1.5ms`
is rejected), no spaces (`10 ms`), no other units (`1h`, `10m`) and no negative values. A
value that overflows `u64` nanoseconds is rejected. All durations are virtual time. Where a
table says "above zero", `0` is rejected.

### MAC addresses

Parsed by `MacAddr::from_str` in
[crates/wasmnet-wire/src/mac.rs](../../crates/wasmnet-wire/src/mac.rs): six octets of exactly
two hex digits each, separated by `:`, in either case (`02:00:5e:10:00:01`,
`02:00:5E:10:00:01`). `2:00:5e:10:00:01` and `02-00-5e-10-00-01` are rejected. Most keys
also require a **unicast** address (bit 0 of the first octet clear).

When a device's own MAC is not configured, it is `MacAddr::local_from_seed` of a value drawn
from the device's seeded `wasi:random`: a locally administered unicast address that is the same
for the same seed.

### Other values

* **Booleans:** exactly `true` or `false`.
* **Integers:** plain decimal, within the range given in each table.
* **Addresses:** Rust's `Ipv4Addr`, `Ipv6Addr` and `SocketAddr` syntax: `10.0.0.1`,
  `fd00::1`, `10.0.0.1:80`, `[fd00::1]:80`. An address with a prefix is `addr/len`
  (`10.0.0.1/24`).
* **DNS names** (netstack `hostname`, dhcp-server `domain`, dns-server names): checked by
  `dns::valid_name` in [crates/wasmnet-wire/src/dns.rs](../../crates/wasmnet-wire/src/dns.rs):
  dot-separated labels of ASCII letters, digits, `-` and `_`, each 1 to 63 bytes and not
  starting or ending with `-`, at most 253 bytes in all, an optional trailing dot.

## Netstack

The TCP/IP stack of every node (smoltcp over Ethernet), with one port, `eth0`. It serves
`wasi:sockets` to the node's apps.

Source of truth: `Config::from_pairs` in
[components/netstack/src/config.rs](../../components/netstack/src/config.rs). It reads the
whole config with `get-all`. Every key is optional. Unknown keys are errors, except keys
under `app.`.

### Interface and addresses

| Key | Value | Default | Meaning |
|---|---|---|---|
| `mac` | unicast MAC | seeded (see above) | The interface's MAC address. |
| `mtu` | integer, 1280..=9000 | `1500` | IP MTU. A frame is MTU + 14 bytes. |
| `ipv4` | `addr/len` (len 0..=32), or `dhcp` | none: no IPv4 | A static IPv4 address and prefix. The address may not be unspecified, multicast or `255.255.255.255`. `dhcp` starts a DHCPv4 client that leases the address, the default gateway and the DNS servers. |
| `ipv4-gateway` | IPv4 address | none | The default IPv4 gateway. Not unspecified, multicast or broadcast. Requires a static `ipv4` (an error with `ipv4 = dhcp` or without `ipv4`). |
| `ipv6` | `addr/len` (len 0..=128) | none | A global IPv6 address and prefix. Not unspecified, multicast, loopback or link-local (`fe80::/10`). |
| `ipv6-link-local` | IPv6 address in `fe80::/10` | EUI-64 from the MAC | The link-local address (prefix /64). |
| `ipv6-gateway` | IPv6 address | none | The default IPv6 gateway (a link-local address is allowed). Not unspecified or multicast. |
| `hop-limit` | integer, 1..=255 | `64` | IPv4 TTL / IPv6 hop limit of unicast packets. |
| `multicast-hop-limit` | integer, 1..=255 | `1` | TTL / hop limit for multicast destinations; also the default of the `wasmnet:sockets-ext/multicast` hop limit. |

### Name lookup, DHCP and DNS

| Key | Value | Default | Meaning |
|---|---|---|---|
| `hosts.<name>` | one IP address or a comma-separated list (`10.0.0.1,fd00::1`) | none | A static entry for `ip-name-lookup`. `<name>` is ASCII letters, digits, `-` and `.`, 1 to 253 bytes, not starting or ending with `.`; it is matched case-insensitively. Addresses are returned in the configured order; the unspecified address is rejected. |
| `hostname` | DNS name | none | Host name sent in DHCP option 12 when `ipv4 = dhcp`. |
| `dns` | one IP address or a comma-separated list | the DHCP lease's servers | DNS servers for `ip-name-lookup`. Not unspecified, multicast or loopback. When set, they replace the servers a DHCP lease names. |
| `resolver.timeout` | duration above zero | `5s` | How long one DNS try waits for its answer. |
| `resolver.attempts` | integer, 1..=5 | `2` | Rounds over the DNS server list. |
| `resolver.mdns-timeout` | duration above zero | `1s` | How long one mDNS query for a `.local` name waits. |
| `resolver.mdns-attempts` | integer, 1..=5 | `3` | mDNS queries before a `.local` name is unresolvable. |

`ip-name-lookup` takes an IP literal as it is; otherwise it looks the name up in
`hosts.<name>`, then resolves a `.local` name with one-shot mDNS queries and any other name
through the DNS servers (if the node has any).

### TCP

| Key | Value | Default | Meaning |
|---|---|---|---|
| `tcp.congestion` | `reno` or `none` | `reno` | The congestion controller of every TCP connection the node opens or accepts: Reno with NewReno's fast recovery, or none (only the peer's receive window limits a sender, which puts it all on the wire at once). See [netstack.md](netstack.md#tcp-congestion-control). |

### Test and embedding keys

| Key | Value | Default | Meaning |
|---|---|---|---|
| `driver.timer-churn` | duration above zero | off | A stress mode for tests: on every pass, the stack's driver cancels its pending timer and arms a new one, at the stack's deadline or `now + churn`, whichever comes first. |
| `snapshot.paused` | `true` or `false` | `false` | Embedder surface, unstable. The node starts paused: it does nothing until its state is restored through `wasmnet:netstack/state`. A restore is only accepted on a paused node. Frames that arrive while it is paused are kept (up to 1024, the rest dropped) and handed to the restored stack. Set by an embedder that restores a saved stack before the node runs. |
| `app.<app>.<key>` | anything | | An app's own config, skipped by the netstack. |

## Network devices

### Switch

A learning Ethernet bridge (no VLANs, no STP) with ports `p0` to `p<N-1>`. It floods
broadcast, multicast and unknown unicast, and ages out MAC entries.

Source of truth: `Config::from_lookup` in
[components/switch/src/lib.rs](../../components/switch/src/lib.rs). It reads each key with
`get`; other keys are ignored. Every key is optional.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `ports` | integer, 1..=64 | `8` | Number of ports. |
| `aging` | duration above zero | `300s` | A MAC entry expires this long after the last frame from that MAC. |
| `max-entries` | integer, 1..=65536 | `1024` | MAC table capacity. When it is full, new MACs are not learned. |
| `mtu` | integer, 68..=65535 | `1500` | The MTU reported for every port. |

### Router

An IPv4/IPv6 router with ARP, NDP, ICMP, static routes, optional Router Advertisements and an
optional DHCP relay per port. Ports are named `p0` to `p<N-1>`.

Source of truth: `Config::from_pairs` and `parse_route` in
[components/router/src/config.rs](../../components/router/src/config.rs). It reads the whole
config with `get-all`. Unknown keys are errors. At least one port must exist.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `ports` | integer, 1..=16 | one more than the highest configured `port<N>` | Number of ports. It may add unconfigured ports, but an error is raised if a configured `port<N>` has `N >= ports`. With no `ports` and no `port<N>` key the config is rejected. |
| `mac` | unicast MAC | `02:52:00:00:00:00` | Base MAC: port N's default MAC is this address with N added to the last octet (wrapping). |
| `routes` | comma-separated list of routes (see below) | none | Static routes. |
| `ttl` | integer, 1..=255 | `64` | TTL / hop limit of packets the router originates (ICMP errors, echo replies, RSTs). |
| `neighbor.retry` | duration above zero | `1s` | Time between ARP requests / Neighbor Solicitations for one neighbor. |
| `neighbor.attempts` | integer, 1..=10 | `3` | Requests before a neighbor is unreachable. |
| `neighbor.queue` | integer, 1..=256 | `16` | Packets queued per unresolved neighbor; the oldest is dropped. |
| `neighbor.lifetime` | duration above zero | `300s` | How long a learned neighbor is trusted (checked when used). |
| `trace.route-lookup` | `first`, `all` or `none` | `first` | Which `route-lookup` events are logged: once per destination address, every one, or none. |
| `trace.ttl-decrement` | `first`, `all` or `none` | `first` | Which `ttl-decrement` events are logged: once per flow (protocol, addresses and ports), every one, or none. |

Per-port keys, `port<N>.<key>` with `N` in 0..=15 written without leading zeros (`port00` is
unknown):

| Key | Value | Default | Meaning |
|---|---|---|---|
| `port<N>.mac` | unicast MAC | from `mac` | The port's MAC. |
| `port<N>.mtu` | integer, 68..=9000; 1280..=9000 when the port has `ipv6` | `1500` | IP MTU. A frame is MTU + 14 bytes. |
| `port<N>.ipv4` | `addr/len` (len 0..=32) | none | The port's address and its connected route. Not unspecified, multicast, broadcast or loopback. |
| `port<N>.ipv6` | `addr/len` (len 0..=128) | none | A global address and its connected route. Not unspecified, multicast, loopback or link-local. |
| `port<N>.ipv6-link-local` | IPv6 address in `fe80::/10` | EUI-64 from the port's MAC | The port's link-local address. |
| `port<N>.ra` | `true` or `false` | `false` | Send a Router Advertisement when the link comes up and answer Router Solicitations. Requires `port<N>.ipv6` (the advertised prefix). |
| `port<N>.dhcp-relay` | one IPv4 address or a comma-separated list | none | DHCP servers to relay this port's DHCP client broadcasts to (an RFC 1542 relay agent, with the port's IPv4 address as `giaddr`). Requires `port<N>.ipv4`. The addresses may not be unspecified, multicast, broadcast or loopback. |

**Route syntax.** Each item of `routes` is whitespace-separated words:

```text
<destination> [via <next-hop>] [port <n>]
```

* `<destination>` is a prefix such as `10.0.3.0/24` or `fd00:3::/64` with no host bits set
  (`10.0.3.1/24` is rejected), or `default`, which means `0.0.0.0/0` or `::/0` by the family of
  `via` (so `default` needs `via`).
* At least one of `via` and `port` is required; each may appear once.
* `via` must be a unicast address of the destination's family.
* Without `port`, the next hop must lie inside a port's connected prefix; the lowest such port
  is used. A link-local next hop needs `port`.
* `port <n>` must name an existing port. `port` without `via` makes the destination on-link
  through that port.

Examples: `10.0.3.0/24 via 10.0.2.2`, `default via 10.0.2.2`, `fd00:3::/64 via fe80::2 port 1`,
`10.9.0.0/16 port 0`. A full value: `routes = "10.0.3.0/24 via 10.0.2.2,default via fd00:1::fe"`.

Besides the errors above, the component traps if `get-all` itself fails.

**Changing routes while it runs.** The config is read once, but the static routes can change
later through the router's commands (`wasmnet:control/commands`): `route-add <route>`,
`route-replace <route>`, `route-remove <prefix or route>` and `routes`, with routes in the
syntax above. An embedder sends them with `Network::command` or as operator events, a controller
with `wasmnet:infra/devices.control`; nothing else about the router (ports, neighbours, links,
counters) changes. Their semantics are in [wit/router/router.wit](../../wit/router/router.wit)
and [topology-and-infra.md](topology-and-infra.md#commands-into-a-running-device).

### WAN port

An L2 WAN port that bridges two segments over a WAN link with VXLAN-style encapsulation (RFC
7348). Port 0, `access`, faces the local segment; port 1, `wan`, faces the peer WAN port.

Source of truth: `Config::from_lookup` in
[components/wan-port/src/lib.rs](../../components/wan-port/src/lib.rs). It reads each key
with `get`; other keys are ignored.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `ip` | IPv4 address | **required** | This port's WAN-side IPv4 address (outer source). |
| `peer-ip` | IPv4 address | **required** | The peer WAN port's IPv4 address (outer destination). |
| `mac` | unicast MAC | **required** | This port's WAN-side MAC. |
| `peer-mac` | MAC | `ff:ff:ff:ff:ff:ff` | The peer's WAN-side MAC (outer destination MAC). |
| `vni` | integer, 0..=16777215 | `1` | The VXLAN network identifier. Frames with another VNI are dropped. |
| `mtu` | integer, 68..=65000 | `1500` | The access port's MTU. The `wan` port declares `mtu + 54` (50 bytes of encapsulation plus room for an 802.1Q tag on the inner frame). |
| `udp-port` | integer, 1..=65535 | `4789` | The outer UDP destination port. |

## Apps

Every app below reads its keys under `app.<app>.` from its node's config. The tables give the
key without that prefix: `listen` in the http-server table is `app.http-server.listen` in the
node's config.

### dhcp-server

A DHCPv4 server (RFC 2131) with per-subnet pools, reservations, and service to remote subnets
through relay agents (the router's `port<N>.dhcp-relay`). It never returns.

Source of truth: `Config::from_pairs` in
[components/apps/dhcp-server/src/lib.rs](../../components/apps/dhcp-server/src/lib.rs).
Unknown keys are errors.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `server-id` | IPv4 address | **required** | This server's address (option 54). Requests that are neither relayed nor renewing are served from the pool whose subnet holds it. |
| `listen` | IPv4 socket address | `0.0.0.0:67` | The local UDP socket address. |

At least one pool is required. A pool is a family of keys `pool.<name>.<key>`; `<name>` is
any non-empty text (it may contain dots: the last dot separates the key).

| Key | Value | Default | Meaning |
|---|---|---|---|
| `pool.<name>.subnet` | `addr/len` IPv4 (len 0..=32) | **required** | The pool's subnet; host bits are cleared. Its mask is option 1. |
| `pool.<name>.range` | `first-last`, two IPv4 addresses | **required** | The dynamic addresses, for example `10.0.2.100-10.0.2.199`. Both ends must lie in the subnet, and `first <= last`. |
| `pool.<name>.router` | IPv4 address | none | Option 3. |
| `pool.<name>.dns` | one IPv4 address or a comma-separated list | none | Option 6. |
| `pool.<name>.domain` | DNS name | none | Option 15. |
| `pool.<name>.lease` | duration in whole seconds, at least `1s`, at most `4294967295s` | `3600s` | Lease time (option 51). |
| `pool.<name>.reserve` | comma-separated list of `mac=ip` | none | Fixed addresses, for example `02:00:00:00:01:10=10.0.1.10`. Each IP must lie in the subnet. |

### dns-server

An authoritative DNS server (RFC 1035) for static zones, over UDP. It does not recurse; a name
outside its zones is answered `REFUSED`. It never returns.

Source of truth: `Config::from_pairs` in
[components/apps/dns-server/src/lib.rs](../../components/apps/dns-server/src/lib.rs). Unknown
keys are errors.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `zone` | DNS name, or a comma-separated list | **required** | The zones it is authoritative for (`internal`). Stored lowercase, without a trailing dot. |
| `listen` | socket address | `0.0.0.0:53` | The local UDP socket address (`[::]:53` for IPv6). |
| `ttl` | duration in whole seconds (`0s` allowed), at most `4294967295s` | `60s` | The TTL of every record. |
| `records.<name>` | one IP address or a comma-separated list | none | A and AAAA records for `<name>` (IPv4 addresses become A, IPv6 addresses AAAA). |
| `cname.<name>` | DNS name | none | `<name>` is an alias of the value (a CNAME record). A name with a CNAME may have no other record. |

`<name>` in `records.<name>` and `cname.<name>` must be a valid DNS name. A name (or CNAME
target) that is not inside a zone and does not end with a dot is relative to the first zone:
with `zone = internal`, `records.web` is `web.internal`, and `cname.out = example.com.` points
outside the zones. Names match case-insensitively.

### http-get

An HTTP/1.1 client. It fetches the configured URLs one after the other and exits: `ok` when
every fetch succeeded or was aborted on purpose, an error otherwise.

Source of truth: `Config::from_pairs` and `Url::parse` in
[components/apps/http-get/src/lib.rs](../../components/apps/http-get/src/lib.rs). Unknown keys
are errors.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `url` | URL | | One URL to fetch. |
| `urls` | comma-separated list of URLs | | More URLs; `url` comes first, then `urls`. At least one URL is **required** unless `console = true`. |
| `keep-alive` | `true` or `false` | `false` | `true`: send `Connection: keep-alive` and reuse one connection for consecutive URLs on the same host and port. `false`: one connection per URL, `Connection: close`. |
| `start` | duration | `0` | Wait before the first request. |
| `interval` | duration | `0` | Wait between two requests. |
| `request-delay` | duration | `0` | Wait between opening a connection and sending its first request. |
| `recv-buffer` | integer, 1..=1073741824 | the netstack's | Receive buffer size in bytes, set before `connect` (the TCP window). |
| `send-buffer` | integer, 1..=1073741824 | the netstack's | Send buffer size in bytes, set before `connect`. |
| `read-size` | integer, 1..=1048576 | `65536` | Bytes asked for per stream read. |
| `read-pause` | duration | `0` | Wait after each read (a slow reader). |
| `abort-after` | integer, 0..=18446744073709551615 | never | Abort the connection (`wasmnet:sockets-ext/tcp.abort`, an RST) once this many body bytes have arrived. |
| `no-delay` | `true` or `false` | `false` | Set `TCP_NODELAY`. |
| `proxy` | `http://host:port` | none | Embedder surface, unstable. A forward proxy. Every request goes there with its absolute URL. `https://` URLs are only allowed with a proxy. |
| `accept` | text | `*/*` | The `Accept:` header. |
| `repeat` | integer, 1..=1000000, or `forever` | `1` | How many times the URL list is fetched. |
| `quiet` | `true` or `false` | `false` | Journal only `http-get-done` and errors per request (no connected, response or closed events, no info lines). |
| `console` | `true` or `false` | `false` | After the URLs, read requests from stdin (see below). |
| `half-close` | `true` or `false` | `false` | Send the client's FIN right after each request, before the response arrives. Connections are then not reused, whatever `keep-alive` says. |

**URL syntax:** `http://host[:port][/path[?query]]` or `https://...`. `host` is an IP literal
(`[fd00::1]` for IPv6) or a name the netstack resolves (for example from its `hosts.<name>`
table). The port defaults to 80 (443 for `https://`) and must be 1..=65535. The path defaults
to `/`. User info (`@`), spaces and fragments (`#`) are rejected.

**stdin (with `console = true`):** one request per line, `METHOD URL [BODY]`. `METHOD` is
`GET`, `PUT`, `POST`, `DELETE` or `PATCH` (any case); `URL` must be `http://`; the body is
the rest of the line, trimmed, sent with `Content-Length`. Empty lines and lines starting with
`#` are skipped. Each request uses its own connection. The app prints `> METHOD URL`, then
`< status reason` and the body lines indented by two spaces (or `< failed`, or `? <error>` for
a line it cannot parse) to stdout. It reads until stdin ends.

### http-lb

An HTTP/1.1 load balancer. It proxies each client request to one healthy backend, chosen
round-robin or at random (from the node's seeded `wasi:random`), checks backends with a real
`GET` on an interval, and serves an admin API on a second address. It never returns.

Source of truth: `Config::from_pairs` in
[components/apps/http-lb/src/lib.rs](../../components/apps/http-lb/src/lib.rs). Unknown keys
are errors.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `listen` | socket address | `0.0.0.0:80` | The client-facing address. |
| `admin` | socket address | `0.0.0.0:8080` | The admin API's address. It must differ from `listen`. |
| `policy` | `round-robin` or `random` | `round-robin` | How a backend is chosen. |
| `backend.<name>` | socket address `ip:port` | none | A backend registered at start. `<name>` is `a-z`, `0-9` and `-`, 1 to 32 characters. |
| `health.path` | path starting with `/`, no spaces | `/healthz` | The health check's request target. |
| `health.interval` | duration | `1s` | Time between two checks of one backend. |
| `health.timeout` | duration | `250ms` | A check that has not answered by then failed. |
| `health.healthy` | integer, 1..=10 | `1` | Consecutive passes that put a backend in rotation. |
| `health.unhealthy` | integer, 1..=10 | `2` | Consecutive failures that take it out. |
| `connect-timeout` | duration | `300ms` | A proxied request whose backend connection is not up by then fails with `502`. |
| `timeout` | duration | `2s` | Reading a client's request (head and body) must finish by then, or the connection is closed; a proxied request whose response has not fully arrived by then fails with `504`. |

A duration of `0` for `health.interval`, `health.timeout`, `connect-timeout` or `timeout` is
taken as 1 ns.

Backends can also be changed at run time through the admin API, one request per connection:
`GET /backends`, `PUT /backends/<name>` with the body `ip:port`, `DELETE /backends/<name>`,
`GET /policy`, and `PUT /policy` with the body `round-robin` or `random`. The pool holds at most
1024 backends; a `PUT` of a new name past that is answered `503`.

### http-server

A small HTTP/1.1 server with static routes, a generated body (`GET /big?n=<bytes>`),
`POST /echo` (answers its body back, at most 1 MiB; embedder surface, unstable), optional
event-stream routes (embedder surface, unstable) and an
optional health route. It never returns.

Source of truth: `Config::from_pairs` in
[components/apps/http-server/src/lib.rs](../../components/apps/http-server/src/lib.rs).
Unknown keys are errors.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `listen` | socket address, or a comma-separated list | `0.0.0.0:80` | One listener per address. A dual-stack server lists one address per family (`10.0.1.10:80,[fd00:1::10]:80`). |
| `backlog` | integer, 1..=1024 | the netstack's | The listen backlog hint. |
| `keep-alive` | `true` or `false` | `true` | `true`: honour persistent connections. `false`: `Connection: close` after every response. |
| `max-requests` | integer, 1..=100000 | `100` | Requests per connection before the server closes it. |
| `no-delay` | `true` or `false` | `false` | Set `TCP_NODELAY` on every accepted connection. |
| `recv-buffer` | integer, 1..=1073741824 | the netstack's | The listener's receive buffer size in bytes (inherited by accepted connections). |
| `send-buffer` | integer, 1..=1073741824 | the netstack's | The listener's send buffer size in bytes. |
| `big-max` | integer, 0..=4294967296 | `16777216` | The largest `/big?n=` body in bytes. |
| `instance` | 1 to 32 of letters, digits, `-`, `.`, `_` | none | Sent as `X-Instance` on every response; replaces `{instance}` in route bodies. |
| `version` | 1 to 32 of letters, digits, `-`, `.`, `_` | none | Sent as `X-Version` on every response; replaces `{version}` in route bodies. |
| `health` | path starting with `/`, no spaces or `?` | none; `/healthz` when `ready-after` is set | A health route: `GET` answers `503 not ready` until `ready-after` has passed, then `200 ok`. |
| `ready-after` | duration | `0` | Virtual time after the app started before the health route answers `200`. Setting it enables the health route. |

Routes are families of keys `route.<name>.<field>`; `<name>` is any text (the last dot
separates the field), and routes are served in name order.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `route.<name>.path` | path starting with `/`, no spaces or `?` | **required** per route | The route's path. |
| `route.<name>.body` | text | empty | The body. |
| `route.<name>.type` | non-empty text | `text/plain` | The `Content-Type`. |
| `route.<name>.sse-events` | integer, 1..=100000 | none | Embedder surface, unstable. Makes the route an event stream (`text/event-stream`, `GET` only) of events `1..=N`. |
| `route.<name>.sse-interval-ms` | integer, 0..=60000 | `1000` | Milliseconds of virtual time between two events. Requires `sse-events`. |

Without any route, `GET /` answers `hello from wasmnet\n`; with `instance` set it answers
`<instance> <version>\n` (or `<instance>\n` without `version`).

### mdns-responder

A Multicast DNS responder (RFC 6762) for one host name: it probes for `<hostname>.local`,
announces it, renames itself (`<hostname>-2`, ...) on a conflict, and answers A and AAAA
questions with the node's addresses. It never returns.

Source of truth: `Config::from_pairs` in
[components/apps/mdns-responder/src/lib.rs](../../components/apps/mdns-responder/src/lib.rs).
Unknown keys are errors.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `hostname` | one host name label: letters, digits and `-` (no dots, no `_`) | **required** | The name to claim: `alice` claims `alice.local`. Stored lowercase. |
| `families` | `ipv4`, `ipv6`, or both as a comma-separated list | `ipv4,ipv6` | The groups to listen on: `224.0.0.251` and `ff02::fb`. |
| `ttl` | duration in whole seconds, at least `1s`, at most `4294967295s` | `120s` | The TTL of its records. |
| `link-local` | `true` or `false` | `false` | Also announce IPv6 link-local addresses. |
| `start` | duration | `0` | Wait before probing. |

### ping

ICMP echo through `wasmnet:sockets-ext/icmp` (see [socket-extensions.md](socket-extensions.md)).
It runs one or more sessions concurrently and exits `ok` when every session got at least one
reply.

Source of truth: `sessions` in
[components/apps/ping/src/lib.rs](../../components/apps/ping/src/lib.rs). Unknown keys are
errors, and at least one session is required.

A session's keys are either unnamed (`app.ping.target`, the session called `ping`) or named
(`app.ping.<name>.target`, where `<name>` has no dots). Both forms may be used together;
sessions run in name order.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `target` | host name or IP literal | **required** per session | What to ping; a name resolves through the netstack (`hosts.<name>`, mDNS, DNS). |
| `count` | integer, 1..=1000 | `3` | Echo requests to send. |
| `interval` | duration above zero | `1s` | Time between requests. |
| `start` | duration | `0` | Virtual time of the first request. |
| `timeout` | duration above zero | `1s` | How long a request waits for its reply. |
| `size` | integer, 0..=1452 | `56` | Payload bytes. |
| `ttl` | integer, 1..=255 | the node's default | The requests' TTL / hop limit. |

### replicas

An in-world controller that keeps `replicas` instances of a template device running through
`wasmnet:infra`, and optionally registers them with a load balancer's admin API over TCP. Its
node must be granted `wasmnet:infra` by the embedder (`DeviceOptions::infra`; see
[topology-and-infra.md](topology-and-infra.md)). It never returns.

Source of truth: `Config::from_pairs` and `Config::expand` in
[components/apps/replicas/src/lib.rs](../../components/apps/replicas/src/lib.rs). Unknown keys
are errors.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `replicas` | integer, 0..=`max` | `1` | How many instances to keep. |
| `max` | integer (`u32`) | `16` | The most `replicas` may become, from config or stdin. |
| `prefix` | 1 to 32 of ASCII letters, digits and `-` | `web` | Instances are named `<prefix>-1` to `<prefix>-N` and labelled `replicas=<prefix>`. |
| `period` | duration | `500ms` | Time between two reconciles. `0` is taken as 1 ns. |
| `start` | duration | `0` | Wait before the first reconcile. |
| `grace` | duration | `0` | A removed instance keeps running this long (a stop with grace). |
| `template.component` | catalog name | **required** | The component instances are made from (`node:http-server`). |
| `template.stdio` | `journal` or `capture` | not set | The instances' `stdio` option: `journal` journals stdout and stderr lines, `capture` only captures them. Any other value is a config error. Not set means `capture`. |
| `template.fuel_per_instant` | integer, optionally followed by `K`, `M` or `G` (×1000, ×10⁶, ×10⁹) | the network's | The instances' fuel per virtual instant (`50M`, `4G`). |
| `template.config.<key>` | text (templated) | | The instances' config key `<key>`. |
| `template.wire.<i>.port` | integer | `0` | Cable `<i>`: the instance's own port. `<i>` is an integer index; cables are applied in index order. |
| `template.wire.<i>.to` | text (templated) | **required** per cable | Cable `<i>`: the far end, `device` (its first free port) or `device:port`. |
| `template.wire.<i>.latency` | duration | `0` | Cable `<i>`: its latency. |
| `backend` | text (templated) | not set | What to register for instance n (`10.0.1.{n}:80`). Not set: no load balancer. |
| `lb` | IPv4 socket address | **required** with `backend` | The load balancer's admin address. |
| `register` | `METHOD /path` (templated, also `{backend}`) | `PUT /backends/{name}` | The request that registers an instance. `METHOD` is uppercase ASCII letters. |
| `register-body` | text (templated, also `{backend}`) | `{backend}` | Its body. A body starting with `{` is sent as `application/json`. |
| `deregister` | `METHOD /path` (templated, also `{backend}`) | `DELETE /backends/{name}` | The request that deregisters an instance. |
| `half-close` | `true` or `false` | `false` | `true`: each admin request leaves with its FIN right behind it. `false`: the FIN goes after the response. |

**Templates.** In templated values, `{n:02x}` is the instance number in two-digit hex, `{n}`
the instance number, `{n+K}` the instance number plus the integer K (`10.0.1.{n+10}`),
`{name}` the instance name and `{prefix}` the prefix. `register`, `register-body` and
`deregister` also have `{backend}`, the expanded `backend`.

The defaults speak http-lb's admin API: `PUT /backends/<name>` with the address as the body
registers a backend, `DELETE /backends/<name>` deregisters it. For another load balancer, set
`register`, `register-body` and `deregister` (an empty `register-body` sends no body).

**stdin:** lines `replicas=N` (spaces around `=` allowed) change the desired count at run time;
`N` must be at most `max`. Other non-empty lines are logged as warnings and ignored.

### traceroute

The classic UDP traceroute: for each target, probes with increasing hop limits to destination
ports from `port` upward, reading the ICMP errors through `wasmnet:sockets-ext/udp`. Probes
are sequential. It exits `ok` when every target was reached.

Source of truth: `Config::from_pairs` in
[components/apps/traceroute/src/lib.rs](../../components/apps/traceroute/src/lib.rs). Unknown
keys are errors.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `target` | host name or IP literal, or a comma-separated list | | What to trace. |
| `targets` | comma-separated list | | More targets; `target` and `targets` add up in config order. At least one target is **required**. |
| `max-hops` | integer, 1..=64 | `30` | The highest hop limit tried. |
| `queries` | integer, 1..=10 | `3` | Probes per hop. |
| `wait` | duration above zero | `1s` | How long a probe waits for its ICMP error. |
| `port` | integer, 1..=65000 | `33434` | The first destination port; each probe uses the next one. |
| `size` | integer, 0..=1400 | `32` | Probe payload bytes. |
| `start` | duration | `0` | Virtual time of the first probe. |
| `gap` | duration | `0` | Virtual time between two traces. |

### udp-echo-client

Sends `count` UDP datagrams to an echo server, one at a time, waits for each echo, measures
round-trip times and exits: `ok` when every datagram came back, an error otherwise.

Source of truth: `Config::from_pairs` in
[components/apps/udp-echo-client/src/lib.rs](../../components/apps/udp-echo-client/src/lib.rs).
Unknown keys are errors.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `target` | IP address or host name | **required** | The server; a name resolves through the netstack. |
| `port` | integer, 1..=65535 | `7` | The server's UDP port. |
| `count` | integer, 1..=1000 | `3` | Datagrams to send. |
| `interval` | duration above zero | `1s` | Time between the scheduled sends. A send never starts before the previous datagram was answered or timed out. |
| `size` | integer, 4..=65507 | `32` | Payload bytes; the first 4 are the sequence number. |
| `timeout` | duration above zero | `1s` | How long to wait for each echo. |
| `start` | duration | `0` | Wait before resolving the target. |

### udp-echo-server

Sends every UDP datagram it receives back to its sender (RFC 862 style). Without `count` it
never returns.

Source of truth: `Config::from_pairs` in
[components/apps/udp-echo-server/src/lib.rs](../../components/apps/udp-echo-server/src/lib.rs).
Unknown keys are errors.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `listen` | socket address | `0.0.0.0:7` | The local socket address (`[::]:7` for IPv6). |
| `count` | integer, at least 1 (`u32`) | never | Exit after echoing this many datagrams. |
| `copies` | integer, 1..=16 | `1` | How many times each datagram is sent back, back to back (more than one makes a duplicating server, for tests). |

## Test fixtures

These components exist for the host's own tests. They are not part of a node.

### blaster (test fixture)

A stepped device with one port, `eth0`, that sends a train of raw Ethernet probe frames
(EtherType `0x88b5`) and counts the echoes it gets back.

Source of truth: `Config::from_lookup` in
[components/blaster/src/lib.rs](../../components/blaster/src/lib.rs). It reads each key with
`get`; other keys are ignored. Every key is optional.

| Key | Value | Default | Meaning |
|---|---|---|---|
| `mac` | unicast MAC | seeded | Its own MAC. |
| `dst` | MAC | `ff:ff:ff:ff:ff:ff` | The probes' destination MAC. |
| `schedule` | comma-separated durations, non-decreasing, at most 100000 | none | The exact send time of each probe. May not be combined with `count`, `interval` or `start`. |
| `count` | integer, 0..=100000 | `8` | Number of probes (without `schedule`). |
| `interval` | duration | `1ms` | Time between probes (without `schedule`). |
| `start` | duration | `0` | Send time of the first probe (without `schedule`). |

### reflector (test fixture)

A stepped device with one port, `eth0`, that echoes every frame addressed to its MAC, to
broadcast or to a multicast group back out of the port it came in on, from its own MAC.

Source of truth: `mac_from_config` in
[components/reflector/src/lib.rs](../../components/reflector/src/lib.rs).

| Key | Value | Default | Meaning |
|---|---|---|---|
| `mac` | unicast MAC | seeded | Its own MAC. |

The `async-device` build of the reflector
([components/reflector/src/component_async.rs](../../components/reflector/src/component_async.rs))
reads no config: its MAC is always seeded.

### clock-probe (test fixture)

A plain `wasm32-wasip2` command that samples clocks and random sources twice and prints them
to stdout. It reads no configuration
([components/clock-probe/src/main.rs](../../components/clock-probe/src/main.rs)).

## Example: a full node config

`node-mdns-web.wasm` (netstack, http-server and mdns-responder), leasing its address with
DHCP and claiming `web.local`:

```text
mac                          = 02:00:00:00:01:10
ipv4                         = dhcp
hostname                     = web
ipv6                         = fd00:1::10/64
app.http-server.listen       = 0.0.0.0:80
app.http-server.instance     = web-1
app.http-server.route.home.path = /
app.http-server.route.home.body = hello from {instance}
app.mdns-responder.hostname  = web
app.mdns-responder.families  = ipv4,ipv6
```

As `DeviceConfig` pairs, each line is one `(key, value)` entry, for example
`("app.http-server.route.home.path", "/")`.
