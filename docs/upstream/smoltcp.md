# smoltcp: issues found while building wasmnet

Pinned version: **smoltcp =0.14.0** (`Medium::Ethernet`, features as in `components/netstack/Cargo.toml`), **vendored with two patches** (`third_party/smoltcp`, `[patch.crates-io]`; #2 and #28 below). This is a running list of upstream bugs, spec deviations and API gaps that we hit, with the part of wasmnet where each was found and how we work around it today. Keep it current. When something gets filed upstream, add the link. When a fix lands, note the version and remove our workaround.

These are our own notes from building one stack on smoltcp. Unless the last column says so, an
entry has not been reported upstream yet, and some may turn out to be our misreading: check
against the source before relying on one.

Legend: **bug**: violates an RFC or is clearly wrong. **gap**: missing behaviour or API that real stacks have. **quirk**: correct but surprising and worth documenting.

| # | Kind | Issue | Found in | Our workaround | Upstream |
|---|---|---|---|---|---|
| 1 | bug | **MLDv2 record types are swapped.** A join is sent as `CHANGE_TO_INCLUDE_MODE` with 0 sources, which RFC 3810 §6.1 defines as a *leave*. A leave is sent as `CHANGE_TO_EXCLUDE_MODE`. It breaks MLD-snooping switches and Wireshark's reading. | any MLD-snooping switch or capture reading a join or leave | Our switch must not depend on smoltcp's MLD record types. | not filed |
| 2 | bug | **Neighbour discovery is rate-limited per interface, not per neighbour.** There is one `silent_until` in `neighbor::Cache`, so after any ARP request or NS the next one, for *any* address, waits 1 s. A socket that hits the limit then backs off for its own second. | netstack (ping), UDP sockets, router and traceroute | **Fixed in our vendored smoltcp**: `third_party/smoltcp` + `[patch.crates-io]`, a per-address `silent_until` (bounded map), 3 tests. A host now resolves several neighbours within a second, with no hand spacing between its first packets to them. | patch ready ([below](#upstream-ready-patch-per-address-neighbour-rate-limit-2), `smoltcp-0001-neighbor-rate-limit-per-address.patch`), not filed |
| 3 | gap | **`poll_at` ignores multicast work.** After a join/leave, `poll_at` returns `None` even though an IGMP/MLD report is pending, and query-response timers are invisible. | multicast joins and leaves | The netstack polls after every control-plane call and keeps its own multicast deadline (polls every 1 ms through a query's max-response window). | not filed |
| 4 | gap | **ICMP errors are ignored by TCP and UDP sockets.** Unreachable, port-unreachable and the rest never reach the socket, so a connect to an unroutable host retries for the full 75 s timeout, and there's no `ECONNREFUSED` for UDP. | router, ICMP errors and traceroute | The netstack classifies received ICMP errors itself, journals `icmp-error-received`, fails SYN-SENT connects with `remote-unreachable`, and exposes `IP_RECVERR`-style errors via `wasmnet:sockets-ext/udp`. | not filed |
| 5 | gap | **No TCP listen backlog.** One LISTEN socket takes one SYN, so simultaneous SYNs get RST. When our N-socket backlog is full, a further SYN is answered with RST, whereas Linux drops it silently. | servers that accept several simultaneous connections | The backlog is N LISTEN sockets per port, honouring `set-listen-backlog-size` (1..=64, default 8). | not filed |
| 6 | gap | **No close reason.** A closed socket doesn't say whether it ended by FIN or RST. | reporting why a TCP connection ended | The netstack infers it from the state history (was the peer's FIN ever seen?). That's a heuristic. | not filed |
| 7 | gap | **Wildcard binds ignore address family.** A datagram goes to the first socket that accepts it regardless of family, so `0.0.0.0:p` and `[::]:p` can't coexist. A `0.0.0.0` TCP listener also takes IPv6. Linux allows this with `IPV6_V6ONLY`. | UDP sockets, dual-stack servers | **Fixed in the netstack**: bindings of different families never conflict; after every poll, UDP datagrams on a port bound by both families are moved to their family's socket (`UdpSockets::demux`) and a TCP connection caught by the other family's listener is handed to its own (`TcpSockets::after_poll`). A server with one dual-stack socket serves IPv4 and IPv6 clients. An upstream fix would let a socket ask for one family (a `V6ONLY`-like flag on `IpListenEndpoint` matching). | not filed |
| 8 | bug | **Oversize UDP is silently dropped.** `send_slice` accepts a payload above the MTU (>1472 B at 1500), and it's then dropped at dispatch with no error to the app. This also happened with `proto-ipv4-fragmentation` at default buffer sizes (not investigated). | UDP sends above the MTU | The netstack returns `datagram-too-large` before handing the datagram to smoltcp. | not filed |
| 9 | gap | **Hop limit is per socket, applied at dispatch.** It can't be set per datagram, so a datagram queued before a `set_hop_limit` leaves with the new value. | traceroute, multicast and mDNS | **Per-datagram stamping in the netstack**: `send` sets the socket's hop limit to the datagram's (unicast or multicast), and waits for the queue to drain first if queued datagrams carry another one (`udp-hop-limit-waits`). | not filed |
| 10 | quirk | **Only one unsolicited IGMP report per join** (RFC 2236 suggests repeating it). A lossy link can lose a join. | multicast joins on a lossy link | None yet. Lossy-link impairments will show it. | not filed |
| 11 | quirk | **No minimum Ethernet frame padding:** ARP frames are 42 B, below the 60 B minimum. | ARP requests on an Ethernet link | The netstack pads transmitted frames to 60 B. | not filed |
| 12 | quirk | **The IPv4 identification is always 0** (DF is set on every packet), so the seed only shows up in TCP ISNs and MLD delays. | netstack (ping) | None needed. Determinism tests account for it. | — |
| 13 | quirk | **`poll_at` returns `Instant::ZERO` to mean "now".** | scheduling the stack's next wake-up | Clamp with `max(now)`. | — |
| 14 | quirk | **The multicast hop limit defaults to 64.** mDNS requires 255. | multicast sends (mDNS) | The `multicast-hop-limit` config key. | — |
| 15 | quirk | **The handshake's final ACK and the first data go as two segments.** An abort with data in flight answers every in-flight segment with a bare RST (44 RSTs in an HTTP test): correct, but noisy. | aborting a TCP connection with data in flight | None. | — |
| 16 | quirk | **Keep-alive has a single interval plus timeout,** with no Linux-style idle/interval/count triple. | TCP sockets | Approximated. | — |
| 17 | quirk | **Time is in i64 microseconds,** so sub-µs link latencies collapse into one instant. | link latencies below 1 µs | Convert ns ↔ µs at the boundary and keep link latencies in whole µs. | — |
| 18 | quirk | **Enabling keep-alive on an idle connection sends a probe at once.** `Socket::set_keep_alive` arms the keep-alive timer at `Instant::ZERO` (`Timer::set_keep_alive`), so the first probe (1 byte, `seq = SND.UNA - 1`) leaves at the next poll instead of after the idle time. Linux waits `tcp_keepalive_time`. | a server that sets `SO_KEEPALIVE` after `accept` | None; harmless (one probe and its ACK per connection). | not filed |
| 19 | quirk | **The DHCP client never sets the broadcast flag.** It can receive a unicast OFFER/ACK before it has an address (`process_ipv4` hands UDP 67→68 to the DHCP socket before the destination check), so this is legal, but a server must then unicast to `yiaddr` at `chaddr`, which a server on ordinary sockets cannot do without a raw ARP entry. | DHCP and DNS | Our `dhcp-server` broadcasts on-link replies (RFC 2131 §4.1 allows it); the router's relay unicasts to `chaddr`. | — |
| 20 | bug | **A renewal is unicast to the OFFER's IP source, not to the server identifier.** `ServerInfo.address` is the IP source of the accepted OFFER, which for a relayed lease is the relay agent; RFC 2131 §4.3.2/§4.4.5 send the RENEWING REQUEST to the server (option 54). | DHCP and DNS, a lease relayed by the router | The router's relay agent also relays requests addressed to itself (RFC 1542 §4.1.1), so renewals of relayed leases still work (through the relay). | not filed |
| 21 | gap | **The DHCP `Config` has no lease time, no domain name and no other options.** Only address, router, DNS servers and the server's address. | DHCP and DNS | `set_receive_packet_buffer` (a buffer leaked once per stack, as smoltcp borrows it for the socket's lifetime) and our own parse of the ACK (`wasmnet_wire::dhcp`). With the buffer set, every ACK (renewals too) is reported as `Configured`, which we use to journal renewals. | not filed |
| 22 | quirk | **A fresh DHCP socket reports `Deconfigured` at its first `poll()`** (its `config_changed` starts true), although it was never configured. | DHCP and DNS | Ignored when no lease is held. | — |
| 23 | gap | **The DHCP client sends no RELEASE and no DECLINE, does not ARP-probe the offered address (RFC 5227), and always sends `secs = 0`.** It also skips RFC 2131 §4.4.1's random 1–10 s delay before the first DISCOVER (handy for exact test timelines). | DHCP and DNS | None needed so far; the server implements RELEASE and DECLINE for other clients. | — |
| 24 | gap | **`socket-dns` ignores ICMP errors** (like #4) and offers one query type per call, no search list and no hooks for ids or ports. | DHCP and DNS | Not used: the netstack has its own stub resolver over its UDP sockets (`resolver.rs`), which fails a lookup one round trip after a port unreachable. | — |
| 25 | quirk | **The interface holds 4 multicast groups by default** (`IFACE_MAX_MULTICAST_GROUP_COUNT`), and the IPv6 solicited-node groups take some. A join beyond the table is `GroupTableFull`. Joins are lazy (the report leaves at the next poll, see #3), and leaving a group that is still `Joining` sends no leave report. | multicast and mDNS | `iface-max-multicast-group-count-16`; the netstack reconciles the apps' memberships at every pass and keeps its own multicast deadline. | — |
| 26 | gap | **No multicast loopback:** a datagram sent to a group the interface joined is never delivered to the node's own sockets (POSIX `IP_MULTICAST_LOOP` is on by default). | multicast and mDNS | The netstack pushes a copy of such a datagram back into its receive queue when the sending socket keeps `multicast-loopback` on. | not filed |
| 27 | gap | **A UDP datagram is delivered to one socket only**, the first that accepts it, even for multicast (Linux delivers a group datagram to every socket bound to the port with `SO_REUSEADDR`). | multicast and mDNS | None needed yet: one mDNS responder per node; the resolver's one-shot queries use their own ephemeral ports. | not filed |
| 28 | gap | **No way to save and restore an interface.** The random generator, the neighbor cache, the multicast groups and their report timers are private, and a socket cannot be put into a given slot of a `SocketSet` (slot order decides the order of frames). A node restored from a snapshot needs all of them. | node snapshots | **Our second vendored patch** (`snapshot` feature, `smoltcp-0002-snapshot-state.patch`): `Interface::snapshot_state`/`restore_state` (an `InterfaceState` of plain values, in the interface's own order), `SocketHandle::index`, `SocketSet::add_at`, and one round-trip test. Additive, behind a feature: nothing changes without it. | not proposed (wasmnet-specific shape; an upstream "interface state" API would be a design discussion) |


## Plan
- ~~Fix #2~~: done (vendored patch). Open the upstream PR below, and drop `third_party/smoltcp` once a release has it.
- ~~Fix #7~~: done in the netstack (family demultiplexing). An upstream family filter would let us delete `UdpSockets::demux` and the TCP stray hand-off.
- File upstream issues for #1, #3, #4, #5, #7, #8, #9, #18, #20, #21, #24, #26 and #27, with minimal repros. Our deterministic simulations make good reproducers.

## Upstream-ready patch: per-address neighbour rate limit (#2)

Ready to send as a PR against smoltcp `main` (written and tested against 0.14.0; not opened yet).
The diff is [`smoltcp-0001-neighbor-rate-limit-per-address.patch`](smoltcp-0001-neighbor-rate-limit-per-address.patch)
(3 files, +153 / -12; applies with `git apply` to the 0.14.0 crate): exactly the change in
`third_party/smoltcp`.

**Title:** iface: rate-limit neighbor discovery per address, not per interface

**Description:**

> `neighbor::Cache` keeps a single `silent_until`. After any ARP request or Neighbor
> Solicitation, a lookup of *any* missing address returns `RateLimited` for one second
> (`SILENT_TIME`), and the socket that hit it then backs off for its own second
> (`socket_meta::DISCOVERY_SILENT_TIME`). A host that talks to two new on-link neighbours in
> quick succession (a DHCP server then a DNS server, a gateway's IPv4 and IPv6 addresses, two
> peers) therefore stalls 1–2 s on the second one, although nothing was sent to that address.
> RFC 1122 §2.3.2.1 recommends a maximum ARP rate of "1 per second per destination", and
> RFC 4861 §7.2.2 paces solicitations per neighbour entry (every `RetransTimer`, at most
> `MAX_MULTICAST_SOLICIT` times); Linux keeps this state per neighbour entry too.
>
> This change keeps a small map of per-address silences instead
> (`LinearMap<IpAddress, Instant, IFACE_NEIGHBOR_CACHE_COUNT>`). `limit_rate` takes the address
> the request was sent for; `lookup` returns `RateLimited` only for an address whose silence has
> not ended. The total rate stays bounded: when every slot holds an address that is still silent,
> a lookup of another missing address is rate-limited too, so the interface never sends more than
> `IFACE_NEIGHBOR_CACHE_COUNT` requests per `SILENT_TIME`; a slot is reused (oldest silence first)
> once its silence ended. Nothing else changes: `SILENT_TIME`, the per-socket back-off and the
> cache itself behave as before, and with one neighbour at a time the behaviour is identical.
>
> Tests: `test_hush` is updated for the new signature; `test_hush_is_per_address` (two addresses
> in one second, each with its own second, a repeated request restarts its silence) and
> `test_hush_is_bounded` (the cap, slot reuse) are new in `iface/neighbor.rs`; and
> `test_arp_requests_are_rate_limited_per_address` (`iface/interface/tests/ipv4.rs`) checks at the
> interface level that a request for one address does not hold back another at the same instant.
> `cargo test` passes with the default features (676 unit tests), and with
> `std,medium-ethernet,proto-ipv4,proto-ipv6,socket-*,multicast`, IPv4-only and IPv6-only
> feature sets.
>
> Memory: one `LinearMap` of `IFACE_NEIGHBOR_CACHE_COUNT` × (`IpAddress` + `Instant`) per
> interface (about 300 B with the default count of 8 and both protocols), replacing one
> `Instant`.

**Found and verified in wasmnet:** the netstack's `neighbor_requests_are_rate_limited_per_address_not_per_interface`
(the NS wanted at 100 ms now leaves at 100 ms instead of 1.1 s) and
`two_neighbors_resolve_at_the_same_instant` (two ARP requests at t=0, both resolved at 200 µs),
and the timelines of a ping test (three resolutions within 2 ms) and a traceroute test (the IPv6
gateway resolved 6 ms after the IPv4 one).
