# smoltcp: issues found while building wasmnet

Pinned version: **smoltcp =0.14.0** (`Medium::Ethernet`, features as in `components/netstack/Cargo.toml`), **vendored with six patches** (`third_party/smoltcp`, `[patch.crates-io]`; #2, #28, #31, #32, #34 and #35 below). This is a running list of upstream bugs, spec deviations and API gaps that we hit, with the part of wasmnet where each was found and how we work around it today. Keep it current. When something gets filed upstream, add the link. When a fix lands, note the version and remove our workaround.

These are our own notes from building one stack on smoltcp. Unless the last column says so, an
entry has not been reported upstream yet, and some may turn out to be our misreading: check
against the source before relying on one.

Legend: **bug**: violates an RFC or is clearly wrong. **gap**: missing behaviour or API that real stacks have. **quirk**: correct but surprising and worth documenting.

| # | Kind | Issue | Found in | Our workaround | Upstream |
|---|---|---|---|---|---|
| 1 | bug | **MLDv2 record types are swapped.** A join is sent as `CHANGE_TO_INCLUDE_MODE` with 0 sources, which RFC 3810 §6.1 defines as a *leave*. A leave is sent as `CHANGE_TO_EXCLUDE_MODE`. It breaks MLD-snooping switches and Wireshark's reading. | any MLD-snooping switch or capture reading a join or leave | Our switch must not depend on smoltcp's MLD record types. | not filed |
| 2 | bug | **Neighbour discovery is rate-limited per interface, not per neighbour.** There is one `silent_until` in `neighbor::Cache`, so after any ARP request or NS the next one, for *any* address, waits 1 s. A socket that hits the limit then backs off for its own second. | netstack (ping), UDP sockets, router and traceroute | **Fixed in our vendored smoltcp**: `third_party/smoltcp` + `[patch.crates-io]`, a per-address `silent_until` (bounded map), 3 tests. A host now resolves several neighbours within a second, with no hand spacing between its first packets to them. | patch ready ([below](#upstream-ready-patch-per-address-neighbour-rate-limit-2), `smoltcp-0001-neighbor-rate-limit-per-address.patch`), not filed |
| 3 | gap | **`poll_at` ignores multicast work.** After a join/leave, `poll_at` returns `None` even though an IGMP/MLD report is pending, and query-response timers are invisible. | multicast joins and leaves | The netstack polls after every control-plane call and keeps its own multicast deadline (polls every 1 ms through a query's max-response window). | not filed |
| 4 | gap | **ICMP errors are ignored by TCP and UDP sockets.** Unreachable, port-unreachable and the rest never reach the socket, so a connect to an unroutable host retries for the full 75 s timeout, and there's no `ECONNREFUSED` for UDP. | router, ICMP errors and traceroute | The netstack classifies received ICMP errors itself, journals `icmp-error-received`, fails SYN-SENT connects with `remote-unreachable`, and exposes `IP_RECVERR`-style errors via `wasmnet:sockets-ext/udp`. Since #35 it also lowers a TCP connection's send MSS on "fragmentation needed" and "packet too big". | not filed |
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
| 29 | bug | **`socket-tcp-cubic` does not build without `std`.** `congestion/cubic.rs` calls `f64::powi` and `f64::mul_add`, which `core` does not have, so a `no_std` build with the feature fails (`E0599`). | TCP congestion control | The netstack enables only `socket-tcp-reno`; `tcp.congestion` offers `reno` and `none`. A fix would use `libm` or integer arithmetic (and `cube_root` already avoids `cbrt`). | not filed |
| 30 | quirk | **The initial congestion window is 2048 bytes whatever the MSS** (`2 * DEFAULT_MSS` with a default MSS of 1024; `set_mss` changes the increments, not the window). At a 1500-byte MTU that is one full segment and 588 bytes, below RFC 5681's two full segments and far below RFC 6928's ten, and the receiver holds its ACK for its delayed-ACK time (10 ms) because less than two full segments arrived. | TCP congestion control, bulk transfers | None: it costs one delayed ACK at the start of a transfer. | not filed |
| 31 | gap | **Fast recovery has no partial-ACK handling (NewReno, RFC 6582).** Reno leaves fast recovery on the first ACK of new data, so a second loss in the same window waits for three more duplicate ACKs, which seldom come, and then for a retransmission timeout (at least 1 s). A queue overflow drops several frames at once, so this is the common case. | TCP congestion control over a small transmit queue | **Fixed in our vendored smoltcp** (`smoltcp-0003-newreno-partial-acks.patch`, [below](#upstream-ready-patch-newreno-partial-acks-31)). | patch ready, not filed |
| 32 | bug | **A FIN is accepted on a segment cut at the receive window's right edge.** `process` trims a segment to the window but took its FIN whenever the segment starts at or before `RCV.NXT` (`control == Fin && window_start < segment_start` was the only check), so the FIN took the sequence number of the first byte that was cut: the stream ended early with `CLOSE-WAIT`, and the ACK of the FIN acknowledged the first cut byte to the sender as if it had arrived. RFC 9293 §3.10.7.4 drops a FIN that lies beyond the window. A sender reaches past the window with a fast retransmission, which sends a full segment from `SND.UNA` without looking at the window, or with a segment sent against an older window that the receiver has since moved back by a few bytes (a scaled window counts in steps of `2^shift`). | TCP congestion-control tests: an app that stops reading while a stream ends, a loss: 1 to 3 bytes missing before EOF | **Fixed in our vendored smoltcp** (`smoltcp-0004-fin-past-the-receive-window.patch`, [below](#upstream-ready-patch-a-fin-past-the-receive-window-32)): the FIN of a segment cut at the right edge is ignored; the sender sends the cut bytes and the FIN again once the window opens. Fast retransmissions still ignore the window (harmless now). | patch ready, not filed |
| 33 | gap | **No SACK-based recovery, Limited Transmit (RFC 3042), early retransmit (RFC 5827) or tail-loss probe, and a minimum RTO of 1 s** (`RTTE_MIN_RTO`, RFC 6298's SHOULD; Linux uses 200 ms). A loss that three duplicate ACKs do not reveal costs at least 1 s. smoltcp sends SACK blocks as a receiver but ignores the peer's. | TCP congestion control, lossy links | None; the costs are in `docs/design/netstack.md`. | not filed |
| 34 | bug | **A connection could hang with only its FIN unacknowledged.** When every data byte is acknowledged but the FIN is not (here: the receiver's window was zero, and it dropped a retransmitted segment whose data it already had together with its FIN, while it accepts a bare FIN at a zero window), the receiver's repeated ACKs count as duplicate ACKs (`ack_number < remote_last_seq`). The third started a fast retransmit: `dispatch` set `pending_fast_retransmit` and idled the retransmission timer, but `seq_to_transmit` wanted a non-empty transmit buffer for a fast retransmit and `can_fin` needs `remote_last_seq == local_seq_no + tx_buffer.len()`, so nothing was sent and no timer was armed: the FIN never went again. | the netstack's simulation: `tcp.congestion = "none"`, the receiving app not reading, 1 MB with data segment 134 lost: every byte arrived, the end of the stream never did | **Fixed in our vendored smoltcp** (`smoltcp-0005-fast-retransmit-of-a-lone-fin.patch`, [below](#upstream-ready-patch-fast-retransmit-of-a-lone-fin-34)): with every data octet acknowledged, a fast retransmit sends the FIN alone. | patch ready, not filed |
| 35 | gap | **No path MTU discovery, and no way to lower a connection's send MSS after the handshake.** smoltcp ignores ICMP "fragmentation needed" and "packet too big" (#4), and a socket's segment size is fixed by the interface MTU and the peer's MSS option. Over a path with a smaller MTU than both ends, every full-size segment is dropped by the router before the narrow link and resent unchanged on every timeout: the transfer stalls after the handshake. | the netstack between two routers joined by a 1280-byte link (`crates/wasmnet-host/tests/path_mtu.rs`) | **Our sixth vendored patch** (`smoltcp-0006-path-mtu-lowered.patch`, [below](#upstream-ready-patch-path-mtu-lowered-35)): `Socket::path_mtu_lowered(seq, mss)` lowers the send MSS when `seq` lies in the send window and resends the data in flight at once in the new size; the netstack validates the ICMP error and calls it (`TcpSockets::path_mtu`). | patch ready, not filed |


## Plan
- ~~Fix #2~~: done (vendored patch). Open the upstream PR below, and drop `third_party/smoltcp` once a release has it.
- ~~Fix #31~~: done (vendored patch, NewReno). Open the upstream PR below.
- ~~Fix #32~~: done (vendored patch). Open the upstream PR below.
- ~~Fix #34~~: done (vendored patch). Open the upstream PR below.
- ~~Fix #35~~: done (vendored patch, path MTU discovery). Open the upstream PR below.
- File the other half of #32: fast retransmissions ignore the receive window (harmless with the #32 fix: the receiver drops what is past the edge, and the sender sends it again once the window opens).
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

## Upstream-ready patch: NewReno partial ACKs (#31)

Ready to send as a PR against smoltcp `main` (written and tested against 0.14.0; not opened
yet). The diff is [`smoltcp-0003-newreno-partial-acks.patch`](smoltcp-0003-newreno-partial-acks.patch)
(4 files, +269 / -8; applies with `git apply` to the 0.14.0 crate): exactly the change in
`third_party/smoltcp`.

**Title:** tcp: retransmit on partial ACKs during fast recovery (NewReno, RFC 6582)

**Description:**

> Fast recovery ends on the first ACK of new data (`Reno::on_ack`, `Cubic::on_ack`). When
> several segments of one window were lost, as when a router queue overflows, that ACK is a
> partial ACK: it points at the next hole. The socket then needs three more duplicate ACKs to
> retransmit it; they only come if enough new data follows, so the usual outcome is a
> retransmission timeout, at least 1 s, and a go-back-N resend in slow start.
>
> This change keeps fast recovery until everything sent before the loss was detected is
> acknowledged (RFC 6582's `recover`, the new `Socket::fast_recovery_until`). A partial ACK
> retransmits the segment it points at right away and calls the controller's new
> `on_partial_ack` instead of `on_ack`; Reno and Cubic deflate the window by the newly
> acknowledged data and add back one segment (RFC 6582 §3.2 step 5). Duplicate ACKs during
> recovery only inflate the window, as before, and no longer start a second fast retransmit.
> A retransmission timeout ends recovery. With `CongestionControl::None` nothing changes: there
> is no fast recovery, and each loss still waits for its own three duplicate ACKs.
>
> Tests: `test_fast_recovery_retransmits_on_partial_ack` (two holes in one window, the second
> retransmitted on the partial ACK, a fourth duplicate ACK sends nothing, the full ACK ends
> recovery), `test_fast_recovery_ends_on_rto` and `test_no_fast_recovery_without_congestion_control`
> in `socket/tcp.rs`, and `partial_acks_deflate_and_keep_fast_recovery` in `congestion/reno.rs`.
> `cargo test --lib` passes with the default features (677 tests), with
> `--features socket-tcp-reno,socket-tcp-cubic` (703), and with
> `std,alloc,medium-ethernet,proto-ipv4,proto-ipv6,multicast,socket-tcp,socket-tcp-reno,socket-tcp-cubic,socket-udp,socket-icmp,socket-dhcpv4,auto-icmp-echo-reply` (318).

**Found and verified in wasmnet:** the netstack's
`reno_repairs_two_losses_in_one_window_without_a_timeout` (two holes in the last window: the
second goes 200 µs after the first instead of after 1 s), and a 1 MB fetch through a 4-frame
transmit queue at 10 Mbit/s (`crates/wasmnet-host/tests/congestion.rs`): 2.85 s with Reno
alone, 1.85 s with this patch.

## Upstream-ready patch: a FIN past the receive window (#32)

Ready to send as a PR against smoltcp `main` (written and tested against 0.14.0; not opened
yet). The diff is [`smoltcp-0004-fin-past-the-receive-window.patch`](smoltcp-0004-fin-past-the-receive-window.patch)
(1 file, +79; applies with `git apply` to the 0.14.0 crate, after the three patches before it):
exactly the change in `third_party/smoltcp`.

**Title:** tcp: ignore the FIN of a segment cut at the receive window's right edge

**Description:**

> `process` trims an incoming segment to the receive window and keeps the part that fits. Its
> FIN was ignored only when the segment starts after `RCV.NXT` (a hole before it); a segment
> that starts in the window but reaches past its right edge kept its FIN. The FIN then takes
> the sequence number of the first octet that was cut: the socket goes to `CLOSE-WAIT`, the
> application reads end-of-stream with the cut octets missing, and the ACK of the FIN
> acknowledges one of them to the peer, which never sends it again. RFC 9293 §3.10.7.4 trims
> a segment to the window, and the FIN beyond it goes with the trimmed part.
>
> A peer reaches past the window with a fast retransmission (smoltcp's own sends a full
> segment from `SND.UNA` whatever the window), or with a segment sent against an older window
> whose right edge the receiver has since moved back by a few octets (a scaled window is
> advertised in steps of `2^shift`). Both need an application that has stopped reading, so the
> window is nearly closed, while the stream ends.
>
> This change ignores the FIN when the accepted payload ends before the segment does. The peer
> retransmits the cut octets and the FIN once the window opens, as for any cut segment. A FIN
> on a segment that fits, and a bare FIN at a zero window (`test_zero_window_fin`), are
> accepted as before.
>
> Test: `test_established_receive_fin_past_right_window_edge` (eight octets and a FIN against a
> window of six: six octets kept, the FIN ignored, the ACK at six with a zero window; after a
> read, the last two octets and the FIN are accepted). `cargo test --lib` passes with the
> default features (678 tests), with `--features socket-tcp-reno,socket-tcp-cubic` (704), and with
> `std,alloc,medium-ethernet,proto-ipv4,proto-ipv6,multicast,socket-tcp,socket-tcp-reno,socket-tcp-cubic,socket-udp,socket-icmp,socket-dhcpv4,auto-icmp-echo-reply` (318).

**Found and verified in wasmnet:** the netstack's
`a_fin_past_the_receive_window_waits_for_the_bytes_before_it` (a stream 2 bytes longer than
the receive buffer, the reader stopped, a fast retransmission with the FIN past the window:
before, 19 998 of 20 000 bytes and end-of-stream, under Reno and without congestion control)
and `reno_loses_no_byte_to_a_loss_while_the_reader_has_stopped` (1 MB against a scaled window
with the reader stopped: before, 30 of 142 loss positions ended the stream 1 to 3 bytes short).

## Upstream-ready patch: fast retransmit of a lone FIN (#34)

Ready to send as a PR against smoltcp `main` (written and tested against 0.14.0; not opened
yet). The diff is [`smoltcp-0005-fast-retransmit-of-a-lone-fin.patch`](smoltcp-0005-fast-retransmit-of-a-lone-fin.patch)
(1 file, +49 / -2; applies with `git apply` to the 0.14.0 crate, after the four patches before
it): exactly the change in `third_party/smoltcp`.

**Title:** tcp: a fast retransmit with only the FIN outstanding retransmits the FIN

**Description:**

> Once every data octet is acknowledged and only the FIN is outstanding, further ACKs of the
> data still count as duplicate ACKs (`ack_number < remote_last_seq`, the FIN occupying the
> last sequence number). The third one starts a fast retransmit: `dispatch` sets
> `pending_fast_retransmit` and idles the retransmission timer. But `seq_to_transmit` only
> honours a pending fast retransmit with data in the transmit buffer, and `can_fin` needs the
> FIN not to have been sent yet, so nothing is sent; with the timer idle nothing is ever sent
> again, and the connection hangs in FIN-WAIT-1, CLOSING or LAST-ACK. A peer gets there by
> dropping the FIN, for example with a zero window it dropped a retransmitted segment whose data
> it already had, FIN included.
>
> This change lets a pending fast retransmit go when the transmit buffer is empty and the FIN is
> outstanding: `dispatch` already follows an empty payload with the FIN in those states, so the
> retransmission is the FIN alone, at `SND.UNA`, and it arms the retransmission timer again as
> any segment does. Nothing else changes.
>
> Test: `test_fast_retransmit_of_a_lone_fin` (data and FIN, the data acknowledged four times:
> the FIN goes again at once, and once more on the retransmission timer). `cargo test --lib`
> passes with the default features (679 tests), with
> `--features socket-tcp-reno,socket-tcp-cubic` (705), and with
> `std,alloc,medium-ethernet,proto-ipv4,proto-ipv6,multicast,socket-tcp,socket-tcp-reno,socket-tcp-cubic,socket-udp,socket-icmp,socket-dhcpv4,auto-icmp-echo-reply` (318).

**Found and verified in wasmnet:** the netstack's
`no_loss_ends_a_stream_short_or_hangs_it_while_the_reader_has_stopped` (1 MB with the reader
stopped, each of the 142 data segments lost in turn, under Reno and without congestion
control): before, losing segment 134 without congestion control delivered every byte and never
the end of the stream.

## Upstream-ready patch: path MTU lowered (#35)

Ready to send as a PR against smoltcp `main` (written and tested against 0.14.0; not opened
yet). The diff is [`smoltcp-0006-path-mtu-lowered.patch`](smoltcp-0006-path-mtu-lowered.patch)
(1 file, +112 / -2; applies with `git apply` to the 0.14.0 crate, after the five patches
before it): exactly the change in `third_party/smoltcp`.

**Title:** tcp: let the owner lower a socket's send MSS on a path MTU error

**Description:**

> smoltcp does not process ICMP errors for TCP, and a socket's segment size is fixed once the
> handshake has set the peer's MSS: `min(interface MTU, remote MSS)`. Over a path whose MTU is
> smaller than both ends', every full-size segment is dropped by the router before the narrow
> link, which answers with an ICMP "fragmentation needed" (IPv4, DF is always set) or "packet
> too big" (IPv6), and the socket resends the same segment on every timeout: the connection
> stalls right after the handshake.
>
> Whoever receives the ICMP errors (the application, or a future interface hook) can now
> act on them. `Socket::path_mtu_lowered(seq, mss)` takes the sequence number of the quoted
> segment and the segment size the reported MTU allows. It is trusted only if `seq` was sent
> and not yet acknowledged (`SND.UNA <= seq < SND.NXT`, as Linux checks), and it only ever
> lowers: a new `path_mss` caps the effective MSS from then on, beside the interface's and
> the peer's. In a synchronized state the data in flight is sent again at once from
> `SND.UNA` in the new size (the oversized segments were dropped); that is not a congestion
> signal, so the congestion window and the retransmission timer are kept, and the RTT sample
> in progress is dropped. `Socket::path_mss()` reads it back. The caller derives `mss` from
> the reported MTU (less the IP and TCP headers), applies the family's minimum, and ignores
> an MTU that is not below its own; RFC 1191's plateau search for errors without an MTU is
> left to it as well.
>
> Test: `test_path_mtu_lowered_resends_in_the_new_size` (two 6-octet segments in flight;
> sequence numbers outside the window and sizes that are not lower are refused; a lowering to
> 4 resends all 12 octets at once in three segments; it never goes back up). `cargo test --lib`
> passes with the default features (680 tests), with
> `--features socket-tcp-reno,socket-tcp-cubic` (706), and with
> `std,alloc,medium-ethernet,proto-ipv4,proto-ipv6,multicast,socket-tcp,socket-tcp-reno,socket-tcp-cubic,socket-udp,socket-icmp,socket-dhcpv4,auto-icmp-echo-reply` (318).

**Found and verified in wasmnet:** `crates/wasmnet-host/tests/path_mtu.rs` (200 KB across two
routers joined by a 1280-byte link, both directions, IPv4 and IPv6: before, the transfer
stalled after the handshake; after, it takes 24 ms to 25 ms of virtual time) and the
netstack's simulations `a_packet_too_big_lowers_the_segment_size_and_resends_at_once`,
`a_packet_too_big_is_trusted_only_when_it_quotes_data_in_flight` and
`an_ipv6_packet_too_big_under_1280_counts_as_1280`.
