# Multi-site networks: the site-sync protocol (version 1)

`wasmnet_core::sites` lets two simulators run **one network split into two sites** so that the
result is byte for byte what one simulator would have produced (**multi-site equivalence**).
Nothing in the protocol is specific to wasmnet's runtime: a simulator that implements the event
order of [event-order.md](event-order.md), the lockstep rule below and the messages below can
be a site.

## Model

- A network is a set of devices (numbered `0..D` in creation order) and point-to-point links
  (numbered `0..L`), each with a one-way latency. Time is virtual, in nanoseconds.
- A **site** runs a subset of the devices; every device runs on exactly one site. Every site
  builds the whole network in the same order, the other sites' devices as placeholders
  (`Network::remote_device`), so device and link numbers and event keys are the same
  everywhere.
- A link whose ends are on different sites is a **WAN link**. The smallest WAN-link latency is
  the **lookahead** `L`, which must be > 0 (`SiteSync::new` panics on 0).
- A scripted link change whose both ends are on the other site is not scheduled here, but
  counted with `Network::skip_link_state`, so setup slots stay aligned with the single-site
  network.
- A **carrier** moves messages between the two sites over one reliable, ordered channel and
  never interprets them. The driver (`SiteSync`) is sans-IO: the embedder moves the bytes of
  `Msg::encode` and hands what arrives to `Msg::decode` and `SiteSync::handle`. The
  `wasmnet:wan` WIT package ([wit/wan/wan.wit](../../wit/wan/wan.wit)) describes a carrier
  component; this repository contains none.

What does not cross sites:

- **Operator events.** `Network::add_op` returns `Error::Refused` once the network has a remote
  device ([event-order.md](event-order.md)).
- **`wasmnet:infra` mutations.** Once a remote device exists, every mutating call answers
  `denied`; reads still work ([topology-and-infra.md](topology-and-infra.md)).
- **Cables.** A cable ([runtime-and-extensions.md](runtime-and-extensions.md)) between two
  devices of the same site works as usual. A message sent on a cable whose other end is on the
  other site is dropped and counted in that link's `LinkStats::dropped_down`; nothing refuses
  the network.

## Output records

Each output record (a journal entry, a transmitted frame, a pcap record of a WAN link, a link
state change) is tagged with the processing context it was made in and its position there.
Merging the two sites' records by tag (`sites::merge`) gives the single-site order. The pcap of
a WAN link is rebuilt from both halves: the sender records a frame outbound at transmit time,
the receiver inbound at arrival time.

## Lockstep

This is conservative parallel discrete-event simulation. Each site keeps a **horizon** `H`: no
frame from the peer can be due before `H`. Initially `H = L` (the peer's earliest transmit is
at `t = 0`).

```text
loop:
  process every local event with at < H (and at <= deadline, if the run has one)
  send FRAMES with every frame transmitted towards the peer's devices, in transmit order
  next    := the earliest queued event that will still be processed (none: infinity)
  promise := min(next, H) + L
  send SYNC{promise, next, sent, recv}          (sent/recv: frames sent/received so far)
  read messages until H grows:
    FRAMES: queue each frame under its key
    SYNC s: if s.recv = sent and s.sent = recv                (nothing in flight)
                and s.next = infinity and next = infinity: send DONE, stop  (finished)
            H := max(H, s.promise)
            if s.recv = sent and s.sent = recv:
              H := max(H, min(s.next, next + L) + L)            (the next-event fixpoint)
    DONE:   stop
```

- Events are processed strictly before `H`: a frame due exactly at `H` may still come, and its
  key may sort before a local event at `H`.
- A received frame is queued under the key the sender computed for it, exactly what a single
  simulator would have queued.
- The fixpoint is optional (`SiteSync::without_fixpoint` turns it off), but it turns
  `O(virtual time / L)` null messages into `O(causal round trips across the WAN)`.
- A run with a deadline stops at it: events after the deadline do not count as `next`. Frames
  due after the deadline are still exchanged (they count as pending events).

## Messages

Every message is one carrier message:

```text
"WNS" (3 bytes) | version: u8 = 1 | type: u8 | body
```

Integers are unsigned LEB128 (`uv`) unless noted. `bytes` is `uv length` then the bytes;
`string` is `bytes` holding UTF-8. A message must be consumed exactly (no trailing bytes).

**HELLO (type 1)**, sent by each site before anything else (`sites::hello`, applied with
`sites::apply_hello`): its own devices' ports. A site can wire a WAN link only after the peer's
HELLO, because a link checks that both ports are declared and takes the smaller of their MTUs.

```text
uv count, then count x { uv device, uv ports, ports x { uv id, string name,
                         u8 has_mac (0|1), [6 bytes mac], uv mtu } }
```

**FRAMES (type 2)**:

```text
uv count, then count x { key, uv link, u8 to_end (0|1), uv generation, uv frame_id,
                         uv device, uv port, bytes frame }
key := uv depth (1..32), then depth x level, level i:
       uv at_i  (i = 0: absolute; i > 0: at_{i-1} - at_i, never negative)
       u8 origin | uv slot | uv round | uv device | uv idx | uv counter
```

`frame_id` is the frame's index in the sender's frame log (the receiver reports its fate in the
merged result). `generation` is the link's down-count at transmit time: a frame in flight when
the link went down is lost on arrival. The origin codes are `setup` 0, `init` 1, `popped` 2,
`control` 3, `operator` 4 (never sent: operator events do not cross sites).

**SYNC (type 3)**, the null message:

```text
uv promise | u8 has_next (0|1) | [uv next] | uv sent | uv recv
```

**DONE (type 4)**: no body. The sender saw the network finish and stops.

**RECORDS (type 5)**: after the network finished, one site sends the other everything it
recorded, so the receiver can merge both sites' records into the single-site result. Not part
of lockstep: a RECORDS message during lockstep is an error.

```text
outcome   u8 0 (quiescent): uv at, strings parked, strings daemons
          u8 1 (deadline):  uv at, uv pending_events
          u8 2 (failed):    uv at, string message
uv now | uv count, count x uv device                      (the sender's own devices)
uv count, count x { tag, uv at, string device, entry }    (journal)
     entry := u8 0 (log): u8 level (trace 0 ... error 4), string message
            | u8 1 (event): string kind, uv n, n x { string key, string value }
            | u8 2 (output): u8 stderr (0|1), string line
uv journal_dropped
uv count, count x { tag, uv link, end from, end to, uv sent_at, fate, bytes frame }  (frame log)
uv count, count x { uv frame_id, fate }                    (arrivals of the peer's frames)
uv count, count x { tag, uv link, uv end, uv at, u8 inbound, bytes frame }  (WAN-link taps)
uv count, count x { tag, uv at, uv link, u8 up }           (link transitions)
uv count, count x { string name, end a, end b, uv latency, uv mtu, u8 up, u8 removed,
                    u8 kind (0 Ethernet, else a cable kind's code), 5 x (uv, uv) stats,
                    bytes pcap }
strings := uv n, n x string
end     := uv device, uv port
fate    := u8 0 (in flight) | u8 1 (delivered), uv at | u8 2 (lost)
         | u8 3 (dropped), u8 reason (0 link down, 1 oversize, 2 operator)
tag     := u8 origin, u8 has_cause (0|1), [key, then uv pre per level], uv slot, uv round,
           uv device, uv n
```

The stats pairs are frames, bytes, dropped while down, oversize and lost, each per end.

## Limits

- Two sites only: `SiteSync` drives one peer, and `sites::merge` takes two sites' records.
- RECORDS carries the journal, frames, taps, transitions and links. A device's raw stdout and
  stderr bytes (`Network::stdout`) stay on its own site; only the lines of a device created with
  `DeviceOptions::journal_stdio` travel, as journal entries.
- The protocol has no authentication: a site trusts whatever its carrier delivers.
