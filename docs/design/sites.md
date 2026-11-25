# Multi-site networks: the site-sync protocol (version 3)

`wasmnet_core::sites` lets two simulators run **one network split into two sites** so that the
result is byte for byte what one simulator would have produced (**multi-site equivalence**).
Nothing in the protocol is specific to wasmnet's runtime: a simulator that implements the event
order of [event-order.md](event-order.md), the lockstep rule below and the messages below can
be a site.

## Model

- A network is a set of devices (numbered `0..D` in creation order) and point-to-point links
  (numbered `0..L`), each with a one-way latency and optional impairments per direction
  ([links.md](links.md)). Time is virtual, in nanoseconds.
- A **site** runs a subset of the devices; every device runs on exactly one site. Every site
  builds the whole network in the same order, the other sites' devices as placeholders
  (`Network::remote_device`, or `Network::remote_device_with` with the device's config and
  options, which a network with controllers needs: below), so device and link numbers and
  event keys are the same everywhere.
- Devices and links created while the network runs (by an in-world controller, below) exist
  only on their creator's site, at the next index there. Their **number** in event keys and
  record tags does not depend on the split: creator `c`'s `n`-th creation is number
  `D + c · CREATOR_RANGE + n` ([event-order.md](event-order.md#devices-created-while-the-network-runs)).
  Their indices in the records are site-local; the merge renumbers them into the unsplit
  network's order.
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

## In-world controllers

A controller (`DeviceOptions::infra`, [topology-and-infra.md](topology-and-infra.md)) works in
a split network as long as everything it changes stays on its own site: `apply`, `start`,
`stop`, `remove` and `control` of its own devices, with cables to devices of its own site. A
split run then gives exactly the unsplit records, the controller's view of the device table
included (`crates/wasmnet-host/tests/infra_sites.rs`, with one controller and with one on each
site). What makes it work:

- **One table on every site.** Placeholders enter the device table with their description
  (`remote_device_with`), at the same position and with the same uid as in the unsplit table.
  A controller sees the network's own devices and the ones it created, and its resource
  versions count only what it sees; both are the same split or not, because a controller and
  its devices always share a site. The table follows app exits only of devices a controller
  created, and `logs` answers only for them, since a site's journal has only its own devices.
- **Numbers by creator**, as above: the uids of created devices (digests of keys) and the
  order of events agree without the sites knowing of each other's creations.
- **Names cannot collide.** Controllers on more than one site must each have an
  `infra_prefix` (no two overlapping); a controller creates and changes only names under its
  own. A network without prefixes is refused when the second site's controller is added
  (`Error::Refused`, on both sites).
- **Locality is checked when a creation or a `wire` applies.** A cable to a device the network
  was built with that runs on another site (a placeholder) fails the split run with
  `Error::Refused` at that derived event: the same site, instant and message on every rerun.
  The unsplit network would have wired it, so no answer on one site could match. A cable to a
  device another controller created is refused by the rule of cables in both runs alike
  (`infra-failed`): its owner is known on the site that has it, and the name's `infra_prefix`
  tells the other site whose it is ([topology-and-infra.md](topology-and-infra.md)).

What does not cross sites:

- **Cables of created devices to another site**, and **WAN links created while the network
  runs**: refused as above. A new WAN link would need both sites to agree on it, exchange its
  ports and perhaps shrink the lookahead.
- **Most operator events.** `Network::add_op` takes only timed operator events at a device
  (`StartOf` or `EndOf`: `Op::Stdin`, `Op::Control`, `Op::Inject`) once the network has a
  remote device, and refuses the rest (`Error::Refused`): topology ops (pauses, resumes,
  operator crashes and embedder actions among them), link changes, and
  events anchored before another event, whose pre number is not on the wire
  ([event-order.md](event-order.md)). Every site must add the same operator events in the same
  order; an op at another site's device takes its index and key but is not queued, and stays
  `Pending` there. `OpState::Applied::events` counts only the site's own events.
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

What crosses follows each link's capture options ([links.md](links.md#what-a-link-records)),
which every site sets alike (they are part of building the network): a frame-log record or a
tap carries the frame's length and only the bytes the link keeps (the first `snap_len`, or
none with recording off, when a link records nothing it has no taps at all), and the merged
capture of a WAN link takes its header (snap length, end descriptions) from the sites' own,
so a split network's records equal the unsplit ones under every option
(`crates/wasmnet-host/tests/measure.rs`). Frames sent to the peer for delivery
(`RemoteFrame`) are always whole. A link's series ([links.md](links.md#counters)) does not
cross: each site's counts what that site counted.

The devices and links a site created while the network ran carry the tag of the processing
context that created them (`Network::created_devices`, `Network::created_links`). The merge
keeps the setup indices, sorts every creation of both sites by that tag (the unsplit creation
order) and renumbers each site's own indices in the frame log, the link transitions and the
links' ends to match; `Merged::devices` and `Merged::link_infos` name them.

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
"WNS" (3 bytes) | version: u8 = 3 | type: u8 | body
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
`control` 3, `operator` 4 (the key of a timed operator event placed at the end of an
instant, or of what it caused).

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
uv setup_devices                                         (devices the network was built with)
uv count, count x { uv device, string name, tag }        (devices it created while running)
uv count, count x { uv link, tag }                       (links it created while running)
uv count, count x { tag, uv at, string device, entry }    (journal)
     entry := u8 0 (log): u8 level (trace 0 ... error 4), string message
            | u8 1 (event): string kind, uv n, n x { string key, string value }
            | u8 2 (output): u8 stderr (0|1), string line
uv journal_dropped
uv count, count x { tag, uv link, end from, end to, uv sent_at, fate, uv len, bytes kept }
                                                         (frame log)
uv count, count x { uv frame_id, fate }                    (arrivals of the peer's frames)
uv count, count x { tag, uv link, uv end, uv at, u8 inbound, uv len, bytes kept }
                                                         (WAN-link taps)
uv count, count x { tag, uv at, uv link, u8 up }           (link transitions)
uv count, count x { string name, end a, end b, uv latency, uv mtu, u8 up, u8 removed,
                    u8 kind (0 Ethernet, else a cable kind's code),
                    2 x { uv rate, uv queue, uv loss_ppm, uv jitter }   (impairments by sending end)
                    u8 record, uv snap_len, u8 name_ends          (capture options)
                    7 x (uv, uv) stats,
                    bytes pcap }
strings := uv n, n x string
end     := uv device, uv port
fate    := u8 0 (in flight) | u8 1 (delivered), uv at | u8 2 (lost)
         | u8 3 (dropped), u8 reason (0 link down, 1 oversize, 2 operator, 3 queue full)
tag     := u8 origin, u8 has_cause (0|1), [key, then uv pre per level], uv slot, uv round,
           uv device, uv n
```

The stats pairs are frames, bytes, dropped while down, oversize, lost, dropped at a full
transmit queue and lost to seeded loss, each per end.

Version 2 added the impairments, the last two stats pairs, drop reason 3 and the devices and
links created while the network ran to RECORDS; the other messages are as in version 1.
Version 3 added each frame's and tap's length on the wire (`len`, with only the bytes its
link's capture keeps) and each link's capture options. A
RECORDS message's device and link indices below the setup counts are the same on both sites;
the others are the sender's own. The links a site did not create are the setup links, the
same list on both sites. A site refuses a message of another version.

## Impaired links

A link's impairments (a rate with a bounded transmit queue, seeded loss, jitter;
[links.md](links.md)) are decided at `wire.transmit`, on the sender's site, from the sending
direction's own state and random streams, and they only ever add delay. A frame transmitted at
`t` over a WAN link is still due no earlier than `t + latency`, so the lookahead holds, and a
frame lost on the wire is simply not sent: only the sender's half of the capture records it.
A WAN link may be impaired, and a split network with impaired links gives the same records as
the unsplit one (`crates/wasmnet-host/tests/impairments.rs`).

## Limits

- Two sites only: `SiteSync` drives one peer, and `sites::merge` takes two sites' records.
- RECORDS carries the journal, frames, taps, transitions and links. A device's raw stdout and
  stderr bytes (`Network::stdout`) stay on its own site; only the lines of a device created with
  `DeviceOptions::journal_stdio` travel, as journal entries.
- The protocol has no authentication: a site trusts whatever its carrier delivers.
