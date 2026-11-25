# The components

Every device in a network is one of these, or a node composed from them. `cargo xtask build`
builds them all for `wasm32-wasip2`, composes the nodes and validates everything; `cargo xtask
build --list` prints the names below.

```sh
cargo xtask build                                       # everything
cargo xtask build --only netstack,switch --out-dir out  # two components, copied to out/
cargo xtask build --only node-http-server               # one node, and the parts it needs
```

`--only` takes the names in the first column, of components and of nodes; a node brings the
components it is composed from. `--out-dir` copies what was asked for (everything, without
`--only`) into a directory, each file under the name in the artifact column. That is all
another repository needs to run a network: the files load with `Host::load`.

In `target/wasm32-wasip2/release/` cargo names a library's artifact after its library target,
with underscores (`udp_echo_server.wasm`, `wan_port.wasm`). `--out-dir` uses the component's
name, as a composition does: `wac` knows a fabric device as `wasmnet:<name>` and an app as
`app:<name>`.

## Fabric devices and the netstack

| Name | Package | Artifact | What |
|---|---|---|---|
| `netstack` | `wasmnet-netstack` | `netstack.wasm` | A smoltcp IP stack: `wasmnet:link` below, `wasi:sockets@0.3.0` and `wasmnet:sockets-ext` above. One per node: every app of a composition shares it. |
| `switch` | `wasmnet-switch` | `switch.wasm` | A transparent learning Ethernet bridge; blocks and delays between port sets, by config or command (`wasmnet:control`); takes a new aging time, table size, blocks or delays in place (`wasmnet:reconfigure`). |
| `router` | `wasmnet-router` | `router.wasm` | Routes IPv4 and IPv6 between its ports: ARP, NDP, ICMP errors, static routes, DHCP relay, address translation (NAT44), a packet filter and tunnel ports (Geneve over UDP, STUN checks). |
| `wan-port` | `wasmnet-wan-port` | `wan-port.wasm` | One end of a bridged WAN link between two sites. |

## Apps

An app never runs alone: a composition plugs it into a netstack
([docs/design/writing-an-app.md](../docs/design/writing-an-app.md)).

| Name | Package | Artifact | What |
|---|---|---|---|
| `dhcp-server` | `wasmnet-dhcp-server` | `dhcp-server.wasm` | A DHCPv4 server: leases, a relay-aware pool, options from config. |
| `dns-server` | `wasmnet-dns-server` | `dns-server.wasm` | An authoritative DNS server for static zones. |
| `http-get` | `wasmnet-http-get` | `http-get.wasm` | An HTTP/1.1 client that fetches the URLs in its config. |
| `http-lb` | `wasmnet-http-lb` | `http-lb.wasm` | An HTTP/1.1 load balancer: health checks, round-robin or random, an admin API. |
| `http-server` | `wasmnet-http-server` | `http-server.wasm` | A small HTTP/1.1 server: static routes from config, keep-alive, generated bodies. |
| `mdns-responder` | `wasmnet-mdns-responder` | `mdns-responder.wasm` | A Multicast DNS responder for one host name, which also advertises DNS-SD services. |
| `ping` | `wasmnet-ping` | `ping.wasm` | ICMP echo over the netstack's ICMP echo sockets. |
| `replicas` | `wasmnet-replicas` | `replicas.wasm` | A controller that keeps N copies of a device running through `wasmnet:infra`. |
| `service-browse` | `wasmnet-service-browse` | `service-browse.wasm` | Browses DNS-SD services over Multicast DNS, resolves them and can fetch from one over HTTP. |
| `traceroute` | `wasmnet-traceroute` | `traceroute.wasm` | The classic UDP traceroute. |
| `udp-echo-client` | `wasmnet-udp-echo-client` | `udp-echo-client.wasm` | Sends UDP datagrams to an echo server and checks the replies. |
| `udp-echo-server` | `wasmnet-udp-echo-server` | `udp-echo-server.wasm` | Sends every UDP datagram it receives straight back. |

## Test fixtures

| Name | Package | Artifact | What |
|---|---|---|---|
| `blaster` | `wasmnet-blaster` | `blaster.wasm` | Emits a train of raw Ethernet probe frames. |
| `clock-probe` | `wasmnet-clock-probe` | `clock-probe.wasm` | A command that samples every source of time and entropy it can reach. |
| `infra-script` | `wasmnet-infra-script` | `infra-script.wasm` | A device with no ports that makes scripted `wasmnet:infra` calls at set times; its commands set variables its calls use. |
| `reflector` | `wasmnet-reflector` | `reflector.wasm` | Echoes frames back out of the port they came in on. |
| `udp-punch` | `wasmnet-udp-punch` | `udp-punch.wasm` | An app (in `components/apps`): UDP hole punching between two peers through a rendezvous server, for the NAT tests. |

## Nodes

A node is the netstack plus the apps in its composition, `compositions/<name>.wac`, built into
`node-<name>.wasm`. Every key of every part is in
[docs/design/configuration.md](../docs/design/configuration.md).

| Name | Parts |
|---|---|
| `node-dhcp-dns` | `netstack`, `dhcp-server`, `dns-server` |
| `node-http-get` | `netstack`, `http-get` |
| `node-http-lb` | `netstack`, `http-lb` |
| `node-http-server` | `netstack`, `http-server` |
| `node-mdns-responder` | `netstack`, `mdns-responder` |
| `node-mdns-web` | `netstack`, `http-server`, `mdns-responder` |
| `node-ping` | `netstack`, `ping` |
| `node-replicas` | `netstack`, `replicas` |
| `node-service-browse` | `netstack`, `service-browse` |
| `node-traceroute` | `netstack`, `traceroute` |
| `node-traceroute-ping` | `netstack`, `traceroute`, `ping` |
| `node-udp-echo-client` | `netstack`, `udp-echo-client` |
| `node-udp-echo-server` | `netstack`, `udp-echo-server` |
| `node-udp-punch` | `netstack`, `udp-punch` |
