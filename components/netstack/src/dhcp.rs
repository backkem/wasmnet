//! The DHCPv4 client: smoltcp's `socket-dhcpv4`, applied to the interface.
//!
//! With `ipv4 = "dhcp"` the stack boots with no IPv4 address. smoltcp's client broadcasts a
//! DISCOVER at the first poll, requests the first OFFER, and reports the ACKed lease; this module
//! applies it: the address (replacing any IPv4 address), the default route, and the DNS servers
//! and domain the resolver uses. Renewals (unicast at T1, broadcast from T2) and expiry are
//! smoltcp's; every ACK is re-read, so a renewal is journalled too.
//!
//! The transaction ids come from smoltcp's RNG, which the netstack seeds from the seeded
//! `wasi:random`; lease timers run on virtual time. So the same network and seed give the same
//! DORA, byte for byte.
//!
//! Journal: `dhcp-bound {ip, router, dns, server, domain, lease-s, after-ns}` when an address is
//! (newly) leased, `dhcp-renewed {ip, server, lease-s}` when an ACK extends it, `dhcp-lost {ip}`
//! when it expired or was refused (NAK).

use std::net::{IpAddr, Ipv4Addr};

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::dhcpv4;
use smoltcp::wire::{DhcpOption, IpCidr, Ipv4Cidr};
use wasmnet_wire::dhcp::{self as wire, opt};

use crate::{Event, Level, Output};

/// Options the client asks for: subnet mask, router, DNS servers, domain name.
const PARAMETERS: &[u8] = &[
    opt::SUBNET_MASK,
    opt::ROUTER,
    opt::DNS_SERVERS,
    opt::DOMAIN_NAME,
];
/// The receive buffer smoltcp copies each accepted message into (so we can read the lease time
/// and the domain, which its `Config` leaves out).
const RX_BUFFER: usize = 1500;

/// The configuration a lease gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    /// The server identifier (option 54).
    pub server: Ipv4Addr,
    pub domain: Option<String>,
    pub lease_s: Option<u32>,
}

/// DHCP client counters (part of the netstack's `counters`; 0 without a client).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DhcpCounters {
    pub bound: u64,
    pub renewed: u64,
    pub lost: u64,
}

/// The client: its smoltcp socket and the lease it applied.
#[derive(Debug)]
pub struct DhcpClient {
    handle: SocketHandle,
    started: u64,
    lease: Option<Lease>,
    pub counters: DhcpCounters,
}

fn leak<T>(v: Vec<T>) -> &'static mut [T] {
    Box::leak(v.into_boxed_slice())
}

impl DhcpClient {
    /// Adds the client's socket to `sockets`. It sends its DISCOVER at the next poll.
    pub fn new(sockets: &mut SocketSet<'static>, hostname: Option<&str>, now: u64) -> Self {
        let mut socket = dhcpv4::Socket::new();
        socket.set_parameter_request_list(PARAMETERS);
        // smoltcp borrows these for the socket's lifetime ('static in our socket set). One
        // stack per instance, so leaking them once is the simplest correct owner.
        socket.set_receive_packet_buffer(leak(vec![0u8; RX_BUFFER]));
        if let Some(name) = hostname {
            let data: &'static [u8] = leak(name.as_bytes().to_vec());
            let options: &'static [DhcpOption<'static>] = leak(vec![DhcpOption {
                kind: opt::HOSTNAME,
                data,
            }]);
            socket.set_outgoing_options(options);
        }
        Self {
            handle: sockets.add(socket),
            started: now,
            lease: None,
            counters: DhcpCounters::default(),
        }
    }

    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    /// Reads the socket's news after `Interface::poll` and applies it to `iface`. Returns whether
    /// the IPv4 configuration changed (the stack then polls again at this instant).
    pub fn poll(
        &mut self,
        now: u64,
        iface: &mut Interface,
        sockets: &mut SocketSet<'static>,
        out: &mut Output,
    ) -> bool {
        let event = match sockets.get_mut::<dhcpv4::Socket>(self.handle).poll() {
            None => return false,
            Some(dhcpv4::Event::Deconfigured) => None,
            Some(dhcpv4::Event::Configured(c)) => {
                let msg = c
                    .packet
                    .and_then(|p| wire::Message::parse(p.into_inner()).ok());
                Some(Lease {
                    address: c.address.address(),
                    prefix: c.address.prefix_len(),
                    router: c.router,
                    dns: c.dns_servers.iter().copied().collect(),
                    server: c.server.identifier,
                    domain: msg.as_ref().and_then(|m| m.text_option(opt::DOMAIN_NAME)),
                    lease_s: msg.as_ref().and_then(|m| m.u32_option(opt::LEASE_TIME)),
                })
            }
        };
        match (event, self.lease.take()) {
            // smoltcp reports "deconfigured" once at the start: nothing to undo.
            (None, None) => false,
            (None, Some(old)) => {
                self.counters.lost += 1;
                iface.update_ip_addrs(|addrs| addrs.retain(|c| !matches!(c, IpCidr::Ipv4(_))));
                iface.routes_mut().remove_default_ipv4_route();
                out.log(Level::Info, format!("dhcp: lease of {} lost", old.address));
                out.event(Event::new("dhcp-lost", &[("ip", old.address.to_string())]));
                true
            }
            (Some(new), Some(old)) if new.address == old.address && new.prefix == old.prefix => {
                self.counters.renewed += 1;
                let changed = new.router != old.router;
                if changed {
                    set_router(iface, new.router);
                }
                out.event(Event::new(
                    "dhcp-renewed",
                    &[
                        ("ip", new.address.to_string()),
                        ("server", new.server.to_string()),
                        ("lease-s", opt_text(new.lease_s)),
                    ],
                ));
                self.lease = Some(new);
                changed
            }
            (Some(new), _) => {
                self.counters.bound += 1;
                let cidr = Ipv4Cidr::new(new.address, new.prefix);
                iface.update_ip_addrs(|addrs| {
                    addrs.retain(|c| !matches!(c, IpCidr::Ipv4(_)));
                    let _ = addrs.push(IpCidr::Ipv4(cidr));
                });
                set_router(iface, new.router);
                out.log(
                    Level::Info,
                    format!(
                        "dhcp: bound {}/{} from {}, router {}, dns {}",
                        new.address,
                        new.prefix,
                        new.server,
                        opt_text(new.router),
                        join(&new.dns)
                    ),
                );
                out.event(Event::new(
                    "dhcp-bound",
                    &[
                        ("ip", format!("{}/{}", new.address, new.prefix)),
                        ("router", opt_text(new.router)),
                        ("dns", join(&new.dns)),
                        ("server", new.server.to_string()),
                        ("domain", new.domain.clone().unwrap_or_default()),
                        ("lease-s", opt_text(new.lease_s)),
                        ("after-ns", (now - self.started).to_string()),
                    ],
                ));
                self.lease = Some(new);
                true
            }
        }
    }

    /// The lease's DNS servers.
    pub fn dns(&self) -> Vec<IpAddr> {
        self.lease
            .iter()
            .flat_map(|l| l.dns.iter().map(|&a| IpAddr::V4(a)))
            .collect()
    }
}

fn set_router(iface: &mut Interface, router: Option<Ipv4Addr>) {
    iface.routes_mut().remove_default_ipv4_route();
    if let Some(r) = router {
        let _ = iface.routes_mut().add_default_ipv4_route(r);
    }
}

fn opt_text<T: ToString>(v: Option<T>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

fn join(addrs: &[Ipv4Addr]) -> String {
    addrs
        .iter()
        .map(Ipv4Addr::to_string)
        .collect::<Vec<_>>()
        .join(",")
}
