//! Site sync with malformed peer input: a frame that names no WAN link end on this site, or one
//! that arrives out of lockstep, is an error from `SiteSync::handle`, never a panic, and
//! nothing of the message is queued.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{built, config};
use wasmnet_host::sim::sites::{Msg, SiteSync, Step};
use wasmnet_host::sim::{DeviceId, EventKey, KeyLevel, LinkId, Origin, RemoteFrame};
use wasmnet_host::{Network, PortInfo};

#[test]
fn malformed_peer_frames_are_errors_not_panics() {
    let b = built();
    let mut network = Network::new(&b.host, 1);
    // This site runs `sw`; `far` is the peer's, cabled to `sw:0` over a WAN link.
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "2")]))
        .unwrap();
    let far = network.remote_device("far").unwrap();
    network.set_remote_ports(
        far,
        vec![PortInfo {
            id: 0,
            name: "eth0".to_owned(),
            mac: None,
            mtu: 1500,
        }],
    );
    let link = network
        .link(sw.port(0), far.port(0))
        .unwrap()
        .latency(1_000)
        .id();
    network.advance_to(5_000);

    let key = |levels: usize, at| EventKey {
        levels: (0..levels)
            .map(|_| KeyLevel {
                at,
                origin: Origin::Popped,
                slot: 0,
                round: 0,
                device: 1,
                idx: 0,
                counter: 0,
                pre: 0,
            })
            .collect(),
    };
    // A frame from `far` to `sw:0` (link end 0), due at 6 µs.
    let good = RemoteFrame {
        key: key(1, 6_000),
        link,
        to_end: 0,
        generation: 0,
        frame_id: 0,
        device: sw,
        port: 0,
        bytes: vec![0xff; 60],
    };
    let bad = [
        RemoteFrame {
            link: LinkId::from_index(7),
            ..good.clone()
        },
        RemoteFrame {
            to_end: 2,
            ..good.clone()
        },
        // The peer's own end.
        RemoteFrame {
            to_end: 1,
            device: far,
            ..good.clone()
        },
        RemoteFrame {
            device: DeviceId::from_index(9),
            ..good.clone()
        },
        RemoteFrame {
            port: 1,
            ..good.clone()
        },
        RemoteFrame {
            key: key(0, 0),
            ..good.clone()
        },
        // Out of lockstep: due before now.
        RemoteFrame {
            key: key(1, 4_000),
            ..good.clone()
        },
    ];
    let mut sync = SiteSync::new(1_000, Some(10_000));
    for frame in bad {
        let what = format!("{frame:?}");
        let pending = network.pending_events();
        let r = sync.handle(&mut network, Msg::Frames(vec![good.clone(), frame]));
        assert!(r.is_err(), "accepted {what}");
        assert_eq!(
            network.pending_events(),
            pending,
            "nothing of a refused message is queued"
        );
    }
    assert!(matches!(
        sync.handle(&mut network, Msg::Frames(vec![good])),
        Ok(Step::Wait)
    ));
    assert_eq!(sync.stats().frames_received, 1);
}
