//! The crate's public types, built the way `docs/stability.md` says to: through a constructor
//! and chainable setters, never a struct literal (most are `#[non_exhaustive]`).

use wasmnet_disk::{
    Corruption, DiskFault, DiskOp, DiskOptions, DiskSpec, Disks, Durability, Keep, image,
};

#[test]
fn every_public_type_has_a_constructor_outside_the_crate() {
    let spec = DiskSpec::new("state")
        .quota(1 << 20)
        .durability(Durability::OnSync)
        .initial(image::of(&[]));
    assert_eq!(spec.name, "state");
    let options = DiskOptions::new(vec![spec]).disk(DiskSpec::new("log"));
    assert_eq!(options.disks.len(), 2);
    let faults = [
        DiskFault::Lose,
        DiskFault::PowerLoss {
            keep: Keep::Prefix,
            tear: true,
        },
        DiskFault::CrashAt {
            call: 1,
            keep: Keep::All,
        },
        DiskFault::FailCalls {
            count: 1,
            text: "x".into(),
        },
        DiskFault::Corrupt {
            prefix: String::new(),
            how: Corruption::SeededBytes(2),
        },
        DiskFault::Quota(10),
    ];
    for f in faults {
        let op = DiskOp::new("state", f.clone());
        assert_eq!(op.fault, f);
    }
    let disks = Disks::new().total(1 << 20);
    assert_eq!(disks.used(), (0, 1 << 20));
    assert_eq!(Disks::interfaces().len(), 4);
}
