//! ext-probe: a std `wasm32-wasip2` command that imports a test-only host capability,
//! `wasmnet-test:ext/probe`, which no host serves by default. `crates/wasmnet-host/tests/extension.rs`
//! links it through a dummy `HostExtension` and checks the output.

wit_bindgen::generate!({
    inline: r#"
        package wasmnet-test:ext@0.1.0;

        /// A dummy host extension: a per-store call counter and a resource.
        interface probe {
            resource counter {
                constructor(start: u32);
                /// Adds one and returns the new value.
                bump: func() -> u32;
            }
            /// Host calls into this extension from this store so far, this one included.
            calls: func() -> u64;
            /// The name the host gave this store.
            device: func() -> string;
        }

        world ext-probe {
            import probe;
        }
    "#,
});

use wasmnet_test::ext::probe;

fn main() {
    let counter = probe::Counter::new(10);
    let (a, b) = (counter.bump(), counter.bump());
    println!("bump {a} {b}");
    println!("calls {}", probe::calls());
    println!("device {}", probe::device());
}
