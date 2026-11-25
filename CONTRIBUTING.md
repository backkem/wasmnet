# Contributing

Thanks for looking. This is an experimental project, so the bar is "small, tested and
deterministic", not "finished".

## Set up

Rust comes from `rust-toolchain.toml`. Three tools must be on `PATH`, at these versions
([tools.toml](tools.toml) is where they are pinned, for CI and for other tooling; `cargo xtask
tools --check` compares it with what is installed):

```sh
cargo install --locked wasmtime-cli@50.0.1 wasm-tools@1.261.0 wac-cli@0.12.0
```

## Before you open a pull request

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask build          # every component and node builds and validates
cargo test --workspace     # native tests, including end-to-end runs of real nodes
cargo xtask test-guest     # component tests, inside wasmtime
cargo xtask check-tree     # no local path, AI tool session link or conflict marker in the tree
```

CI also runs `cargo xtask check-tree --commits <base>..<head>` on the commits a pull request
brings: their messages and added lines must be free of the same. A placeholder path that must
stay (in an example) carries `tree-check: allow` on its line.

## What we look for

- **Determinism is a feature, flakiness is a bug.** Never fix a failing seed with a retry.
  Use `BTreeMap` or a sorted `Vec` wherever order can reach the output.
- **A component never traps on data off the wire.** A malformed frame is dropped and
  counted. No `unwrap` on bytes a peer controls.
- **Logic and glue stay apart.** A component keeps its protocol logic in `src/lib.rs`, where
  it is tested without an instance, and its wit-bindgen glue in `src/component.rs`.
- **Tests run in wasmtime.** Anything that ships as a component is tested as wasm
  (`cargo test --target wasm32-wasip2 -p <crate>`), not natively.
- **WIT is the API.** Document every function's timing and ownership. Every change to a
  package's interface bumps its version, an addition included and whether or not the previous
  version was ever released: a vendored copy must be able to tell two revisions apart by the
  version alone. A breaking change also updates every implementer in the same change.
- **No `unsafe`** outside generated bindings.

## License

Contributions are accepted under the project's dual license, MIT or Apache-2.0, without
additional terms.
