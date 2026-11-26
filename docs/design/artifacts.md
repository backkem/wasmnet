# Component artifacts

An embedder that pins a revision of this repository needs its components: the netstack, the
switch, the router, and perhaps the apps and the composed nodes. Building them means finding
cargo's checkout of this repository and running its build there, with this repository's Rust
toolchain, `wasm-tools` and `wac`. This note is about the other way: a revision's components
as a set of files with hashes, which a build fetches and checks instead of building.

## The set

`cargo xtask artifacts` builds the published components and writes them to a directory
(`target/artifacts` by default) with two descriptions:

```text
target/artifacts/
  manifest.toml        the revision, the toolchain and tools, and every file's hash and interfaces
  SHA256SUMS           the same hashes, as `sha256sum -c` reads them
  netstack.wasm  switch.wasm  router.wasm  wan-port.wasm
  dhcp-server.wasm  dns-server.wasm  http-get.wasm  ...       the apps
  node-http-server.wasm  node-dhcp-dns.wasm  ...              the composed nodes
```

Published: every component and app in [components/README.md](../../components/README.md)
except the test fixtures (`blaster`, `clock-probe`, `infra-script`, `reflector`, `udp-punch`),
and every node composed only of published parts. The netstack matters most: an embedder that
composes its own nodes needs it and its own apps, nothing else. The files carry the names
`--out-dir` gives them (`wan-port.wasm`, not cargo's `wan_port.wasm`).

`manifest.toml` is TOML in one fixed order, so that the same set always gives the same bytes
(`wasmnet_artifacts::Manifest` reads and writes it):

```toml
format = "wasmnet-artifacts/1"
revision = "<the commit's full hash>"
dirty = false
target = "wasm32-wasip2"
host = "x86_64-unknown-linux-gnu"
rust = "1.98.1"

[tools]
wac-cli = "0.12.0"
wasm-tools = "1.261.0"
wasmtime-cli = "50.0.1"

[[file]]
name = "netstack.wasm"
kind = "component"
sha256 = "<64 hex digits>"
size = 1277522
exports = [
  "wasi:sockets/ip-name-lookup@0.3.0",
  "wasi:sockets/types@0.3.0",
  "wasmnet:link/counters@0.1.0",
  "wasmnet:link/device@0.1.0",
  ...
]
imports = [
  "wasi:clocks/monotonic-clock@0.3.0",
  "wasmnet:link/wire@0.1.0",
  ...
]

[[file]]
name = "node-http-server.wasm"
kind = "node"
parts = ["netstack", "http-server"]
...
```

`exports` and `imports` are the names at the component's top level with their versions, read
from its bytes. They are what an embedder checks before it composes its apps with a netstack:
`File::check_exports(&["wasi:sockets/types@0.3.0", ...])` fails when the set's netstack does
not serve the versions its apps were built against. A key may be added within format 1; a
change to what a key means renames the format.

Commands:

```sh
cargo xtask artifacts [--out DIR]          # build the set and write it
cargo xtask artifacts --verify DIR         # every file matches its manifest; no stray .wasm
cargo xtask artifacts --rebuild MANIFEST   # build here and compare with a manifest built elsewhere
cargo xtask artifacts --compare A B        # compare two manifests' hashes
```

`artifacts` refuses to build with tools other than the pinned ones (`rustc`, `wasm-tools`,
`wac`), or with a release profile changed from the environment (`CARGO_PROFILE_RELEASE_*`),
and fails if a file's bytes contain the workspace's path, the cargo home, the user's home or
a source path with backslashes.

## Reproducible bytes

Hashes only mean something if a rebuild gives the same bytes. What was observed, with the
pinned toolchain and tools, on Windows and on Linux (x86-64 both):

- **Two builds in one checkout** give the same 36 files (components and nodes, fixtures
  included).
- **Without the mapping, a build embeds its paths.** rustc writes the source path of every
  place that can panic into the binary. Cargo passes a workspace crate's files relative to the
  workspace root with the platform's separator (`components\router\src\nat.rs`), and a
  crates.io crate's files as absolute paths into the cargo home, which name the user. The
  netstack would carry 16 such strings.
- **`build` maps them out** (`xtask/src/remap.rs`): one `--remap-path-prefix` per source
  directory of every crate the components are built from, a workspace directory to its
  relative path with `/` separators, any other crate's to `/deps/<name>-<version>/...`. Per
  directory, not per crate, because rustc keeps the rest of a path as it found it, separators
  included. The flags reach rustc through an argument file in the target directory, which
  only the components' build uses (`CARGO_ENCODED_RUSTFLAGS`), so `RUSTFLAGS` from the
  environment does not reach them.
- **Two checkouts at different paths give the same bytes.** On Windows, a copy of the source
  (`git archive`) at another path, with its own target directory and a separate, freshly
  downloaded cargo home, gave the same 30 files as the checkout, byte for byte (`--compare`).
  On Linux, two clones in different directories did too. Two builds whose argument files
  differed (one mapped only the published crates' sources, the other every component's) gave
  the same bytes: the flags themselves do not reach the output.
- **Without the wrapper below, each operating system was reproducible on its own, but Linux
  and Windows disagreed.** At one revision, a Linux build gave the hashes that CI's Linux runner
  reported, and a Windows build those of CI's Windows runner (`switch.wasm` `8ee6b213…` and
  `22d97274…`); all 30 files differed between the two. Only the core module that rustc makes
  differed: the component's adapter modules, its `producers` section and the source paths left
  in its data were the same. In `switch.wasm` the 397 functions were the same functions under
  other symbol names (`_RNvNtCseD8GTKePBbU_6switch…` against `_RNvNtCshNMtWm67Ajj_6switch…`),
  but one of them (`switch::component::wasmnet::link::log::log`) was at another index and took
  two parameters on Windows and three on Linux, and data addresses moved by 4 bytes; in
  `netstack.wasm` the code section differed by 158 bytes.
- **The cause is cargo's `-C metadata`.** rustc derives a crate's identity (its
  `StableCrateId`) from it; the identity is in every symbol name, and how rustc splits a crate
  into codegen units depends on it, so it reaches the code. In `cargo build -v` of one small
  workspace on both systems, a crates.io crate without dependencies and a workspace crate
  directly in the root got the same value on both; a workspace crate in a subdirectory (`x/a`)
  got different values, its relative path being hashed with the platform's separator; and a
  crates.io crate's build script, with no dependencies, got different values, as did the crate
  itself, whose value mixes in its build script's. Every value mixes in its dependencies', and
  every component depends on `wit-bindgen`, which has a build script and a proc macro. A rustc
  wrapper that changed nothing but the value (a hash of what identifies the crate, below) made
  all 30 files agree: the value was the whole difference.
- **`build` gives every crate a value of its own** (`xtask/src/metadata.rs`). It runs cargo
  with `xtask` itself as `RUSTC_WRAPPER`, which replaces cargo's value with a hash of the
  package's name and version, the crate's name and types, the target, its `--cfg`s (the
  features) and its edition, and passes everything else through. With it, a Windows build and
  two Linux builds in different directories gave the same 30 files, byte for byte.
- The `producers` sections name only tool versions (rustc, clang of the WASI libc, wit-component,
  wit-bindgen, wac), and `wac compose` adds nothing that depends on paths or time.

What is guaranteed: the same revision, built with `cargo xtask artifacts` with the pinned
toolchain and tools, gives the same bytes in any checkout directory, for any user and cargo
home, **on Linux and on Windows**. `--rebuild` checks it, and CI's `platforms` job compares a
Linux and a Windows build's manifests on every push and pull request and fails when they
differ. macOS has not been tried.

What the wrapper costs:

- A wrapper that `RUSTC_WRAPPER` already named (a compiler cache) runs in turn, behind ours.
  One set only in a cargo configuration (`build.rustc-wrapper`) is overridden for the
  components' build.
- Cargo does not notice a change of wrapper, and would reuse crates built with its own values.
  The argument file is therefore named for the scheme too (`metadata::SCHEME`): another scheme,
  or none, means other flags, and cargo rebuilds.
- Two crates in one build that agree on everything hashed would get one identity: the same
  package name and version from two sources. rustc refuses to link two crates with the same
  `StableCrateId`, so that fails the build; it cannot miscompile.
- A component built by hand (`cargo build --target wasm32-wasip2 -p ...`) has other bytes
  than `build` gives, as it already had without the path mapping.

## Where a revision's set lives

The consumer is a build script or an xtask in another repository. It knows the revision it
pinned, wants no tool beyond what every machine has, and must check what it fetched against
hashes kept in its own repository. The candidates:

| | Per commit | Anonymous plain HTTPS | Fetch by hash | Cost and clutter |
|---|---|---|---|---|
| **OCI artifact** in `ghcr.io`, tagged with the commit | yes | yes, after a token request | yes: a blob is addressed by its SHA-256 | none in the repository; retention is a registry setting |
| **Release assets** | only with a release (and a tag) per commit | yes | no: by name under a tag | a release per commit buries the real releases |
| **A branch** of sets | yes | yes (raw files) | no | the repository's history grows by megabytes per commit, and every cargo git checkout of the repository fetches it |
| **The Pages site** | only by keeping old sets elsewhere: a deployment replaces the whole site | yes | no | a 1 GB site limit; shares the site with the browser page |
| **Actions artifacts** | yes | no: a download needs a token | no | expire after at most 90 days |

**The choice: an OCI artifact per commit**, `ghcr.io/<owner>/<repository>/components:<commit>`,
with every file a layer of media type `application/wasm` (and `manifest.toml` and `SHA256SUMS`
as layers too). The reasons:

- **The pin is the address.** A layer's digest is the SHA-256 of the file. An embedder that
  pinned `netstack.wasm`'s hash fetches `GET /v2/<repository>/blobs/sha256:<hash>` and checks
  the bytes: no tag, registry manifest or index has to be trusted, and a moved tag cannot
  change what it gets.
- **No tool.** An anonymous pull is two HTTPS requests: a token from
  `https://ghcr.io/token?scope=repository:<repository>:pull`, then the blob with it. `curl`,
  which Windows, macOS and most Linux systems ship, is enough; an embedder that already has an
  HTTP client uses it instead.
- **It is the convention.** Components are distributed as OCI artifacts in the component
  ecosystem (the Wasm OCI artifact layout, `wkg`, wasmCloud), so registries, mirrors and
  scanners know what they hold.
- **Nothing in the repository.** The source tree and its history stay small for the cargo git
  checkouts that embedders already make.

Release assets remain the right place for versioned releases, once there are any: the same
files and `SHA256SUMS`, attached to a release.

## How a build gets a set

`crates/wasmnet-artifacts` is the consumer's side, as a small library an embedder can depend
on (by git, at the revision it pins: cargo has that checkout anyway) or copy. It depends on
`sha2` and `thiserror` only.

```rust
// build.rs of an embedder
use wasmnet_artifacts::{Source, fetch, parse_sums};

// Lines copied from the set's SHA256SUMS into the embedder's repository.
let pins = parse_sums(include_str!("components.sha256"))?;
let source = match std::env::var_os("WASMNET_ARTIFACTS_DIR") {
    Some(dir) => Source::Dir(dir.into()),                       // a set built locally
    None => Source::oci("ghcr.io", "backkem/wasmnet/components"), // the published set
};
let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
let paths = fetch(&source, &pins, &out.join("components"))?;
```

`fetch` keeps a file that is already there with the pinned hash (a second build reads and
downloads nothing), and writes any other file under its name only after its bytes match the
pin. `fetch_with` takes another downloader than `curl`. A directory source works today: point
`WASMNET_ARTIFACTS_DIR` (the embedder's name for it) at what `cargo xtask artifacts` wrote, in
a checkout of the pinned revision. The example `cargo run -p wasmnet-artifacts --example fetch
-- SOURCE PINS OUT` does the same from the command line (`oci://ghcr.io/<repository>` or a
directory).

**Updating the pins** to a new revision is a step a person takes, not the build: read the new
revision's `SHA256SUMS`, check what changed, and commit the lines. From a published set,
`oras pull ghcr.io/<owner>/<repository>/components:<commit>` gets it; without oras, fetch the
registry manifest (`oci::manifest_url`, with `Accept: application/vnd.oci.image.manifest.v1+json`),
find the layer titled `SHA256SUMS`, and fetch that blob. Or build the set in a checkout of the
revision and read its `SHA256SUMS`.

## Publishing

Nothing is published yet. [artifacts-workflow.yml.example](artifacts-workflow.yml.example) is
the workflow, as a proposal that does not run: on a push to `main` it builds the set on a
fresh Linux and a fresh Windows runner, compares the two manifests, and pushes the Linux set to
`ghcr.io/<owner>/<repository>/components:<commit>` with `oras` only when they agree.

Enabling it means:

- copying it to `.github/workflows/artifacts.yml`;
- the workflow's `GITHUB_TOKEN` gets `packages: write` in the publishing job (the repository's
  settings must allow workflows to be granted it: Settings, Actions, General, Workflow
  permissions);
- after the first push, making the package public (the package's settings: change visibility)
  and checking that it is linked to the repository; anonymous pulls fail until it is public;
- deciding how long sets are kept (a registry retention policy, or none) and whether pull
  requests get sets too (this proposal publishes only from `main`).
