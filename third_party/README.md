# Vendored code

| Directory | Upstream | License |
|---|---|---|
| `smoltcp/` | [smoltcp](https://github.com/smoltcp-rs/smoltcp) 0.14.0, the crates.io release (`.cargo_vcs_info.json` names the commit) | 0BSD (`smoltcp/LICENSE-0BSD.txt`) |

`smoltcp/` is the pristine crate plus three patches of ours, kept as patch files in
[`docs/upstream/`](../docs/upstream/):

1. `smoltcp-0001-neighbor-rate-limit-per-address.patch`: neighbor discovery is rate-limited
   per address instead of per interface.
2. `smoltcp-0002-snapshot-state.patch`: the `snapshot` feature, which reads and restores
   interface and socket state.
3. `smoltcp-0003-newreno-partial-acks.patch`: TCP fast recovery retransmits on partial ACKs
   (NewReno, RFC 6582).

The workspace patches it in with `[patch.crates-io]`, and the version stays `=0.14.0`, so
dropping a patch is one line once upstream has the change. Edit nothing here without
updating the matching patch file. [`docs/upstream/smoltcp.md`](../docs/upstream/smoltcp.md)
lists what we found in smoltcp along the way.
