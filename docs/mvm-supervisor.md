# Patched mvm HVF supervisor

The sandbox requires the `rts-vsock-drain-v1` HVF supervisor patch for mvm
v0.22.0. The source base is the immutable upstream commit
`b6b77f83730bed54d52f5f8b9cdcd8d5136ca1de` in
[tinylabscom/mvm](https://github.com/tinylabscom/mvm/tree/b6b77f83730bed54d52f5f8b9cdcd8d5136ca1de).
The reviewed changes live in `patches/mvm-v0.22.0-hvf-drain.patch`.

Build on Apple-silicon macOS with Apple's command line tools, Git, and Rust
installed. The upstream `rust-toolchain.toml` selects its compiler. Cargo may
download that toolchain and locked dependencies. The isolated source and target
directories are temporary; allow several minutes and sufficient build disk space.

```sh
bash scripts/build-patched-mvm-supervisor.sh
```

To avoid cloning upstream, supply a clean checkout whose HEAD is exactly the
commit above. The script archives tracked files into its own temporary directory;
it never applies changes to the supplied checkout or copies its `target` directory.

```sh
bash scripts/build-patched-mvm-supervisor.sh --source /absolute/path/to/mvm
```

The script verifies the source revision and cleanliness, checks that the repository
patch applies, then builds only `mvm-hostd`'s `mvm-hvf-supervisor` binary with the
lockfile, explicit `aarch64-apple-darwin` target, `RUSTFLAGS='-D warnings'`, and
`CARGO_INCREMENTAL=0`. The explicit target prevents accidentally installing the
non-macOS stub. It checks the patch marker and helper contract, applies an ad-hoc
signature using the pinned source's hypervisor entitlement, verifies the signature,
then atomically replaces the private installed binary.

By default the binary is installed at
`$HOME/.local/share/nearai-red-sandbox/mvm-hvf-supervisor`. The installation
directory must be owned by you with mode `700`; a new directory gets that mode
automatically. Existing files must be owned regular files. Symlinks in the
installation path or destination are refused. `--install-dir /absolute/path`
selects another private directory. Existing mvm installations are untouched.

The launcher automatically selects that default installed path when
`MVM_HVF_SUPERVISOR_PATH` is unset. Inspect the installed marker and launch:

```sh
"$HOME/.local/share/nearai-red-sandbox/mvm-hvf-supervisor" --rts-vsock-drain-fix-version
# rts-vsock-drain-v1
"$HOME/.local/share/nearai-red-sandbox/mvm-hvf-supervisor" --contract-version
# mvm-hvf-supervisor contract-version=4
cargo run -- launch
```

For a custom `--install-dir`, set the absolute override for each launch,
including when launching an already built `rts` binary:

```sh
export MVM_HVF_SUPERVISOR_PATH="/absolute/private/install-dir/mvm-hvf-supervisor"
cargo run -- launch
```

A helper contract of `4` establishes compatibility with this mvmctl source
base; it does not establish that the drain patch is present. The separate patch
probe identifies this build's declared patch version. Launcher preflight requires
that marker and passes the selected absolute override to mvmctl, preventing mvm
from silently finding a stock supervisor beside its CLI.

The sibling `mvm-hvf-supervisor.build-info` records the upstream revision, local
patch hash, installed signed binary hash, compiler versions, and build flags.
These are build provenance for inspection, not a trusted signature or remote
attestation. The two files are replaced independently; only the executable is used
to run the VM. A marker and user-writable metadata cannot protect against a
malicious process running as the same user. Trust comes from reviewing the pinned
source and repository patch and building them locally.

This procedure reproduces the source inputs and build process. It does not claim
byte-identical binaries across machines or toolchains; absolute build paths and
ad-hoc signing can change the output hash. Ad-hoc signing grants the local
hypervisor entitlement and provides no Apple Developer identity or notarization.
Successful compilation and marker probes do not establish live VM correctness;
the containment and export tests remain separate validation gates.
