# Hyper-V guest: kernel, agent and initramfs

The Windows backend boots this kernel and initramfs with HCS
`LinuxKernelDirect`. The VM gets no network adapter. Its only channel to
the host is hvsocket. This directory holds the recipe for both
artifacts. rts pins their digests.

## Kernel

```sh
guest/hyperv/build.sh <out-dir>     # needs docker
```

What the build does:

- **Starts from a pinned tarball.** It uses kernel.org `linux-6.18.64.tar.xz`
  (longterm) and checks it against kernel.org's published sha256.
- **Uses a pinned toolchain.** The build runs in
  `debian:trixie-20261104-slim`, pinned by digest, with packages from
  `snapshot.debian.org` at 2026-11-04.
- **Fixes the embedded build metadata.** Timestamp, user and host are
  fixed (`SOURCE_DATE_EPOCH`, `KBUILD_BUILD_*`).
- **Builds a minimal config.** It starts from `make allnoconfig` and merges
  in `kernel.config`.
- **Checks the result before building.** The build fails if any requested
  option was dropped. It also fails if any option that would give the
  guest a device, a network or a module loader is on: Hyper-V virtual PCI,
  NETDEVICES, BLOCK, MODULES, IPv6 (its `sit0` tunnel is a second network
  device), NIC/storage/9p/CIFS/NFS/FUSE drivers, or the virtio and
  loopback vsock transports.
- **Keeps ACPI and core PCI on.** x86 finds VMBus through ACPI, and
  Hyper-V's DSDT has PCI configuration-space regions that fail to load
  without PCI support, which leaves VMBus (and hvsocket) absent. No PCI
  device driver is built.
- **Runs as amd64 on any host.** `build.sh` passes `--platform linux/amd64`.

Three builds on 2026-11-21 gave identical bytes: an arm64 Mac running
docker under Rosetta through colima. This kernel booted under HCS on
Windows (host build 26100). It probed VMBus, listed only `lo`, and
served hvexec to the host.

| file | sha256 |
| --- | --- |
| `vmlinuz` | `a331c0ab03687e36fea6ecca473c5fdb0351e76c0331f7be8fddd1cfe62b2d58` |
| `kernel.config.full` | `666857cb71ddef61d95b33f07d14236d63aaa66e1d0888deb8464ca20ec30dad` |

## Agent (`agent/`)

`rts-guest` runs commands rts sends over hvsocket:

- **One connection per command.** Each connection carries one command.
- **No shell.** The argv runs directly; nothing parses it as a shell line.
- **Unprivileged.** The agent runs as uid 1000, with every group dropped
  after it binds its vsock port.
- **Same protocol code as the host.** It speaks rts's `hvexec` protocol by
  including `src/hvexec/{wire,serve}.rs` as source, so host and guest
  cannot drift. Those files are tested in rts over a socket pair.

Build:

```sh
cd guest/hyperv/agent
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build --release --target x86_64-unknown-linux-musl
```

It is a static-pie binary. Its only dependency is the libc rts already
uses. The build verified here (rustc 1.100.0) has sha256
`d3299687563be85c03e6548c0ff6413d80a9cad0925fcf112d39d8c07af65bee`.
The agent build is not yet reproducible across toolchains; the release
pipeline will pin the toolchain.

## Initramfs

```sh
python3 -I guest/hyperv/build-initramfs.py <rts-guest> <out.cpio.gz>
```

What the script does:

- **Fetches the pinned guest image.** It pulls the amd64 member of the rts
  guest image (`6b72caa2…`) by digest and checks every blob against its
  digest.
- **Rebuilds the image's filesystem in memory.** It applies the layers,
  including whiteouts.
- **Adds rts's pieces.** It adds `/init`, the agent and an `rts` user.
- **Writes deterministic output.** The cpio and gzip are written with
  sorted entries and zero mtimes.

Standard library only.

With the agent above, two runs gave
`1286b5648649d1126b9416d111e6f98946632861aa89f7f956c9bcb91e42635a`.
