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
guest/hyperv/build-agent.sh <out-dir>     # needs docker
```

It builds in a digest-pinned `rust:1.100.0-slim-trixie` image (amd64)
from `agent/Cargo.lock`. It links with rust-lld and remaps the build
paths, so two runs give identical bytes on any docker host. The result is
a static-pie binary whose only dependency is the libc rts already uses.

Two builds (an arm64 Mac under Rosetta) gave
`0d376deb57a697258e3ed2c8c1dddfa56759185fb5c4e4d868b2ca93213f6855`.

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
`cdef2be2e9e687ebdd32b96717e687cb5b43723c142ddcf5a71b4d5b056b0a00`.

## Release

`.github/workflows/hyperv-guest.yml` runs on every pull request that
touches the guest. It rebuilds `vmlinuz` and `initramfs.cpio.gz` from this
directory, and `check-pins.sh` fails the run unless both match the pins in
`src/backend/hyperv/backend.rs`. Those are the digests rts checks before
every boot.

The workflow publishes only on a `hyperv-guest-v*` tag that carries an SSH
signature from a key in `allowed_signers`. It reads that file from the
default branch (`main`), never from the tag. So until this directory,
including `allowed_signers`, is on `main`, no tag can be verified and
nothing is published. Publishing creates the release that `rts setup`
downloads from.
