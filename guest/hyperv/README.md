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
  guest a device, a filesystem bridge or a module loader is on: PCI,
  NETDEVICES, BLOCK, MODULES, NIC/storage/9p/CIFS/NFS/FUSE drivers, or the
  virtio and loopback vsock transports.

Two runs on 2026-11-21 (with ACPI, which x86 VMBus discovery needs) (x86_64 Linux host, docker) gave identical bytes:

| file | sha256 |
| --- | --- |
| `vmlinuz` | `40272ed75e3af6ebc7618abd9c272ba352e049adfbcef05b86ee1b17ee1318f8` |
| `kernel.config.full` | `577c45c5b5a44b5096526da50acf43780a929aae5a5c7a4ffdaab98e0c148b30` |

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
`475d0ebd97a18856329eef916b788ff1fb8262aaa6f1923f2547cbc5821a3d04`.
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
`86be012012ab96c290f563d591440f691a4c8b59307e4cd6ba4e923fb22cdbfd`.
