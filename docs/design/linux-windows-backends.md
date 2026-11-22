# Linux and Windows backends

Status: proposal, 2026-11-20. No code changes yet; see "Phase 1 decision".

rts runs today only on Apple-silicon macOS: each session is an mvm v0.22.0
microVM on Hypervisor.framework (HVF), driven by `mvmctl`, with a patched
`mvm-hvf-supervisor`. This document maps what is platform-neutral, compares
isolation options for Linux and Windows, fixes the invariants every backend
must hold, and proposes PR-sized phases, Linux first.

## 1. Where the session actually runs

This matters for every option below, so it comes first:

- **OpenCode runs on the host**, as a child of the launcher
  (`session::session_body`, `Terminal::spawn`). It talks only to the embedded
  IronWire proxy, which talks only to the attested, key-pinned forwarder
  (`launch::run` -> `forwarder::Forwarder::start`, `inference::start_with_endpoint`).
- **The guest runs only tool commands.** The OpenCode plugin spawns
  `rts tool <name>` (`bridge::run`), which reconstructs an `MvmSandbox` handle
  from `BridgeOptions` (machine, mvmctl, mvmHome, emptyGitConfig, stateDir)
  and runs a wrapped argv through `mvmctl` (`MvmSandbox::exec`,
  `protocol::wrap_argv`).
- **Guest egress is mvm's, not rts's.** The guest has no NIC. Apps reach the
  network through `mvm-egress-client`'s SOCKS5/HTTP proxy on `127.0.0.1:1080`
  and DNS stub on `127.0.0.1:53` inside the guest, over authenticated FlowMux on
  vsock port 5253, to a per-VM host `mvm-network-endpoint` that applies the
  `--allow-host` list and writes `<mvm root>/audit/local.jsonl`
  (`docs/research/2026-10-29-mvm-v0.22.0-egress.md`). rts plans and resolves the
  allowlist (`network::plan`), passes it as `--allow-host`
  (`MvmSandbox::create`), probes it from inside the guest (`network::run_probes`,
  deny-all probe to `1.1.1.1:443`), and checks mvm's pinned IPs against its own
  resolution (`session::wait_for_pins`, `network::check_pinned`).

So the inference path never crosses the guest boundary, and the guest's only
route out is mvm's endpoint. A new backend must reproduce the guest side of
that contract (proxy at `127.0.0.1:1080`, `nc` in the image for probes, `/in`,
`/out`, `/tmp` layout) or the probes and `network::proxy_env` must become
backend-supplied.

## 2. Platform-neutral vs mvm/macOS-specific

### Neutral (compiles and behaves the same on any Unix today)

| Area | Files / items |
|---|---|
| Attestation | `attest.rs`, `attest/{tdx,nras,report,record,http}.rs` (TDX via vendored dcap-qvl, NRAS, per-environment policy from #47) |
| Pinned forwarder, receipts | `forwarder.rs`, `forwarder/{pin,signature}.rs` |
| IronWire embed | `inference.rs` |
| Launch orchestration | `launch::run`, `LaunchSpec`, `resolve_and_attest`, `start_connected` |
| Config and limits | `config.rs` (`check_host_fit`, `DEFAULT_IMAGE` is a pin, not a platform) |
| Allowlist planning and records | `network::{expand, plan, Plan::*, refused_range, read_pinned, check_pinned, extract_audit}` (they parse mvm's audit format, which is the same on every mvm host) |
| Sandbox seam | `sandbox::{Exec, Sandbox, CreateSpec, Egress}`, `copy.rs`, `untar.rs`, `protocol.rs` |
| Tool bridge logic | `bridge::call`, `tools.rs`, `canary.rs` (has `cfg(target_os = "linux")` already) |
| Auth, update, brand, terminal | `auth/*` (Linux secret-service store already in `Cargo.toml`), `update/*`, `brand/*`, `terminal.rs` (pty) |

"Neutral" means Unix-neutral. 23 of 46 source files use `std::os::unix` or
`libc::` directly (`attest/record.rs auth/sponsored.rs auth/tests.rs brand.rs
brand/splash.rs brand/theme.rs bridge.rs canary.rs copy.rs forwarder/signature.rs
inference.rs install.rs launch.rs main.rs mvm.rs network.rs session.rs setup.rs
sys.rs terminal.rs untar.rs update.rs update/apply.rs`). The crate does not
compile for Windows, and trace-commons already depends on it only under
`cfg(target_os = "macos")` (`trace-commons-contributor/Cargo.toml`).

### mvm-specific (would differ per VMM even within mvm)

| Item | Where | HVF today | Firecracker equivalent (mvm v0.22.0 source) |
|---|---|---|---|
| VMM process for RSS ceiling | `session::Supervisor::{discover,sample}`, `host_rss_mib` | `<mvm root>/vms/<name>/hvf.pid`, comm `mvm-hvf-supervisor` | `fc.pid`, comm `firecracker` (`mvm-client/src/local.rs`, `mvm-core/src/config.rs`) |
| Network process tree | `session::network_children`, `NETWORK_PROCESSES`, teardown kill | children of `machine run`: `mvm-network-endpoint`, `mvm-hvf-supervisor` | endpoint likely the same; Firecracker is started via `sudo` and detaches (`mvm-backends/src/fc/daemon.rs`), so it is not a plain child and runs as root: rts cannot `kill -KILL` it |
| Patched supervisor | `session::{supervisor_path, check_supervisor_marker, check_supervisor_contract, mvm_environment}`, `install::{prefix_supervisor, home_supervisor}`, `setup::supervisor_step`, `patches/mvm-v0.22.0-hvf-drain.patch` | required (`rts-vsock-drain-v1`) | the patch touches mvm's in-house VMM (`mvm-vmm/src/vmm/vsock*.rs`, `agent_bridge.rs`, `host_write.rs`), which Firecracker does not use; whether Firecracker's own vsock has the same copy-out drain bug is untested |
| Host preflight | `session::preflight` (`mvmctl doctor --workflow bundle-run`), `network::check_mvm_host` | same | same commands; doctor result differs |
| Release components | `setup::{mvm, opencode}` | `mvmctl-aarch64-apple-darwin.tar.gz`, `opencode-darwin-arm64.zip` | release assets exist: `mvmctl-{x86_64,aarch64}-unknown-linux-gnu.tar.gz`, `opencode-linux-{x64,arm64}.tar.gz` (checked with `gh release view`) |
| Guest image | `config::DEFAULT_IMAGE`, `guest/Dockerfile` | digest-pinned; arch of the pinned digest not checked here | x86_64 Linux hosts need an amd64 (or multi-arch index) digest |
| Bridge handle | `bridge::run`, `BridgeOptions` | rebuilds `MvmSandbox` + `SpawnRunner` | same |

trace-commons calls several of these directly: `rts::mvm::SpawnRunner`,
`rts::session::{mvm_environment, RealHost}`, `rts::install::prefix_supervisor`,
`rts::setup::{run_in_prefix, SetupContext, SetupOptions, HttpsFetch,
ReleaseArchive}`, `rts::config::Defaults::for_prefix`, `rts::launch::{LaunchSpec,
run, private_git_config}`. Those paths must keep working; the per-OS backend
should be reachable through `rts::setup` and `rts::launch` so trace-commons
stops naming mvm types over time.

## 3. The backend abstraction

`sandbox::Sandbox` already isolates exec/copy/create/remove. What still leaks
into `session.rs` and `bridge.rs` is session-level: preflight, host-config
checks, orphan sweep, network-path liveness, the VMM process to sample, egress
evidence (pins, audit), teardown residue, and how a `rts tool` process
re-attaches. Proposed shape (sketch, not final):

```rust
/// One isolation backend, chosen per OS at launch. LaunchSpec and
/// launch::run do not change; session_body talks only to this.
pub trait Backend: Send + Sync {
    /// Host checks before any machine command (doctor, VMM binary, host
    /// config that could widen egress). Called after the OpenCode check.
    fn preflight(&self, env: &[(String, String)]) -> Result<(), String>;
    /// Preserve-and-log sweep of machines from earlier launches.
    fn sweep(&self, log: &mut dyn FnMut(&str)) -> Result<(), String>;
    /// Create the machine; returns the live handle.
    fn create(&self, spec: &CreateSpec) -> Result<Box<dyn Machine>, String>;
    /// What a `rts tool` process needs to reach the same machine
    /// (serialized into plugin options, parsed by bridge::run).
    fn bridge_options(&self, machine: &str) -> serde_json::Value;
}

pub trait Machine: Sandbox + Send {
    /// Some(reason) once the egress path is gone (session must end).
    fn network_lost(&self) -> Option<String>;
    /// Host RSS of the VMM process, checked against the ceiling.
    fn host_rss_mib(&self) -> Result<u64, String>;
    /// Pinned IPs per allowlisted name, from the backend's egress audit.
    fn pinned(&self) -> Result<Pinned, String>;
    /// After remove(): kill residue, copy egress audit to `out`.
    fn finish(&mut self, network_audit: &Path, log: &mut dyn FnMut(&str));
}
```

`MvmBackend { flavor: Hvf | Firecracker }` would implement it; the flavor
carries the pid-file name, process names, supervisor requirements and release
asset names from the table above. A non-mvm backend (Windows native) would be a
second `impl Backend`.

## 4. Linux options

| | A. mvm on Firecracker/KVM | B. rts drives Firecracker or cloud-hypervisor directly | C. bubblewrap + seccomp + netns |
|---|---|---|---|
| Boundary | hardware VM, own kernel | hardware VM | shared host kernel (namespaces + seccomp + Landlock) |
| Guest image | same OCI image, same mvm agent | rts must build OCI->ext4, kernel, guest exec agent | host's `/usr` or an unpacked rootfs; no kernel |
| Egress forced through allowlist | guest has no NIC; mvm endpoint over vsock, confined with Landlock + seccomp on Linux (stronger than macOS, where it is unconfined) | rts must write a vsock allowlist proxy + DNS pinning + audit | netns with only `lo`; an rts-owned allowlist proxy reached over a bind-mounted UDS and relayed to `127.0.0.1:1080` inside; rts must write the proxy, DNS pinning and audit |
| Install friction | `/dev/kvm` access; **v0.22.0 launches Firecracker through `sudo` for any non-root caller** (`fc/daemon.rs::sudo_prefix_for_euid`), unjailed, default seccomp filter | `/dev/kvm` via `kvm` group only; rootless; jailer possible | `bwrap` package; unprivileged userns (restricted by AppArmor on recent Ubuntu; whether bwrap is exempt varies by release, not verified here) |
| rts code reuse | nearly all (`MvmSandbox`, probes, pins, audit) | exec/copy seam only | exec/copy seam only; existing Python prototype is not reusable as-is |
| Known blockers | v0.22.0 (latest stable, pinned by rts) fails every Linux egress handshake: mvm#3962, fixed on mvm `main` (musl endpoint), not in a stable release. GHSA-7pc3-7vgg-jqxr (high, `/tmp` socket dir + sudo chown, Firecracker/Linux only) | large new surface rts would own | kernel attack surface is the boundary for hostile code |

**Recommendation: A**, with two preconditions that are hard gates, not
nice-to-haves:

1. An mvm build that passes the egress handshake on Linux (a post-v0.22.0
   stable release, or a source-pinned commit built in rts's release workflow
   the way the HVF supervisor already is) and carries the GHSA-7pc3 fix.
2. Firecracker must not run as root. With the user in the `kvm` group, sudo
   buys nothing for a no-NIC workload VM (mvm's own comment justifies sudo by
   `/dev/kvm` and TAP access; workload VMs have no TAP). Either upstream a
   "no sudo when `/dev/kvm` is writable" change or carry it as an rts patch
   next to the HVF one. A root VMM also breaks rts's teardown kill and makes a
   GTK app prompt for a password mid-launch.

Why not C: it fails the threat model (hostile code against a shared kernel) and
would make rts own an allowlist proxy, DNS pinning and audit that mvm already
does better confined. Why not B: it reimplements mvm. Keep `linux/rts_linux.py`
as the documented dev-only prototype; do not ship a degraded "bubblewrap mode"
that sessions silently fall back to.

## 5. Windows: a native Hyper-V backend

Owner decision (2026-11-21): Windows runs a native Hyper-V backend in rts.
There is no WSL2 and no mvm on Windows. The WSL2 spike's result is kept in
section 5.9 for the record.

### 5.1 API choice

| | HCS (`computecore.dll`, compute system JSON) | Hyper-V WMI / PowerShell (`Msvm_*`, `New-VM`) | hcsshim (Go) |
|---|---|---|---|
| Direct kernel boot (`LinuxKernelDirect`: kernel + initrd + cmdline) | yes, used by WSL2 and LCOW | no: Gen1/Gen2 boot from firmware and a disk | yes (it wraps HCS) |
| Per-VM hvsocket service table and security descriptors | yes, in the VM document | registry only | yes |
| Ephemeral, unnamed systems that die with their last handle | yes (`ShouldTerminateOnLastHandleClosed`) | no: registered VMs persist in Hyper-V Manager | yes |
| From Rust | a few `extern "system"` calls (`windows-sys` has them, feature `Win32_System_HostComputeSystem`) | COM/WMI or spawning PowerShell | a Go runtime or a sidecar |
| Spike result | boots our guest in about 0.75 s, no NIC, hvsocket exec works, also as a non-admin member of Hyper-V Administrators | not tried | not tried |

**Choice: HCS.** It is what WSL2 itself uses, it boots a kernel and initrd
directly, it scopes hvsocket access per VM, and its systems are ephemeral.
WMI would leave persistent VMs behind and needs a disk image and firmware boot.
hcsshim would bring in a Go runtime.

### 5.2 Guest boot

- **Kernel:** a pinned Linux kernel with `CONFIG_HYPERV=y` (VMBus),
  `CONFIG_HYPERV_VSOCKETS` and `CONFIG_VSOCKETS`, no network drivers loaded, and
  `console=ttyS0` for a COM-port log. The spike used Ubuntu's
  `linux-image-7.0.0-1020-azure` (vmlinuz sha256 `eda095ff…`), with `vsock.ko` and
  `hv_sock.ko` loaded from the initrd. For production, either pin that package
  by its Ubuntu archive digest, or build a kernel with those options built in (`=y`)
  and every NIC driver off, so there is nothing to load. mvm's Firecracker
  kernel has no VMBus drivers, so it can't be reused.
- **Root filesystem:** derived from the pinned amd64 guest image
  `guest@sha256:6b72caa2…`. rts setup pulls it by digest with rts's own OCI
  client (checking every blob digest), flattens the layers into a read-only
  ext4 or erofs image (or, for a first version, a cpio initrd), and records the
  image's sha256 beside it. A small rts-owned init in the initrd verifies that
  digest before mounting it, as mvm checks its dm-verity roothash. `/tmp` is a
  per-VM tmpfs, as on mvm, so `/in` and `/out` stay the same links into `/tmp/rts`.
- **Guest agent:** an rts-owned static binary (`rts-guest`, built from this
  repo for `x86_64-unknown-linux-musl`). It serves the exec protocol rts
  already speaks (`protocol::wrap_argv` / `parse_result`: exit code, capped
  output, timeouts) over hvsocket. The spike's `hvexec.c` is the minimal
  version.

### 5.3 Host <-> guest channel

- hvsocket. Host side: `AF_HYPERV` (34) / `HV_PROTOCOL_RAW`, bound to
  `{VmId, ServiceId}`. Guest side: `AF_VSOCK` to CID 2 with the `hv_sock`
  transport. A vsock port maps to the service GUID
  `{port:08x}-facb-11e6-bd58-64006a7986d3`.
- Each compute system's document lists its services in
  `HvSocketConfig.ServiceTable`, with bind and connect security descriptors
  that admit only the session's user (the spike used SYSTEM, Administrators
  and Hyper-V Administrators).
- The host listener binds that VM's id, never the wildcard. The host must
  also register the service once under
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices\{guid}`.
  That needs admin, so the installer does it.
- `rts tool` reaches the session's channel through a per-session named pipe or
  the hvsocket itself, plus the existing state-dir lock and the "unavailable"
  marker (`MvmSandbox` semantics: one exec at a time, poisoned on a host-side
  kill).

### 5.4 Egress

The same shape as mvm's design:
- The VM document has no `NetworkAdapters`; the spike's guest sees only `lo`.
- The guest's loopback SOCKS/HTTP proxy (`127.0.0.1:1080`) and DNS stub forward
  over a second hvsocket service to a host-side endpoint in rts.
- That endpoint applies the allowlist, pins resolved IPs, writes a
  `network.jsonl` audit, and refuses everything else.

rts already has the allowlist planning, probes and pin checks, which are
platform-neutral. What's new is:
- the endpoint itself. Port mvm's FlowMux endpoint, or write a minimal
  CONNECT-only proxy, since rts's probes and `proxy_env` only use HTTP CONNECT;
- a confinement story for it on Windows: an AppContainer or a restricted-token
  child process, in place of Landlock/seccomp.

With no NIC, the guest has no route except this endpoint, which the deny-all
probe and the "no network device" invariant check.

### 5.5 /in copy-in and /out export

The existing tar streams (`copy::copy_in_via` / `copy_out_via`) run over the
exec channel, with the same `untar.rs` hostile-archive rejection on the host.
There is no shared folder (no Plan 9, no VSMB), so the guest sees no host
path.

### 5.6 Process limits

- The VM's memory and vCPU count are set in its compute system document.
- The worker process (`vmwp.exe`) is created by the Hyper-V service, not by
  rts, so it can't be put in an rts job object. Instead, rts samples the
  compute system's memory (`HcsGetComputeSystemProperties`, statistics) for
  the RSS ceiling.
- The rts-owned host processes (the egress endpoint, `rts tool`) run in a job
  object with memory and process-count limits and kill-on-close, so nothing
  outlives the session.
- Teardown: `HcsTerminateComputeSystem`, then close the handle. With
  `ShouldTerminateOnLastHandleClosed`, a crashed rts also takes the VM down.

### 5.7 Privileges

- **One-time admin steps at install:**
  - enable `Microsoft-Hyper-V-All` (reboot);
  - add the user to `Hyper-V Administrators`;
  - register the hvsocket service GUIDs.
- **Every session runs unelevated.** The spike created, booted and talked to a
  compute system as `rtsuser`, which is only in Hyper-V Administrators and
  Users, at Medium integrity.
- **Windows editions:** Hyper-V needs Windows 11 Pro, Enterprise or Education,
  so **Windows Home is not supported** (it has no Hyper-V role).
- **Azure VMs:** nested virtualization is needed (D4s_v4 works).

### 5.8 Making the rts crate compile for `x86_64-pc-windows-msvc`

23 files use `std::os::unix` or `libc`. By kind:

- **File modes and private files**: `fs::PermissionsExt`/`OpenOptionsExt`, in
  `attest/record.rs`, `auth/*`, `brand/theme.rs`, `bridge.rs`,
  `forwarder/signature.rs`, `inference.rs`, `launch.rs`, `network.rs`,
  `setup.rs`, `untar.rs`, `update*.rs`, `mvm.rs`, `session.rs`. A small
  `sys::private_file` / `sys::private_dir` helper: 0600/0700 on Unix, an
  owner-only DACL on Windows.
- **Symlinks** (`copy.rs`, `install.rs`, `session.rs`, `update.rs`): the guest
  side is Linux either way. Host-side uses get a Windows path (junction or
  copy) or are cfg'd to Unix where they only serve the mvm backend.
- **Terminal and splash** (`terminal.rs`, `brand.rs`, `brand/splash.rs`: pty,
  termios, ioctl, poll): a Windows implementation on ConPTY
  (`CreatePseudoConsole`) behind the same `Terminal` API.
- **Signals and process groups** (`sys.rs`, `session.rs`): Ctrl-C/close
  handlers plus job objects on Windows.
- **Canary directory scans** (`canary.rs`: `openat`/`fdopendir` race-free
  walks): a Windows walk with handle-relative opens (`NtCreateFile` with
  `RootDirectory`), or a narrower check.
- **FIFOs** (`main.rs` `mkfifo`): a named pipe.
- **The mvm backend and the KVM helpers** (`mvm.rs`, `backend/mvm.rs`,
  `backend/kvm.rs`): `#[cfg(unix)]` only. Windows builds just the Hyper-V
  backend.

The platform-neutral core (attestation, forwarder, IronWire, config,
allowlist planning, protocol, untar checks) needs no change beyond the file
helpers. Keychain storage: Windows Credential Manager through the existing
`keyring-core` store family, which may be a new store crate to propose.

### 5.9 Record: the WSL2 spike (not pursued)

- WSL 3.0.5 with `nestedVirtualization=true` exposes `/dev/kvm` in a WSL2
  distro.
- mvm v0.22.0's doctor accepts WSL2 and picks Firecracker, and machines boot.
  But `machine exec` fails ("no host-side console transport"), because mvm
  treats only native Linux as a Firecracker runner. Upstream main does the
  same.
- A one-line mvm change would fix that. It was dropped by owner decision and
  kept as a patch for reference.
- rts unit tests pass in WSL2 (564 passed, 0 failed).

### 5.10 How the shared invariant tests prove each property on Hyper-V

`tests/contain/invariants.rs` drives a `Backend`. A `HyperVBackend`
implements the same `Machine`, so the same four tests run on Windows:

| Invariant | Test on Hyper-V |
|---|---|
| No route out without an allowlist | deny-all probe; `ip -o link` shows only `lo` (the spike's guest already does: `/sys/class/net` = `lo`) |
| Allowlist exact and pinned | probes through the hvsocket endpoint; pins from its audit log |
| No host files except /in and /out | the host-path checks plus `/in` copy and `/out` export over the exec channel (no shared folders in the VM document) |
| VMM confirmed, RSS ceiling | `Monitor` reads the compute system's memory statistics |

`src/backend/invariants.rs` gets a Hyper-V fake: a recording HCS seam,
checking that the VM document has no `NetworkAdapters` and no shares, and that
its hvsocket table lists only the session's services, bound to the VM id.

### 5.11 Phased plan for Windows

1. **Spike** (done 2026-11-21): HCS `LinuxKernelDirect` boot with no NIC,
   exec over hvsocket, also as a non-admin Hyper-V Administrators member. See
   `docs/research/2026-11-21-hyperv-hcs-spike.md`.
2. **Crate compiles for x86_64-pc-windows-msvc**: the file, terminal, signal
   and FIFO helpers in 5.8 behind `sys`; the mvm backend `cfg(unix)`. CI:
   `cargo check --target x86_64-pc-windows-msvc`. Needs the `windows-sys`
   proposal approved.
3. **Guest artifacts**: kernel pin, `rts-guest` agent (musl static), and the
   rootfs derived from `guest@sha256:6b72caa2…`, with digest checks. Built and
   checksummed in CI.
4. **`HyperVBackend` without egress**: create, exec, copy, remove, monitor
   (HCS through `windows-sys`), plus fake-seam unit tests. Live invariants 1, 3
   and 4 on rts-win-dev.
5. **hvsocket egress endpoint**: CONNECT proxy, allowlist, pins, audit,
   confinement (AppContainer or restricted token). Live invariant 2.
6. **Windows setup and installer**: feature check, Hyper-V Administrators,
   hvsocket service registration, pulling the guest artifacts, and Credential
   Manager for keys. Then trace-commons' Windows app.

## 6. Invariants every backend must hold, and how each proves it

| Invariant | Proof on every backend |
|---|---|
| No guest route except the allowlist path | `network::run_probes`: allowlisted targets connect through `127.0.0.1:1080`; deny-all probe to `1.1.1.1:443` unreachable directly and through the proxy; a live-host CI job per backend runs these against a real machine |
| Allowlist resolution is what the egress path pinned | `wait_for_pins` + `check_pinned` against the backend's audit; unit tests with fixture audit lines per backend format |
| Egress is audited | `extract_audit` copies to `sessions/<id>/network.jsonl`; live test asserts one line per probe |
| No host FS except `/in` copy-in and `/out` export | live test: guest lists `/`, tries `$HOME`, `/mnt`, `/Users`, `/home`, host-path canaries; `copy.rs` / `untar.rs` rejection tests (already platform-neutral) |
| Inference only via the attested, pinned forwarder | unchanged code path (`launch::run`); `forwarder` tests are host-side and run on every OS |
| Attestation before any inference | `run_connected` ordering tests (existing) |
| Receipts per response | `forwarder/signature.rs` tests (existing) |
| Session TTL, RSS ceiling, canaries | `session_limit`, `Machine::host_rss_mib` per flavor, `canary` tests |
| No fallback to the host | `RTS_TEST_LEAK` seam stays refused in real sessions (`preflight`) |

Each backend gets (1) the existing unit suite, (2) a backend-flavor unit suite
with a fake runner (pid file, process names, release asset names), and (3) a
live smoke on a real host: macOS runner today; a KVM-capable Linux runner
(self-hosted or a cloud VM with nested virt) for Linux; a Windows 11 nested-virt
runner for W1.

## 7. Install and setup per OS

- **macOS**: unchanged (`rts setup` installs mvmctl, the signed patched
  supervisor, OpenCode, pulls the image).
- **Linux**: `rts setup` picks `mvmctl-<arch>-unknown-linux-gnu.tar.gz` and
  `opencode-linux-<arch>.tar.gz` by target, checks `/dev/kvm` is writable by
  the user and otherwise prints the one admin command
  (`sudo usermod -aG kvm $USER`, re-login) instead of running it. No
  `NOPASSWD` sudo, ever. trace-commons' GTK app runs the same `run_in_prefix`
  and shows that message. Secret storage: the existing secret-service store.
  The pinned release archive for embedders is
  `rts-<v>-x86_64-unknown-linux-gnu.tar.gz` (`scripts/package-linux.sh`):
  `bin/rts` and the plugin, no supervisor; `run_in_prefix` installs only the
  plugin from it. As on macOS, setup's `mvm` runner, the launch
  (`LaunchSpec.env`) and the `rts tool` bridge must share one mvm root
  (MVM_HOME, else `HOME/.mvm`): mvmctl keeps its image cache, VM state and
  bootstrap's guest-runtime cache there, and a launch under another root
  does not find them. Leaving MVM_HOME unset for setup and launch (root
  `HOME/.mvm`), as trace-commons' macOS app does, satisfies it.
- **Windows (W1)**: the trace-commons Windows app checks Windows 11 + "Virtual
  Machine Platform" + nested virtualization, asks the user once to enable the
  feature (admin, reboot), imports the `nearai-rts` distro from a signed
  rootfs tarball with a hardened `wsl.conf`, then runs `rts setup` inside it.

## 8. Phased plan (PR-sized, Linux first)

1. **Linux spike (no rts merge).** On a KVM host with mvm `main` (or a newer
   stable): one `machine run --allow-host` session, the rts probes, pin check,
   copy-in/out of a large tree (drain bug check), confirm the Firecracker pid
   file, process tree, and whether it can run without sudo. Output: a research
   note in `docs/research/`. Gates everything below.
2. **mvm pin bump / Linux mvm build.** Either a new stable mvm pin for all
   platforms (re-validating macOS) or a source-built Linux mvm in the release
   workflow, plus the no-sudo patch if upstream will not take it.
3. **Backend trait refactor (pure).** Introduce `Backend`/`Machine` with
   `MvmBackend { Hvf }` only; session.rs and bridge.rs go through it. Bar:
   zero edits to existing test bodies, macOS behaviour identical.
4. **Firecracker flavor.** `MvmBackend { Firecracker }`: pid file, process
   names, RSS, network-children, teardown, unit tests with a fake runner.
5. **Linux setup.** Per-target components in `setup.rs`, `/dev/kvm` check,
   multi-arch guest image digest, `rts setup` on Linux.
6. **Linux CI live smoke** on a KVM runner; release artifacts for Linux.
7. **trace-commons Linux.** Move the `rts` dependency from macOS-only to
   macOS + Linux; GTK app setup flow.
8. **Windows spike (W1).** Win11 nested virt, WSL2 distro, mvm Firecracker
   under WSL2; record whether mvm needs a change to accept `Platform::Wsl2`.
9. **Windows launcher** in trace-commons: distro import, hardened `wsl.conf`,
   `/in` `/out` streaming, credentials.
10. **(Later) W2 native Hyper-V** backend, only if W1's Windows 11 /
    nested-virt requirement excludes too many users.

## 9. Phase 1 decision

The task allowed implementing the backend trait as a pure refactor now. I
stopped at this document because:

- The seam is not small: `session_body`, `Live::teardown`, `run_session_with_prompt`
  and `bridge::run` reach about a dozen mvm-specific items (section 2), and the
  session tests assert exact ordered mvmctl/host call lists through a fake
  runner. Moving preflight pieces behind a trait changes that order unless done
  with care.
- With Linux on mvm/Firecracker, the trait would have one implementation and
  the real variation lives inside mvm (pid file, process names, sudo). Fixing
  the trait's shape before the Linux spike (phase 1 above) risks guessing the
  wrong seams; the spike tells us what `Machine` actually needs.

Superseded: the owner asked for the refactor now; see 9a.

## 9a. Status, 2026-11-20

Owner decisions: move every platform to a newer mvm once a release has the
Linux egress fix (none yet: latest stable is v0.22.0; only `v0.28.0-rc.*`
tags exist, without release assets); no root VMs; refuse hosts without KVM
or nested virtualization; Windows 11 with nested virtualization is the
floor, pending a spike.

Done on this branch (macOS host only):

- `src/backend.rs`: `Backend`, `Machine`, `Monitor`. `session_body`, its
  teardown and the launch preflight use them; `backend::mvm::MvmBackend`
  adapts the existing mvm plumbing with no behaviour change.
- `backend::mvm::Flavor::{Hvf, Firecracker}`, Firecracker selected on
  Linux. `src/backend/kvm.rs`: `/dev/kvm` access check, a `sudo` shim that
  never elevates placed first on mvmctl's PATH, and a check that the VMM
  is not root before OpenCode starts. `setup::Target` pins the Linux
  mvmctl and OpenCode assets.
- `src/backend/invariants.rs` (per flavor, fake mvmctl) and
  `tests/contain/invariants.rs` (this host's flavor, real machine).

Still needs a real Linux KVM host, then a Windows 11 host:

- Whether mvm v0.22.0's Firecracker path works with the non-elevating
  `sudo` (or needs a patch), and whether `machine exec` from `rts tool`
  needs it too (`bridge::run` does not set it today).
- A post-#3962 mvm release, then re-pin every platform.
- `rts setup` on Linux: skip the HVF supervisor and codesign steps, check
  KVM; the release archive layout for Linux.
- The session unit tests in `session.rs` assume HVF (supervisor probe in
  the call lists); on Linux they need the HVF flavor injected or gating.
  So do `setup::tests::the_pinned_components_match_the_spec` (asserts the
  macOS assets through `mvm()`/`opencode()`) and the zip fixtures, which
  use `/usr/bin/ditto`.
- Whether mvm-network-endpoint is a child of the attached `machine run` on
  Firecracker, as `track_network` requires (it is on HVF).
- A guest image digest for x86_64; the live invariants and the rest of
  `tests/contain` on a KVM host; trace-commons' Linux dependency.

## 10. Open questions for the owner

1. Is Linux-on-mvm acceptable given that it requires moving off mvm v0.22.0
   (Linux egress broken in that release)? Bump the pin for macOS too, or carry
   a separate Linux mvm build?
2. Carry an rts patch to stop mvm running Firecracker as root via sudo, or
   push it upstream first and wait?
3. Should a host without KVM (or Windows without nested virtualization) be
   refused outright, or is an explicitly labelled reduced-isolation mode
   (bubblewrap) ever acceptable for any user tier?
4. Windows: is Windows 11 + nested virtualization an acceptable floor for the
   first Windows release?
5. Who provides a KVM-capable CI runner (self-hosted, or a cloud VM with
   nested virt)?
6. Is the pinned guest image digest arm64-only? Publishing a multi-arch index
   changes the digest every platform pins.
