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

## 5. Windows options

| | W1. WSL2 distro + nested KVM + mvm Firecracker | W2. Native Hyper-V (HCS API) | W3. WSL2 utility VM as the boundary (no nested VM) |
|---|---|---|---|
| Boundary | Firecracker VM inside the WSL2 VM | Hyper-V partition per session | WSL2's single shared utility VM + namespaces |
| Reuse | the whole Linux backend, unchanged, inside a dedicated distro | guest image + kernel; needs a new host endpoint, agent transport over hvsocket, lifecycle | Linux backend option C, with extra holes |
| Requirements | Windows 11 (nested virtualization in WSL2), "Virtual Machine Platform" feature (one admin step), works on Home; CPU nested-virt support | Hyper-V / HCS availability on the target editions must be verified (Home is unclear); admin to enable | WSL2 only |
| Egress enforcement | same mvm vsock endpoint | must be built (hvsocket endpoint) | WSL2 NAT or mirrored networking gives the distro full network; would need the C-style netns |
| Host FS exposure | distro must disable `automount` and `interop` (`/etc/wsl.conf`) so the distro cannot reach `C:\` or run Windows binaries; the guest is one VM boundary further in | none by default | `/mnt/c` and interop are inside the same kernel as the hostile code |
| mvm status | `install/windows.md` says WSL2 is unsupported for workloads; but `mvm-core/src/platform/platform.rs:46` makes `has_kvm()` true on WSL2 when `/dev/kvm` exists. Contradictory; needs a spike | upstream mvm#428 (WHP) closed as not planned | n/a |

**Recommendation: W1 first, W2 as the long-term native path; reject W3.**
W1 makes Windows "Linux in a box": the Windows app installs a dedicated
`nearai-rts` WSL distro containing the Linux rts build, mvm and OpenCode, and
launches sessions with `wsl.exe -d nearai-rts -- rts launch ...`. The rts crate
never has to compile for Windows; the Windows side is a thin launcher in
trace-commons. Main trade-off: it needs Windows 11 with nested virtualization
and depends on mvm accepting WSL2 as a Firecracker host. Hosts without nested
virtualization are refused, not degraded.

Open items specific to W1: `/in` and `/out` crossing the Windows/WSL boundary
with automount off (stream tar over `wsl.exe` stdio rather than `/mnt/c`);
credential storage (no secret-service in WSL; keep the key in Windows
Credential Manager and pass it on stdin, or a 0600 file store inside the
distro); terminal rendering of the OpenCode TUI through `wsl.exe`.

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
