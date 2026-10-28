# Sandboxed opencode sessions on mvm: design

Date: 2026-10-27
Status: approved 2026-10-27, then amended by probes 1-5 the same day

## Purpose

Run opencode sessions for security research and red-teaming where every tool
call executes inside an mvm microVM, never in host user space. opencode itself
runs on the host and talks to NEAR AI inference. The microVM is the only place
tool effects land.

## Decisions

| Topic | Decision |
|---|---|
| Harness | opencode, a released v2 build pinned by version (v2.1.4, already installed). Plugin API V2; its tool API is identical in v2.1.4, v2.2.0 and `dev`. |
| Where the harness runs | Host. Tools are replaced, not intercepted, so execution goes to the VM. |
| Sandbox | mvm (`tinylabscom/mvm`, Apache-2.0), dev profile, `machine create` / `exec` / `rm` |
| Guest image | A digest-pinned OCI image (default `docker.io/library/alpine@sha256:e311ae74...ffb42`, the one the probes ran on). A Nix `mkGuest` image is deferred. |
| Inference | NEAR AI provider in the host opencode config. The key stays on the host; the VM never sees it. |
| VM egress | None. mvm default-deny, no `--allow-host`. |
| Files in | An operator inputs directory, packed into a tar on the host and pushed in after boot as base64 argv chunks, extracted to `/in`. A copy, not a live mount. |
| Files out | Only the guest's `/out`, copied to `sessions/<id>/out` before teardown. |
| Lifecycle | One VM per opencode session, always destroyed when the session ends, including on crash or signal. |
| mvm access | Shell out to `mvmctl` release v0.22.0, installed from the cosign-verified release tarball at `~/.local/mvm/v0.22.0`. No mvm SDK in v1. |
| Backend seam | Launcher and plugin talk to a `Sandbox` interface, never to `mvmctl` directly. mvm is the only v1 backend. |
| Language | TypeScript on bun for the launcher and plugin. Nix flake for the guest image. |

## Architecture

```
host (macOS)                                   mvm microVM (dev profile, no network)
-------------------------------------          -------------------------------------
launcher
  1. mvmctl machine create/start rts-<s> ---> boots image; inputs pushed to /in
  2. starts opencode (pinned v2 version)
       |-- NEAR AI provider (key on host)
       '-- sandbox plugin
             shell/read/write/edit/glob/grep
               '-- mvmctl machine exec    ---> runs in guest, stdout/stderr/exit back
  3. on exit or signal:
       copy /out -> sessions/<id>/out     <--- /out only
       mvmctl machine rm rts-<session>
```

### Sandbox interface (`sandbox/`)

```ts
interface Sandbox {
  create(spec: { name: string; image: string; memoryMiB: number; cpus: number }): Promise<void>
  exec(argv: string[], opts: { timeoutMs: number; maxOutputBytes: number }):
    Promise<{ exitCode: number; timedOut: boolean; stdout: Uint8Array; stderr: Uint8Array;
              stdoutBytes: number; stderrBytes: number; truncated: boolean }>
  copyIn(hostDir: string, guestDir: string): Promise<void>
  copyOut(guestDir: string, hostDir: string): Promise<void>
  remove(): Promise<void>
}
```

The v1 implementation, `MvmSandbox`, shells out to `mvmctl`. Every call is
argv-based; nothing is passed through a host shell. A second backend (for
example apple/container) would implement the same interface and must pass the
same containment suite.

`create` runs exactly `mvmctl machine create <name> --image <digest-ref>
--profile dev --cpus <n> --memory <MiB>M`, then `mvmctl machine start <name>`.
It never passes `--net`, `--allow-host`, `--peer`, or `--gpu`; those are what
would open a path out. Every `mvmctl` child gets stdin `/dev/null` and
`GIT_CONFIG_GLOBAL` pointing at an empty file.

`mvmctl machine exec` constraints measured on v0.22.0 (probe 4) shape the
implementation:

- **A nonzero exit poisons the machine.** After any exec whose guest command
  exits nonzero (`false`, `exit 3`), every later exec on that machine fails
  with `machine input sequence N has no durable finish; refuse exec and
  checkpoint until the ambiguous operation is recovered`, and a restart does
  not clear it. So every exec runs inside a guest-side wrapper that always
  exits 0 and reports the real status on stderr as a final line
  `RTS_EXIT_<nonce> <status>`, with a fresh random nonce per call. The status
  is information for the model, not a security property; a guest that forges
  it only misleads itself.
- **Killing the exec client from the host also poisons the machine.** Tool
  time limits are enforced in the guest by the wrapper with
  `timeout -s KILL <seconds>` (status 137 on expiry). The host keeps a
  backstop timer at the limit plus 30 s; if it fires, the machine is treated
  as lost and the session ends with `sandbox unavailable`.
- **stdin is not passed through**; the guest command reads nothing. `exec`
  is always spawned with stdin set to `/dev/null`. File content for `write`
  and `edit` travels in argv as base64, in chunks of at most 48 KiB, each
  appended in the guest with `base64 -d`. A 48 KiB random base64 argv was
  measured to work; the host's own `ARG_MAX` refused 1 MiB.
- **Large stdout is truncated silently.** An 8 MiB stdout arrived as
  974,403 bytes with no error. The wrapper writes the command's stdout to a
  guest temp file, and stderr to another, reports both full sizes in the
  trailer, and emits only the first `maxOutputBytes` of each, so `truncated`
  is computed from the reported sizes. The trailer line is
  `RTS_EXIT_<nonce> <status> <stdoutBytes> <stderrBytes>`.
- Any exec result containing the `no durable finish` error, or missing its
  trailer, means the machine is unusable: `exec` reports `sandbox
  unavailable` for that call and every later one.

Root cause of the poisoning, read from the v0.22.0 source: `machine exec`
journals a start (`machine/mod.rs:1448`) and a finish (`:1450`) around
`exec_machine`, but the console path calls `std::process::exit` on a nonzero
guest status (`vm/console.rs:320`), so the finish is never written. A host
kill skips it the same way. `main` at `054ec4c3` has the same structure. No
upstream issue was found as of 2026-10-27.

The SDK (`mvm` on npm) may use a different vsock path for `exec` and
`files.write`; that is the obvious v2 investigation if the argv protocol
becomes a bottleneck, and it needs its own dependency approval.

Other v0.22.0 behavior the implementation depends on (probe 5):

- `machine create` accepts any string as `--image`, including an error
  message, and only `machine start` rejects it. `MvmSandbox.create` accepts
  only a digest-pinned reference matching
  `^[a-z0-9./-]+@sha256:[0-9a-f]{64}$`.
- `machine rm` prompts for confirmation; without `--yes` it prints `aborted`
  and removes nothing. Teardown uses `rm --force --yes` and then confirms with
  `machine ps` that no machine of that name remains.
- `image inspect` has no `--digest-ref` in v0.22.0 (that flag is on `main`).
  The digest comes from the `Resolved digest:` line of `image inspect
  <full reference>`.
- An alpine machine (1 vCPU, 512 MiB) boots in about 2 s on the HVF backend.
- No egress, measured on a dev-profile alpine machine created as above: the
  only interface is `lo`; routes are blackholes for `100.64.0.0/10`,
  `169.254.0.0/16`, and `169.254.169.254`; there is no `/etc/resolv.conf`;
  `wget http://1.1.1.1` fails with `Network unreachable`.

`copyIn` packs the host inputs directory into a tar on the host and pushes it
as base64 argv chunks (the `write` path), then extracts it to `/in` in the
guest. v0.22.0 `machine create` has no mount flag, so this replaces the
boot-time mount the first draft assumed.

`copyOut` treats the guest as hostile. It archives `/out` inside the guest,
reads the archive back in base64 chunks of at most 512 KiB (under the silent
stdout truncation measured near 950 KB), checks the reassembled size against
the size the guest reported, and extracts it with a host-side extractor
that accepts only regular files and directories. It rejects symlinks,
hardlinks, device nodes, absolute paths, and any path containing `..`, and
caps total size and entry count. microsandbox's GHSA-4vq3-cjpp-v7fg (a guest
symlink in `msb copy` writing arbitrary host files) is the class of bug this
blocks.

### Launcher (`launcher/`)

- Preflight: `mvmctl doctor`, and a check that the opencode binary reports the
  pinned version. Any failure refuses before a VM exists and names what is
  missing.
- Sweeps orphaned `rts-*` machines left by an earlier crash, before creating a
  new one.
- Creates and starts `rts-<session-id>` from the configured image, runs
  `copyIn` for the inputs directory,
  then starts opencode with the machine name passed to the plugin as an option.
- Runs opencode with `--standalone` (a private server per session). Without it,
  v2 attaches to the operator's shared background service, which loads the
  operator's own config and plugins.
- Points `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`, and
  `XDG_STATE_HOME` at a per-session directory, so no global opencode plugins,
  config, auth, or session history load. The only config is the one the
  launcher writes.
- Runs opencode with its working directory set to an empty, launcher-created
  directory, never the operator's project. opencode loads `opencode.json` and
  `AGENTS.md` from its working directory, and a project `opencode.json` can
  declare local MCP servers that opencode spawns as host processes (probe 3).
  Operator inputs reach the VM through `copyIn` only.
- Plugin handshake: the launcher passes a random per-session nonce as a plugin
  option. After its allowlist checks pass, the plugin writes the nonce to a
  ready file. If the ready file does not appear with the right nonce before a
  deadline, the launcher kills opencode and removes the VM. This is required
  because v2.1.4 skips a plugin that fails to load with only a log warning (a
  configured path that is a file rather than a directory is one such case) and
  then runs the session with the host tools.
- On normal exit, SIGINT or SIGTERM: export `/out`, then `mvmctl machine rm`.
  If the export fails, report it loudly and still remove the VM.

### Sandbox plugin (`plugin/`)

opencode v2.1.4 registers 20 built-in tools (measured, probe 2). The plugin
keeps seven:

- Sandboxed, `execute` replaced: `shell`, `read`, `write`, `edit`, `glob`,
  `grep`.
- Kept unchanged because it executes nothing: `question` (asks the operator in
  the opencode UI).

It removes the other thirteen, among them `patch` (see below), `webfetch` and `websearch` (host
network), `opencode_worktree_create` / `_remove` (host git), `subagent`,
`skill`, `opencode_session_*`, `opencode_models`, and the MCP resource tools.

- One `ctx.tool.transform` replaces each sandboxed tool's `execute` with an
  implementation that runs through the `Sandbox` interface, and removes every
  tool not on the list. opencode re-runs transforms on reload, so the
  transform is idempotent.
- `ctx.mcp.transform` removes every MCP server.
- `ctx.model.transform` keeps only the NEAR AI provider's models. With no
  credentials configured, v2.1.4 still offers about 80 models from opencode's
  own hosted service; without this step a prompt could go there instead of
  NEAR AI.
- After setup, `ctx.tool.list()` must equal the seven-tool list exactly and
  every remaining model must be NEAR AI. Anything else makes setup throw, the
  ready file is never written, and the launcher refuses the session.
- A `tool` `execute.before` hook rejects any tool name outside the allowlist, a
  second layer behind the transform.
- `execute.before` / `execute.after` also write the audit log (below).

Tool implementations, all on guest paths:

| Tool | Guest-side implementation |
|---|---|
| `shell` | `sh -c <command>` in the guest, with `workdir` applied by `cd` inside the wrapper. The only tool whose input is run as a shell command. `background: true` is refused, since exec is synchronous. |
| `read` | Bounded guest read (`head -c`), path as an argv entry. Line slicing and the `<line>: <content>` prefix are applied on the host. A directory returns one entry per line. Text only; images and PDFs are not returned. |
| `write` | Content as base64 argv chunks, decoded and appended in the guest into a temp file that is then renamed over the target. Path as an argv entry. |
| `edit` | Read the file from the guest, apply the exact-match replacement on the host (a pure function), and write it back as `write` does. Fails if `oldString` is missing, or matches more than once without `replaceAll`. Refuses, writing nothing, when the read reports `truncated` (file larger than `maxOutputBytes`), so a large file is never written back short. |
| `glob` | Guest `find <root> -type f` (bounded), then the pattern matched on the host with `Bun.Glob`. |
| `grep` | Guest `grep -rn`, with `-F` for `literal`, `-i` when `caseSensitive` is false, and `--include` for `include`. Pattern and root as argv entries. Exit status 1 (no match) is reported as no matches, not an error. |

The file tools never interpolate arguments into a shell string; their
fixed scripts read operands from `"$1"`, `"$2"` and so on. `patch` is
removed rather than sandboxed: implementing opencode's patch format is out of
scope for v1, and `edit` and `write` cover the same ground.

### Guest image

A digest-pinned OCI image, pulled with `mvmctl image pull` before the first
session. The operator chooses it; the default is the alpine digest the probes
ran on. A Nix `mkGuest` flake is deferred: it needs mvm's builder VM, which
was not exercised. The harness requires `sh`, coreutils, `find`, `grep`,
`timeout`, `base64`, and `tar` in the guest (busybox provides all of them, as
in the alpine image used for the probes), plus a writable `/out` and `/tmp`.

## Error handling

Every failure ends in a refusal or a tool error. Nothing falls back to the host.

- VM create fails: opencode is never started.
- Allowlist mismatch at plugin setup: setup throws, the session does not start.
- Tool call exceeds its time limit (configurable, default 120 s): the guest
  wrapper's `timeout -s KILL` ends the command (status 137) and the tool
  returns a timeout error. If the host backstop fires instead, the machine is
  lost and the session ends.
- VM dies mid-session: tool calls return `sandbox unavailable`. The plugin does
  not recreate the VM, since the session's state would be gone without notice.
- Exec output is capped before it reaches the model, with a truncation marker.
- `/out` export fails at teardown: reported, VM still removed.
- `/out` archive contains a rejected entry: extraction stops, the partial host
  directory is removed, and the rejection is reported.
- Each VM gets a fixed memory cap (default 2 GiB). Because of
  GHSA-x85r-49ww-2pxq (guest-driven host memory growth through vsock), the
  launcher also samples the per-VM host process RSS and tears the session down
  if it exceeds a configured ceiling.

## Audit

- mvm's hash-chained audit log records each launch plan.
- The launcher writes `sessions/<id>/tools.jsonl`, one line per tool call: tool
  name, call ID, SHA-256 of the input, status, and duration. Inputs and outputs
  are not stored in this log.

## Testing

Written test-first.

1. Unit tests (`tests/unit/`) run the tool implementations against a fake
   executor: argv construction, line ranges, edit semantics, truncation, and
   timeout mapping.
2. Containment tests (`tests/contain/`) run against real mvm:
   - `write` and `shell touch` of a sentinel path: present in the guest, absent
     on the host.
   - A network connection attempt from inside the guest fails.
   - With an MCP server configured and a second plugin adding a stray tool, the
     session refuses to start.
   - After the VM is killed mid-session, the next tool call errors and nothing
     runs on the host.
   - After SIGINT, no `rts-*` machine remains and `/out` was exported.
   - A guest `/out` containing a symlink to a host path, a hardlink, a `..`
     entry, and an oversized file: none is written to the host, and the export
     reports a rejection.
3. Exec-protocol tests (`tests/contain/`, real mvm), one fresh machine each:
   - A guest command exiting 3, then `echo ok`: the first reports status 3,
     the second succeeds (the wrapper prevents poisoning).
   - `sleep 30` with a 3 s limit: a timeout error with status 137, and the
     next exec succeeds.
   - A 2 MiB stdout with `maxOutputBytes` 64 KiB: exactly 64 KiB returned,
     `truncated: true`, and the reported full size is 2,097,152.
   - A 200 KiB random binary `write` (several argv chunks), read back
     byte-exact by sha256 in the guest.
   - `edit` on a file larger than `maxOutputBytes` is refused and the file's
     guest sha256 is unchanged.
   - An exec result without a valid trailer, simulated by a fake executor in
     the unit tests, marks the sandbox unavailable for every later call.
4. Leak-detection check: replacing one tool's implementation with a stub that
   runs on the host must turn the containment suite red.

## Repository layout

```
sandbox/         Sandbox interface, MvmSandbox, hostile-archive extractor
launcher/        TypeScript CLI (bun): preflight, VM lifecycle, export, orphan sweep
plugin/          opencode V2 plugin: tool transform, allowlist check, audit hooks
opencode/        pinned version and opencode config (NEAR AI provider, plugin enabled)
tests/unit/      fake-executor tests
tests/contain/   real-mvm containment suite and the leak-detection check
sessions/        per-session out/ and tools.jsonl (gitignored)
docs/specs/      design documents
```

## Out of scope for v1

- VM egress allowlists.
- Persistent or reused VMs.
- The mvm SDK.
- Concurrent sessions.
- Linux hosts (Firecracker should work unchanged, but is not tested).
- Guest image contents beyond the harness minimum.
- A Nix `mkGuest` guest image (needs the builder VM, not exercised).

## Checks before the implementation plan is final

Each is a short probe. None is assumed.

1. Done 2026-10-27: opencode v2.1.4 runs a V2 `{ id, setup }` plugin loaded
   from a directory path in config, and passes config options to it. A file
   path is skipped with only a warning (hence the handshake).
2. Done 2026-10-27: the 20 built-in tool IDs are as listed under the sandbox
   plugin, and `ctx.tool.list()` reflects a removal made in the transform.
3. Done 2026-10-27: removing servers in `ctx.mcp.transform` stops local MCP
   servers from both global and project config from spawning. Control: with
   removal off, both spawned and wrote their sentinel files. Not covered:
   servers added by another plugin after ours. The XDG isolation and the
   launcher-owned working directory mean no other plugin loads, and the plugin
   also checks that `ctx.mcp.list()` is empty before writing the ready file.
4. Done 2026-10-27: `exec` returns the guest exit code and keeps stdout and
   stderr separate, but does not pass stdin, poisons the machine on a nonzero
   exit or a host-side client kill, and truncates large stdout silently. See
   the constraints under the sandbox interface.
5. Done 2026-10-27: dev-profile `machine create` / `start` / `exec` /
   `rm --force --yes` work on the macOS HVF backend.

## Host setup notes (measured 2026-10-27)

- mvm v0.22.0 is installed from the release tarball, not the `curl | sh`
  installer. Verification: sha256 matches `checksums-sha256.txt`, and
  `cosign verify-blob` passes on both files with the certificate identity
  pinned to `https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.22.0`
  and issuer `https://token.actions.githubusercontent.com`. The certificate's
  commit, `b6b77f83`, is the `v0.22.0` tag commit.
- The tarball's binaries carry no VM entitlements. `mvmctl env sign`
  ad-hoc re-signs `mvmctl` (`com.apple.security.virtualization`) and
  `mvm-hvf-supervisor` (`com.apple.security.hypervisor`); `mvmctl doctor`
  fails until it has run.
- A source build was abandoned: its bootstrap cross-compiles the guest runtime
  and needs `cargo-zigbuild`, `zig`, and the `aarch64-unknown-linux-musl`
  target.
- mvm's git reader rejects `includeIf "hasconfig:..."` entries in the
  operator's global git config. The launcher runs every `mvmctl` command with
  `GIT_CONFIG_GLOBAL` pointing at an empty file; the operator's git config is
  not modified.

## Dependencies requiring approval before install

- mvm (`mvmctl`), release v0.22.0. Approved 2026-10-27. Four advisories were published
  2026-10-26, none with a patched version listed. Relevant here:
  GHSA-x85r-49ww-2pxq (medium), where a guest can grow host memory through the
  vsock device model. That is a denial-of-service on the host, not an escape,
  but this design assumes a hostile guest. Not relevant: the externally signed
  plan replay (not used), the GPU endpoint (not enabled), and the Firecracker
  `/tmp` socket issue (Linux only).

opencode v2.1.4 and bun 1.3.3 are already installed and need no new install.
