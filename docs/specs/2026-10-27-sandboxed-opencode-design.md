# Sandboxed opencode sessions on mvm: design

Date: 2026-10-27
Status: draft, awaiting review

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
| Inference | NEAR AI provider in the host opencode config. The key stays on the host; the VM never sees it. |
| VM egress | None. mvm default-deny, no `--allow-host`. |
| Files in | Read-only inputs directory, copied in at boot by mvm. |
| Files out | Only the guest's `/out`, copied to `sessions/<id>/out` before teardown. |
| Lifecycle | One VM per opencode session, always destroyed when the session ends, including on crash or signal. |
| mvm access | Shell out to `mvmctl`, built from source at `054ec4c3` (main, 2026-10-27). No mvm SDK in v1. |
| Backend seam | Launcher and plugin talk to a `Sandbox` interface, never to `mvmctl` directly. mvm is the only v1 backend. |
| Language | TypeScript on bun for the launcher and plugin. Nix flake for the guest image. |

## Architecture

```
host (macOS)                                   mvm microVM (dev profile, no network)
-------------------------------------          -------------------------------------
launcher
  1. mvmctl machine create rts-<session>  ---> boots image, inputs copied in read-only
  2. starts opencode (pinned v2 version)
       |-- NEAR AI provider (key on host)
       '-- sandbox plugin
             shell/read/write/edit/patch/glob/grep
               '-- mvmctl machine exec    ---> runs in guest, stdout/stderr/exit back
  3. on exit or signal:
       copy /out -> sessions/<id>/out     <--- /out only
       mvmctl machine rm rts-<session>
```

### Sandbox interface (`sandbox/`)

```ts
interface Sandbox {
  create(spec: { name: string; image: string; inputs?: string; memoryMiB: number; cpus: number }): Promise<void>
  exec(argv: string[], opts: { stdin?: Uint8Array; timeoutMs: number; maxOutputBytes: number }):
    Promise<{ exitCode: number; stdout: Uint8Array; stderr: Uint8Array; truncated: boolean }>
  copyOut(guestDir: string, hostDir: string): Promise<void>
  remove(): Promise<void>
}
```

The v1 implementation, `MvmSandbox`, shells out to `mvmctl`. Every call is
argv-based; nothing is passed through a host shell. A second backend (for
example apple/container) would implement the same interface and must pass the
same containment suite.

`copyOut` treats the guest as hostile. It archives `/out` inside the guest,
streams the archive to the host, and extracts it with a host-side extractor
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
- Creates `rts-<session-id>` from the configured image with the inputs mount,
  then starts opencode with the machine name passed to the plugin as an option.
- Runs opencode with `--standalone` (a private server per session). Without it,
  v2 attaches to the operator's shared background service, which loads the
  operator's own config and plugins.
- Points `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`, and
  `XDG_STATE_HOME` at a per-session directory, so no global opencode plugins,
  config, auth, or session history load. The only config is the one the
  launcher writes.
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
keeps eight:

- Sandboxed, `execute` replaced: `shell`, `read`, `write`, `edit`, `patch`,
  `glob`, `grep`.
- Kept unchanged because it executes nothing: `question` (asks the operator in
  the opencode UI).

It removes the other twelve, among them `webfetch` and `websearch` (host
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
- After setup, `ctx.tool.list()` must equal the eight-tool list exactly and
  every remaining model must be NEAR AI. Anything else makes setup throw, the
  ready file is never written, and the launcher refuses the session.
- A `tool` `execute.before` hook rejects any tool name outside the allowlist, a
  second layer behind the transform.
- `execute.before` / `execute.after` also write the audit log (below).

Tool implementations, all on guest paths:

| Tool | Guest-side implementation |
|---|---|
| `shell` | `sh -c <command>` in the guest. The only tool that gets a shell. |
| `read` | Line-range read, path passed as an argv entry. |
| `write` | Content sent on stdin, path as an argv entry. |
| `edit` | A small exact-match replacement applier, inputs via stdin and argv. |
| `patch` | The same applier, taking opencode's patch format on stdin. |
| `glob` | `find`, pattern and root as argv entries. |
| `grep` | `grep`, pattern and root as argv entries. |

The file tools never interpolate arguments into a shell string.

### Guest image (`image/`)

An mvm `mkGuest` Nix flake with `entrypoint.shell` (dev profile). The operator
supplies the contents. The harness requires only `sh`, coreutils, `find`, and
`grep` in the guest, plus a writable `/out`.

## Error handling

Every failure ends in a refusal or a tool error. Nothing falls back to the host.

- VM create fails: opencode is never started.
- Allowlist mismatch at plugin setup: setup throws, the session does not start.
- Tool call exceeds its time limit (configurable, default 120 s): the exec is
  killed and the tool returns an error.
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
3. Leak-detection check: replacing one tool's implementation with a stub that
   runs on the host must turn the containment suite red.

## Repository layout

```
sandbox/         Sandbox interface, MvmSandbox, hostile-archive extractor
launcher/        TypeScript CLI (bun): preflight, VM lifecycle, export, orphan sweep
plugin/          opencode V2 plugin: tool transform, allowlist check, audit hooks
image/           Nix mkGuest flake
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

## Checks before the implementation plan is final

Each is a short probe. None is assumed.

1. Done 2026-10-27: opencode v2.1.4 runs a V2 `{ id, setup }` plugin loaded
   from a directory path in config, and passes config options to it. A file
   path is skipped with only a warning (hence the handshake).
2. Done 2026-10-27: the 20 built-in tool IDs are as listed under the sandbox
   plugin, and `ctx.tool.list()` reflects a removal made in the transform.
3. `ctx.mcp.transform` covers every MCP source: global config, project config,
   and plugin-added servers.
4. `mvmctl machine exec` passes stdin through and returns the guest exit code.
5. Dev-profile `machine create` / `exec` / `rm` works on the macOS HVF backend.

## Dependencies requiring approval before install

- mvm (`mvmctl`), built from source. Four advisories were published
  2026-10-26, none with a patched version listed. Relevant here:
  GHSA-x85r-49ww-2pxq (medium), where a guest can grow host memory through the
  vsock device model. That is a denial-of-service on the host, not an escape,
  but this design assumes a hostile guest. Not relevant: the externally signed
  plan replay (not used), the GPU endpoint (not enabled), and the Firecracker
  `/tmp` socket issue (Linux only).

opencode v2.1.4 and bun 1.3.3 are already installed and need no new install.
