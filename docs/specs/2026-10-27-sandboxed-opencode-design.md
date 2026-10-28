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
| mvm access | Shell out to `mvmctl`. No mvm SDK in v1. |
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
             bash/read/write/edit/glob/grep
               '-- mvmctl machine exec    ---> runs in guest, stdout/stderr/exit back
  3. on exit or signal:
       copy /out -> sessions/<id>/out     <--- /out only
       mvmctl machine rm rts-<session>
```

### Launcher (`launcher/`)

- Preflight: `mvmctl doctor`, and a check that the opencode binary reports the
  pinned version. Any failure refuses before a VM exists and names what is
  missing.
- Sweeps orphaned `rts-*` machines left by an earlier crash, before creating a
  new one.
- Creates `rts-<session-id>` from the configured image with the inputs mount,
  then starts opencode with the machine name passed to the plugin as an option.
- On normal exit, SIGINT or SIGTERM: export `/out`, then `mvmctl machine rm`.
  If the export fails, report it loudly and still remove the VM.

### Sandbox plugin (`plugin/`)

The allowlist is exactly six tool IDs: `bash`, `read`, `write`, `edit`, `glob`,
`grep`.

- One `ctx.tool.transform` replaces each allowlisted tool's `execute` with an
  implementation that runs through `mvmctl machine exec`, and removes every
  other tool.
- `ctx.mcp.transform` removes every MCP server.
- After setup, `ctx.tool.list()` must equal the allowlist exactly. Any extra or
  missing tool makes setup throw and the session does not start.
- A `tool` `execute.before` hook rejects any tool name outside the allowlist, a
  second layer behind the transform.
- `execute.before` / `execute.after` also write the audit log (below).

Tool implementations, all on guest paths:

| Tool | Guest-side implementation |
|---|---|
| `bash` | `sh -c <command>` in the guest. The only tool that gets a shell. |
| `read` | Line-range read, path passed as an argv entry. |
| `write` | Content sent on stdin, path as an argv entry. |
| `edit` | A small exact-match replacement applier, inputs via stdin and argv. |
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
   - `write` and `bash touch` of a sentinel path: present in the guest, absent
     on the host.
   - A network connection attempt from inside the guest fails.
   - With an MCP server configured and a second plugin adding a stray tool, the
     session refuses to start.
   - After the VM is killed mid-session, the next tool call errors and nothing
     runs on the host.
   - After SIGINT, no `rts-*` machine remains and `/out` was exported.
3. Leak-detection check: replacing one tool's implementation with a stub that
   runs on the host must turn the containment suite red.

## Repository layout

```
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

1. opencode v2.1.4 loads a V2 plugin from config.
2. The built-in tool IDs are exactly the six above, and `ctx.tool.list()`
   reflects removals.
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
