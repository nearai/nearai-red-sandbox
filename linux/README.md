# rts-linux (prototype)

A Linux/bubblewrap backend for the **NEAR AI Red SandBox** contract. It is a small, readable
prototype for contributors who want to run the upstream OpenCode sandbox plugin on Linux before a
production microVM backend lands.

## What it reuses

- The upstream `plugin/` directory **unchanged**:
  - the six sandboxed tools (`shell`, `read`, `write`, `edit`, `glob`, `grep`);
  - the `question` tool;
  - the no-MCP rule;
  - the exact model allowlist;
  - the plugin audit log;
  - the ready-file handshake.
- The same tool request shape (`rts tool <name>` + JSON on stdin), so the plugin's `rts` option points
  at this script.
- `/tmp/in` copy-in, `/tmp/out` export and `/tmp/work` scratch space.

## What is different from the macOS/mvm sandbox

| mvm / SandBox | rts-linux prototype |
|---|---|
| Apple-silicon HVF microVM | Linux user-namespace bubblewrap jail |
| mvm image + supervisor | host root read-only + private `/tmp` |
| host-side proxy with host:port allowlist | **no guest network by default**; `--network` shares the host network (no allowlist proxy yet) |
| attestation and IronWire receipts | not implemented |
| canaries, RSS ceiling, session TTL | session record only; TTL is a `subprocess` timeout |
| interactive OpenCode TUI | headless `opencode run --standalone --format json` |

The prototype is **not** a replacement for the microVM boundary for hostile code. Use it for
development, CI smoke tests and Linux integration work; use mvm (or a Firecracker backend) for
untrusted production targets.

## Requirements

- Linux with unprivileged user namespaces (`bwrap` works)
- Python 3.10+
- `bubblewrap`
- OpenCode **2.2.2** for the pinned plugin contract (the upstream pin)
- An OpenAI-compatible provider, e.g. an RTH/Near AI gateway or NEAR AI Cloud

## Usage

```bash
# session.json
{
  "inputsDir": "./inputs",
  "provider": {
    "baseURL": "http://127.0.0.1:8001/v1",
    "model": "deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated",
    "apiKeyEnv": "NEARAI_API_KEY"
  },
  "limits": { "sessionHours": 1 },
  "network": { "allow": [] }
}
```

```bash
chmod +x linux/rts_linux.py
linux/rts_linux.py launch --config session.json \
  --opencode /path/to/opencode-2.2.2 \
  --prompt 'Review /tmp/in and save a report to /tmp/out/report.md.'
```

The session directory is printed. It contains `session.json`, `tools.jsonl` (plugin audit), `out/`
and `work/`.

Tool-only smoke test (no OpenCode, no model):

```bash
printf '%s' '{"options":{"root":"/tmp/rts-session"},"input":{"command":"uname -s"}}' \
  | linux/rts_linux.py tool shell
```

## Tests

```bash
python3 -m pytest linux/test_rts_linux.py -q
```

The tests exercise copy-in/out, path-escape refusal, the six tools, and no-network behavior. They
skip when `bwrap` is unavailable.

## Next steps toward a production Linux backend

1. Replace `--network` with the upstream host:port allowlist proxy (HTTP CONNECT/SOCKS) and audit
   `network.jsonl`.
2. Add canaries, host RSS ceiling, session TTL and export scanning.
3. Add a Firecracker backend behind the same `Sandbox`/`Exec` seam for high-risk sessions.
4. Add attestation/IronWire support and model receipts.
5. Upstream the backend into the Rust `Sandbox` trait once the contract is stable.

This directory intentionally does not modify the macOS launcher. It is additive and can be removed
without changing release behavior.
