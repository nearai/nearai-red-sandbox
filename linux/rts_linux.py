#!/usr/bin/env python3
"""rts-linux: a small Linux/bubblewrap prototype for the NEAR AI Red SandBox contract.

This is deliberately a prototype, not a production microVM:
- it reuses upstream `plugin/` unchanged (six sandboxed tools, model allowlist, no MCP);
- it copies inputs into a private root, exports /out, and records a session;
- it uses bubblewrap user namespaces instead of mvm/HVF;
- network is off by default; `--network` shares the host network (no allowlist proxy yet);
- no attestation, canaries, or host RSS ceiling yet.

Usage:
  rts-linux launch --config session.json --prompt "Review /in" [--network]
  rts-linux tool shell                 # JSON request on stdin, called by the plugin
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TOOLS = ("shell", "read", "write", "edit", "glob", "grep")
MAX_OUTPUT = 65_536
PROMPT_MAX = 65_536


def die(message: str, code: int = 1) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)


# ------------------------------------------------------------------ path safety
def safe_path(root: Path, raw: str) -> Path:
    if not raw:
        raise ValueError("path is required")
    candidate = (root / raw.lstrip("/")).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise ValueError("path escapes the session root")
    return candidate


def _guest(root: Path, path: str) -> Path:
    """Map /in/foo, /out/foo, /work/foo to the host session root."""
    p = path.strip()
    if p in ("/in", "/tmp/in"):
        return root / "in"
    if p in ("/out", "/tmp/out"):
        return root / "out"
    if p in ("/work", "/tmp/work"):
        return root / "work"
    if p.startswith("/in/"):
        return safe_path(root / "in", p[3:].lstrip("/"))
    if p.startswith("/out/"):
        return safe_path(root / "out", p[4:].lstrip("/"))
    if p.startswith("/work/"):
        return safe_path(root / "work", p[5:].lstrip("/"))
    if p.startswith("/tmp/in/"):
        return safe_path(root / "in", p[7:].lstrip("/"))
    if p.startswith("/tmp/out/"):
        return safe_path(root / "out", p[8:].lstrip("/"))
    if p.startswith("/tmp/work/"):
        return safe_path(root / "work", p[9:].lstrip("/"))
    return safe_path(root / "work", p)


# ------------------------------------------------------------------ tools
def tool_shell(root: Path, options: dict, payload: dict) -> str:
    command = payload.get("command")
    if not isinstance(command, str) or not command:
        raise ValueError("command is required")
    if payload.get("background"):
        raise ValueError("background mode is not supported")
    timeout = max(1, int(payload.get("timeout_ms") or options.get("timeoutMs") or 120_000)) / 1000
    argv = [
        "bwrap",
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--unshare-user",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--bind",
        str(root / "in"),
        "/tmp/in",
        "--bind",
        str(root / "out"),
        "/tmp/out",
        "--bind",
        str(root / "work"),
        "/tmp/work",
        "--chdir",
        "/tmp/work",
        "--setenv",
        "HOME",
        "/tmp/work",
        "--setenv",
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ]
    if not options.get("network"):
        argv.append("--unshare-net")
    argv += ["--", "/bin/sh", "-c", command]
    try:
        result = subprocess.run(argv, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ValueError(f"command timed out after {timeout:.0f}s")
    out = result.stdout
    err = result.stderr
    text = out[:MAX_OUTPUT].decode("utf-8", "replace")
    if err:
        text += ("\n" if text else "") + "[stderr]\n" + err[:MAX_OUTPUT].decode("utf-8", "replace")
    if result.returncode != 0:
        text += f"\n[exit {result.returncode}]"
    return text


def tool_read(root: Path, options: dict, payload: dict) -> str:
    path = _guest(root, payload.get("path", ""))
    if not path.exists():
        raise ValueError("file not found")
    if path.is_dir():
        return "\n".join(sorted(p.name + ("/" if p.is_dir() else "") for p in path.iterdir()))
    text = path.read_text(errors="replace")
    offset = max(1, int(payload.get("offset") or 1))
    limit = max(1, int(payload.get("limit") or 2000))
    lines = text.splitlines()[offset - 1 : offset - 1 + limit]
    return "\n".join(f"{offset + i}: {line}" for i, line in enumerate(lines))[:MAX_OUTPUT]


def tool_write(root: Path, options: dict, payload: dict) -> str:
    path = _guest(root, payload.get("path", ""))
    content = payload.get("content")
    if not isinstance(content, str):
        raise ValueError("content is required")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return f"wrote {path.relative_to(root)} ({len(content)} bytes)"


def tool_edit(root: Path, options: dict, payload: dict) -> str:
    path = _guest(root, payload.get("path", ""))
    old = payload.get("oldString")
    new = payload.get("newString")
    if not isinstance(old, str) or not isinstance(new, str):
        raise ValueError("oldString and newString are required")
    text = path.read_text()
    count = text.count(old)
    if count == 0:
        raise ValueError("oldString not found")
    if count > 1 and not payload.get("replaceAll"):
        raise ValueError(f"oldString matches {count} times; set replaceAll")
    path.write_text(text.replace(old, new, -1 if payload.get("replaceAll") else 1))
    return f"edited {path.relative_to(root)}"


def tool_glob(root: Path, options: dict, payload: dict) -> str:
    pattern = payload.get("pattern") or "*"
    base = _guest(root, payload.get("path") or "/work")
    matches = []
    for path in base.rglob("*"):
        if path.is_file() and fnmatch.fnmatch(str(path.relative_to(base)), pattern):
            matches.append(str(path.relative_to(root)))
            if len(matches) >= 500:
                break
    return "\n".join(sorted(matches))


def tool_grep(root: Path, options: dict, payload: dict) -> str:
    pattern = payload.get("pattern")
    if not pattern:
        raise ValueError("pattern is required")
    literal = bool(payload.get("literal"))
    case_sensitive = bool(payload.get("caseSensitive"))
    include = payload.get("include")
    base = _guest(root, payload.get("path") or "/work")
    regex = re.compile(re.escape(pattern) if literal else pattern, 0 if case_sensitive else re.I)
    out = []
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if include and not fnmatch.fnmatch(path.name, include):
            continue
        try:
            for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                if regex.search(line):
                    out.append(f"{path.relative_to(root)}:{n}: {line[:400]}")
                    if len(out) >= 200:
                        return "\n".join(out)
        except OSError:
            continue
    return "\n".join(out)


def tool_call(name: str) -> int:
    if name not in TOOLS:
        die(f"tool not allowed in sandbox: {name}", 2)
    try:
        request = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        die(f"bad tool request: {exc}", 2)
    options = request.get("options") or {}
    payload = request.get("input") or {}
    root = Path(options.get("root") or "").expanduser().resolve()
    if not root.is_dir():
        die("sandbox session root is unavailable", 3)
    try:
        result = {
            "shell": tool_shell,
            "read": tool_read,
            "write": tool_write,
            "edit": tool_edit,
            "glob": tool_glob,
            "grep": tool_grep,
        }[name](root, options, payload)
    except Exception as exc:  # noqa: BLE001
        die(f"{name} failed: {exc}", 1)
    sys.stdout.write(result)
    return 0


# ------------------------------------------------------------------ launch
def load_config(path: str | None) -> dict:
    if not path:
        return {}
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        die(f"cannot read config: {exc}", 2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rts-linux")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("tool", help="execute one sandboxed tool (plugin bridge)")
    p.add_argument("name")
    p = sub.add_parser("launch", help="run a headless OpenCode session in a bwrap sandbox")
    p.add_argument("--config", default=None)
    p.add_argument("--prompt", default=None)
    p.add_argument("--prompt-file", default=None)
    p.add_argument("--network", action="store_true", help="share the host network (no allowlist proxy yet)")
    p.add_argument("--sessions-dir", default=None)
    p.add_argument("--plugin-dir", default=None)
    p.add_argument("--opencode", default="opencode")
    args = parser.parse_args(argv)
    if args.cmd == "tool":
        return tool_call(args.name)
    if args.cmd == "launch":
        return launch(args)
    return 2


def launch(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    base = Path(args.config).resolve().parent if args.config else Path.cwd()
    prompt = args.prompt
    if args.prompt_file:
        prompt = Path(args.prompt_file).read_text()
    if prompt is None:
        die("a --prompt or --prompt-file is required for the headless prototype", 2)
    prompt = prompt[:PROMPT_MAX]
    provider = cfg.get("provider") or {}
    base_url = provider.get("baseURL") or os.environ.get("RTS_LINUX_PROVIDER_URL") or "http://127.0.0.1:8001/v1"
    model = provider.get("model") or os.environ.get("RTS_LINUX_MODEL") or "deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated"
    api_key_env = provider.get("apiKeyEnv") or "NEARAI_API_KEY"
    api_key = provider.get("apiKey") or os.environ.get(api_key_env) or ""
    limit = (cfg.get("limits") or {}).get("sessionHours", 1)
    network = bool(args.network or (cfg.get("network") or {}).get("allow"))
    sessions_dir = Path(args.sessions_dir or os.environ.get("RTS_LINUX_SESSIONS") or (Path.cwd() / "sessions")).resolve()
    sessions_dir.mkdir(parents=True, exist_ok=True)
    sid = "rts-" + secrets.token_hex(6)
    root = sessions_dir / sid
    for sub in ("in", "out", "work"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    inputs = cfg.get("inputsDir")
    if inputs:
        src = (base / inputs).resolve()
        if not src.is_dir():
            die(f"inputsDir not found: {src}", 2)
        for item in src.iterdir():
            dest = root / "in" / item.name
            if item.is_dir():
                shutil.copytree(item, dest, symlinks=False)
            else:
                shutil.copy2(item, dest)
    plugin_dir = Path(args.plugin_dir or (Path(__file__).resolve().parents[1] / "plugin")).resolve()
    if not (plugin_dir / "package.json").is_file():
        die(f"plugin directory not found: {plugin_dir}", 2)
    nonce = secrets.token_hex(16)
    ready = root / "ready"
    options = {
        "machine": sid,
        "nonce": nonce,
        "readyFile": str(ready),
        "auditFile": str(root / "tools.jsonl"),
        "provider": "rth",
        "models": [model],
        "rts": str(Path(__file__).resolve()),
        "bridge": {"machine": sid, "root": str(root), "network": network, "timeoutMs": 120_000},
    }
    opencode = {
        "$schema": "https://opencode.ai/config.json",
        "plugin": [[str(plugin_dir), options]],
        "provider": {
            "rth": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "RTH Linux Sandbox",
                "options": {"baseURL": base_url, "apiKey": api_key},
                "models": {model: {"name": "RTH model", "tool_call": True}},
            }
        },
        "model": f"rth/{model}",
        "enabled_providers": ["rth"],
        "share": "disabled",
        "autoupdate": False,
    }
    global_dir = root / "home" / ".config" / "opencode"
    global_dir.mkdir(parents=True, exist_ok=True)
    (global_dir / "opencode.json").write_text(json.dumps(opencode, indent=2))
    # Keep a copy beside the session for review; OpenCode reads the global config above.
    (root / "opencode.json").write_text(json.dumps(opencode, indent=2))
    (root / "AGENTS.md").write_text(
        "You are running inside a Linux bwrap sandbox. Inputs are in /tmp/in, writable work is "
        "/tmp/work, and /out/tmp is exported when the session ends. Network is "
        + ("enabled (host namespace; prototype has no allowlist proxy)." if network else "disabled.")
        + " Use only the provided shell/read/write/edit/glob/grep tools."
    )
    env = dict(os.environ)
    for key in ("AI_AGENT", "OPENCODE", "OPENCODE_TERMINAL", "OPENCODE_SESSION_ID", "OPENCODE_CONFIG", "OPENCODE_CONFIG_CONTENT"):
        env.pop(key, None)
    env["HOME"] = str(root / "home")
    env["XDG_CONFIG_HOME"] = str(root / "home" / ".config")
    env["XDG_DATA_HOME"] = str(root / "home" / ".local" / "share")
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    session = {
        "id": sid,
        "root": str(root),
        "network": network,
        "model": model,
        "provider": base_url,
        "startedAt": time.time(),
        "limits": {"sessionHours": limit},
    }
    (root / "session.json").write_text(json.dumps(session, indent=2))
    print(f"[rts-linux] session {sid} · root {root} · net={'host' if network else 'none'}", flush=True)
    try:
        proc = subprocess.run(
            [args.opencode, "run", "--standalone", "--format", "json", "--title", "NEAR AI Red Linux Sandbox", prompt],
            cwd=root / "work",
            env=env,
            timeout=max(60, int(limit) * 3600),
        )
        print(f"[rts-linux] opencode exit {proc.returncode}", flush=True)
    except subprocess.TimeoutExpired:
        print("[rts-linux] session timed out", file=sys.stderr)
        return 124
    finally:
        (root / "session.json").write_text(json.dumps({**session, "endedAt": time.time()}, indent=2))
        print(f"[rts-linux] exported /out: {root / 'out'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
