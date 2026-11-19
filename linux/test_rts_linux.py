from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
CLI = HERE / "rts_linux.py"


def run_tool(root: Path, name: str, payload: dict) -> subprocess.CompletedProcess:
    request = {"options": {"root": str(root), "network": False}, "input": payload}
    return subprocess.run(
        [sys.executable, str(CLI), "tool", name],
        input=json.dumps(request),
        text=True,
        capture_output=True,
    )


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    for sub in ("in", "out", "work"):
        (tmp_path / sub).mkdir()
    (tmp_path / "in" / "hello.txt").write_text("hello\n")
    return tmp_path


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap not installed")
def test_shell_copy_in_and_out(root: Path):
    r = run_tool(root, "shell", {"command": "cat /tmp/in/hello.txt; echo made > /tmp/out/result.txt"})
    assert r.returncode == 0, r.stderr
    assert "hello" in r.stdout
    assert (root / "out" / "result.txt").read_text().strip() == "made"


def test_file_tools(root: Path):
    assert run_tool(root, "read", {"path": "/in/hello.txt"}).stdout.startswith("1: hello")
    w = run_tool(root, "write", {"path": "/work/new.txt", "content": "one"})
    assert w.returncode == 0, w.stderr
    e = run_tool(root, "edit", {"path": "/work/new.txt", "oldString": "one", "newString": "two"})
    assert e.returncode == 0, e.stderr
    assert (root / "work" / "new.txt").read_text() == "two"
    assert "new.txt" in run_tool(root, "glob", {"pattern": "*.txt", "path": "/work"}).stdout
    assert "two" in run_tool(root, "grep", {"pattern": "two", "path": "/work"}).stdout


def test_path_escape_is_refused(root: Path):
    r = run_tool(root, "read", {"path": "/work/../../etc/passwd"})
    assert r.returncode != 0
    assert "escapes" in r.stderr or "not found" in r.stderr


needs_bwrap = pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap not installed")

PY_CONNECT = (
    "python3 -c \"import socket; socket.create_connection(('1.1.1.1', 80), timeout=2); print('NET' + '_OK')\""
)


@needs_bwrap
def test_network_is_disabled_by_default(root: Path):
    r = run_tool(root, "shell", {"command": PY_CONNECT})
    assert r.returncode == 0, r.stderr
    assert "NET_OK" not in r.stdout
    assert "[exit " in r.stdout


@needs_bwrap
def test_shell_cannot_see_host_files_outside_the_session(root: Path, tmp_path_factory):
    # A secret next to the session (like the session's own opencode.json) and the
    # caller's home directory must both be invisible inside the jail.
    secret = root / "secret.json"
    secret.write_text("sk-SECRET")
    home = Path.home()
    r = run_tool(root, "shell", {"command": f"cat {secret}; ls -A {home}; echo done"})
    assert r.returncode == 0, r.stderr
    assert "sk-SECRET" not in r.stdout
    assert "done" in r.stdout
    assert "No such file" in r.stdout


@needs_bwrap
def test_shell_environment_is_cleared(root: Path):
    request = {"options": {"root": str(root)}, "input": {"command": "echo token=$RTS_LINUX_API_KEY"}}
    r = subprocess.run(
        [sys.executable, str(CLI), "tool", "shell"],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        env={**os.environ, "RTS_LINUX_API_KEY": "sk-SECRET"},
    )
    assert r.returncode == 0, r.stderr
    assert "sk-SECRET" not in r.stdout


def test_glob_and_grep_do_not_follow_symlinks_out(root: Path, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret.txt"
    outside.write_text("sk-SECRET\n")
    (root / "work" / "link.txt").symlink_to(outside)
    assert "sk-SECRET" not in run_tool(root, "grep", {"pattern": "SECRET", "path": "/work"}).stdout
    assert "link.txt" not in run_tool(root, "glob", {"pattern": "*.txt", "path": "/work"}).stdout
    assert run_tool(root, "read", {"path": "/work/link.txt"}).returncode != 0


def test_launch_refuses_an_allowlist_without_a_proxy(tmp_path: Path):
    cfg = tmp_path / "session.json"
    cfg.write_text(json.dumps({"network": {"allow": ["example.com:443"]}}))
    r = subprocess.run(
        [sys.executable, str(CLI), "launch", "--config", str(cfg), "--prompt", "hi",
         "--sessions-dir", str(tmp_path / "s"), "--opencode", "/bin/false"],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 2
    assert "network.allow" in r.stderr


def test_launch_keeps_the_api_key_off_disk(tmp_path: Path):
    cfg = tmp_path / "session.json"
    cfg.write_text(json.dumps({"provider": {"apiKeyEnv": "TEST_KEY"}}))
    r = subprocess.run(
        [sys.executable, str(CLI), "launch", "--config", str(cfg), "--prompt", "hi",
         "--sessions-dir", str(tmp_path / "s"), "--opencode", "/bin/true"],
        text=True,
        capture_output=True,
        env={**os.environ, "TEST_KEY": "sk-SECRET"},
    )
    assert r.returncode == 0, r.stderr
    for f in (tmp_path / "s").rglob("*"):
        if f.is_file():
            assert "sk-SECRET" not in f.read_text(errors="replace"), f


def test_launch_drops_host_opencode_config_overrides(tmp_path: Path):
    dump = tmp_path / "env.json"
    stub = tmp_path / "opencode"
    stub.write_text(
        "#!/usr/bin/env python3\nimport json, os\n"
        f"open({str(dump)!r}, 'w').write(json.dumps(dict(os.environ)))\n"
    )
    stub.chmod(0o755)
    r = subprocess.run(
        [sys.executable, str(CLI), "launch", "--prompt", "hi",
         "--sessions-dir", str(tmp_path / "s"), "--opencode", str(stub)],
        text=True,
        capture_output=True,
        env={**os.environ, "OPENCODE_CONFIG_CONTENT": '{"mcp":{}}', "OPENCODE_CONFIG_DIR": "/tmp/evil"},
    )
    assert r.returncode == 0, r.stderr
    env = json.loads(dump.read_text())
    assert "OPENCODE_CONFIG_CONTENT" not in env
    assert "OPENCODE_CONFIG_DIR" not in env
    assert env["OPENCODE_CONFIG"].endswith("opencode.json")
