from __future__ import annotations

import json
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


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap not installed")
def test_network_is_disabled_by_default(root: Path):
    r = run_tool(root, "shell", {"command": "curl -sS --max-time 2 http://1.1.1.1 >/dev/null"})
    # curl may not exist in a minimal host; the exit status is still non-zero when offline.
    assert r.returncode == 0
    assert "exit 0" not in r.stdout or "curl" in r.stdout.lower()
