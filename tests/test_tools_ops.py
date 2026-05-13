"""Tests for tools/ops.py — mutating ops (write_file + restart + reopen + quit)."""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from nginx_ui_ops.backends import reset_cache
from nginx_ui_ops.backends.base import BackendError
from nginx_ui_ops.tools import ops as ops_mod

# ---------------------------------------------------------------------------
# Fake backend
# ---------------------------------------------------------------------------

class FakeBackend:
    def __init__(self):
        self.commands: list[tuple[list[str], bool]] = []
        self.command_responses: list[Any] = []
        self.reads: dict[str, bytes] = {}
        # (content, path, mode, sudo) — preserves order to verify backup-then-write.
        self.pushes: list[tuple[bytes, str, int, bool]] = []
        # Optional override: pushes to these paths raise BackendError.
        self.push_failures: set[str] = set()

    def run_cmd(self, argv, *, sudo=False, timeout=30):
        self.commands.append((list(argv), sudo))
        if self.command_responses:
            return self.command_responses.pop(0)
        m = MagicMock()
        m.ok = True
        m.return_code = 0
        m.stdout = ""
        m.stderr = ""
        return m

    def read_file(self, remote_path, *, sudo=False):
        if remote_path in self.reads:
            return self.reads[remote_path]
        raise BackendError(f"file not found: {remote_path}")

    def push_file(self, content, remote_path, *, mode=0o644, sudo=False):
        if remote_path in self.push_failures:
            raise BackendError(f"push refused for {remote_path}")
        self.pushes.append((content, remote_path, mode, sudo))


def _ok(stdout="", stderr="", rc=0):
    m = MagicMock()
    m.ok = (rc == 0)
    m.return_code = rc
    m.stdout = stdout
    m.stderr = stderr
    return m


@pytest.fixture
def fake(monkeypatch):
    f = FakeBackend()
    reset_cache()
    monkeypatch.setattr(ops_mod, "get_backend", lambda *a, **kw: f)
    return f


# ---------------------------------------------------------------------------
# nginx_write_file — path validation
# ---------------------------------------------------------------------------

def test_write_file_rejects_relative_path(fake):
    with pytest.raises(ValueError, match="absolute"):
        ops_mod.nginx_write_file("foo.conf", "content")


def test_write_file_rejects_outside_config_dir(fake):
    with pytest.raises(ValueError, match="under"):
        ops_mod.nginx_write_file("/etc/passwd", "content")


def test_write_file_rejects_root_etc_nginx_itself(fake):
    """The dir itself isn't a valid file target."""
    with pytest.raises(ValueError, match="under"):
        ops_mod.nginx_write_file("/etc/nginx", "content")


# ---------------------------------------------------------------------------
# nginx_write_file — happy path
# ---------------------------------------------------------------------------

def test_write_file_happy_path_with_existing_file(fake):
    """Existing file → backup is created, new content pushed, nginx -t passes."""
    target = "/etc/nginx/sites-available/foo.conf"
    fake.reads[target] = b"old content\n"
    fake.command_responses = [_ok(stdout="syntax is ok\n")]
    result = ops_mod.nginx_write_file(target, "new content\n")
    assert result["ok"] is True
    assert result["nginx_test_passed"] is True
    assert result["rolled_back"] is False
    assert result["backup_path"] is not None
    assert result["backup_path"].startswith(target + ".bak-")
    assert result["bytes_written"] == len(b"new content\n")
    # 2 pushes: backup, then target.
    assert len(fake.pushes) == 2
    backup_push = fake.pushes[0]
    new_push = fake.pushes[1]
    assert backup_push[0] == b"old content\n"  # backup content
    assert backup_push[1] == result["backup_path"]
    assert new_push[0] == b"new content\n"
    assert new_push[1] == target


def test_write_file_happy_path_new_file(fake):
    """Path that didn't exist before → no backup, new content pushed, test passes."""
    target = "/etc/nginx/conf.d/new.conf"
    fake.command_responses = [_ok()]
    result = ops_mod.nginx_write_file(target, "server { listen 80; }\n")
    assert result["ok"] is True
    assert result["backup_path"] is None
    assert result["nginx_test_passed"] is True
    # Only the target push, no backup.
    assert len(fake.pushes) == 1
    assert fake.pushes[0][1] == target


# ---------------------------------------------------------------------------
# nginx_write_file — rollback
# ---------------------------------------------------------------------------

def test_write_file_rolls_back_on_test_failure(fake):
    """nginx -t fails after write → backup is restored to target."""
    target = "/etc/nginx/sites-available/foo.conf"
    fake.reads[target] = b"good content\n"
    fake.command_responses = [_ok(stderr="syntax error in line 5\n", rc=1)]
    result = ops_mod.nginx_write_file(target, "broken {\n")
    assert result["ok"] is False
    assert result["nginx_test_passed"] is False
    assert result["rolled_back"] is True
    assert "syntax error" in result["test_stderr"]
    # 3 pushes: backup, broken target, restored target.
    assert len(fake.pushes) == 3
    restored_push = fake.pushes[2]
    assert restored_push[0] == b"good content\n"
    assert restored_push[1] == target


def test_write_file_rolls_back_new_file_via_rm(fake):
    """New file + nginx -t fails → file is removed (no backup to restore)."""
    target = "/etc/nginx/conf.d/broken.conf"
    fake.command_responses = [
        _ok(stderr="syntax error\n", rc=1),  # nginx -t fail
        _ok(),                                # rm -f
    ]
    result = ops_mod.nginx_write_file(target, "broken {\n")
    assert result["ok"] is False
    assert result["rolled_back"] is True
    assert result["backup_path"] is None
    # rm -f was called against the target.
    assert any(
        cmd[0][:2] == ["rm", "-f"] and cmd[0][-1] == target for cmd in fake.commands
    )


def test_write_file_aborts_if_backup_push_fails(fake):
    """If we can't back up the existing file, refuse to touch it."""
    target = "/etc/nginx/sites-available/foo.conf"
    fake.reads[target] = b"old\n"
    # Backup path is dynamically generated — fail ANY push to a *.bak-* path.
    # We approximate by failing all pushes; validate that we never mutate target.
    fake.push_failures = {target + ".bak-PLACEHOLDER"}
    # Easier: stub push_file to fail on any first call.
    original = fake.push_file
    calls = {"n": 0}

    def fail_first_push(content, remote_path, *, mode=0o644, sudo=False):
        calls["n"] += 1
        if calls["n"] == 1:
            raise BackendError("disk full")
        return original(content, remote_path, mode=mode, sudo=sudo)

    fake.push_file = fail_first_push  # type: ignore[assignment]
    with pytest.raises(BackendError, match="backup"):
        ops_mod.nginx_write_file(target, "new\n")


# ---------------------------------------------------------------------------
# nginx_full_restart
# ---------------------------------------------------------------------------

def test_full_restart_runs_test_then_restart(fake):
    fake.command_responses = [_ok(), _ok()]  # nginx -t, then systemctl restart
    result = ops_mod.nginx_full_restart()
    assert result["action"] == "restart"
    assert result["ok"] is True
    assert len(fake.commands) == 2
    assert fake.commands[0][0] == ["nginx", "-t"]
    assert fake.commands[1][0] == ["systemctl", "restart", "nginx"]


def test_full_restart_skips_when_test_fails(fake):
    fake.command_responses = [_ok(stderr="syntax error\n", rc=1)]
    result = ops_mod.nginx_full_restart()
    assert result["ok"] is False
    assert "skipped" in result["note"]
    # Only nginx -t was invoked, NOT systemctl restart.
    assert len(fake.commands) == 1
    assert fake.commands[0][0] == ["nginx", "-t"]


def test_full_restart_failure_during_systemctl(fake):
    fake.command_responses = [_ok(), _ok(stderr="Failed to restart\n", rc=1)]
    result = ops_mod.nginx_full_restart()
    assert result["ok"] is False
    assert "non-zero" in result["note"]


# ---------------------------------------------------------------------------
# nginx_reopen_logs
# ---------------------------------------------------------------------------

def test_reopen_logs_success(fake):
    fake.command_responses = [_ok()]
    result = ops_mod.nginx_reopen_logs()
    assert result["action"] == "reopen_logs"
    assert result["ok"] is True
    assert "SIGUSR1" in result["note"]
    assert fake.commands[0][0] == ["nginx", "-s", "reopen"]


def test_reopen_logs_failure(fake):
    fake.command_responses = [_ok(stderr="signal failed\n", rc=1)]
    result = ops_mod.nginx_reopen_logs()
    assert result["ok"] is False
    assert "failed" in result["note"].lower()


# ---------------------------------------------------------------------------
# nginx_quit
# ---------------------------------------------------------------------------

def test_quit_success_warns_operator(fake):
    fake.command_responses = [_ok()]
    result = ops_mod.nginx_quit()
    assert result["action"] == "quit"
    assert result["ok"] is True
    assert "stopped" in result["note"]
    assert "systemctl start" in result["note"]
    assert fake.commands[0][0] == ["nginx", "-s", "quit"]


def test_quit_failure(fake):
    fake.command_responses = [_ok(stderr="not running\n", rc=1)]
    result = ops_mod.nginx_quit()
    assert result["ok"] is False
    assert "may still be running" in result["note"]
