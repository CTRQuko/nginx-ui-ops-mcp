"""Tests for tools/diagnostics.py — read-only ops & introspection."""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from nginx_ui_ops.backends import reset_cache
from nginx_ui_ops.backends.base import BackendError
from nginx_ui_ops.tools import diagnostics as diag


# ---------------------------------------------------------------------------
# Fake backend
# ---------------------------------------------------------------------------

class FakeBackend:
    def __init__(self):
        self.commands: list[tuple[list[str], bool]] = []
        self.command_responses: list[Any] = []
        self.reads: dict[str, bytes] = {}
        self.pushes: list[tuple[bytes, str, int, bool]] = []

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
    monkeypatch.setattr(diag, "get_backend", lambda: f)
    return f


# ---------------------------------------------------------------------------
# nginx_status
# ---------------------------------------------------------------------------

def test_nginx_status_active(fake):
    """systemctl status output gets parsed into structured fields."""
    fake.command_responses = [
        _ok(stdout=(
            "● nginx.service - A high performance web server\n"
            "     Loaded: loaded (/lib/systemd/system/nginx.service; enabled)\n"
            "     Active: active (running) since Thu 2026-05-04 10:00:00 UTC; 2h ago\n"
            "    Main PID: 12345 (nginx)\n"
            "      Tasks: 5 (limit: 9426)\n"
        )),
        _ok(stdout="12346\n12347\n12348\n12349\n"),  # 4 workers
        _ok(stdout="ActiveEnterTimestampMonotonic=1234567\n"),
        _ok(stdout="ActiveEnterTimestamp=Thu 2026-05-04 10:00:00 UTC\n"),
    ]
    result = diag.nginx_status()
    assert result["active"] is True
    assert result["sub_state"] == "running"
    assert result["main_pid"] == 12345
    assert result["worker_count"] == 4
    assert result["started_at"] is not None


def test_nginx_status_inactive(fake):
    fake.command_responses = [
        _ok(stdout=(
            "● nginx.service - A high performance web server\n"
            "     Active: inactive (dead) since ...\n"
        ), rc=3),
    ]
    result = diag.nginx_status()
    assert result["active"] is False
    assert result["sub_state"] == "dead"


# ---------------------------------------------------------------------------
# nginx_dump_config
# ---------------------------------------------------------------------------

def test_nginx_dump_config_success(fake):
    fake.command_responses = [_ok(stdout="# config dump...\nuser nginx;\n")]
    result = diag.nginx_dump_config()
    assert result["ok"] is True
    assert "user nginx" in result["config"]
    assert result["size_bytes"] > 0


def test_nginx_dump_config_failure(fake):
    fake.command_responses = [_ok(stderr="syntax error", rc=1)]
    result = diag.nginx_dump_config()
    assert result["ok"] is False
    assert "syntax error" in result["stderr"]


# ---------------------------------------------------------------------------
# nginx_logs
# ---------------------------------------------------------------------------

def test_nginx_logs_default_error_log(fake):
    fake.command_responses = [_ok(stdout="2026-05-06 ERROR foo\n2026-05-06 ERROR bar\n")]
    result = diag.nginx_logs()
    assert result["file"] == "/var/log/nginx/error.log"
    assert result["lines_returned"] == 2


def test_nginx_logs_with_grep(fake):
    fake.command_responses = [_ok(stdout="ERROR foo\nERROR bar\n")]
    result = diag.nginx_logs(file="error.log", lines=50, grep="ERROR")
    assert result["grep_filter"] == "ERROR"
    # Verify command shape uses sh -c with tail | grep.
    cmd = fake.commands[0][0]
    assert cmd[0] == "sh"
    assert "tail -n 50" in cmd[2]
    assert "grep -iE" in cmd[2]


def test_nginx_logs_absolute_path(fake):
    fake.command_responses = [_ok(stdout="line1\n")]
    result = diag.nginx_logs(file="/var/log/custom/nginx.log")
    assert result["file"] == "/var/log/custom/nginx.log"


def test_nginx_logs_path_traversal_rejected(fake):
    with pytest.raises(ValueError, match="flat name"):
        diag.nginx_logs(file="../../etc/passwd")


def test_nginx_logs_empty_filename_rejected(fake):
    with pytest.raises(ValueError):
        diag.nginx_logs(file="")


def test_nginx_logs_lines_clamped(fake):
    fake.command_responses = [_ok(stdout="")]
    result = diag.nginx_logs(file="error.log", lines=999999)
    # Capped at MAX_LOG_LINES.
    assert result["lines_requested"] == diag.MAX_LOG_LINES


def test_nginx_logs_failure_no_grep(fake):
    fake.command_responses = [_ok(stderr="No such file", rc=1)]
    with pytest.raises(BackendError, match="No such file"):
        diag.nginx_logs(file="missing.log")


# ---------------------------------------------------------------------------
# nginx_compiled_with
# ---------------------------------------------------------------------------

def test_nginx_compiled_with_parses_v_output(fake):
    nginx_v_output = (
        "nginx version: nginx/1.24.0\n"
        "built by gcc 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)\n"
        "built with OpenSSL 3.0.2 15 Mar 2022\n"
        "TLS SNI support enabled\n"
        "configure arguments: --prefix=/usr/share/nginx --with-http_ssl_module --with-http_v2_module\n"
    )
    fake.command_responses = [_ok(stderr=nginx_v_output)]
    result = diag.nginx_compiled_with()
    assert "1.24.0" in result["version"]
    assert "gcc 11.4.0" in result["built_with"]
    assert "OpenSSL 3.0.2" in result["tls_library"]
    assert result["prefix"] == "/usr/share/nginx"
    assert "--with-http_ssl_module" in result["configure_flags"]


def test_nginx_compiled_with_falls_back_when_no_match(fake):
    fake.command_responses = [_ok(stderr="weird output")]
    result = diag.nginx_compiled_with()
    assert result["version"] == "unknown"


# ---------------------------------------------------------------------------
# nginx_active_conns
# ---------------------------------------------------------------------------

def test_nginx_active_conns_stub_status_enabled(fake):
    stub_body = (
        "Active connections: 42\n"
        "server accepts handled requests\n"
        " 1000 1000 5000\n"
        "Reading: 1 Writing: 2 Waiting: 39\n"
    )
    fake.command_responses = [_ok(stdout=stub_body)]
    result = diag.nginx_active_conns()
    assert result["enabled"] is True
    assert result["active_connections"] == 42
    assert result["accepts"] == 1000
    assert result["handled"] == 1000
    assert result["requests"] == 5000
    assert result["reading"] == 1
    assert result["writing"] == 2
    assert result["waiting"] == 39


def test_nginx_active_conns_disabled_returns_hint(fake):
    """All endpoints fail → enabled=False with hint."""
    fail = _ok(rc=7)  # curl exit 7 = couldn't connect
    fake.command_responses = [fail, fail, fail]
    result = diag.nginx_active_conns()
    assert result["enabled"] is False
    assert "stub_status" in result["note"]
    assert "location = /nginx_status" in result["note"]


def test_nginx_active_conns_falls_through_non_stub_responses(fake):
    """If first endpoint returns 200 with non-stub_status content, try next."""
    fake.command_responses = [
        _ok(stdout="<html>404 page</html>"),
        _ok(stdout="Active connections: 5\nserver accepts handled requests\n 10 10 50\nReading: 0 Writing: 1 Waiting: 4\n"),
    ]
    result = diag.nginx_active_conns()
    assert result["enabled"] is True
    assert result["active_connections"] == 5


# ---------------------------------------------------------------------------
# nginx_pending_changes
# ---------------------------------------------------------------------------

def test_nginx_pending_changes_no_pending(fake):
    """Service started, no files newer."""
    fake.command_responses = [
        _ok(stdout="ActiveEnterTimestampMonotonic=1234567\n"),
        _ok(stdout="ActiveEnterTimestamp=Thu 2026-05-04 10:00:00 UTC\n"),
        _ok(stdout=""),  # find returns nothing
    ]
    result = diag.nginx_pending_changes()
    assert result["has_pending"] is False
    assert result["pending_files"] == []


def test_nginx_pending_changes_with_pending(fake):
    fake.command_responses = [
        _ok(stdout="ActiveEnterTimestampMonotonic=1234567\n"),
        _ok(stdout="ActiveEnterTimestamp=Thu 2026-05-04 10:00:00 UTC\n"),
        _ok(stdout="/etc/nginx/sites-available/foo.conf\n/etc/nginx/conf.d/extras.conf\n"),
    ]
    result = diag.nginx_pending_changes()
    assert result["has_pending"] is True
    assert len(result["pending_files"]) == 2
    assert "/etc/nginx/sites-available/foo.conf" in result["pending_files"]


def test_nginx_pending_changes_service_not_active(fake):
    """No ActiveEnterTimestamp → returns has_pending=False with note."""
    fake.command_responses = [
        _ok(stdout="ActiveEnterTimestampMonotonic=0\n"),
        _ok(stdout="ActiveEnterTimestamp=\n"),
    ]
    result = diag.nginx_pending_changes()
    assert result["has_pending"] is False
    assert result["service_started_at"] is None


# ---------------------------------------------------------------------------
# nginx_test_with_diff
# ---------------------------------------------------------------------------

def test_nginx_test_with_diff_relative_path_rejected(fake):
    with pytest.raises(ValueError, match="absolute"):
        diag.nginx_test_with_diff("foo.conf", "content")


def test_nginx_test_with_diff_outside_config_dir_rejected(fake):
    with pytest.raises(ValueError, match="under"):
        diag.nginx_test_with_diff("/etc/passwd", "content")


def test_nginx_test_with_diff_success_with_diff(fake):
    """File exists; cp -al works; nginx -t passes; diff returned."""
    fake.reads["/etc/nginx/sites-available/foo.conf"] = b"server { listen 80; }\n"
    fake.command_responses = [
        _ok(),  # cp -al staging
        _ok(),  # nginx -t against staging
        _ok(),  # cleanup rm -rf
    ]
    result = diag.nginx_test_with_diff(
        "/etc/nginx/sites-available/foo.conf",
        "server { listen 443 ssl; }\n",
    )
    assert result["ok"] is True
    assert result["target_path"] == "/etc/nginx/sites-available/foo.conf"
    assert "+server { listen 443 ssl;" in result["diff"]
    assert "-server { listen 80;" in result["diff"]


def test_nginx_test_with_diff_proposed_invalid(fake):
    """nginx -t fails on proposed content → ok=False."""
    fake.reads["/etc/nginx/sites-available/foo.conf"] = b"server { listen 80; }\n"
    fake.command_responses = [
        _ok(),  # cp -al
        _ok(stderr="syntax error in line 1", rc=1),  # nginx -t fails
        _ok(),  # cleanup
    ]
    result = diag.nginx_test_with_diff(
        "/etc/nginx/sites-available/foo.conf",
        "this is broken {",
    )
    assert result["ok"] is False
    assert "syntax error" in result["test_stderr"]


def test_nginx_test_with_diff_new_file(fake):
    """File doesn't exist yet → diff says so; nginx -t still runs."""
    # No reads registered → BackendError → file_exists=False
    fake.command_responses = [
        _ok(),  # cp -al
        _ok(),  # nginx -t
        _ok(),  # cleanup
    ]
    result = diag.nginx_test_with_diff(
        "/etc/nginx/sites-available/newvhost.conf",
        "server { listen 80; }\n",
    )
    assert result["ok"] is True
    assert "does not exist yet" in result["diff"]


def test_nginx_test_with_diff_cp_al_falls_back_to_cp_r(fake):
    """If cp -al fails (some FS), fallback to cp -r should kick in."""
    fake.reads["/etc/nginx/sites-available/foo.conf"] = b"original\n"
    fake.command_responses = [
        _ok(stderr="cp: cannot create hard link", rc=1),  # cp -al fails
        _ok(),  # cp -r succeeds
        _ok(),  # nginx -t
        _ok(),  # cleanup
    ]
    result = diag.nginx_test_with_diff(
        "/etc/nginx/sites-available/foo.conf",
        "modified\n",
    )
    assert result["ok"] is True


# ---------------------------------------------------------------------------
# nginx_read_file
# ---------------------------------------------------------------------------

def test_nginx_read_file_relative_rejected(fake):
    with pytest.raises(ValueError, match="absolute"):
        diag.nginx_read_file("foo.conf")


def test_nginx_read_file_outside_config_dir_rejected(fake):
    with pytest.raises(ValueError, match="under"):
        diag.nginx_read_file("/etc/passwd")


def test_nginx_read_file_returns_content(fake):
    fake.reads["/etc/nginx/nginx.conf"] = b"user nginx;\nworker_processes auto;\n"
    fake.command_responses = [_ok(stdout="1714000000\n")]  # stat mtime
    result = diag.nginx_read_file("/etc/nginx/nginx.conf")
    assert result["path"] == "/etc/nginx/nginx.conf"
    assert "user nginx" in result["content"]
    assert result["truncated"] is False
    assert result["mtime"] is not None


def test_nginx_read_file_truncates_huge(fake):
    big = b"x" * (300 * 1024)  # > 256 KB cap
    fake.reads["/etc/nginx/big.conf"] = big
    fake.command_responses = [_ok(stdout="1714000000\n")]
    result = diag.nginx_read_file("/etc/nginx/big.conf")
    assert result["truncated"] is True
    assert result["size_bytes"] == diag.READ_FILE_CAP_BYTES
