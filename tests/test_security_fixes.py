"""Regression guards for the security fixes documented in
``docs/security/audit-2026-05-29-0455.md``.

Each test asserts the FIX behavior, not the implementation. If a future
refactor re-introduces a vector, the test should fail loudly.
"""
from __future__ import annotations

import os
from typing import Any
from unittest.mock import MagicMock

import pytest

from nginx_ui_ops._paths import validate_under_any, validate_under_dir
from nginx_ui_ops._redact import redact_secrets
from nginx_ui_ops.backends import reset_cache
from nginx_ui_ops.backends.base import BackendError
from nginx_ui_ops.tools import certs as certs_mod
from nginx_ui_ops.tools import diagnostics as diag_mod
from nginx_ui_ops.tools import ops as ops_mod


# ---------------------------------------------------------------------------
# Fake backend (minimal, sufficient for tool tests)
# ---------------------------------------------------------------------------

class _FakeBackend:
    def __init__(self):
        self.commands: list[tuple[list[str], bool]] = []
        self.command_responses: list[Any] = []
        self.pushes: list[tuple[bytes, str, int, bool]] = []
        self.reads: dict[str, bytes] = {}
        self.queries: list[tuple[str, str, tuple]] = []
        self.query_responses: list[list[dict]] = []

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

    def query_db(self, db_path, sql, *, params=()):
        self.queries.append((db_path, sql, params))
        if self.query_responses:
            return self.query_responses.pop(0)
        return []


def _ok(stdout: str = "", stderr: str = "", rc: int = 0):
    m = MagicMock()
    m.ok = rc == 0
    m.return_code = rc
    m.stdout = stdout
    m.stderr = stderr
    return m


@pytest.fixture
def fake(monkeypatch):
    f = _FakeBackend()
    reset_cache()
    monkeypatch.setattr(ops_mod, "get_backend", lambda *a, **kw: f)
    monkeypatch.setattr(diag_mod, "get_backend", lambda *a, **kw: f)
    monkeypatch.setattr(certs_mod, "get_backend", lambda *a, **kw: f)
    return f


# ===========================================================================
# [VULN-01] Path traversal in nginx_write_file
# ===========================================================================

@pytest.mark.parametrize("evil_path", [
    "/etc/nginx/../etc/passwd",
    "/etc/nginx/../../tmp/x",
    "/etc/nginx/../../../etc/sudoers.d/zzz",
    "/etc/nginx/./../../var/log/x",
    "/etc/nginx/sites/../../etc/x",
])
def test_vuln_01_nginx_write_file_rejects_traversal(fake, evil_path):
    """`..` in any segment must be rejected BEFORE any I/O happens."""
    with pytest.raises(ValueError, match=r"'\.\.'|under"):
        ops_mod.nginx_write_file(evil_path, "content")
    # No backend interactions at all.
    assert fake.commands == []
    assert fake.pushes == []


def test_vuln_01_validate_under_dir_normalizes_extra_slashes():
    out = validate_under_dir("/etc/nginx//sites//foo.conf", "/etc/nginx")
    assert out == "/etc/nginx/sites/foo.conf"


def test_vuln_01_validate_under_dir_rejects_relative():
    with pytest.raises(ValueError, match="absolute"):
        validate_under_dir("relative/path", "/etc/nginx")


def test_vuln_01_validate_under_dir_rejects_root_by_default():
    with pytest.raises(ValueError, match="not the dir itself"):
        validate_under_dir("/etc/nginx", "/etc/nginx")


def test_vuln_01_validate_under_dir_allows_root_when_opted_in():
    out = validate_under_dir("/etc/nginx", "/etc/nginx", allow_root=True)
    assert out == "/etc/nginx"


# ===========================================================================
# [VULN-02] nginx_logs() shadowed `target` parameter
# ===========================================================================

def test_vuln_02_nginx_logs_passes_target_to_get_backend(monkeypatch):
    """Verify the target arg reaches get_backend AS the multi-target
    instance name — NOT shadowed by the log file path."""
    seen: dict[str, Any] = {}

    def fake_get_backend(t=None):
        seen["target"] = t
        f = _FakeBackend()
        f.command_responses = [_ok(stdout="line1\nline2\n")]
        return f

    monkeypatch.setattr(diag_mod, "get_backend", fake_get_backend)
    diag_mod.nginx_logs(file="error.log", target="vps")
    assert seen["target"] == "vps"
    # File path must NOT have leaked into the target slot.
    assert seen["target"] != "/var/log/nginx/error.log"


def test_vuln_02_nginx_logs_default_target_is_none(monkeypatch):
    """Calling without target arg → forwards None to get_backend."""
    seen: dict[str, Any] = {}

    def fake_get_backend(t=None):
        seen["target"] = t
        f = _FakeBackend()
        f.command_responses = [_ok(stdout="")]
        return f

    monkeypatch.setattr(diag_mod, "get_backend", fake_get_backend)
    diag_mod.nginx_logs(file="error.log")
    assert seen["target"] is None


# ===========================================================================
# [VULN-03] cert_deploy_files allowlist
# ===========================================================================

def test_vuln_03_cert_deploy_rejects_arbitrary_dest_path(fake):
    """DB-controlled ssl_certificate_path outside the allowlist must
    be rejected BEFORE any push_file."""
    fake.query_responses = [[
        {"id": 1, "domains": '["a.com"]',
         "ssl_certificate_path": "/root/.ssh/authorized_keys",
         "ssl_certificate_key_path": "/etc/nginx/ssl/key.pem",
         "key_type": "P256"},
    ]]
    with pytest.raises(ValueError, match="not under any allowed dir"):
        certs_mod.cert_deploy_files(1)
    # No pushes happened.
    assert fake.pushes == []


def test_vuln_03_cert_deploy_rejects_traversal_in_dest(fake):
    fake.query_responses = [[
        {"id": 1, "domains": '["a.com"]',
         "ssl_certificate_path": "/etc/nginx/../etc/passwd",
         "ssl_certificate_key_path": "/etc/nginx/ssl/key.pem",
         "key_type": "P256"},
    ]]
    with pytest.raises(ValueError, match=r"'\.\.'"):
        certs_mod.cert_deploy_files(1)


def test_vuln_03_cert_deploy_dirs_env_override(monkeypatch):
    monkeypatch.setenv("NGINXUI_CERT_DEPLOY_DIRS", "/opt/mycerts,/srv/certs")
    dirs = certs_mod._cert_deploy_dirs()
    assert "/opt/mycerts" in dirs
    assert "/srv/certs" in dirs


def test_vuln_03_validate_under_any_accepts_first_match():
    out = validate_under_any(
        "/etc/ssl/full.pem",
        ("/etc/nginx/", "/etc/ssl/", "/var/lib/nginx-ui/"),
    )
    assert out == "/etc/ssl/full.pem"


def test_vuln_03_validate_under_any_rejects_no_match():
    with pytest.raises(ValueError, match="not under any allowed dir"):
        validate_under_any("/tmp/evil", ("/etc/nginx/", "/etc/ssl/"))


# ===========================================================================
# [VULN-05] TOCTOU in _acquire_acme_lock
# ===========================================================================

def test_vuln_05_acquire_acme_lock_uses_mkdir(fake):
    """Lock is atomic mkdir, not test+touch."""
    mkdir_ok = MagicMock(); mkdir_ok.ok = True; mkdir_ok.return_code = 0
    fake.command_responses = [mkdir_ok]
    assert certs_mod._acquire_acme_lock(fake) is True
    # Exactly ONE command — mkdir. No TOCTOU `test -e` precursor.
    assert len(fake.commands) == 1
    argv, _ = fake.commands[0]
    assert argv[0] == "mkdir"
    assert argv[1].endswith(".lock.d")


def test_vuln_05_acquire_acme_lock_returns_false_when_held(fake):
    mkdir_fail = MagicMock(); mkdir_fail.ok = False; mkdir_fail.return_code = 1
    fake.command_responses = [mkdir_fail]
    assert certs_mod._acquire_acme_lock(fake) is False


def test_vuln_05_release_uses_rmdir(fake):
    certs_mod._release_acme_lock(fake)
    argv, _ = fake.commands[0]
    assert argv[0] == "rmdir"


# ===========================================================================
# [VULN-07] Redactor for BackendError surfaces
# ===========================================================================

@pytest.mark.parametrize("payload,expected_not_present", [
    ("CF_API_TOKEN=ghp_supersecrettoken123456", "ghp_supersecrettoken123456"),
    ("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE/wJalrXUt", "AKIAIOSFODNN7EXAMPLE"),
    ("Authorization: Bearer ey.JWTpayload.signature", "JWTpayload"),
    ("token: supersecret_value", "supersecret_value"),
    ("password=hunter2", "hunter2"),
])
def test_vuln_07_redact_secrets(payload, expected_not_present):
    out = redact_secrets(payload)
    assert "<REDACTED>" in out
    assert expected_not_present not in out


def test_vuln_07_redact_preserves_non_secrets():
    text = "acme.sh exited with rc=1 at line 42"
    assert redact_secrets(text) == text


# ===========================================================================
# [VULN-08] grep client-side (already covered by test_nginx_logs_with_grep)
# ===========================================================================

def test_vuln_08_invalid_grep_regex_raises_locally(fake):
    """Bad regex now surfaces as a Python ValueError, never reaching SSH."""
    fake.command_responses = [_ok(stdout="line\n")]
    with pytest.raises(ValueError, match="invalid grep regex"):
        diag_mod.nginx_logs(file="error.log", grep="[unclosed")


# ===========================================================================
# [VULN-09] nginx_test_with_diff path traversal
# ===========================================================================

def test_vuln_09_test_with_diff_rejects_traversal(fake):
    with pytest.raises(ValueError, match=r"'\.\.'"):
        diag_mod.nginx_test_with_diff(
            target_path="/etc/nginx/../etc/passwd",
            proposed_content="x",
        )
    assert fake.pushes == []


# ===========================================================================
# [VULN-10] nginx_read_file path traversal
# ===========================================================================

def test_vuln_10_read_file_rejects_traversal(fake):
    with pytest.raises(ValueError, match=r"'\.\.'"):
        diag_mod.nginx_read_file("/etc/nginx/../etc/shadow")


def test_vuln_10_read_file_allows_root_dir(fake):
    """Preserved v0.3.0 behavior — reading the config dir itself is OK."""
    # No exception expected on validation; backend.read_file may fail
    # but that's outside the scope of this guard.
    fake.reads["/etc/nginx"] = b"<dir>"
    # stat result for the mtime path.
    fake.command_responses = [_ok(stdout="1700000000\n")]
    result = diag_mod.nginx_read_file("/etc/nginx")
    assert result["path"] == "/etc/nginx"


# ===========================================================================
# [VULN-11] CommandResult.notes gate
# ===========================================================================

def test_vuln_11_backend_notes_gate_default_off(monkeypatch):
    """Without NGINXUI_INCLUDE_BACKEND_NOTES=true, run_cmd must NOT
    append backend identity to result.notes."""
    monkeypatch.delenv("NGINXUI_INCLUDE_BACKEND_NOTES", raising=False)
    from nginx_ui_ops.backends.wrapper_lxc import _include_backend_notes
    assert _include_backend_notes() is False


def test_vuln_11_backend_notes_gate_on_when_env_set(monkeypatch):
    monkeypatch.setenv("NGINXUI_INCLUDE_BACKEND_NOTES", "true")
    from nginx_ui_ops.backends.wrapper_lxc import _include_backend_notes
    assert _include_backend_notes() is True


# ===========================================================================
# [VULN-12] _collect_provider_env explicit allowlist
# ===========================================================================

def test_vuln_12_collect_only_documented_vars(monkeypatch):
    """Unrelated CF_-prefixed env vars must NOT be exported to acme.sh."""
    monkeypatch.setenv("CF_API_TOKEN", "real-token")
    monkeypatch.setenv("CF_UNRELATED_THING", "noise")
    out = certs_mod._collect_provider_env("dns_cf")
    assert "CF_API_TOKEN" in out
    assert "CF_UNRELATED_THING" not in out


def test_vuln_12_unknown_provider_returns_empty(monkeypatch):
    monkeypatch.setenv("MADE_UP_API_KEY", "x")
    assert certs_mod._collect_provider_env("dns_made_up") == {}


# ===========================================================================
# [VULN-14] backup preserves original mode
# ===========================================================================

def test_vuln_14_backup_inherits_source_mode(fake):
    """A 0600 source file → 0600 backup. Default 0644 if stat fails."""
    target = "/etc/nginx/conf.d/secret.include"
    fake.reads[target] = b"include /etc/nginx/ssl/dhparam.pem;\n"
    # stat returns 600; then nginx -t succeeds.
    fake.command_responses = [_ok(stdout="600\n"), _ok()]
    ops_mod.nginx_write_file(target, "include /etc/nginx/ssl/other.pem;\n")
    # First push is the backup — should carry mode 0o600.
    backup_push = fake.pushes[0]
    assert backup_push[2] == 0o600
    # Second push (target) also inherits the source mode.
    target_push = fake.pushes[1]
    assert target_push[2] == 0o600


def test_vuln_14_stat_failure_defaults_to_0644(fake):
    target = "/etc/nginx/conf.d/x.conf"
    fake.reads[target] = b"old"
    # stat output is garbage → fallback 0o644; nginx -t ok.
    fake.command_responses = [_ok(stdout="notanumber\n"), _ok()]
    ops_mod.nginx_write_file(target, "new")
    backup_push = fake.pushes[0]
    assert backup_push[2] == 0o644
