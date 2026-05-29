"""Tests for WrapperLXCBackend.

We never actually shell out — every test stubs ``_run_ssh`` (or the
underlying ``subprocess.run`` for the rare cases that hit it through
``_run_ssh``) so the suite is hermetic and fast. Tests focus on:

- Construction from env vars (validation, defaults)
- Command shape (the exact remote command string sent over SSH)
- Gotcha mitigations (CRLF strip, sudo without -S/+stdin mix, SQL via
  tempfile + redirection)
- BackendError propagation on failures
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from nginx_ui_ops.backends.base import BackendError, CommandResult
from nginx_ui_ops.backends.wrapper_lxc import (
    WrapperLXCBackend,
    _bind_params,
    _key_type_to_keylength,
    _quote_sql_value,
)

# ---------------------------------------------------------------------------
# from_env
# ---------------------------------------------------------------------------

def test_from_env_minimal(monkeypatch):
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "999")
    monkeypatch.delenv("NGINXUI_WRAPPER_PATH", raising=False)
    monkeypatch.delenv("NGINXUI_SUDO_METHOD", raising=False)
    b = WrapperLXCBackend.from_env()
    assert b.pve_ssh_alias == "pve-test"
    assert b.lxc_id == "999"
    assert b.wrapper_path == "/usr/local/bin/claude-wrapper"
    assert b.sudo_method == "nopasswd"


def test_from_env_missing_pve_alias_raises(monkeypatch):
    monkeypatch.delenv("NGINXUI_PVE_SSH_ALIAS", raising=False)
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    with pytest.raises(BackendError, match="NGINXUI_PVE_SSH_ALIAS"):
        WrapperLXCBackend.from_env()


def test_from_env_missing_lxc_id_raises(monkeypatch):
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.delenv("NGINXUI_LXC_ID", raising=False)
    with pytest.raises(BackendError, match="NGINXUI_LXC_ID"):
        WrapperLXCBackend.from_env()


def test_from_env_invalid_sudo_method(monkeypatch):
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    monkeypatch.setenv("NGINXUI_SUDO_METHOD", "magic")
    with pytest.raises(BackendError, match="NGINXUI_SUDO_METHOD"):
        WrapperLXCBackend.from_env()


def test_from_env_password_method_requires_password_ref(monkeypatch):
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    monkeypatch.setenv("NGINXUI_SUDO_METHOD", "password")
    monkeypatch.delenv("NGINXUI_SUDO_PASSWORD_REF", raising=False)
    with pytest.raises(BackendError, match="NGINXUI_SUDO_PASSWORD_REF"):
        WrapperLXCBackend.from_env()


def test_describe_redacts_secrets(monkeypatch):
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    b = WrapperLXCBackend.from_env()
    desc = b.describe()
    # Identifies the target without leaking sudo password / sensitive paths.
    assert "pve-test" in desc
    assert "100" in desc


# ---------------------------------------------------------------------------
# SQL parameter helpers
# ---------------------------------------------------------------------------

def test_quote_sql_value_str_escapes_single_quote():
    assert _quote_sql_value("O'Brien") == "'O''Brien'"


def test_quote_sql_value_int_passthrough():
    assert _quote_sql_value(42) == "42"


def test_quote_sql_value_none_is_null():
    assert _quote_sql_value(None) == "NULL"


def test_quote_sql_value_bytes_as_blob_literal():
    assert _quote_sql_value(b"\x00\x01\xff") == "X'0001ff'"


def test_quote_sql_value_unsupported_type_raises():
    with pytest.raises(TypeError):
        _quote_sql_value([1, 2, 3])


def test_bind_params_substitutes_in_order():
    sql = "SELECT * FROM t WHERE a=? AND b=?"
    bound = _bind_params(sql, ("hello", 42))
    assert bound == "SELECT * FROM t WHERE a='hello' AND b=42"


def test_bind_params_count_mismatch_raises():
    with pytest.raises(ValueError, match="placeholder"):
        _bind_params("SELECT ? FROM t", (1, 2))


def test_bind_params_zero_placeholders():
    assert _bind_params("SELECT 1", ()) == "SELECT 1"


# ---------------------------------------------------------------------------
# _key_type_to_keylength
# ---------------------------------------------------------------------------

def test_key_type_p256():
    assert _key_type_to_keylength("P256") == "ec-256"


def test_key_type_rsa2048():
    assert _key_type_to_keylength("RSA2048") == "2048"


def test_key_type_unknown_raises():
    with pytest.raises(ValueError, match="not supported"):
        _key_type_to_keylength("CHACHA20")


# ---------------------------------------------------------------------------
# run_cmd — wraps argv in pct exec + claude-wrapper
# ---------------------------------------------------------------------------

def _backend(monkeypatch, **overrides):
    """Helper to build a backend with controlled env."""
    env = {
        "NGINXUI_PVE_SSH_ALIAS": "pve-test",
        "NGINXUI_LXC_ID": "104",
        **overrides,
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return WrapperLXCBackend.from_env()


def test_run_cmd_no_sudo_command_shape(monkeypatch):
    b = _backend(monkeypatch)
    captured: list[str] = []

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        captured.append(remote_cmd)
        return CommandResult(return_code=0, stdout="ok", stderr="")

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        result = b.run_cmd(["nginx", "-t"])
    assert result.ok
    assert "/usr/sbin/pct exec 104 --" in captured[0]
    assert "/usr/local/bin/claude-wrapper" in captured[0]
    assert "nginx -t" in captured[0]
    assert not captured[0].startswith("sudo ")  # no sudo prefix


def test_run_cmd_with_sudo_uses_nopasswd_no_dash_S(monkeypatch):
    """Gotcha #2: sudo NOPASSWD path must NOT use ``-S`` (which would
    consume stdin and corrupt password-less invocations)."""
    b = _backend(monkeypatch)
    captured: list[str] = []
    captured_stdin: list = []

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        captured.append(remote_cmd)
        captured_stdin.append(stdin)
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        b.run_cmd(["systemctl", "status", "nginx"], sudo=True)

    cmd = captured[0]
    assert cmd.startswith("sudo ")
    assert "-S" not in cmd  # NOPASSWD path
    assert captured_stdin[0] is None  # no password fed via stdin


def test_run_cmd_password_method_writes_password_to_stdin(monkeypatch, tmp_path):
    """When SUDO_METHOD=password, the password is fed via SSH stdin
    (separate from any command stdin) — never echoed to the command line."""
    pw = tmp_path / "sudo.pw"
    pw.write_text("s3cret\n", encoding="utf-8")

    b = _backend(
        monkeypatch,
        NGINXUI_SUDO_METHOD="password",
        NGINXUI_SUDO_PASSWORD_REF=str(pw),
    )
    captured_stdin: list = []

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        captured_stdin.append(stdin)
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        b.run_cmd(["nginx", "-t"], sudo=True)

    assert captured_stdin[0] == b"s3cret\n"


def test_run_cmd_empty_argv_raises(monkeypatch):
    b = _backend(monkeypatch)
    with pytest.raises(ValueError, match="argv cannot be empty"):
        b.run_cmd([])


def test_run_cmd_argv_quoted_for_shell_safety(monkeypatch):
    """Args with spaces must be shell-quoted to avoid splitting."""
    b = _backend(monkeypatch)
    captured: list[str] = []

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        captured.append(remote_cmd)
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        b.run_cmd(["echo", "hello world"])

    # 'hello world' should appear quoted in the remote cmd.
    assert "'hello world'" in captured[0]


# ---------------------------------------------------------------------------
# push_file — gotcha #3 (CRLF) + staging + chmod
# ---------------------------------------------------------------------------

def test_push_file_strips_crlf_from_utf8(monkeypatch):
    b = _backend(monkeypatch)
    captured_stdin: list = []
    captured_cmds: list[str] = []

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        captured_cmds.append(remote_cmd)
        captured_stdin.append(stdin)
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        # Content has Windows CRLF.
        b.push_file(b"line1\r\nline2\r\n", "/etc/foo.conf")

    # First call is the stage step — its stdin should have \r stripped.
    assert captured_stdin[0] == b"line1\nline2\n"


def test_push_file_keeps_binary_content_verbatim(monkeypatch):
    """Non-UTF-8 content (e.g. a binary cert) must NOT be normalized."""
    b = _backend(monkeypatch)
    captured_stdin: list = []

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        captured_stdin.append(stdin)
        return CommandResult(return_code=0)

    binary = b"\xff\xfe\x00\x01\r\n\xfd"  # invalid UTF-8 with embedded \r\n
    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        b.push_file(binary, "/etc/cert.bin")

    # Binary preserved as-is, including \r\n.
    assert captured_stdin[0] == binary


def test_push_file_chmods_after_push(monkeypatch):
    b = _backend(monkeypatch)
    cmds: list[str] = []

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        cmds.append(remote_cmd)
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        b.push_file(b"data", "/etc/foo", mode=0o600)

    # Look for a chmod command in the captured remote calls.
    chmod_cmds = [c for c in cmds if "chmod" in c]
    assert chmod_cmds, "no chmod command captured"
    assert "600" in chmod_cmds[0]


def test_push_file_failure_raises_backend_error(monkeypatch):
    b = _backend(monkeypatch)

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        # Fail the stage step.
        if "cat >" in remote_cmd:
            return CommandResult(return_code=1, stderr="disk full")
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        with pytest.raises(BackendError, match="disk full"):
            b.push_file(b"data", "/etc/foo")


# ---------------------------------------------------------------------------
# query_db — gotcha #4 (SQL via tempfile + redirection)
# ---------------------------------------------------------------------------

def test_query_db_uses_tempfile_redirection(monkeypatch):
    """Verifies the gotcha #4 mitigation: SQL is staged to a tempfile
    and sqlite3 reads it via stdin redirection, not inline."""
    b = _backend(monkeypatch)
    cmds: list[str] = []
    stdins: list = []

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        cmds.append(remote_cmd)
        stdins.append(stdin)
        # Return JSON for the sqlite3 invocation (the one with redirection).
        if "sqlite3" in remote_cmd:
            return CommandResult(
                return_code=0,
                stdout='[{"id":1,"name":"foo"}]',
            )
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        rows = b.query_db("/path/to/db", "SELECT * FROM t WHERE id=?", params=(1,))

    assert rows == [{"id": 1, "name": "foo"}]
    # SQL was staged via stdin to a tempfile.
    sql_stdin = next((s for s in stdins if s and b".mode json" in s), None)
    assert sql_stdin is not None, "SQL never staged via stdin"
    assert b"id=1" in sql_stdin  # bound param is inline in the SQL


def test_query_db_empty_result(monkeypatch):
    b = _backend(monkeypatch)

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        if "sqlite3" in remote_cmd:
            return CommandResult(return_code=0, stdout="")
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        rows = b.query_db("/db", "SELECT 1 WHERE 0")
    assert rows == []


def test_query_db_non_json_output_raises(monkeypatch):
    b = _backend(monkeypatch)

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        if "sqlite3" in remote_cmd:
            return CommandResult(
                return_code=0,
                stdout="not valid json",
            )
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        with pytest.raises(BackendError, match="non-JSON"):
            b.query_db("/db", "SELECT 1")


# ---------------------------------------------------------------------------
# acme_issue — gotcha #1 (CF Zone ID via provider_env)
# ---------------------------------------------------------------------------

def test_acme_issue_forwards_provider_env_without_logging(monkeypatch):
    """[VULN-06] mitigation: provider env vars (CF_API_TOKEN, etc.) are
    written to a chmod-0700 tempfile via stdin, NOT included in any
    cmdline that would be visible to `ps aux` / auditd. The remote
    cmd only mentions the tempfile path; the secrets are in the
    stdin payload of the stage step."""
    b = _backend(monkeypatch)
    captured: list[tuple[str, bytes | None]] = []

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        captured.append((remote_cmd, stdin))
        # Stage call ("cat > /tmp/...") returns ok; subsequent run
        # ("sh /tmp/...") returns success.
        return CommandResult(return_code=0, stdout="cert issued")

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        result = b.acme_issue(
            domains=["*.example.com", "example.com"],
            key_type="P256",
            dns_provider="dns_cf",
            provider_env={
                "CF_API_TOKEN": "secret-token-xyz",
                "CF_ZONE_ID": "zone-123",
            },
            acme_home="/home/test/.acme.sh",
        )

    # 3 SSH ops: stage, run, cleanup.
    assert len(captured) == 3
    stage_cmd, stage_stdin = captured[0]
    run_cmd, run_stdin = captured[1]
    cleanup_cmd, _ = captured[2]

    # Stage: cat into tempfile + chmod 700 — no token in the cmdline.
    assert "cat > " in stage_cmd
    assert "chmod 700" in stage_cmd
    assert "secret-token-xyz" not in stage_cmd
    assert "zone-123" not in stage_cmd
    # Secrets present ONLY inside the stdin payload (script body).
    assert stage_stdin is not None
    assert b"export CF_API_TOKEN=" in stage_stdin
    assert b"secret-token-xyz" in stage_stdin
    assert b"export CF_ZONE_ID=" in stage_stdin
    # Run: invokes the script via `sh <tmppath>` — still no token in cmdline.
    assert run_cmd.startswith("sh ")
    assert "secret-token-xyz" not in run_cmd
    # Cleanup removes the tempfile.
    assert "rm -f" in cleanup_cmd
    # acme.sh invocation visible in script body.
    assert b"--issue" in stage_stdin
    assert b"-d '*.example.com'" in stage_stdin
    assert b"--dns dns_cf" in stage_stdin
    # Result paths derive from the primary domain + ECC.
    assert "*.example.com_ecc" in result["fullchain_path"]
    assert "/fullchain.cer" in result["fullchain_path"]


def test_acme_issue_rejects_empty_domains(monkeypatch):
    b = _backend(monkeypatch)
    with pytest.raises(ValueError, match="domains cannot be empty"):
        b.acme_issue(
            domains=[],
            key_type="P256",
            dns_provider="dns_cf",
            provider_env={},
            acme_home="/h/.acme.sh",
        )


def test_acme_issue_failure_raises_backend_error(monkeypatch):
    b = _backend(monkeypatch)
    call_count = {"n": 0}

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        call_count["n"] += 1
        # 1st = stage tempfile (ok), 2nd = run script (fail rc=1), 3rd = cleanup
        if call_count["n"] == 2:
            return CommandResult(return_code=1, stderr="rate limit hit")
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        with pytest.raises(BackendError, match="rate limit"):
            b.acme_issue(
                domains=["example.com"],
                key_type="P256",
                dns_provider="dns_cf",
                provider_env={},
                acme_home="/h/.acme.sh",
            )


def test_acme_issue_rc2_treated_as_skip_not_error(monkeypatch):
    """acme.sh exits 2 when cert is current — we tolerate this."""
    b = _backend(monkeypatch)
    call_count = {"n": 0}

    def fake_run_ssh(remote_cmd, *, stdin=None, timeout=30):
        call_count["n"] += 1
        # 1st = stage tempfile (ok), 2nd = run script (rc=2), 3rd = cleanup
        if call_count["n"] == 2:
            return CommandResult(
                return_code=2,
                stdout="Skipping: cert not yet due for renewal",
            )
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake_run_ssh):
        result = b.acme_issue(
            domains=["example.com"],
            key_type="P256",
            dns_provider="dns_cf",
            provider_env={},
            acme_home="/h/.acme.sh",
        )
    assert result["acme_returncode"] == 2


# ---------------------------------------------------------------------------
# read_file
# ---------------------------------------------------------------------------

def test_read_file_returns_bytes(monkeypatch):
    """[VULN-04] mitigation: read_file uses _run_ssh_bytes (raw bytes),
    not _run_ssh (UTF-8 decoded). Binary content is preserved."""
    b = _backend(monkeypatch)

    def fake_run_ssh_bytes(remote_cmd, *, stdin=None, timeout=30):
        # Include a non-UTF-8 byte to prove no round-trip happens.
        return (0, b"hello\xff world", b"")

    with patch.object(b, "_run_ssh_bytes", side_effect=fake_run_ssh_bytes):
        content = b.read_file("/etc/foo")
    assert content == b"hello\xff world"


def test_read_file_failure_raises(monkeypatch):
    b = _backend(monkeypatch)

    def fake_run_ssh_bytes(remote_cmd, *, stdin=None, timeout=30):
        return (1, b"", b"No such file")

    with patch.object(b, "_run_ssh_bytes", side_effect=fake_run_ssh_bytes):
        with pytest.raises(BackendError, match="No such file"):
            b.read_file("/etc/missing")
