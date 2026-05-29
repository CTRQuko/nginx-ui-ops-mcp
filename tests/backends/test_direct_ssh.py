"""Tests for DirectSSHBackend (mocks of _run_ssh)."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from nginx_ui_ops.backends.base import BackendError, CommandResult
from nginx_ui_ops.backends.direct_ssh import DirectSSHBackend


def _backend(monkeypatch, **overrides):
    env = {"NGINXUI_HOST": "ngx-host"}
    env.update(overrides)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return DirectSSHBackend.from_env()


# from_env

def test_from_env_minimal(monkeypatch):
    monkeypatch.setenv("NGINXUI_HOST", "ngx-host")
    monkeypatch.delenv("NGINXUI_SSH_USER", raising=False)
    monkeypatch.delenv("NGINXUI_SUDO_METHOD", raising=False)
    b = DirectSSHBackend.from_env()
    assert b.host == "ngx-host"
    assert b.ssh_user == ""
    assert b.sudo_method == "nopasswd"


def test_from_env_missing_host_raises(monkeypatch):
    monkeypatch.delenv("NGINXUI_HOST", raising=False)
    with pytest.raises(BackendError, match="NGINXUI_HOST"):
        DirectSSHBackend.from_env()


def test_from_env_invalid_sudo_method(monkeypatch):
    monkeypatch.setenv("NGINXUI_HOST", "ngx-host")
    monkeypatch.setenv("NGINXUI_SUDO_METHOD", "magic")
    with pytest.raises(BackendError, match="NGINXUI_SUDO_METHOD"):
        DirectSSHBackend.from_env()


def test_from_env_password_method_requires_password_ref(monkeypatch):
    monkeypatch.setenv("NGINXUI_HOST", "ngx-host")
    monkeypatch.setenv("NGINXUI_SUDO_METHOD", "password")
    monkeypatch.delenv("NGINXUI_SUDO_PASSWORD_REF", raising=False)
    with pytest.raises(BackendError, match="NGINXUI_SUDO_PASSWORD_REF"):
        DirectSSHBackend.from_env()


def test_describe_with_user(monkeypatch):
    b = _backend(monkeypatch, NGINXUI_SSH_USER="ops")
    assert "ops@ngx-host" in b.describe()


def test_describe_without_user(monkeypatch):
    b = _backend(monkeypatch)
    desc = b.describe()
    assert "ngx-host" in desc
    assert "@" not in desc.replace("Backend(", "")  # no user prefix


# run_cmd

def test_run_cmd_no_sudo(monkeypatch):
    b = _backend(monkeypatch)
    captured: list[str] = []

    def fake(remote_cmd, *, stdin=None, timeout=30):
        captured.append(remote_cmd)
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        b.run_cmd(["nginx", "-t"])
    assert "nginx -t" in captured[0]
    assert not captured[0].startswith("sudo")


def test_run_cmd_sudo_nopasswd(monkeypatch):
    b = _backend(monkeypatch)
    captured: list[str] = []
    captured_stdin: list = []

    def fake(remote_cmd, *, stdin=None, timeout=30):
        captured.append(remote_cmd)
        captured_stdin.append(stdin)
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        b.run_cmd(["systemctl", "restart", "nginx"], sudo=True)
    assert captured[0].startswith("sudo ")
    assert "-S" not in captured[0]
    assert captured_stdin[0] is None


def test_run_cmd_sudo_none_omits_prefix(monkeypatch):
    """When SUDO_METHOD=none (running as root), no sudo prefix even
    when sudo=True."""
    b = _backend(monkeypatch, NGINXUI_SUDO_METHOD="none")
    captured: list[str] = []

    def fake(remote_cmd, *, stdin=None, timeout=30):
        captured.append(remote_cmd)
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        b.run_cmd(["systemctl", "restart", "nginx"], sudo=True)
    assert not captured[0].startswith("sudo ")


def test_run_cmd_sudo_password_method(monkeypatch, tmp_path):
    pw = tmp_path / "sudo.pw"
    pw.write_text("hunter2\n", encoding="utf-8")
    b = _backend(
        monkeypatch,
        NGINXUI_SUDO_METHOD="password",
        NGINXUI_SUDO_PASSWORD_REF=str(pw),
    )
    captured_cmd: list[str] = []
    captured_stdin: list = []

    def fake(remote_cmd, *, stdin=None, timeout=30):
        captured_cmd.append(remote_cmd)
        captured_stdin.append(stdin)
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        b.run_cmd(["nginx", "-t"], sudo=True)
    assert captured_cmd[0].startswith("sudo -S ")
    assert captured_stdin[0] == b"hunter2\n"


def test_run_cmd_empty_argv_raises(monkeypatch):
    b = _backend(monkeypatch)
    with pytest.raises(ValueError, match="argv cannot be empty"):
        b.run_cmd([])


# push_file

def test_push_file_strips_crlf(monkeypatch):
    b = _backend(monkeypatch)
    stdins: list = []

    def fake(remote_cmd, *, stdin=None, timeout=30):
        stdins.append(stdin)
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        b.push_file(b"line1\r\nline2\r\n", "/etc/foo.conf")
    # First call is the stage step.
    assert stdins[0] == b"line1\nline2\n"


def test_push_file_binary_preserved(monkeypatch):
    b = _backend(monkeypatch)
    stdins: list = []

    def fake(remote_cmd, *, stdin=None, timeout=30):
        stdins.append(stdin)
        return CommandResult(return_code=0)

    binary = b"\xff\xfe\r\n\x00"
    with patch.object(b, "_run_ssh", side_effect=fake):
        b.push_file(binary, "/etc/cert.bin")
    assert stdins[0] == binary


def test_push_file_uses_mv_with_sudo(monkeypatch):
    b = _backend(monkeypatch)
    cmds: list[str] = []

    def fake(remote_cmd, *, stdin=None, timeout=30):
        cmds.append(remote_cmd)
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        b.push_file(b"data", "/etc/protected", sudo=True)
    # 2nd call is the mv+chmod chain.
    assert "sudo mv" in cmds[1]
    assert "/etc/protected" in cmds[1]
    assert "chmod 644" in cmds[1]


def test_push_file_failure_raises(monkeypatch):
    b = _backend(monkeypatch)

    def fake(remote_cmd, *, stdin=None, timeout=30):
        if "cat >" in remote_cmd:
            return CommandResult(return_code=1, stderr="permission denied")
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        with pytest.raises(BackendError, match="permission denied"):
            b.push_file(b"data", "/etc/foo")


# read_file

def test_read_file_returns_bytes(monkeypatch):
    """[VULN-04] mitigation: bytes-preserving path via _run_ssh_bytes."""
    b = _backend(monkeypatch)

    def fake_bytes(remote_cmd, *, stdin=None, timeout=30):
        return (0, b"contents\xff", b"")

    with patch.object(b, "_run_ssh_bytes", side_effect=fake_bytes):
        assert b.read_file("/etc/foo") == b"contents\xff"


def test_read_file_failure_raises(monkeypatch):
    b = _backend(monkeypatch)

    def fake_bytes(remote_cmd, *, stdin=None, timeout=30):
        return (1, b"", b"No such file")

    with patch.object(b, "_run_ssh_bytes", side_effect=fake_bytes):
        with pytest.raises(BackendError):
            b.read_file("/etc/missing")


# query_db

def test_query_db_returns_rows(monkeypatch):
    b = _backend(monkeypatch)

    def fake(remote_cmd, *, stdin=None, timeout=30):
        if "sqlite3" in remote_cmd:
            return CommandResult(
                return_code=0,
                stdout='[{"id":1,"name":"a"},{"id":2,"name":"b"}]',
            )
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        rows = b.query_db("/db", "SELECT * FROM t WHERE id=?", params=(1,))
    assert rows == [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]


def test_query_db_empty(monkeypatch):
    b = _backend(monkeypatch)

    def fake(remote_cmd, *, stdin=None, timeout=30):
        if "sqlite3" in remote_cmd:
            return CommandResult(return_code=0, stdout="")
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        assert b.query_db("/db", "SELECT 1 WHERE 0") == []


def test_query_db_non_json_raises(monkeypatch):
    b = _backend(monkeypatch)

    def fake(remote_cmd, *, stdin=None, timeout=30):
        if "sqlite3" in remote_cmd:
            return CommandResult(return_code=0, stdout="invalid")
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        with pytest.raises(BackendError, match="non-JSON"):
            b.query_db("/db", "SELECT 1")


# acme_issue

def test_acme_issue_command_shape(monkeypatch):
    """[VULN-06] mitigation: env exports + acme.sh invocation live in
    the script body sent via stdin to the tempfile staging step,
    NOT in the SSH cmdline (which would leak to `ps aux`)."""
    b = _backend(monkeypatch)
    captured: list[tuple[str, bytes | None]] = []

    def fake(remote_cmd, *, stdin=None, timeout=30):
        captured.append((remote_cmd, stdin))
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        result = b.acme_issue(
            domains=["foo.example.com"],
            key_type="RSA2048",
            dns_provider="dns_aws",
            provider_env={"AWS_ACCESS_KEY_ID": "ABC", "AWS_SECRET_ACCESS_KEY": "XYZ"},
            acme_home="/home/test/.acme.sh",
        )

    # 3 SSH calls: stage tempfile, run script, cleanup.
    assert len(captured) == 3
    stage_cmd, stage_stdin = captured[0]
    run_cmd, _ = captured[1]
    cleanup_cmd, _ = captured[2]

    # No secrets / env exports in any cmdline.
    for cmd in (stage_cmd, run_cmd, cleanup_cmd):
        assert "AWS_ACCESS_KEY_ID" not in cmd
        assert "ABC" not in cmd
        assert "XYZ" not in cmd
        assert "export " not in cmd

    # Stage payload (stdin) contains the env exports + acme invocation.
    assert stage_stdin is not None
    assert b"export AWS_ACCESS_KEY_ID=" in stage_stdin
    assert b"--dns dns_aws" in stage_stdin
    assert b"--keylength 2048" in stage_stdin
    assert b"-d foo.example.com" in stage_stdin
    # Run step references the tempfile.
    assert run_cmd.startswith("sh ")
    # RSA → no _ecc suffix in path.
    assert result["fullchain_path"].endswith("/foo.example.com/fullchain.cer")


def test_acme_issue_ecc_path_uses_suffix(monkeypatch):
    b = _backend(monkeypatch)

    def fake(remote_cmd, *, stdin=None, timeout=30):
        return CommandResult(return_code=0)

    with patch.object(b, "_run_ssh", side_effect=fake):
        result = b.acme_issue(
            domains=["foo.example.com"],
            key_type="P256",
            dns_provider="dns_cf",
            provider_env={},
            acme_home="/h",
        )
    assert "_ecc" in result["fullchain_path"]


def test_acme_issue_failure_raises(monkeypatch):
    b = _backend(monkeypatch)

    def fake(remote_cmd, *, stdin=None, timeout=30):
        return CommandResult(return_code=1, stderr="rate limit")

    with patch.object(b, "_run_ssh", side_effect=fake):
        with pytest.raises(BackendError, match="rate limit"):
            b.acme_issue(
                domains=["foo.example.com"],
                key_type="P256",
                dns_provider="dns_cf",
                provider_env={},
                acme_home="/h",
            )


def test_acme_issue_rejects_empty_domains(monkeypatch):
    b = _backend(monkeypatch)
    with pytest.raises(ValueError, match="domains cannot be empty"):
        b.acme_issue(
            domains=[],
            key_type="P256",
            dns_provider="dns_cf",
            provider_env={},
            acme_home="/h",
        )
