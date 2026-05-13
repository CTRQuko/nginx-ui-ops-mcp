"""Tests for DockerExecBackend (v0.4.0+).

Mocks subprocess to avoid touching real SSH/docker. Covers:
- from_env / from_env_target construction
- describe
- run_cmd argv composition
- push_file (tee + chmod)
- read_file (bytes preservation)
- query_db (tempfile + sqlite3 -json roundtrip)
- acme_issue raises BackendError (supports_acme=False)
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from nginx_ui_ops.backends import BackendError
from nginx_ui_ops.backends.docker_exec import DockerExecBackend


@pytest.fixture
def fake_proc():
    """Helper to build a fake CompletedProcess for subprocess.run."""
    def _make(stdout=b"", stderr=b"", returncode=0):
        m = MagicMock()
        m.returncode = returncode
        m.stdout = stdout
        m.stderr = stderr
        return m
    return _make


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_from_env_legacy(monkeypatch):
    monkeypatch.setenv("NGINXUI_DOCKER_SSH_ALIAS", "vps-test")
    monkeypatch.setenv("NGINXUI_DOCKER_CONTAINER", "nginx-ui")
    b = DockerExecBackend.from_env()
    assert b.ssh_alias == "vps-test"
    assert b.container == "nginx-ui"
    assert b.docker_user is None


def test_from_env_missing_ssh_alias_raises(monkeypatch):
    monkeypatch.delenv("NGINXUI_DOCKER_SSH_ALIAS", raising=False)
    monkeypatch.setenv("NGINXUI_DOCKER_CONTAINER", "x")
    with pytest.raises(BackendError, match="SSH_ALIAS"):
        DockerExecBackend.from_env()


def test_from_env_missing_container_raises(monkeypatch):
    monkeypatch.setenv("NGINXUI_DOCKER_SSH_ALIAS", "x")
    monkeypatch.delenv("NGINXUI_DOCKER_CONTAINER", raising=False)
    with pytest.raises(BackendError, match="CONTAINER"):
        DockerExecBackend.from_env()


def test_from_env_target(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGET_VPS_DOCKER_SSH_ALIAS", "h")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_DOCKER_CONTAINER", "c")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_DOCKER_USER", "root")
    b = DockerExecBackend.from_env_target("vps")
    assert b.ssh_alias == "h"
    assert b.container == "c"
    assert b.docker_user == "root"


def test_from_env_target_missing_raises(monkeypatch):
    monkeypatch.delenv("NGINXUI_TARGET_VPS_DOCKER_SSH_ALIAS", raising=False)
    with pytest.raises(BackendError, match="VPS_DOCKER_SSH_ALIAS"):
        DockerExecBackend.from_env_target("vps")


def test_describe_includes_ssh_and_container():
    b = DockerExecBackend(ssh_alias="hetzner", container="nginx-ui")
    assert "hetzner" in b.describe()
    assert "nginx-ui" in b.describe()


def test_supports_acme_is_false():
    assert DockerExecBackend.supports_acme is False


# ---------------------------------------------------------------------------
# run_cmd
# ---------------------------------------------------------------------------


def test_run_cmd_composes_ssh_docker_exec_argv(fake_proc):
    b = DockerExecBackend(ssh_alias="h", container="c")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = fake_proc(stdout=b"hello", returncode=0)
        result = b.run_cmd(["echo", "hi"])
    assert result.ok
    assert result.stdout == "hello"
    # Verify argv shape
    args, _ = mock_run.call_args
    cmd = args[0]
    assert cmd[0] == "ssh"
    assert cmd[1] == "h"
    # Remote command should mention docker exec, container, echo, hi
    assert "docker" in cmd[2]
    assert "exec" in cmd[2]
    assert "c" in cmd[2]
    assert "echo" in cmd[2]
    assert "hi" in cmd[2]


def test_run_cmd_includes_user_flag_when_set(fake_proc):
    b = DockerExecBackend(ssh_alias="h", container="c", docker_user="root")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = fake_proc()
        b.run_cmd(["echo"])
    cmd = mock_run.call_args[0][0]
    assert "--user" in cmd[2]
    assert "root" in cmd[2]


def test_run_cmd_empty_argv_raises():
    b = DockerExecBackend(ssh_alias="h", container="c")
    with pytest.raises(BackendError, match="non-empty argv"):
        b.run_cmd([])


def test_run_cmd_timeout_raises(fake_proc):
    import subprocess as _sp
    b = DockerExecBackend(ssh_alias="h", container="c")
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = _sp.TimeoutExpired(cmd="ssh", timeout=10)
        with pytest.raises(BackendError, match="timeout"):
            b.run_cmd(["sleep", "60"], timeout=10)


# ---------------------------------------------------------------------------
# push_file
# ---------------------------------------------------------------------------


def test_push_file_strips_crlf_for_utf8(fake_proc):
    b = DockerExecBackend(ssh_alias="h", container="c")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = fake_proc()
        b.push_file(b"line1\r\nline2\r\n", "/tmp/x", mode=0o644)
    # First call should be the tee+stdin write
    first_args, first_kwargs = mock_run.call_args_list[0]
    assert first_kwargs.get("input") == b"line1\nline2\n"


def test_push_file_passes_binary_through(fake_proc):
    """Non-UTF-8 bytes should pass verbatim (no normalization)."""
    b = DockerExecBackend(ssh_alias="h", container="c")
    binary = b"\xff\xfe\x00\x01\x02"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = fake_proc()
        b.push_file(binary, "/tmp/x")
    first_args, first_kwargs = mock_run.call_args_list[0]
    assert first_kwargs.get("input") == binary


def test_push_file_chmod_called_after_write(fake_proc):
    b = DockerExecBackend(ssh_alias="h", container="c")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = fake_proc()
        b.push_file(b"data", "/tmp/x", mode=0o600)
    # 2nd call = chmod
    second_args, _ = mock_run.call_args_list[1]
    second_cmd = second_args[0]
    assert "chmod" in second_cmd[2]
    assert "600" in second_cmd[2]


# ---------------------------------------------------------------------------
# read_file
# ---------------------------------------------------------------------------


def test_read_file_returns_raw_bytes(fake_proc):
    b = DockerExecBackend(ssh_alias="h", container="c")
    payload = b"some\x00binary\xff"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = fake_proc(stdout=payload)
        result = b.read_file("/etc/nginx/nginx.conf")
    assert result == payload


def test_read_file_nonzero_rc_raises(fake_proc):
    b = DockerExecBackend(ssh_alias="h", container="c")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = fake_proc(stderr=b"no such file", returncode=1)
        with pytest.raises(BackendError, match="no such file"):
            b.read_file("/missing")


# ---------------------------------------------------------------------------
# query_db
# ---------------------------------------------------------------------------


def test_query_db_parses_json_output(fake_proc):
    b = DockerExecBackend(ssh_alias="h", container="c")
    payload = json.dumps([
        {"id": 1, "name": "foo"},
        {"id": 2, "name": "bar"},
    ]).encode("utf-8")

    call_count = {"n": 0}

    def side_effect(*args, **kwargs):
        call_count["n"] += 1
        # 1st: push_file tee → return OK
        # 2nd: push_file chmod → return OK
        # 3rd: sqlite3 -json → return JSON
        # 4th: cleanup rm → return OK
        if call_count["n"] == 3:
            return fake_proc(stdout=payload.decode("utf-8").encode("utf-8"))
        return fake_proc()

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        # subprocess.run returns text=False mode for read_file; for query_db
        # via _run_local it uses bytes.decode, so we need the stdout as bytes
        # but the _run_local wraps stdout/stderr with .decode("utf-8")
        # → so the third call's stdout should be the JSON BYTES
        result = b.query_db("/db.sqlite", "SELECT * FROM t")

    assert result == [
        {"id": 1, "name": "foo"},
        {"id": 2, "name": "bar"},
    ]


def test_query_db_empty_result(fake_proc):
    b = DockerExecBackend(ssh_alias="h", container="c")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = fake_proc(stdout=b"", returncode=0)
        result = b.query_db("/db.sqlite", "SELECT * FROM t WHERE 0=1")
    assert result == []


def test_query_db_param_binding(fake_proc):
    """Verify ? placeholders get bound + quoted SQL is written to tempfile."""
    b = DockerExecBackend(ssh_alias="h", container="c")
    written: dict[str, bytes] = {}

    def side_effect(*args, **kwargs):
        # Capture the SQL written to the tempfile (1st call's stdin)
        if "input" in kwargs and kwargs["input"]:
            written["sql"] = kwargs["input"]
        return fake_proc(stdout=b"[]", returncode=0)

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        b.query_db(
            "/db.sqlite",
            "SELECT * FROM certs WHERE id = ?",
            params=(42,),
        )

    assert b"42" in written["sql"]
    assert b"FROM certs WHERE id" in written["sql"]


# ---------------------------------------------------------------------------
# acme_issue — must refuse cleanly
# ---------------------------------------------------------------------------


def test_acme_issue_raises_unsupported():
    b = DockerExecBackend(ssh_alias="h", container="c")
    with pytest.raises(BackendError, match="does not support acme.sh"):
        b.acme_issue(
            ["example.com"],
            key_type="P256",
            dns_provider="dns_cf",
            provider_env={},
            acme_home="/root/.acme.sh",
        )
