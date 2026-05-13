"""Tests for tools/nginx.py."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from nginx_ui_ops.backends import reset_cache
from nginx_ui_ops.tools import nginx as nginx_mod


class FakeBackend:
    def __init__(self):
        self.commands: list[tuple[list[str], bool]] = []
        self.responses: list = []

    def run_cmd(self, argv, *, sudo=False, timeout=30):
        self.commands.append((list(argv), sudo))
        if self.responses:
            return self.responses.pop(0)
        m = MagicMock()
        m.ok = True
        m.return_code = 0
        m.stdout = "syntax is ok\nconfiguration test is successful"
        m.stderr = ""
        return m


@pytest.fixture
def fake_backend(monkeypatch):
    fake = FakeBackend()
    reset_cache()
    monkeypatch.setattr(nginx_mod, "get_backend", lambda *a, **kw: fake)
    return fake


# nginx_test

def test_nginx_test_runs_with_sudo(fake_backend):
    result = nginx_mod.nginx_test()
    assert result["ok"] is True
    assert "syntax is ok" in result["stdout"]
    assert fake_backend.commands[0] == (["nginx", "-t"], True)


def test_nginx_test_failure(fake_backend):
    bad = MagicMock(); bad.ok = False; bad.return_code = 1
    bad.stdout = ""; bad.stderr = "nginx: invalid config\n"
    fake_backend.responses = [bad]
    result = nginx_mod.nginx_test()
    assert result["ok"] is False
    assert "invalid config" in result["stderr"]


# nginx_reload

def test_nginx_reload_skips_reload_when_test_fails(fake_backend):
    bad = MagicMock(); bad.ok = False; bad.return_code = 1
    bad.stdout = ""; bad.stderr = "syntax error"
    fake_backend.responses = [bad]
    result = nginx_mod.nginx_reload()
    assert result["ok"] is False
    assert result["test"]["ok"] is False
    assert result["reload_attempted"] is False
    # Only the test command was issued.
    assert len(fake_backend.commands) == 1
    assert fake_backend.commands[0] == (["nginx", "-t"], True)


def test_nginx_reload_reloads_after_test_pass(fake_backend):
    test_ok = MagicMock(); test_ok.ok = True; test_ok.return_code = 0
    test_ok.stdout = "ok"; test_ok.stderr = ""
    reload_ok = MagicMock(); reload_ok.ok = True; reload_ok.return_code = 0
    reload_ok.stdout = ""; reload_ok.stderr = ""
    fake_backend.responses = [test_ok, reload_ok]
    result = nginx_mod.nginx_reload()
    assert result["ok"] is True
    assert result["reload_attempted"] is True
    assert result["reload_rc"] == 0
    assert len(fake_backend.commands) == 2
    assert fake_backend.commands[1] == (["nginx", "-s", "reload"], True)


def test_nginx_reload_failure_during_reload(fake_backend):
    test_ok = MagicMock(); test_ok.ok = True; test_ok.return_code = 0
    test_ok.stdout = "ok"; test_ok.stderr = ""
    reload_fail = MagicMock(); reload_fail.ok = False; reload_fail.return_code = 1
    reload_fail.stdout = ""; reload_fail.stderr = "fail"
    fake_backend.responses = [test_ok, reload_fail]
    result = nginx_mod.nginx_reload()
    assert result["ok"] is False
    assert result["reload_attempted"] is True
    assert result["test"]["ok"] is True
