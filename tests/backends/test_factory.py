"""Tests for backend factory selector."""
from __future__ import annotations

import pytest

from nginx_ui_ops.backends import get_backend, reset_cache
from nginx_ui_ops.backends.base import BackendError
from nginx_ui_ops.backends.direct_ssh import DirectSSHBackend
from nginx_ui_ops.backends.wrapper_lxc import WrapperLXCBackend


@pytest.fixture(autouse=True)
def _reset_cache_fixture():
    """Each test gets a clean cached backend."""
    reset_cache()
    yield
    reset_cache()


def test_unset_env_raises(monkeypatch):
    monkeypatch.delenv("NGINXUI_BACKEND", raising=False)
    with pytest.raises(BackendError, match="NGINXUI_BACKEND not set"):
        get_backend()


def test_unknown_env_value_raises(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "magic-cloud")
    with pytest.raises(BackendError, match="unknown"):
        get_backend()


def test_wrapper_lxc_selection(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    backend = get_backend()
    assert isinstance(backend, WrapperLXCBackend)


def test_direct_ssh_selection(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "direct-ssh")
    monkeypatch.setenv("NGINXUI_HOST", "ngx-host")
    backend = get_backend()
    assert isinstance(backend, DirectSSHBackend)


def test_cached_returns_same_instance(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "direct-ssh")
    monkeypatch.setenv("NGINXUI_HOST", "ngx-host")
    a = get_backend()
    b = get_backend()
    assert a is b


def test_reset_cache_yields_new_instance(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "direct-ssh")
    monkeypatch.setenv("NGINXUI_HOST", "ngx-host")
    a = get_backend()
    reset_cache()
    b = get_backend()
    assert a is not b


def test_case_insensitive_env_value(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "Direct-SSH")
    monkeypatch.setenv("NGINXUI_HOST", "ngx-host")
    backend = get_backend()
    assert isinstance(backend, DirectSSHBackend)


def test_whitespace_in_env_value_stripped(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "  direct-ssh  ")
    monkeypatch.setenv("NGINXUI_HOST", "ngx-host")
    backend = get_backend()
    assert isinstance(backend, DirectSSHBackend)


def test_backend_validation_error_propagates(monkeypatch):
    """If the chosen backend's from_env fails, the factory raises
    BackendError too (no swallowing)."""
    monkeypatch.setenv("NGINXUI_BACKEND", "direct-ssh")
    monkeypatch.delenv("NGINXUI_HOST", raising=False)
    with pytest.raises(BackendError, match="NGINXUI_HOST"):
        get_backend()
