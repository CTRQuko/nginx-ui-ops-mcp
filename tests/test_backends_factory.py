"""Tests for the multi-target factory (v0.4.0+).

Covers ``list_targets``, ``default_target``, ``get_backend(target)``,
``supports_acme(target)``, legacy backward-compat, and error paths.
"""
from __future__ import annotations

import pytest

from nginx_ui_ops.backends import (
    BackendError,
    default_target,
    get_backend,
    list_targets,
    reset_cache,
    supports_acme,
)
from nginx_ui_ops.backends.docker_exec import DockerExecBackend
from nginx_ui_ops.backends.wrapper_lxc import WrapperLXCBackend


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_cache()
    yield
    reset_cache()


# ---------------------------------------------------------------------------
# list_targets + default_target
# ---------------------------------------------------------------------------


def test_list_targets_legacy_mode_when_no_env(monkeypatch):
    """No NGINXUI_TARGETS → returns __default__ sentinel."""
    monkeypatch.delenv("NGINXUI_TARGETS", raising=False)
    assert list_targets() == ["__default__"]


def test_list_targets_parses_comma_separated(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono,vps,edge")
    assert list_targets() == ["logrono", "vps", "edge"]


def test_list_targets_strips_whitespace(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "  logrono , vps  , edge  ")
    assert list_targets() == ["logrono", "vps", "edge"]


def test_list_targets_skips_empty_entries(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono,,vps,")
    assert list_targets() == ["logrono", "vps"]


def test_default_target_uses_explicit(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono,vps")
    monkeypatch.setenv("NGINXUI_DEFAULT_TARGET", "vps")
    assert default_target() == "vps"


def test_default_target_falls_back_to_first(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono,vps")
    monkeypatch.delenv("NGINXUI_DEFAULT_TARGET", raising=False)
    assert default_target() == "logrono"


def test_default_target_rejects_unknown_explicit(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono,vps")
    monkeypatch.setenv("NGINXUI_DEFAULT_TARGET", "nope")
    with pytest.raises(BackendError, match="not in NGINXUI_TARGETS"):
        default_target()


# ---------------------------------------------------------------------------
# get_backend — multi-target
# ---------------------------------------------------------------------------


def test_get_backend_resolves_target_to_wrapper_lxc(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_LXC_ID", "100")
    backend = get_backend("logrono")
    assert isinstance(backend, WrapperLXCBackend)
    assert backend.pve_ssh_alias == "pve-test"
    assert backend.lxc_id == "100"


def test_get_backend_resolves_target_to_docker_exec(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "vps")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_BACKEND", "docker-exec")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_DOCKER_SSH_ALIAS", "vps-host")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_DOCKER_CONTAINER", "nginx-ui")
    backend = get_backend("vps")
    assert isinstance(backend, DockerExecBackend)
    assert backend.ssh_alias == "vps-host"
    assert backend.container == "nginx-ui"


def test_get_backend_caches_per_target(monkeypatch):
    """Two get_backend(t) calls return the same instance."""
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_LXC_ID", "100")
    b1 = get_backend("logrono")
    b2 = get_backend("logrono")
    assert b1 is b2


def test_get_backend_separate_cache_per_target(monkeypatch):
    """Different targets get different cached instances."""
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono,vps")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_LXC_ID", "100")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_BACKEND", "docker-exec")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_DOCKER_SSH_ALIAS", "vps-host")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_DOCKER_CONTAINER", "nginx-ui")
    b_l = get_backend("logrono")
    b_v = get_backend("vps")
    assert b_l is not b_v
    assert isinstance(b_l, WrapperLXCBackend)
    assert isinstance(b_v, DockerExecBackend)


def test_get_backend_rejects_undeclared_target(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_PVE_SSH_ALIAS", "pve")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_LXC_ID", "100")
    with pytest.raises(BackendError, match="not in NGINXUI_TARGETS"):
        get_backend("nope")


def test_get_backend_default_when_target_none(monkeypatch):
    """target=None → default_target()."""
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono,vps")
    monkeypatch.setenv("NGINXUI_DEFAULT_TARGET", "vps")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_BACKEND", "docker-exec")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_DOCKER_SSH_ALIAS", "h")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_DOCKER_CONTAINER", "c")
    backend = get_backend()
    assert isinstance(backend, DockerExecBackend)


def test_get_backend_missing_target_backend_var_raises(monkeypatch):
    """Target declared but no NGINXUI_TARGET_<T>_BACKEND set."""
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono")
    monkeypatch.delenv("NGINXUI_TARGET_LOGRONO_BACKEND", raising=False)
    with pytest.raises(BackendError, match="LOGRONO_BACKEND"):
        get_backend("logrono")


def test_get_backend_unknown_backend_raises(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_BACKEND", "magic")
    with pytest.raises(BackendError, match="unknown"):
        get_backend("logrono")


# ---------------------------------------------------------------------------
# get_backend — legacy single-target backward-compat
# ---------------------------------------------------------------------------


def test_get_backend_legacy_mode_wrapper_lxc(monkeypatch):
    """No NGINXUI_TARGETS → reads NGINXUI_BACKEND + legacy vars."""
    monkeypatch.delenv("NGINXUI_TARGETS", raising=False)
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-legacy")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    backend = get_backend()
    assert isinstance(backend, WrapperLXCBackend)
    assert backend.pve_ssh_alias == "pve-legacy"


def test_get_backend_legacy_mode_no_backend_set_raises(monkeypatch):
    monkeypatch.delenv("NGINXUI_TARGETS", raising=False)
    monkeypatch.delenv("NGINXUI_BACKEND", raising=False)
    with pytest.raises(BackendError, match="NGINXUI_BACKEND not set"):
        get_backend()


# ---------------------------------------------------------------------------
# supports_acme
# ---------------------------------------------------------------------------


def test_supports_acme_wrapper_lxc_true(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "logrono")
    monkeypatch.setenv("NGINXUI_TARGET_LOGRONO_BACKEND", "wrapper-lxc")
    assert supports_acme("logrono") is True


def test_supports_acme_direct_ssh_true(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "edge")
    monkeypatch.setenv("NGINXUI_TARGET_EDGE_BACKEND", "direct-ssh")
    assert supports_acme("edge") is True


def test_supports_acme_docker_exec_false(monkeypatch):
    monkeypatch.setenv("NGINXUI_TARGETS", "vps")
    monkeypatch.setenv("NGINXUI_TARGET_VPS_BACKEND", "docker-exec")
    assert supports_acme("vps") is False


def test_supports_acme_defensive_when_env_missing(monkeypatch):
    """If backend class cannot be resolved, supports_acme returns True (permissive default)."""
    monkeypatch.delenv("NGINXUI_TARGETS", raising=False)
    monkeypatch.delenv("NGINXUI_BACKEND", raising=False)
    assert supports_acme() is True  # defensive fallback
