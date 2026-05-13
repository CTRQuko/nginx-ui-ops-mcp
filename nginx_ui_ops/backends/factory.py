"""Backend factory — selects the right transport(s) from env vars.

Used by tools to get a backend without coupling to specific
implementations. v0.4.0 adds multi-target support: declare multiple
nginx-ui instances via ``NGINXUI_TARGETS`` and request one by name.

Calling pattern::

    from nginx_ui_ops.backends import get_backend

    # Multi-target (v0.4.0+)
    backend = get_backend("logrono")  # explicit target
    backend = get_backend()           # default target (first declared)

    # Backward compat (v0.3.0 style)
    backend = get_backend()           # reads legacy NGINXUI_BACKEND

Caches are per-target for the process lifetime — flipping env vars
requires plugin restart.

Adding a new backend (LocalBackend, etc.):
  1. Implement ``NginxUIBackend`` in ``backends/<name>.py``.
  2. Add a case to ``_SUPPORTED`` below.
  3. Document the env vars in README.md and ``plugin.toml``
     credential_refs.

Multi-target env var convention (v0.4.0+):

    NGINXUI_TARGETS=logrono,vps
    NGINXUI_DEFAULT_TARGET=logrono       # optional, else first in list

    NGINXUI_TARGET_LOGRONO_BACKEND=wrapper-lxc
    NGINXUI_TARGET_LOGRONO_PVE_SSH_ALIAS=<pve-ssh-alias>
    NGINXUI_TARGET_LOGRONO_LXC_ID=<lxc-id>
    ...

    NGINXUI_TARGET_VPS_BACKEND=docker-exec
    NGINXUI_TARGET_VPS_DOCKER_SSH_ALIAS=hetzner-claude
    NGINXUI_TARGET_VPS_DOCKER_CONTAINER=nginx-ui
    ...

Legacy single-target (sin NGINXUI_TARGETS) sigue funcionando — el
factory cae a ``NGINXUI_BACKEND`` + las vars históricas.
"""
from __future__ import annotations

import os
import threading
from typing import Optional

from .base import BackendError, NginxUIBackend
from .direct_ssh import DirectSSHBackend
from .docker_exec import DockerExecBackend
from .wrapper_lxc import WrapperLXCBackend

_SUPPORTED: dict[str, type[NginxUIBackend]] = {
    "wrapper-lxc": WrapperLXCBackend,
    "direct-ssh": DirectSSHBackend,
    "docker-exec": DockerExecBackend,
}

# Sentinel name for legacy single-target mode (NGINXUI_BACKEND only).
_LEGACY_TARGET = "__default__"

_cached: dict[str, NginxUIBackend] = {}
_lock = threading.Lock()


def _norm_target(target: str) -> str:
    """Normalize target name to UPPER for env-var lookups."""
    return target.strip().upper()


def list_targets() -> list[str]:
    """Return declared targets from NGINXUI_TARGETS, or legacy sentinel.

    Legacy mode (no NGINXUI_TARGETS) returns ``["__default__"]`` so
    callers can iterate uniformly. The wizard + diagnostic tools use
    this to enumerate what's configured.
    """
    raw = os.environ.get("NGINXUI_TARGETS", "").strip()
    if not raw:
        return [_LEGACY_TARGET]
    parsed = [t.strip() for t in raw.split(",") if t.strip()]
    if not parsed:
        return [_LEGACY_TARGET]
    return parsed


def default_target() -> str:
    """Return the target used when caller doesn't pass one.

    Precedence:
      1. NGINXUI_DEFAULT_TARGET if set and present in NGINXUI_TARGETS
      2. First entry of NGINXUI_TARGETS
      3. ``__default__`` sentinel (legacy mode)
    """
    explicit = os.environ.get("NGINXUI_DEFAULT_TARGET", "").strip()
    targets = list_targets()
    if explicit:
        if explicit in targets:
            return explicit
        raise BackendError(
            f"NGINXUI_DEFAULT_TARGET={explicit!r} not in "
            f"NGINXUI_TARGETS={targets!r}. Fix vault or env."
        )
    return targets[0]


def _resolve_backend_class(target: str) -> type[NginxUIBackend]:
    """Look up which backend class handles ``target``.

    Legacy mode reads ``NGINXUI_BACKEND``; multi-target reads
    ``NGINXUI_TARGET_<TARGET>_BACKEND``.
    """
    if target == _LEGACY_TARGET:
        name = os.environ.get("NGINXUI_BACKEND", "").strip().lower()
        if not name:
            raise BackendError(
                "NGINXUI_BACKEND not set (legacy mode) and "
                "NGINXUI_TARGETS not declared. "
                f"Supported backends: {sorted(_SUPPORTED)}. "
                "See README.md for per-backend env vars."
            )
    else:
        norm = _norm_target(target)
        env_key = f"NGINXUI_TARGET_{norm}_BACKEND"
        name = os.environ.get(env_key, "").strip().lower()
        if not name:
            raise BackendError(
                f"{env_key} not set. Target {target!r} declared in "
                f"NGINXUI_TARGETS but no backend chosen. "
                f"Supported: {sorted(_SUPPORTED)}."
            )

    cls = _SUPPORTED.get(name)
    if cls is None:
        raise BackendError(
            f"backend {name!r} for target {target!r} unknown. "
            f"Supported: {sorted(_SUPPORTED)}."
        )
    return cls


def get_backend(target: str | None = None) -> NginxUIBackend:
    """Return the backend for ``target``. Default = first declared.

    In legacy mode (no NGINXUI_TARGETS), ``target`` should be left
    None — the factory resolves to the sentinel ``__default__`` and
    reads ``NGINXUI_BACKEND``.

    In multi-target mode, ``target`` must be one of NGINXUI_TARGETS
    or None (= NGINXUI_DEFAULT_TARGET).

    Cached per-target after first call. Thread-safe.

    Raises:
        BackendError: target not declared, backend env var missing,
            backend value unknown, or ``from_env_target()`` validation
            failed.
    """
    t = target.strip() if target else default_target()

    # Validate target is declared (multi-target mode only).
    declared = list_targets()
    if t not in declared:
        raise BackendError(
            f"target {t!r} not in NGINXUI_TARGETS={declared!r}. "
            f"Add it to the list or pass an existing target."
        )

    if t in _cached:
        return _cached[t]

    with _lock:
        if t not in _cached:
            cls = _resolve_backend_class(t)
            if t == _LEGACY_TARGET:
                _cached[t] = cls.from_env()
            else:
                _cached[t] = cls.from_env_target(t)
    return _cached[t]


def reset_cache() -> None:
    """Clear the cached backends. Used by tests; rarely useful in prod."""
    global _cached
    with _lock:
        _cached = {}


def supports_acme(target: str | None = None) -> bool:
    """Quick check without instantiating the backend.

    Returns the class-level ``supports_acme`` attribute. Useful for
    tools to fail fast before composing the (potentially expensive)
    backend instance.

    Defensive: if backend class cannot be resolved (env vars missing,
    invalid backend name, test mode without NGINXUI_BACKEND, etc.),
    returns ``True`` (permissive default). The real backend
    instantiation will raise a clearer error at the actual call site
    instead of failing inside this capability check.
    """
    try:
        t = target.strip() if target else default_target()
        cls = _resolve_backend_class(t)
        return getattr(cls, "supports_acme", True)
    except BackendError:
        return True
