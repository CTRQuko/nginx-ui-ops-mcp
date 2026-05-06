"""Backend factory — selects the right transport from env vars.

Used by tools to get a backend without coupling to specific
implementations. The selection is cached for the process lifetime —
flipping ``NGINXUI_BACKEND`` requires plugin restart.

Calling pattern::

    from nginx_ui_ops.backends import get_backend
    backend = get_backend()
    backend.run_cmd(["nginx", "-t"])

Adding a new backend (DockerExecBackend, LocalBackend, ...):
  1. Implement ``NginxUIBackend`` in ``backends/<name>.py``.
  2. Add a case to ``_resolve_backend_class`` below.
  3. Document the env vars in README.md and ``plugin.toml`` credential_refs.
"""
from __future__ import annotations

import os
import threading
from typing import Optional

from .base import BackendError, NginxUIBackend
from .direct_ssh import DirectSSHBackend
from .wrapper_lxc import WrapperLXCBackend

_SUPPORTED: dict[str, type[NginxUIBackend]] = {
    "wrapper-lxc": WrapperLXCBackend,
    "direct-ssh": DirectSSHBackend,
}

_cached: Optional[NginxUIBackend] = None
_lock = threading.Lock()


def _resolve_backend_class() -> type[NginxUIBackend]:
    """Pick the backend class for the configured ``NGINXUI_BACKEND``."""
    name = os.environ.get("NGINXUI_BACKEND", "").strip().lower()
    if not name:
        raise BackendError(
            "NGINXUI_BACKEND not set. "
            f"Supported: {sorted(_SUPPORTED)}. "
            "See README.md for per-backend env vars."
        )
    cls = _SUPPORTED.get(name)
    if cls is None:
        raise BackendError(
            f"NGINXUI_BACKEND={name!r} unknown. "
            f"Supported: {sorted(_SUPPORTED)}."
        )
    return cls


def get_backend() -> NginxUIBackend:
    """Return the backend selected by ``NGINXUI_BACKEND`` env var.

    Cached after first call. Thread-safe.

    Raises:
        BackendError: env var not set, value unknown, or backend
            ``from_env()`` validation failed.
    """
    global _cached
    if _cached is not None:
        return _cached
    with _lock:
        if _cached is None:
            _cached = _resolve_backend_class().from_env()
    return _cached


def reset_cache() -> None:
    """Clear the cached backend. Used by tests; rarely useful in prod."""
    global _cached
    with _lock:
        _cached = None
