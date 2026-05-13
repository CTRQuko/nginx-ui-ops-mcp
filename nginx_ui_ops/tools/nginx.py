"""nginx control tools: ``nginx -t`` and ``nginx -s reload``.

``nginx_reload`` always runs ``nginx -t`` first as a safety net —
never reload with a broken config (would 500 every request until
fixed).

v0.4.0: each tool accepts an optional ``target`` param to select a
specific nginx-ui instance (when ``NGINXUI_TARGETS`` is declared).
``target=None`` falls back to the default target (first declared or
``NGINXUI_DEFAULT_TARGET``).
"""
from __future__ import annotations

from typing import Any

from ..backends import get_backend
from ..models import NginxTestResult


def nginx_test(target: str | None = None) -> dict[str, Any]:
    """Run ``nginx -t`` to validate config syntax. Read-only.

    Args:
        target: nginx-ui instance to operate on (e.g. ``"logrono"``,
            ``"vps"``). None → default target.
    """
    backend = get_backend(target)
    result = backend.run_cmd(["nginx", "-t"], sudo=True, timeout=10)
    return NginxTestResult(
        ok=result.ok,
        stdout=result.stdout,
        stderr=result.stderr,
        return_code=result.return_code,
    ).model_dump()


def nginx_reload(target: str | None = None) -> dict[str, Any]:
    """Reload nginx after implicit ``nginx -t`` pass.

    If the test fails, the reload is skipped and the result reflects
    the test failure. Mutating tool — gated by allow_mutations.

    Args:
        target: nginx-ui instance to operate on. None → default target.

    Returns dict with:
      - ``ok``: True if both test and reload succeeded
      - ``test``: NginxTestResult dict
      - ``reload_attempted``: bool
      - ``reload_stdout`` / ``reload_stderr`` / ``reload_rc``: when attempted
    """
    backend = get_backend(target)
    test_res = backend.run_cmd(["nginx", "-t"], sudo=True, timeout=10)
    out: dict[str, Any] = {
        "ok": False,
        "test": NginxTestResult(
            ok=test_res.ok,
            stdout=test_res.stdout,
            stderr=test_res.stderr,
            return_code=test_res.return_code,
        ).model_dump(),
        "reload_attempted": False,
    }
    if not test_res.ok:
        return out

    reload_res = backend.run_cmd(["nginx", "-s", "reload"], sudo=True, timeout=10)
    out["reload_attempted"] = True
    out["reload_stdout"] = reload_res.stdout
    out["reload_stderr"] = reload_res.stderr
    out["reload_rc"] = reload_res.return_code
    out["ok"] = reload_res.ok
    return out
