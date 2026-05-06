"""nginx control tools: ``nginx -t`` and ``nginx -s reload``.

``nginx_reload`` always runs ``nginx -t`` first as a safety net —
never reload with a broken config (would 500 every request until
fixed).
"""
from __future__ import annotations

from typing import Any

from ..backends import get_backend
from ..models import NginxTestResult


def nginx_test() -> dict[str, Any]:
    """Run ``nginx -t`` to validate config syntax. Read-only."""
    backend = get_backend()
    result = backend.run_cmd(["nginx", "-t"], sudo=True, timeout=10)
    return NginxTestResult(
        ok=result.ok,
        stdout=result.stdout,
        stderr=result.stderr,
        return_code=result.return_code,
    ).model_dump()


def nginx_reload() -> dict[str, Any]:
    """Reload nginx after implicit ``nginx -t`` pass.

    If the test fails, the reload is skipped and the result reflects
    the test failure. Mutating tool — gated by allow_mutations.

    Returns dict with:
      - ``ok``: True if both test and reload succeeded
      - ``test``: NginxTestResult dict
      - ``reload_attempted``: bool
      - ``reload_stdout`` / ``reload_stderr`` / ``reload_rc``: when attempted
    """
    backend = get_backend()
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
