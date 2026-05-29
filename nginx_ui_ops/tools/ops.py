"""Mutation/ops tools for nginx (gated by allow_mutations).

4 tools that touch the running service or its config files:

  nginx_write_file    atomic write under /etc/nginx/ + implicit nginx -t + rollback
  nginx_full_restart  systemctl restart nginx (drops conns; use reload when possible)
  nginx_reopen_logs   nginx -s reopen (after logrotate, etc.)
  nginx_quit          nginx -s quit (graceful shutdown — operator must start again)

All mutating — registered ONLY when NGINXUI_ALLOW_MUTATIONS=true. The
mutation gate lives in server.py, not here.

Design:
- nginx_write_file is the "edit a config" primitive. It is paired with
  the read-only nginx_test_with_diff (in diagnostics.py) — that tool
  validates a proposed change WITHOUT touching prod, this one commits
  it with a safety net.
- The safety net is: backup current file → write new → nginx -t →
  rollback if test fails. Never leave the system in a broken state.
- backup_path uses a timestamp suffix (e.g. ``foo.conf.bak-20260506-181500``)
  so multiple writes don't clobber each other. The operator can prune
  old backups manually.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from .._paths import validate_under_dir
from ..backends import BackendError, get_backend
from ..models import NginxControlResult, NginxFileWriteResult

log = logging.getLogger(__name__)

DEFAULT_CONFIG_DIR = "/etc/nginx"


def _config_dir() -> str:
    return os.environ.get("NGINXUI_CONFIG_DIR", "").strip() or DEFAULT_CONFIG_DIR


def _backup_suffix() -> str:
    """Generate a timestamped suffix for backup files.

    Format: ``.bak-YYYYMMDD-HHMMSS`` (UTC). Stable across calls within
    the same second, but realistic ops are seconds apart.
    """
    return ".bak-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _read_remote_mode(backend, path: str) -> int:
    """Best-effort read of POSIX mode of a remote file. Returns 0o644
    on any failure (safe default for nginx config files).

    [VULN-14] mitigation: backups inherit the source file's mode so
    secrets in 0600 includes don't leak via 0644 backups.
    """
    try:
        res = backend.run_cmd(["stat", "-c", "%a", path], sudo=True, timeout=5)
    except BackendError:
        return 0o644
    if not res.ok or not res.stdout.strip():
        return 0o644
    try:
        return int(res.stdout.strip(), 8)
    except ValueError:
        return 0o644


# ---------------------------------------------------------------------------
# nginx_write_file
# ---------------------------------------------------------------------------

def nginx_write_file(path: str, content: str, target: str | None = None) -> dict[str, Any]:
    """Atomic write to a config file under /etc/nginx/ with rollback on test failure.

    Workflow:
      1. Validate ``path`` is absolute and under NGINXUI_CONFIG_DIR.
      2. Read current content (if any) → back up to ``<path>.bak-<ts>``.
      3. Push new content (backend strips CRLF, applies chmod 0644).
      4. Run ``nginx -t``. If it fails → restore backup, return
         rolled_back=True with the test stderr for the LLM to surface
         to the operator.
      5. If it passes → leave the backup in place (operator prunes
         later) and return ok=True.

    The caller is expected to have already validated the *proposed*
    content via ``nginx_test_with_diff`` — this tool does NOT
    pre-validate. That separation lets you commit a change you've
    already reviewed without re-running the staging dance.

    Args:
        path: absolute path under /etc/nginx/.
        content: full new file content as text.

    Returns NginxFileWriteResult dict.

    Raises:
        ValueError: path validation failed (rejected pre-flight).
        BackendError: file I/O failed unrecoverably.
    """
    # [VULN-01] mitigation — canonicalize + reject '..' BEFORE any I/O.
    path = validate_under_dir(path, _config_dir(), label="path")

    backend = get_backend(target)
    encoded = content.encode("utf-8")

    # Step 1: try to read current content for backup. Missing is OK
    # (this is a new file).
    backup_path: str | None = None
    prior_content: bytes | None = None
    prior_mode: int = 0o644
    try:
        prior_content = backend.read_file(path, sudo=True)
    except BackendError:
        prior_content = None

    if prior_content is not None:
        # [VULN-14] preserve the original mode so 0600 includes don't
        # leak via a 0644 backup.
        prior_mode = _read_remote_mode(backend, path)
        backup_path = path + _backup_suffix()
        try:
            backend.push_file(prior_content, backup_path, mode=prior_mode, sudo=True)
        except BackendError as e:
            # If we can't back up, abort BEFORE touching the live file.
            raise BackendError(
                f"refusing to write {path}: backup to {backup_path} failed: {e}"
            ) from e

    # Step 2: push new content (preserve original mode if known,
    # otherwise default 0644 for new config files).
    write_mode = prior_mode if prior_content is not None else 0o644
    try:
        backend.push_file(encoded, path, mode=write_mode, sudo=True)
    except BackendError as e:
        raise BackendError(f"failed to write {path}: {e}") from e

    # Step 3: validate via nginx -t.
    test_res = backend.run_cmd(["nginx", "-t"], sudo=True, timeout=10)
    if test_res.ok:
        return NginxFileWriteResult(
            ok=True,
            path=path,
            bytes_written=len(encoded),
            backup_path=backup_path,
            nginx_test_passed=True,
            rolled_back=False,
            test_stderr=test_res.stderr[:1000],
        ).model_dump()

    # Step 4: rollback. If we have a backup, restore it; otherwise
    # leave the broken file (the operator is going to fix it manually).
    rolled_back = False
    if backup_path is not None and prior_content is not None:
        try:
            backend.push_file(prior_content, path, mode=prior_mode, sudo=True)
            rolled_back = True
        except BackendError as e:
            log.error("rollback push failed for %s: %s", path, e)
    else:
        # New file with no backup — remove it so we don't leave a
        # broken include sitting around.
        try:
            backend.run_cmd(["rm", "-f", path], sudo=True, timeout=5)
            rolled_back = True
        except BackendError as e:
            log.error("rollback rm failed for %s: %s", path, e)

    return NginxFileWriteResult(
        ok=False,
        path=path,
        bytes_written=len(encoded),
        backup_path=backup_path,
        nginx_test_passed=False,
        rolled_back=rolled_back,
        test_stderr=test_res.stderr[:1000],
    ).model_dump()


# ---------------------------------------------------------------------------
# nginx_full_restart
# ---------------------------------------------------------------------------

def nginx_full_restart(target: str | None = None) -> dict[str, Any]:
    """Full ``systemctl restart nginx`` — drops connections momentarily.

    Use ``nginx_reload`` (graceful) when possible; reach for this only
    when the running master is in a wedged state, you've changed
    something that requires a fresh process (e.g. a binary upgrade,
    a module load), or the SSL/TLS context needs to be torn down hard.

    Includes an implicit ``nginx -t`` first — never restart with a
    broken config. If the test fails, the restart is skipped.

    Returns NginxControlResult dict.
    """
    backend = get_backend(target)
    # Safety: validate before restart.
    test_res = backend.run_cmd(["nginx", "-t"], sudo=True, timeout=10)
    if not test_res.ok:
        return NginxControlResult(
            action="restart",
            ok=False,
            return_code=test_res.return_code,
            stdout=test_res.stdout[:1000],
            stderr=test_res.stderr[:1000],
            note="nginx -t failed; restart skipped to avoid leaving service down.",
        ).model_dump()

    res = backend.run_cmd(
        ["systemctl", "restart", "nginx"],
        sudo=True, timeout=20,
    )
    return NginxControlResult(
        action="restart",
        ok=res.ok,
        return_code=res.return_code,
        stdout=res.stdout[:1000],
        stderr=res.stderr[:1000],
        note=(
            "Connections dropped during restart. Use nginx_reload for graceful changes."
            if res.ok
            else "systemctl restart returned non-zero. Inspect with nginx_status / nginx_logs."
        ),
    ).model_dump()


# ---------------------------------------------------------------------------
# nginx_reopen_logs
# ---------------------------------------------------------------------------

def nginx_reopen_logs(target: str | None = None) -> dict[str, Any]:
    """``nginx -s reopen`` — reopen log files without dropping connections.

    Sends SIGUSR1 to the master. Useful after manual logrotate, after
    moving log files, or if a log volume was remounted. Does NOT
    re-read the config — that's ``nginx_reload``.

    Returns NginxControlResult dict.
    """
    backend = get_backend(target)
    res = backend.run_cmd(["nginx", "-s", "reopen"], sudo=True, timeout=10)
    return NginxControlResult(
        action="reopen_logs",
        ok=res.ok,
        return_code=res.return_code,
        stdout=res.stdout[:1000],
        stderr=res.stderr[:1000],
        note=(
            "Master sent SIGUSR1; workers reopen file descriptors on next request."
            if res.ok
            else "reopen failed. Inspect with nginx_status."
        ),
    ).model_dump()


# ---------------------------------------------------------------------------
# nginx_quit
# ---------------------------------------------------------------------------

def nginx_quit(target: str | None = None) -> dict[str, Any]:
    """``nginx -s quit`` — graceful shutdown. Operator must start again.

    Sends SIGQUIT to the master. Existing connections finish, no new
    ones accepted, then the process exits. After this, nginx is NOT
    running — the operator must ``systemctl start nginx`` (or use a
    future ``nginx_start`` tool — not in this version) to bring it
    back up.

    Use case: maintenance window, planned shutdown, debugging a wedged
    master that won't accept ``nginx -s reload`` cleanly.

    Returns NginxControlResult dict with a clear note that nginx is
    now stopped.
    """
    backend = get_backend(target)
    res = backend.run_cmd(["nginx", "-s", "quit"], sudo=True, timeout=15)
    return NginxControlResult(
        action="quit",
        ok=res.ok,
        return_code=res.return_code,
        stdout=res.stdout[:1000],
        stderr=res.stderr[:1000],
        note=(
            "nginx is now stopped. Operator must start it manually "
            "(systemctl start nginx) to restore service."
            if res.ok
            else "quit signal failed. Service may still be running; check nginx_status."
        ),
    ).model_dump()
