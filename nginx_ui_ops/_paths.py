"""Path validation helpers — shared across tools.

Centralizes the "is this path under <allowed dir>" check used by
``nginx_write_file``, ``nginx_read_file``, ``nginx_test_with_diff``,
and ``cert_deploy_files``. Single source of truth so a missed
canonicalization in one tool doesn't reintroduce
[VULN-01 / VULN-09 / VULN-10] from
``docs/security/audit-2026-05-29-0455.md``.

Defense-in-depth model:

1. Reject relative paths immediately.
2. Reject any path containing ``..`` components — fail closed.
3. ``os.path.normpath`` the input to collapse extra ``/`` and
   redundant ``.`` segments.
4. Re-check that the normalized result is *equal to* the allowed
   root or *strictly under* it (``startswith(root + "/")``).
5. Return the normalized path so callers operate on a canonical form.

We deliberately do NOT call ``os.path.realpath`` here — that would
resolve symlinks on the *local* MCP host, but the path is destined
for a *remote* host where the symlinks may differ. Remote canonical
form (resolving symlinks on the target) is the backend's
responsibility if needed; the typed name-level checks above already
block the obvious traversal vectors.
"""
from __future__ import annotations

import os.path


def validate_under_dir(
    path: str,
    allowed_dir: str,
    *,
    label: str = "path",
    allow_root: bool = False,
) -> str:
    """Validate ``path`` is absolute and strictly under ``allowed_dir``.

    Returns the canonicalized form. Raises ``ValueError`` on any
    rejection — caller is expected to surface the message to the
    operator / LLM.

    Args:
        path: input path to validate (typically from a tool param).
        allowed_dir: the directory that ``path`` must be inside.
            Trailing slashes are normalized.
        label: human-readable noun used in error messages (e.g.
            ``"path"``, ``"target_path"``, ``"cert dest"``).
        allow_root: when True, accept ``path == allowed_dir`` itself.
            Default False — most callers want a file inside the dir,
            not the dir itself.

    Returns:
        Canonical form of ``path`` (``os.path.normpath``).

    Raises:
        ValueError: ``path`` is relative, contains ``..``, resolves
            outside ``allowed_dir`` after normalization, or equals
            the root when ``allow_root=False``.
    """
    if not path.startswith("/"):
        raise ValueError(f"{label} must be absolute, got {path!r}")

    # Use POSIX separators since the remote side is always POSIX
    # (nginx hosts: Linux). Splitting on "/" works correctly.
    if ".." in path.split("/"):
        raise ValueError(
            f"{label} {path!r} contains '..' (traversal not allowed)"
        )

    root = allowed_dir.rstrip("/")
    normalized = os.path.normpath(path)
    # On Windows os.path.normpath may flip separators — re-normalize
    # to POSIX for our equality check (the remote target is POSIX).
    normalized = normalized.replace("\\", "/")

    if normalized == root:
        if allow_root:
            return normalized
        raise ValueError(
            f"{label} {normalized!r} must be under {root!r}, not the dir itself"
        )
    if normalized.startswith(root + "/"):
        return normalized
    raise ValueError(
        f"{label} {normalized!r} not under {root!r} after normalization"
    )


def validate_under_any(path: str, allowed_dirs: tuple[str, ...], *, label: str = "path") -> str:
    """Like :func:`validate_under_dir` but accepts multiple allowed roots.

    Returns the canonical form on first match. Raises ``ValueError``
    if no root matches.

    Used by cert deploy paths where multiple legitimate locations
    exist (``/etc/nginx/``, ``/usr/local/etc/nginx-ui/``, etc.).
    """
    if not path.startswith("/"):
        raise ValueError(f"{label} must be absolute, got {path!r}")
    if ".." in path.split("/"):
        raise ValueError(
            f"{label} {path!r} contains '..' (traversal not allowed)"
        )

    normalized = os.path.normpath(path).replace("\\", "/")
    for root in allowed_dirs:
        r = root.rstrip("/")
        if normalized == r or normalized.startswith(r + "/"):
            return normalized
    raise ValueError(
        f"{label} {normalized!r} not under any allowed dir: "
        f"{allowed_dirs}"
    )
