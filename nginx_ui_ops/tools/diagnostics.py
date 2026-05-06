"""Diagnostic + introspection tools for nginx (read-only).

8 tools that surface the runtime + filesystem state of nginx without
mutating anything:

  nginx_status            systemctl + workers + uptime
  nginx_dump_config       nginx -T (effective merged config)
  nginx_logs              snapshot tail + grep of any nginx log file
  nginx_compiled_with     nginx -V parsed (version, TLS, modules, flags)
  nginx_active_conns      stub_status if mounted
  nginx_pending_changes   files modified since service start
  nginx_test_with_diff    validate a proposed change without touching prod
  nginx_read_file         raw read of any /etc/nginx/** file

All read-only — registered unconditionally regardless of the
allow_mutations gate.
"""
from __future__ import annotations

import difflib
import logging
import os
import re
import secrets as _secrets
import shlex
from datetime import datetime, timezone
from typing import Any

from ..backends import BackendError, get_backend
from ..models import (
    NginxActiveConns,
    NginxCompiledInfo,
    NginxFileContent,
    NginxLogResult,
    NginxPendingChanges,
    NginxStatusResult,
    NginxTestWithDiffResult,
)

log = logging.getLogger(__name__)

# Default log location for upstream nginx packages on Linux. Override via
# NGINXUI_LOG_DIR.
DEFAULT_LOG_DIR = "/var/log/nginx"

# Where nginx config files live. Override via NGINXUI_CONFIG_DIR.
DEFAULT_CONFIG_DIR = "/etc/nginx"

# Cap on file content read for nginx_read_file — protects against
# accidental binary/huge file reads.
READ_FILE_CAP_BYTES = 256 * 1024  # 256 KB

# Cap on log lines returned in a single snapshot — protects context
# window. Operator can request up to this many; default is much lower.
MAX_LOG_LINES = 5000


def _log_dir() -> str:
    return os.environ.get("NGINXUI_LOG_DIR", "").strip() or DEFAULT_LOG_DIR


def _config_dir() -> str:
    return os.environ.get("NGINXUI_CONFIG_DIR", "").strip() or DEFAULT_CONFIG_DIR


def _parse_systemd_timestamp(stamp: str) -> datetime | None:
    """Parse systemd's ActiveEnterTimestamp into a timezone-aware UTC datetime.

    Format examples:
      'Thu 2026-05-04 10:00:00 UTC'
      'Thu 2026-05-04 12:00:00 CEST'
      'Thu 2026-05-04 10:00:00'

    Python's ``strptime`` ``%Z`` is fragile (only matches a small set
    of zone abbreviations and even then unreliably). Strip a trailing
    word that looks like a TZ abbreviation manually, then parse the
    rest. Result is normalized to UTC by assuming the original was UTC
    when the abbrev is UTC; for non-UTC abbrevs we do best-effort by
    using zoneinfo where the abbreviation maps unambiguously to a
    canonical zone (rare). Default: assume UTC.
    """
    s = stamp.strip()
    parts = s.split()
    tz_abbrev: str | None = None
    if len(parts) >= 1 and parts[-1].isalpha() and parts[-1].isupper():
        tz_abbrev = parts[-1]
        s = " ".join(parts[:-1])

    for fmt in ("%a %Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            # Naive — attach tz. UTC is the safest default; non-UTC
            # abbreviations are inherently ambiguous (CST = US Central or
            # China Standard?). For our use case (uptime calculation),
            # off-by-a-few-hours is acceptable; the operator gets the
            # raw systemctl text alongside.
            if tz_abbrev == "UTC" or tz_abbrev is None:
                return dt.replace(tzinfo=timezone.utc)
            # Best-effort: leave as UTC; at worst uptime is off by the
            # operator's timezone offset, fine for ballpark.
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# nginx_status
# ---------------------------------------------------------------------------

_PID_RE = re.compile(r"Main PID:\s+(\d+)")
_ACTIVE_RE = re.compile(r"Active:\s+(\w+)\s+\((\w+)\)")


def nginx_status() -> dict[str, Any]:
    """systemctl status nginx + worker count + uptime.

    Returns NginxStatusResult dict. All best-effort: if systemctl fails
    or output format differs, fields default to None and the raw output
    is preserved for the caller to inspect.
    """
    backend = get_backend()
    res = backend.run_cmd(["systemctl", "status", "nginx"], timeout=10)

    # systemctl status returns 3 when service is dead; output is still
    # informative. Parse regardless of exit code.
    raw = res.stdout + ("\n" + res.stderr if res.stderr else "")

    active_match = _ACTIVE_RE.search(raw)
    pid_match = _PID_RE.search(raw)

    active = False
    sub_state: str | None = None
    if active_match:
        sub_state = active_match.group(2)
        active = active_match.group(1).lower() == "active"

    main_pid: int | None = None
    if pid_match:
        try:
            main_pid = int(pid_match.group(1))
        except ValueError:
            pass

    # Worker count via ps. The master nginx process forks workers under
    # the same parent — count children.
    worker_count: int | None = None
    if main_pid:
        ps = backend.run_cmd(
            ["ps", "--no-headers", "-o", "pid", "--ppid", str(main_pid)],
            timeout=5,
        )
        if ps.ok:
            worker_count = sum(1 for line in ps.stdout.splitlines() if line.strip())

    # Started_at via systemd's ActiveEnterTimestamp (more reliable than
    # parsing free-form "since" line in `status` output).
    started_at: datetime | None = None
    uptime_seconds: int | None = None
    show = backend.run_cmd(
        ["systemctl", "show", "nginx", "--property=ActiveEnterTimestamp"],
        timeout=5,
    )
    if show.ok:
        for line in show.stdout.splitlines():
            if line.startswith("ActiveEnterTimestamp="):
                stamp = line.split("=", 1)[1].strip()
                # Format: "Thu 2026-05-04 10:00:00 UTC" or empty if never.
                if stamp and stamp != "0":
                    started_at = _parse_systemd_timestamp(stamp)
    if started_at is not None:
        uptime_seconds = int((datetime.now(timezone.utc) - started_at).total_seconds())

    return NginxStatusResult(
        active=active,
        sub_state=sub_state,
        main_pid=main_pid,
        started_at=started_at,
        uptime_seconds=uptime_seconds,
        worker_count=worker_count,
        raw_systemctl=raw[:2000],  # cap to avoid context blowup
    ).model_dump()


# ---------------------------------------------------------------------------
# nginx_dump_config
# ---------------------------------------------------------------------------

def nginx_dump_config() -> dict[str, Any]:
    """nginx -T — full effective merged configuration.

    Returns dict with raw output + a synthetic ``ok`` flag. nginx -T
    runs the syntax check internally (same as -t) and dumps every
    config file the master would load. Useful for "what's actually
    going to be served" without having to walk include directives.
    """
    backend = get_backend()
    res = backend.run_cmd(["nginx", "-T"], sudo=True, timeout=15)
    return {
        "ok": res.ok,
        "return_code": res.return_code,
        "config": res.stdout,
        "stderr": res.stderr,
        "size_bytes": len(res.stdout),
    }


# ---------------------------------------------------------------------------
# nginx_logs
# ---------------------------------------------------------------------------

def nginx_logs(
    file: str = "error.log",
    lines: int = 100,
    grep: str = "",
) -> dict[str, Any]:
    """Snapshot tail of an nginx log file with optional grep filter.

    Args:
        file: filename relative to NGINXUI_LOG_DIR (default /var/log/nginx/),
              OR absolute path. Common: 'error.log', 'access.log'.
        lines: max lines to return (capped at MAX_LOG_LINES=5000).
        grep: case-insensitive regex filter applied AFTER tail.

    Returns NginxLogResult dict.
    """
    if not file or "\x00" in file:
        raise ValueError(f"invalid log file: {file!r}")
    lines = max(1, min(int(lines), MAX_LOG_LINES))

    if file.startswith("/"):
        target = file
    else:
        # Reject path traversal in relative names.
        if ".." in file or "/" in file:
            raise ValueError(f"file must be a flat name, got {file!r}")
        target = f"{_log_dir().rstrip('/')}/{file}"

    backend = get_backend()
    if grep:
        # tail -n N <file> | grep -i -E '<pattern>'
        # Use shlex.quote on grep to avoid command injection — backend
        # may run via shell on some transports.
        cmd = [
            "sh", "-c",
            f"tail -n {lines} {shlex.quote(target)} | grep -iE {shlex.quote(grep)} || true",
        ]
    else:
        cmd = ["tail", "-n", str(lines), target]

    res = backend.run_cmd(cmd, sudo=True, timeout=15)
    if not res.ok and not grep:
        # tail-only failure (e.g. file not found) → bubble up.
        raise BackendError(
            f"reading {target}: rc={res.return_code} stderr={res.stderr[:200]}"
        )

    content_lines = res.stdout.splitlines()
    return NginxLogResult(
        file=target,
        lines_returned=len(content_lines),
        lines_requested=lines,
        grep_filter=grep or None,
        content=res.stdout,
        truncated=len(content_lines) >= lines,
    ).model_dump()


# ---------------------------------------------------------------------------
# nginx_compiled_with
# ---------------------------------------------------------------------------

def nginx_compiled_with() -> dict[str, Any]:
    """nginx -V parsed: version, TLS lib, prefix, configure flags.

    nginx -V writes to stderr (not stdout — historic quirk). The
    backend captures both, we read stderr.
    """
    backend = get_backend()
    res = backend.run_cmd(["nginx", "-V"], timeout=10)
    raw = res.stderr or res.stdout

    version: str | None = None
    built_with: str | None = None
    tls_library: str | None = None
    prefix: str | None = None
    flags: list[str] = []

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("nginx version:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("built by"):
            built_with = line.split("by", 1)[1].strip()
        elif line.startswith("built with"):
            tls_library = line.split("with", 1)[1].strip()
        elif line.startswith("configure arguments:"):
            args_str = line.split(":", 1)[1].strip()
            flags = [f.strip() for f in args_str.split() if f.strip()]
            for f in flags:
                if f.startswith("--prefix="):
                    prefix = f.split("=", 1)[1]

    return NginxCompiledInfo(
        version=version or "unknown",
        built_with=built_with,
        tls_library=tls_library,
        prefix=prefix,
        configure_flags=flags,
        raw_output=raw[:3000],
    ).model_dump()


# ---------------------------------------------------------------------------
# nginx_active_conns
# ---------------------------------------------------------------------------

# stub_status output:
#   Active connections: N
#   server accepts handled requests
#    A B C
#   Reading: N Writing: N Waiting: N
_STUB_ACTIVE_RE = re.compile(r"Active connections:\s*(\d+)")
_STUB_TOTALS_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$", re.MULTILINE)
_STUB_RWW_RE = re.compile(r"Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)")


def nginx_active_conns() -> dict[str, Any]:
    """Runtime stats from stub_status module.

    Tries common endpoints in order:
      http://127.0.0.1/nginx_status
      http://127.0.0.1/stub_status
      http://127.0.0.1/status

    If none reachable, returns enabled=False with hint how to mount
    a stub_status block. Never raises.
    """
    backend = get_backend()
    candidates = [
        "http://127.0.0.1/nginx_status",
        "http://127.0.0.1/stub_status",
        "http://127.0.0.1/status",
    ]

    for endpoint in candidates:
        res = backend.run_cmd(
            ["curl", "-sS", "-m", "5", endpoint],
            timeout=10,
        )
        if not res.ok or not res.stdout.strip():
            continue
        body = res.stdout
        m_active = _STUB_ACTIVE_RE.search(body)
        if not m_active:
            continue  # Not stub_status format; some other 200 response.

        m_totals = _STUB_TOTALS_RE.search(body)
        m_rww = _STUB_RWW_RE.search(body)
        return NginxActiveConns(
            enabled=True,
            active_connections=int(m_active.group(1)),
            accepts=int(m_totals.group(1)) if m_totals else None,
            handled=int(m_totals.group(2)) if m_totals else None,
            requests=int(m_totals.group(3)) if m_totals else None,
            reading=int(m_rww.group(1)) if m_rww else None,
            writing=int(m_rww.group(2)) if m_rww else None,
            waiting=int(m_rww.group(3)) if m_rww else None,
            endpoint=endpoint,
        ).model_dump()

    return NginxActiveConns(
        enabled=False,
        note=(
            "stub_status not reachable on common endpoints "
            "(/nginx_status, /stub_status, /status). To enable, add a block "
            "like:\n  location = /nginx_status {\n    stub_status;\n    "
            "allow 127.0.0.1;\n    deny all;\n  }\nin a server{} that listens "
            "on localhost, then nginx_reload."
        ),
    ).model_dump()


# ---------------------------------------------------------------------------
# nginx_pending_changes
# ---------------------------------------------------------------------------

def nginx_pending_changes() -> dict[str, Any]:
    """Files under config dir with mtime newer than nginx service start.

    Pragmatic "is there anything pending a reload?" — compares mtime of
    each file under NGINXUI_CONFIG_DIR (recursive) against the service's
    ActiveEnterTimestamp. Files newer than that are flagged.

    Limitations:
    - mtime can lag if files are merely re-saved with no content change.
    - If the service hasn't started, returns has_pending=False (nothing
      to reload yet).
    """
    backend = get_backend()
    # Get service start time (single systemctl show call).
    show = backend.run_cmd(
        ["systemctl", "show", "nginx", "--property=ActiveEnterTimestamp"],
        timeout=5,
    )
    started_at: datetime | None = None
    if show.ok:
        for line in show.stdout.splitlines():
            if line.startswith("ActiveEnterTimestamp="):
                stamp = line.split("=", 1)[1].strip()
                if stamp and stamp != "0":
                    started_at = _parse_systemd_timestamp(stamp)

    if started_at is None:
        return NginxPendingChanges(
            service_started_at=None,
            pending_files=[],
            has_pending=False,
            note="nginx service not active or start time unparseable.",
        ).model_dump()

    # Find files with mtime newer than start. -newermt accepts ISO-ish.
    started_iso = started_at.strftime("%Y-%m-%d %H:%M:%S")
    config_dir = _config_dir()
    res = backend.run_cmd(
        [
            "find", config_dir, "-type", "f",
            "-newermt", started_iso,
            "-not", "-path", "*/.*",  # skip dot-dirs / dot-files
        ],
        sudo=True, timeout=15,
    )
    if not res.ok:
        # find may fail with permissions; surface as no-pending + note.
        return NginxPendingChanges(
            service_started_at=started_at,
            pending_files=[],
            has_pending=False,
            note=f"find failed: {res.stderr[:200]}",
        ).model_dump()

    files = [line.strip() for line in res.stdout.splitlines() if line.strip()]
    return NginxPendingChanges(
        service_started_at=started_at,
        pending_files=files,
        has_pending=len(files) > 0,
        note=(
            f"{len(files)} file(s) under {config_dir} have mtime > service start. "
            "Run nginx_test() then nginx_reload() to apply."
            if files else None
        ),
    ).model_dump()


# ---------------------------------------------------------------------------
# nginx_test_with_diff
# ---------------------------------------------------------------------------

def nginx_test_with_diff(target_path: str, proposed_content: str) -> dict[str, Any]:
    """Validate a proposed change to a config file WITHOUT touching prod.

    Strategy:
      1. Stage the proposed content to a temp dir on the host.
      2. Build a parallel config layout where target_path is replaced
         by the staged file (other files symlink to the originals).
      3. Run `nginx -t -p <staging-prefix>` against that layout.
      4. Return ok/error + unified diff vs the current file content.

    The current ``/etc/nginx/`` and running nginx are untouched. This
    is the safety net: validate first, then optionally use
    ``nginx_write_file`` to commit.

    Args:
        target_path: absolute path the file would have in production
            (e.g. /etc/nginx/sites-available/foo.conf).
        proposed_content: full new file content as string.

    Returns NginxTestWithDiffResult dict.
    """
    if not target_path.startswith("/"):
        raise ValueError(f"target_path must be absolute, got {target_path!r}")
    backend = get_backend()
    config_dir = _config_dir()
    if not target_path.startswith(config_dir.rstrip("/") + "/"):
        raise ValueError(
            f"target_path {target_path!r} must be under {config_dir!r}"
        )

    # Read current content for diff (best-effort).
    current_content = ""
    file_exists = True
    try:
        current_bytes = backend.read_file(target_path, sudo=True)
        current_content = current_bytes.decode("utf-8", errors="replace")
    except BackendError:
        file_exists = False

    # Build staging dir. We mirror config_dir tree using cp -al
    # (hardlinks — fast, safe to override one file).
    staging = f"/tmp/nginx-ui-ops-stage-{_secrets.token_hex(8)}"
    setup = backend.run_cmd(
        [
            "sh", "-c",
            f"rm -rf {shlex.quote(staging)} && "
            f"cp -al {shlex.quote(config_dir)} {shlex.quote(staging)}",
        ],
        sudo=True, timeout=30,
    )
    if not setup.ok:
        # cp -al may not be available on all FS (e.g. FUSE). Fall back
        # to plain cp -r.
        setup = backend.run_cmd(
            [
                "sh", "-c",
                f"rm -rf {shlex.quote(staging)} && "
                f"cp -r {shlex.quote(config_dir)} {shlex.quote(staging)}",
            ],
            sudo=True, timeout=60,
        )
        if not setup.ok:
            raise BackendError(
                f"failed to stage config: {setup.stderr[:200]}"
            )

    # Compute path inside staging.
    relative = target_path[len(config_dir.rstrip("/")) + 1 :]
    staged_target = f"{staging}/{relative}"

    # Push proposed content (this also strips CRLF, applies chmod).
    try:
        backend.push_file(
            proposed_content.encode("utf-8"),
            staged_target,
            mode=0o644,
            sudo=True,
        )
    except BackendError as e:
        # Cleanup before re-raising.
        backend.run_cmd(["rm", "-rf", staging], sudo=True, timeout=10)
        raise BackendError(f"failed to stage proposed content: {e}") from e

    # Run nginx -t against the staged prefix.
    test_res = backend.run_cmd(
        ["nginx", "-t", "-p", staging, "-c", f"{staging}/nginx.conf"],
        sudo=True, timeout=15,
    )

    # Cleanup.
    backend.run_cmd(["rm", "-rf", staging], sudo=True, timeout=10)

    # Compute diff (None if file didn't exist before).
    diff_text: str | None = None
    if file_exists:
        diff_lines = list(difflib.unified_diff(
            current_content.splitlines(keepends=True),
            proposed_content.splitlines(keepends=True),
            fromfile=f"current:{target_path}",
            tofile=f"proposed:{target_path}",
            lineterm="",
        ))
        diff_text = "".join(diff_lines)
    else:
        diff_text = f"<file does not exist yet at {target_path}>\n+ {len(proposed_content)} bytes proposed"

    return NginxTestWithDiffResult(
        ok=test_res.ok,
        target_path=target_path,
        proposed_content_size=len(proposed_content),
        test_stdout=test_res.stdout[:2000],
        test_stderr=test_res.stderr[:2000],
        diff=diff_text,
    ).model_dump()


# ---------------------------------------------------------------------------
# nginx_read_file
# ---------------------------------------------------------------------------

def nginx_read_file(path: str) -> dict[str, Any]:
    """Read raw content of a file under the nginx config dir.

    Read-only. Refuses paths outside NGINXUI_CONFIG_DIR (default /etc/nginx)
    to avoid being a generic "read any file" tool. Truncates content at
    READ_FILE_CAP_BYTES (256 KB default) — enough for any realistic
    nginx config; if you hit the cap, your config has bigger problems.
    """
    if not path.startswith("/"):
        raise ValueError(f"path must be absolute, got {path!r}")
    config_dir = _config_dir()
    if not path.startswith(config_dir.rstrip("/") + "/") and path != config_dir.rstrip("/"):
        raise ValueError(
            f"path {path!r} must be under {config_dir!r} (refusing to read arbitrary files)"
        )

    backend = get_backend()
    raw = backend.read_file(path, sudo=True)
    truncated = False
    if len(raw) > READ_FILE_CAP_BYTES:
        raw = raw[:READ_FILE_CAP_BYTES]
        truncated = True

    # mtime via stat (best-effort).
    mtime: datetime | None = None
    stat_res = backend.run_cmd(
        ["stat", "-c", "%Y", path], sudo=True, timeout=5,
    )
    if stat_res.ok and stat_res.stdout.strip():
        try:
            mtime = datetime.fromtimestamp(
                int(stat_res.stdout.strip()), tz=timezone.utc,
            )
        except ValueError:
            pass

    return NginxFileContent(
        path=path,
        size_bytes=len(raw),
        content=raw.decode("utf-8", errors="replace"),
        mtime=mtime,
        truncated=truncated,
    ).model_dump()
