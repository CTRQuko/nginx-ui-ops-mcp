"""Cert management tools.

Read-only:
- ``cert_list``    — SELECT from nginx-ui's ``certs`` SQLite table
- ``cert_get``     — one cert + on-disk + parsed status

Mutating (gated by ``allow_mutations`` in plugin.toml):
- ``cert_domains_update``  — UPDATE certs.domains + restart nginx-ui
- ``cert_issue``           — acme.sh, idempotent unless force=True
- ``cert_deploy_files``    — push fullchain + key to paths from DB
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from .._paths import validate_under_any
from ..backends import BackendError, get_backend
from ..models import (
    CertDeployResult,
    CertDetail,
    CertDomainsUpdateResult,
    CertInfo,
    CertIssueResult,
    CertOnDiskStatus,
)
from ..x509_parse import parse_cert_pem

log = logging.getLogger(__name__)

# Default DB path used by upstream nginx-ui. Override via NGINXUI_DB_PATH.
DEFAULT_DB_PATH = "/usr/local/etc/nginx-ui/database.db"

# Default acme.sh home. Override via NGINXUI_ACME_HOME.
DEFAULT_ACME_HOME = "/root/.acme.sh"

# Lock directory on the nginx-ui host to prevent races with the cron
# of acme.sh when this plugin issues a new cert. [VULN-05] mitigation
# — using a *directory* (created with mkdir, POSIX-atomic) instead of
# a touched file makes ``test -e`` + ``touch`` TOCTOU impossible.
ACME_LOCK_PATH = "/tmp/nginx-ui-ops-acme.lock.d"

# Default allowlist of directories where cert files may be deployed.
# [VULN-03] mitigation — paths read from the nginx-ui DB are validated
# against this allowlist before push. Operator overrides via
# NGINXUI_CERT_DEPLOY_DIRS (comma-separated absolute paths).
DEFAULT_CERT_DEPLOY_DIRS: tuple[str, ...] = (
    "/etc/nginx/",
    "/etc/ssl/",
    "/usr/local/etc/nginx-ui/",
    "/var/lib/nginx-ui/",
)

# How long days_remaining must be for cert_issue to skip re-issuance.
DEFAULT_RENEW_THRESHOLD_DAYS = 30


def _cert_deploy_dirs() -> tuple[str, ...]:
    """Return the allowlist of cert deploy directories.

    Operator override: ``NGINXUI_CERT_DEPLOY_DIRS=/a/,/b/,...``
    (comma-separated absolute paths). Trailing slashes optional.
    """
    raw = os.environ.get("NGINXUI_CERT_DEPLOY_DIRS", "").strip()
    if not raw:
        return DEFAULT_CERT_DEPLOY_DIRS
    parsed = tuple(p.strip() for p in raw.split(",") if p.strip())
    return parsed or DEFAULT_CERT_DEPLOY_DIRS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _db_path() -> str:
    return os.environ.get("NGINXUI_DB_PATH", "").strip() or DEFAULT_DB_PATH


def _acme_home() -> str:
    return os.environ.get("NGINXUI_ACME_HOME", "").strip() or DEFAULT_ACME_HOME


def _renew_threshold_days() -> int:
    raw = os.environ.get("NGINXUI_RENEW_THRESHOLD_DAYS", "").strip()
    if not raw:
        return DEFAULT_RENEW_THRESHOLD_DAYS
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_RENEW_THRESHOLD_DAYS


def _normalize_cert_row(row: dict[str, Any]) -> CertInfo:
    """Convert a sqlite3 row dict to CertInfo.

    nginx-ui stores ``domains`` as a JSON string. SANs become a list.
    Boolean-ish fields stored as 0/1. ``deleted_at`` not None means
    deleted.
    """
    raw_domains = row.get("domains") or "[]"
    if isinstance(raw_domains, str):
        try:
            domains = json.loads(raw_domains)
            if not isinstance(domains, list):
                domains = []
        except json.JSONDecodeError:
            domains = []
    else:
        domains = list(raw_domains) if raw_domains else []

    return CertInfo(
        id=int(row["id"]),
        name=str(row.get("name") or ""),
        domains=[str(d) for d in domains],
        ssl_certificate_path=str(row.get("ssl_certificate_path") or ""),
        ssl_certificate_key_path=str(row.get("ssl_certificate_key_path") or ""),
        auto_cert=bool(row.get("auto_cert")),
        challenge_method=row.get("challenge_method") or None,
        dns_credential_id=(
            int(row["dns_credential_id"])
            if row.get("dns_credential_id") is not None
            else None
        ),
        key_type=row.get("key_type") or None,
        deleted=row.get("deleted_at") is not None,
    )


# ---------------------------------------------------------------------------
# Read-only tools
# ---------------------------------------------------------------------------

def cert_list(deleted: bool = False, target: str | None = None) -> list[dict[str, Any]]:
    """List certs from nginx-ui's ``certs`` SQLite table."""
    backend = get_backend(target)
    where = "" if deleted else " WHERE deleted_at IS NULL"
    sql = (
        f"SELECT id, name, domains, ssl_certificate_path, "
        f"ssl_certificate_key_path, auto_cert, challenge_method, "
        f"dns_credential_id, key_type, deleted_at "
        f"FROM certs{where}"
    )
    rows = backend.query_db(_db_path(), sql)
    return [_normalize_cert_row(r).model_dump() for r in rows]


def cert_get(cert_id: int, target: str | None = None) -> dict[str, Any]:
    """Detail of one cert: DB row + on-disk + parsed x509."""
    backend = get_backend(target)
    rows = backend.query_db(
        _db_path(),
        "SELECT id, name, domains, ssl_certificate_path, "
        "ssl_certificate_key_path, auto_cert, challenge_method, "
        "dns_credential_id, key_type, deleted_at "
        "FROM certs WHERE id=?",
        params=(int(cert_id),),
    )
    if not rows:
        raise ValueError(f"cert {cert_id} not found")
    info = _normalize_cert_row(rows[0])
    on_disk = _read_on_disk_status(
        backend, info.ssl_certificate_path, info.ssl_certificate_key_path,
    )
    return CertDetail(db=info, on_disk=on_disk).model_dump()


def _read_on_disk_status(
    backend: Any, fullchain_path: str, key_path: str,
) -> CertOnDiskStatus:
    """Best-effort on-disk inspection — partial info is fine, never raises."""
    fullchain_exists = False
    fullchain_modified: datetime | None = None
    key_exists = False
    key_mode_octal: str | None = None
    parsed: dict[str, Any] = {}

    try:
        stat_result = backend.run_cmd(
            ["stat", "-c", "%Y", fullchain_path], sudo=True, timeout=5,
        )
        if stat_result.ok and stat_result.stdout.strip():
            try:
                fullchain_exists = True
                fullchain_modified = datetime.fromtimestamp(
                    int(stat_result.stdout.strip()), tz=timezone.utc,
                )
            except ValueError:
                pass
        if fullchain_exists:
            try:
                pem = backend.read_file(fullchain_path, sudo=True)
                parsed = parse_cert_pem(pem)
            except (BackendError, ValueError) as e:
                log.debug("Failed to parse %s: %s", fullchain_path, e)
    except BackendError:
        pass

    try:
        stat_key = backend.run_cmd(
            ["stat", "-c", "%a", key_path], sudo=True, timeout=5,
        )
        if stat_key.ok and stat_key.stdout.strip():
            key_exists = True
            mode_str = stat_key.stdout.strip()
            key_mode_octal = mode_str.zfill(4) if len(mode_str) < 4 else mode_str
    except BackendError:
        pass

    return CertOnDiskStatus(
        fullchain_exists=fullchain_exists,
        fullchain_modified=fullchain_modified,
        key_exists=key_exists,
        key_mode_octal=key_mode_octal,
        not_before=parsed.get("not_before"),
        not_after=parsed.get("not_after"),
        days_remaining=parsed.get("days_remaining"),
        sans=parsed.get("sans", []),
        issuer=parsed.get("issuer"),
    )


# ---------------------------------------------------------------------------
# Mutating tools — gated by [security].allow_mutations in plugin.toml
# ---------------------------------------------------------------------------

def cert_domains_update(cert_id: int, domains: list[str], target: str | None = None) -> dict[str, Any]:
    """UPDATE certs.domains for a cert id, restart nginx-ui."""
    if not domains:
        raise ValueError("domains cannot be empty")
    backend = get_backend(target)

    rows = backend.query_db(
        _db_path(),
        "SELECT domains FROM certs WHERE id=?",
        params=(int(cert_id),),
    )
    if not rows:
        raise ValueError(f"cert {cert_id} not found")
    prev_raw = rows[0].get("domains") or "[]"
    try:
        previous = json.loads(prev_raw) if isinstance(prev_raw, str) else list(prev_raw)
    except json.JSONDecodeError:
        previous = []

    new_json = json.dumps(list(domains))
    backend.query_db(
        _db_path(),
        "UPDATE certs SET domains=? WHERE id=?",
        params=(new_json, int(cert_id)),
    )

    restart = backend.run_cmd(
        ["systemctl", "restart", "nginx-ui"], sudo=True, timeout=15,
    )
    return CertDomainsUpdateResult(
        ok=restart.ok,
        cert_id=int(cert_id),
        previous_domains=[str(d) for d in previous],
        new_domains=[str(d) for d in domains],
        nginx_ui_restarted=restart.ok,
    ).model_dump()


def _collect_provider_env(dns_provider: str) -> dict[str, str]:
    """Scoop the recognized env vars for the given acme.sh DNS provider.

    [VULN-12] mitigation — explicit allowlist per provider instead of a
    prefix match. Avoids accidentally exporting unrelated env vars that
    happen to share a prefix (e.g. ``CF_OTHER_SERVICE_TOKEN``) to the
    acme.sh subprocess.

    The lists are the documented env vars for each provider's acme.sh
    DNS API plugin. If a new provider needs additional vars, extend
    the mapping here.
    """
    explicit_map: dict[str, tuple[str, ...]] = {
        "dns_cf": (
            "CF_API_TOKEN", "CF_Token", "CF_Zone_ID", "CF_ZONE_ID",
            "CF_Account_ID", "CF_API_KEY", "CF_Email", "CF_EMAIL",
        ),
        "dns_aws": (
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
            "AWS_REGION", "AWS_SESSION_TOKEN", "AWS_DNS_SLOWRATE",
        ),
        "dns_do": ("DO_API_KEY", "DO_API_TOKEN"),
        "dns_gandi": ("GANDI_LIVEDNS_KEY",),
        "dns_namecheap": ("NAMECHEAP_API_KEY", "NAMECHEAP_USERNAME", "NAMECHEAP_SOURCEIP"),
        "dns_namesilo": ("NAMESILO_KEY",),
        "dns_dynu": ("DYNU_ClientId", "DYNU_Secret"),
        "dns_he": ("HE_Username", "HE_Password"),
        "dns_linode": ("LINODE_API_KEY",),
        "dns_ovh": ("OVH_END_POINT", "OVH_AK", "OVH_AS", "OVH_CK"),
    }
    allowed = explicit_map.get(dns_provider, ())
    return {k: os.environ[k] for k in allowed if k in os.environ}


def _acquire_acme_lock(backend: Any) -> bool:
    """Atomic lock acquisition via ``mkdir``.

    [VULN-05] mitigation — ``mkdir`` on POSIX is an atomic operation;
    if the directory already exists, ``mkdir`` returns non-zero. This
    closes the TOCTOU window between ``test -e`` and ``touch`` that
    the previous implementation suffered.

    Returns True if the lock was acquired, False if another process
    already held it.
    """
    res = backend.run_cmd(["mkdir", ACME_LOCK_PATH], timeout=5)
    return res.ok


def _release_acme_lock(backend: Any) -> None:
    """Best-effort lock release (rmdir of the lock directory)."""
    try:
        backend.run_cmd(["rmdir", ACME_LOCK_PATH], timeout=5)
    except BackendError as e:
        log.warning("Failed to release acme lock: %s", e)


def cert_issue(
    domains: list[str],
    key_type: str = "P256",
    dns_provider: str = "dns_cf",
    force: bool = False,
    target: str | None = None,
) -> dict[str, Any]:
    """Issue a cert via acme.sh. Idempotent unless ``force=True``.

    v0.4.0: requires the selected ``target``'s backend to declare
    ``supports_acme = True`` (wrapper-lxc, direct-ssh — yes;
    docker-exec — no, because the upstream container doesn't ship
    acme.sh). On unsupported targets returns ok=False with a
    legible message instead of crashing.
    """
    from ..backends import supports_acme as _supports_acme

    if not domains:
        raise ValueError("domains cannot be empty")

    if not _supports_acme(target):
        return {
            "ok": False,
            "error": (
                f"cert_issue: target {target or 'default'!r} backend does not "
                "support acme.sh (e.g. docker-exec on uozi/nginx-ui has no "
                "acme.sh inside the container). Issue the cert on another "
                "target (wrapper-lxc, direct-ssh) or run acme.sh manually "
                "on the host, then push the cert with cert_deploy_files."
            ),
            "error_type": "unsupported_capability",
        }

    backend = get_backend(target)

    if not force:
        existing = _find_existing_cert(backend, domains)
        if existing is not None:
            threshold = _renew_threshold_days()
            days = existing.get("days_remaining", -1)
            if days is not None and days > threshold:
                return CertIssueResult(
                    action="kept_existing",
                    domains=domains,
                    key_type=key_type,
                    fullchain_path=existing.get("fullchain_path"),
                    key_path=existing.get("key_path"),
                    days_remaining=days,
                    reason=(
                        f"cert valid {days} days remaining "
                        f"(threshold={threshold}d). Pass force=True to re-issue."
                    ),
                ).model_dump()

    if not _acquire_acme_lock(backend):
        raise BackendError(
            f"acme lock file {ACME_LOCK_PATH} exists — another acme.sh "
            f"invocation in flight (or stale lock). Manual cleanup may "
            f"be required: rm {ACME_LOCK_PATH}"
        )

    try:
        provider_env = _collect_provider_env(dns_provider)
        result = backend.acme_issue(
            domains=domains,
            key_type=key_type,
            dns_provider=dns_provider,
            provider_env=provider_env,
            acme_home=_acme_home(),
        )
    finally:
        _release_acme_lock(backend)

    return CertIssueResult(
        action="issued_new",
        domains=domains,
        key_type=key_type,
        fullchain_path=result.get("fullchain_path"),
        key_path=result.get("key_path"),
        reason=f"acme.sh rc={result.get('acme_returncode', '?')}",
    ).model_dump()


def _find_existing_cert(
    backend: Any, domains: list[str],
) -> dict[str, Any] | None:
    """Look up a cert in the DB whose domains match the requested set."""
    target = sorted({d.lower() for d in domains})
    rows = backend.query_db(
        _db_path(),
        "SELECT id, domains, ssl_certificate_path, ssl_certificate_key_path "
        "FROM certs WHERE deleted_at IS NULL",
    )
    for row in rows:
        raw = row.get("domains") or "[]"
        try:
            doms = json.loads(raw) if isinstance(raw, str) else list(raw)
        except json.JSONDecodeError:
            continue
        if sorted({str(d).lower() for d in doms}) != target:
            continue
        path = row.get("ssl_certificate_path") or ""
        if not path:
            return None
        try:
            pem = backend.read_file(path, sudo=True)
            parsed = parse_cert_pem(pem)
        except (BackendError, ValueError):
            return None
        return {
            "fullchain_path": path,
            "key_path": row.get("ssl_certificate_key_path") or "",
            "days_remaining": parsed.get("days_remaining"),
        }
    return None


def cert_deploy_files(cert_id: int, target: str | None = None) -> dict[str, Any]:
    """Push acme.sh-issued cert to nginx-ui's expected paths + reload nginx."""
    backend = get_backend(target)
    rows = backend.query_db(
        _db_path(),
        "SELECT id, domains, ssl_certificate_path, ssl_certificate_key_path, key_type "
        "FROM certs WHERE id=?",
        params=(int(cert_id),),
    )
    if not rows:
        raise ValueError(f"cert {cert_id} not found")
    row = rows[0]

    raw_domains = row.get("domains") or "[]"
    try:
        domains = json.loads(raw_domains) if isinstance(raw_domains, str) else list(raw_domains)
    except json.JSONDecodeError:
        domains = []
    if not domains:
        raise ValueError(f"cert {cert_id} has no domains stored")

    primary = str(domains[0])
    key_type = (row.get("key_type") or "P256").upper()
    is_ecc = key_type in ("P256", "P384", "P521", "ECC")
    acme_home = _acme_home()
    cert_dir = f"{primary}_ecc" if is_ecc else primary
    src_fullchain = f"{acme_home.rstrip('/')}/{cert_dir}/fullchain.cer"
    src_key = f"{acme_home.rstrip('/')}/{cert_dir}/{primary.lstrip('*').lstrip('.')}.key"

    dest_fullchain = str(row.get("ssl_certificate_path") or "")
    dest_key = str(row.get("ssl_certificate_key_path") or "")
    if not dest_fullchain or not dest_key:
        raise ValueError(
            f"cert {cert_id}: missing ssl_certificate_path / "
            f"ssl_certificate_key_path in DB"
        )

    # [VULN-03] mitigation — validate the DB-controlled paths against
    # the deploy allowlist BEFORE pushing as root. An attacker with
    # write access to nginx-ui's DB could otherwise pivot to writing
    # any cert/key file as root.
    allowed = _cert_deploy_dirs()
    dest_fullchain = validate_under_any(
        dest_fullchain, allowed, label="cert deploy fullchain",
    )
    dest_key = validate_under_any(
        dest_key, allowed, label="cert deploy key",
    )

    fullchain_bytes = backend.read_file(src_fullchain)
    key_bytes = backend.read_file(src_key)

    backend.push_file(fullchain_bytes, dest_fullchain, mode=0o644, sudo=True)
    backend.push_file(key_bytes, dest_key, mode=0o600, sudo=True)

    test_result = backend.run_cmd(["nginx", "-t"], sudo=True, timeout=10)
    if not test_result.ok:
        return CertDeployResult(
            ok=False,
            cert_id=int(cert_id),
            fullchain_pushed_to=dest_fullchain,
            key_pushed_to=dest_key,
            nginx_test_passed=False,
            nginx_reloaded=False,
        ).model_dump()

    reload_result = backend.run_cmd(["nginx", "-s", "reload"], sudo=True, timeout=10)
    return CertDeployResult(
        ok=reload_result.ok,
        cert_id=int(cert_id),
        fullchain_pushed_to=dest_fullchain,
        key_pushed_to=dest_key,
        nginx_test_passed=True,
        nginx_reloaded=reload_result.ok,
    ).model_dump()
