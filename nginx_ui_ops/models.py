"""Pydantic models for nginx-ui-ops tool outputs.

These define the schema the LLM sees back from each tool. Stable
contract — bumps require changelog entry and version bump in the
plugin's pyproject.toml.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class CertInfo(BaseModel):
    """Row from nginx-ui's ``certs`` SQLite table, normalized."""

    id: int
    name: str
    domains: list[str] = Field(
        default_factory=list,
        description="SANs as parsed from the JSON string in the DB.",
    )
    ssl_certificate_path: str
    ssl_certificate_key_path: str
    auto_cert: bool = False
    challenge_method: Optional[str] = Field(
        default=None,
        description="e.g. 'dns01' for DNS-01 ACME challenge.",
    )
    dns_credential_id: Optional[int] = None
    key_type: Optional[str] = Field(
        default=None,
        description="e.g. 'P256', 'P384', 'RSA2048'.",
    )
    deleted: bool = False


class CertOnDiskStatus(BaseModel):
    """Live state of the cert files on disk + parsed via openssl."""

    fullchain_exists: bool
    fullchain_modified: Optional[datetime] = None
    key_exists: bool
    key_mode_octal: Optional[str] = Field(
        default=None,
        description="Permissions of the private key file, e.g. '0600'.",
    )
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: Optional[int] = None
    sans: list[str] = Field(default_factory=list)
    issuer: Optional[str] = None


class CertDetail(BaseModel):
    """Combined view returned by ``cert_get(id)``."""

    db: CertInfo
    on_disk: CertOnDiskStatus


class CertIssueResult(BaseModel):
    """Outcome of ``cert_issue``. ``action`` distinguishes idempotent
    skips (``kept_existing``) from new issues (``issued_new``)."""

    action: Literal["kept_existing", "issued_new"]
    domains: list[str]
    key_type: str
    fullchain_path: Optional[str] = Field(
        default=None,
        description="Path on the host where acme.sh stored the new cert "
        "(or existing cert if skipped). Use cert_deploy_files to copy "
        "to nginx-ui's expected location.",
    )
    key_path: Optional[str] = None
    days_remaining: Optional[int] = Field(
        default=None,
        description="Days remaining on the kept_existing cert. Only set "
        "when action='kept_existing'.",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Human-readable explanation of why this action.",
    )


class NginxTestResult(BaseModel):
    ok: bool
    stdout: str
    stderr: str
    return_code: int


class CertValidationResult(BaseModel):
    """Output of ``nginx_cert_validate(hostname)`` — what the world sees."""

    hostname: str
    port: int
    sans: list[str] = Field(default_factory=list)
    issuer: Optional[str] = None
    subject: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: Optional[int] = None
    matches_hostname: bool = Field(
        default=False,
        description="True if hostname is in the cert's SANs.",
    )


class CertDomainsUpdateResult(BaseModel):
    """Outcome of ``cert_domains_update``."""

    ok: bool
    cert_id: int
    previous_domains: list[str]
    new_domains: list[str]
    nginx_ui_restarted: bool


class CertDeployResult(BaseModel):
    """Outcome of ``cert_deploy_files``."""

    ok: bool
    cert_id: int
    fullchain_pushed_to: str
    key_pushed_to: str
    nginx_test_passed: bool
    nginx_reloaded: bool


# ---------------------------------------------------------------------------
# v0.3.0 — Diagnostics + ops models
# ---------------------------------------------------------------------------

class NginxStatusResult(BaseModel):
    """Output of ``nginx_status``: systemd state + worker count + uptime."""

    active: bool = Field(description="True if systemd reports active (running).")
    sub_state: Optional[str] = Field(
        default=None,
        description="systemd substate: running, dead, failed, etc.",
    )
    main_pid: Optional[int] = None
    started_at: Optional[datetime] = None
    uptime_seconds: Optional[int] = None
    worker_count: Optional[int] = Field(
        default=None,
        description="Number of nginx worker processes detected via ps.",
    )
    raw_systemctl: str = Field(
        default="",
        description="Raw output of `systemctl status nginx` for full detail.",
    )


class NginxLogResult(BaseModel):
    """Output of ``nginx_logs`` — snapshot tail of a log file."""

    file: str = Field(description="Absolute path of the log file read.")
    lines_returned: int
    lines_requested: int
    grep_filter: Optional[str] = None
    content: str = Field(description="Joined log lines (newline-separated).")
    truncated: bool = Field(
        default=False,
        description="True when more lines matched the filter than requested.",
    )


class NginxCompiledInfo(BaseModel):
    """Output of ``nginx_compiled_with`` — build-time configuration."""

    version: str = Field(description="e.g. 'nginx/1.24.0'")
    built_with: Optional[str] = Field(
        default=None,
        description="Compiler version line, e.g. 'gcc 11.4.0'.",
    )
    tls_library: Optional[str] = Field(
        default=None,
        description="OpenSSL/BoringSSL/LibreSSL version compiled against.",
    )
    prefix: Optional[str] = None
    configure_flags: list[str] = Field(default_factory=list)
    raw_output: str = Field(
        default="",
        description="Full `nginx -V` stderr (where nginx prints build info).",
    )


class NginxActiveConns(BaseModel):
    """Output of ``nginx_active_conns`` — runtime stats from stub_status."""

    enabled: bool = Field(
        description="True if stub_status module is mounted and reachable."
    )
    active_connections: Optional[int] = None
    accepts: Optional[int] = None
    handled: Optional[int] = None
    requests: Optional[int] = None
    reading: Optional[int] = None
    writing: Optional[int] = None
    waiting: Optional[int] = None
    endpoint: Optional[str] = Field(
        default=None,
        description="The URL queried (e.g. http://127.0.0.1/nginx_status).",
    )
    note: Optional[str] = Field(
        default=None,
        description=(
            "Hint for the operator if stub_status is not enabled — "
            "instructions to add a `location = /nginx_status` block."
        ),
    )


class NginxPendingChanges(BaseModel):
    """Output of ``nginx_pending_changes`` — files modified since service start."""

    service_started_at: Optional[datetime] = None
    pending_files: list[str] = Field(
        default_factory=list,
        description="Files under nginx config dir with mtime newer than service start.",
    )
    has_pending: bool = Field(
        description="True if any file has been modified since the running nginx started.",
    )
    note: Optional[str] = None


class NginxTestWithDiffResult(BaseModel):
    """Output of ``nginx_test_with_diff`` — validate a proposed config change."""

    ok: bool = Field(description="True if the proposed change passes nginx -t.")
    target_path: str
    proposed_content_size: int
    test_stdout: str = ""
    test_stderr: str = ""
    diff: Optional[str] = Field(
        default=None,
        description="Unified diff from current to proposed content (None if file didn't exist).",
    )


class NginxFileContent(BaseModel):
    """Output of ``nginx_read_file`` — content of a config file under /etc/nginx/."""

    path: str
    size_bytes: int
    content: str
    mtime: Optional[datetime] = None
    truncated: bool = Field(
        default=False,
        description="True if the file was larger than the read cap (default 256KB).",
    )


class NginxFileWriteResult(BaseModel):
    """Output of ``nginx_write_file`` — atomic write with backup + test."""

    ok: bool
    path: str
    bytes_written: int
    backup_path: Optional[str] = Field(
        default=None,
        description="Where the previous content was archived. None if no prior file.",
    )
    nginx_test_passed: bool = Field(
        description="Result of the implicit `nginx -t` after writing.",
    )
    rolled_back: bool = Field(
        default=False,
        description="True when test failed and the backup was restored.",
    )
    test_stderr: str = ""


class NginxControlResult(BaseModel):
    """Output of ``nginx_full_restart``, ``nginx_reopen_logs``, ``nginx_quit``."""

    action: Literal["restart", "reopen_logs", "quit"]
    ok: bool
    return_code: int
    stdout: str = ""
    stderr: str = ""
    note: Optional[str] = None
