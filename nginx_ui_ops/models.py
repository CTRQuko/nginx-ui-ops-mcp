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
