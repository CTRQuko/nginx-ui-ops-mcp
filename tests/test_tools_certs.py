"""Tests for tools/certs.py.

Backend is mocked through ``nginx_ui_ops.backends.factory.get_backend``.
Tests focus on tool semantics: SQL shape, idempotence, lock acquisition,
result schema. The backend's transport mechanics are tested separately
in tests/backends/.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from nginx_ui_ops.backends import reset_cache
from nginx_ui_ops.backends.base import BackendError
from nginx_ui_ops.tools import certs as certs_mod
from nginx_ui_ops.tools.certs import (
    _collect_provider_env,
    _normalize_cert_row,
    cert_deploy_files,
    cert_domains_update,
    cert_get,
    cert_issue,
    cert_list,
)

# ---------------------------------------------------------------------------
# Fake backend fixture
# ---------------------------------------------------------------------------

class FakeBackend:
    """Hand-rolled mock of NginxUIBackend for tool tests."""

    def __init__(self):
        self.queries: list[tuple[str, str, tuple]] = []
        self.commands: list[tuple[list[str], bool]] = []
        self.pushes: list[tuple[bytes, str, int, bool]] = []
        self.reads: dict[str, bytes] = {}
        self.query_responses: list[list[dict[str, Any]]] = []
        self.command_responses: list[Any] = []
        self.acme_response: dict[str, Any] = {
            "fullchain_path": "/acme/cert/fullchain.cer",
            "key_path": "/acme/cert/key.key",
            "domains": [],
            "key_type": "P256",
            "acme_returncode": 0,
            "acme_stdout_tail": "",
        }

    def query_db(self, db_path, sql, *, params=()):
        self.queries.append((db_path, sql, params))
        if self.query_responses:
            return self.query_responses.pop(0)
        return []

    def run_cmd(self, argv, *, sudo=False, timeout=30):
        self.commands.append((list(argv), sudo))
        if self.command_responses:
            r = self.command_responses.pop(0)
            return r
        # Default: success with empty output.
        m = MagicMock()
        m.ok = True
        m.return_code = 0
        m.stdout = ""
        m.stderr = ""
        return m

    def push_file(self, content, remote_path, *, mode=0o644, sudo=False):
        self.pushes.append((content, remote_path, mode, sudo))

    def read_file(self, remote_path, *, sudo=False):
        if remote_path in self.reads:
            return self.reads[remote_path]
        raise BackendError(f"file not found: {remote_path}")

    def acme_issue(self, domains, *, key_type, dns_provider, provider_env, acme_home):
        return {**self.acme_response, "domains": domains, "key_type": key_type}


@pytest.fixture
def fake_backend(monkeypatch):
    fake = FakeBackend()
    reset_cache()
    monkeypatch.setattr(certs_mod, "get_backend", lambda *a, **kw: fake)
    return fake


# ---------------------------------------------------------------------------
# _normalize_cert_row
# ---------------------------------------------------------------------------

def test_normalize_basic():
    row = {
        "id": 1, "name": "wildcard",
        "domains": '["*.example.com","example.com"]',
        "ssl_certificate_path": "/x/full",
        "ssl_certificate_key_path": "/x/key",
        "auto_cert": 1,
        "challenge_method": "dns01",
        "dns_credential_id": 5,
        "key_type": "P256",
        "deleted_at": None,
    }
    info = _normalize_cert_row(row)
    assert info.id == 1
    assert info.domains == ["*.example.com", "example.com"]
    assert info.auto_cert is True
    assert info.dns_credential_id == 5
    assert info.deleted is False


def test_normalize_marks_deleted():
    row = {
        "id": 2, "domains": "[]", "deleted_at": "2026-05-06T10:00:00Z",
        "ssl_certificate_path": "", "ssl_certificate_key_path": "",
    }
    info = _normalize_cert_row(row)
    assert info.deleted is True


def test_normalize_invalid_json_domains_yields_empty():
    row = {
        "id": 3, "domains": "not valid json", "deleted_at": None,
        "ssl_certificate_path": "", "ssl_certificate_key_path": "",
    }
    info = _normalize_cert_row(row)
    assert info.domains == []


# ---------------------------------------------------------------------------
# cert_list
# ---------------------------------------------------------------------------

def test_cert_list_default_excludes_deleted(fake_backend):
    fake_backend.query_responses = [[
        {"id": 1, "name": "active", "domains": '["a.com"]',
         "ssl_certificate_path": "/p1", "ssl_certificate_key_path": "/k1",
         "auto_cert": 1, "challenge_method": "dns01",
         "dns_credential_id": 1, "key_type": "P256", "deleted_at": None},
    ]]
    rows = cert_list()
    assert len(rows) == 1
    # SQL must include the WHERE filter for deleted_at IS NULL.
    sql = fake_backend.queries[0][1]
    assert "deleted_at IS NULL" in sql


def test_cert_list_with_deleted_includes_them(fake_backend):
    fake_backend.query_responses = [[]]
    cert_list(deleted=True)
    sql = fake_backend.queries[0][1]
    assert "deleted_at IS NULL" not in sql


# ---------------------------------------------------------------------------
# cert_get
# ---------------------------------------------------------------------------

def test_cert_get_not_found_raises(fake_backend):
    fake_backend.query_responses = [[]]
    with pytest.raises(ValueError, match="cert 99 not found"):
        cert_get(99)


def test_cert_get_returns_db_and_disk(fake_backend):
    fake_backend.query_responses = [[
        {"id": 1, "name": "test", "domains": '["a.com"]',
         "ssl_certificate_path": "/x/full", "ssl_certificate_key_path": "/x/key",
         "auto_cert": 1, "challenge_method": "dns01",
         "dns_credential_id": 1, "key_type": "P256", "deleted_at": None},
    ]]
    # Stat fullchain → epoch
    stat_full = MagicMock(); stat_full.ok = True; stat_full.stdout = "1714000000\n"
    # Stat key → 600
    stat_key = MagicMock(); stat_key.ok = True; stat_key.stdout = "600\n"
    fake_backend.command_responses = [stat_full, stat_key]
    # Read fullchain — return invalid PEM, parse fails silently.
    fake_backend.reads["/x/full"] = b"not a real PEM"

    result = cert_get(1)
    assert result["db"]["id"] == 1
    assert result["on_disk"]["fullchain_exists"] is True
    assert result["on_disk"]["key_exists"] is True
    assert result["on_disk"]["key_mode_octal"] == "0600"


# ---------------------------------------------------------------------------
# cert_domains_update
# ---------------------------------------------------------------------------

def test_cert_domains_update_empty_domains_raises(fake_backend):
    with pytest.raises(ValueError, match="domains cannot be empty"):
        cert_domains_update(1, [])


def test_cert_domains_update_not_found_raises(fake_backend):
    fake_backend.query_responses = [[]]
    with pytest.raises(ValueError, match="cert 1 not found"):
        cert_domains_update(1, ["a.com"])


def test_cert_domains_update_does_update_and_restart(fake_backend):
    fake_backend.query_responses = [
        [{"domains": '["old.com"]'}],  # current value
        [],  # UPDATE returns nothing
    ]
    result = cert_domains_update(1, ["a.com", "b.com"])
    assert result["ok"] is True
    assert result["previous_domains"] == ["old.com"]
    assert result["new_domains"] == ["a.com", "b.com"]
    assert result["nginx_ui_restarted"] is True
    # An UPDATE was issued.
    update_q = next(
        (q for q in fake_backend.queries if "UPDATE" in q[1]), None,
    )
    assert update_q is not None
    # And a systemctl restart command.
    restart_cmd = next(
        (c for c in fake_backend.commands if "systemctl" in c[0]), None,
    )
    assert restart_cmd is not None


# ---------------------------------------------------------------------------
# _collect_provider_env
# ---------------------------------------------------------------------------

def test_collect_provider_env_cf(monkeypatch):
    monkeypatch.setenv("CF_API_TOKEN", "tok")
    monkeypatch.setenv("CF_ZONE_ID", "zone")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "should-not-leak")
    out = _collect_provider_env("dns_cf")
    assert "CF_API_TOKEN" in out
    assert "CF_ZONE_ID" in out
    assert "AWS_ACCESS_KEY_ID" not in out


def test_collect_provider_env_aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "id")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("CF_API_TOKEN", "should-not-leak")
    out = _collect_provider_env("dns_aws")
    assert "AWS_ACCESS_KEY_ID" in out
    assert "AWS_SECRET_ACCESS_KEY" in out
    assert "CF_API_TOKEN" not in out


def test_collect_provider_env_unknown_provider_returns_empty(monkeypatch):
    monkeypatch.setenv("MAGIC_API_KEY", "x")
    out = _collect_provider_env("dns_magic_unsupported")
    assert out == {}


# ---------------------------------------------------------------------------
# cert_issue — idempotence + force + lock
# ---------------------------------------------------------------------------

def _make_cert_pem_with_days_remaining(days: int) -> bytes:
    """Generate a self-signed cert with a controlled notAfter for tests."""
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    not_before = datetime.now(timezone.utc) - timedelta(days=1)
    not_after = datetime.now(timezone.utc) + timedelta(days=days)
    cert = (
        _x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            _x509.SubjectAlternativeName([_x509.DNSName("a.com"), _x509.DNSName("b.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_cert_issue_idempotent_when_existing_has_more_than_threshold_days(fake_backend):
    """If cert exists and has 60 days remaining (> threshold 30), skip."""
    fake_backend.query_responses = [
        # _find_existing_cert SELECT
        [{
            "id": 1, "domains": '["a.com","b.com"]',
            "ssl_certificate_path": "/x/full",
            "ssl_certificate_key_path": "/x/key",
        }],
    ]
    fake_backend.reads["/x/full"] = _make_cert_pem_with_days_remaining(60)

    result = cert_issue(["a.com", "b.com"])
    assert result["action"] == "kept_existing"
    assert result["fullchain_path"] == "/x/full"
    assert result["days_remaining"] is not None
    assert result["days_remaining"] >= 50  # ~60 with rounding tolerance


def test_cert_issue_force_skips_idempotence(fake_backend):
    """force=True triggers a real acme_issue even with valid cert."""
    fake_backend.query_responses = [[]]  # no existing match (force skips check)
    # Lock check + lock touch + lock release
    not_locked = MagicMock(); not_locked.ok = False; not_locked.return_code = 1
    locked_ok = MagicMock(); locked_ok.ok = True
    fake_backend.command_responses = [not_locked, locked_ok, locked_ok]

    result = cert_issue(["a.com"], force=True)
    assert result["action"] == "issued_new"


def test_cert_issue_re_issues_when_threshold_exceeded(fake_backend):
    """Cert exists but only 5 days remaining < threshold 30 → re-issue."""
    fake_backend.query_responses = [
        # _find_existing_cert SELECT
        [{
            "id": 1, "domains": '["a.com"]',
            "ssl_certificate_path": "/x/full",
            "ssl_certificate_key_path": "/x/key",
        }],
    ]
    fake_backend.reads["/x/full"] = _make_cert_pem_with_days_remaining(5)
    # Lock acquire chain.
    not_locked = MagicMock(); not_locked.ok = False; not_locked.return_code = 1
    ok = MagicMock(); ok.ok = True
    fake_backend.command_responses = [not_locked, ok, ok]

    result = cert_issue(["a.com"])
    assert result["action"] == "issued_new"


def test_cert_issue_lock_held_raises(fake_backend):
    """If acme lock file exists, bail with BackendError."""
    fake_backend.query_responses = [[]]  # no existing match
    locked = MagicMock(); locked.ok = True; locked.return_code = 0  # test -e succeeds
    fake_backend.command_responses = [locked]

    with pytest.raises(BackendError, match="lock"):
        cert_issue(["a.com"])


def test_cert_issue_empty_domains_raises(fake_backend):
    with pytest.raises(ValueError, match="domains cannot be empty"):
        cert_issue([])


# ---------------------------------------------------------------------------
# cert_deploy_files
# ---------------------------------------------------------------------------

def test_cert_deploy_files_pushes_with_correct_modes(fake_backend):
    fake_backend.query_responses = [[
        {"id": 1, "domains": '["*.example.com"]',
         "ssl_certificate_path": "/dest/full",
         "ssl_certificate_key_path": "/dest/key",
         "key_type": "P256"},
    ]]
    # acme.sh paths derived: /root/.acme.sh/*.example.com_ecc/...
    fake_backend.reads["/root/.acme.sh/*.example.com_ecc/fullchain.cer"] = b"FULLCHAIN"
    fake_backend.reads["/root/.acme.sh/*.example.com_ecc/example.com.key"] = b"KEY"
    nginx_test = MagicMock(); nginx_test.ok = True
    nginx_reload = MagicMock(); nginx_reload.ok = True
    fake_backend.command_responses = [nginx_test, nginx_reload]

    result = cert_deploy_files(1)
    assert result["ok"] is True
    assert result["nginx_test_passed"] is True
    assert result["nginx_reloaded"] is True

    pushes = fake_backend.pushes
    assert len(pushes) == 2
    # Modes: 0o644 fullchain, 0o600 key.
    fullchain_push = next(p for p in pushes if p[1] == "/dest/full")
    key_push = next(p for p in pushes if p[1] == "/dest/key")
    assert fullchain_push[2] == 0o644
    assert key_push[2] == 0o600


def test_cert_deploy_files_skips_reload_when_test_fails(fake_backend):
    fake_backend.query_responses = [[
        {"id": 1, "domains": '["a.com"]',
         "ssl_certificate_path": "/dest/full",
         "ssl_certificate_key_path": "/dest/key",
         "key_type": "P256"},
    ]]
    fake_backend.reads["/root/.acme.sh/a.com_ecc/fullchain.cer"] = b"FULLCHAIN"
    fake_backend.reads["/root/.acme.sh/a.com_ecc/a.com.key"] = b"KEY"
    nginx_test = MagicMock(); nginx_test.ok = False; nginx_test.return_code = 1
    fake_backend.command_responses = [nginx_test]

    result = cert_deploy_files(1)
    assert result["ok"] is False
    assert result["nginx_test_passed"] is False
    assert result["nginx_reloaded"] is False


def test_cert_deploy_files_not_found_raises(fake_backend):
    fake_backend.query_responses = [[]]
    with pytest.raises(ValueError, match="cert 99 not found"):
        cert_deploy_files(99)
