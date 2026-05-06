"""Tests for tools/validate.py and x509_parse helpers."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from nginx_ui_ops.x509_parse import cert_matches_hostname, parse_cert_pem

# ---------------------------------------------------------------------------
# parse_cert_pem
# ---------------------------------------------------------------------------

def _make_self_signed_pem(*, sans: list[str], days: int = 30) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, sans[0] if sans else "cn.test"),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def test_parse_cert_pem_extracts_sans():
    pem = _make_self_signed_pem(
        sans=["a.example.com", "*.example.com"], days=10,
    )
    parsed = parse_cert_pem(pem)
    assert "a.example.com" in parsed["sans"]
    assert "*.example.com" in parsed["sans"]


def test_parse_cert_pem_days_remaining_within_tolerance():
    pem = _make_self_signed_pem(sans=["a.com"], days=30)
    parsed = parse_cert_pem(pem)
    assert 28 <= parsed["days_remaining"] <= 30


def test_parse_cert_pem_handles_fullchain_bundle():
    """Fullchain has multiple certs concatenated — only leaf is parsed."""
    leaf = _make_self_signed_pem(sans=["leaf.com"])
    intermediate = _make_self_signed_pem(sans=["intermediate.com"])
    fullchain = leaf + intermediate
    parsed = parse_cert_pem(fullchain)
    # Should pick the FIRST cert (leaf), not the intermediate.
    assert "leaf.com" in parsed["sans"]
    assert "intermediate.com" not in parsed["sans"]


def test_parse_cert_pem_no_pem_block_raises():
    with pytest.raises(ValueError, match="No PEM"):
        parse_cert_pem(b"this is not a cert")


def test_parse_cert_pem_truncated_raises():
    with pytest.raises(ValueError, match="Truncated"):
        parse_cert_pem(b"-----BEGIN CERTIFICATE-----\nincomplete...")


# ---------------------------------------------------------------------------
# cert_matches_hostname
# ---------------------------------------------------------------------------

def test_matches_hostname_exact():
    assert cert_matches_hostname({"sans": ["example.com"]}, "example.com")


def test_matches_hostname_case_insensitive():
    assert cert_matches_hostname({"sans": ["Example.COM"]}, "example.com")


def test_matches_hostname_wildcard_one_level():
    assert cert_matches_hostname({"sans": ["*.example.com"]}, "foo.example.com")
    # NOT two levels
    assert not cert_matches_hostname({"sans": ["*.example.com"]}, "foo.bar.example.com")
    # NOT the apex
    assert not cert_matches_hostname({"sans": ["*.example.com"]}, "example.com")


def test_matches_hostname_no_match():
    assert not cert_matches_hostname({"sans": ["a.com"]}, "b.com")


def test_matches_hostname_empty_sans():
    assert not cert_matches_hostname({"sans": []}, "foo.com")


# ---------------------------------------------------------------------------
# nginx_cert_validate — mocked socket
# ---------------------------------------------------------------------------

def test_nginx_cert_validate_returns_parsed_dict():
    """Use a real self-signed cert, mock the socket so no actual TLS
    handshake happens."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.local"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("test.local")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)

    fake_ssock = MagicMock()
    fake_ssock.getpeercert.return_value = der
    fake_ssock.__enter__ = MagicMock(return_value=fake_ssock)
    fake_ssock.__exit__ = MagicMock(return_value=False)

    fake_raw = MagicMock()
    fake_raw.__enter__ = MagicMock(return_value=fake_raw)
    fake_raw.__exit__ = MagicMock(return_value=False)

    fake_ctx = MagicMock()
    fake_ctx.wrap_socket.return_value = fake_ssock

    with patch("nginx_ui_ops.tools.validate.socket.create_connection",
               return_value=fake_raw), \
         patch("nginx_ui_ops.tools.validate.ssl.SSLContext",
               return_value=fake_ctx):
        from nginx_ui_ops.tools.validate import nginx_cert_validate
        result = nginx_cert_validate("test.local")

    assert result["hostname"] == "test.local"
    assert "test.local" in result["sans"]
    assert result["matches_hostname"] is True
    assert result["days_remaining"] is not None
    assert result["days_remaining"] >= 80
