"""x509 cert parsing helpers — pure local, no backend roundtrip.

Used by ``cert_get`` and ``nginx_cert_validate`` to extract SANs,
issuer, subject, validity dates from a PEM/DER-encoded certificate.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend


def parse_cert_pem(pem_bytes: bytes) -> dict[str, Any]:
    """Parse a PEM-encoded certificate and return a structured summary.

    Tolerates fullchain bundles (multiple certs concatenated) — only
    the leaf (first cert) is parsed. The intermediates are intentionally
    ignored at this layer; chain validation is a separate concern.

    Returns dict with keys:
      sans, issuer, subject, not_before, not_after, days_remaining

    Raises:
        ValueError: input is not parseable as PEM x509.
    """
    # Find the first BEGIN CERTIFICATE block. fullchain.cer concatenates
    # leaf + intermediates; we only want the leaf.
    text = pem_bytes.decode("utf-8", errors="replace")
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    start_idx = text.find(begin)
    if start_idx < 0:
        raise ValueError("No PEM CERTIFICATE block found")
    end_idx = text.find(end, start_idx)
    if end_idx < 0:
        raise ValueError("Truncated PEM CERTIFICATE block (no END marker)")
    leaf_pem = text[start_idx : end_idx + len(end)].encode("utf-8")

    cert = x509.load_pem_x509_certificate(leaf_pem, backend=default_backend())

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value)
    except x509.ExtensionNotFound:
        pass

    not_before = cert.not_valid_before_utc.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_remaining = (not_after - now).days

    return {
        "sans": sans,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_remaining,
    }


def cert_matches_hostname(parsed: dict[str, Any], hostname: str) -> bool:
    """True if hostname is in the cert's SANs (handles wildcards)."""
    sans = parsed.get("sans", [])
    h = hostname.lower()
    for san in sans:
        s = san.lower()
        if s == h:
            return True
        if s.startswith("*."):
            # Wildcard matches one DNS level: *.example.com matches
            # foo.example.com but not foo.bar.example.com.
            suffix = s[1:]  # ".example.com"
            if h.endswith(suffix) and h.count(".") == s.count("."):
                return True
    return False
