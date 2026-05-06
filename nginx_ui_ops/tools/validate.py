"""External cert validation via TLS handshake.

Connects directly from the local machine running the MCP server to
the nginx host (or a reverse proxy in front), retrieves the served
certificate via TLS handshake with SNI, and parses it locally.

Does NOT use the backend — talks straight to the nginx socket. This
gives a "world view": is the cert that the DB says is configured the
one that's actually being served? Catches deploy mistakes (cert in
DB but not on disk; nginx loaded an older cert; SNI routing wrong
vhost; etc.).

Pure stdlib (``socket`` + ``ssl``) + ``cryptography`` for parsing.
"""
from __future__ import annotations

import socket
import ssl
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

from ..models import CertValidationResult
from ..x509_parse import cert_matches_hostname, parse_cert_pem


def nginx_cert_validate(hostname: str, port: int = 443) -> dict[str, Any]:
    """Fetch the cert served on ``hostname:port`` and parse it.

    Connects with TLS + SNI to the given host:port, retrieves the
    server's cert chain, parses the leaf, and returns the structured
    summary including whether the hostname matches the cert SANs.

    Args:
        hostname: DNS name to connect to (also used as SNI).
        port: TCP port (default 443).

    Returns:
        CertValidationResult dict with sans, issuer, dates,
        days_remaining, matches_hostname.
    """
    # Build a context that does NOT verify the cert chain — we only
    # want to see what's served, not validate trust. The whole point
    # is that the operator may be looking at a self-signed or staging
    # cert during diagnosis.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    der_cert: bytes
    with socket.create_connection((hostname, port), timeout=10) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=hostname) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)

    if not der_cert:
        raise RuntimeError(
            f"No cert received from {hostname}:{port} — server may not "
            f"be using TLS, or aborted the handshake."
        )

    # getpeercert returns DER; convert to PEM-ish for our parser by
    # loading directly via cryptography (which handles both).
    cert = x509.load_der_x509_certificate(der_cert, backend=default_backend())
    pem = cert.public_bytes(encoding=Encoding.PEM)

    parsed = parse_cert_pem(pem)
    matches = cert_matches_hostname(parsed, hostname)

    return CertValidationResult(
        hostname=hostname,
        port=port,
        sans=parsed["sans"],
        issuer=parsed["issuer"],
        subject=parsed["subject"],
        not_before=parsed["not_before"],
        not_after=parsed["not_after"],
        days_remaining=parsed["days_remaining"],
        matches_hostname=matches,
    ).model_dump()
