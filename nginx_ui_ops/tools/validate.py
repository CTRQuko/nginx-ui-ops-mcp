"""External cert validation via openssl s_client. Wired in Step 7.

This tool does NOT use the backend — it talks directly to the nginx
listening socket from the operator's machine. Useful to confirm what
the world actually sees vs what the DB says.
"""
from __future__ import annotations


def nginx_cert_validate(hostname: str, port: int = 443) -> dict:
    """Connect with openssl s_client and parse the served cert.

    (Skeleton — Step 7.)
    """
    raise NotImplementedError("nginx_cert_validate — wired in Step 7")
