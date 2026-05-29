"""Secret-redacting helper for error/log strings.

Used by acme.sh BackendError surfacing — see [VULN-07] in the audit.
The DNS provider plugins for acme.sh sometimes echo tokens verbatim
into stderr during debug output. Without redaction, those tokens end
up in BackendError → LLM → potentially in the host's MCP transcript.

The redactor is conservative — it only blanks the *value* portion
of recognized ``key=value``-style assignments. It does NOT attempt
generic high-entropy detection (false positives on hashes/uuids).
"""
from __future__ import annotations

import re

# Patterns intentionally chosen to catch the common shell + JSON +
# log shapes acme.sh + curl emit. The match group capture is the
# key/label that we preserve in the output; the value is replaced.
_KV_RE = re.compile(
    r"\b("
    r"token|secret|password|api[_-]?key|auth|bearer|"
    r"CF_API_TOKEN|CF_API_KEY|CF_EMAIL|"
    r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|"
    r"DO_API_TOKEN|GANDI_LIVEDNS_KEY|"
    r"NAMECHEAP_API_KEY|NAMESILO_KEY|LINODE_API_KEY|"
    r"OVH_AK|OVH_AS|HE_Password|DYNU_Secret"
    r")"
    r"\s*[=:]\s*"
    r"\S+",
    re.IGNORECASE,
)

# Bearer/Authorization headers as they appear in curl -v output.
# Match the rest of the line (greedy) so values that contain dots or
# spaces (``Bearer ey.JWT.signature``) are fully redacted.
_BEARER_RE = re.compile(
    r"(Authorization|X-Auth(?:-Key|-Email)?|X-API-Key):\s*\S+(?:\s+\S+)*",
    re.IGNORECASE,
)


def redact_secrets(text: str) -> str:
    """Return ``text`` with recognized secret values replaced.

    Patterns covered:
      - ``token=...`` / ``token: ...`` (case-insensitive)
      - ``CF_API_TOKEN=...`` and similar known DNS provider env vars
      - ``Authorization: Bearer ...`` style HTTP headers
      - ``X-API-Key: ...`` style HTTP headers

    Non-secret content passes through unchanged. The output is safe
    to surface to the LLM / operator without leaking the underlying
    credentials.
    """
    if not text:
        return text
    redacted = _KV_RE.sub(lambda m: f"{m.group(1)}=<REDACTED>", text)
    redacted = _BEARER_RE.sub(
        lambda m: f"{m.group(1).split(':', 1)[0]}: <REDACTED>", redacted,
    )
    return redacted
