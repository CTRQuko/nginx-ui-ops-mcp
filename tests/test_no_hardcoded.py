"""CI-style test: enforce anonymization.

The plugin is meant to be publishable. No operator-specific data
should leak in source. This test greps the source tree for patterns
that look like:

- Private IP addresses (RFC1918 + Tailscale)
- Specific domain names (the operator's homelab domain, etc.)
- Hardcoded LXC IDs in numeric ranges typical of homelab setups
- Suspicious literal "secret-like" strings

Whitelist documented inline — adjust as the project evolves.
"""
from __future__ import annotations

import re
from pathlib import Path

# Paths considered "source code". Tests + docs are inspected for
# example data with explicit "example" markers.
SOURCE_ROOT = Path(__file__).resolve().parent.parent / "nginx_ui_ops"


# --- patterns to detect -----------------------------------------------------

# RFC1918 + Tailscale + link-local
PRIVATE_IPV4_PATTERN = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|100\.(?:6[4-9]|7\d|8\d|9\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# Common operator-specific TLDs / subdomains that have shown up in
# the reference logs. Add more if more leaks are detected.
OPERATOR_DOMAINS = [
    "casaredes",  # operator's homelab domain
]
OPERATOR_DOMAIN_PATTERN = re.compile(
    r"\b(?:" + "|".join(OPERATOR_DOMAINS) + r")\b",
    re.IGNORECASE,
)

# UUIDs (could be node_secret, JWT secret, crypto secret, CF token, etc.)
UUID_OR_HEX_TOKEN_PATTERN = re.compile(
    r"\b(?:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUID
    r"|cfut_[A-Za-z0-9]{30,}"  # CF token prefix
    r"|tskey-[a-z]+-[A-Za-z0-9]{20,}"  # Tailscale key
    r"|ghp_[A-Za-z0-9]{30,}"  # GitHub PAT
    r")\b",
    re.IGNORECASE,
)


# --- whitelist ---------------------------------------------------------------
# Allowed example/dummy data in source. These are explicitly fake and
# documented. Anything matching these can appear in source freely.
WHITELIST = {
    # IETF reserved example domains.
    "example.com",
    "example.org",
    "example.net",
    # IETF reserved IPs (RFC5737)
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
    # Common documentation defaults that are NOT operator-specific:
    "127.0.0.1",
    "localhost",
}


def _iter_source_files() -> list[Path]:
    return list(SOURCE_ROOT.rglob("*.py"))


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _strip_whitelist_lines(text: str) -> str:
    """Drop lines containing whitelisted strings before pattern checks."""
    out = []
    for line in text.splitlines():
        if any(w in line for w in WHITELIST):
            continue
        # Skip comments that explicitly mention "example" (docstrings
        # of public APIs that show usage with example.com).
        stripped = line.strip()
        if stripped.startswith("#") and "example" in stripped.lower():
            continue
        out.append(line)
    return "\n".join(out)


# --- the tests --------------------------------------------------------------

def test_no_private_ipv4_in_source():
    """Source must not contain RFC1918 / Tailscale IPs that would
    pin the code to the operator's network."""
    offenders: list[tuple[Path, str]] = []
    for path in _iter_source_files():
        text = _strip_whitelist_lines(_read(path))
        for m in PRIVATE_IPV4_PATTERN.finditer(text):
            offenders.append((path, m.group(0)))
    assert not offenders, (
        "Private IPs hardcoded in source — must come from env vars instead:\n"
        + "\n".join(f"  {p.relative_to(SOURCE_ROOT.parent)}: {ip}" for p, ip in offenders)
    )


def test_no_operator_domains_in_source():
    """Source must not contain the operator's specific domain names."""
    offenders: list[tuple[Path, str]] = []
    for path in _iter_source_files():
        text = _read(path)
        for m in OPERATOR_DOMAIN_PATTERN.finditer(text):
            offenders.append((path, m.group(0)))
    assert not offenders, (
        "Operator-specific domain in source:\n"
        + "\n".join(f"  {p.relative_to(SOURCE_ROOT.parent)}: {d}" for p, d in offenders)
    )


def test_no_secrets_or_tokens_in_source():
    """No UUIDs / CF tokens / Tailscale keys / GitHub PATs in source."""
    offenders: list[tuple[Path, str]] = []
    for path in _iter_source_files():
        text = _read(path)
        for m in UUID_OR_HEX_TOKEN_PATTERN.finditer(text):
            offenders.append((path, m.group(0)[:30] + "..."))
    assert not offenders, (
        "Secret-shaped string in source:\n"
        + "\n".join(f"  {p.relative_to(SOURCE_ROOT.parent)}: {s}" for p, s in offenders)
    )


def test_no_specific_lxc_ids_in_source():
    """Hardcoded numeric LXC IDs in the typical homelab range
    (100-999) suggest the code is pinned to a specific container.
    We allow port numbers and common defaults via context — the test
    is conservative, false positives can be whitelisted by reformatting
    as comments referring to "LXC <ID>" rather than bare numbers in
    code paths."""
    # This test is intentionally lenient — only fails on contexts
    # that look like LXC ID assignment.
    pattern = re.compile(
        r"(?:lxc[_-]?id|container[_-]?id|ctid)\s*=\s*[\"']?(\d{2,4})",
        re.IGNORECASE,
    )
    offenders: list[tuple[Path, str]] = []
    for path in _iter_source_files():
        for line in _read(path).splitlines():
            stripped = line.strip()
            # Allow inside docstrings explicitly using "e.g." or "100"
            # in comments.
            if stripped.startswith("#") or stripped.startswith('"""'):
                continue
            for m in pattern.finditer(line):
                offenders.append((path, line.strip()))
                break
    assert not offenders, (
        "Hardcoded LXC ID found:\n"
        + "\n".join(f"  {p.relative_to(SOURCE_ROOT.parent)}: {ln}" for p, ln in offenders)
    )
