"""nginx control tools (test/reload). Wired in Step 7."""
from __future__ import annotations


def nginx_test() -> dict:
    """Run ``nginx -t`` via backend. (Skeleton — Step 7.)"""
    raise NotImplementedError("nginx_test — wired in Step 7")


def nginx_reload() -> dict:
    """Reload nginx after implicit test pass. (Skeleton — Step 7.)"""
    raise NotImplementedError("nginx_reload — wired in Step 7")
