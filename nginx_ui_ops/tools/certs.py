"""Cert management tools — populated in Step 5+6."""
from __future__ import annotations


def cert_list(deleted: bool = False) -> list[dict]:
    """List certs from the nginx-ui SQLite DB. (Skeleton — Step 5.)"""
    raise NotImplementedError("cert_list — wired in Step 5")


def cert_get(cert_id: int) -> dict:
    """Fetch one cert with on-disk + parsed status. (Skeleton — Step 5.)"""
    raise NotImplementedError("cert_get — wired in Step 5")


def cert_domains_update(cert_id: int, domains: list[str]) -> dict:
    """UPDATE certs.domains + restart nginx-ui. (Skeleton — Step 5.)"""
    raise NotImplementedError("cert_domains_update — wired in Step 5")


def cert_issue(
    domains: list[str],
    key_type: str = "P256",
    dns_provider: str = "dns_cf",
    force: bool = False,
) -> dict:
    """Issue cert via acme.sh, idempotent unless force=True. (Skeleton — Step 6.)"""
    raise NotImplementedError("cert_issue — wired in Step 6")


def cert_deploy_files(cert_id: int) -> dict:
    """pct-push fullchain + key to paths from DB. (Skeleton — Step 6.)"""
    raise NotImplementedError("cert_deploy_files — wired in Step 6")
