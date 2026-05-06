"""Tests for the conversational setup wizard.

The wizard is read-only and idempotent: each test sets up the
``os.environ`` state and verifies the structured payload.

Stages tested:
  - needs_backend (NGINXUI_BACKEND unset)
  - invalid_backend (unsupported value)
  - needs_backend_config (per-backend required vars missing)
  - ready_readonly (backend OK, optional creds suggested)
  - ready_full (everything in place)
"""
from __future__ import annotations

import pytest

from nginx_ui_ops.tools.setup_wizard import nginxui_setup


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Each test starts with all NGINXUI_*/CF_*/AWS_*/DO_* unset."""
    for key in list(__import__("os").environ.keys()):
        if (
            key.startswith("NGINXUI_")
            or key.startswith("CF_")
            or key.startswith("AWS_")
            or key.startswith("DO_")
            or key.startswith("GANDI_")
            or key.startswith("NAMECHEAP_")
            or key.startswith("NAMESILO_")
            or key.startswith("LINODE_")
            or key.startswith("OVH_")
            or key.startswith("HE_")
            or key.startswith("DYNU_")
        ):
            monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------------------
# Stage 1: needs_backend
# ---------------------------------------------------------------------------

def test_no_backend_returns_needs_backend():
    result = nginxui_setup()
    assert result["status"] == "needs_backend"
    # Prompt names the credential to set, not just text.
    assert result["prompt"]["credential_ref"] == "NGINXUI_BACKEND"
    # Both backend options offered.
    options = result["prompt"]["options"]
    values = {o["value"] for o in options}
    assert values == {"wrapper-lxc", "direct-ssh"}


def test_needs_backend_next_action_mentions_router_add_credential():
    """Wizard must instruct the LLM to use mimir's router_add_credential."""
    result = nginxui_setup()
    assert "router_add_credential" in result["next_action"]


# ---------------------------------------------------------------------------
# Stage 1b: invalid_backend
# ---------------------------------------------------------------------------

def test_invalid_backend_value_returns_error_status(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "magic-cloud")
    result = nginxui_setup()
    assert result["status"] == "invalid_backend"
    assert result["current_value"] == "magic-cloud"
    # Lists valid options.
    assert "wrapper-lxc" in result["message"]
    assert "direct-ssh" in result["message"]


def test_backend_value_is_case_insensitive(monkeypatch):
    """'WRAPPER-LXC' should be normalized internally."""
    monkeypatch.setenv("NGINXUI_BACKEND", "WRAPPER-LXC")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    result = nginxui_setup()
    # Should not be invalid_backend.
    assert result["status"] != "invalid_backend"


# ---------------------------------------------------------------------------
# Stage 2: needs_backend_config (wrapper-lxc)
# ---------------------------------------------------------------------------

def test_wrapper_lxc_without_pve_alias_asks_for_it(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    result = nginxui_setup()
    assert result["status"] == "needs_backend_config"
    assert result["backend"] == "wrapper-lxc"
    refs = {p["credential_ref"] for p in result["prompts"]}
    assert "NGINXUI_PVE_SSH_ALIAS" in refs
    assert "NGINXUI_LXC_ID" in refs


def test_wrapper_lxc_with_only_pve_alias_still_needs_lxc_id(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    result = nginxui_setup()
    assert result["status"] == "needs_backend_config"
    refs = {p["credential_ref"] for p in result["prompts"]}
    # Only LXC_ID still missing — alias already set.
    assert refs == {"NGINXUI_LXC_ID"}


def test_wrapper_lxc_complete_progresses_to_ready(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    result = nginxui_setup()
    # Backend OK; optional suggestions still missing → ready_readonly.
    assert result["status"] == "ready_readonly"


# ---------------------------------------------------------------------------
# Stage 2: needs_backend_config (direct-ssh)
# ---------------------------------------------------------------------------

def test_direct_ssh_needs_host(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "direct-ssh")
    result = nginxui_setup()
    assert result["status"] == "needs_backend_config"
    refs = {p["credential_ref"] for p in result["prompts"]}
    assert refs == {"NGINXUI_HOST"}


def test_direct_ssh_with_host_progresses_to_ready(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "direct-ssh")
    monkeypatch.setenv("NGINXUI_HOST", "ngx-host")
    result = nginxui_setup()
    assert result["status"] == "ready_readonly"


# ---------------------------------------------------------------------------
# Stage 3: ready_readonly with optional suggestions
# ---------------------------------------------------------------------------

def test_ready_readonly_suggests_acme_home_when_unset(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    result = nginxui_setup()
    assert result["status"] == "ready_readonly"
    refs_in_suggestions = {
        s.get("credential_ref")
        for s in result["optional_suggestions"]
        if "credential_ref" in s
    }
    assert "NGINXUI_ACME_HOME" in refs_in_suggestions


def test_ready_readonly_suggests_dns_provider_when_no_creds(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    result = nginxui_setup()
    dns_suggestion = next(
        (s for s in result["optional_suggestions"]
         if s.get("what") == "DNS-01 provider credentials"),
        None,
    )
    assert dns_suggestion is not None
    # Cloudflare is in the offered options.
    option_values = {o["value"] for o in dns_suggestion["options"]}
    assert "cloudflare" in option_values
    assert "skip" in option_values  # operator can opt out of mutations entirely


def test_ready_readonly_no_acme_suggestion_when_set(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    monkeypatch.setenv("NGINXUI_ACME_HOME", "/home/me/.acme.sh")
    result = nginxui_setup()
    refs = {
        s.get("credential_ref")
        for s in result.get("optional_suggestions", [])
        if "credential_ref" in s
    }
    assert "NGINXUI_ACME_HOME" not in refs


def test_ready_readonly_no_dns_suggestion_when_provider_detected(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    monkeypatch.setenv("NGINXUI_ACME_HOME", "/home/me/.acme.sh")
    monkeypatch.setenv("CF_API_TOKEN", "tok")
    monkeypatch.setenv("CF_ZONE_ID", "zone")
    result = nginxui_setup()
    # All optional config present → ready_full.
    assert result["status"] == "ready_full"
    assert result["dns_provider_detected"] == "cloudflare"


# ---------------------------------------------------------------------------
# Stage 4: ready_full
# ---------------------------------------------------------------------------

def test_ready_full_with_mutations_disabled_says_so(monkeypatch):
    """All creds set but NGINXUI_ALLOW_MUTATIONS not 'true' → message
    explains how to enable mutations."""
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    monkeypatch.setenv("NGINXUI_ACME_HOME", "/home/me/.acme.sh")
    monkeypatch.setenv("CF_API_TOKEN", "tok")
    monkeypatch.setenv("CF_ZONE_ID", "zone")
    result = nginxui_setup()
    assert result["status"] == "ready_full"
    assert result["mutations_enabled"] is False
    assert "NGINXUI_ALLOW_MUTATIONS" in result["message"]


def test_ready_full_with_mutations_enabled(monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    monkeypatch.setenv("NGINXUI_ACME_HOME", "/home/me/.acme.sh")
    monkeypatch.setenv("CF_API_TOKEN", "tok")
    monkeypatch.setenv("CF_ZONE_ID", "zone")
    monkeypatch.setenv("NGINXUI_ALLOW_MUTATIONS", "true")
    result = nginxui_setup()
    assert result["status"] == "ready_full"
    assert result["mutations_enabled"] is True


# ---------------------------------------------------------------------------
# Idempotence
# ---------------------------------------------------------------------------

def test_wizard_is_idempotent(monkeypatch):
    """Calling the wizard repeatedly with the same env produces the
    same payload — no side effects, no state mutation."""
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    a = nginxui_setup()
    b = nginxui_setup()
    assert a == b


# ---------------------------------------------------------------------------
# DNS provider detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("env_key,expected_provider", [
    ("CF_API_TOKEN", "cloudflare"),
    ("AWS_ACCESS_KEY_ID", "route53"),
    ("DO_API_TOKEN", "digitalocean"),
    ("GANDI_LIVEDNS_KEY", "gandi"),
    ("NAMECHEAP_API_KEY", "namecheap"),
])
def test_dns_provider_detection_per_provider(env_key, expected_provider, monkeypatch):
    monkeypatch.setenv("NGINXUI_BACKEND", "wrapper-lxc")
    monkeypatch.setenv("NGINXUI_PVE_SSH_ALIAS", "pve-test")
    monkeypatch.setenv("NGINXUI_LXC_ID", "100")
    monkeypatch.setenv("NGINXUI_ACME_HOME", "/h")
    monkeypatch.setenv(env_key, "value")
    result = nginxui_setup()
    assert result["status"] == "ready_full"
    assert result["dns_provider_detected"] == expected_provider
