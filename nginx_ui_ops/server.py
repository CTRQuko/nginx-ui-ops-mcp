"""MCP server entry point for nginx-ui-ops.

Wires 21 tools (1 wizard + 12 read-only + 8 mutating) and applies the
``allow_mutations`` gate from plugin.toml at registration time —
mutating tools are simply not registered when the gate is closed,
so the LLM cannot invoke them.

Tools are split across modules:

- ``tools.setup_wizard`` — nginxui_setup (always available)
- ``tools.certs``        — cert_list, cert_get, cert_domains_update,
                           cert_issue, cert_deploy_files
- ``tools.nginx``        — nginx_test, nginx_reload
- ``tools.validate``     — nginx_cert_validate (uses local openssl, no backend)
- ``tools.diagnostics``  — nginx_status, nginx_dump_config, nginx_logs,
                           nginx_compiled_with, nginx_active_conns,
                           nginx_pending_changes, nginx_test_with_diff,
                           nginx_read_file (all read-only — v0.3.0)
- ``tools.ops``          — nginx_write_file, nginx_full_restart,
                           nginx_reopen_logs, nginx_quit (mutating — v0.3.0)
"""
from __future__ import annotations

import logging
import os

from mcp.server.fastmcp import FastMCP

log = logging.getLogger(__name__)

mcp = FastMCP("nginx-ui-ops")


def _allow_mutations() -> bool:
    """Read the mutation gate.

    Source of truth in production is the plugin.toml ``[security].allow_mutations``,
    which mimir parses and exposes via env var ``NGINXUI_ALLOW_MUTATIONS``.
    For standalone use (no mimir), the same env var works as override.

    Default false — operator opts in explicitly.
    """
    raw = os.environ.get("NGINXUI_ALLOW_MUTATIONS", "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _register_tools() -> None:
    """Register tools on the FastMCP instance.

    Read-only tools always register. Mutating tools register only when
    the mutation gate is open. The gate is checked once at startup —
    flipping it requires plugin restart.
    """
    # Imports inside the function so the modules are loaded lazily,
    # which keeps unit tests cheap.
    from .tools import certs, diagnostics, nginx, ops, setup_wizard, validate

    # Always-on (read-only) tools.
    # nginxui_setup is the conversational onboarding wizard — always
    # available regardless of the mutation gate. Read-only by design;
    # it returns instructions that the LLM executes via mimir's
    # router_add_credential. Listed FIRST so it's discoverable when
    # a fresh installation has nothing else configured.
    mcp.tool()(setup_wizard.nginxui_setup)

    # Cert read-only.
    mcp.tool()(certs.cert_list)
    mcp.tool()(certs.cert_get)

    # Nginx control read-only.
    mcp.tool()(nginx.nginx_test)
    mcp.tool()(validate.nginx_cert_validate)

    # Diagnostics read-only (v0.3.0).
    mcp.tool()(diagnostics.nginx_status)
    mcp.tool()(diagnostics.nginx_dump_config)
    mcp.tool()(diagnostics.nginx_logs)
    mcp.tool()(diagnostics.nginx_compiled_with)
    mcp.tool()(diagnostics.nginx_active_conns)
    mcp.tool()(diagnostics.nginx_pending_changes)
    mcp.tool()(diagnostics.nginx_test_with_diff)
    mcp.tool()(diagnostics.nginx_read_file)

    if _allow_mutations():
        log.info(
            "nginx-ui-ops: allow_mutations=true → exposing 8 mutating tools "
            "(4 cert + 4 nginx ops)"
        )
        # Cert mutations.
        mcp.tool()(certs.cert_domains_update)
        mcp.tool()(certs.cert_issue)
        mcp.tool()(certs.cert_deploy_files)
        # Nginx control mutations.
        mcp.tool()(nginx.nginx_reload)
        # Nginx ops mutations (v0.3.0).
        mcp.tool()(ops.nginx_write_file)
        mcp.tool()(ops.nginx_full_restart)
        mcp.tool()(ops.nginx_reopen_logs)
        mcp.tool()(ops.nginx_quit)
    else:
        log.info(
            "nginx-ui-ops: allow_mutations=false → only read-only tools "
            "exposed (1 wizard + 12 read-only). Set NGINXUI_ALLOW_MUTATIONS=true "
            "(or [security].allow_mutations = true in plugin.toml) to enable "
            "the 8 mutating tools (cert_issue, cert_domains_update, "
            "cert_deploy_files, nginx_reload, nginx_write_file, "
            "nginx_full_restart, nginx_reopen_logs, nginx_quit)."
        )


def main() -> None:
    """CLI entry — runs the MCP server over stdio."""
    logging.basicConfig(
        level=os.environ.get("NGINXUI_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    _register_tools()
    mcp.run()


if __name__ == "__main__":
    main()
