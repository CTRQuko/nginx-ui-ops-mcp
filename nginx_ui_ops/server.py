"""MCP server entry point for nginx-ui-ops.

Wires the 8 tools (4 read-only + 4 mutating) and applies the
``allow_mutations`` gate from plugin.toml at registration time —
mutating tools are simply not registered when the gate is closed,
so the LLM cannot invoke them.

Tools are split across modules:
- ``tools.certs``   — cert_list, cert_get, cert_domains_update,
                      cert_issue, cert_deploy_files
- ``tools.nginx``   — nginx_test, nginx_reload
- ``tools.validate``— nginx_cert_validate (uses local openssl, no backend)
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
    from .tools import certs, nginx, validate

    # Always-on (read-only) tools
    mcp.tool()(certs.cert_list)
    mcp.tool()(certs.cert_get)
    mcp.tool()(nginx.nginx_test)
    mcp.tool()(validate.nginx_cert_validate)

    if _allow_mutations():
        log.info("nginx-ui-ops: allow_mutations=true → exposing 4 mutating tools")
        mcp.tool()(certs.cert_domains_update)
        mcp.tool()(certs.cert_issue)
        mcp.tool()(certs.cert_deploy_files)
        mcp.tool()(nginx.nginx_reload)
    else:
        log.info(
            "nginx-ui-ops: allow_mutations=false → only read-only tools "
            "exposed. Set NGINXUI_ALLOW_MUTATIONS=true (or "
            "[security].allow_mutations = true in plugin.toml) to enable "
            "cert_issue, cert_domains_update, cert_deploy_files, nginx_reload."
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
