"""nginx-ui-ops — MCP server for nginx-ui cert management.

Public surface:
- ``server.main`` — CLI entry point (registered as ``nginx-ui-ops-mcp``)
- ``backends.NginxUIBackend`` — abstract transport interface
- ``backends.get_backend`` — factory selecting backend from env

The plugin exposes 8 MCP tools (4 read-only + 4 mutating) that operate
on a remote nginx-ui instance through a configurable transport backend.
See ``README.md`` for backend selection and per-backend env vars.
"""
__version__ = "0.1.0"
