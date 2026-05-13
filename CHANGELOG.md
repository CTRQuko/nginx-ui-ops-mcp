# Changelog

All notable changes to nginx-ui-ops-mcp documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
SemVer.

## Distribución

v0.4.0 (y siguientes hasta nuevo aviso) **NO se publica en PyPI**.
Paquete de uso interno homelab; sin necesidad de descubrimiento
público en PyPI.

Instalación recomendada:

```bash
pip install git+https://github.com/CTRQuko/nginx-ui-ops-mcp.git@v0.4.0
```

O pin por tag en `mimir-mcp/plugin.toml`:

```toml
source = "git+https://github.com/CTRQuko/nginx-ui-ops-mcp.git@v0.4.0"
```

Si en el futuro cambia el caso de uso (multi-tenant, descubrimiento
público, mirror corporativo), ver las vías documentadas en
`~/.claude/plans/mimir-mpc-verificar-si-elegant-sun.md` — Vía A
(token account efímero + project-scope post-bootstrap) o Vía B
(Trusted Publishing via GitHub OIDC).

## [Unreleased]

## [0.4.0] — 2026-05-14 — Multi-target + `docker-exec` backend

### Added

- **Multi-target support** — operate multiple nginx-ui instances from
  one plugin via `NGINXUI_TARGETS=logrono,vps` and per-target env vars
  `NGINXUI_TARGET_<T>_*`. Each of the 20 tools accepts `target: str |
  None = None` as an optional parameter; `None` resolves to
  `NGINXUI_DEFAULT_TARGET` or the first declared target.

- **`docker-exec` backend** (`nginx_ui_ops/backends/docker_exec.py`, NEW
  ~330 LOC) — transport `ssh <alias> 'docker exec <container> <cmd>'`
  for nginx-ui running inside a Docker container (e.g. Hetzner VPS
  with `uozi/nginx-ui:latest`). Implements all 6 abstract methods:
  `run_cmd`, `push_file`, `read_file`, `query_db`, `acme_issue`,
  `from_env`/`from_env_target`. CRLF normalization + tempfile-based
  SQL stdin redirection match the wrapper-lxc gotcha handling.

- **`supports_acme: bool` class attribute** on `NginxUIBackend` (default
  True). Subclass `DockerExecBackend` sets `False` because the upstream
  `uozi/nginx-ui` container doesn't ship acme.sh. The `cert_issue` tool
  checks this BEFORE invoking the backend and returns a legible error
  message instead of crashing.

- **`factory.list_targets()`, `factory.default_target()`,
  `factory.supports_acme(target)`** — public API for introspection.

- **`from_env_target(target)` classmethod** on all backends — reads
  `NGINXUI_TARGET_<TARGET>_*` env vars. Legacy `from_env()` still
  works for single-target setups.

- **Multi-target stage in setup wizard** — `nginxui_setup()` returns
  `status: ready_multi_target` or `status: multi_target_partial` when
  `NGINXUI_TARGETS` is declared. Legacy flow intact for single-target.

### Changed

- **`backends/factory.py` rewrite** — singleton `_cached` becomes
  `dict[str, NginxUIBackend]` keyed by target name. Thread-safe per
  target.

- **20 tools** add `target: str | None = None` param. Backward
  compatible: callers that don't pass `target` get the default
  (legacy = NGINXUI_BACKEND, multi-target = NGINXUI_DEFAULT_TARGET or
  first declared).

- **`plugin.toml`** declares wildcard credential_refs
  `NGINXUI_TARGET_*_*` so mimir vault accepts per-target patterns
  without enumerating each target. Legacy single-target vars retained
  for backward-compat.

### Backward compatibility

- 100% backward compatible. v0.3.x callers (using `NGINXUI_BACKEND` +
  legacy single-target vars, no `target` arg in tool calls) keep
  working identically.
- The wizard detects multi-target mode automatically via presence of
  `NGINXUI_TARGETS`.

## [0.3.1] — (no formal release)

Minor fixes:
- `manifest`: declare `NGINXUI_ALLOW_MUTATIONS` in `credential_refs`
- `docs`: clarify mutations gating real path in README

## [0.3.0] — 2026-05-06 — Diagnostics + ops tools

### Added
- 21 tools total (1 wizard + 12 read-only + 8 mutating)
- `tools/diagnostics.py` — `nginx_status`, `nginx_dump_config`,
  `nginx_logs`, `nginx_compiled_with`, `nginx_active_conns`,
  `nginx_pending_changes`, `nginx_test_with_diff`, `nginx_read_file`
- `tools/ops.py` — `nginx_write_file` (atomic backup + rollback),
  `nginx_full_restart`, `nginx_reopen_logs`, `nginx_quit`

## [0.2.0] — 2026-05-06 — Setup wizard

Conversational `nginxui_setup` wizard for LLM-guided onboarding.

## [0.1.0] — 2026-05-06 — Initial release

8 tools (1 setup + 4 read-only + 4 mutating) for cert management on
nginx-ui via SSH/wrapper transport.
