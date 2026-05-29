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

## [0.4.1] — 2026-05-29 — Security audit closeout

All 14 findings from the internal red-team audit
(`docs/security/audit-2026-05-29-0455.md`) are resolved in this release.
No breaking changes — fully backward-compatible with 0.4.0.

### Fixed

- **[VULN-01] HIGH** — `nginx_write_file` path traversal: validation
  used `startswith()` without canonicalizing `..`. A path like
  `/etc/nginx/../etc/sudoers.d/zzz` was accepted and could write
  arbitrary files. New `nginx_ui_ops/_paths.validate_under_dir`
  helper normalizes + rejects `..` before any I/O.
- **[VULN-02] HIGH** — `nginx_logs()` reassigned its `target`
  parameter (multi-target instance name) with the log file path,
  breaking the tool in production. Renamed the local var to
  `log_path`. The existing tests masked this bug because
  `get_backend` was mocked with `lambda *a, **kw: f` (ignoring args);
  added a signature-checking test.
- **[VULN-03] MEDIUM** — `cert_deploy_files` now validates the
  DB-controlled `ssl_certificate_path` / `ssl_certificate_key_path`
  against an allowlist (`NGINXUI_CERT_DEPLOY_DIRS`, default
  `/etc/nginx/,/etc/ssl/,/usr/local/etc/nginx-ui/,/var/lib/nginx-ui/`)
  before pushing as root.
- **[VULN-04] MEDIUM** — `WrapperLXCBackend.read_file` and
  `DirectSSHBackend.read_file` re-encoded UTF-8 with
  `errors='replace'`, corrupting binary content. Both now use a new
  `_run_ssh_bytes()` path that preserves raw stdout bytes.
  `DockerExecBackend.read_file` was already correct (consistency
  fix).
- **[VULN-05] MEDIUM** — `_acquire_acme_lock` had a TOCTOU between
  `test -e` and `touch`. Replaced with POSIX-atomic `mkdir` on a
  lock directory (`/tmp/nginx-ui-ops-acme.lock.d`). Release uses
  `rmdir`.
- **[VULN-06] MEDIUM** — `acme.sh` `provider_env` exports were
  serialized into the SSH cmdline, visible via `ps aux` / auditd /
  bash history during the issuance window. Now written to a
  chmod-0700 tempfile via stdin and executed with `sh <tmpfile>`.
- **[VULN-07] LOW** — BackendError text surfaced from `acme.sh`
  stderr/stdout now passes through `nginx_ui_ops/_redact.py
  redact_secrets()`, masking known token patterns
  (`CF_API_TOKEN=`, `AWS_SECRET_ACCESS_KEY=`,
  `Authorization: Bearer <jwt>`, generic `token/password/key=value`).
- **[VULN-08] LOW** — `nginx_logs` grep filter is now applied
  client-side via Python `re` against the `tail` output, instead of
  pushed through `sh -c "tail | grep"` to the remote. Removes a
  shell-eval layer. Invalid regex now surfaces as a local
  `ValueError`.
- **[VULN-09] LOW** — `nginx_test_with_diff` validates `target_path`
  through the same `validate_under_dir` helper.
- **[VULN-10] LOW** — `nginx_read_file` ditto (with
  `allow_root=True` to preserve v0.3.0 behavior of reading the
  config dir itself).
- **[VULN-11] INFO** — `CommandResult.notes` no longer leaks the
  backend's `describe()` (SSH alias, LXC ID, container name) by
  default. Gated behind `NGINXUI_INCLUDE_BACKEND_NOTES=true` for
  diagnostics.
- **[VULN-12] INFO** — `_collect_provider_env` replaced prefix
  matching with an explicit per-provider allowlist of documented env
  vars. Stops accidentally exporting `CF_OTHER_SERVICE_TOKEN` and
  similar.
- **[VULN-14] INFO** — `nginx_write_file` now preserves the original
  POSIX mode of the source file when creating its backup (via
  `stat -c %a`). 0600 includes no longer leak through a 0644 backup.

### Added

- `nginx_ui_ops/_paths.py` — shared `validate_under_dir` and
  `validate_under_any` helpers.
- `nginx_ui_ops/_redact.py` — shared `redact_secrets()` helper.
- `tests/test_security_fixes.py` — 35 regression guards, one block
  per VULN. Suite total: 264 (was 229).
- README "SSH hardening" section — addresses [VULN-13] by documenting
  the required `StrictHostKeyChecking yes` config for SSH aliases
  the plugin uses.
- README "Hardening env vars" table documenting
  `NGINXUI_CERT_DEPLOY_DIRS` and `NGINXUI_INCLUDE_BACKEND_NOTES`.

### Backward compatibility

100%. All env vars are new opt-ins with safe defaults. No tool
signatures changed. Plugin manifest credentials list unchanged.

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
