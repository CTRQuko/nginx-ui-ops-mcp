# nginx-ui-ops

> MCP server for **cert management and ops** on a remote
> [nginx-ui](https://nginxui.com) instance — fills the gap that nginx-ui's
> native MCP doesn't cover (cert issue/deploy, DB updates, deep diagnostics).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python versions](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

**Status**: 🚧 Alpha (`v0.3.0`). Designed to be portable and
publishable — not tied to any specific homelab.

## What it does

21 MCP tools — 1 setup wizard + 12 read-only + 8 mutating:

### Setup (always available)
| Tool | Purpose |
|------|---------|
| `nginxui_setup` | Conversational onboarding wizard — detects missing env vars and walks the operator through them |

### Cert management (read-only)
| Tool | Purpose |
|------|---------|
| `cert_list` | List certs from nginx-ui's SQLite DB |
| `cert_get` | Detail of one cert + on-disk + parsed status |
| `nginx_cert_validate` | What the world actually sees (openssl s_client) |

### Nginx control (read-only)
| Tool | Purpose |
|------|---------|
| `nginx_test` | `nginx -t` — config syntax check |
| `nginx_status` | systemd state + worker count + uptime |
| `nginx_dump_config` | `nginx -T` — full effective merged config |
| `nginx_logs` | snapshot tail + grep of any nginx log file |
| `nginx_compiled_with` | parsed `nginx -V`: version, TLS lib, modules, configure flags |
| `nginx_active_conns` | runtime stats from `stub_status` (if mounted) |
| `nginx_pending_changes` | files modified since service start |
| `nginx_test_with_diff` | validate a proposed change without touching prod + unified diff |
| `nginx_read_file` | raw read of any file under `/etc/nginx/**` |

### Cert mutations (gated)
| Tool | Purpose |
|------|---------|
| `cert_issue` | Issue cert via acme.sh, idempotent |
| `cert_domains_update` | UPDATE SANs in DB + restart nginx-ui |
| `cert_deploy_files` | Push fullchain + key to paths from DB |

### Nginx mutations (gated)
| Tool | Purpose |
|------|---------|
| `nginx_reload` | `nginx -t && nginx -s reload` |
| `nginx_write_file` | atomic write under `/etc/nginx/` + implicit `nginx -t` + rollback |
| `nginx_full_restart` | `systemctl restart nginx` (drops connections; safer to use reload) |
| `nginx_reopen_logs` | `nginx -s reopen` (after logrotate, log volume remount) |
| `nginx_quit` | `nginx -s quit` (graceful shutdown — operator must start again) |

Mutating tools are **gated** behind `[security].allow_mutations = true`
in `plugin.toml` (or `NGINXUI_ALLOW_MUTATIONS=true` env var). Default
off — read-only by default. Operator opts in explicitly.

## Why not just use nginx-ui's native MCP?

The native MCP covers vhost / config management, but **not**:

- Issuing new certs via acme.sh + DNS-01 with arbitrary providers
- Deploying cert files to nginx-ui's expected paths
- Direct DB updates (e.g. add a SAN to an existing cert)
- Restarting the nginx-ui daemon
- Validating what's actually served vs what the DB says
- **Direct nginx control** outside the UI: `nginx -t -p staging`, full
  `nginx -T` dump, `nginx -V` parsed, `stub_status` runtime metrics,
  log tail/grep, "what files have been touched since last reload",
  atomic config writes with backup/rollback, `nginx -s reopen` after
  logrotate, `systemctl restart` when reload isn't enough, graceful quit.

This plugin runs alongside the native MCP — both can be declared in
your `.mcp.json` or mimir manifest. The native MCP handles vhost
configs through nginx-ui; this one handles certs and direct nginx ops.

## Backends

The plugin doesn't assume how to reach the nginx-ui host. Two backends
ship in `v0.1.0`, more are PR-friendly.

### `wrapper-lxc`

For Proxmox + LXC setups with a `claude-wrapper` script restricting
allowed commands. Operator workflow:

```
mimir/MCP client
   ↓ subprocess stdio
plugin nginx-ui-ops
   ↓ ssh <pve-alias>
Proxmox host
   ↓ pct exec <lxc-id> -- /usr/local/bin/claude-wrapper <cmd>
nginx-ui LXC
```

**Env vars (set in `secrets/` and reference via `credential_refs`):**

```
NGINXUI_BACKEND=wrapper-lxc
NGINXUI_PVE_SSH_ALIAS=<your-pve-alias>      # e.g. "pve2"
NGINXUI_LXC_ID=<lxc-id>                     # e.g. "104"
NGINXUI_WRAPPER_PATH=/usr/local/bin/claude-wrapper   # optional
NGINXUI_SUDO_METHOD=nopasswd|password       # default nopasswd
NGINXUI_SUDO_PASSWORD_REF=<path-to-pw-file> # only if SUDO_METHOD=password
```

### `direct-ssh`

For nginx-ui running on a plain SSH-accessible host (bare metal, VM,
container with SSH). No Proxmox, no wrapper.

```
mimir/MCP client
   ↓ subprocess stdio
plugin nginx-ui-ops
   ↓ ssh <user>@<host>
nginx-ui host
```

**Env vars:**

```
NGINXUI_BACKEND=direct-ssh
NGINXUI_HOST=<host-or-alias>                # e.g. "nginx.example.local"
NGINXUI_SSH_USER=<user>                     # e.g. "ops"
NGINXUI_SUDO_METHOD=nopasswd|password|none  # "none" if user is root
```

### Other backends

PRs welcome for:
- `docker-exec` — nginx-ui running in a Docker container
- `local` — nginx-ui on the same host as the MCP server
- `kubernetes` — nginx-ui pod with `kubectl exec`

## DNS providers

The plugin is **provider-agnostic**. `cert_issue` takes a
`dns_provider` string (e.g. `dns_cf`, `dns_aws`, `dns_do`) that's
passed literally to `acme.sh --dns <provider>`. Required env vars
for that provider must be set in your scoped credentials and are
forwarded transparently to the acme.sh subprocess.

acme.sh supports 100+ providers — see
[acme.sh dnsapi docs](https://github.com/acmesh-official/acme.sh/wiki/dnsapi)
for the full list.

Common examples:

```bash
# Cloudflare
CF_API_TOKEN=<token>
CF_ZONE_ID=<zone-id>          # explicit Zone ID — required if using
                              # restricted Cloudflare API tokens
# or legacy:
CF_API_KEY=<global-api-key>
CF_EMAIL=<cf-account-email>

# Route 53
AWS_ACCESS_KEY_ID=<id>
AWS_SECRET_ACCESS_KEY=<secret>
AWS_REGION=us-east-1

# DigitalOcean
DO_API_TOKEN=<token>
```

## Install (standalone)

```bash
pip install nginx-ui-ops-mcp     # not yet published
# or from source:
pip install git+https://github.com/CTRQuko/nginx-ui-ops-mcp
```

Run:

```bash
NGINXUI_BACKEND=wrapper-lxc \
NGINXUI_PVE_SSH_ALIAS=pve2 \
NGINXUI_LXC_ID=104 \
nginx-ui-ops-mcp
```

## Install (mimir plugin)

Drop the `plugin.toml` into `<mimir-root>/plugins/nginx-ui-ops/` (this
repo as a sub-checkout or symlink), set the env vars in your scoped
credentials, restart mimir.

## Easy setup — let the LLM walk you through it

The plugin ships a conversational wizard tool, ``nginxui_setup``,
designed for users who don't want to read this README cover-to-cover.
Just ask the LLM:

> "Help me set up nginx-ui-ops"

The LLM calls ``nginxui_setup()`` and the tool returns a structured
payload telling it exactly what to ask you:

```
LLM:  ¿Cómo está accesible tu instancia de nginx-ui?
       a) En un LXC de Proxmox con claude-wrapper
       b) En un host con SSH directo
You:  a, alias 'pve2', LXC 104
LLM:  [persists 3 credentials in mimir's vault via router_add_credential]
LLM:  ¿Usas Cloudflare para DNS-01? Si sí, dame el API token y zone ID
You:  [pegar valores]
LLM:  [persists CF_API_TOKEN + CF_ZONE_ID]
LLM:  ✅ Setup completo. Reinicia el cliente MCP para que las env vars surtan efecto.
```

You don't edit JSON, don't touch ``.mcp.json``, don't read the
"Backends" section below. The wizard is **idempotent** — call it any
time to check status, fix a missing variable, or expand from
read-only to mutating tools.

The wizard is read-only and always available, regardless of the
``allow_mutations`` gate.

## Quick start

Read-only diagnostic on a hypothetical Proxmox+LXC setup:

```bash
export NGINXUI_BACKEND=wrapper-lxc
export NGINXUI_PVE_SSH_ALIAS=pve-prod        # your SSH alias
export NGINXUI_LXC_ID=204                    # your LXC ID
uv run nginx-ui-ops-mcp
```

From an MCP client:

```python
cert_list()
# → [{id: 1, domains: ["*.example.com", "example.com"], days_remaining: 73, ...}]

nginx_cert_validate("foo.example.com")
# → {sans: [...], matches_hostname: true, days_remaining: 73}

nginx_test()
# → {ok: true, stdout: "syntax is ok"}

# v0.3.0 diagnostics
nginx_status()
# → {active: true, sub_state: "running", main_pid: 12345, worker_count: 4,
#    started_at: "2026-05-04T10:00:00Z", uptime_seconds: 8632, ...}

nginx_active_conns()
# → {enabled: true, active_connections: 42, accepts: 1000, requests: 5000, ...}
# Or, if stub_status not mounted:
# → {enabled: false, note: "To enable, add a `location = /nginx_status` block..."}

nginx_pending_changes()
# → {has_pending: true, pending_files: ["/etc/nginx/sites-available/foo.conf"], ...}

nginx_test_with_diff(
    "/etc/nginx/sites-available/foo.conf",
    "server { listen 443 ssl; ... }\n",
)
# → {ok: true, diff: "+server { listen 443 ssl;\n-server { listen 80;\n", ...}
# nginx -t against a staged copy — production untouched.
```

To unlock mutations (cert renewal, deploy, reload):

```bash
export NGINXUI_ALLOW_MUTATIONS=true
export CF_API_TOKEN=...
export CF_ZONE_ID=...
uv run nginx-ui-ops-mcp
```

```python
# Add a SAN to an existing cert (DB update + restart nginx-ui)
cert_domains_update(1, ["*.example.com", "example.com", "*.apps.example.com"])

# Issue a new cert (idempotent — skips if cert has >30d remaining)
cert_issue(["*.example.com", "example.com", "*.apps.example.com"])
# → {action: "issued_new", fullchain_path: "...", key_path: "..."}
# Or: {action: "kept_existing", days_remaining: 73, ...}

# Deploy the issued cert to nginx-ui paths + reload
cert_deploy_files(1)
# → {ok: true, nginx_test_passed: true, nginx_reloaded: true}

# v0.3.0 ops — atomic config edit with rollback
nginx_write_file(
    "/etc/nginx/conf.d/security_headers.conf",
    "add_header X-Frame-Options DENY always;\n",
)
# → {ok: true, backup_path: "...bak-20260506-181500", nginx_test_passed: true,
#    rolled_back: false}
# If the new content fails nginx -t, the backup is restored automatically.

nginx_reopen_logs()  # after logrotate
nginx_full_restart()  # nuclear option — drops connections; runs nginx -t first
nginx_quit()  # graceful shutdown — service is down until manual start
```

## Safety features

- **Idempotent `cert_issue`** — if a valid cert (>30 days remaining)
  exists for the requested domains, it's returned without contacting
  Let's Encrypt. Override with `force=True`.
- **Lock file** — `cert_issue` takes `/tmp/acme-lock` to prevent
  collisions with acme.sh's renewal cron.
- **Implicit `nginx -t` before `nginx_reload` and `nginx_full_restart`**
  — never reload/restart with a broken config.
- **`nginx_write_file` rollback** — backs up the prior content to a
  timestamped `.bak-` file, runs `nginx -t` after writing, restores
  the backup if the test fails. New files (no backup) get rm'd on
  failure so a broken include can't sit in the tree.
- **`nginx_test_with_diff`** — validate a proposed change against a
  staged copy of `/etc/nginx/`. Production untouched, returns the
  unified diff vs current.
- **Path validation** — `nginx_write_file` and `nginx_read_file`
  refuse paths outside `NGINXUI_CONFIG_DIR` (default `/etc/nginx`)
  to avoid being a generic file-mover.
- **Mutation gate** — read-only by default; the 8 mutating tools off
  until operator opts in via `NGINXUI_ALLOW_MUTATIONS=true`.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Built on top of:
- [nginx-ui](https://nginxui.com) — the panel
- [acme.sh](https://github.com/acmesh-official/acme.sh) — the cert
  issuance engine
- [FastMCP](https://github.com/jlowin/fastmcp) — the MCP framework
