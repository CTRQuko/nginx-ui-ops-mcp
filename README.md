# nginx-ui-ops

> MCP server for **cert management and ops** on a remote
> [nginx-ui](https://nginxui.com) instance — fills the gap that nginx-ui's
> native MCP doesn't cover (cert issue/deploy, DB updates, deep diagnostics).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python versions](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

**Status**: 🚧 Alpha (`v0.1.0` in development). Designed to be portable
and publishable — not tied to any specific homelab.

## What it does

8 MCP tools, split across 4 read-only and 4 mutating:

| Tool | Type | Purpose |
|------|------|---------|
| `cert_list` | read | List certs from nginx-ui's SQLite DB |
| `cert_get` | read | Detail of one cert + on-disk + parsed status |
| `nginx_test` | read | `nginx -t` — config syntax check |
| `nginx_cert_validate` | read | What the world actually sees (openssl s_client) |
| `cert_issue` | mutate | Issue cert via acme.sh, idempotent |
| `cert_domains_update` | mutate | UPDATE SANs in DB + restart nginx-ui |
| `cert_deploy_files` | mutate | Push fullchain + key to paths from DB |
| `nginx_reload` | mutate | `nginx -t && nginx -s reload` |

Mutating tools are **gated** behind `[security].allow_mutations = true`
in `plugin.toml` (or `NGINXUI_ALLOW_MUTATIONS=true` env var). Default
off — read-only by default. Operator opts in explicitly.

## Why not just use nginx-ui's native MCP?

The native MCP covers vhost / config management, but **not**:

- Issuing new certs via acme.sh
- DNS-01 challenges with arbitrary providers
- Deploying cert files to nginx-ui's expected paths
- Direct DB updates (e.g. add a SAN)
- Restarting the nginx-ui daemon
- Validating what's actually served vs what the DB says

This plugin runs alongside the native MCP — both can be declared in
your `.mcp.json` or mimir manifest. The native MCP handles vhost
configs, this one handles certs.

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

## Safety features

- **Idempotent `cert_issue`** — if a valid cert (>30 days remaining)
  exists for the requested domains, it's returned without contacting
  Let's Encrypt. Override with `force=True`.
- **Lock file** — `cert_issue` takes `/tmp/acme-lock` to prevent
  collisions with acme.sh's renewal cron.
- **Implicit `nginx -t` before `nginx_reload`** — never reload with a
  broken config.
- **Mutation gate** — read-only by default; mutations off until
  operator opts in.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Built on top of:
- [nginx-ui](https://nginxui.com) — the panel
- [acme.sh](https://github.com/acmesh-official/acme.sh) — the cert
  issuance engine
- [FastMCP](https://github.com/jlowin/fastmcp) — the MCP framework
