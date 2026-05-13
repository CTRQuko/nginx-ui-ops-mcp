"""Conversational setup wizard for nginx-ui-ops.

Read-only tool always available. The LLM calls ``nginxui_setup()``,
reads the structured payload (``status``, ``prompts``, ``next_action``),
asks the operator each question in natural language, and executes the
matching ``router_add_credential`` calls in mimir for each answer.

Re-call ``nginxui_setup()`` after persisting credentials — it
progresses to the next stage automatically:

  needs_backend
  → needs_backend_config (per-backend required vars)
  → ready_readonly (4 read-only tools work; suggests optional creds)
  → ready_full (all 8 tools available once allow_mutations=true)

The wizard is **idempotent**: calling it on a fully-configured plugin
returns ``status='ready_full'`` without side effects.

Design notes:
- The plugin can't write to mimir's vault directly (different process).
  It returns instructions for the LLM to execute via mimir's
  ``router_add_credential``. This is the standard mimir LLM-guided
  onboarding pattern (see ``setup_<plugin>`` meta-tools).
- ``status`` enum is stable contract — clients can branch on it.
- Each prompt names the exact ``credential_ref`` to set, so the LLM
  doesn't have to map natural-language answer to env var name.
"""
from __future__ import annotations

import os
from typing import Any

# DNS provider env-var prefixes — same set as in tools.certs._collect_provider_env.
# Used here to detect whether *any* DNS credentials are already set.
_DNS_ENV_KEYS_BY_PROVIDER: dict[str, list[str]] = {
    "cloudflare": ["CF_API_TOKEN", "CF_ZONE_ID", "CF_API_KEY", "CF_EMAIL"],
    "route53": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
    "digitalocean": ["DO_API_TOKEN"],
    "gandi": ["GANDI_LIVEDNS_KEY"],
    "namecheap": ["NAMECHEAP_API_KEY", "NAMECHEAP_USERNAME"],
    "namesilo": ["NAMESILO_KEY"],
    "linode": ["LINODE_API_KEY"],
    "ovh": ["OVH_END_POINT", "OVH_AK", "OVH_AS"],
    "hurricane": ["HE_Username", "HE_Password"],
    "dynu": ["DYNU_ClientId", "DYNU_Secret"],
}

_BACKEND_REQUIRED_VARS: dict[str, list[tuple[str, str]]] = {
    "wrapper-lxc": [
        (
            "NGINXUI_PVE_SSH_ALIAS",
            "¿Qué alias tiene tu Proxmox en ~/.ssh/config? (e.g. pve, pve2, my-pve-host)",
        ),
        (
            "NGINXUI_LXC_ID",
            "¿Qué ID numérico tiene el LXC donde corre nginx-ui? (e.g. 100, 104, 200)",
        ),
    ],
    "direct-ssh": [
        (
            "NGINXUI_HOST",
            "¿Cuál es el SSH alias o IP del host con nginx-ui? (e.g. nginx.local, 192.0.2.10)",
        ),
    ],
}


def _is_set(key: str) -> bool:
    return bool(os.environ.get(key, "").strip())


def _detect_dns_provider() -> str | None:
    """Detect which DNS provider has creds set, if any. Returns the
    first provider whose required vars are all populated."""
    for provider, keys in _DNS_ENV_KEYS_BY_PROVIDER.items():
        if any(_is_set(k) for k in keys):
            return provider
    return None


def _detect_multi_target() -> dict[str, Any] | None:
    """Return a status dict if NGINXUI_TARGETS is declared, else None.

    Multi-target mode (v0.4.0+) overrides the legacy wizard flow. For
    each declared target, this checks whether ``NGINXUI_TARGET_<T>_BACKEND``
    is set and whether the per-backend required vars are present.

    Returns:
        - ``None`` if NGINXUI_TARGETS is NOT set (caller falls through
          to legacy wizard).
        - ``{"status": "ready_multi_target", ...}`` if all targets are
          fully configured.
        - ``{"status": "multi_target_partial", ...}`` if any target is
          missing required vars.
    """
    raw = os.environ.get("NGINXUI_TARGETS", "").strip()
    if not raw:
        return None
    targets = [t.strip() for t in raw.split(",") if t.strip()]
    if not targets:
        return None

    inventory: list[dict[str, Any]] = []
    missing_targets: list[dict[str, Any]] = []

    # Per-backend required vars (target-scoped). Keys match the
    # _BACKEND_REQUIRED_VARS layout but suffixed for multi-target.
    multi_required: dict[str, list[str]] = {
        "wrapper-lxc": ["PVE_SSH_ALIAS", "LXC_ID"],
        "direct-ssh": ["HOST"],
        "docker-exec": ["DOCKER_SSH_ALIAS", "DOCKER_CONTAINER"],
    }

    for t in targets:
        norm = t.upper()
        be = os.environ.get(f"NGINXUI_TARGET_{norm}_BACKEND", "").strip().lower()
        if not be:
            missing_targets.append({
                "target": t,
                "missing": [f"NGINXUI_TARGET_{norm}_BACKEND"],
                "hint": (
                    f"Declare backend for target {t!r}: "
                    f"router_add_credential('NGINXUI_TARGET_{norm}_BACKEND', "
                    f"'wrapper-lxc|direct-ssh|docker-exec')"
                ),
            })
            continue
        if be not in multi_required:
            missing_targets.append({
                "target": t,
                "backend": be,
                "missing": [],
                "hint": (
                    f"Backend {be!r} for target {t!r} unknown. "
                    f"Supported: {sorted(multi_required)}"
                ),
            })
            continue
        missing = [
            f"NGINXUI_TARGET_{norm}_{var}"
            for var in multi_required[be]
            if not _is_set(f"NGINXUI_TARGET_{norm}_{var}")
        ]
        if missing:
            missing_targets.append({
                "target": t,
                "backend": be,
                "missing": missing,
                "hint": (
                    f"Set the missing vars for target {t!r}: " + ", ".join(missing)
                ),
            })
            continue
        # Target fully configured
        inventory.append({
            "target": t,
            "backend": be,
            "vars": {
                v: os.environ.get(f"NGINXUI_TARGET_{norm}_{v}", "")
                for v in multi_required[be]
            },
        })

    default_t = (
        os.environ.get("NGINXUI_DEFAULT_TARGET", "").strip()
        or (targets[0] if targets else None)
    )
    mutations_enabled = os.environ.get(
        "NGINXUI_ALLOW_MUTATIONS", ""
    ).strip().lower() in ("1", "true", "yes", "on")

    if missing_targets:
        return {
            "status": "multi_target_partial",
            "declared_targets": targets,
            "default_target": default_t,
            "configured": inventory,
            "missing": missing_targets,
            "mutations_enabled": mutations_enabled,
            "message": (
                f"Multi-target mode detectado ({len(targets)} declarados). "
                f"{len(inventory)} OK, {len(missing_targets)} con vars "
                "incompletas. Completa via router_add_credential según los "
                "hints, después re-llama nginxui_setup() para verificar."
            ),
        }

    return {
        "status": "ready_multi_target",
        "declared_targets": targets,
        "default_target": default_t,
        "configured": inventory,
        "mutations_enabled": mutations_enabled,
        "message": (
            f"Multi-target mode OK. {len(inventory)} targets configurados: "
            f"{', '.join(t['target'] + '(' + t['backend'] + ')' for t in inventory)}. "
            f"Default: {default_t}. "
            + (
                "Mutations HABILITADAS — las 8 tools de mutación están disponibles."
                if mutations_enabled
                else "Mutations DESHABILITADAS — solo read-only. Para activar: "
                "router_add_credential('NGINXUI_ALLOW_MUTATIONS', 'true') + restart."
            )
        ),
    }


def nginxui_setup() -> dict[str, Any]:
    """Conversational setup wizard. Detects state, returns next steps.

    The LLM should:
      1. Call this tool.
      2. Read ``status``, ``message``, ``prompts``, ``next_action``.
      3. Ask the operator each question in natural language.
      4. For each answer, execute the matching ``router_add_credential``
         in mimir — the prompt tells you the exact ``credential_ref``.
      5. Re-call this tool to advance to the next stage.

    Stages (``status`` values):
      - ``needs_backend``: first run, no NGINXUI_BACKEND set (legacy mode)
      - ``invalid_backend``: NGINXUI_BACKEND value not supported
      - ``needs_backend_config``: backend chosen, missing per-backend vars
      - ``ready_readonly``: backend complete, optional DNS creds suggested
      - ``ready_full``: all suggested creds set, plugin fully configured
      - ``ready_multi_target`` (v0.4.0+): NGINXUI_TARGETS declared, all
         targets resolved successfully. Includes target inventory.
      - ``multi_target_partial`` (v0.4.0+): NGINXUI_TARGETS declared but
         some target has misconfigured backend vars.

    Status is a stable contract — safe to branch on.
    """
    # v0.4.0: multi-target mode takes precedence if NGINXUI_TARGETS is set.
    multi = _detect_multi_target()
    if multi is not None:
        return multi

    backend = os.environ.get("NGINXUI_BACKEND", "").strip().lower()

    # ---- Stage 1: backend not chosen yet ---------------------------------
    if not backend:
        return {
            "status": "needs_backend",
            "message": (
                "Necesito saber cómo conectar a tu nginx-ui antes de configurar nada más."
            ),
            "prompt": {
                "credential_ref": "NGINXUI_BACKEND",
                "question": (
                    "¿Cómo está accesible tu instancia de nginx-ui?"
                ),
                "options": [
                    {
                        "value": "wrapper-lxc",
                        "label": (
                            "En un LXC de Proxmox accesible vía SSH al host + "
                            "pct exec + claude-wrapper (operator-style setup)"
                        ),
                    },
                    {
                        "value": "direct-ssh",
                        "label": (
                            "En un host accesible por SSH directo (bare metal, "
                            "VM, container) con sudo NOPASSWD configurado"
                        ),
                    },
                ],
            },
            "next_action": (
                "Pregunta al operador la opción y ejecuta:\n"
                "  router_add_credential('NGINXUI_BACKEND', '<wrapper-lxc|direct-ssh>')\n"
                "Después llama de nuevo nginxui_setup() para continuar."
            ),
        }

    # ---- Stage 1b: backend value is invalid ------------------------------
    if backend not in _BACKEND_REQUIRED_VARS:
        return {
            "status": "invalid_backend",
            "current_value": backend,
            "message": (
                f"NGINXUI_BACKEND='{backend}' no es un backend soportado. "
                f"Valores válidos: {sorted(_BACKEND_REQUIRED_VARS)}."
            ),
            "next_action": (
                "Reset y vuelve a empezar. Ejecuta:\n"
                "  router_add_credential('NGINXUI_BACKEND', '<wrapper-lxc|direct-ssh>')\n"
                "Después llama nginxui_setup()."
            ),
        }

    # ---- Stage 2: backend chosen, check per-backend required vars --------
    required = _BACKEND_REQUIRED_VARS[backend]
    missing = [(k, q) for k, q in required if not _is_set(k)]
    if missing:
        return {
            "status": "needs_backend_config",
            "backend": backend,
            "message": (
                f"Backend '{backend}' elegido. Faltan {len(missing)} dato(s) más "
                "para que el backend pueda conectar."
            ),
            "prompts": [
                {
                    "credential_ref": k,
                    "question": q,
                    "next_action": (
                        f"Pregunta al operador, después ejecuta:\n"
                        f"  router_add_credential('{k}', '<respuesta>')"
                    ),
                }
                for k, q in missing
            ],
            "next_action": (
                "Pregunta cada dato al operador y persiste con "
                "router_add_credential. Cuando todos estén seteados, "
                "llama nginxui_setup() de nuevo para verificar."
            ),
        }

    # ---- Stage 3: backend ready. Check optional/suggested ----------------
    suggestions: list[dict[str, Any]] = []

    # ACME home (only relevant for cert_issue, but cheap to ask early).
    if not _is_set("NGINXUI_ACME_HOME"):
        suggestions.append({
            "credential_ref": "NGINXUI_ACME_HOME",
            "question": (
                "¿Dónde tienes instalado acme.sh? (default: /root/.acme.sh, "
                "o /home/<usuario>/.acme.sh si lo instalaste como user)"
            ),
            "default_if_skipped": "/root/.acme.sh",
            "needed_for": "cert_issue tool (gated, requires allow_mutations)",
            "skippable": True,
        })

    # DNS provider creds.
    dns_provider = _detect_dns_provider()
    if dns_provider is None:
        suggestions.append({
            "what": "DNS-01 provider credentials",
            "question": (
                "Para emitir certs nuevos vía acme.sh DNS-01, necesitas "
                "credenciales del proveedor DNS. ¿Qué usas?"
            ),
            "options": [
                {
                    "value": "cloudflare",
                    "label": "Cloudflare (most common)",
                    "credential_refs": [
                        ("CF_API_TOKEN", "Tu API token de Cloudflare"),
                        (
                            "CF_ZONE_ID",
                            "Zone ID del dominio en Cloudflare "
                            "(panel CF → Overview → ID en la barra derecha)",
                        ),
                    ],
                },
                {
                    "value": "route53",
                    "label": "AWS Route 53",
                    "credential_refs": [
                        ("AWS_ACCESS_KEY_ID", "AWS access key"),
                        ("AWS_SECRET_ACCESS_KEY", "AWS secret"),
                        ("AWS_REGION", "Región AWS, e.g. us-east-1"),
                    ],
                },
                {
                    "value": "digitalocean",
                    "label": "DigitalOcean",
                    "credential_refs": [
                        ("DO_API_TOKEN", "DigitalOcean API token"),
                    ],
                },
                {
                    "value": "skip",
                    "label": (
                        "No voy a emitir certs nuevos — solo usar las tools "
                        "read-only (cert_list, cert_get, nginx_test, "
                        "nginx_cert_validate)"
                    ),
                    "credential_refs": [],
                },
                {
                    "value": "other",
                    "label": (
                        "Otro provider — dime cuál y consulto la doc de acme.sh "
                        "para saber qué env vars necesita"
                    ),
                    "credential_refs": [],
                },
            ],
            "needed_for": (
                "cert_issue tool (gated, requires allow_mutations). "
                "Las read-only NO necesitan DNS creds."
            ),
            "skippable": True,
        })

    if suggestions:
        return {
            "status": "ready_readonly",
            "backend": backend,
            "message": (
                f"Backend '{backend}' configurado. Las 4 tools read-only ya "
                "funcionarán tras reiniciar el cliente MCP: cert_list, "
                "cert_get, nginx_test, nginx_cert_validate.\n\n"
                "Hay configs opcionales para habilitar tools que MUTAN "
                "(cert_issue, cert_domains_update, cert_deploy_files, "
                "nginx_reload). Si solo quieres diagnosticar, puedes saltarte "
                "estas y reiniciar ahora."
            ),
            "optional_suggestions": suggestions,
            "next_actions": [
                "1. (Opcional) Recorre las suggestions y persiste las que el "
                "operador quiera con router_add_credential.",
                "2. Para HABILITAR las tools que mutan, ejecuta también:\n"
                "   router_add_credential('NGINXUI_ALLOW_MUTATIONS', 'true')",
                "3. Pide al operador que reinicie el cliente MCP "
                "(Claude Code / OpenCode) para que las env vars surtan efecto.",
            ],
        }

    # ---- Stage 4: everything looks ready ---------------------------------
    mutations_enabled = os.environ.get(
        "NGINXUI_ALLOW_MUTATIONS", ""
    ).strip().lower() in ("1", "true", "yes", "on")

    return {
        "status": "ready_full",
        "backend": backend,
        "dns_provider_detected": dns_provider,
        "mutations_enabled": mutations_enabled,
        "message": (
            f"Setup completo con backend '{backend}'. "
            + (
                "Mutations HABILITADAS — las 8 tools están disponibles."
                if mutations_enabled
                else "Las 4 tools read-only funcionan; mutations DESHABILITADAS "
                "(NGINXUI_ALLOW_MUTATIONS no está 'true'). Para habilitar las "
                "tools que mutan: router_add_credential('NGINXUI_ALLOW_MUTATIONS', 'true')."
            )
            + " Reinicia el cliente MCP para que cualquier cambio reciente "
            "tome efecto."
        ),
    }
