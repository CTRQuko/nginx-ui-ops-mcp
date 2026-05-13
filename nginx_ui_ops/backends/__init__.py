"""Transport backends for reaching the nginx-ui host.

Public:
- ``NginxUIBackend``  — abstract base
- ``CommandResult``   — return type of ``run_cmd``
- ``BackendError``    — canonical failure type for transport problems
- ``get_backend()``   — factory, selects via ``NGINXUI_BACKEND`` env (legacy)
                        or per-target ``NGINXUI_TARGETS`` (v0.4.0+)
- ``list_targets()``  — declared targets (v0.4.0+)
- ``default_target()`` — target used when caller doesn't pass one
- ``supports_acme()`` — quick capability check without instantiating
- ``reset_cache()``   — clear cached backends (test helper)
"""
from .base import BackendError, CommandResult, NginxUIBackend  # noqa: F401
from .factory import (  # noqa: F401
    default_target,
    get_backend,
    list_targets,
    reset_cache,
    supports_acme,
)
