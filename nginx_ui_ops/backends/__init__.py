"""Transport backends for reaching the nginx-ui host.

Public:
- ``NginxUIBackend``  — abstract base
- ``CommandResult``   — return type of ``run_cmd``
- ``BackendError``    — canonical failure type for transport problems
- ``get_backend()``   — factory, selects via ``NGINXUI_BACKEND`` env
- ``reset_cache()``   — clear cached backend (test helper)
"""
from .base import BackendError, CommandResult, NginxUIBackend  # noqa: F401
from .factory import get_backend, reset_cache  # noqa: F401
