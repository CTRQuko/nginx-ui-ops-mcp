"""Transport backends for reaching the nginx-ui host.

Public:
- ``NginxUIBackend``  — abstract base
- ``get_backend()``   — factory, selects via ``NGINXUI_BACKEND`` env
"""
from .base import NginxUIBackend  # noqa: F401
