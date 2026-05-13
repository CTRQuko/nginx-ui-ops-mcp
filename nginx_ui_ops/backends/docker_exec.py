"""DockerExecBackend — nginx-ui running inside a Docker container.

Transport: ``ssh <alias> 'docker exec [--user U] <container> <cmd>'``.

Use case: Hetzner VPS where nginx-ui runs as a Docker container
(`uozi/nginx-ui:latest`), accessed via SSH to the host and
``docker exec`` to the container. v0.4.0+ — added 2026-05-14.

Required env vars (multi-target mode, recommended):
  - ``NGINXUI_TARGET_<T>_DOCKER_SSH_ALIAS`` — SSH alias of the host
  - ``NGINXUI_TARGET_<T>_DOCKER_CONTAINER`` — container name or ID

Optional:
  - ``NGINXUI_TARGET_<T>_DOCKER_USER`` — passed to ``docker exec --user``
    (default: empty → uses container's default user)
  - ``NGINXUI_TARGET_<T>_DOCKER_SSH_BIN`` — default ``ssh``
  - ``NGINXUI_TARGET_<T>_DOCKER_BIN``    — default ``docker``

Legacy single-target mode reads ``NGINXUI_DOCKER_SSH_ALIAS`` and
``NGINXUI_DOCKER_CONTAINER`` (etc.) without the prefix.

Capability flags:
  - ``supports_acme = False`` — the upstream container image
    ``uozi/nginx-ui:latest`` does NOT include acme.sh. Tools that try
    to call :meth:`acme_issue` raise ``BackendError`` with a hint that
    the operator should run acme.sh on the host instead, or switch to
    a backend that has it (``wrapper-lxc`` / ``direct-ssh``).
"""
from __future__ import annotations

import logging
import os
import shlex
import subprocess
from typing import Any

from .base import BackendError, CommandResult, NginxUIBackend
from .wrapper_lxc import _bind_params  # reuse SQL binding helper

log = logging.getLogger(__name__)


# Path the backend writes temp files to inside the container — used by
# query_db to dodge eval-quote issues (same pattern as WrapperLXCBackend).
_CONTAINER_TMP = "/tmp"


class DockerExecBackend(NginxUIBackend):
    """Backend for ``NGINXUI_BACKEND=docker-exec`` (or per-target equivalent).

    Wraps every operation as ``ssh <alias> docker exec <container> <cmd>``.
    No sudo escalation involved — the container typically runs as root
    internally. The ``sudo=True`` flag on :meth:`run_cmd` is accepted
    (for API symmetry) but **ignored**; docker exec already runs with
    container-process privileges.
    """

    # Class-level capability flag — see module docstring.
    supports_acme: bool = False

    def __init__(
        self,
        ssh_alias: str,
        container: str,
        *,
        docker_user: str | None = None,
        ssh_bin: str = "ssh",
        docker_bin: str = "docker",
    ):
        self.ssh_alias = ssh_alias
        self.container = container
        self.docker_user = docker_user or None  # empty → None
        self.ssh_bin = ssh_bin
        self.docker_bin = docker_bin

    @classmethod
    def from_env(cls) -> "DockerExecBackend":
        """Legacy single-target mode — reads NGINXUI_DOCKER_* directly."""
        ssh_alias = os.environ.get("NGINXUI_DOCKER_SSH_ALIAS", "").strip()
        container = os.environ.get("NGINXUI_DOCKER_CONTAINER", "").strip()
        if not ssh_alias:
            raise BackendError(
                "NGINXUI_DOCKER_SSH_ALIAS is required for docker-exec backend"
            )
        if not container:
            raise BackendError(
                "NGINXUI_DOCKER_CONTAINER is required for docker-exec backend"
            )
        return cls(
            ssh_alias=ssh_alias,
            container=container,
            docker_user=os.environ.get("NGINXUI_DOCKER_USER") or None,
            ssh_bin=os.environ.get("NGINXUI_DOCKER_SSH_BIN", "ssh"),
            docker_bin=os.environ.get("NGINXUI_DOCKER_BIN", "docker"),
        )

    @classmethod
    def from_env_target(cls, target: str) -> "DockerExecBackend":
        """Multi-target mode (v0.4.0+) — reads NGINXUI_TARGET_<TARGET>_DOCKER_*."""
        prefix = f"NGINXUI_TARGET_{target.upper()}_DOCKER_"
        ssh_alias = os.environ.get(f"{prefix}SSH_ALIAS", "").strip()
        container = os.environ.get(f"{prefix}CONTAINER", "").strip()
        if not ssh_alias:
            raise BackendError(
                f"{prefix}SSH_ALIAS is required for docker-exec target {target!r}"
            )
        if not container:
            raise BackendError(
                f"{prefix}CONTAINER is required for docker-exec target {target!r}"
            )
        return cls(
            ssh_alias=ssh_alias,
            container=container,
            docker_user=os.environ.get(f"{prefix}USER") or None,
            ssh_bin=os.environ.get(f"{prefix}SSH_BIN", "ssh"),
            docker_bin=os.environ.get(f"{prefix}BIN", "docker"),
        )

    def describe(self) -> str:
        u = f" user={self.docker_user}" if self.docker_user else ""
        return (
            f"DockerExecBackend(ssh={self.ssh_alias}, "
            f"container={self.container}{u})"
        )

    # -----------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------

    def _docker_exec_argv(
        self,
        argv: list[str],
        *,
        interactive: bool = False,
    ) -> list[str]:
        """Build the local argv that ssh's into the host + runs docker exec.

        Returns a list ready for ``subprocess.run``. The ``argv`` of the
        command to run INSIDE the container is shell-quoted into a single
        string because we go through SSH (which itself does another
        shell-split on the remote).
        """
        # Inner command: docker exec [-i] [--user U] <container> <argv...>
        inner: list[str] = [self.docker_bin, "exec"]
        if interactive:
            inner.append("-i")
        if self.docker_user:
            inner += ["--user", self.docker_user]
        inner.append(self.container)
        inner += argv
        # Quote inner command for SSH transport (one big string arg).
        remote_cmd = " ".join(shlex.quote(p) for p in inner)
        return [self.ssh_bin, self.ssh_alias, remote_cmd]

    def _run_local(
        self,
        cmd: list[str],
        *,
        timeout: int,
        stdin_bytes: bytes | None = None,
    ) -> CommandResult:
        """Run a subprocess locally. Translates errors to BackendError."""
        try:
            proc = subprocess.run(
                cmd,
                input=stdin_bytes,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise BackendError(
                f"docker-exec timeout after {timeout}s on "
                f"{self.ssh_alias}/{self.container}: {e}"
            ) from e
        except OSError as e:
            raise BackendError(
                f"docker-exec failed to spawn {self.ssh_bin!r}: {e}"
            ) from e
        return CommandResult(
            return_code=proc.returncode,
            stdout=proc.stdout.decode("utf-8", errors="replace"),
            stderr=proc.stderr.decode("utf-8", errors="replace"),
        )

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def run_cmd(
        self,
        argv: list[str],
        *,
        sudo: bool = False,
        timeout: int = 30,
    ) -> CommandResult:
        """Run ``argv`` inside the container via ``docker exec``.

        ``sudo`` is accepted for API symmetry but **ignored** — docker
        exec already runs with container-process privileges (typically
        root). If the operator needs a different user inside the
        container, set ``NGINXUI_TARGET_<T>_DOCKER_USER``.
        """
        if not argv:
            raise BackendError("run_cmd requires non-empty argv")
        cmd = self._docker_exec_argv(argv)
        return self._run_local(cmd, timeout=timeout)

    def push_file(
        self,
        content: bytes,
        remote_path: str,
        *,
        mode: int = 0o644,
        sudo: bool = False,
    ) -> None:
        """Write ``content`` to ``remote_path`` inside the container.

        Strategy:
          1. ``ssh <alias> 'docker exec -i <container> tee <path> > /dev/null'``
             with content piped via stdin.
          2. ``ssh <alias> 'docker exec <container> chmod <mode> <path>'``

        CRLF normalization: same as wrapper-lxc — if content decodes as
        valid UTF-8, strip ``\\r`` before writing.
        """
        # Same CRLF normalization as WrapperLXCBackend.
        try:
            text = content.decode("utf-8")
            content = text.replace("\r\n", "\n").replace("\r", "").encode("utf-8")
        except UnicodeDecodeError:
            pass  # binary file — pass through verbatim

        # Step 1: write via tee
        write_argv = ["tee", remote_path]
        cmd = self._docker_exec_argv(write_argv, interactive=True)
        # Use shell redirection in the SSH layer to discard tee's stdout
        # which would otherwise echo the entire content back.
        remote_redir = cmd[2] + " > /dev/null"
        ssh_cmd = [cmd[0], cmd[1], remote_redir]
        res = self._run_local(ssh_cmd, timeout=60, stdin_bytes=content)
        if not res.ok:
            raise BackendError(
                f"docker-exec push_file failed (tee): rc={res.return_code} "
                f"stderr={res.stderr[:200]}"
            )

        # Step 2: chmod
        chmod_cmd = self._docker_exec_argv(["chmod", f"{mode:o}", remote_path])
        res = self._run_local(chmod_cmd, timeout=10)
        if not res.ok:
            raise BackendError(
                f"docker-exec push_file failed (chmod): rc={res.return_code} "
                f"stderr={res.stderr[:200]}"
            )

    def read_file(self, remote_path: str, *, sudo: bool = False) -> bytes:
        """Read raw bytes of ``remote_path`` from inside the container.

        Uses ``docker exec <container> cat <path>`` and captures stdout
        as bytes. Errors translate to :class:`BackendError`.
        """
        cmd = self._docker_exec_argv(["cat", remote_path])
        # Local run with bytes-preserving output: re-run without text mode
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=30, check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise BackendError(
                f"docker-exec read_file timeout: {e}"
            ) from e
        if proc.returncode != 0:
            raise BackendError(
                f"docker-exec read_file failed: rc={proc.returncode} "
                f"stderr={proc.stderr.decode('utf-8', errors='replace')[:200]}"
            )
        return proc.stdout

    def query_db(
        self,
        db_path: str,
        sql: str,
        *,
        params: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        """Run SQL against a SQLite DB inside the container.

        Strategy: same as wrapper-lxc — write SQL to a tempfile inside
        the container, then run ``sqlite3 <db> < <tmpfile>`` so the
        shell handles redirection correctly. After: cleanup.

        Output mode: ``-json`` (sqlite3 v3.33+). Each row becomes a
        dict keyed by column name.
        """
        bound = _bind_params(sql, params)
        import secrets as _secrets
        token = _secrets.token_hex(8)
        tmpfile = f"{_CONTAINER_TMP}/nui-q-{token}.sql"

        # Step 1: push the SQL to the container
        self.push_file(bound.encode("utf-8"), tmpfile, mode=0o600)

        # Step 2: run sqlite3 <db> -json < <tmpfile>
        # The redirection needs to happen INSIDE the container's shell,
        # so we wrap the cmd as `sh -c 'sqlite3 ... < tmpfile'`.
        sql_cmd = f"sqlite3 -json {shlex.quote(db_path)} < {shlex.quote(tmpfile)}"
        cmd = self._docker_exec_argv(["sh", "-c", sql_cmd])
        res = self._run_local(cmd, timeout=30)

        # Step 3: cleanup tempfile (best-effort, don't fail if rm fails)
        try:
            self._run_local(
                self._docker_exec_argv(["rm", "-f", tmpfile]),
                timeout=10,
            )
        except BackendError:
            pass

        if not res.ok:
            raise BackendError(
                f"docker-exec query_db failed: rc={res.return_code} "
                f"stderr={res.stderr[:200]}"
            )

        if not res.stdout.strip():
            return []
        try:
            import json
            rows = json.loads(res.stdout)
            if not isinstance(rows, list):
                raise BackendError(
                    f"docker-exec query_db: expected JSON array, "
                    f"got {type(rows).__name__}"
                )
            return rows
        except json.JSONDecodeError as e:
            raise BackendError(
                f"docker-exec query_db: failed to parse JSON: {e} "
                f"stdout[:200]={res.stdout[:200]!r}"
            ) from e

    def acme_issue(
        self,
        domains: list[str],
        *,
        key_type: str,
        dns_provider: str,
        provider_env: dict[str, str],
        acme_home: str,
    ) -> dict[str, Any]:
        """Always raises — see :attr:`supports_acme` = False.

        The default container image ``uozi/nginx-ui:latest`` does not
        ship acme.sh. Cert issuance for VPS-style installs should be
        done on the host (e.g. via ``DirectSSHBackend`` against the host,
        or manually) and the resulting cert+key copied into the
        container with :meth:`push_file` + ``cert_deploy_files``.

        Tools should check ``backend.supports_acme`` (or
        ``factory.supports_acme(target)``) BEFORE calling this method
        to give the LLM a clear refusal message instead of a stack.
        """
        raise BackendError(
            "DockerExecBackend does not support acme.sh — the upstream "
            "container image (uozi/nginx-ui) doesn't include it. Issue "
            "certs on the host (DirectSSHBackend) or another backend, "
            "then deploy with cert_deploy_files."
        )
