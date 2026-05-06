"""DirectSSHBackend — SSH directo a un host con nginx-ui (sin Proxmox/LXC).

Para setups donde nginx-ui corre en bare metal, una VM, o un container
con SSH expuesto. No hay ``pct exec`` ni ``claude-wrapper``: los
comandos llegan directos al host vía ``ssh user@host cmd``.

Cobertura de gotchas vs WrapperLXCBackend:

  #1 acme.sh CF zone lookup  → Aplica igual: caller pasa
     ``CF_Zone_ID`` via ``provider_env``.
  #2 echo PASS | sudo -S     → Aplica igual: NOPASSWD por defecto;
     password via stdin separado si SUDO_METHOD=password.
  #3 CRLF Windows            → Aplica igual: ``push_file`` strippea
     ``\\r`` en contenido UTF-8.
  #4 wrapper eval SQL        → NO aplica: SQL pasa directo a sqlite3
     sin shell wrapper intermedio. Aún así escribimos a tempfile +
     redirección stdin para uniformidad y para evitar sorpresas con
     ssh argument escaping.

acme.sh debe estar instalado **en el mismo host nginx-ui** (no hay
"PVE host" separado en este backend). El path se controla via
``NGINXUI_ACME_HOME``.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import shlex
import subprocess
from typing import Any

from .base import BackendError, CommandResult, NginxUIBackend
from .wrapper_lxc import _bind_params, _key_type_to_keylength

log = logging.getLogger(__name__)


class DirectSSHBackend(NginxUIBackend):
    """Backend for ``NGINXUI_BACKEND=direct-ssh``.

    Required env vars:
      - ``NGINXUI_HOST``  — SSH alias or address of the nginx-ui host

    Optional env vars (with defaults):
      - ``NGINXUI_SSH_USER``       — default empty (uses SSH config)
      - ``NGINXUI_SUDO_METHOD``    — ``nopasswd`` (default) | ``password`` | ``none``
      - ``NGINXUI_SUDO_PASSWORD_REF`` — file path; only used if SUDO_METHOD=password
      - ``NGINXUI_SSH_BIN``        — default ``ssh``

    ``SUDO_METHOD=none`` is for hosts where the SSH user is already
    root — sudo prefix is omitted entirely.
    """

    def __init__(
        self,
        host: str,
        *,
        ssh_user: str = "",
        sudo_method: str = "nopasswd",
        sudo_password_ref: str | None = None,
        ssh_bin: str = "ssh",
    ):
        self.host = host
        self.ssh_user = ssh_user
        self.sudo_method = sudo_method
        self.sudo_password_ref = sudo_password_ref
        self.ssh_bin = ssh_bin

        if sudo_method not in ("nopasswd", "password", "none"):
            raise BackendError(
                f"NGINXUI_SUDO_METHOD={sudo_method!r} invalid — "
                f"must be 'nopasswd', 'password', or 'none'"
            )
        if sudo_method == "password" and not sudo_password_ref:
            raise BackendError(
                "NGINXUI_SUDO_METHOD=password requires "
                "NGINXUI_SUDO_PASSWORD_REF (path to password file)"
            )

    @classmethod
    def from_env(cls) -> "DirectSSHBackend":
        host = os.environ.get("NGINXUI_HOST", "").strip()
        if not host:
            raise BackendError("NGINXUI_HOST is required for direct-ssh backend")
        return cls(
            host=host,
            ssh_user=os.environ.get("NGINXUI_SSH_USER", "").strip(),
            sudo_method=os.environ.get("NGINXUI_SUDO_METHOD", "nopasswd").strip(),
            sudo_password_ref=os.environ.get("NGINXUI_SUDO_PASSWORD_REF") or None,
            ssh_bin=os.environ.get("NGINXUI_SSH_BIN", "ssh"),
        )

    def describe(self) -> str:
        target = f"{self.ssh_user}@{self.host}" if self.ssh_user else self.host
        return f"DirectSSHBackend({target})"

    # -----------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------

    def _ssh_target(self) -> str:
        return f"{self.ssh_user}@{self.host}" if self.ssh_user else self.host

    def _read_sudo_password(self) -> str:
        if not self.sudo_password_ref:
            raise BackendError("sudo_password_ref not set")
        try:
            with open(self.sudo_password_ref, "rb") as fh:
                return fh.read().rstrip(b"\r\n ").decode("utf-8")
        except OSError as e:
            raise BackendError(f"Cannot read sudo password file: {e}") from e

    def _run_ssh(
        self,
        remote_cmd: str,
        *,
        stdin: bytes | None = None,
        timeout: int = 30,
    ) -> CommandResult:
        argv = [self.ssh_bin, self._ssh_target(), remote_cmd]
        log.debug("ssh exec: target=%s cmd=%s", self._ssh_target(), remote_cmd)
        try:
            proc = subprocess.run(  # noqa: S603 — argv internal
                argv,
                input=stdin,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise BackendError(
                f"ssh to {self._ssh_target()} timed out after {timeout}s"
            ) from e
        except FileNotFoundError as e:
            raise BackendError(f"ssh binary not found: {self.ssh_bin}") from e
        return CommandResult(
            return_code=proc.returncode,
            stdout=proc.stdout.decode("utf-8", errors="replace"),
            stderr=proc.stderr.decode("utf-8", errors="replace"),
        )

    def _sudo_prefix(self, *, sudo: bool) -> str:
        """Build the sudo prefix string. Empty if no sudo or method=none."""
        if not sudo or self.sudo_method == "none":
            return ""
        if self.sudo_method == "nopasswd":
            return "sudo "
        # password method
        return "sudo -S "

    # -----------------------------------------------------------------
    # NginxUIBackend implementation
    # -----------------------------------------------------------------

    def run_cmd(
        self,
        argv: list[str],
        *,
        sudo: bool = False,
        timeout: int = 30,
    ) -> CommandResult:
        if not argv:
            raise ValueError("argv cannot be empty")
        cmd_str = " ".join(shlex.quote(a) for a in argv)
        remote = f"{self._sudo_prefix(sudo=sudo)}{cmd_str}"
        stdin = None
        if sudo and self.sudo_method == "password":
            stdin = (self._read_sudo_password() + "\n").encode("utf-8")
        result = self._run_ssh(remote, stdin=stdin, timeout=timeout)
        result.notes.append(f"backend={self.describe()}")
        return result

    def push_file(
        self,
        content: bytes,
        remote_path: str,
        *,
        mode: int = 0o644,
        sudo: bool = False,
    ) -> None:
        # Gotcha #3: strip CRLF if content is UTF-8 text.
        try:
            decoded = content.decode("utf-8")
            content = decoded.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
        except UnicodeDecodeError:
            pass

        # Stage to /tmp first, then mv with sudo to dest.
        # This avoids piping content through sudo and keeps gotcha #2 clean.
        tmp_name = f"/tmp/nginx-ui-ops-push-{secrets.token_hex(8)}"
        stage_cmd = f"cat > {shlex.quote(tmp_name)}"
        stage = self._run_ssh(stage_cmd, stdin=content, timeout=30)
        if not stage.ok:
            raise BackendError(
                f"Stage to {tmp_name}: rc={stage.return_code} "
                f"stderr={stage.stderr[:200]}"
            )

        # Move to final dest (with sudo if needed) + chmod.
        sudo_prefix = self._sudo_prefix(sudo=sudo)
        mv_cmd = f"{sudo_prefix}mv {shlex.quote(tmp_name)} {shlex.quote(remote_path)}"
        chmod_cmd = f"{sudo_prefix}chmod {mode:o} {shlex.quote(remote_path)}"
        full_remote = f"{mv_cmd} && {chmod_cmd}"

        stdin = None
        if sudo and self.sudo_method == "password":
            # password fed twice via stdin? sudo caches credentials for ~5min,
            # one password feed is enough for the chained command.
            stdin = (self._read_sudo_password() + "\n").encode("utf-8")

        result = self._run_ssh(full_remote, stdin=stdin, timeout=60)

        # Cleanup attempt if mv failed (tempfile may still exist).
        if not result.ok:
            self._run_ssh(f"rm -f {shlex.quote(tmp_name)}", timeout=10)
            raise BackendError(
                f"push_file mv/chmod {remote_path}: rc={result.return_code} "
                f"stderr={result.stderr[:200]}"
            )

    def read_file(self, remote_path: str, *, sudo: bool = False) -> bytes:
        result = self.run_cmd(["cat", remote_path], sudo=sudo, timeout=30)
        if not result.ok:
            raise BackendError(
                f"read_file {remote_path}: rc={result.return_code} "
                f"stderr={result.stderr[:200]}"
            )
        return result.stdout.encode("utf-8")

    def query_db(
        self,
        db_path: str,
        sql: str,
        *,
        params: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        bound_sql = _bind_params(sql, params)

        # Stage SQL to /tmp + invoke sqlite3 with redirection.
        # Even though gotcha #4 doesn't strictly apply here (no wrapper),
        # tempfile-based redirection avoids edge cases with shell quoting
        # in long SQL queries.
        tmp_name = f"/tmp/nginx-ui-ops-sql-{secrets.token_hex(8)}.sql"
        full_sql = f".mode json\n{bound_sql.rstrip(';')};\n"

        stage = self._run_ssh(
            f"cat > {shlex.quote(tmp_name)}",
            stdin=full_sql.encode("utf-8"),
            timeout=10,
        )
        if not stage.ok:
            raise BackendError(
                f"Stage SQL to {tmp_name}: rc={stage.return_code} "
                f"stderr={stage.stderr[:200]}"
            )

        # sqlite3 db.sqlite < /tmp/q.sql — sqlite3 doesn't typically
        # need sudo (db readable by user), but if it does the operator
        # configures sudoers accordingly. We default to no-sudo here
        # and let read_file / run_cmd be the sudo path for permissions.
        result = self._run_ssh(
            f"sqlite3 {shlex.quote(db_path)} < {shlex.quote(tmp_name)}",
            timeout=30,
        )

        # Cleanup.
        self._run_ssh(f"rm -f {shlex.quote(tmp_name)}", timeout=5)

        if not result.ok:
            raise BackendError(
                f"sqlite3 query: rc={result.return_code} "
                f"stderr={result.stderr[:200]}"
            )

        out = result.stdout.strip()
        if not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError as e:
            raise BackendError(
                f"sqlite3 returned non-JSON: {out[:200]}"
            ) from e
        if not isinstance(data, list):
            raise BackendError(
                f"sqlite3 JSON not a list: {type(data).__name__}"
            )
        return data

    def acme_issue(
        self,
        domains: list[str],
        *,
        key_type: str,
        dns_provider: str,
        provider_env: dict[str, str],
        acme_home: str,
    ) -> dict[str, Any]:
        if not domains:
            raise ValueError("domains cannot be empty")

        keylength = _key_type_to_keylength(key_type)
        env_exports = " && ".join(
            f"export {k}={shlex.quote(v)}" for k, v in provider_env.items()
        )
        domain_args = " ".join(f"-d {shlex.quote(d)}" for d in domains)
        acme_bin = shlex.quote(f"{acme_home.rstrip('/')}/acme.sh")
        cmd = (
            f"{env_exports} && "
            f"{acme_bin} --issue {domain_args} "
            f"--dns {shlex.quote(dns_provider)} "
            f"--keylength {shlex.quote(keylength)} "
            f"--server letsencrypt "
            f"--home {shlex.quote(acme_home)}"
        )

        result = self._run_ssh(cmd, timeout=300)
        if result.return_code not in (0, 2):
            raise BackendError(
                f"acme.sh --issue failed (rc={result.return_code}): "
                f"{result.stderr[:500] or result.stdout[:500]}"
            )

        primary = domains[0].lstrip("*").lstrip(".")
        cert_dir_name = domains[0]
        is_ecc = key_type.upper() in ("P256", "P384", "P521", "ECC")
        if is_ecc:
            cert_dir_name = f"{cert_dir_name}_ecc"
        fullchain = f"{acme_home.rstrip('/')}/{cert_dir_name}/fullchain.cer"
        keyfile = f"{acme_home.rstrip('/')}/{cert_dir_name}/{primary}.key"

        return {
            "fullchain_path": fullchain,
            "key_path": keyfile,
            "domains": domains,
            "key_type": key_type,
            "acme_returncode": result.return_code,
            "acme_stdout_tail": result.stdout[-500:],
        }
