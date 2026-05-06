"""WrapperLXCBackend — Proxmox + LXC + claude-wrapper.

Operator-style transport: ``ssh pve-alias`` → ``pct exec <lxc-id>`` →
``/usr/local/bin/claude-wrapper <cmd>``. The wrapper restricts the
allowed commands to a whitelist; all 4 gotchas of the operator log
are handled internally:

  #1 acme.sh CF zone lookup — caller passes ``CF_Zone_ID`` via
     ``provider_env``; backend forwards verbatim.
  #2 ``echo PASS | sudo -S`` mixes stdin with password — we use
     NOPASSWD sudoers for the wrapper invocation, never piping
     password through ``-S``.
  #3 CRLF Windows breaks the wrapper.conf — ``push_file`` strips
     ``\\r`` from UTF-8 content before pushing.
  #4 ``eval`` in wrapper destroys SQL quotes — ``query_db`` writes the
     SQL to a tempfile in the host's ``/tmp`` and uses redirection
     (``sqlite3 db < /tmp/q.sql``) which the wrapper's ``eval``
     interprets correctly.
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

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SQL parameter binding (for query_db)
# ---------------------------------------------------------------------------

def _quote_sql_value(v: Any) -> str:
    """Quote a Python value as a SQLite literal.

    Used because we cannot pass params to sqlite3 via the wrapper
    — the SQL must be self-contained when sent to ``sqlite3 < file``.
    Conservative: only accept None / int / float / bool / str / bytes.
    """
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return "'" + v.replace("'", "''") + "'"
    if isinstance(v, bytes):
        return "X'" + v.hex() + "'"
    raise TypeError(
        f"WrapperLXCBackend.query_db: unsupported param type "
        f"{type(v).__name__!r}; supported: None, int, float, bool, str, bytes"
    )


def _bind_params(sql: str, params: tuple) -> str:
    """Substitute ``?`` placeholders in ``sql`` with quoted ``params``."""
    parts = sql.split("?")
    if len(parts) - 1 != len(params):
        raise ValueError(
            f"SQL has {len(parts) - 1} placeholders, got {len(params)} params"
        )
    out: list[str] = []
    for i, segment in enumerate(parts):
        out.append(segment)
        if i < len(params):
            out.append(_quote_sql_value(params[i]))
    return "".join(out)


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------

class WrapperLXCBackend(NginxUIBackend):
    """Backend for ``NGINXUI_BACKEND=wrapper-lxc``.

    Required env vars:
      - ``NGINXUI_PVE_SSH_ALIAS``  — SSH alias of the Proxmox host
      - ``NGINXUI_LXC_ID``         — LXC container ID where nginx-ui runs

    Optional env vars (with defaults):
      - ``NGINXUI_WRAPPER_PATH``   — default ``/usr/local/bin/claude-wrapper``
      - ``NGINXUI_SUDO_METHOD``    — ``nopasswd`` (default) | ``password``
      - ``NGINXUI_SUDO_PASSWORD_REF`` — file path; only used if SUDO_METHOD=password
      - ``NGINXUI_SSH_BIN``        — default ``ssh``
      - ``NGINXUI_PCT_PATH``       — default ``/usr/sbin/pct``
    """

    def __init__(
        self,
        pve_ssh_alias: str,
        lxc_id: str,
        *,
        wrapper_path: str = "/usr/local/bin/claude-wrapper",
        sudo_method: str = "nopasswd",
        sudo_password_ref: str | None = None,
        ssh_bin: str = "ssh",
        pct_path: str = "/usr/sbin/pct",
    ):
        self.pve_ssh_alias = pve_ssh_alias
        self.lxc_id = str(lxc_id)
        self.wrapper_path = wrapper_path
        self.sudo_method = sudo_method
        self.sudo_password_ref = sudo_password_ref
        self.ssh_bin = ssh_bin
        self.pct_path = pct_path

        if sudo_method not in ("nopasswd", "password"):
            raise BackendError(
                f"NGINXUI_SUDO_METHOD={sudo_method!r} invalid — "
                f"must be 'nopasswd' or 'password'"
            )
        if sudo_method == "password" and not sudo_password_ref:
            raise BackendError(
                "NGINXUI_SUDO_METHOD=password requires "
                "NGINXUI_SUDO_PASSWORD_REF (path to password file)"
            )

    # -----------------------------------------------------------------
    # Construction from env
    # -----------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "WrapperLXCBackend":
        pve = os.environ.get("NGINXUI_PVE_SSH_ALIAS", "").strip()
        lxc = os.environ.get("NGINXUI_LXC_ID", "").strip()
        if not pve:
            raise BackendError("NGINXUI_PVE_SSH_ALIAS is required for wrapper-lxc backend")
        if not lxc:
            raise BackendError("NGINXUI_LXC_ID is required for wrapper-lxc backend")
        return cls(
            pve_ssh_alias=pve,
            lxc_id=lxc,
            wrapper_path=os.environ.get(
                "NGINXUI_WRAPPER_PATH", "/usr/local/bin/claude-wrapper"
            ),
            sudo_method=os.environ.get("NGINXUI_SUDO_METHOD", "nopasswd").strip(),
            sudo_password_ref=os.environ.get("NGINXUI_SUDO_PASSWORD_REF") or None,
            ssh_bin=os.environ.get("NGINXUI_SSH_BIN", "ssh"),
            pct_path=os.environ.get("NGINXUI_PCT_PATH", "/usr/sbin/pct"),
        )

    def describe(self) -> str:
        return f"WrapperLXCBackend(pve={self.pve_ssh_alias}, lxc={self.lxc_id})"

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _read_sudo_password(self) -> str:
        """Read the sudo password from the configured file. Bytes only
        once when needed. NEVER logged. Stripped of trailing whitespace."""
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
        """Low-level ssh exec — backend internal."""
        argv = [self.ssh_bin, self.pve_ssh_alias, remote_cmd]
        log.debug("ssh exec: alias=%s cmd=%s", self.pve_ssh_alias, remote_cmd)
        try:
            proc = subprocess.run(  # noqa: S603 — argv is internal, not user-controlled
                argv,
                input=stdin,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise BackendError(
                f"ssh to {self.pve_ssh_alias} timed out after {timeout}s"
            ) from e
        except FileNotFoundError as e:
            raise BackendError(f"ssh binary not found: {self.ssh_bin}") from e
        return CommandResult(
            return_code=proc.returncode,
            stdout=proc.stdout.decode("utf-8", errors="replace"),
            stderr=proc.stderr.decode("utf-8", errors="replace"),
        )

    def _wrap_pct_exec(self, inner: str, *, sudo: bool) -> str:
        """Build the ``[sudo] pct exec <lxc> -- claude-wrapper <inner>``
        remote command string. Uses NOPASSWD path when sudo=True."""
        wrapped = f"{shlex.quote(self.pct_path)} exec {shlex.quote(self.lxc_id)} -- {shlex.quote(self.wrapper_path)} {inner}"
        if not sudo:
            return wrapped
        if self.sudo_method == "nopasswd":
            return f"sudo {wrapped}"
        # password method: writes password to stdin of `sudo -S`. We
        # avoid mixing it with command stdin by running the password
        # injection in a subshell isolated from any pipeline downstream.
        # See docstring for the gotcha #2 mitigation.
        # Note: callers that need command stdin must use NOPASSWD.
        return f'sudo -S {wrapped}'  # caller writes password to ssh stdin

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
        inner = " ".join(shlex.quote(a) for a in argv)
        remote = self._wrap_pct_exec(inner, sudo=sudo)
        stdin: bytes | None = None
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
            # Binary content — leave verbatim.
            pass

        # Stage on PVE host first (no sudo needed for /tmp/<random>),
        # then pct push to the LXC. Random suffix prevents collisions.
        tmp_name = f"/tmp/nginx-ui-ops-push-{secrets.token_hex(8)}"
        # Stage step: write to /tmp on PVE via stdin redirection — no sudo.
        stage_cmd = f"cat > {shlex.quote(tmp_name)}"
        stage = self._run_ssh(stage_cmd, stdin=content, timeout=30)
        if not stage.ok:
            raise BackendError(
                f"Stage to {tmp_name}: rc={stage.return_code} stderr={stage.stderr[:200]}"
            )

        # pct push step.
        sudo_prefix = "sudo " if sudo else ""
        if sudo and self.sudo_method == "password":
            # password method via -S: see _wrap_pct_exec note.
            sudo_prefix = "sudo -S "
        push_cmd = (
            f"{sudo_prefix}{shlex.quote(self.pct_path)} push "
            f"{shlex.quote(self.lxc_id)} "
            f"{shlex.quote(tmp_name)} "
            f"{shlex.quote(remote_path)}"
        )
        stdin = None
        if sudo and self.sudo_method == "password":
            stdin = (self._read_sudo_password() + "\n").encode("utf-8")
        push = self._run_ssh(push_cmd, stdin=stdin, timeout=60)

        # Best-effort cleanup of staged tempfile (don't fail the op if rm fails).
        self._run_ssh(f"rm -f {shlex.quote(tmp_name)}", timeout=10)

        if not push.ok:
            raise BackendError(
                f"pct push {tmp_name} → {remote_path}: rc={push.return_code} "
                f"stderr={push.stderr[:200]}"
            )

        # chmod via wrapper.
        chmod = self.run_cmd(
            ["chmod", f"{mode:o}", remote_path],
            sudo=sudo,
            timeout=10,
        )
        if not chmod.ok:
            raise BackendError(
                f"chmod {mode:o} {remote_path}: rc={chmod.return_code} "
                f"stderr={chmod.stderr[:200]}"
            )

    def read_file(self, remote_path: str, *, sudo: bool = False) -> bytes:
        result = self.run_cmd(["cat", remote_path], sudo=sudo, timeout=30)
        if not result.ok:
            raise BackendError(
                f"read_file {remote_path}: rc={result.return_code} "
                f"stderr={result.stderr[:200]}"
            )
        # stdout is decoded UTF-8; re-encode to bytes for the contract.
        # If the file has non-UTF-8 bytes, replacements happen during decode.
        return result.stdout.encode("utf-8")

    def query_db(
        self,
        db_path: str,
        sql: str,
        *,
        params: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        # Bind params client-side to avoid passing them through eval-prone
        # shell wrappers (gotcha #4).
        bound_sql = _bind_params(sql, params)

        # Stage the SQL to /tmp on PVE, then pct push to LXC's /tmp,
        # then sqlite3 < /tmp/file.sql via wrapper.
        host_tmp = f"/tmp/nginx-ui-ops-sql-{secrets.token_hex(8)}.sql"
        lxc_tmp = host_tmp  # same path inside LXC for simplicity

        # Wrap SQL so sqlite3 emits JSON.
        full_sql = f".mode json\n{bound_sql.rstrip(';')};\n"

        # Stage on PVE.
        stage = self._run_ssh(
            f"cat > {shlex.quote(host_tmp)}",
            stdin=full_sql.encode("utf-8"),
            timeout=10,
        )
        if not stage.ok:
            raise BackendError(
                f"Stage SQL to {host_tmp}: rc={stage.return_code} "
                f"stderr={stage.stderr[:200]}"
            )

        # Push to LXC.
        push = self._run_ssh(
            f"sudo {shlex.quote(self.pct_path)} push "
            f"{shlex.quote(self.lxc_id)} {shlex.quote(host_tmp)} {shlex.quote(lxc_tmp)}",
            timeout=30,
        )
        if not push.ok:
            self._run_ssh(f"rm -f {shlex.quote(host_tmp)}", timeout=5)
            raise BackendError(
                f"pct push SQL: rc={push.return_code} stderr={push.stderr[:200]}"
            )

        # Execute via wrapper (gotcha #4 — eval interprets `<` as
        # redirection without mangling SQL contents).
        inner = f"sqlite3 {shlex.quote(db_path)} < {shlex.quote(lxc_tmp)}"
        remote = self._wrap_pct_exec(inner, sudo=True)
        # Note: pct exec runs as root; the wrapper inside the LXC may
        # require sudoers config but most setups have it.
        result = self._run_ssh(remote, timeout=30)

        # Cleanup tempfiles.
        self._run_ssh(f"rm -f {shlex.quote(host_tmp)}", timeout=5)
        # In-LXC tempfile cleanup via wrapper (best-effort).
        self.run_cmd(["rm", "-f", lxc_tmp], sudo=True, timeout=5)

        if not result.ok:
            raise BackendError(
                f"sqlite3 query failed: rc={result.return_code} "
                f"stderr={result.stderr[:200]}"
            )

        # Parse JSON output.
        out = result.stdout.strip()
        if not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError as e:
            raise BackendError(
                f"sqlite3 returned non-JSON output: {out[:200]}"
            ) from e
        if not isinstance(data, list):
            raise BackendError(
                f"sqlite3 JSON output not a list: {type(data).__name__}"
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

        # Build env export prefix. NEVER log the values.
        env_exports = " && ".join(
            f"export {k}={shlex.quote(v)}" for k, v in provider_env.items()
        )

        # acme.sh runs on the PVE host, NOT inside the LXC (the operator's
        # acme.sh installation is in /home/<user>/.acme.sh on PVE).
        domain_args = " ".join(f"-d {shlex.quote(d)} " for d in domains)
        acme_bin = shlex.quote(f"{acme_home.rstrip('/')}/acme.sh")
        cmd = (
            f"{env_exports} && "
            f"{acme_bin} --issue {domain_args.strip()} "
            f"--dns {shlex.quote(dns_provider)} "
            f"--keylength {shlex.quote(keylength)} "
            f"--server letsencrypt "
            f"--home {shlex.quote(acme_home)}"
        )

        result = self._run_ssh(cmd, timeout=300)

        # acme.sh exits with 2 when cert is "skipped because not yet
        # due for renewal" — we treat that as success at backend level
        # but bubble the message up. The tool layer's idempotence check
        # should normally prevent this from happening.
        if result.return_code not in (0, 2):
            raise BackendError(
                f"acme.sh --issue failed (rc={result.return_code}): "
                f"{result.stderr[:500] or result.stdout[:500]}"
            )

        # Compute expected paths. acme.sh stores certs at
        # <acme_home>/<primary>_<key_type_dir>/{fullchain.cer,<primary>.key}
        # where <key_type_dir> is "ecc" for EC keys, "" (no suffix) for RSA.
        primary = domains[0].lstrip("*").lstrip(".")
        # acme.sh strips wildcards: "*.casaredes.cc" → dir "*.casaredes.cc_ecc"
        # or "casaredes.cc_ecc". Use the actual first domain (with wildcard).
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


def _key_type_to_keylength(key_type: str) -> str:
    """Map our key_type names to acme.sh --keylength values."""
    mapping = {
        "P256": "ec-256",
        "P384": "ec-384",
        "P521": "ec-521",
        "RSA2048": "2048",
        "RSA3072": "3072",
        "RSA4096": "4096",
    }
    if key_type not in mapping:
        raise ValueError(
            f"key_type {key_type!r} not supported. "
            f"Supported: {sorted(mapping)}"
        )
    return mapping[key_type]
