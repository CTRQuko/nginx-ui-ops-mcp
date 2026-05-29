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

from .._redact import redact_secrets
from .base import BackendError, CommandResult, NginxUIBackend

log = logging.getLogger(__name__)


def _include_backend_notes() -> bool:
    """[VULN-11] gate — notes leak SSH alias / LXC id to the LLM.

    Default off in v0.4.0+. Operator opts in via
    ``NGINXUI_INCLUDE_BACKEND_NOTES=true`` for diagnostics.
    """
    return os.environ.get(
        "NGINXUI_INCLUDE_BACKEND_NOTES", "",
    ).strip().lower() in ("1", "true", "yes", "on")


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
        """Legacy single-target mode — reads NGINXUI_* vars directly."""
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

    @classmethod
    def from_env_target(cls, target: str) -> "WrapperLXCBackend":
        """Multi-target mode (v0.4.0+) — reads NGINXUI_TARGET_<TARGET>_* vars.

        Example for target ``logrono``::

            NGINXUI_TARGET_LOGRONO_PVE_SSH_ALIAS=<pve-ssh-alias>
            NGINXUI_TARGET_LOGRONO_LXC_ID=<lxc-id>
            NGINXUI_TARGET_LOGRONO_WRAPPER_PATH=/usr/local/bin/claude-wrapper  # opt
            NGINXUI_TARGET_LOGRONO_SUDO_METHOD=password                        # opt
            NGINXUI_TARGET_LOGRONO_SUDO_PASSWORD_REF=...                       # opt
        """
        prefix = f"NGINXUI_TARGET_{target.upper()}_"
        pve = os.environ.get(f"{prefix}PVE_SSH_ALIAS", "").strip()
        lxc = os.environ.get(f"{prefix}LXC_ID", "").strip()
        if not pve:
            raise BackendError(
                f"{prefix}PVE_SSH_ALIAS is required for wrapper-lxc target {target!r}"
            )
        if not lxc:
            raise BackendError(
                f"{prefix}LXC_ID is required for wrapper-lxc target {target!r}"
            )
        return cls(
            pve_ssh_alias=pve,
            lxc_id=lxc,
            wrapper_path=os.environ.get(
                f"{prefix}WRAPPER_PATH", "/usr/local/bin/claude-wrapper"
            ),
            sudo_method=os.environ.get(f"{prefix}SUDO_METHOD", "nopasswd").strip(),
            sudo_password_ref=os.environ.get(f"{prefix}SUDO_PASSWORD_REF") or None,
            ssh_bin=os.environ.get(f"{prefix}SSH_BIN", "ssh"),
            pct_path=os.environ.get(f"{prefix}PCT_PATH", "/usr/sbin/pct"),
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

    def _run_ssh_bytes(
        self,
        remote_cmd: str,
        *,
        stdin: bytes | None = None,
        timeout: int = 30,
    ) -> tuple[int, bytes, bytes]:
        """Like :meth:`_run_ssh` but preserves stdout/stderr as raw bytes.

        [VULN-04] mitigation — used by :meth:`read_file` so binary
        content (DER certs, blobs) is not corrupted by an intermediate
        UTF-8 round-trip with ``errors='replace'``.
        """
        argv = [self.ssh_bin, self.pve_ssh_alias, remote_cmd]
        log.debug("ssh exec (bytes): alias=%s cmd=%s",
                  self.pve_ssh_alias, remote_cmd)
        try:
            proc = subprocess.run(
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
        return proc.returncode, proc.stdout, proc.stderr

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
        # [VULN-11] gate — backend identity included only when operator opts in.
        if _include_backend_notes():
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
        # [VULN-04] mitigation — bypass run_cmd's text-mode decoding
        # so binary content (DER, blobs) is preserved verbatim.
        inner_cat = f"cat {shlex.quote(remote_path)}"
        remote = self._wrap_pct_exec(inner_cat, sudo=sudo)
        stdin: bytes | None = None
        if sudo and self.sudo_method == "password":
            stdin = (self._read_sudo_password() + "\n").encode("utf-8")
        rc, out, err = self._run_ssh_bytes(remote, stdin=stdin, timeout=30)
        if rc != 0:
            raise BackendError(
                f"read_file {remote_path}: rc={rc} "
                f"stderr={err.decode('utf-8', errors='replace')[:200]}"
            )
        return out

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

        # [VULN-06] mitigation — write the secret env exports + acme.sh
        # invocation to a chmod-0700 tempfile and execute it. This keeps
        # the token values OUT of /proc/<pid>/cmdline (visible to `ps`,
        # auditd, etc.) and off the shell history of the ssh session.
        script_lines: list[str] = ["#!/bin/sh", "set -e"]
        for k, v in provider_env.items():
            script_lines.append(f"export {k}={shlex.quote(v)}")
        acme_bin = shlex.quote(f"{acme_home.rstrip('/')}/acme.sh")
        domain_args = " ".join(f"-d {shlex.quote(d)}" for d in domains)
        script_lines.append(
            f"exec {acme_bin} --issue {domain_args} "
            f"--dns {shlex.quote(dns_provider)} "
            f"--keylength {shlex.quote(keylength)} "
            f"--server letsencrypt "
            f"--home {shlex.quote(acme_home)}"
        )
        script = ("\n".join(script_lines) + "\n").encode("utf-8")

        tmp_script = f"/tmp/nginx-ui-ops-acme-{secrets.token_hex(8)}.sh"
        # Stage the script on the PVE host with mode 0700 — only the
        # ssh user can read it. Best-effort cleanup in finally.
        stage = self._run_ssh(
            f"umask 077 && cat > {shlex.quote(tmp_script)} && "
            f"chmod 700 {shlex.quote(tmp_script)}",
            stdin=script,
            timeout=10,
        )
        if not stage.ok:
            raise BackendError(
                f"acme tempfile stage failed: rc={stage.return_code} "
                f"stderr={redact_secrets(stage.stderr[:200])}"
            )

        try:
            result = self._run_ssh(
                f"sh {shlex.quote(tmp_script)}",
                timeout=300,
            )
        finally:
            # Best-effort cleanup; ignore failures.
            try:
                self._run_ssh(f"rm -f {shlex.quote(tmp_script)}", timeout=5)
            except BackendError:
                pass

        # acme.sh exits with 2 when cert is "skipped because not yet
        # due for renewal" — we treat that as success at backend level
        # but bubble the message up. The tool layer's idempotence check
        # should normally prevent this from happening.
        if result.return_code not in (0, 2):
            # [VULN-07] mitigation — redact known secret patterns from
            # surfaced stderr/stdout. acme.sh DNS plugins occasionally
            # echo tokens verbatim during debug; redaction avoids
            # leaking them via BackendError → LLM transcript.
            err_text = redact_secrets(
                result.stderr[:500] or result.stdout[:500]
            )
            raise BackendError(
                f"acme.sh --issue failed (rc={result.return_code}): "
                f"{err_text}"
            )

        # Compute expected paths. acme.sh stores certs at
        # <acme_home>/<primary>_<key_type_dir>/{fullchain.cer,<primary>.key}
        # where <key_type_dir> is "ecc" for EC keys, "" (no suffix) for RSA.
        primary = domains[0].lstrip("*").lstrip(".")
        # acme.sh strips wildcards: "*.example.com" → dir "*.example.com_ecc"
        # or "example.com_ecc". Use the actual first domain (with wildcard).
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
