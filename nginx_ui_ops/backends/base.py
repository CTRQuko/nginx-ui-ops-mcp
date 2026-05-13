"""NginxUIBackend ABC — transport interface for nginx-ui ops.

Backends encapsulate **how** commands reach the nginx-ui host. Two
ship in v0.1.0 (``WrapperLXCBackend``, ``DirectSSHBackend``); the
ABC keeps room for ``DockerExecBackend``, ``LocalBackend``, etc.

Design contract:

- All methods MUST be exception-safe in the sense that connectivity
  failures raise :class:`BackendError` (a subclass of ``RuntimeError``)
  with a human-readable message — they don't bubble up
  ``subprocess.CalledProcessError`` or low-level network exceptions.
  Tool layer catches ``BackendError`` and surfaces it to the LLM.

- ``run_cmd`` returns a structured ``CommandResult`` instead of
  ``subprocess.CompletedProcess`` so backends that don't shell out
  (e.g. a future ``DockerSDKBackend``) can implement it natively.

- Idempotence and rate-limit safety live at the **tool** layer, not
  the backend. The backend just executes what it's asked to execute.

- Backends MUST handle the well-known transport gotchas internally
  (encoding normalization, sudo/stdin separation, eval-quoting in
  shell wrappers, etc.). Tool callers should never have to think
  about them.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class BackendError(RuntimeError):
    """Raised by backend methods when transport / command fails.

    Distinguishes deliberate transport problems from programming
    errors. Tool code catches this to translate into MCP errors with
    operator-friendly messages.
    """


@dataclass
class CommandResult:
    """Outcome of a command run on the nginx-ui host."""

    return_code: int
    stdout: str = ""
    stderr: str = ""
    # Optional metadata the backend may surface (e.g. "ran via wrapper",
    # "sudoers rule matched", etc.) — purely informational.
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.return_code == 0


class NginxUIBackend(ABC):
    """Abstract transport for ops on a remote nginx-ui host.

    Implementations:
      - :class:`~nginx_ui_ops.backends.wrapper_lxc.WrapperLXCBackend`
      - :class:`~nginx_ui_ops.backends.direct_ssh.DirectSSHBackend`
      - :class:`~nginx_ui_ops.backends.docker_exec.DockerExecBackend` (v0.4.0+)

    Subclasses MUST implement all 6 abstract methods. They MAY override
    :meth:`describe` for richer diagnostics (default uses class name).

    Class attribute :attr:`supports_acme` (default True) signals whether
    this backend has ``acme.sh`` reachable. Backends running inside a
    minimal container (e.g. docker-exec on ``uozi/nginx-ui``) should
    set it to ``False`` so :func:`cert_issue` tools fail fast with a
    legible message instead of attempting an acme.sh that doesn't exist.
    """

    # Class-level capability flag. v0.4.0+ — defaults True for backward
    # compat. Subclasses override per-impl.
    supports_acme: bool = True

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    @classmethod
    @abstractmethod
    def from_env(cls) -> "NginxUIBackend":
        """Construct the backend from environment variables (legacy mode).

        Reads the historic single-target vars (``NGINXUI_PVE_SSH_ALIAS``,
        ``NGINXUI_LXC_ID``, ``NGINXUI_HOST``, etc.). The factory in
        ``backends.factory`` calls this when no ``NGINXUI_TARGETS``
        is declared.

        Raises :class:`BackendError` (or a more specific subclass) if
        required env vars are missing or malformed.
        """

    @classmethod
    def from_env_target(cls, target: str) -> "NginxUIBackend":
        """Construct the backend reading per-target env vars (v0.4.0+).

        Subclasses MUST override to read ``NGINXUI_TARGET_<TARGET>_*``
        vars. Default implementation raises NotImplementedError so a
        backend that hasn't been multi-target-enabled fails loudly
        instead of silently using legacy vars.

        Args:
            target: target name as declared in ``NGINXUI_TARGETS``.
                Used to construct env var prefixes (uppercased).

        Returns:
            Backend instance configured for this target.

        Raises:
            BackendError: required ``NGINXUI_TARGET_<T>_*`` vars missing.
            NotImplementedError: subclass hasn't implemented multi-target
                support.
        """
        raise NotImplementedError(
            f"{cls.__name__} hasn't implemented from_env_target(). "
            "Use from_env() (legacy mode) or upgrade the backend."
        )

    def describe(self) -> str:
        """Short human-readable identity of this backend instance.

        Used in error messages and logs. Default implementation returns
        the class name; backends should override to include the host /
        LXC ID / etc. they target (without leaking secrets).
        """
        return self.__class__.__name__

    # -----------------------------------------------------------------
    # Command execution
    # -----------------------------------------------------------------

    @abstractmethod
    def run_cmd(
        self,
        argv: list[str],
        *,
        sudo: bool = False,
        timeout: int = 30,
    ) -> CommandResult:
        """Run a command on the nginx-ui host.

        Args:
            argv: argument vector — first element is the binary, rest
                are its arguments. Backend MAY transparently route this
                through a wrapper (e.g. ``pct exec ... claude-wrapper``)
                — caller does not see that.
            sudo: when True, the backend MUST escalate privileges in a
                way that does **not** mix the password with stdin (a
                common ``echo PASS | sudo -S`` anti-pattern). The
                concrete escalation strategy is backend-specific
                (NOPASSWD sudoers, separate password channel, etc.).
            timeout: max seconds to wait for completion. On timeout the
                backend raises :class:`BackendError`.

        Returns:
            :class:`CommandResult` with stdout/stderr/return_code.

        Raises:
            BackendError: connectivity failure, timeout, sudo denied
                with no fallback, etc.
        """

    # -----------------------------------------------------------------
    # File I/O
    # -----------------------------------------------------------------

    @abstractmethod
    def push_file(
        self,
        content: bytes,
        remote_path: str,
        *,
        mode: int = 0o644,
        sudo: bool = False,
    ) -> None:
        """Place ``content`` at ``remote_path`` on the nginx-ui host.

        The implementation MUST normalize line endings on text-shaped
        content (e.g. strip ``\\r`` so a config edited on Windows
        doesn't break the wrapper that reads it). Heuristic for "is
        this text" is up to the backend; conservative default: only
        normalize when the content is valid UTF-8.

        Args:
            content: raw bytes. Caller passes whatever it has.
            remote_path: absolute path on the nginx-ui host.
            mode: octal POSIX mode for the resulting file. Backend
                should ``chmod`` after write.
            sudo: True when destination requires elevated privileges.
                Same escalation contract as :meth:`run_cmd`.

        Raises:
            BackendError: write failed (no perms, disk full, etc.).
        """

    @abstractmethod
    def read_file(self, remote_path: str, *, sudo: bool = False) -> bytes:
        """Fetch raw bytes of a file on the nginx-ui host.

        Returns the bytes verbatim — no encoding conversion. Caller
        decides how to decode. Useful for cert files, configs,
        binary blobs.

        Raises:
            BackendError: file not found, permission denied, etc.
        """

    # -----------------------------------------------------------------
    # SQLite query (gated through a wrapper that may mangle quotes)
    # -----------------------------------------------------------------

    @abstractmethod
    def query_db(
        self,
        db_path: str,
        sql: str,
        *,
        params: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        """Run a SQL query against an SQLite DB on the nginx-ui host.

        Returns each row as a dict keyed by column name.

        Backends MUST handle quote-preservation: if the transport runs
        through a shell wrapper that ``eval``s arguments (the operator's
        ``claude-wrapper`` does this), inline SQL with quotes will be
        destroyed. The mitigation is to write the SQL to a tempfile
        and redirect stdin (``sqlite3 db.sqlite < /tmp/q.sql``).
        Backends MUST do this transparently.

        Args:
            db_path: absolute path to the .db file on the host.
            sql: query string. Use ``?`` placeholders for params.
            params: tuple of values to bind to placeholders.

        Raises:
            BackendError: SQL error, locked DB, file not found, etc.
        """

    # -----------------------------------------------------------------
    # acme.sh cert issuance
    # -----------------------------------------------------------------

    @abstractmethod
    def acme_issue(
        self,
        domains: list[str],
        *,
        key_type: str,
        dns_provider: str,
        provider_env: dict[str, str],
        acme_home: str,
    ) -> dict[str, Any]:
        """Run ``acme.sh --issue`` on the host where acme.sh is installed.

        The plugin is **provider-agnostic**: this method just forwards
        ``dns_provider`` (a string like ``dns_cf``, ``dns_aws``,
        ``dns_do``) to ``acme.sh --dns <provider>`` and exports the
        ``provider_env`` dict into the subprocess scope (the backend
        MUST NOT log these values). The plugin does not know what
        env vars each provider needs — that's the operator's
        responsibility documented in README.

        A common pitfall (gotcha #1 in the operator log): some
        Cloudflare-restrictive tokens cause acme.sh to look up the
        wrong zone. The fix is to set ``CF_Zone_ID`` explicitly via
        ``provider_env`` — backends pass it through verbatim.

        Args:
            domains: list of FQDNs / wildcards for the cert SANs.
                First entry is the primary CN.
            key_type: e.g. ``P256``, ``P384``, ``RSA2048``. Mapped
                internally to ``--keylength`` flag.
            dns_provider: acme.sh DNS provider id (``dns_cf``,
                ``dns_aws``, ``dns_do``, etc.).
            provider_env: env vars to export into the subprocess. NOT
                logged. Caller composes this from the operator's
                scoped credentials.
            acme_home: path to the acme.sh installation dir on the
                host (e.g. ``/home/<user>/.acme.sh``).

        Returns:
            Dict with at least ``fullchain_path`` and ``key_path`` —
            absolute paths on the host where acme.sh stored the new
            cert. Caller passes these to a deploy step.

        Raises:
            BackendError: acme.sh failed (rate limit, DNS auth error,
                etc.). The error message includes the truncated stderr.
        """
