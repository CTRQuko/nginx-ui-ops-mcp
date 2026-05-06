"""Tests for the NginxUIBackend ABC contract.

These tests don't exercise a real backend implementation — they
verify the abstract surface is well-defined: subclasses MUST
implement all 6 methods, BackendError is the canonical failure
mode, and CommandResult behaves as expected.

Concrete backend tests live in test_wrapper_lxc.py / test_direct_ssh.py.
"""
from __future__ import annotations

import pytest

from nginx_ui_ops.backends.base import (
    BackendError,
    CommandResult,
    NginxUIBackend,
)


# ---------------------------------------------------------------------------
# CommandResult
# ---------------------------------------------------------------------------

def test_command_result_ok_when_rc_zero():
    r = CommandResult(return_code=0)
    assert r.ok is True


def test_command_result_not_ok_when_rc_nonzero():
    r = CommandResult(return_code=1)
    assert r.ok is False


def test_command_result_defaults_empty_streams():
    r = CommandResult(return_code=0)
    assert r.stdout == ""
    assert r.stderr == ""
    assert r.notes == []


def test_command_result_carries_streams():
    r = CommandResult(return_code=0, stdout="hello", stderr="warn")
    assert r.stdout == "hello"
    assert r.stderr == "warn"


def test_command_result_notes_independent_per_instance():
    """Defensive: dataclass field default_factory must produce a fresh
    list per instance — otherwise notes mutations leak across calls."""
    a = CommandResult(return_code=0)
    b = CommandResult(return_code=0)
    a.notes.append("from a")
    assert b.notes == []


# ---------------------------------------------------------------------------
# BackendError
# ---------------------------------------------------------------------------

def test_backend_error_is_runtime_error():
    """Tool layer can catch RuntimeError and get any backend failure."""
    assert issubclass(BackendError, RuntimeError)


def test_backend_error_carries_message():
    err = BackendError("connectivity timeout")
    assert "connectivity timeout" in str(err)


# ---------------------------------------------------------------------------
# NginxUIBackend ABC enforcement
# ---------------------------------------------------------------------------

def test_cannot_instantiate_abc_directly():
    with pytest.raises(TypeError):
        NginxUIBackend()  # type: ignore[abstract]


def test_subclass_missing_methods_cannot_instantiate():
    """Forgotten abstract methods must fail loud at instantiation."""

    class Half(NginxUIBackend):
        @classmethod
        def from_env(cls):
            return cls()

        def run_cmd(self, argv, *, sudo=False, timeout=30):
            return CommandResult(return_code=0)

        # Missing: push_file, read_file, query_db, acme_issue.

    with pytest.raises(TypeError):
        Half()  # type: ignore[abstract]


def test_subclass_implementing_all_methods_can_instantiate():
    """Sanity: a complete subclass instantiates without issues."""

    class Complete(NginxUIBackend):
        @classmethod
        def from_env(cls):
            return cls()

        def run_cmd(self, argv, *, sudo=False, timeout=30):
            return CommandResult(return_code=0)

        def push_file(self, content, remote_path, *, mode=0o644, sudo=False):
            return None

        def read_file(self, remote_path, *, sudo=False):
            return b""

        def query_db(self, db_path, sql, *, params=()):
            return []

        def acme_issue(self, domains, *, key_type, dns_provider, provider_env, acme_home):
            return {"fullchain_path": "/x", "key_path": "/y"}

    backend = Complete()
    # describe() default returns class name.
    assert backend.describe() == "Complete"


def test_subclass_can_override_describe():
    class WithIdentity(NginxUIBackend):
        @classmethod
        def from_env(cls):
            return cls()

        def run_cmd(self, argv, *, sudo=False, timeout=30):
            return CommandResult(return_code=0)

        def push_file(self, content, remote_path, *, mode=0o644, sudo=False):
            return None

        def read_file(self, remote_path, *, sudo=False):
            return b""

        def query_db(self, db_path, sql, *, params=()):
            return []

        def acme_issue(self, domains, *, key_type, dns_provider, provider_env, acme_home):
            return {}

        def describe(self) -> str:
            return "WithIdentity@example.host:9000"

    assert "example.host" in WithIdentity().describe()


# ---------------------------------------------------------------------------
# Method signatures — argument names matter for kwargs-only contracts
# ---------------------------------------------------------------------------

def test_run_cmd_keyword_only_args():
    """``sudo`` and ``timeout`` should be keyword-only — prevents
    accidental positional misuse like run_cmd(['nginx', '-t'], True)."""
    import inspect

    sig = inspect.signature(NginxUIBackend.run_cmd)
    params = sig.parameters
    assert params["sudo"].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["timeout"].kind == inspect.Parameter.KEYWORD_ONLY


def test_push_file_keyword_only_args():
    import inspect

    sig = inspect.signature(NginxUIBackend.push_file)
    params = sig.parameters
    assert params["mode"].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["sudo"].kind == inspect.Parameter.KEYWORD_ONLY


def test_acme_issue_keyword_only_args():
    """All non-positional args of acme_issue MUST be keyword-only —
    domains is the only positional."""
    import inspect

    sig = inspect.signature(NginxUIBackend.acme_issue)
    params = sig.parameters
    for name in ("key_type", "dns_provider", "provider_env", "acme_home"):
        assert params[name].kind == inspect.Parameter.KEYWORD_ONLY, (
            f"acme_issue.{name} should be keyword-only"
        )
