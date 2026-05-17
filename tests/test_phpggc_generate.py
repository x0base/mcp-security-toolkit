"""Tests for phpggc_generate — covers opt-in gate, input validation, and
absent-binary path.

End-to-end tests against a real phpggc binary are an integration concern;
this suite covers the cases that don't require it.
"""
from unittest.mock import patch

import pytest

from mcp_security_toolkit.tools.phpggc_generate import OPT_IN_ENV, phpggc_generate


@pytest.fixture
def opt_in(monkeypatch):
    monkeypatch.setenv(OPT_IN_ENV, "1")


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv(OPT_IN_ENV, raising=False)
    r = phpggc_generate(chain="Laravel/RCE9", command="id")
    assert r["error"] == "offensive-tool-disabled"
    assert OPT_IN_ENV in r["hint"]


def test_missing_chain(opt_in):
    r = phpggc_generate(chain="", command="id")
    assert "error" in r
    assert "chain" in r["error"]


def test_missing_command(opt_in):
    r = phpggc_generate(chain="Laravel/RCE9", command="")
    assert "error" in r
    assert "command" in r["error"]


def test_invalid_encoding(opt_in):
    r = phpggc_generate(chain="Laravel/RCE9", command="id", encoding="weird")  # type: ignore[arg-type]
    assert "error" in r
    assert "encoding" in r["error"]


def test_binary_not_installed(opt_in):
    with patch("mcp_security_toolkit.tools.phpggc_generate.shutil.which", return_value=None):
        r = phpggc_generate(chain="Laravel/RCE9", command="id")
    assert r["available"] is False
    assert "phpggc" in r["stderr"].lower()


def test_double_dash_separator_in_argv(opt_in):
    """Positional args must be preceded by `--` so a `chain` starting with
    `-` cannot be reinterpreted as a phpggc flag."""
    from subprocess import CompletedProcess

    fake = CompletedProcess(args=[], returncode=0, stdout="payload", stderr="")
    with patch("mcp_security_toolkit.tools.phpggc_generate.shutil.which", return_value="/fake/phpggc"), \
         patch("mcp_security_toolkit.tools.phpggc_generate.subprocess.run", return_value=fake) as run:
        r = phpggc_generate(chain="Laravel/RCE9", command="id", encoding="base64")
    assert r["payload"] == "payload"
    argv = run.call_args[0][0]
    assert "--" in argv
    dash_idx = argv.index("--")
    # chain and command come AFTER `--`
    assert argv[dash_idx + 1] == "Laravel/RCE9"
    assert argv[dash_idx + 2] == "id"
