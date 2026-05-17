"""Tests for phpggc_generate — covers input validation and absent-binary path.

End-to-end tests against a real phpggc binary are an integration concern;
this suite covers the cases that don't require it.
"""
from unittest.mock import patch

from mcp_security_toolkit.tools.phpggc_generate import phpggc_generate


def test_missing_chain():
    r = phpggc_generate(chain="", command="id")
    assert "error" in r


def test_missing_command():
    r = phpggc_generate(chain="Laravel/RCE9", command="")
    assert "error" in r


def test_invalid_encoding():
    r = phpggc_generate(chain="Laravel/RCE9", command="id", encoding="weird")  # type: ignore[arg-type]
    assert "error" in r


def test_binary_not_installed():
    with patch("mcp_security_toolkit.tools.phpggc_generate.shutil.which", return_value=None):
        r = phpggc_generate(chain="Laravel/RCE9", command="id")
    assert r["available"] is False
    assert "phpggc" in r["stderr"].lower()
