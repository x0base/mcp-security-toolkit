"""Tests for interactsh wrappers.

Real interactsh-client invocation is an integration concern; this suite covers:
  - graceful behavior when the binary is absent
  - input validation
  - poll-without-known-token
  - reading captured interactions from a known session log
"""
import json
from pathlib import Path
from unittest.mock import patch

from mcp_security_toolkit.tools import interactsh as mod


def test_register_binary_missing():
    with patch.object(mod.shutil, "which", return_value=None):
        r = mod.interactsh_register()
    assert r["available"] is False
    assert "interactsh-client" in r["error"]


def test_poll_invalid_token_input():
    r = mod.interactsh_poll("")
    assert "error" in r


def test_poll_unknown_token():
    r = mod.interactsh_poll("definitely-not-a-real-token-xyz")
    assert "error" in r


def test_poll_reads_session_log(tmp_path: Path):
    log = tmp_path / "log.jsonl"
    log.write_text(json.dumps({
        "protocol": "dns", "unique-id": "u1", "full-id": "u1.oast.fun",
        "raw-request": "A? u1.oast.fun", "timestamp": "2026-05-16T00:00:00Z",
    }) + "\n")
    session_path = mod.SESSIONS_DIR / "test-token-xyz.json"
    mod.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    session_path.write_text(json.dumps({
        "server": "interact.sh",
        "callback_url": "u1.oast.fun",
        "pid": 0,
        "log_path": str(log),
        "started": 0,
    }))
    try:
        r = mod.interactsh_poll("test-token-xyz")
        assert r["count"] == 1
        assert r["interactions"][0]["protocol"] == "dns"
        assert r["interactions"][0]["unique_id"] == "u1"
    finally:
        session_path.unlink(missing_ok=True)


def test_poll_no_interactions_returns_helpful_note(tmp_path: Path):
    log = tmp_path / "empty.jsonl"
    log.write_text("")
    session_path = mod.SESSIONS_DIR / "empty-token-xyz.json"
    mod.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    session_path.write_text(json.dumps({
        "server": "interact.sh",
        "callback_url": "u2.oast.fun",
        "pid": 0,
        "log_path": str(log),
        "started": 0,
    }))
    try:
        r = mod.interactsh_poll("empty-token-xyz")
        assert r["count"] == 0
        assert "no interactions" in r["note"]
    finally:
        session_path.unlink(missing_ok=True)
