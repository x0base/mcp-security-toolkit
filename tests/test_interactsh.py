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


def test_register_rejects_flag_like_server():
    """`server` starting with `-` could be parsed as a flag by the CLI."""
    r = mod.interactsh_register(server="--config=/etc/passwd")
    assert r["available"] is False
    assert "invalid server" in r["error"]


def test_register_rejects_shell_metachar_server():
    r = mod.interactsh_register(server="evil.com; rm -rf /")
    assert r["available"] is False
    assert "invalid server" in r["error"]


def test_poll_handles_corrupt_session_json():
    """A malformed session.json must not crash _poll."""
    mod.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    token = "dddd44445555"
    sp = mod.SESSIONS_DIR / f"{token}.json"
    sp.write_text("{ not valid json")
    try:
        r = mod.interactsh_poll(token)
        assert "error" in r
        assert "failed to read session" in r["error"]
    finally:
        sp.unlink(missing_ok=True)


def test_poll_invalid_token_input():
    r = mod.interactsh_poll("")
    assert "error" in r


def test_poll_unknown_token():
    # 12 hex chars but not registered
    r = mod.interactsh_poll("abcdef012345")
    assert "error" in r
    assert "unknown" in r["error"]


def test_poll_rejects_path_traversal_token():
    r = mod.interactsh_poll("../../../etc/passwd")
    assert r["error"].startswith("invalid token format")


def test_poll_rejects_non_hex_token():
    r = mod.interactsh_poll("ZZZZZZZZZZZZ")
    assert r["error"].startswith("invalid token format")


def test_stop_rejects_path_traversal_token():
    r = mod.interactsh_stop("../malicious")
    assert r["error"].startswith("invalid token format")


def test_poll_rejects_log_path_outside_sessions_dir(tmp_path: Path):
    # Simulate tampered session: log_path points outside SESSIONS_DIR
    outside_log = tmp_path / "evil.log"
    outside_log.write_text('{"protocol":"dns"}\n')
    token = "deadbeef0000"
    session_path = mod.SESSIONS_DIR / f"{token}.json"
    mod.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    session_path.write_text(json.dumps({
        "server": "interact.sh",
        "callback_url": "u.oast.fun",
        "pid": 0,
        "log_path": str(outside_log),  # ← outside
        "started": 0,
    }))
    try:
        r = mod.interactsh_poll(token)
        assert "error" in r
        assert "escaped" in r["error"]
    finally:
        session_path.unlink(missing_ok=True)
        outside_log.unlink(missing_ok=True)


def test_stop_refuses_to_unlink_outside_sessions_dir(tmp_path: Path):
    # Tampered session points log_path outside SESSIONS_DIR; stop must not unlink it.
    outside_log = tmp_path / "outside.log"
    outside_log.write_text("nope")
    token = "beefdead0001"
    session_path = mod.SESSIONS_DIR / f"{token}.json"
    mod.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    session_path.write_text(json.dumps({
        "server": "interact.sh",
        "callback_url": "u.oast.fun",
        "pid": 0,
        "log_path": str(outside_log),
        "started": 0,
    }))
    try:
        r = mod.interactsh_stop(token, delete_log=True)
        assert "error" not in r
        assert r["log_removed"] is False
        assert outside_log.exists(), "stop must NOT remove files outside sessions dir"
    finally:
        outside_log.unlink(missing_ok=True)


def test_poll_reads_session_log():
    mod.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    log = mod.SESSIONS_DIR / "aaaa11112222.log"
    log.write_text(json.dumps({
        "protocol": "dns", "unique-id": "u1", "full-id": "u1.oast.fun",
        "raw-request": "A? u1.oast.fun", "timestamp": "2026-05-16T00:00:00Z",
    }) + "\n")
    session_path = mod.SESSIONS_DIR / "aaaa11112222.json"
    session_path.write_text(json.dumps({
        "server": "interact.sh",
        "callback_url": "u1.oast.fun",
        "pid": 0,
        "log_path": str(log),
        "started": 0,
    }))
    try:
        r = mod.interactsh_poll("aaaa11112222")
        assert r["count"] == 1
        assert r["interactions"][0]["protocol"] == "dns"
        assert r["interactions"][0]["unique_id"] == "u1"
    finally:
        session_path.unlink(missing_ok=True)
        log.unlink(missing_ok=True)


def test_stop_unknown_token():
    r = mod.interactsh_stop("ffffeeee0000")
    assert "error" in r


def test_stop_invalid_token_input():
    r = mod.interactsh_stop("")
    assert "error" in r


def test_stop_cleans_session_and_log():
    mod.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    log = mod.SESSIONS_DIR / "bbbb22223333.log"
    log.write_text('{"protocol":"dns"}\n')
    session_path = mod.SESSIONS_DIR / "bbbb22223333.json"
    session_path.write_text(json.dumps({
        "server": "interact.sh",
        "callback_url": "u.oast.fun",
        "pid": 0,  # zero — no real process to signal
        "log_path": str(log),
        "started": 0,
    }))
    r = mod.interactsh_stop("bbbb22223333", delete_log=True)
    assert "error" not in r
    assert r["log_removed"] is True
    assert not session_path.exists()
    assert not log.exists()


def test_poll_no_interactions_returns_helpful_note():
    mod.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    log = mod.SESSIONS_DIR / "cccc33334444.log"
    log.write_text("")
    session_path = mod.SESSIONS_DIR / "cccc33334444.json"
    session_path.write_text(json.dumps({
        "server": "interact.sh",
        "callback_url": "u2.oast.fun",
        "pid": 0,
        "log_path": str(log),
        "started": 0,
    }))
    try:
        r = mod.interactsh_poll("cccc33334444")
        assert r["count"] == 0
        assert "no interactions" in r["note"]
    finally:
        session_path.unlink(missing_ok=True)
        log.unlink(missing_ok=True)
