"""Wrap the `interactsh-client` CLI for OOB (out-of-band) interaction capture.

Two atomic tools, both stateless from the caller's perspective:

  - `interactsh_register(server)` — spawn an interactsh-client and return the
    public callback URL plus a local session token. The client runs detached;
    pollers find it via the token.

  - `interactsh_poll(token, timeout)` — read captured interactions for the
    given token from a session file on disk.

This is a thin wrapper. The interactsh-client binary owns the cryptography
and the polling loop. We give the agent a clean request/response shape.

Install: https://github.com/projectdiscovery/interactsh
Default server: https://interact.sh (public) — override via `server`.

For authorized testing only.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from pydantic import BaseModel, Field

SESSIONS_DIR = Path(tempfile.gettempdir()) / "mcp_security_toolkit_interactsh"
URL_REGEX = re.compile(r"([a-z0-9]+\.(?:oast\.|interact\.).+?)(?:\s|$)", re.IGNORECASE)

# Matches exactly what `uuid.uuid4().hex[:12]` produces. Strict.
TOKEN_REGEX = re.compile(r"^[a-f0-9]{12}$")

# Conservative hostname/IP shape: letters, digits, dot, hyphen, underscore,
# colon (for IPv6 / port). Rejects values starting with `-` (would be parsed
# as a flag by the interactsh-client CLI) and any shell metacharacters.
SERVER_REGEX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,253}$")

DEFAULT_TTL_SECONDS = 3600  # 1 hour
DEFAULT_MAX_LOG_BYTES = 1024 * 1024  # 1 MB


def _validate_token(token: str) -> bool:
    return isinstance(token, str) and bool(TOKEN_REGEX.match(token))


def _validate_server(server: str) -> bool:
    return isinstance(server, str) and bool(SERVER_REGEX.match(server))


def _path_is_inside(child: Path, parent: Path) -> bool:
    """True iff resolved `child` is at or below resolved `parent`."""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


class RegisterReport(BaseModel):
    available: bool
    token: str | None = None
    callback_url: str | None = None
    pid: int | None = None
    server: str
    error: str | None = None


class Interaction(BaseModel):
    protocol: str
    unique_id: str | None = None
    full_id: str | None = None
    raw: str | None = None
    timestamp: str | None = None


class PollReport(BaseModel):
    token: str
    server: str | None = None
    callback_url: str | None = None
    interactions: list[Interaction] = Field(default_factory=list)
    count: int = 0
    note: str | None = None


def _session_path(token: str) -> Path:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(SESSIONS_DIR, 0o700)
    except OSError:
        pass
    return SESSIONS_DIR / f"{token}.json"


def _secure_write(path: Path, content: str) -> None:
    """Write file with 0600 perms atomically — no world-readable window."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    # If the file pre-existed with looser perms, `os.open` does NOT change
    # them — normalize explicitly.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _gc_old_sessions(ttl_seconds: int = DEFAULT_TTL_SECONDS) -> int:
    """Sweep sessions whose started+ttl is in the past. Returns count removed."""
    if not SESSIONS_DIR.exists():
        return 0
    cutoff = time.time() - ttl_seconds
    removed = 0
    for sf in SESSIONS_DIR.glob("*.json"):
        try:
            session = json.loads(sf.read_text())
            if session.get("started", 0) < cutoff:
                # try to stop the process if still running
                pid = session.get("pid")
                if isinstance(pid, int) and pid > 0:
                    try:
                        os.killpg(os.getpgid(pid), signal.SIGTERM)
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                log = Path(session.get("log_path", ""))
                # Defense in depth: same boundary check as poll/stop.
                if log.exists() and _path_is_inside(log, SESSIONS_DIR):
                    log.unlink(missing_ok=True)
                sf.unlink(missing_ok=True)
                removed += 1
        except (OSError, json.JSONDecodeError):
            continue
    return removed


def interactsh_register(server: str = "interact.sh", timeout: float = 8.0) -> dict:
    """Register a new interactsh callback URL via the `interactsh-client` CLI.

    Spawns interactsh-client detached, captures the assigned callback URL,
    and persists a session descriptor for later polling. Returns a token
    that pairs with `interactsh_poll`.

    Args:
        server: interactsh server hostname (default `interact.sh` public).
        timeout: seconds to wait for the client to emit its URL.

    Returns:
        RegisterReport with `callback_url` and `token`.
    """
    if not _validate_server(server):
        return RegisterReport(
            available=False, server=str(server),
            error="invalid server value (expected hostname/IP, alnum + . _ - : only)",
        ).model_dump()

    bin_path = shutil.which("interactsh-client")
    if not bin_path:
        return RegisterReport(
            available=False, server=server,
            error="interactsh-client not found on PATH — install from https://github.com/projectdiscovery/interactsh",
        ).model_dump()

    _gc_old_sessions()

    token = uuid.uuid4().hex[:12]
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(SESSIONS_DIR, 0o700)
    except OSError:
        pass
    log_path = SESSIONS_DIR / f"{token}.log"
    _secure_write(log_path, "")

    args = [bin_path, "-s", server, "-json", "-o", str(log_path)]
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True,
        )
    except OSError as e:
        return RegisterReport(
            available=True, server=server, error=f"failed to start interactsh-client: {e}",
        ).model_dump()

    callback_url: str | None = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.stdout is None or proc.poll() is not None:
            break
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue
        m = URL_REGEX.search(line)
        if m:
            callback_url = m.group(1).strip()
            break

    if not callback_url:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        return RegisterReport(
            available=True, server=server,
            error="interactsh-client did not emit a callback URL within timeout",
        ).model_dump()

    _secure_write(_session_path(token), json.dumps({
        "server": server,
        "callback_url": callback_url,
        "pid": proc.pid,
        "log_path": str(log_path),
        "started": time.time(),
    }))

    return RegisterReport(
        available=True, token=token, callback_url=callback_url,
        pid=proc.pid, server=server,
    ).model_dump()


def interactsh_poll(token: str) -> dict:
    """Read captured OOB interactions for a previously-registered token.

    Args:
        token: token returned by `interactsh_register`.

    Returns:
        PollReport with all interactions captured so far.
    """
    if not _validate_token(token):
        return {"error": "invalid token format (expected 12 hex chars from interactsh_register)"}

    sp = _session_path(token)
    if not sp.exists():
        return {"error": f"unknown token: {token}"}

    try:
        session = json.loads(sp.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return {"error": f"failed to read session: {e}"}
    log_path = Path(str(session.get("log_path", "")))
    if not _path_is_inside(log_path, SESSIONS_DIR):
        return {"error": "session log_path escaped sessions dir — possible tampering"}
    interactions: list[Interaction] = []

    if log_path.exists():
        # cap to avoid pathological allocations on huge logs
        try:
            log_data = log_path.read_text()
        except OSError as e:
            return {"error": f"failed to read session log: {e}"}
        if len(log_data) > DEFAULT_MAX_LOG_BYTES:
            log_data = log_data[-DEFAULT_MAX_LOG_BYTES:]
        for line in log_data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            interactions.append(Interaction(
                protocol=str(obj.get("protocol", "unknown")),
                unique_id=obj.get("unique-id") or obj.get("unique_id"),
                full_id=obj.get("full-id") or obj.get("full_id"),
                raw=obj.get("raw-request") or obj.get("raw_request"),
                timestamp=obj.get("timestamp"),
            ))

    note = None
    if not interactions:
        note = (
            "no interactions captured yet — fire the callback URL from your target "
            "(curl, DNS lookup, SSRF probe, XXE entity, etc.) and re-poll"
        )

    return PollReport(
        token=token,
        server=session.get("server"),
        callback_url=session.get("callback_url"),
        interactions=interactions,
        count=len(interactions),
        note=note,
    ).model_dump()


def interactsh_stop(token: str, delete_log: bool = True) -> dict:
    """Stop a previously-registered interactsh-client session and clean up.

    Terminates the spawned `interactsh-client` process (best-effort) and
    removes the session descriptor. The log file is removed by default
    (set `delete_log=False` to keep it for post-mortem).

    Args:
        token: token returned by `interactsh_register`.
        delete_log: also remove the session log file (default True).

    Returns:
        {"stopped": bool, "log_removed": bool, "note": str | None}
    """
    if not _validate_token(token):
        return {"error": "invalid token format (expected 12 hex chars from interactsh_register)"}

    sp = _session_path(token)
    if not sp.exists():
        return {"error": f"unknown token: {token}"}

    try:
        session = json.loads(sp.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return {"error": f"failed to read session: {e}"}

    stopped = False
    pid = session.get("pid")
    if isinstance(pid, int) and pid > 0:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            stopped = True
        except (ProcessLookupError, PermissionError, OSError):
            stopped = False

    log_removed = False
    if delete_log:
        log = Path(session.get("log_path", ""))
        # Defense in depth: never unlink anything outside our sessions dir,
        # even if a tampered session descriptor points elsewhere.
        if log.exists() and _path_is_inside(log, SESSIONS_DIR):
            try:
                log.unlink()
                log_removed = True
            except OSError:
                log_removed = False

    sp.unlink(missing_ok=True)

    return {
        "stopped": stopped,
        "log_removed": log_removed,
        "note": None if stopped else "process already exited or no permission to signal",
    }
