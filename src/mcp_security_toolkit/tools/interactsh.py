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
    return SESSIONS_DIR / f"{token}.json"


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
    bin_path = shutil.which("interactsh-client")
    if not bin_path:
        return RegisterReport(
            available=False, server=server,
            error="interactsh-client not found on PATH — install from https://github.com/projectdiscovery/interactsh",
        ).model_dump()

    token = uuid.uuid4().hex[:12]
    log_path = SESSIONS_DIR / f"{token}.log"
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    log_path.write_text("")

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

    _session_path(token).write_text(json.dumps({
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
    if not isinstance(token, str) or not token.strip():
        return {"error": "token must be a non-empty string"}

    sp = _session_path(token)
    if not sp.exists():
        return {"error": f"unknown token: {token}"}

    session = json.loads(sp.read_text())
    log_path = Path(session["log_path"])
    interactions: list[Interaction] = []

    if log_path.exists():
        for line in log_path.read_text().splitlines():
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
