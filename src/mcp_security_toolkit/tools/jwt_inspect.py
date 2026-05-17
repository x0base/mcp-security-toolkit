"""JWT inspector.

Decodes a JWT, surfaces algorithm/claim issues, optionally tries a small
dictionary of common HS256 secrets to flag obviously weak signing keys.

No external dependencies — pure stdlib base64/json + hmac.
"""

from __future__ import annotations

import base64
import hmac
import json
import time
from hashlib import sha256, sha384, sha512
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high"]

DEFAULT_WEAK_SECRETS = [
    "secret", "password", "changeme", "admin", "12345", "test",
    "jwt", "key", "your-256-bit-secret", "your-secret-key", "1234567890",
    "qwerty", "supersecret", "default", "abc123",
]

HS_ALGS = {"HS256": sha256, "HS384": sha384, "HS512": sha512}


class JwtFinding(BaseModel):
    category: str
    severity: Severity
    message: str


class JwtInspection(BaseModel):
    valid_structure: bool
    header: dict | None = None
    payload: dict | None = None
    signature_b64: str | None = None
    findings: list[JwtFinding] = Field(default_factory=list)
    weak_secret: str | None = None
    weak_secret_check_performed: bool = False
    weak_secret_check_scope: str = (
        f"small_builtin_dictionary ({len(DEFAULT_WEAK_SECRETS)} entries) — "
        "absence of finding is NOT proof of strong secret"
    )


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def _try_weak_secret(token: str, alg: str, secrets: list[str]) -> str | None:
    if alg not in HS_ALGS:
        return None
    try:
        signing_input, signature = token.rsplit(".", 1)
    except ValueError:
        return None
    sig = _b64url_decode(signature)
    hashfn = HS_ALGS[alg]
    for s in secrets:
        mac = hmac.new(s.encode("utf-8"), signing_input.encode("ascii"), hashfn).digest()
        if hmac.compare_digest(mac, sig):
            return s
    return None


def jwt_inspect(token: str, check_weak_secrets: bool = True) -> dict:
    """Decode and audit a JWT.

    Reports algorithm issues (`none`, weak HS*), expiry, missing standard
    claims (`exp`, `iat`, `iss`, `aud`), suspicious `kid` values that look
    like path traversal or SQL, and (optionally) checks the signature
    against a small dictionary of common weak HS256/384/512 secrets.

    Args:
        token: The JWT string (three dot-separated base64url segments).
        check_weak_secrets: If True, attempt a small dictionary of common
            secrets against the signature for HS* algorithms. Default True.

    Returns:
        Structured inspection report (see JwtInspection schema).
    """
    result = JwtInspection(valid_structure=False)
    parts = token.split(".")
    if len(parts) != 3:
        result.findings.append(
            JwtFinding(
                category="malformed",
                severity="high",
                message=f"expected 3 segments, got {len(parts)}",
            )
        )
        return result.model_dump()

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as e:
        result.findings.append(
            JwtFinding(category="malformed", severity="high", message=f"decode error: {e}")
        )
        return result.model_dump()

    result.valid_structure = True
    result.header = header
    result.payload = payload
    result.signature_b64 = parts[2]

    alg = str(header.get("alg", "")).upper()
    if alg in {"NONE", ""}:
        result.findings.append(
            JwtFinding(
                category="alg-none",
                severity="high",
                message="alg is 'none' or missing — token is unsigned, trivially forgeable",
            )
        )
    elif alg not in HS_ALGS and not alg.startswith(("RS", "ES", "PS", "ED")):
        result.findings.append(
            JwtFinding(
                category="unknown-alg",
                severity="medium",
                message=f"unknown algorithm `{alg}`",
            )
        )

    if "kid" in header:
        kid = str(header["kid"])
        if any(s in kid for s in ("../", "..\\", "/", "\\", "'", '"', ";", "--")):
            result.findings.append(
                JwtFinding(
                    category="suspicious-kid",
                    severity="medium",
                    message=f"`kid` contains characters suggestive of path traversal or injection: {kid!r}",
                )
            )

    if "jku" in header or "x5u" in header:
        result.findings.append(
            JwtFinding(
                category="external-key-url",
                severity="medium",
                message="header references external key URL (jku/x5u) — verify allow-list",
            )
        )

    now = int(time.time())
    exp = payload.get("exp")
    if exp is None:
        result.findings.append(
            JwtFinding(
                category="missing-claim",
                severity="medium",
                message="no `exp` claim — token never expires",
            )
        )
    elif isinstance(exp, int | float) and exp < now:
        result.findings.append(
            JwtFinding(
                category="expired",
                severity="info",
                message=f"token expired {now - int(exp)}s ago",
            )
        )

    for claim, sev in (("iat", "low"), ("iss", "low"), ("aud", "low")):
        if claim not in payload:
            result.findings.append(
                JwtFinding(
                    category="missing-claim",
                    severity=sev,
                    message=f"no `{claim}` claim",
                )
            )

    nbf = payload.get("nbf")
    if isinstance(nbf, int | float) and nbf > now:
        result.findings.append(
            JwtFinding(
                category="not-yet-valid",
                severity="info",
                message=f"token not valid for another {int(nbf) - now}s",
            )
        )

    if check_weak_secrets and alg in HS_ALGS:
        result.weak_secret_check_performed = True
        weak = _try_weak_secret(token, alg, DEFAULT_WEAK_SECRETS)
        if weak:
            result.weak_secret = weak
            result.findings.append(
                JwtFinding(
                    category="weak-secret",
                    severity="high",
                    message=f"signature verifies with common weak secret: {weak!r}",
                )
            )

    return result.model_dump()
