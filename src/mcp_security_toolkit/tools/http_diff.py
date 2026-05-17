"""Security-flavored diff of two HTTP responses.

Designed for manual auth-bypass / IDOR / parameter-tampering triage. Takes
two responses (raw strings or `{status, headers, body}` dicts), returns a
structured diff with security-tagged changes:

  - status-code transitions that suggest auth-bypass or redirect changes
  - added / removed / changed headers (security headers highlighted)
  - cookie-attribute changes (HttpOnly, Secure, SameSite)
  - body deltas (size, content-type shift, error-leak hints, reflected tokens)

Stateless. Two inputs in, one diff out.

Part of the Redmai security stack. In production: autonomous request
permutation across auth contexts + kill-chain narrative from IDOR/auth-bypass
diffs → redmai.io
"""

from __future__ import annotations

import difflib
import re
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high"]

SECURITY_HEADERS = {
    "content-security-policy", "x-frame-options", "x-content-type-options",
    "strict-transport-security", "x-xss-protection", "referrer-policy",
    "permissions-policy", "cross-origin-opener-policy",
    "cross-origin-resource-policy", "cross-origin-embedder-policy",
}

AUTH_HEADERS = {
    "authorization", "www-authenticate", "proxy-authenticate", "cookie",
    "set-cookie", "x-csrf-token", "x-xsrf-token",
}

ERROR_LEAK_HINTS = [
    (r"Traceback \(most recent call last\)", "python-stack-trace"),
    (r"at \w+\.\w+\([^)]+\.java:\d+\)", "java-stack-trace"),
    (r"#0\s+/\S+\.php\(\d+\)", "php-stack-trace"),
    (r"SQLSTATE\[", "sql-error"),
    (r"ORA-\d{5}", "oracle-error"),
    (r"You have an error in your SQL syntax", "mysql-error"),
    (r"\bpsycopg2\.errors\.", "postgres-error"),
    (r"\bSystem\.Exception", "dotnet-error"),
    (r"<title>[^<]*(error|exception|stack)", "html-error-page"),
]

AUTH_BYPASS_TRANSITIONS = {
    (401, 200): ("auth-bypass-likely", "high", "unauthorized → ok suggests auth was bypassed"),
    (403, 200): ("auth-bypass-likely", "high", "forbidden → ok suggests access control bypass"),
    (302, 200): ("auth-bypass-possible", "medium", "redirect → ok may indicate login wall bypassed"),
    (404, 200): ("idor-possible", "medium", "not-found → ok suggests resource-existence enumeration"),
    (200, 401): ("regression-or-protection-added", "low", "ok → unauthorized — possibly fixed"),
    (200, 403): ("regression-or-protection-added", "low", "ok → forbidden — possibly fixed"),
}


class HeaderChange(BaseModel):
    name: str
    change: Literal["added", "removed", "changed"]
    before: str | None = None
    after: str | None = None
    severity: Severity
    note: str | None = None


class CookieChange(BaseModel):
    name: str
    change: Literal["added", "removed", "attributes-changed"]
    before_attrs: dict | None = None
    after_attrs: dict | None = None
    severity: Severity
    note: str | None = None


class BodyChange(BaseModel):
    same: bool
    similarity: float
    size_before: int
    size_after: int
    content_type_before: str | None = None
    content_type_after: str | None = None
    leak_hints: list[str] = Field(default_factory=list)
    unified_diff_excerpt: str | None = None


class StatusChange(BaseModel):
    before: int
    after: int
    severity: Severity
    note: str


class DiffReport(BaseModel):
    status: StatusChange | None
    header_changes: list[HeaderChange] = Field(default_factory=list)
    cookie_changes: list[CookieChange] = Field(default_factory=list)
    body: BodyChange
    summary: dict[str, int] = Field(default_factory=dict)


def _parse_raw_response(raw: str) -> dict:
    parts = raw.split("\r\n\r\n", 1)
    if len(parts) != 2 and "\n\n" in raw:
        parts = raw.split("\n\n", 1)
    head = parts[0]
    body = parts[1] if len(parts) == 2 else ""
    lines = head.splitlines()
    status = 0
    if lines and lines[0].startswith(("HTTP/", "http/")):
        m = re.match(r"HTTP/\S+\s+(\d{3})", lines[0])
        if m:
            status = int(m.group(1))
        lines = lines[1:]
    headers: list[tuple[str, str]] = []
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return {"status": status, "headers": headers, "body": body}


def _normalize(resp: dict | str) -> dict:
    if isinstance(resp, str):
        return _parse_raw_response(resp)
    if not isinstance(resp, dict):
        raise ValueError("response must be a dict or raw HTTP string")
    out: dict = {"status": int(resp.get("status", 0)), "body": str(resp.get("body", ""))}
    headers = resp.get("headers", [])
    if isinstance(headers, dict):
        out["headers"] = [(k, str(v)) for k, v in headers.items()]
    elif isinstance(headers, list):
        out["headers"] = [(k, str(v)) for k, v in headers]
    else:
        out["headers"] = []
    return out


def _header_map(headers: list[tuple[str, str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for k, v in headers:
        out.setdefault(k.lower(), []).append(v)
    return out


def _parse_set_cookie(value: str) -> tuple[str, dict]:
    parts = [p.strip() for p in value.split(";")]
    name, _, raw_val = parts[0].partition("=")
    attrs: dict = {"value": raw_val}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.strip().lower()] = True
    return name.strip(), attrs


def _cookies_map(headers: list[tuple[str, str]]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for k, v in headers:
        if k.lower() == "set-cookie":
            name, attrs = _parse_set_cookie(v)
            if name:
                out[name] = attrs
    return out


def _diff_headers(a: dict[str, list[str]], b: dict[str, list[str]]) -> list[HeaderChange]:
    changes: list[HeaderChange] = []
    keys = set(a) | set(b)
    keys.discard("set-cookie")
    for key in sorted(keys):
        before = ", ".join(a.get(key, [])) or None
        after = ", ".join(b.get(key, [])) or None
        if before == after:
            continue
        if before is None:
            change = "added"
        elif after is None:
            change = "removed"
        else:
            change = "changed"

        sev: Severity = "info"
        note = None
        if key in SECURITY_HEADERS:
            if change == "removed":
                sev = "high"
                note = "security header removed — protection regression"
            elif change == "added":
                sev = "low"
                note = "security header added"
            else:
                sev = "medium"
                note = "security header value changed"
        elif key in AUTH_HEADERS:
            sev = "medium"
            note = "auth-related header change"

        changes.append(HeaderChange(
            name=key, change=change, before=before, after=after, severity=sev, note=note,
        ))
    return changes


def _diff_cookies(a: dict[str, dict], b: dict[str, dict]) -> list[CookieChange]:
    changes: list[CookieChange] = []
    names = set(a) | set(b)
    for name in sorted(names):
        ba = a.get(name)
        bb = b.get(name)
        if ba == bb:
            continue
        if ba is None:
            changes.append(CookieChange(
                name=name, change="added", after_attrs=bb, severity="low",
                note="cookie added",
            ))
        elif bb is None:
            changes.append(CookieChange(
                name=name, change="removed", before_attrs=ba, severity="medium",
                note="cookie removed",
            ))
        else:
            sev: Severity = "info"
            notes = []
            for attr in ("httponly", "secure", "samesite"):
                if attr in ba and attr not in bb:
                    sev = "high"
                    notes.append(f"`{attr}` attribute removed")
                elif attr not in ba and attr in bb:
                    notes.append(f"`{attr}` attribute added")
                    if sev == "info":
                        sev = "low"
            if not notes and ba.get("value") != bb.get("value"):
                notes.append("value changed")
                sev = "info"
            changes.append(CookieChange(
                name=name, change="attributes-changed",
                before_attrs=ba, after_attrs=bb, severity=sev,
                note="; ".join(notes) if notes else None,
            ))
    return changes


def _body_diff(body_a: str, body_b: str, ct_a: str | None, ct_b: str | None) -> BodyChange:
    same = body_a == body_b
    ratio = difflib.SequenceMatcher(None, body_a, body_b).quick_ratio()
    leak_hints: list[str] = []
    for pattern, label in ERROR_LEAK_HINTS:
        if re.search(pattern, body_b, re.IGNORECASE) and not re.search(pattern, body_a, re.IGNORECASE):
            leak_hints.append(label)

    excerpt = None
    if not same and len(body_a) + len(body_b) < 200_000:
        lines = list(difflib.unified_diff(
            body_a.splitlines(keepends=False)[:200],
            body_b.splitlines(keepends=False)[:200],
            lineterm="", n=2,
        ))
        if lines:
            excerpt = "\n".join(lines[:60])
            if len("\n".join(lines)) > len(excerpt):
                excerpt += "\n…(truncated)"

    return BodyChange(
        same=same,
        similarity=round(ratio, 3),
        size_before=len(body_a),
        size_after=len(body_b),
        content_type_before=ct_a,
        content_type_after=ct_b,
        leak_hints=leak_hints,
        unified_diff_excerpt=excerpt,
    )


def _status_change(before: int, after: int) -> StatusChange | None:
    if before == after:
        return None
    cat, sev, note = AUTH_BYPASS_TRANSITIONS.get(
        (before, after),
        ("status-change", "info", f"status changed {before} → {after}"),
    )
    return StatusChange(before=before, after=after, severity=sev, note=f"{cat}: {note}")  # type: ignore[arg-type]


def http_diff(response_a: dict | str, response_b: dict | str) -> dict:
    """Diff two HTTP responses with security-relevant findings.

    Inputs may be raw HTTP response strings (status line + headers + body)
    or dicts shaped `{"status": int, "headers": list|dict, "body": str}`.

    Reports:
      - status transitions classed as auth-bypass-likely / idor-possible / etc.
      - header diffs with security-header and auth-header tagging
      - cookie attribute diffs (HttpOnly / Secure / SameSite removal flagged high)
      - body diff: size, content-type shift, error-leak hints, unified diff excerpt

    Stateless. Two inputs in, one report out.
    """
    try:
        a = _normalize(response_a)
        b = _normalize(response_b)
    except ValueError as e:
        return {"error": str(e)}

    ha = _header_map(a["headers"])
    hb = _header_map(b["headers"])
    ca = _cookies_map(a["headers"])
    cb = _cookies_map(b["headers"])

    ct_a = (ha.get("content-type") or [None])[0]
    ct_b = (hb.get("content-type") or [None])[0]

    report = DiffReport(
        status=_status_change(a["status"], b["status"]),
        header_changes=_diff_headers(ha, hb),
        cookie_changes=_diff_cookies(ca, cb),
        body=_body_diff(a["body"], b["body"], ct_a, ct_b),
    )

    counts: dict[str, int] = {}
    if report.status:
        counts[report.status.severity] = counts.get(report.status.severity, 0) + 1
    for h in report.header_changes:
        counts[h.severity] = counts.get(h.severity, 0) + 1
    for c in report.cookie_changes:
        counts[c.severity] = counts.get(c.severity, 0) + 1
    for _ in report.body.leak_hints:
        counts["medium"] = counts.get("medium", 0) + 1
    report.summary = counts

    return report.model_dump()
