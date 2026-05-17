"""Static risk analysis of a single agent tool's JSON schema.

Accepts an agent / function-calling tool definition (OpenAI, Anthropic, MCP,
or a bare JSON Schema) and reports schema-level risks: over-broad params,
ambiguous descriptions, missing constraints, exfil-potential shapes, and
dangerous defaults.

Stateless. One tool definition in, one report out. No chaining.

Part of the Redmai security stack. In production: continuous schema review
across an organisation's agent fleet + custom rule packs → redmai.io
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high"]

PATH_LIKE = {"path", "file", "filepath", "filename", "dir", "directory", "folder"}
COMMAND_LIKE = {"cmd", "command", "shell", "script", "exec"}
URL_LIKE = {"url", "endpoint", "host", "target", "webhook", "callback", "uri"}
DATA_LIKE = {"data", "content", "body", "payload", "text", "blob"}

RISKY_NAME_HINTS = {
    "exec": "executes",
    "shell": "runs shell",
    "run": "executes",
    "delete": "destroys",
    "remove": "destroys",
    "drop": "destroys",
    "write": "modifies state",
    "upload": "exfil channel",
    "send": "exfil channel",
    "post": "exfil channel",
    "fetch": "network egress",
    "download": "network egress",
}

UNSAFE_BOOL_DEFAULTS = {
    "verify_ssl": False,
    "verify": False,
    "ssl_verify": False,
    "confirm": False,
    "dry_run": False,
    "safe": False,
    "sandbox": False,
}


class Finding(BaseModel):
    category: str
    severity: Severity
    path: str
    message: str


class AuditReport(BaseModel):
    tool_name: str | None
    detected_format: str
    has_description: bool
    description_length: int
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)


def _normalize(schema: dict) -> tuple[str, str | None, str, dict]:
    """Return (format, name, description, parameter_schema)."""
    if isinstance(schema.get("function"), dict):
        fn = schema["function"]
        return ("openai", fn.get("name"), fn.get("description", ""), fn.get("parameters", {}))
    if "input_schema" in schema:
        return ("anthropic", schema.get("name"), schema.get("description", ""), schema["input_schema"])
    if "inputSchema" in schema:
        return ("mcp", schema.get("name"), schema.get("description", ""), schema["inputSchema"])
    if "parameters" in schema and ("name" in schema or "description" in schema):
        return ("generic", schema.get("name"), schema.get("description", ""), schema["parameters"])
    if schema.get("type") == "object" or "properties" in schema:
        return ("bare-schema", None, "", schema)
    return ("unknown", schema.get("name"), schema.get("description", ""), schema)


def _check_param(name: str, spec: dict, required: bool, parent_path: str) -> list[Finding]:
    out: list[Finding] = []
    path = f"{parent_path}.{name}" if parent_path else name
    ptype = spec.get("type")
    lname = name.lower()

    has_constraint = any(k in spec for k in ("enum", "pattern", "const", "format"))

    if ptype == "string" and not has_constraint:
        if lname in PATH_LIKE:
            out.append(Finding(
                category="over-broad-param", severity="high", path=path,
                message=f"path-like param `{name}` is bare string with no `pattern`/`enum` — agent can read/write arbitrary paths",
            ))
        elif lname in COMMAND_LIKE:
            out.append(Finding(
                category="over-broad-param", severity="high", path=path,
                message=f"command-like param `{name}` is bare string — agent can execute arbitrary commands",
            ))
        elif lname in URL_LIKE:
            out.append(Finding(
                category="over-broad-param", severity="high", path=path,
                message=f"url-like param `{name}` is bare string with no `pattern` — agent can reach arbitrary hosts (SSRF / exfil)",
            ))
        elif "maxLength" not in spec:
            out.append(Finding(
                category="missing-constraint", severity="low", path=path,
                message=f"string param `{name}` has no `maxLength` — unbounded input",
            ))

    if ptype in {"number", "integer"} and not any(k in spec for k in ("minimum", "maximum", "enum")):
        out.append(Finding(
            category="missing-constraint", severity="low", path=path,
            message=f"numeric param `{name}` has no min/max — accepts any value",
        ))

    if ptype == "array" and "maxItems" not in spec:
        out.append(Finding(
            category="missing-constraint", severity="low", path=path,
            message=f"array param `{name}` has no `maxItems` — unbounded",
        ))

    if ptype == "object":
        if spec.get("additionalProperties", True) is True and "properties" not in spec:
            out.append(Finding(
                category="over-broad-param", severity="medium", path=path,
                message=f"object param `{name}` allows arbitrary keys (`additionalProperties: true`, no `properties`)",
            ))
        for sub_name, sub_spec in (spec.get("properties") or {}).items():
            sub_required = sub_name in (spec.get("required") or [])
            out.extend(_check_param(sub_name, sub_spec, sub_required, path))

    if "default" in spec:
        default = spec["default"]
        if lname in PATH_LIKE and isinstance(default, str):
            if default.startswith("/") or "../" in default or default == "*":
                out.append(Finding(
                    category="dangerous-default", severity="high", path=path,
                    message=f"path-like param `{name}` defaults to suspicious value: {default!r}",
                ))
        if lname in UNSAFE_BOOL_DEFAULTS and default == UNSAFE_BOOL_DEFAULTS[lname]:
            out.append(Finding(
                category="dangerous-default", severity="medium", path=path,
                message=f"safety-related param `{name}` defaults to `{default}` — disables a safeguard by default",
            ))

    if not spec.get("description") and ptype:
        out.append(Finding(
            category="ambiguous-description", severity="low", path=path,
            message=f"param `{name}` has no description — agent must guess intent",
        ))

    if not required and ptype is not None and "default" not in spec and lname in (PATH_LIKE | COMMAND_LIKE | URL_LIKE):
        out.append(Finding(
            category="ambiguous-semantics", severity="info", path=path,
            message=f"sensitive param `{name}` is optional with no default — behavior on omission is implicit",
        ))

    return out


def _check_exfil_shape(params: dict, findings: list[Finding]) -> None:
    props = (params.get("properties") or {})
    has_url = any(k.lower() in URL_LIKE for k in props)
    has_data = any(k.lower() in DATA_LIKE for k in props)
    if has_url and has_data:
        findings.append(Finding(
            category="exfil-shape", severity="medium", path="<tool>",
            message="tool accepts both a URL-like destination and a data-like payload — classic exfil shape",
        ))


def _check_name_and_desc(name: str | None, desc: str, findings: list[Finding]) -> None:
    if not desc:
        findings.append(Finding(
            category="ambiguous-description", severity="high", path="<tool>",
            message="tool has no description — agent cannot reliably decide when to call it",
        ))
    elif len(desc) < 40:
        findings.append(Finding(
            category="ambiguous-description", severity="medium", path="<tool>",
            message=f"description is very short ({len(desc)} chars) — high risk of LLM misuse",
        ))

    if name:
        lname = name.lower()
        for hint, why in RISKY_NAME_HINTS.items():
            if hint in lname:
                if desc and len(desc) >= 80:
                    continue
                findings.append(Finding(
                    category="risky-name-vague-desc", severity="medium", path="<tool>",
                    message=f"tool name suggests it {why} ({hint!r}) but description is brief — agent may misuse",
                ))
                break


def agent_tool_risk_audit(schema: dict) -> dict:
    """Statically audit a single agent tool definition for schema-level risks.

    Accepts OpenAI function-calling, Anthropic tool-use, MCP tool, or a bare
    JSON Schema. Reports:
      - over-broad params (bare-string paths/commands/URLs)
      - missing constraints (enum/pattern/min/max/maxLength/maxItems)
      - dangerous defaults (suspicious paths, disabled safeguards)
      - exfil-shape (URL-destination + data-payload in the same tool)
      - ambiguous descriptions vs risky tool names

    Args:
        schema: A tool definition as a dict.

    Returns:
        Structured AuditReport. Pure function, no I/O, no chaining.
    """
    if not isinstance(schema, dict):
        return {"error": "schema must be a JSON object"}

    fmt, name, desc, params = _normalize(schema)
    report = AuditReport(
        tool_name=name,
        detected_format=fmt,
        has_description=bool(desc),
        description_length=len(desc or ""),
    )

    _check_name_and_desc(name, desc or "", report.findings)

    if isinstance(params, dict):
        required = set(params.get("required") or [])
        for pname, pspec in (params.get("properties") or {}).items():
            if isinstance(pspec, dict):
                report.findings.extend(_check_param(pname, pspec, pname in required, ""))
        _check_exfil_shape(params, report.findings)

    counts: dict[str, int] = {}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    report.summary = counts

    return report.model_dump()
