"""Heuristic static analyzer for MCP server source files.

Parses a Python file that defines a FastMCP (or low-level Server) and reports
on each registered tool: parameters, docstring quality, and a set of risk
heuristics (shell exec, filesystem writes, network egress, over-broad params).

This is a heuristic AST audit, not a soundness-checked SAST. It catches
direct module attribute calls (`subprocess.run(...)`) and `from <mod> import`
aliases (`from subprocess import run as r; r(...)`), but will miss
arbitrarily aliased / dynamically-resolved calls. False negatives are
expected — treat findings as triage signal, not verdict.

Does not execute the target file.

Part of the Redmai security stack. In production: autonomous scanning across
many MCP servers + scan history + industry-specific rule packs → redmai.io
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high"]

DANGEROUS_CALLS: dict[tuple[str, ...], tuple[str, Severity]] = {
    ("subprocess", "run"): ("shell-exec", "high"),
    ("subprocess", "call"): ("shell-exec", "high"),
    ("subprocess", "Popen"): ("shell-exec", "high"),
    ("subprocess", "check_output"): ("shell-exec", "high"),
    ("subprocess", "check_call"): ("shell-exec", "high"),
    ("os", "system"): ("shell-exec", "high"),
    ("os", "popen"): ("shell-exec", "high"),
    ("os", "exec"): ("shell-exec", "high"),
    ("os", "execv"): ("shell-exec", "high"),
    ("os", "execvp"): ("shell-exec", "high"),
    ("os", "spawn"): ("shell-exec", "high"),
    ("shutil", "rmtree"): ("fs-destructive", "high"),
    ("os", "remove"): ("fs-destructive", "medium"),
    ("os", "unlink"): ("fs-destructive", "medium"),
    ("requests", "get"): ("network-egress", "medium"),
    ("requests", "post"): ("network-egress", "medium"),
    ("requests", "request"): ("network-egress", "medium"),
    ("httpx", "get"): ("network-egress", "medium"),
    ("httpx", "post"): ("network-egress", "medium"),
    ("urllib.request", "urlopen"): ("network-egress", "medium"),
}

EVAL_CALLS = {"eval", "exec", "compile"}


class Finding(BaseModel):
    tool: str
    category: str
    severity: Severity
    message: str
    line: int | None = None


class ToolReport(BaseModel):
    name: str
    line: int
    has_docstring: bool
    docstring_length: int = 0
    params: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class Coverage(BaseModel):
    decorator_tools_found: int = 0
    imperative_tools_resolved: int = 0
    imperative_tools_external: int = 0
    detectors_run: list[str] = Field(default_factory=list)


class AuditReport(BaseModel):
    file: str
    bytes_read: int = 0
    tools_found: int
    tools: list[ToolReport] = Field(default_factory=list)
    file_level_findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
    coverage: Coverage = Field(default_factory=Coverage)
    limitations: list[str] = Field(default_factory=lambda: [
        "Heuristic AST analysis; soundness not guaranteed.",
        "Dynamically-resolved calls (e.g. getattr-based, lambda-wrapped) are not tracked.",
        "Tools registered from imported symbols are flagged but their source is NOT analyzed transitively — audit each external module separately.",
        "Weak-secret patterns, eval/exec heuristics, and dangerous-call dictionary are deliberately small; absence of finding is NOT proof of safety.",
        "path-traversal, ssrf, and mcp-resource-uri-sqli detectors require both parameter shape AND sink usage — indirect flows through helper functions are not tracked.",
        "tool-shadowing compares descriptions via edit-distance ratio; tools with short (<20 char) descriptions may produce false positives.",
    ])


# ── D1: path-traversal ────────────────────────────────────────────────────

_PATH_PARAM_RE = re.compile(
    r"^(filename|file_path|filepath|path|output_path|output_filename|image_path|"
    r"src_path|dst_path|source|destination|target|input_path|save_path)$"
)

_PATH_SINKS = {
    "open", "Path", "Document", "Presentation",
    "makedirs", "remove", "unlink", "rename", "copyfile", "copy", "copy2", "move", "rmtree",
}

_PATH_VALIDATION_MARKERS = {
    ".resolve(", ".relative_to(", "commonpath(", "_path_is_inside(", "is_safe_path(",
    "secure_filename(", "../",
}

_UPPER_ROOT_RE = re.compile(r"\b[A-Z_]+(ROOT|DIR|BASE|HOME)\b")


def _detect_path_traversal(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[Finding]:
    target_params = {
        a.arg for a in fn.args.args
        if _PATH_PARAM_RE.match(a.arg.lower())
    }
    if not target_params:
        return []

    fn_source_lines = ast.unparse(fn)

    # Validation present? Check via unparsed source (fast heuristic).
    for marker in _PATH_VALIDATION_MARKERS:
        if marker in fn_source_lines:
            return []
    if _UPPER_ROOT_RE.search(fn_source_lines):
        return []

    # Check sink usage — param name appears in a Call arg.
    findings = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        call_name = (
            func.attr if isinstance(func, ast.Attribute)
            else func.id if isinstance(func, ast.Name)
            else None
        )
        if call_name not in _PATH_SINKS:
            continue
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in all_args:
            if isinstance(arg, ast.Name) and arg.id in target_params:
                findings.append(Finding(
                    tool=fn.name,
                    category="path-traversal",
                    severity="high",
                    message=(
                        f"parameter `{arg.id}` passed to `{call_name}()` "
                        f"without path-validation (.resolve()/.relative_to()/allow-list)"
                    ),
                    line=node.lineno,
                ))
                break  # one finding per sink call is enough
    return findings


# ── D2: tool-description-injection ────────────────────────────────────────

_INJECTION_TAGS = re.compile(
    r"<\s*(IMPORTANT|SYSTEM|ADMIN|URGENT|SECRET|INSTRUCTION|HIDDEN|DO_NOT_DISPLAY)\s*>",
    re.IGNORECASE,
)

_INJECTION_PHRASES = re.compile(
    r"\b(IGNORE\s+PREVIOUS|DISREGARD\s+INSTRUCTIONS|DO\s+NOT\s+MENTION|DO\s+NOT\s+TELL|"
    r"ALWAYS\s+INCLUDE|ALWAYS\s+USE|MUST\s+ACCESS|BEFORE\s+RESPONDING|PRETEND)\b",
    re.IGNORECASE,
)

_SILENT_FETCH_RE = re.compile(
    r"access(?:ing)?\s+(?:the\s+)?resource\s+at|silently\s+(?:fetch|read|call)",
    re.IGNORECASE,
)


def _detect_tool_description_injection(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[Finding]:
    docstring = ast.get_docstring(fn) or ""
    if not docstring:
        return []

    matches: list[str] = []
    for m in _INJECTION_TAGS.finditer(docstring):
        matches.append(f"injection tag <{m.group(1)}>")
    for m in _INJECTION_PHRASES.finditer(docstring):
        matches.append(f"override phrase '{m.group(0).strip()}'")
    for m in _SILENT_FETCH_RE.finditer(docstring):
        matches.append(f"silent-fetch marker '{m.group(0).strip()}'")

    if not matches:
        return []

    return [Finding(
        tool=fn.name,
        category="tool-description-injection",
        severity="medium",
        message=(
            f"docstring contains prompt-injection patterns: {', '.join(matches[:3])}"
            + (f" (+{len(matches) - 3} more)" if len(matches) > 3 else "")
        ),
        line=fn.lineno,
    )]


# ── D3: ssrf ──────────────────────────────────────────────────────────────

_SSRF_PARAM_NAMES = {
    "url", "uri", "endpoint", "target_url", "webhook_url",
    "callback_url", "link", "host", "target",
}

_SSRF_SINKS = {
    ("requests", "get"), ("requests", "post"), ("requests", "put"),
    ("requests", "delete"), ("requests", "request"),
    ("httpx", "get"), ("httpx", "post"),
    ("httpx", "AsyncClient"), ("aiohttp", "ClientSession"),
    ("urllib", "request", "urlopen"), ("urllib.request", "urlopen"),
    ("urlopen",),
}

_SSRF_VALIDATION_MARKERS = {
    "_is_private_address(", "_is_safe_url(", "_is_allowed_url(", "_validate_url(",
    "ipaddress.ip_address(", "is_global",
    "in ALLOWED_", "startswith('http'", 'startswith("http"',
    "scheme not in", "allowlist", "allow_list",
}


def _detect_ssrf(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, tuple[str, ...]] | None = None,
) -> list[Finding]:
    url_params = {a.arg for a in fn.args.args if a.arg in _SSRF_PARAM_NAMES}
    if not url_params:
        return []

    fn_source = ast.unparse(fn)
    for marker in _SSRF_VALIDATION_MARKERS:
        if marker in fn_source:
            return []

    findings = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        resolved = _resolve_call(node, aliases)
        if resolved is None:
            continue
        matched_sink = any(
            resolved[-len(s):] == s if isinstance(s, tuple) else resolved == (s,)
            for s in _SSRF_SINKS
        )
        if not matched_sink:
            continue
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in all_args:
            if isinstance(arg, ast.Name) and arg.id in url_params:
                findings.append(Finding(
                    tool=fn.name,
                    category="ssrf",
                    severity="high",
                    message=(
                        f"parameter `{arg.id}` passed to `{'.'.join(resolved)}()` "
                        f"without host/scheme validation — attacker can reach internal services"
                    ),
                    line=node.lineno,
                ))
                break
    return findings


# ── D4: mcp-resource-uri-sqli ─────────────────────────────────────────────

_RESOURCE_DECORATORS = {"read_resource", "resource"}

_SQL_EXECUTE_ATTRS = {"execute", "executemany", "execute_many"}

_SAFE_QUERY_MARKERS = {"?", "%s", ":name", "%("}


def _is_resource_decorator(dec: ast.expr) -> bool:
    target: ast.expr = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr in _RESOURCE_DECORATORS
    if isinstance(target, ast.Name):
        return target.id in _RESOURCE_DECORATORS
    return False


def _detect_uri_sqli(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[Finding]:
    if not any(_is_resource_decorator(d) for d in fn.decorator_list):
        return []

    uri_params = {a.arg for a in fn.args.args if a.arg in {"uri", "resource_uri", "path"}}
    if not uri_params:
        return []

    # Collect variable names derived from uri params via split/slice/urlparse.
    derived: set[str] = set(uri_params)
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign):
            continue
        val = node.value
        is_derived = False
        if isinstance(val, ast.Call):
            # uri.split(...), urlparse(uri), uri.removeprefix(...)
            if isinstance(val.func, ast.Attribute) and val.func.attr in {"split", "removeprefix"}:
                if isinstance(val.func.value, ast.Name) and val.func.value.id in derived:
                    is_derived = True
            if isinstance(val.func, ast.Name) and val.func.id == "urlparse":
                if val.args and isinstance(val.args[0], ast.Name) and val.args[0].id in derived:
                    is_derived = True
        elif isinstance(val, ast.Subscript):
            inner = val.value
            if isinstance(inner, ast.Name) and inner.id in derived:
                is_derived = True
            elif isinstance(inner, ast.Call):
                # uri.split(...)[idx] — subscript of a method call on a derived var
                func = inner.func
                if (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id in derived
                ):
                    is_derived = True
        if is_derived:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    derived.add(target.id)

    # Now look for derived vars inside f-strings passed to .execute().
    findings = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_EXECUTE_ATTRS):
            continue
        # Check the first argument is an f-string containing a derived var.
        if not node.args:
            continue
        query_arg = node.args[0]
        if not isinstance(query_arg, ast.JoinedStr):
            continue
        fn_src = ast.unparse(query_arg)
        # Safe if uses placeholders.
        if any(p in fn_src for p in _SAFE_QUERY_MARKERS):
            continue
        # Check if any derived var appears in the f-string values.
        for part in ast.walk(query_arg):
            if isinstance(part, ast.Name) and part.id in derived:
                findings.append(Finding(
                    tool=fn.name,
                    category="mcp-resource-uri-sqli",
                    severity="high",
                    message=(
                        f"URI-derived variable `{part.id}` interpolated into SQL via f-string "
                        f"— use parameterized queries instead"
                    ),
                    line=node.lineno,
                ))
                break
    return findings


# ── D5: tool-shadowing ────────────────────────────────────────────────────

def _edit_distance_ratio(a: str, b: str) -> float:
    """Simple normalized edit distance (Levenshtein ratio) for short strings."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return 1.0 - prev[lb] / max(la, lb)


def _detect_tool_shadowing(tools: list[ToolReport]) -> list[Finding]:
    """Cross-tool detector: finds pairs with suspiciously similar names or descriptions."""
    findings = []
    for i, a in enumerate(tools):
        for b in tools[i + 1:]:
            # Name similarity.
            name_ratio = _edit_distance_ratio(a.name.lower(), b.name.lower())
            if name_ratio >= 0.8 and a.name != b.name:
                findings.append(Finding(
                    tool=f"{a.name} / {b.name}",
                    category="tool-shadowing",
                    severity="medium",
                    message=(
                        f"tools `{a.name}` and `{b.name}` have very similar names "
                        f"(similarity {name_ratio:.0%}) — LLM may invoke wrong tool"
                    ),
                    line=None,
                ))
                continue  # don't also emit description finding for same pair

            # Description similarity check happens in _audit_tool_shadowing
            # which has access to the raw docstring text via (ToolReport, str) tuples.
    return findings


def _audit_tool_shadowing(
    tools_with_docs: list[tuple[ToolReport, str]],
) -> list[Finding]:
    """Full cross-tool shadowing check including description similarity."""
    findings = []
    for i, (a_report, a_doc) in enumerate(tools_with_docs):
        for b_report, b_doc in tools_with_docs[i + 1:]:
            name_ratio = _edit_distance_ratio(a_report.name.lower(), b_report.name.lower())
            if name_ratio >= 0.8 and a_report.name != b_report.name:
                findings.append(Finding(
                    tool=f"{a_report.name} / {b_report.name}",
                    category="tool-shadowing",
                    severity="medium",
                    message=(
                        f"tools `{a_report.name}` and `{b_report.name}` have very similar names "
                        f"(similarity {name_ratio:.0%}) — an LLM may invoke the wrong one"
                    ),
                    line=None,
                ))
                continue

            # Description comparison — only when both have non-trivial docstrings.
            if len(a_doc) >= 20 and len(b_doc) >= 20:
                desc_ratio = _edit_distance_ratio(a_doc[:120].lower(), b_doc[:120].lower())
                if desc_ratio >= 0.85:
                    findings.append(Finding(
                        tool=f"{a_report.name} / {b_report.name}",
                        category="tool-shadowing",
                        severity="medium",
                        message=(
                            f"tools `{a_report.name}` and `{b_report.name}` have nearly identical "
                            f"descriptions (similarity {desc_ratio:.0%}) — ambiguous tool identity "
                            f"enables confusion/substitution attacks"
                        ),
                        line=None,
                    ))
    return findings


def _is_tool_decorator(dec: ast.expr) -> bool:
    # @mcp.tool() or @something.tool() or @tool()
    target: ast.expr = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute) and target.attr == "tool":
        return True
    if isinstance(target, ast.Name) and target.id == "tool":
        return True
    return False


def _resolve_call(node: ast.Call, aliases: dict[str, tuple[str, ...]] | None = None) -> tuple[str, ...] | None:
    func = node.func
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        resolved = tuple(reversed(parts))
        if aliases and resolved[0] in aliases:
            return (*aliases[resolved[0]], *resolved[1:])
        return resolved
    return None


def _collect_aliases(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    """Build `local_name → (module, ...attr_chain)` from top-level imports.

    Examples:
      `import subprocess`              → subprocess → (subprocess,)
      `import subprocess as sp`        → sp         → (subprocess,)
      `from subprocess import run`     → run        → (subprocess, run)
      `from subprocess import run as r`→ r          → (subprocess, run)
    """
    out: dict[str, tuple[str, ...]] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for n in node.names:
                local = n.asname or n.name.split(".")[0]
                out[local] = tuple(n.name.split("."))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            mod_parts = tuple(module.split(".")) if module else ()
            for n in node.names:
                if n.name == "*":
                    continue
                local = n.asname or n.name
                out[local] = (*mod_parts, n.name)
    return out


def _param_is_overbroad(arg: ast.arg) -> str | None:
    if arg.annotation is None:
        return "no type annotation"
    if isinstance(arg.annotation, ast.Name):
        # bare str/dict/list/Any without constraints
        if arg.annotation.id in {"str", "dict", "list", "Any", "object"}:
            if arg.arg in {"path", "file", "filepath", "filename", "dir", "directory"}:
                return f"path-like parameter typed as bare `{arg.annotation.id}` (no allow-list)"
            if arg.arg in {"cmd", "command", "shell", "script"}:
                return f"command-like parameter typed as bare `{arg.annotation.id}`"
            if arg.arg in {"url", "endpoint", "host"}:
                return f"url-like parameter typed as bare `{arg.annotation.id}` (no allow-list)"
    return None


def _analyze_function(fn: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, tuple[str, ...]] | None = None) -> ToolReport:
    docstring = ast.get_docstring(fn) or ""
    report = ToolReport(
        name=fn.name,
        line=fn.lineno,
        has_docstring=bool(docstring),
        docstring_length=len(docstring),
        params=[a.arg for a in fn.args.args if a.arg != "self"],
    )

    if not docstring:
        report.findings.append(
            Finding(
                tool=fn.name,
                category="ambiguous-description",
                severity="medium",
                message="tool has no docstring — the LLM cannot reason about when to use it",
                line=fn.lineno,
            )
        )
    elif len(docstring) < 40:
        report.findings.append(
            Finding(
                tool=fn.name,
                category="ambiguous-description",
                severity="low",
                message=f"docstring is very short ({len(docstring)} chars) — risk of LLM misuse",
                line=fn.lineno,
            )
        )

    for arg in fn.args.args:
        if arg.arg == "self":
            continue
        reason = _param_is_overbroad(arg)
        if reason:
            report.findings.append(
                Finding(
                    tool=fn.name,
                    category="over-broad-param",
                    severity="medium",
                    message=f"parameter `{arg.arg}`: {reason}",
                    line=arg.lineno,
                )
            )

    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            resolved = _resolve_call(node, aliases)
            if resolved:
                for key, (category, sev) in DANGEROUS_CALLS.items():
                    if resolved[-len(key):] == key:
                        report.findings.append(
                            Finding(
                                tool=fn.name,
                                category=category,
                                severity=sev,
                                message=f"calls `{'.'.join(resolved)}`",
                                line=node.lineno,
                            )
                        )
                        break
            if isinstance(node.func, ast.Name) and node.func.id in EVAL_CALLS:
                report.findings.append(
                    Finding(
                        tool=fn.name,
                        category="code-injection",
                        severity="high",
                        message=f"calls built-in `{node.func.id}()` on potentially untrusted input",
                        line=node.lineno,
                    )
                )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    if isinstance(kw.value.value, str) and any(c in kw.value.value for c in "wax"):
                        report.findings.append(
                            Finding(
                                tool=fn.name,
                                category="fs-write",
                                severity="medium",
                                message=f"opens file for writing (mode={kw.value.value!r})",
                                line=node.lineno,
                            )
                        )
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
                if isinstance(mode, str) and any(c in mode for c in "wax"):
                    report.findings.append(
                        Finding(
                            tool=fn.name,
                            category="fs-write",
                            severity="medium",
                            message=f"opens file for writing (mode={mode!r})",
                            line=node.lineno,
                        )
                    )

    # D1 / D2 / D3 — per-tool detectors
    report.findings.extend(_detect_path_traversal(fn))
    report.findings.extend(_detect_tool_description_injection(fn))
    report.findings.extend(_detect_ssrf(fn, aliases))

    return report


def _collect_file_level_findings(tree: ast.Module, aliases: dict[str, tuple[str, ...]] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            resolved = _resolve_call(node, aliases)
            if resolved and resolved[-2:] == ("os", "getenv"):
                if node.args and isinstance(node.args[0], ast.Constant):
                    name = str(node.args[0].value)
                    if any(s in name.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD")):
                        findings.append(
                            Finding(
                                tool="<module>",
                                category="secret-in-env",
                                severity="info",
                                message=f"reads secret from env `{name}` — ensure it is documented in README and never logged",
                                line=node.lineno,
                            )
                        )
    return findings


DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB


def mcp_server_audit(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> dict:
    """Statically audit an MCP server Python source file.

    Enumerates tools registered with FastMCP-style `@*.tool()` decorators (and
    imperative `mcp.tool()(fn)` calls) and reports risk findings per tool:
    shell execution, filesystem writes, network egress, code injection,
    over-broad parameter types, and ambiguous/short descriptions.

    Args:
        path: Absolute path to a Python file defining an MCP server.
        max_bytes: Reject files larger than this (default 5 MB). Prevents
            DoS via huge input. Pass a larger value if you need to audit a
            big monolith, but consider splitting it first.

    Returns:
        Structured audit report (see AuditReport schema). Does NOT execute
        the target file. Includes a `coverage` block and `limitations` list
        — absence of finding is NOT proof of safety.
    """
    p = Path(path)
    if not p.is_file():
        return {"error": f"file not found: {path}"}

    try:
        size = p.stat().st_size
    except OSError as e:
        return {"error": f"stat failed: {e}"}
    if size > max_bytes:
        return {
            "error": "input-too-large",
            "file": str(p),
            "bytes": size,
            "max_bytes": max_bytes,
            "hint": "Pass `max_bytes` explicitly to raise the limit, or split the file.",
        }

    source = p.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=str(p))
    except SyntaxError as e:
        return {"error": f"syntax error: {e}"}
    except RecursionError:
        return {
            "error": "input-too-deep",
            "file": str(p),
            "hint": "Source contains nested expressions exceeding Python's recursion limit; "
                    "audit can't parse it safely. Split the file or refactor the offending expression.",
        }

    aliases = _collect_aliases(tree)
    report = AuditReport(file=str(p), bytes_read=size, tools_found=0)
    decorator_tools: set[str] = set()

    tools_with_docs: list[tuple[ToolReport, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if any(_is_tool_decorator(d) for d in node.decorator_list):
                tool_report = _analyze_function(node, aliases)
                report.tools.append(tool_report)
                decorator_tools.add(node.name)
                tools_with_docs.append((tool_report, ast.get_docstring(node) or ""))
    report.coverage.decorator_tools_found = len(decorator_tools)

    imperative_names: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Call)
            and isinstance(node.func.func, ast.Attribute)
            and node.func.func.attr == "tool"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Attribute | ast.Name)
        ):
            ref = node.args[0]
            name = ref.attr if isinstance(ref, ast.Attribute) else ref.id
            imperative_names.add(name)

    if imperative_names:
        functions_by_name = {
            n.name: n
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        for name in sorted(imperative_names):
            if name in decorator_tools:
                continue
            if name in functions_by_name:
                tool_report = _analyze_function(functions_by_name[name], aliases)
                report.tools.append(tool_report)
                tools_with_docs.append((tool_report, ast.get_docstring(functions_by_name[name]) or ""))
                report.coverage.imperative_tools_resolved += 1
            else:
                report.tools.append(
                    ToolReport(
                        name=name,
                        line=0,
                        has_docstring=False,
                        findings=[
                            Finding(
                                tool=name,
                                category="external-tool",
                                severity="info",
                                message="tool registered imperatively from an imported symbol — audit the source module separately",
                            )
                        ],
                    )
                )
                report.coverage.imperative_tools_external += 1

    # D4 — resource handlers (not @tool, walk all functions)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if any(_is_resource_decorator(d) for d in node.decorator_list):
                sqli_findings = _detect_uri_sqli(node)
                if sqli_findings:
                    # Attach to an existing tool report if the function was already captured,
                    # otherwise create a minimal one.
                    existing = next((t for t in report.tools if t.name == node.name), None)
                    if existing:
                        existing.findings.extend(sqli_findings)
                    else:
                        r = ToolReport(name=node.name, line=node.lineno, has_docstring=bool(ast.get_docstring(node)))
                        r.findings.extend(sqli_findings)
                        report.tools.append(r)

    # D5 — cross-tool shadowing
    shadowing_findings = _audit_tool_shadowing(tools_with_docs)
    report.file_level_findings.extend(shadowing_findings)

    report.tools_found = len(report.tools)
    report.file_level_findings.extend(_collect_file_level_findings(tree, aliases))
    report.coverage.detectors_run = [
        "shell-exec", "fs-write", "fs-destructive", "network-egress", "code-injection",
        "over-broad-param", "ambiguous-description", "secret-in-env",
        "path-traversal", "tool-description-injection", "ssrf",
        "mcp-resource-uri-sqli", "tool-shadowing",
    ]

    counts: dict[str, int] = {}
    for t in report.tools:
        for f in t.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    for f in report.file_level_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    report.summary = counts

    return report.model_dump()
