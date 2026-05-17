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


class AuditReport(BaseModel):
    file: str
    tools_found: int
    tools: list[ToolReport] = Field(default_factory=list)
    file_level_findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)


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


def mcp_server_audit(path: str) -> dict:
    """Statically audit an MCP server Python source file.

    Enumerates tools registered with FastMCP-style `@*.tool()` decorators and
    reports risk findings per tool: shell execution, filesystem writes,
    network egress, code injection, over-broad parameter types, and
    ambiguous/short descriptions.

    Args:
        path: Absolute path to a Python file defining an MCP server.

    Returns:
        Structured audit report (see AuditReport schema). Does NOT execute
        the target file.
    """
    p = Path(path)
    if not p.is_file():
        return {"error": f"file not found: {path}"}

    source = p.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=str(p))
    except SyntaxError as e:
        return {"error": f"syntax error: {e}"}

    aliases = _collect_aliases(tree)
    report = AuditReport(file=str(p), tools_found=0)
    decorator_tools: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if any(_is_tool_decorator(d) for d in node.decorator_list):
                report.tools.append(_analyze_function(node, aliases))
                decorator_tools.add(node.name)

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
                report.tools.append(_analyze_function(functions_by_name[name], aliases))
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

    report.tools_found = len(report.tools)
    report.file_level_findings = _collect_file_level_findings(tree, aliases)

    counts: dict[str, int] = {}
    for t in report.tools:
        for f in t.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    for f in report.file_level_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    report.summary = counts

    return report.model_dump()
