"""Static analyzer for prompt-injection surface in a system prompt or template.

Pure string analysis: regex + rule heuristics. No LLM call, no I/O, no chaining.
Reports placeholders without delimiters, untrusted variables, dangerous
instruction patterns, trust-boundary violations, and precedence inversion.

Part of the Redmai security stack. In production: full prompt-template
inventory across an LLM application + autonomous regression scanning on
every prompt change → redmai.io
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high"]

UNTRUSTED_HINTS = {
    "user_input", "user", "input", "query", "question", "message",
    "messages", "document", "documents", "doc", "content", "context",
    "passage", "text", "snippet", "chunk", "chunks", "tool_output",
    "tool_result", "search_result", "search_results", "results",
    "web_content", "web_page", "page", "html", "email", "comment",
    "comments", "review", "post", "transcript", "history",
    "retrieved", "rag", "kb", "knowledge",
}

TRUSTED_HINTS = {
    "system", "role", "persona", "instructions", "rules", "policy",
    "today", "date", "time", "now", "version", "model", "language",
    "locale", "timezone",
}

DANGEROUS_INSTRUCTION_PATTERNS = [
    (r"\bignore (the )?(previous|prior|above|all) instructions?\b",
     "instruction-override-phrase",
     "high",
     "prompt contains 'ignore (previous) instructions' phrasing — common injection canary"),
    (r"\bdisregard (the )?(previous|prior|above|all) instructions?\b",
     "instruction-override-phrase", "high",
     "prompt contains 'disregard (previous) instructions' phrasing"),
    (r"\byou are (now|actually) (a |an )?",
     "role-override-phrase", "medium",
     "prompt contains role-override phrasing ('you are now/actually a...')"),
    (r"\b(follow|obey|do what) (the |any )?(user|document|content|input)\b",
     "trust-boundary-violation", "high",
     "prompt instructs the model to obey untrusted content — explicit trust-boundary violation"),
    (r"\bprint (your |the )?(system )?prompt\b",
     "system-prompt-leakage", "medium",
     "prompt mentions printing/revealing the system prompt — extraction surface"),
    (r"\brepeat (your |the )?(system )?(prompt|instructions)\b",
     "system-prompt-leakage", "medium",
     "prompt mentions repeating the system prompt/instructions"),
    (r"<\|.*?\|>",
     "special-tokens", "low",
     "prompt contains special-token-like sequences (`<|...|>`) — may interact with tokenizer specials"),
]

PLACEHOLDER_PATTERNS = [
    ("jinja",  re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\}\}")),
    ("fstring", re.compile(r"(?<!\{)\{([a-zA-Z_][a-zA-Z0-9_.]*)\}(?!\})")),
    ("dollar", re.compile(r"\$\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\}")),
    ("percent", re.compile(r"%\(([a-zA-Z_][a-zA-Z0-9_]*)\)s")),
]

DELIMITER_BEFORE = re.compile(
    r"(<[a-zA-Z_]+>|<<<+|```|\"\"\"|'''|---+\s*$|\[START\]|<\|.*?\|>)",
    re.IGNORECASE,
)
DELIMITER_AFTER = re.compile(
    r"(</[a-zA-Z_]+>|>>>+|```|\"\"\"|'''|---+\s*$|\[END\]|<\|.*?\|>)",
    re.IGNORECASE,
)


class Finding(BaseModel):
    category: str
    severity: Severity
    message: str
    line: int | None = None
    excerpt: str | None = None


class Placeholder(BaseModel):
    name: str
    style: str
    line: int
    trust: Literal["trusted", "untrusted", "unknown"]
    has_delimiter: bool


class AuditReport(BaseModel):
    chars: int
    lines: int
    placeholders: list[Placeholder] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)


def _classify_trust(name: str) -> Literal["trusted", "untrusted", "unknown"]:
    base = name.split(".")[0].lower()
    if base in UNTRUSTED_HINTS:
        return "untrusted"
    if base in TRUSTED_HINTS:
        return "trusted"
    for hint in UNTRUSTED_HINTS:
        if hint in base:
            return "untrusted"
    return "unknown"


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _window(text: str, start: int, end: int, radius: int = 80) -> tuple[str, str]:
    return text[max(0, start - radius):start], text[end:end + radius]


def _has_surrounding_delimiter(text: str, start: int, end: int) -> bool:
    before, after = _window(text, start, end)
    return bool(DELIMITER_BEFORE.search(before) and DELIMITER_AFTER.search(after))


def _find_placeholders(text: str) -> list[tuple[str, str, int, int, int]]:
    """Returns list of (style, name, start, end, line)."""
    seen: set[tuple[int, int]] = set()
    out: list[tuple[str, str, int, int, int]] = []
    for style, rx in PLACEHOLDER_PATTERNS:
        for m in rx.finditer(text):
            span = m.span()
            if span in seen:
                continue
            seen.add(span)
            out.append((style, m.group(1), span[0], span[1], _line_of(text, span[0])))
    out.sort(key=lambda r: r[2])
    return out


def _check_precedence_inversion(
    text: str,
    placeholders: list[tuple[str, str, int, int, int]],
) -> Finding | None:
    """Untrusted placeholder appears AFTER the last instruction-like line."""
    if not placeholders:
        return None
    last_untrusted_offset = -1
    for _style, name, start, _end, _line in placeholders:
        if _classify_trust(name) == "untrusted":
            last_untrusted_offset = max(last_untrusted_offset, start)
    if last_untrusted_offset < 0:
        return None
    trailer = text[last_untrusted_offset:]
    has_reinforcement = bool(re.search(
        r"\b(remember|always|never|important|note that|original (instructions|task)|do not (deviate|follow))\b",
        trailer,
        re.IGNORECASE,
    ))
    if not has_reinforcement:
        return Finding(
            category="precedence-inversion",
            severity="medium",
            message=(
                "untrusted content placeholder appears near the end of the prompt with no "
                "instruction reinforcement after it — recency bias makes injected instructions more likely to win"
            ),
            line=_line_of(text, last_untrusted_offset),
        )
    return None


def prompt_injection_audit(prompt: str) -> dict:
    """Statically analyze a system prompt / template for prompt-injection surface.

    Reports:
      - placeholders (jinja `{{x}}`, fstring `{x}`, dollar `${x}`, percent `%(x)s`)
        with a trust classification (untrusted / trusted / unknown)
      - missing-delimiter findings: untrusted placeholders not wrapped in
        XML tags / triple-backticks / triple-quotes / `[START]..[END]` etc.
      - dangerous-instruction patterns (`ignore previous instructions`,
        role overrides, trust-boundary violations, system-prompt leakage hints,
        special-token sequences)
      - precedence-inversion: untrusted content placed near the end with no
        instruction reinforcement after it

    Pure function. No LLM call, no I/O, no chaining.

    Args:
        prompt: The system prompt or template text.

    Returns:
        Structured AuditReport.
    """
    if not isinstance(prompt, str):
        return {"error": "prompt must be a string"}

    report = AuditReport(chars=len(prompt), lines=prompt.count("\n") + 1)

    placeholders = _find_placeholders(prompt)
    for style, name, start, end, line in placeholders:
        trust = _classify_trust(name)
        wrapped = _has_surrounding_delimiter(prompt, start, end)
        report.placeholders.append(
            Placeholder(name=name, style=style, line=line, trust=trust, has_delimiter=wrapped)
        )
        if trust == "untrusted" and not wrapped:
            report.findings.append(Finding(
                category="missing-delimiter",
                severity="high",
                message=(
                    f"untrusted placeholder `{name}` ({style}) is not wrapped in delimiters — "
                    f"injected instructions inside this variable will read as system text"
                ),
                line=line,
                excerpt=prompt[max(0, start - 30):end + 30].replace("\n", "\\n"),
            ))
        elif trust == "unknown" and not wrapped:
            report.findings.append(Finding(
                category="unknown-trust",
                severity="low",
                message=(
                    f"placeholder `{name}` ({style}) has unknown trust level and is not wrapped — "
                    f"if this carries any external content, wrap it"
                ),
                line=line,
            ))

    for pattern, category, severity, message in DANGEROUS_INSTRUCTION_PATTERNS:
        for m in re.finditer(pattern, prompt, re.IGNORECASE):
            report.findings.append(Finding(
                category=category,
                severity=severity,  # type: ignore[arg-type]
                message=message,
                line=_line_of(prompt, m.start()),
                excerpt=prompt[max(0, m.start() - 20):m.end() + 20].replace("\n", "\\n"),
            ))

    pi = _check_precedence_inversion(prompt, placeholders)
    if pi:
        report.findings.append(pi)

    counts: dict[str, int] = {}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    report.summary = counts

    return report.model_dump()
