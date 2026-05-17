"""Convert mcp_server_audit reports to SARIF 2.1.0.

SARIF is the industry-standard JSON schema for static-analysis output and
what GitHub Code Scanning ingests. Emitting SARIF lets users upload
`mcp_server_audit` findings to the GitHub Security tab via the standard
`github/codeql-action/upload-sarif` action.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

from __future__ import annotations

from typing import Any

from mcp_security_toolkit import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)

# SARIF only knows: none, note, warning, error.
_SEVERITY_MAP = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
}


def to_sarif(report: dict) -> dict:
    """Build a SARIF 2.1.0 document from an `mcp_server_audit` report.

    Args:
        report: The dict returned by `mcp_server_audit()`.

    Returns:
        A SARIF 2.1.0 document (dict, JSON-serializable). If the input
        report contains an `error` key (e.g. file-not-found) a SARIF
        document is still returned with an empty `results` array — that's
        the SARIF idiom for "ran cleanly, found nothing".
    """
    file_path = report.get("file") or "<unknown>"
    tools_reports = report.get("tools") or []
    file_findings = report.get("file_level_findings") or []

    # Collect every unique rule id we cite.
    rule_index: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for tool_report in tools_reports:
        tool_name = tool_report.get("name", "<unknown>")
        line = tool_report.get("line") or 1
        for f in tool_report.get("findings") or []:
            results.append(_finding_to_result(f, file_path, default_line=line, tool_name=tool_name))
            _ensure_rule(rule_index, f)

    for f in file_findings:
        results.append(_finding_to_result(f, file_path, default_line=1, tool_name=None))
        _ensure_rule(rule_index, f)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-security-toolkit",
                        "version": __version__,
                        "informationUri": (
                            "https://github.com/x0base/mcp-security-toolkit"
                        ),
                        "rules": list(rule_index.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _ensure_rule(index: dict[str, dict[str, Any]], finding: dict) -> None:
    rule_id = finding.get("category") or "unknown"
    if rule_id in index:
        return
    index[rule_id] = {
        "id": rule_id,
        "name": rule_id.replace("-", "_"),
        "shortDescription": {"text": rule_id.replace("-", " ").title()},
        "defaultConfiguration": {
            "level": _SEVERITY_MAP.get(finding.get("severity", "info"), "warning")
        },
        "helpUri": (
            "https://github.com/x0base/mcp-security-toolkit"
            f"/blob/main/docs/detectors.md#{rule_id}"
        ),
    }


def _finding_to_result(
    finding: dict,
    file_path: str,
    *,
    default_line: int,
    tool_name: str | None,
) -> dict[str, Any]:
    rule_id = finding.get("category") or "unknown"
    line = finding.get("line") or default_line
    message = finding.get("message", "")
    if tool_name:
        message = f"[{tool_name}] {message}"

    return {
        "ruleId": rule_id,
        "level": _SEVERITY_MAP.get(finding.get("severity", "info"), "warning"),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": int(line)},
                }
            }
        ],
    }
