"""Tests for SARIF 2.1.0 conversion."""
from pathlib import Path

from mcp_security_toolkit.sarif import SARIF_VERSION, to_sarif
from mcp_security_toolkit.tools.mcp_server_audit import mcp_server_audit

FIXTURE = Path(__file__).parent / "fixtures" / "sample_mcp_server.py"


def test_sarif_basic_shape():
    report = mcp_server_audit(str(FIXTURE))
    sarif = to_sarif(report)
    assert sarif["version"] == SARIF_VERSION
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1


def test_sarif_driver_metadata():
    sarif = to_sarif(mcp_server_audit(str(FIXTURE)))
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "mcp-security-toolkit"
    assert driver["version"]
    assert driver["informationUri"].startswith("https://github.com/")


def test_sarif_results_present():
    sarif = to_sarif(mcp_server_audit(str(FIXTURE)))
    results = sarif["runs"][0]["results"]
    assert len(results) > 0
    for r in results:
        assert r["ruleId"]
        assert r["level"] in {"none", "note", "warning", "error"}
        assert r["message"]["text"]
        assert r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_sarif_severity_mapping():
    sarif = to_sarif(mcp_server_audit(str(FIXTURE)))
    levels = {r["level"] for r in sarif["runs"][0]["results"]}
    # The fixture has at least one high (shell-exec) → error in SARIF
    assert "error" in levels


def test_sarif_rules_collected():
    sarif = to_sarif(mcp_server_audit(str(FIXTURE)))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert "shell-exec" in rule_ids
    for r in rules:
        assert r["helpUri"].startswith("https://github.com/")


def test_sarif_handles_empty_report():
    empty = {"file": "x.py", "tools_found": 0, "tools": [], "file_level_findings": []}
    sarif = to_sarif(empty)
    assert sarif["runs"][0]["results"] == []
