from pathlib import Path

from mcp_security_toolkit.tools.mcp_server_audit import mcp_server_audit

FIXTURE = Path(__file__).parent / "fixtures" / "sample_mcp_server.py"


def test_enumerates_all_tools():
    report = mcp_server_audit(str(FIXTURE))
    names = {t["name"] for t in report["tools"]}
    assert names == {"safe_echo", "run_cmd", "read_anything", "write_log"}
    assert report["tools_found"] == 4


def test_flags_subprocess_shell_exec():
    report = mcp_server_audit(str(FIXTURE))
    run_cmd = next(t for t in report["tools"] if t["name"] == "run_cmd")
    categories = {f["category"] for f in run_cmd["findings"]}
    assert "shell-exec" in categories
    assert any(f["severity"] == "high" for f in run_cmd["findings"])


def test_flags_short_docstring():
    report = mcp_server_audit(str(FIXTURE))
    run_cmd = next(t for t in report["tools"] if t["name"] == "run_cmd")
    assert any(f["category"] == "ambiguous-description" for f in run_cmd["findings"])


def test_flags_missing_docstring():
    report = mcp_server_audit(str(FIXTURE))
    read = next(t for t in report["tools"] if t["name"] == "read_anything")
    assert any(
        f["category"] == "ambiguous-description" and "no docstring" in f["message"]
        for f in read["findings"]
    )


def test_flags_overbroad_path_param():
    report = mcp_server_audit(str(FIXTURE))
    read = next(t for t in report["tools"] if t["name"] == "read_anything")
    assert any(f["category"] == "over-broad-param" for f in read["findings"])


def test_flags_fs_write():
    report = mcp_server_audit(str(FIXTURE))
    wl = next(t for t in report["tools"] if t["name"] == "write_log")
    assert any(f["category"] == "fs-write" for f in wl["findings"])


def test_safe_tool_has_no_high_findings():
    report = mcp_server_audit(str(FIXTURE))
    echo = next(t for t in report["tools"] if t["name"] == "safe_echo")
    assert not any(f["severity"] == "high" for f in echo["findings"])


def test_file_level_secret_env():
    report = mcp_server_audit(str(FIXTURE))
    assert any(f["category"] == "secret-in-env" for f in report["file_level_findings"])


def test_summary_counts():
    report = mcp_server_audit(str(FIXTURE))
    assert "high" in report["summary"]
    assert report["summary"]["high"] >= 1


def test_missing_file():
    report = mcp_server_audit("/nonexistent/path.py")
    assert "error" in report


ALIASED = Path(__file__).parent / "fixtures" / "sample_aliased_imports.py"


def test_from_import_resolves_subprocess_run():
    report = mcp_server_audit(str(ALIASED))
    t1 = next(t for t in report["tools"] if t["name"] == "t1")
    cats = {f["category"] for f in t1["findings"]}
    assert "shell-exec" in cats
    assert any(f["severity"] == "high" for f in t1["findings"])


def test_from_import_renamed_resolves_os_system():
    report = mcp_server_audit(str(ALIASED))
    t2 = next(t for t in report["tools"] if t["name"] == "t2")
    cats = {f["category"] for f in t2["findings"]}
    assert "shell-exec" in cats


def test_max_bytes_blocks_huge_input(tmp_path):
    big = tmp_path / "big.py"
    big.write_text("x = 1\n" * 100_000)  # ~600 KB
    r = mcp_server_audit(str(big), max_bytes=1000)
    assert r["error"] == "input-too-large"
    assert r["max_bytes"] == 1000
    assert r["bytes"] > 1000


def test_coverage_block_present():
    r = mcp_server_audit(str(FIXTURE))
    cov = r["coverage"]
    assert cov["decorator_tools_found"] == 4
    assert cov["imperative_tools_resolved"] == 0
    assert cov["imperative_tools_external"] == 0


def test_limitations_present():
    r = mcp_server_audit(str(FIXTURE))
    assert isinstance(r["limitations"], list)
    assert len(r["limitations"]) >= 3
    assert any("heuristic" in lim.lower() for lim in r["limitations"])


def test_bytes_read_recorded():
    r = mcp_server_audit(str(FIXTURE))
    assert r["bytes_read"] > 0


# ── v0.4 detector tests ────────────────────────────────────────────────────

V0_4 = Path(__file__).parent / "fixtures" / "v0_4"


def test_d1_path_traversal_positive():
    r = mcp_server_audit(str(V0_4 / "path_traversal_positive.py"))
    all_cats = [f["category"] for t in r["tools"] for f in t["findings"]]
    assert "path-traversal" in all_cats


def test_d1_path_traversal_negative():
    r = mcp_server_audit(str(V0_4 / "path_traversal_negative.py"))
    all_cats = [f["category"] for t in r["tools"] for f in t["findings"]]
    assert "path-traversal" not in all_cats


def test_d2_tool_description_injection_positive():
    r = mcp_server_audit(str(V0_4 / "tool_desc_injection_positive.py"))
    all_cats = [f["category"] for t in r["tools"] for f in t["findings"]]
    assert "tool-description-injection" in all_cats
    finding = next(
        f for t in r["tools"] for f in t["findings"]
        if f["category"] == "tool-description-injection"
    )
    assert finding["severity"] == "medium"


def test_d3_ssrf_positive():
    r = mcp_server_audit(str(V0_4 / "ssrf_positive.py"))
    all_cats = [f["category"] for t in r["tools"] for f in t["findings"]]
    assert "ssrf" in all_cats
    finding = next(
        f for t in r["tools"] for f in t["findings"]
        if f["category"] == "ssrf"
    )
    assert finding["severity"] == "high"


def test_d3_ssrf_negative():
    r = mcp_server_audit(str(V0_4 / "ssrf_negative.py"))
    all_cats = [f["category"] for t in r["tools"] for f in t["findings"]]
    assert "ssrf" not in all_cats


def test_d4_uri_sqli_positive():
    r = mcp_server_audit(str(V0_4 / "mcp_uri_sqli_positive.py"))
    all_cats = [f["category"] for t in r["tools"] for f in t["findings"]]
    assert "mcp-resource-uri-sqli" in all_cats
    finding = next(
        f for t in r["tools"] for f in t["findings"]
        if f["category"] == "mcp-resource-uri-sqli"
    )
    assert finding["severity"] == "high"


def test_d4_uri_sqli_negative():
    r = mcp_server_audit(str(V0_4 / "mcp_uri_sqli_negative.py"))
    all_cats = [f["category"] for t in r["tools"] for f in t["findings"]]
    assert "mcp-resource-uri-sqli" not in all_cats


def test_d5_tool_shadowing_positive():
    r = mcp_server_audit(str(V0_4 / "tool_shadowing_positive.py"))
    file_cats = [f["category"] for f in r["file_level_findings"]]
    assert "tool-shadowing" in file_cats
    findings = [f for f in r["file_level_findings"] if f["category"] == "tool-shadowing"]
    assert len(findings) >= 2


def test_detectors_run_populated():
    r = mcp_server_audit(str(FIXTURE))
    assert "path-traversal" in r["coverage"]["detectors_run"]
    assert "tool-shadowing" in r["coverage"]["detectors_run"]
    assert "ssrf" in r["coverage"]["detectors_run"]
    assert "mcp-resource-uri-sqli" in r["coverage"]["detectors_run"]
