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
