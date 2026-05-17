"""Tests for the CLI surface (version, scan-installed)."""
import json
from pathlib import Path
from unittest.mock import patch

from mcp_security_toolkit import cli


def test_version_command(capsys):
    rc = cli.main(["version"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "mcp-security-toolkit" in out


def test_scan_installed_no_configs(capsys):
    with patch.object(cli, "_config_candidates", return_value=[]):
        rc = cli.main(["scan-installed"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "no MCP client configs found" in err


def test_scan_installed_no_python_servers(tmp_path: Path, capsys):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"x": {"command": "node", "args": ["server.js"]}}}))
    with patch.object(cli, "_config_candidates", return_value=[cfg]):
        rc = cli.main(["scan-installed"])
    assert rc == 1
    assert "no Python MCP servers" in capsys.readouterr().err


def test_scan_installed_text_report(tmp_path: Path, capsys):
    # Use the existing fixture as the discovered MCP server.
    fixture = Path(__file__).parent / "fixtures" / "sample_mcp_server.py"
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({
        "mcpServers": {
            "demo": {"command": "python", "args": [str(fixture)]},
        }
    }))
    with patch.object(cli, "_config_candidates", return_value=[cfg]):
        rc = cli.main(["scan-installed"])
    out = capsys.readouterr().out
    assert "demo" in out
    assert "high=" in out
    # Fixture has a shell-exec → high → non-zero exit
    assert rc == 2


def test_scan_installed_sarif_emit(tmp_path: Path, capsys):
    fixture = Path(__file__).parent / "fixtures" / "sample_mcp_server.py"
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({
        "mcpServers": {
            "demo": {"command": "python", "args": [str(fixture)]},
        }
    }))
    with patch.object(cli, "_config_candidates", return_value=[cfg]):
        rc = cli.main(["scan-installed", "--sarif"])
    assert rc == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"]
    assert doc["runs"][0]["properties"]["mcp.client"] == cfg.name
    assert doc["runs"][0]["properties"]["mcp.server"] == "demo"


def test_extract_python_sources_with_cwd(tmp_path: Path):
    fixture = Path(__file__).parent / "fixtures" / "sample_mcp_server.py"
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({
        "mcpServers": {
            "demo": {
                "command": "python",
                "args": ["sample_mcp_server.py"],
                "cwd": str(fixture.parent),
            }
        }
    }))
    sources = cli._extract_python_sources(cfg)
    assert len(sources) == 1
    assert sources[0][1] == "demo"
    assert sources[0][2].name == "sample_mcp_server.py"


def test_extract_python_sources_handles_malformed(tmp_path: Path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{ not valid json")
    assert cli._extract_python_sources(cfg) == []
