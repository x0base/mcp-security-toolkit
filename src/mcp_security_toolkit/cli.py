"""CLI subcommands.

Default behavior (no args) still launches the MCP stdio server — that's
how `mcp-security-toolkit` is meant to be invoked from a client config.

Subcommands:

  scan-installed [--sarif]
      Discover MCP servers configured in the standard client config
      files (`~/.cursor/mcp.json`, `~/.claude/mcp.json`,
      `~/Library/Application Support/Claude/claude_desktop_config.json`
      on macOS, etc.) and run `mcp_server_audit` on any Python source
      file referenced. Prints a per-server summary; with `--sarif`,
      emits a single SARIF document on stdout.

  version
      Print version and exit.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from mcp_security_toolkit import __version__
from mcp_security_toolkit.sarif import to_sarif
from mcp_security_toolkit.tools.mcp_server_audit import mcp_server_audit


def _config_candidates() -> list[Path]:
    home = Path.home()
    paths = [
        home / ".cursor" / "mcp.json",
        home / ".claude" / "mcp.json",
        home / ".config" / "claude" / "mcp.json",
        home / ".config" / "claude-desktop" / "config.json",
    ]
    if sys.platform == "darwin":
        paths.append(home / "Library/Application Support/Claude/claude_desktop_config.json")
    elif sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            paths.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
    return [p for p in paths if p.is_file()]


def _extract_python_sources(config_path: Path) -> list[tuple[str, str, Path]]:
    """Returns [(client_label, server_name, python_file)] from a config."""
    try:
        config = json.loads(config_path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    out: list[tuple[str, str, Path]] = []
    servers = (config.get("mcpServers") or config.get("servers") or {})
    if not isinstance(servers, dict):
        return out
    client_label = config_path.name
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        # Look for python invocations: command="python", args=["server.py"] or args=["-m", "module"]
        command = str(spec.get("command", ""))
        args = spec.get("args") or []
        cwd_str = str(spec.get("cwd", ""))
        cwd = Path(cwd_str).expanduser() if cwd_str else None
        if not isinstance(args, list):
            continue
        for arg in args:
            if not isinstance(arg, str):
                continue
            if arg.endswith(".py"):
                p = Path(arg).expanduser()
                if not p.is_absolute() and cwd:
                    p = (cwd / p).resolve()
                if p.is_file():
                    out.append((client_label, name, p))
                break
        # Note: we don't yet resolve `-m module.path` to a file. Phase 2.
        _ = command  # placeholder for future heuristics
    return out


def cmd_scan_installed(args: argparse.Namespace) -> int:
    configs = _config_candidates()
    if not configs:
        print("no MCP client configs found in known locations", file=sys.stderr)
        return 1

    discovered: list[tuple[str, str, Path]] = []
    for cfg in configs:
        discovered.extend(_extract_python_sources(cfg))

    if not discovered:
        print("no Python MCP servers referenced in known configs", file=sys.stderr)
        return 1

    if args.sarif:
        combined_runs: list[dict] = []
        for client, name, path in discovered:
            report = mcp_server_audit(str(path))
            if "error" in report and "tools_found" not in report:
                continue
            sarif = to_sarif(report)
            for run in sarif["runs"]:
                # Tag the run with the source MCP server for traceability
                run.setdefault("properties", {}).update({
                    "mcp.client": client,
                    "mcp.server": name,
                })
            combined_runs.extend(sarif["runs"])
        sample = to_sarif({"file": "<combined>", "tools_found": 0, "tools": [], "file_level_findings": []})
        sample["runs"] = combined_runs or sample["runs"]
        print(json.dumps(sample, indent=2))
        return 0

    # Text mode
    print(f"Discovered {len(discovered)} Python MCP server(s):\n")
    total_high = total_med = total_low = 0
    for client, name, path in discovered:
        report = mcp_server_audit(str(path))
        if "error" in report and "tools_found" not in report:
            print(f"  [{client}] {name}\n    ! {report['error']}\n")
            continue
        s = report.get("summary", {})
        h, m, lo = s.get("high", 0), s.get("medium", 0), s.get("low", 0)
        total_high += h
        total_med += m
        total_low += lo
        marker = "🔴" if h else ("🟡" if m else ("🟢" if not lo else "⚪"))
        print(f"  {marker} [{client}] {name}")
        print(f"     file: {path}")
        print(f"     tools: {report.get('tools_found', 0)}, "
              f"findings: high={h} medium={m} low={lo}\n")

    print(f"Totals: high={total_high} medium={total_med} low={total_low}")
    return 0 if total_high == 0 else 2


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"mcp-security-toolkit {__version__}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-security-toolkit",
        description="Atomic MCP tools for AppSec & AI Security. "
                    "Run without subcommand to launch the MCP stdio server.",
    )
    sub = parser.add_subparsers(dest="cmd")

    scan = sub.add_parser(
        "scan-installed",
        help="Audit MCP servers referenced in local client configs",
    )
    scan.add_argument(
        "--sarif",
        action="store_true",
        help="Emit SARIF 2.1.0 on stdout instead of a text summary",
    )
    scan.set_defaults(func=cmd_scan_installed)

    ver = sub.add_parser("version", help="Print version and exit")
    ver.set_defaults(func=cmd_version)

    args = parser.parse_args(argv)

    if not args.cmd:
        # Default: run the MCP server.
        from mcp_security_toolkit.server import main as run_server
        run_server()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
