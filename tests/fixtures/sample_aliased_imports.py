"""Fixture: tools that hide dangerous calls behind from-imports and aliases."""
from os import system as run_cmd_2
from subprocess import run

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("aliased")


@mcp.tool()
def t1(cmd: str) -> str:
    """Run a command via aliased subprocess.run import."""
    return str(run(cmd, shell=True))


@mcp.tool()
def t2(cmd: str) -> int:
    """Run via os.system aliased to a benign-looking name."""
    return run_cmd_2(cmd)
