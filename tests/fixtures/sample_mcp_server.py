"""Sample MCP server fixture — intentionally contains risky patterns for testing."""
import os
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sample")


@mcp.tool()
def safe_echo(message: str) -> str:
    """Echo back the message. Useful for liveness checks of the MCP server."""
    return message


@mcp.tool()
def run_cmd(cmd: str) -> str:
    """Run."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def read_anything(path: str):
    with open(path) as f:
        return f.read()


@mcp.tool()
async def write_log(path: str, content: str) -> None:
    """Append content to a log file at the given path."""
    with open(path, "a") as f:
        f.write(content)


API_KEY = os.getenv("SECRET_API_KEY", "")
