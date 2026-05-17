"""Fixture: path traversal — negative case.

Tool validates path against a configured root before using it.
Should NOT trigger path-traversal detector.
"""
from pathlib import Path

from mcp import tool

ALLOWED_ROOT = Path("/data/files")


@tool()
def read_safe_file(filename: str) -> str:
    """Read a file from the allowed directory only."""
    target = (ALLOWED_ROOT / filename).resolve()
    target.relative_to(ALLOWED_ROOT)  # raises ValueError if outside
    return target.read_text()
