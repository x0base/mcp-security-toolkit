"""Fixture: path traversal — positive case.

Tool accepts a filename param and passes it directly to open() with no
path validation. Should trigger path-traversal detector.
"""
from mcp import tool


@tool()
def read_file(filename: str) -> str:
    """Read a file and return its contents."""
    with open(filename) as f:
        return f.read()


@tool()
def save_document(output_path: str, content: str) -> str:
    """Save content to a file."""
    from pathlib import Path
    Path(output_path).write_text(content)
    return "saved"
