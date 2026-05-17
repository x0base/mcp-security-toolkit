"""Filename sanitization (basename-only, no path components).

For MCP tools that accept a `filename` parameter and use it to name a
file inside a known directory the tool itself controls (e.g.
`uploads/{filename}`). The helper strips any directory components,
rejects `..` after normalization, and refuses control characters /
separators that would let an attacker break out of the intended layout.

Use `safe_path` when the user supplies a full path; use
`safe_filename` when the user supplies a *name* the tool then joins
to its own directory.
"""

from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath


class UnsafeFilename(ValueError):
    """The filename has separators, control characters, or is otherwise unsafe."""


# Control characters (0x00-0x1F and DEL) are never legitimate in a
# filename and cause surprising behavior on many filesystems / shells.
_CONTROL = frozenset(chr(c) for c in (*range(0x00, 0x20), 0x7F))

# Reserved Windows device names. These can shadow real device handles
# even when used as a regular filename inside a directory.
_WINDOWS_RESERVED = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})


def safe_filename(name: str) -> str:
    """Return the safe basename of `name`, or raise.

    Rules:
      * Must be a non-empty string.
      * Must not contain a path separator (`/` or `\\`) — anywhere.
      * Must not contain control characters (0x00-0x1F, DEL).
      * Must not equal `.` or `..` after stripping.
      * Must not equal a Windows reserved device name (CON, PRN, …).
      * After running through both POSIX and Windows `Path.name`, the
        result must equal the input — i.e. no implicit directory part
        was stripped (which would mean the caller passed a path, not
        a filename).

    Args:
        name: Filename candidate from agent / user / config.

    Returns:
        `name`, unchanged, when safe to use as a basename.

    Raises:
        UnsafeFilename: any rule violated.

    Example:
        >>> from mcp_security_toolkit.helpers import safe_filename
        >>> @mcp.tool()
        ... def save_upload(filename: str, data: bytes) -> str:
        ...     name = safe_filename(filename)
        ...     path = Path("/var/uploads") / name
        ...     path.write_bytes(data)
        ...     return str(path)
    """
    if not isinstance(name, str):
        raise UnsafeFilename("filename must be a string")
    if not name:
        raise UnsafeFilename("filename must not be empty")

    if any(c in _CONTROL for c in name):
        raise UnsafeFilename("filename contains control characters")

    if "/" in name or "\\" in name:
        raise UnsafeFilename("filename contains a path separator")

    stripped = name.strip()
    if stripped in {".", ".."}:
        raise UnsafeFilename(f"filename {name!r} is a directory traversal token")

    # If the input survives basename extraction on BOTH POSIX and Windows
    # parsers unchanged, no directory part was hidden in there.
    if PurePosixPath(name).name != name or PureWindowsPath(name).name != name:
        raise UnsafeFilename(
            f"filename {name!r} resolves to a different basename — pass a basename, not a path"
        )

    if name.split(".")[0].upper() in _WINDOWS_RESERVED:
        raise UnsafeFilename(
            f"filename {name!r} matches a Windows reserved device name"
        )

    return name
