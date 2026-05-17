"""Path-traversal-safe filesystem access.

Resolves a user-supplied path against a fixed allow-list root and refuses
anything that escapes. Use this when an MCP tool takes a `path` parameter
from the agent.

Fixes findings of category `path-traversal` and `over-broad-param` for
path-like parameters.
"""

from __future__ import annotations

from pathlib import Path


class PathOutsideRoot(ValueError):
    """Raised when a user-supplied path resolves outside the allow-list root."""


def safe_path(user_path: str | Path, root: str | Path, *, must_exist: bool = False) -> Path:
    """Resolve `user_path` against `root` and refuse anything outside.

    The check uses fully-resolved paths (`.resolve()`) so symlinks and
    `..` components are normalized first — closes the classic
    *"join + check string prefix"* TOCTOU.

    Args:
        user_path: Path supplied by an agent / user / config.
            May be absolute or relative; either way it is anchored to `root`.
        root: The directory the agent is permitted to touch.
        must_exist: If True, also require the resolved path to exist on disk.

    Returns:
        A resolved `Path` known to live at or under `root`.

    Raises:
        PathOutsideRoot: if the resolved path escapes `root`, or
            `must_exist=True` and the file is missing.

    Example:
        >>> from mcp_security_toolkit.helpers import safe_path
        >>> @mcp.tool()
        ... def read_log(name: str) -> str:
        ...     p = safe_path(name, root="/var/log/myapp", must_exist=True)
        ...     return p.read_text()
    """
    root_p = Path(root).resolve()
    if not root_p.is_dir():
        raise PathOutsideRoot(f"root {root!r} does not exist or is not a directory")

    # Treat user_path as relative-to-root unless it's already absolute.
    candidate = Path(user_path)
    resolved = candidate.resolve() if candidate.is_absolute() else (root_p / candidate).resolve()

    try:
        resolved.relative_to(root_p)
    except ValueError as e:
        raise PathOutsideRoot(
            f"path {str(user_path)!r} resolves to {resolved!s}, outside root {root_p!s}"
        ) from e

    if must_exist and not resolved.exists():
        raise PathOutsideRoot(f"path {resolved!s} does not exist")

    return resolved
