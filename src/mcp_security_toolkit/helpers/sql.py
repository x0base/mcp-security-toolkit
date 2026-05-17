"""SQL identifier (table/column) validation.

Parameterized queries protect *values*. They do NOT protect *identifiers*
— most drivers refuse to bind an identifier, and string-interpolating a
user-supplied table or column name is a classic SQL-injection vector for
MCP tools that accept dynamic schema input from the agent.

`safe_sql_identifier` is the simple correct check: an identifier must
match a strict character set and (optionally) be in an allow-list.
Fixes findings of category `mcp-resource-uri-sqli` and adjacent SQLi
patterns.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# RFC-ish identifier: letter or underscore, then letters / digits /
# underscores. Length capped at 64 (MySQL's identifier limit; PostgreSQL
# is 63 by default — stricter than both is fine).
_IDENT_REGEX = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class UnsafeIdentifier(ValueError):
    """The identifier does not satisfy the SQL identifier rules or allow-list."""


def safe_sql_identifier(
    name: str,
    *,
    allow: Iterable[str] | None = None,
) -> str:
    """Return `name` if it is a syntactically valid SQL identifier.

    Args:
        name: Identifier candidate from agent / user / config.
        allow: If provided, `name` must also be a member of this set.
            Strongly recommended for any code that uses the returned
            identifier in interpolated SQL.

    Returns:
        `name`, unchanged, when valid.

    Raises:
        UnsafeIdentifier: bad character set, length, or not in allow-list.

    Example:
        >>> from mcp_security_toolkit.helpers import safe_sql_identifier
        >>> ALLOWED_TABLES = {"users", "orders", "events"}
        >>> @mcp.tool()
        ... def count_rows(table: str) -> int:
        ...     table = safe_sql_identifier(table, allow=ALLOWED_TABLES)
        ...     # Now safe to interpolate.
        ...     return db.execute(f"SELECT COUNT(*) FROM {table}").scalar()
    """
    if not isinstance(name, str):
        raise UnsafeIdentifier("identifier must be a string")
    if not _IDENT_REGEX.match(name):
        raise UnsafeIdentifier(
            f"identifier {name!r} is not a valid SQL identifier "
            "(letter/underscore + letters/digits/underscores, max 64 chars)"
        )
    if allow is not None and name not in set(allow):
        raise UnsafeIdentifier(
            f"identifier {name!r} is not in the caller's allow-list"
        )
    return name
