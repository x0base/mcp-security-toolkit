"""Defensive helpers for MCP server authors.

The detectors in `mcp_security_toolkit.tools` find unsafe patterns in
other people's MCP servers. The helpers in *this* package are the
inverse: drop-in primitives that an MCP author can import to make their
tools safe by construction.

Each helper is the simplest correct version that fixes a class of bug
our detectors flag. They are pure functions, no I/O, no globals, no
network — easy to audit, easy to embed.

  >>> from mcp_security_toolkit.helpers import safe_path, safe_url, safe_sql_identifier

If you're building an MCP tool and an `mcp_server_audit` finding points
at your code, the corresponding helper here is the one-line fix.
"""

from mcp_security_toolkit.helpers.eval_expr import (
    UnsafeExpression,
    evaluate_expression,
)
from mcp_security_toolkit.helpers.filenames import (
    UnsafeFilename,
    safe_filename,
)
from mcp_security_toolkit.helpers.paths import (
    PathOutsideRoot,
    safe_path,
)
from mcp_security_toolkit.helpers.sql import (
    UnsafeIdentifier,
    safe_sql_identifier,
)
from mcp_security_toolkit.helpers.urls import (
    BlockedAddress,
    UnsafeURL,
    safe_url,
)

__all__ = [
    "BlockedAddress",
    "PathOutsideRoot",
    "UnsafeExpression",
    "UnsafeFilename",
    "UnsafeIdentifier",
    "UnsafeURL",
    "evaluate_expression",
    "safe_filename",
    "safe_path",
    "safe_sql_identifier",
    "safe_url",
]
