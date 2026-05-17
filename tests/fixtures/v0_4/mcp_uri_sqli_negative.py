"""Fixture: mcp-resource-uri-sqli — negative case.

Resource handler uses parameterized queries only.
Should NOT trigger mcp-resource-uri-sqli detector.
"""
import sqlite3

from mcp import app


@app.read_resource("db://{table}/{row_id}")
async def read_db_resource(uri: str):
    """Read a specific row using parameterized query.

    The `{table}` from the URI is intentionally ignored — the handler
    targets a hardcoded `items` table and binds `row_id` via parameters.
    Demonstrates the safe pattern: never interpolate user input into a
    table/column name; if you must, use `safe_sql_identifier(..., allow=...)`.
    """
    parts = uri.split("://")[1].split("/")
    row_id = parts[1] if len(parts) > 1 else "0"
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE id = ?", (row_id,))
    return cursor.fetchall()
