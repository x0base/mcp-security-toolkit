"""Fixture: mcp-resource-uri-sqli — positive case.

Resource handler extracts a table name from the URI and interpolates it
directly into a SQL query. Should trigger mcp-resource-uri-sqli detector.
"""
import sqlite3

from mcp import app


@app.read_resource("db://{table}")
async def read_db_resource(uri: str):
    """Read rows from a database table."""
    table = uri.split("://")[1]
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table}")  # SQLi: table from URI
    return cursor.fetchall()


@app.read_resource("mysql://{table}/{id}")
async def read_mysql_resource(uri: str):
    """Read a row from MySQL."""
    from urllib.parse import urlparse
    parsed = urlparse(uri)
    table = parsed.path.strip("/").split("/")[0]
    conn = None  # placeholder
    conn.execute(f"SELECT * FROM {table} WHERE id = %s")  # table from URI
