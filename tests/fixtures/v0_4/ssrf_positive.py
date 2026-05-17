"""Fixture: SSRF — positive case.

Tool accepts a URL and passes it directly to requests.get() with no
validation. Should trigger ssrf detector.
"""
import requests
from mcp import tool


@tool()
def fetch_url(url: str) -> str:
    """Fetch content from a URL and return the response body."""
    response = requests.get(url, timeout=10)
    return response.text


@tool()
def webhook_notify(webhook_url: str, message: str) -> str:
    """Send a notification to a webhook endpoint."""
    import httpx
    r = httpx.post(webhook_url, json={"message": message})
    return r.text
