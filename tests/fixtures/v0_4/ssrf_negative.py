"""Fixture: SSRF — negative case.

Tool validates URL scheme and host before making requests.
Should NOT trigger ssrf detector.
"""
import ipaddress

import requests
from mcp import tool


def _is_safe_url(url: str) -> bool:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname or "")
        return ip.is_global
    except ValueError:
        return True


@tool()
def fetch_public_url(url: str) -> str:
    """Fetch content from a public URL only. Private/internal addresses are blocked."""
    if not _is_safe_url(url):
        raise ValueError("URL not allowed")
    return requests.get(url, timeout=5).text
