"""SSRF-safe URL validation.

`safe_url(url)` returns the URL if it resolves to a public address and
uses an allowed scheme; otherwise raises. Use this whenever an MCP tool
takes a URL from the agent and is about to fetch it.

Fixes findings of category `ssrf` and `over-broad-param` for url-like
parameters. Mirrors the SSRF protection used inside
`graphql_introspect`, but exposed as a stand-alone helper for arbitrary
MCP tools.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse


class UnsafeURL(ValueError):
    """The URL is malformed, has a disallowed scheme, or has no hostname."""


class BlockedAddress(ValueError):
    """The URL's host resolves to a non-public address and `allow_private` is False."""


DEFAULT_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Cloud-metadata IPs that should never be reachable from a tool by default.
METADATA_ADDRESSES = frozenset({
    "169.254.169.254",   # AWS, GCP, OpenStack, Azure (sometimes)
    "fd00:ec2::254",     # AWS IMDSv2 IPv6
    "100.100.100.200",   # Alibaba Cloud
})


def _resolve_host(host: str) -> list[ipaddress._BaseAddress]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    out: list[ipaddress._BaseAddress] = []
    for info in infos:
        addr = info[4][0]
        try:
            out.append(ipaddress.ip_address(addr))
        except ValueError:
            continue
    return out


def _is_blocked(ip: ipaddress._BaseAddress) -> bool:
    if str(ip) in METADATA_ADDRESSES:
        return True
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_unspecified or ip.is_reserved
    )


def safe_url(
    url: str,
    *,
    allow_private: bool = False,
    allowed_schemes: frozenset[str] = DEFAULT_ALLOWED_SCHEMES,
) -> str:
    """Return `url` if it is safe to fetch; otherwise raise.

    Checks performed:
      1. URL must parse, have a non-empty hostname.
      2. Scheme must be in `allowed_schemes` (default: http, https).
      3. Hostname must resolve. Refusing to resolve is treated as unsafe
         to avoid leaking lookups to attacker-controlled DNS through
         downstream HTTP libraries.
      4. None of the resolved A/AAAA records may be private, loopback,
         link-local, multicast, reserved, or a known cloud-metadata IP —
         unless `allow_private=True` (opt-in for explicit internal audits).

    Residual: this is a *pre-flight* check. A hostile DNS server could
    return a public IP here and a private IP at the time the actual
    request is made (DNS rebinding). For high-stakes use, run inside a
    network namespace / egress proxy that enforces address restrictions
    independently — same caveat as `graphql_introspect`.

    Args:
        url: URL string from agent / user / config.
        allow_private: Permit hosts on private / internal networks.
            Default False.
        allowed_schemes: Schemes to accept. Default `{"http", "https"}`.

    Returns:
        The original `url` string, unchanged. Callers can pass it to
        their HTTP client knowing it has been validated.

    Raises:
        UnsafeURL: malformed URL, disallowed scheme, or hostname missing.
        BlockedAddress: resolved to private / loopback / metadata address.

    Example:
        >>> from mcp_security_toolkit.helpers import safe_url
        >>> @mcp.tool()
        ... def fetch_metadata(url: str) -> str:
        ...     url = safe_url(url)
        ...     return httpx.get(url, timeout=5).text
    """
    if not isinstance(url, str) or not url.strip():
        raise UnsafeURL("url must be a non-empty string")

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in allowed_schemes:
        raise UnsafeURL(
            f"scheme {parsed.scheme!r} not in allowed set {sorted(allowed_schemes)}"
        )

    host = parsed.hostname
    if not host:
        raise UnsafeURL("url has no hostname")

    if allow_private:
        return url

    ips = _resolve_host(host)
    if not ips:
        raise BlockedAddress(f"host {host!r} did not resolve")

    for ip in ips:
        if _is_blocked(ip):
            raise BlockedAddress(
                f"host {host!r} resolves to {ip!s} (private / loopback / metadata) "
                f"— pass allow_private=True to permit"
            )

    return url
