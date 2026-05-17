"""Send a GraphQL introspection query and summarize the schema.

Single HTTP POST. Returns:
  - whether introspection is enabled
  - operation counts (queries, mutations, subscriptions)
  - top-level operation names
  - types defined in the schema
  - security observations (mutations exposed, sensitive-named fields)

Atomic: one URL in, one report out.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high"]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}
""".strip()

SENSITIVE_FIELD_HINTS = (
    "password", "secret", "token", "apikey", "api_key", "private",
    "ssn", "credit", "internal", "admin", "debug",
)

# Cap response body to bound memory in case a hostile target streams
# unbounded data. An introspection response is typically <100 KB; 5 MB
# is a generous ceiling that still prevents DoS.
MAX_RESPONSE_BYTES = 5 * 1024 * 1024


class GraphQLObservation(BaseModel):
    category: str
    severity: Severity
    message: str


class IntrospectReport(BaseModel):
    url: str
    introspection_enabled: bool
    status: int | None = None
    error: str | None = None
    query_type: str | None = None
    mutation_type: str | None = None
    subscription_type: str | None = None
    query_count: int = 0
    mutation_count: int = 0
    subscription_count: int = 0
    type_count: int = 0
    sample_queries: list[str] = Field(default_factory=list)
    sample_mutations: list[str] = Field(default_factory=list)
    observations: list[GraphQLObservation] = Field(default_factory=list)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Block all redirects.

    Following Location: from an attacker-controlled server can land on
    private IPs (SSRF) or attacker-controlled second-stage URLs that the
    pre-flight SSRF check didn't see. For an introspection POST, redirects
    are not legitimate behavior — fail fast.
    """

    def http_error_301(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(
            req.full_url, code,
            "redirects disabled (SSRF protection — redirect from initial URL not allowed)",
            headers, fp,
        )
    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def _post(url: str, payload: dict, timeout: float, insecure: bool) -> tuple[int, dict | None, str | None]:
    body = json.dumps({"query": payload["query"]}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    handlers: list = [_NoRedirectHandler()]
    if insecure and url.startswith("https://"):
        ctx = ssl._create_unverified_context()  # noqa: SLF001
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            # Bounded read: one byte over the cap and we bail out.
            data = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                return resp.status, None, f"response-too-large (>{MAX_RESPONSE_BYTES} bytes)"
            try:
                return resp.status, json.loads(data), None
            except json.JSONDecodeError:
                return resp.status, None, "non-JSON response"
    except urllib.error.HTTPError as e:
        try:
            body_bytes = e.read(MAX_RESPONSE_BYTES + 1)
            body_text = body_bytes[:200].decode("utf-8", errors="replace")
        except Exception:
            body_text = ""
        return e.code, None, f"HTTP {e.code}: {body_text}"
    except urllib.error.URLError as e:
        return 0, None, f"URL error: {e.reason}"
    except (TimeoutError, OSError) as e:
        return 0, None, f"network error: {e}"


def _is_private_address(host: str) -> tuple[bool, str | None]:
    """Resolve `host` and return (is_private, resolved_ip_or_None).

    Treats RFC1918, loopback, link-local, multicast, unspecified, ULA, and
    cloud-metadata addresses as private. Failure to resolve is treated as
    NOT private (let the request fail in the HTTP layer with a clear error).
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return (False, None)
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_unspecified or ip.is_reserved
        ):
            return (True, str(ip))
        # cloud metadata endpoints
        if str(ip) in {"169.254.169.254", "fd00:ec2::254"}:
            return (True, str(ip))
    return (False, infos[0][4][0] if infos else None)


def graphql_introspect(
    url: str,
    timeout: float = 10.0,
    insecure: bool = False,
    allow_private: bool = False,
) -> dict:
    """Run a GraphQL introspection query against `url` and summarize the schema.

    Single HTTP POST. Read-only. Will not mutate state on the server.

    By default, requests resolving to private / loopback / link-local /
    cloud-metadata addresses are blocked (SSRF protection). Set
    `allow_private=True` to override — useful when explicitly auditing
    internal infrastructure.

    Redirects are disabled (an HTTP 3xx from the target raises
    `HTTP-error: redirects disabled`). This prevents a public endpoint from
    redirecting the request to a private address after the pre-flight check.

    Residual risk: DNS rebinding. The pre-flight resolution and the actual
    HTTP request happen in separate syscalls and the OS may resolve the
    hostname twice. A hostile DNS that returns a public IP for the check
    and a private IP for the request can defeat the guard. For high-stakes
    environments, run this tool inside a network namespace / egress proxy
    that enforces address restrictions independently.

    Args:
        url: Full GraphQL endpoint URL (e.g. `https://api.example.com/graphql`).
        timeout: Network timeout in seconds (clamped to [1, 60]).
        insecure: Skip TLS verification (for self-signed certs in test envs).
        allow_private: Permit requests to private / internal addresses.
            Default False.

    Returns:
        IntrospectReport summarizing the schema and security observations.
        If the URL resolves to a private address and `allow_private` is
        False, returns `{"error": "blocked-private-address", ...}`.
    """
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return {"error": "url must be an http(s) URL"}

    timeout = max(1.0, min(float(timeout), 60.0))

    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return {"error": "url has no hostname"}

    is_private, resolved = _is_private_address(host)
    if is_private and not allow_private:
        return {
            "error": "blocked-private-address",
            "host": host,
            "resolved_ip": resolved,
            "hint": "Pass allow_private=True to audit internal infrastructure intentionally.",
        }

    status, data, err = _post(url, {"query": INTROSPECTION_QUERY}, timeout, insecure)
    report = IntrospectReport(url=url, introspection_enabled=False, status=status, error=err)

    if not data or "data" not in data or not data.get("data", {}).get("__schema"):
        if data and data.get("errors"):
            report.error = json.dumps(data["errors"])[:300]
        return report.model_dump()

    schema = data["data"]["__schema"]
    report.introspection_enabled = True
    report.query_type = (schema.get("queryType") or {}).get("name")
    report.mutation_type = (schema.get("mutationType") or {}).get("name")
    report.subscription_type = (schema.get("subscriptionType") or {}).get("name")

    by_name = {t["name"]: t for t in (schema.get("types") or []) if t.get("name")}
    report.type_count = sum(1 for n in by_name if not n.startswith("__"))

    def _fields(type_name: str | None) -> list[str]:
        if not type_name or type_name not in by_name:
            return []
        return [f["name"] for f in (by_name[type_name].get("fields") or [])]

    queries = _fields(report.query_type)
    mutations = _fields(report.mutation_type)
    subs = _fields(report.subscription_type)
    report.query_count = len(queries)
    report.mutation_count = len(mutations)
    report.subscription_count = len(subs)
    report.sample_queries = queries[:25]
    report.sample_mutations = mutations[:25]

    report.observations.append(GraphQLObservation(
        category="introspection-exposed",
        severity="medium",
        message="introspection is enabled on this endpoint — consider disabling in production",
    ))
    if report.mutation_count > 0:
        report.observations.append(GraphQLObservation(
            category="mutations-exposed",
            severity="info",
            message=f"{report.mutation_count} mutation(s) exposed; review auth on each",
        ))

    sensitive_hits: list[str] = []
    for name in queries + mutations:
        low = name.lower()
        if any(h in low for h in SENSITIVE_FIELD_HINTS):
            sensitive_hits.append(name)
    if sensitive_hits:
        report.observations.append(GraphQLObservation(
            category="sensitive-named-fields",
            severity="medium",
            message=f"operations with sensitive-looking names: {', '.join(sensitive_hits[:8])}",
        ))

    return report.model_dump()
