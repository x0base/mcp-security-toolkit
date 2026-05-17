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

import json
import ssl
import urllib.error
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


def _post(url: str, payload: dict, timeout: float, insecure: bool) -> tuple[int, dict | None, str | None]:
    body = json.dumps({"query": payload["query"]}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    ctx = None
    if insecure and url.startswith("https://"):
        ctx = ssl._create_unverified_context()  # noqa: SLF001
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = resp.read()
            try:
                return resp.status, json.loads(data), None
            except json.JSONDecodeError:
                return resp.status, None, "non-JSON response"
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode("utf-8", errors="replace")
        except Exception:
            body_text = ""
        return e.code, None, f"HTTP {e.code}: {body_text[:200]}"
    except urllib.error.URLError as e:
        return 0, None, f"URL error: {e.reason}"
    except (TimeoutError, OSError) as e:
        return 0, None, f"network error: {e}"


def graphql_introspect(url: str, timeout: float = 10.0, insecure: bool = False) -> dict:
    """Run a GraphQL introspection query against `url` and summarize the schema.

    Single HTTP POST. Read-only. Will not mutate state on the server.

    Args:
        url: Full GraphQL endpoint URL (e.g. `https://api.example.com/graphql`).
        timeout: Network timeout in seconds.
        insecure: Skip TLS verification (for self-signed certs in test envs).

    Returns:
        IntrospectReport summarizing the schema and security observations.
        If introspection is disabled, `introspection_enabled` is False and
        the report contains the server's error message.
    """
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return {"error": "url must be an http(s) URL"}

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
