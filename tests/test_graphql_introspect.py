"""Unit tests for graphql_introspect — uses a stubbed HTTP layer (no network)."""
from unittest.mock import patch

from mcp_security_toolkit.tools import graphql_introspect as mod


def _stub_response(payload):
    return (200, payload, None)


def _schema(queries=None, mutations=None, subs=None, types=None):
    schema = {
        "queryType": {"name": "Query"} if queries is not None else None,
        "mutationType": {"name": "Mutation"} if mutations is not None else None,
        "subscriptionType": {"name": "Subscription"} if subs is not None else None,
        "types": types or [],
    }
    return {"data": {"__schema": schema}}


def test_introspection_disabled():
    with patch.object(mod, "_post", return_value=(200, {"errors": [{"message": "disabled"}]}, None)):
        r = mod.graphql_introspect("https://api.example.com/graphql")
    assert r["introspection_enabled"] is False
    assert "disabled" in r["error"]


def test_introspection_enabled_minimal():
    payload = _schema(queries=[], types=[{"name": "Query", "kind": "OBJECT", "fields": []}])
    with patch.object(mod, "_post", return_value=_stub_response(payload)):
        r = mod.graphql_introspect("https://api.example.com/graphql")
    assert r["introspection_enabled"] is True
    assert any(o["category"] == "introspection-exposed" for o in r["observations"])


def test_mutations_flagged():
    types = [
        {"name": "Query", "kind": "OBJECT", "fields": [{"name": "user"}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "createUser"}, {"name": "deleteUser"}]},
    ]
    payload = _schema(queries=["user"], mutations=["createUser", "deleteUser"], types=types)
    with patch.object(mod, "_post", return_value=_stub_response(payload)):
        r = mod.graphql_introspect("https://api.example.com/graphql")
    assert r["mutation_count"] == 2
    assert any(o["category"] == "mutations-exposed" for o in r["observations"])


def test_sensitive_named_field_flagged():
    types = [
        {"name": "Query", "kind": "OBJECT", "fields": [{"name": "userPassword"}, {"name": "apiKey"}]},
    ]
    payload = _schema(queries=["userPassword", "apiKey"], types=types)
    with patch.object(mod, "_post", return_value=_stub_response(payload)):
        r = mod.graphql_introspect("https://api.example.com/graphql")
    assert any(o["category"] == "sensitive-named-fields" for o in r["observations"])


def test_invalid_url():
    r = mod.graphql_introspect("not-a-url")
    assert "error" in r


def test_network_error_propagates():
    with patch.object(mod, "_post", return_value=(0, None, "URL error: timed out")):
        r = mod.graphql_introspect("https://api.example.com/graphql")
    assert r["introspection_enabled"] is False
    assert "timed out" in r["error"]


def test_sample_lists_truncated():
    queries = [f"q{i}" for i in range(100)]
    types = [{"name": "Query", "kind": "OBJECT", "fields": [{"name": n} for n in queries]}]
    payload = _schema(queries=queries, types=types)
    with patch.object(mod, "_post", return_value=_stub_response(payload)):
        r = mod.graphql_introspect("https://api.example.com/graphql")
    assert r["query_count"] == 100
    assert len(r["sample_queries"]) == 25
