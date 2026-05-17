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


def test_blocks_private_ip_by_default():
    with patch.object(mod, "_is_private_address", return_value=(True, "10.0.0.1")):
        r = mod.graphql_introspect("https://internal.local/graphql")
    assert r["error"] == "blocked-private-address"
    assert r["resolved_ip"] == "10.0.0.1"


def test_allow_private_opt_in():
    with patch.object(mod, "_is_private_address", return_value=(True, "10.0.0.1")), \
         patch.object(mod, "_post", return_value=_stub_response(_schema(queries=[], types=[]))):
        r = mod.graphql_introspect("https://internal.local/graphql", allow_private=True)
    assert "error" not in r or r.get("error") is None
    assert r["introspection_enabled"] is True


def test_timeout_is_clamped():
    with patch.object(mod, "_is_private_address", return_value=(False, "1.2.3.4")), \
         patch.object(mod, "_post", return_value=_stub_response(_schema(queries=[], types=[]))) as p:
        mod.graphql_introspect("https://api.example.com/graphql", timeout=600.0)
    # second positional arg to _post is payload; timeout is third
    args, kwargs = p.call_args
    timeout = args[2] if len(args) > 2 else kwargs.get("timeout")
    assert timeout <= 60.0


def test_missing_hostname():
    r = mod.graphql_introspect("https:///graphql")
    assert "error" in r


def test_response_body_cap():
    # Simulate _post returning the cap-exceeded sentinel; ensure it surfaces cleanly.
    with patch.object(mod, "_is_private_address", return_value=(False, "1.2.3.4")), \
         patch.object(mod, "_post", return_value=(200, None, "response-too-large (>5242880 bytes)")):
        r = mod.graphql_introspect("https://api.example.com/graphql")
    assert r["introspection_enabled"] is False
    assert "response-too-large" in r["error"]


def test_no_redirect_handler_raises_on_3xx():
    # _NoRedirectHandler should turn any 3xx into an HTTPError; verify the
    # handler exists and its methods refuse the redirect.
    import urllib.error
    import urllib.request

    handler = mod._NoRedirectHandler()
    req = urllib.request.Request("https://example.com/q")
    try:
        handler.http_error_302(req, None, 302, "Found", {})
    except urllib.error.HTTPError as e:
        assert "redirects disabled" in str(e).lower()
    else:
        raise AssertionError("expected HTTPError")


def test_sample_lists_truncated():
    queries = [f"q{i}" for i in range(100)]
    types = [{"name": "Query", "kind": "OBJECT", "fields": [{"name": n} for n in queries]}]
    payload = _schema(queries=queries, types=types)
    with patch.object(mod, "_post", return_value=_stub_response(payload)):
        r = mod.graphql_introspect("https://api.example.com/graphql")
    assert r["query_count"] == 100
    assert len(r["sample_queries"]) == 25
