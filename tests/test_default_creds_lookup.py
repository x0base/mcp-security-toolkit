from mcp_security_toolkit.tools.default_creds_lookup import default_creds_lookup


def test_exact_key():
    r = default_creds_lookup("router:cisco")
    assert r["matched_keys"] == ["router:cisco"]
    assert any(c["username"] == "cisco" for c in r["credentials"])


def test_substring_match():
    r = default_creds_lookup("tomcat")
    assert "app:tomcat" in r["matched_keys"]
    assert len(r["credentials"]) >= 3


def test_alias_resolves():
    r = default_creds_lookup("fortigate")
    assert r["matched_keys"] == ["firewall:fortinet"]


def test_alias_idrac():
    r = default_creds_lookup("idrac")
    assert "ipmi:dell" in r["matched_keys"]
    assert any(c["username"] == "root" and c["password"] == "calvin" for c in r["credentials"])


def test_unknown_returns_empty():
    r = default_creds_lookup("totally-unknown-product-xyz")
    assert r["credentials"] == []
    assert r["matched_keys"] == []


def test_case_insensitive():
    r1 = default_creds_lookup("Tomcat")
    r2 = default_creds_lookup("TOMCAT")
    assert r1["matched_keys"] == r2["matched_keys"]


def test_empty_query_errors():
    r = default_creds_lookup("")
    assert "error" in r


def test_note_present():
    r = default_creds_lookup("cisco")
    assert "authorized testing" in r["note"].lower()
