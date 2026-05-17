from mcp_security_toolkit.tools.http_diff import http_diff


def _resp(status=200, headers=None, body=""):
    return {"status": status, "headers": headers or [], "body": body}


def test_no_change():
    a = _resp(200, [("Content-Type", "text/html")], "<html>ok</html>")
    r = http_diff(a, a)
    assert r["status"] is None
    assert r["header_changes"] == []
    assert r["body"]["same"] is True


def test_auth_bypass_403_to_200():
    a = _resp(403, body="forbidden")
    b = _resp(200, body="welcome admin")
    r = http_diff(a, b)
    assert r["status"]["severity"] == "high"
    assert "auth-bypass-likely" in r["status"]["note"]


def test_auth_bypass_401_to_200():
    r = http_diff(_resp(401), _resp(200, body="ok"))
    assert r["status"]["severity"] == "high"


def test_idor_404_to_200():
    r = http_diff(_resp(404), _resp(200, body="data"))
    assert r["status"]["severity"] == "medium"
    assert "idor" in r["status"]["note"]


def test_regression_200_to_403_is_low():
    r = http_diff(_resp(200), _resp(403))
    assert r["status"]["severity"] == "low"


def test_security_header_removed_is_high():
    a = _resp(200, [("Content-Security-Policy", "default-src 'self'")])
    b = _resp(200, [])
    r = http_diff(a, b)
    assert any(
        h["name"] == "content-security-policy" and h["severity"] == "high"
        for h in r["header_changes"]
    )


def test_security_header_added_is_low():
    a = _resp(200, [])
    b = _resp(200, [("Strict-Transport-Security", "max-age=31536000")])
    r = http_diff(a, b)
    assert any(
        h["name"] == "strict-transport-security" and h["change"] == "added"
        for h in r["header_changes"]
    )


def test_httponly_removed_is_high():
    a = _resp(200, [("Set-Cookie", "session=abc; HttpOnly; Secure; SameSite=Strict")])
    b = _resp(200, [("Set-Cookie", "session=abc; Secure; SameSite=Strict")])
    r = http_diff(a, b)
    sess = next(c for c in r["cookie_changes"] if c["name"] == "session")
    assert sess["severity"] == "high"
    assert "httponly" in sess["note"].lower()


def test_secure_removed_is_high():
    a = _resp(200, [("Set-Cookie", "id=1; HttpOnly; Secure")])
    b = _resp(200, [("Set-Cookie", "id=1; HttpOnly")])
    r = http_diff(a, b)
    assert any(c["severity"] == "high" for c in r["cookie_changes"])


def test_cookie_added():
    a = _resp(200, [])
    b = _resp(200, [("Set-Cookie", "new=1; HttpOnly")])
    r = http_diff(a, b)
    assert any(c["change"] == "added" and c["name"] == "new" for c in r["cookie_changes"])


def test_cookie_removed():
    a = _resp(200, [("Set-Cookie", "session=abc")])
    b = _resp(200, [])
    r = http_diff(a, b)
    assert any(c["change"] == "removed" for c in r["cookie_changes"])


def test_body_size_and_similarity():
    a = _resp(200, body="hello world")
    b = _resp(200, body="hello universe")
    r = http_diff(a, b)
    assert r["body"]["same"] is False
    assert 0.0 < r["body"]["similarity"] < 1.0
    assert r["body"]["size_before"] == 11
    assert r["body"]["size_after"] == 14


def test_content_type_shift():
    a = _resp(200, [("Content-Type", "text/html")], body="<p>hi</p>")
    b = _resp(200, [("Content-Type", "application/json")], body='{"hi":1}')
    r = http_diff(a, b)
    assert r["body"]["content_type_before"] == "text/html"
    assert r["body"]["content_type_after"] == "application/json"


def test_error_leak_hint_detected():
    a = _resp(200, body="<html>ok</html>")
    b = _resp(500, body='Traceback (most recent call last):\n  File "x.py", line 1\nSyntaxError')
    r = http_diff(a, b)
    assert "python-stack-trace" in r["body"]["leak_hints"]


def test_sql_error_leak_detected():
    a = _resp(200, body="ok")
    b = _resp(500, body="You have an error in your SQL syntax near 'foo'")
    r = http_diff(a, b)
    assert "mysql-error" in r["body"]["leak_hints"]


def test_unified_diff_excerpt_present_for_small_diff():
    a = _resp(200, body="line1\nline2\nline3")
    b = _resp(200, body="line1\nLINE2\nline3")
    r = http_diff(a, b)
    assert r["body"]["unified_diff_excerpt"]


def test_raw_string_input():
    raw_a = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"
    raw_b = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\ndenied"
    r = http_diff(raw_a, raw_b)
    assert r["status"]["before"] == 200
    assert r["status"]["after"] == 403


def test_headers_as_dict():
    a = {"status": 200, "headers": {"Content-Type": "text/html"}, "body": "a"}
    b = {"status": 200, "headers": {"Content-Type": "text/plain"}, "body": "a"}
    r = http_diff(a, b)
    assert any(h["name"] == "content-type" for h in r["header_changes"])


def test_summary_counts():
    a = _resp(403, [("Content-Security-Policy", "default-src 'self'"),
                    ("Set-Cookie", "s=1; HttpOnly; Secure")])
    b = _resp(200, [("Set-Cookie", "s=1; Secure")], body="welcome")
    r = http_diff(a, b)
    assert r["summary"].get("high", 0) >= 2  # auth-bypass + CSP removed + HttpOnly removed


def test_invalid_input():
    r = http_diff(42, _resp())  # type: ignore[arg-type]
    assert "error" in r
