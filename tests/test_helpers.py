"""Tests for the defensive helpers library."""
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_security_toolkit.helpers import (
    BlockedAddress,
    PathOutsideRoot,
    UnsafeExpression,
    UnsafeFilename,
    UnsafeIdentifier,
    UnsafeURL,
    evaluate_expression,
    safe_filename,
    safe_path,
    safe_sql_identifier,
    safe_url,
)
from mcp_security_toolkit.helpers import urls as urls_mod

# ── safe_path ──────────────────────────────────────────────────────────────

def test_safe_path_accepts_relative_inside_root(tmp_path: Path):
    f = tmp_path / "ok.log"
    f.write_text("hi")
    p = safe_path("ok.log", root=tmp_path, must_exist=True)
    assert p == f.resolve()


def test_safe_path_accepts_absolute_inside_root(tmp_path: Path):
    f = tmp_path / "ok.log"
    f.write_text("hi")
    p = safe_path(str(f), root=tmp_path)
    assert p == f.resolve()


def test_safe_path_rejects_traversal(tmp_path: Path):
    with pytest.raises(PathOutsideRoot):
        safe_path("../etc/passwd", root=tmp_path)


def test_safe_path_rejects_absolute_outside(tmp_path: Path):
    with pytest.raises(PathOutsideRoot):
        safe_path("/etc/passwd", root=tmp_path)


def test_safe_path_must_exist_flag(tmp_path: Path):
    with pytest.raises(PathOutsideRoot):
        safe_path("ghost.log", root=tmp_path, must_exist=True)


def test_safe_path_bad_root_raises(tmp_path: Path):
    with pytest.raises(PathOutsideRoot):
        safe_path("x", root=tmp_path / "does-not-exist")


def test_safe_path_symlink_escape_blocked(tmp_path: Path):
    target = tmp_path.parent / "outside.log"
    target.write_text("secret")
    try:
        link = tmp_path / "link.log"
        link.symlink_to(target)
        with pytest.raises(PathOutsideRoot):
            safe_path("link.log", root=tmp_path)
    finally:
        target.unlink(missing_ok=True)


# ── safe_url ───────────────────────────────────────────────────────────────

def test_safe_url_accepts_public(monkeypatch):
    with patch.object(urls_mod, "_resolve_host", return_value=[urls_mod.ipaddress.ip_address("1.1.1.1")]):
        assert safe_url("https://example.com/api") == "https://example.com/api"


def test_safe_url_rejects_private():
    with patch.object(urls_mod, "_resolve_host", return_value=[urls_mod.ipaddress.ip_address("10.0.0.1")]), \
         pytest.raises(BlockedAddress):
        safe_url("https://internal.local/api")


def test_safe_url_rejects_loopback():
    with patch.object(urls_mod, "_resolve_host", return_value=[urls_mod.ipaddress.ip_address("127.0.0.1")]), \
         pytest.raises(BlockedAddress):
        safe_url("https://localhost/api")


def test_safe_url_rejects_metadata():
    with patch.object(urls_mod, "_resolve_host", return_value=[urls_mod.ipaddress.ip_address("169.254.169.254")]), \
         pytest.raises(BlockedAddress):
        safe_url("https://aws-metadata/")


def test_safe_url_allow_private_opt_in():
    # No need to mock resolution when allow_private bypasses the check.
    assert safe_url("https://internal/api", allow_private=True) == "https://internal/api"


def test_safe_url_rejects_bad_scheme():
    with pytest.raises(UnsafeURL):
        safe_url("file:///etc/passwd")


def test_safe_url_rejects_missing_host():
    with pytest.raises(UnsafeURL):
        safe_url("https:///nope")


def test_safe_url_rejects_unresolvable():
    with patch.object(urls_mod, "_resolve_host", return_value=[]), pytest.raises(BlockedAddress):
        safe_url("https://nope.invalid/")


def test_safe_url_rejects_empty():
    with pytest.raises(UnsafeURL):
        safe_url("")


# ── safe_sql_identifier ────────────────────────────────────────────────────

def test_sql_identifier_accepts_valid():
    assert safe_sql_identifier("users") == "users"
    assert safe_sql_identifier("user_events_2025") == "user_events_2025"
    assert safe_sql_identifier("_internal") == "_internal"


def test_sql_identifier_rejects_quote():
    with pytest.raises(UnsafeIdentifier):
        safe_sql_identifier("users'; DROP TABLE users--")


def test_sql_identifier_rejects_space():
    with pytest.raises(UnsafeIdentifier):
        safe_sql_identifier("user table")


def test_sql_identifier_rejects_leading_digit():
    with pytest.raises(UnsafeIdentifier):
        safe_sql_identifier("2024_table")


def test_sql_identifier_rejects_too_long():
    with pytest.raises(UnsafeIdentifier):
        safe_sql_identifier("x" * 65)


def test_sql_identifier_allow_list_enforced():
    with pytest.raises(UnsafeIdentifier):
        safe_sql_identifier("admin_secrets", allow={"users", "orders"})


def test_sql_identifier_allow_list_accepts_member():
    assert safe_sql_identifier("users", allow={"users", "orders"}) == "users"


def test_sql_identifier_non_string():
    with pytest.raises(UnsafeIdentifier):
        safe_sql_identifier(123)  # type: ignore[arg-type]


# ── safe_filename ──────────────────────────────────────────────────────────

def test_safe_filename_accepts_basename():
    assert safe_filename("report.pdf") == "report.pdf"
    assert safe_filename("user-data_2026.json") == "user-data_2026.json"


def test_safe_filename_rejects_forward_slash():
    with pytest.raises(UnsafeFilename):
        safe_filename("dir/file.txt")


def test_safe_filename_rejects_backslash():
    with pytest.raises(UnsafeFilename):
        safe_filename("dir\\file.txt")


def test_safe_filename_rejects_traversal_token():
    with pytest.raises(UnsafeFilename):
        safe_filename("..")


def test_safe_filename_rejects_traversal_in_path():
    with pytest.raises(UnsafeFilename):
        safe_filename("../etc/passwd")


def test_safe_filename_rejects_absolute_path():
    with pytest.raises(UnsafeFilename):
        safe_filename("/etc/passwd")


def test_safe_filename_rejects_windows_path():
    with pytest.raises(UnsafeFilename):
        safe_filename("C:\\Windows\\System32\\drivers\\etc\\hosts")


def test_safe_filename_rejects_null_byte():
    with pytest.raises(UnsafeFilename):
        safe_filename("ok.txt\x00.evil")


def test_safe_filename_rejects_newline():
    with pytest.raises(UnsafeFilename):
        safe_filename("ok\n.txt")


def test_safe_filename_rejects_empty():
    with pytest.raises(UnsafeFilename):
        safe_filename("")


def test_safe_filename_rejects_windows_reserved():
    for n in ["CON", "PRN", "AUX", "NUL", "COM1", "LPT9", "con.txt", "PRN.dat"]:
        with pytest.raises(UnsafeFilename):
            safe_filename(n)


def test_safe_filename_rejects_non_string():
    with pytest.raises(UnsafeFilename):
        safe_filename(None)  # type: ignore[arg-type]


# ── evaluate_expression ────────────────────────────────────────────────────

def test_eval_arithmetic():
    assert evaluate_expression("2 + 2") == 4
    assert evaluate_expression("(1 + 2) * 3 - 4 / 2") == 7.0
    assert evaluate_expression("10 % 3") == 1
    assert evaluate_expression("10 // 3") == 3


def test_eval_with_variables():
    assert evaluate_expression("x * 2 + y", variables={"x": 5, "y": 1}) == 11
    assert evaluate_expression(
        "price * (1 - discount)", variables={"price": 100, "discount": 0.1}
    ) == 90.0


def test_eval_unknown_variable_rejected():
    with pytest.raises(UnsafeExpression):
        evaluate_expression("x + 1")


def test_eval_booleans_and_comparisons():
    assert evaluate_expression("3 > 2 and 4 < 5") is True
    assert evaluate_expression("not (1 == 2)") is True
    assert evaluate_expression("1 < 2 < 3") is True  # chained comparison


def test_eval_ternary():
    assert evaluate_expression("a if a > b else b", variables={"a": 5, "b": 3}) == 5
    assert evaluate_expression("a if a > b else b", variables={"a": 1, "b": 9}) == 9


def test_eval_safe_calls():
    assert evaluate_expression("abs(-7)") == 7
    assert evaluate_expression("min(3, 1, 2)") == 1
    assert evaluate_expression("max(3, 1, 2)") == 3
    assert evaluate_expression("round(3.14159, 2)") == 3.14


def test_eval_rejects_unsafe_call():
    with pytest.raises(UnsafeExpression):
        evaluate_expression("__import__('os').system('id')")


def test_eval_rejects_open_call():
    with pytest.raises(UnsafeExpression):
        evaluate_expression("open('/etc/passwd').read()")


def test_eval_rejects_attribute_access():
    with pytest.raises(UnsafeExpression):
        evaluate_expression("(1).__class__")


def test_eval_rejects_subscript():
    with pytest.raises(UnsafeExpression):
        evaluate_expression("[1,2,3][0]")


def test_eval_rejects_lambda():
    with pytest.raises(UnsafeExpression):
        evaluate_expression("(lambda: 1)()")


def test_eval_rejects_comprehension():
    with pytest.raises(UnsafeExpression):
        evaluate_expression("[i for i in range(10)]")


def test_eval_rejects_walrus():
    with pytest.raises(UnsafeExpression):
        evaluate_expression("(x := 1)")


def test_eval_caps_huge_exponent():
    with pytest.raises(UnsafeExpression):
        evaluate_expression("9 ** 99999999")


def test_eval_rejects_oversized_input():
    with pytest.raises(UnsafeExpression):
        evaluate_expression("1+" * 1000 + "0", max_length=100)


def test_eval_rejects_syntax_error():
    with pytest.raises(UnsafeExpression):
        evaluate_expression("2 +")


def test_eval_rejects_non_string():
    with pytest.raises(UnsafeExpression):
        evaluate_expression(42)  # type: ignore[arg-type]
