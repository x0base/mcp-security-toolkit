import base64
import hmac
import json
import time
from hashlib import sha256

from mcp_security_toolkit.tools.jwt_inspect import jwt_inspect


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_jwt(header: dict, payload: dict, secret: str = "secret") -> str:
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing = f"{h}.{p}"
    sig = hmac.new(secret.encode(), signing.encode(), sha256).digest()
    return f"{signing}.{_b64url(sig)}"


def test_malformed_token():
    r = jwt_inspect("not.a.jwt.extra")
    assert r["valid_structure"] is False
    assert any(f["category"] == "malformed" for f in r["findings"])


def test_alg_none_flagged():
    token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "x"}, secret="")
    r = jwt_inspect(token, check_weak_secrets=False)
    assert any(f["category"] == "alg-none" and f["severity"] == "high" for f in r["findings"])


def test_weak_secret_detected():
    token = _make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "x", "exp": int(time.time()) + 3600, "iat": int(time.time()), "iss": "a", "aud": "b"},
        secret="secret",
    )
    r = jwt_inspect(token)
    assert r["weak_secret"] == "secret"
    assert any(f["category"] == "weak-secret" for f in r["findings"])


def test_missing_exp():
    token = _make_jwt({"alg": "HS256"}, {"sub": "x"}, secret="not-in-dict-xyz-9871")
    r = jwt_inspect(token, check_weak_secrets=False)
    assert any(
        f["category"] == "missing-claim" and "exp" in f["message"] for f in r["findings"]
    )


def test_expired_token():
    token = _make_jwt(
        {"alg": "HS256"}, {"sub": "x", "exp": int(time.time()) - 100}, secret="zzz"
    )
    r = jwt_inspect(token, check_weak_secrets=False)
    assert any(f["category"] == "expired" for f in r["findings"])


def test_weak_secret_check_scope_present():
    r = jwt_inspect("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", check_weak_secrets=False)
    assert "weak_secret_check_scope" in r
    assert "absence" in r["weak_secret_check_scope"].lower()


def test_weak_secret_check_performed_true_for_hs():
    token = _make_jwt(
        {"alg": "HS256"},
        {"sub": "x", "exp": int(time.time()) + 60, "iat": int(time.time()), "iss": "a", "aud": "b"},
        secret="not-in-dict-zzz-9999",
    )
    r = jwt_inspect(token)
    assert r["weak_secret_check_performed"] is True
    assert r["weak_secret"] is None


def test_weak_secret_check_skipped_when_disabled():
    token = _make_jwt({"alg": "HS256"}, {"sub": "x"}, secret="zzz")
    r = jwt_inspect(token, check_weak_secrets=False)
    assert r["weak_secret_check_performed"] is False


def test_suspicious_kid():
    token = _make_jwt(
        {"alg": "HS256", "kid": "../../etc/passwd"},
        {"sub": "x", "exp": int(time.time()) + 60},
        secret="zzz",
    )
    r = jwt_inspect(token, check_weak_secrets=False)
    assert any(f["category"] == "suspicious-kid" for f in r["findings"])


def test_jku_flagged():
    token = _make_jwt(
        {"alg": "RS256", "jku": "https://evil.example/jwks"},
        {"sub": "x", "exp": int(time.time()) + 60},
    )
    r = jwt_inspect(token, check_weak_secrets=False)
    assert any(f["category"] == "external-key-url" for f in r["findings"])
