"""Offline tests for exaaiagnt.api (OpenAPI parsing + authz checks)."""

import base64
import json

from exaaiagnt.api.authz import (
    check_bfla,
    check_bola,
    check_cookie_flags,
    check_csrf,
    check_jwt,
    check_mass_assignment,
    check_oauth,
)
from exaaiagnt.api.openapi import extract_endpoints, find_path_params, parse_openapi


SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Demo", "version": "1.0"},
    "paths": {
        "/users/{id}": {
            "get": {
                "operationId": "getUser",
                "parameters": [{"name": "id", "in": "path", "required": True}],
                "security": [{"bearerAuth": []}],
            },
            "delete": {"operationId": "deleteUser"},
        },
        "/health": {"get": {"operationId": "health"}},
    },
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
}


def test_parse_openapi_dict():
    parsed = parse_openapi(SPEC)
    assert parsed["version"] == "3.0.0"
    assert parsed["info"]["title"] == "Demo"


def test_parse_openapi_json_string():
    parsed = parse_openapi(json.dumps(SPEC))
    assert parsed["version"] == "3.0.0"


def test_extract_endpoints():
    endpoints = extract_endpoints(parse_openapi(SPEC))
    methods = {(e["path"], e["method"]) for e in endpoints}
    assert ("/users/{id}", "GET") in methods
    assert ("/users/{id}", "DELETE") in methods
    get_user = next(e for e in endpoints if e["operation_id"] == "getUser")
    assert get_user["auth_required"] is True
    assert get_user["auth_schemes"] == ["bearerAuth"]
    assert get_user["parameters"][0]["name"] == "id"
    delete_user = next(e for e in endpoints if e["operation_id"] == "deleteUser")
    assert delete_user["auth_required"] is False


def test_find_path_params():
    assert find_path_params("/users/{id}/posts/{post_id}") == ["id", "post_id"]


def test_bola_vulnerable():
    own = {"status": 200, "body": {"id": 1, "name": "Alice"}}
    other = {"status": 200, "body": {"id": 1, "name": "Alice"}}
    finding = check_bola(own, other)
    assert finding["status"] == "fail"
    assert finding["severity"] == "high"


def test_bola_safe():
    own = {"status": 200, "body": {"id": 1}}
    other = {"status": 403, "body": {"error": "forbidden"}}
    assert check_bola(own, other)["status"] == "pass"


def test_bfla():
    assert check_bfla({"status": 200})["status"] == "fail"
    assert check_bfla({"status": 403})["status"] == "pass"


def test_mass_assignment():
    baseline = {"status": 200, "body": {"name": "x"}}
    probe = {"status": 200, "body": {"name": "x", "is_admin": True}}
    finding = check_mass_assignment(baseline, probe, ["is_admin"])
    assert finding["status"] == "fail"
    assert finding["honoured"] == ["is_admin"]
    safe = check_mass_assignment(baseline, {"status": 200, "body": {"name": "y"}}, ["is_admin"])
    assert safe["status"] == "pass"


def _make_jwt(header, payload, signature="sig"):
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{seg(header)}.{seg(payload)}.{signature}"


def test_jwt_alg_none():
    token = _make_jwt({"alg": "none"}, {"exp": 9999999999}, signature="")
    checks = {c["check"]: c for c in check_jwt(token)}
    assert checks["jwt_alg_none"]["status"] == "fail"


def test_jwt_valid_shape():
    token = _make_jwt({"alg": "HS256"}, {"exp": 9999999999})
    checks = {c["check"]: c for c in check_jwt(token)}
    assert checks["jwt_alg_none"]["status"] == "pass"
    assert checks["jwt_exp"]["status"] == "pass"
    assert checks["jwt_signature"]["status"] == "pass"


def test_jwt_expired_and_no_exp():
    expired = _make_jwt({"alg": "HS256"}, {"exp": 1})
    assert {c["check"]: c for c in check_jwt(expired)}["jwt_exp"]["status"] == "fail"
    no_exp = _make_jwt({"alg": "HS256"}, {})
    assert {c["check"]: c for c in check_jwt(no_exp)}["jwt_exp"]["status"] == "fail"


def test_jwt_kid_header_flagged():
    token = _make_jwt({"alg": "HS256", "kid": "../../etc"}, {"exp": 9999999999})
    checks = check_jwt(token)
    assert any(c["check"] == "jwt_header_kid" for c in checks)


def test_oauth_checks():
    findings = {
        c["check"]: c
        for c in check_oauth({"redirect_uri": "http://evil.example/cb", "response_type": "code"})
    }
    assert findings["oauth_redirect_uri"]["status"] == "fail"
    assert findings["oauth_state"]["status"] == "fail"
    assert findings["oauth_pkce"]["status"] == "fail"
    good = {
        c["check"]: c
        for c in check_oauth(
            {
                "redirect_uri": "https://app.example/cb",
                "state": "xyz",
                "response_type": "code",
                "code_challenge": "abc",
                "code_challenge_method": "S256",
            }
        )
    }
    assert good["oauth_redirect_uri"]["status"] == "pass"
    assert good["oauth_pkce"]["status"] == "pass"


def test_cookie_flags():
    findings = check_cookie_flags("session=abc; Path=/")
    failed = {c["check"] for c in findings if c["status"] == "fail"}
    assert failed == {"cookie_httponly", "cookie_secure", "cookie_samesite"}
    ok = check_cookie_flags("session=abc; HttpOnly; Secure; SameSite=Lax")
    assert all(c["status"] == "pass" for c in ok)


def test_csrf():
    assert check_csrf({"method": "GET"})["status"] == "info"
    assert check_csrf({"method": "POST"}, {"csrf_token": "x"})["status"] == "pass"
    assert check_csrf({"method": "POST"})["status"] == "fail"
    same_site = check_csrf({"method": "POST", "headers": {"set-cookie": "s=1; SameSite=Lax"}})
    assert same_site["status"] == "pass"
