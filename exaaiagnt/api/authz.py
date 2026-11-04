"""Authorization / authentication checks (pure functions, no network).

All helpers take response dicts shaped like::

    {"status": 200, "headers": {...}, "body": {...} | "...", "json": {...}}

and return findings as dicts: {"check", "status", "severity", "detail"}.
Status values: "pass" | "fail" | "info" | "inconclusive".
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any


def _finding(check: str, status: str, severity: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {"check": check, "status": status, "severity": severity, "detail": detail, **extra}


def _body_text(response: dict[str, Any]) -> str:
    body = response.get("body", response.get("json", ""))
    if isinstance(body, str):
        return body
    try:
        return json.dumps(body, sort_keys=True)
    except (TypeError, ValueError):
        return str(body)


def _status(response: dict[str, Any]) -> int:
    try:
        return int(response.get("status", 0))
    except (TypeError, ValueError):
        return 0


def _headers(response: dict[str, Any]) -> dict[str, str]:
    headers = response.get("headers", {})
    if not isinstance(headers, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def compare_two_account_responses(
    own_response: dict[str, Any], other_response: dict[str, Any]
) -> dict[str, Any]:
    """BOLA/IDOR signal: does account B see account A's resource?"""
    own_body, other_body = _body_text(own_response), _body_text(other_response)
    own_status, other_status = _status(own_response), _status(other_response)
    vulnerable = other_status in (200, 201) and other_body and other_body == own_body
    # Partial overlap: other body contains own body content
    if not vulnerable and other_status == 200 and own_body and own_body in other_body:
        vulnerable = True
    return _finding(
        "bola_two_account",
        "fail" if vulnerable else "pass",
        "high" if vulnerable else "info",
        "Account B received account A resource data (possible IDOR/BOLA)."
        if vulnerable
        else "Account B did not receive account A resource data.",
        own_status=own_status,
        other_status=other_status,
    )


def check_bola(own_response: dict[str, Any], other_response: dict[str, Any]) -> dict[str, Any]:
    """Alias with explicit name for test/tool clarity."""
    result = compare_two_account_responses(own_response, other_response)
    result["check"] = "bola"
    return result


def check_bfla(
    low_priv_response: dict[str, Any],
    high_priv_response: dict[str, Any] | None = None,  # noqa: ARG001
) -> dict[str, Any]:
    """BFLA: low-privilege role can perform privileged action (2xx)."""
    status = _status(low_priv_response)
    allowed = status in (200, 201, 204)
    detail = (
        f"Low-privilege role succeeded with status {status} on privileged action."
        if allowed
        else f"Low-privilege role was denied with status {status}."
    )
    return _finding(
        "bfla",
        "fail" if allowed else "pass",
        "high" if allowed else "info",
        detail,
        low_priv_status=status,
    )


def check_mass_assignment(
    baseline_response: dict[str, Any],
    probe_response: dict[str, Any],
    injected_fields: list[str],
) -> dict[str, Any]:
    """Mass-assignment: injected privileged fields were honoured."""
    probe_body = _body_text(probe_response)
    baseline_body = _body_text(baseline_response)
    honoured = [f for f in injected_fields if f and f in probe_body and f not in baseline_body]
    if _status(probe_response) not in (200, 201, 204):
        return _finding(
            "mass_assignment",
            "inconclusive",
            "info",
            f"Probe request returned status {_status(probe_response)}; cannot assess.",
            honoured=honoured,
        )
    vulnerable = bool(honoured)
    return _finding(
        "mass_assignment",
        "fail" if vulnerable else "pass",
        "high" if vulnerable else "info",
        f"Injected fields honoured in response: {', '.join(honoured)}."
        if vulnerable
        else "Injected fields were not reflected in response.",
        honoured=honoured,
    )


def _b64url_decode(segment: str) -> dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode())
        loaded = json.loads(decoded)
        return loaded if isinstance(loaded, dict) else {}
    except (ValueError, TypeError, UnicodeDecodeError):
        return {}


def check_jwt(token: str, now: int | None = None) -> list[dict[str, Any]]:
    """JWT hygiene: alg none, kid/jku/x5u, exp, signature presence."""
    findings: list[dict[str, Any]] = []
    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        findings.append(_finding("jwt_structure", "fail", "medium", "Token is not a 3-part JWT."))
        return findings
    header = _b64url_decode(parts[0])
    payload = _b64url_decode(parts[1])
    signature = parts[2]
    alg = str(header.get("alg", ""))
    if alg.lower() == "none":
        findings.append(
            _finding(
                "jwt_alg_none", "fail", "critical", "JWT uses alg=none (unsigned token accepted)."
            )
        )
    else:
        findings.append(_finding("jwt_alg_none", "pass", "info", f"JWT alg={alg or 'missing'}."))
    findings.extend(
        _finding(
            f"jwt_header_{field}",
            "info",
            "medium",
            f"JWT header contains {field} (review for injection).",
        )
        for field in ("kid", "jku", "x5u")
        if header.get(field)
    )
    if not signature:
        findings.append(_finding("jwt_signature", "fail", "high", "JWT has no signature."))
    else:
        findings.append(_finding("jwt_signature", "pass", "info", "JWT signature segment present."))
    exp = payload.get("exp")
    if exp is None:
        findings.append(_finding("jwt_exp", "fail", "medium", "JWT has no exp claim."))
    else:
        try:
            exp_int = int(exp)  # type: ignore[arg-type]
            current = now if now is not None else int(time.time())
            if exp_int < current:
                findings.append(_finding("jwt_exp", "fail", "medium", "JWT is expired."))
            else:
                findings.append(_finding("jwt_exp", "pass", "info", "JWT exp is in the future."))
        except (TypeError, ValueError):
            findings.append(_finding("jwt_exp", "inconclusive", "info", "JWT exp is not numeric."))
    return findings


def check_oauth(flow: dict[str, Any]) -> list[dict[str, Any]]:
    """OAuth/OIDC flow checks from a dict of flow parameters."""
    findings: list[dict[str, Any]] = []
    redirect = str(flow.get("redirect_uri", ""))
    if not redirect:
        findings.append(
            _finding("oauth_redirect_uri", "inconclusive", "info", "No redirect_uri supplied.")
        )
    elif (
        redirect.startswith("http://")
        and "localhost" not in redirect
        and "127.0.0.1" not in redirect
    ):
        findings.append(
            _finding("oauth_redirect_uri", "fail", "high", "redirect_uri uses plain http.")
        )
    elif "*" in redirect or redirect.endswith("/"):
        findings.append(
            _finding(
                "oauth_redirect_uri",
                "fail",
                "medium",
                "redirect_uri is wildcard/overly permissive.",
            )
        )
    else:
        findings.append(
            _finding(
                "oauth_redirect_uri", "pass", "info", "redirect_uri is specific and uses https."
            )
        )
    if not flow.get("state"):
        findings.append(
            _finding("oauth_state", "fail", "medium", "OAuth flow has no state parameter.")
        )
    else:
        findings.append(_finding("oauth_state", "pass", "info", "OAuth state present."))
    if flow.get("response_type") in ("code",) or flow.get("flow") == "code":
        if not flow.get("nonce"):
            findings.append(
                _finding(
                    "oauth_nonce",
                    "info",
                    "low",
                    "OIDC code flow without nonce (check id_token use).",
                )
            )
        if not flow.get("code_challenge"):
            findings.append(
                _finding("oauth_pkce", "fail", "medium", "Code flow without PKCE code_challenge.")
            )
        else:
            method = str(flow.get("code_challenge_method", ""))
            if method and method.lower() != "s256":
                findings.append(
                    _finding(
                        "oauth_pkce", "fail", "medium", f"PKCE method is {method}, expected S256."
                    )
                )
            else:
                findings.append(_finding("oauth_pkce", "pass", "info", "PKCE S256 present."))
    return findings


def check_cookie_flags(set_cookie: str | list[str]) -> list[dict[str, Any]]:
    """Check Set-Cookie flags: HttpOnly, Secure, SameSite."""
    cookies = [set_cookie] if isinstance(set_cookie, str) else list(set_cookie or [])
    findings: list[dict[str, Any]] = []
    for cookie in cookies:
        lower = cookie.lower()
        name = cookie.split("=", 1)[0].strip() if "=" in cookie else cookie[:32]
        for flag, check in (
            ("httponly", "cookie_httponly"),
            ("secure", "cookie_secure"),
            ("samesite=", "cookie_samesite"),
        ):
            if flag not in lower:
                findings.append(
                    _finding(
                        check, "fail", "medium", f"Cookie '{name}' missing {flag.rstrip('=')}."
                    )
                )
            else:
                findings.append(
                    _finding(check, "pass", "info", f"Cookie '{name}' has {flag.rstrip('=')}.")
                )
    return findings


def check_csrf(response: dict[str, Any], form: dict[str, Any] | None = None) -> dict[str, Any]:
    """CSRF: state-changing endpoint without anti-CSRF token/SameSite."""
    headers = _headers(response)
    set_cookie = headers.get("set-cookie", "")
    has_samesite = "samesite" in set_cookie.lower()
    form = form or {}
    token_fields = [k for k in form if "csrf" in k.lower() or "token" in k.lower()]
    has_token = bool(token_fields)
    method = str(response.get("method", form.get("method", "GET"))).upper()
    if method in ("GET", "HEAD", "OPTIONS"):
        return _finding("csrf", "info", "info", "Safe method; CSRF not applicable.")
    if has_token:
        return _finding("csrf", "pass", "info", f"CSRF token field present: {token_fields[0]}.")
    if has_samesite:
        return _finding(
            "csrf", "pass", "info", "SameSite cookie flag provides partial CSRF defence."
        )
    return _finding(
        "csrf", "fail", "high", "State-changing request without CSRF token or SameSite cookie."
    )
