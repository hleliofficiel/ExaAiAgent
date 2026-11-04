"""API/Auth + secrets + cloud tool wrappers.

Argv-only design: these tools take plain arguments (strings/dicts),
never shell strings, never touch the network. They wrap the pure
functions in exaaiagnt.api / exaaiagnt.secrets / exaaiagnt.cloud.
"""

from __future__ import annotations

import json
from typing import Any

from exaaiagnt.api.authz import check_bfla, check_bola, check_jwt
from exaaiagnt.api.openapi import extract_endpoints, parse_openapi
from exaaiagnt.cloud.checks import check_dockerfile, check_tls_config
from exaaiagnt.secrets.scanner import scan_text
from exaaiagnt.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def parse_openapi_spec(spec_json: str) -> dict[str, Any]:
    """Parse an OpenAPI/Swagger spec supplied as JSON and list endpoints.

    Args:
        spec_json: OpenAPI 3 / Swagger 2 spec as a JSON string.

    Returns:
        Dict with version, endpoint count, endpoints, and unauthenticated
        endpoints.
    """
    try:
        spec = json.loads(spec_json or "{}")
    except json.JSONDecodeError as exc:
        return {"success": False, "error": f"invalid JSON: {exc}"}
    if not isinstance(spec, dict):
        return {"success": False, "error": "spec must be a JSON object"}
    parsed = parse_openapi(spec)
    endpoints = extract_endpoints(parsed)
    return {
        "success": True,
        "version": parsed["version"],
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
        "unauthenticated": [e for e in endpoints if not e["auth_required"]],
    }


@register_tool(sandbox_execution=False)
def analyze_api_auth(
    own_response_json: str,
    other_response_json: str,
    jwt_token: str = "",
    low_priv_status: int = 0,
) -> dict[str, Any]:
    """Run BOLA/BFLA/JWT checks on supplied response fixtures (no network).

    Args:
        own_response_json: Response dict JSON for account A.
        other_response_json: Response dict JSON for account B.
        jwt_token: Optional JWT to inspect.
        low_priv_status: HTTP status for the low-privilege BFLA probe.

    Returns:
        Dict with BOLA, BFLA, and JWT findings.
    """
    try:
        own = json.loads(own_response_json or "{}")
        other = json.loads(other_response_json or "{}")
    except json.JSONDecodeError as exc:
        return {"success": False, "error": f"invalid JSON: {exc}"}
    result: dict[str, Any] = {
        "success": True,
        "bola": check_bola(own, other),
        "bfla": check_bfla({"status": low_priv_status}),
        "jwt": check_jwt(jwt_token) if jwt_token else [],
    }
    return result


@register_tool(sandbox_execution=False)
def scan_secrets_text(text: str, source: str = "<input>") -> dict[str, Any]:
    """Scan text for hardcoded secrets and return redacted findings.

    Args:
        text: Text content to scan.
        source: Label recorded with each finding.

    Returns:
        Dict with findings (secrets are redacted, never echoed in full).
    """
    findings = scan_text(text or "", source=source)
    return {"success": True, "count": len(findings), "findings": findings}


@register_tool(sandbox_execution=False)
def check_container_config(
    dockerfile_text: str = "",
    tls_config_json: str = "",
) -> dict[str, Any]:
    """Check Dockerfile and TLS config fixtures (no network, no docker).

    Args:
        dockerfile_text: Dockerfile content to audit.
        tls_config_json: TLS config dict as JSON.

    Returns:
        Dict with Dockerfile and TLS findings.
    """
    tls_config: dict[str, Any] = {}
    if tls_config_json:
        try:
            loaded = json.loads(tls_config_json)
            tls_config = loaded if isinstance(loaded, dict) else {}
        except json.JSONDecodeError as exc:
            return {"success": False, "error": f"invalid TLS JSON: {exc}"}
    return {
        "success": True,
        "dockerfile": check_dockerfile(dockerfile_text or ""),
        "tls": check_tls_config(tls_config),
    }
