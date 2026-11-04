"""OpenAPI 3 / Swagger 2 parsing (pure functions, no network).

Parses a spec supplied as a dict, JSON string, or YAML-lite string (no
PyYAML dependency) and extracts endpoints, methods, parameters, and
auth requirements. YAML-lite handles the subset commonly used in specs:
nested maps by indentation, lists, scalars, and inline flow maps.
"""

from __future__ import annotations

import json
import re
from typing import Any


_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}


def _coerce_scalar(raw: str) -> Any:  # noqa: PLR0911
    value = raw.strip()
    if value in ("", "~", "null"):
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    if value in ("[]", "{}"):
        return [] if value == "[]" else {}
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def _load_spec(spec: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(spec, dict):
        return spec
    if not isinstance(spec, str):
        raise TypeError("spec must be dict or string")
    text = spec.strip()
    if not text:
        raise ValueError("empty spec")
    if text.startswith("{"):
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON spec: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ValueError("spec must be a JSON object")
        return loaded
    # Try stdlib-free YAML-lite; if PyYAML happens to be available use it.
    try:
        import yaml  # type: ignore[import-not-found]

        loaded_yaml = yaml.safe_load(text)
        if isinstance(loaded_yaml, dict):
            return loaded_yaml
    except ImportError:
        pass
    return _parse_yaml_lite_list_aware(text)


def _parse_yaml_lite_list_aware(text: str) -> dict[str, Any]:  # noqa: PLR0912
    root: dict[str, Any] = {}
    # Stack entries: (indent, container). Container may be dict or list.
    stack: list[tuple[int, Any]] = [(-1, root)]
    pending_key: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1] if stack else root
        if stripped.startswith("- "):
            if isinstance(parent, dict):
                # Parent should have been a list; convert in place.
                if pending_key is not None and parent.get(pending_key) == {}:
                    parent[pending_key] = []
                    stack[-1] = (stack[-1][0], parent[pending_key])
                    parent = parent[pending_key]
                else:
                    continue
            item = stripped[2:].strip()
            if ":" in item and not item.startswith(("{", "[", '"', "'")):
                key, _, rest = item.partition(":")
                entry: dict[str, Any] = {}
                entry[key.strip().strip("\"'")] = _coerce_scalar(rest) if rest.strip() else {}
                parent.append(entry)
                stack.append((indent, entry))
                if not rest.strip():
                    pending_key = key.strip()
            else:
                parent.append(_coerce_scalar(item))
            continue
        if ":" not in stripped:
            continue
        key, _, rest = stripped.partition(":")
        key = key.strip().strip("\"'")
        rest = rest.strip()
        if isinstance(parent, list):
            if not parent:
                parent.append({})
            parent = parent[-1]
        if not isinstance(parent, dict):
            continue
        pending_key = key
        if rest == "":
            parent[key] = {}
            stack.append((indent, parent[key]))
        else:
            parent[key] = _coerce_scalar(rest)
    return root


def parse_openapi(spec: dict[str, Any] | str) -> dict[str, Any]:
    """Parse an OpenAPI 3 / Swagger 2 spec into a normalized dict.

    Returns {"openapi"|"swagger": version, "info": {...}, "paths": {...},
    "components"/"definitions": {...}, "security": [...]}.
    """
    data = _load_spec(spec)
    version = str(data.get("openapi") or data.get("swagger") or "")
    return {
        "version": version,
        "info": data.get("info", {}) if isinstance(data.get("info", {}), dict) else {},
        "paths": data.get("paths", {}) if isinstance(data.get("paths", {}), dict) else {},
        "components": data.get("components", {})
        if isinstance(data.get("components", {}), dict)
        else {},
        "definitions": data.get("definitions", {})
        if isinstance(data.get("definitions", {}), dict)
        else {},
        "security": data.get("security", []) if isinstance(data.get("security", []), list) else [],
        "servers": data.get("servers", []) if isinstance(data.get("servers", []), list) else [],
        "raw": data,
    }


def extract_endpoints(parsed: dict[str, Any]) -> list[dict[str, Any]]:  # noqa: PLR0912
    """Extract endpoints with methods, parameters, and auth requirements."""
    paths = parsed.get("paths", {})
    global_security = parsed.get("security", [])
    endpoints: list[dict[str, Any]] = []
    if not isinstance(paths, dict):
        return endpoints
    for path, item in sorted(paths.items()):
        if not isinstance(item, dict):
            continue
        path_params = (
            item.get("parameters", []) if isinstance(item.get("parameters", []), list) else []
        )
        for method, operation in sorted(item.items()):
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            params = list(path_params)
            op_params = operation.get("parameters", [])
            if isinstance(op_params, list):
                params.extend(op_params)
            normalized_params = []
            for param in params:
                if not isinstance(param, dict):
                    continue
                normalized_params.append(
                    {
                        "name": str(param.get("name", "")),
                        "in": str(param.get("in", "")),
                        "required": bool(param.get("required", False)),
                        "schema": param.get("schema", {}),
                        "type": param.get("type", ""),
                    }
                )
            security = operation.get("security", global_security)
            auth_required = bool(security)
            auth_schemes: list[str] = []
            if isinstance(security, list):
                for entry in security:
                    if isinstance(entry, dict):
                        auth_schemes.extend(sorted(entry.keys()))
            body_schema = {}
            request_body = operation.get("requestBody", {})
            if isinstance(request_body, dict):
                content = request_body.get("content", {})
                if isinstance(content, dict):
                    for media in content.values():
                        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                            body_schema = media["schema"]
                            break
            if not body_schema and isinstance(operation.get("parameters"), list):
                for param in operation["parameters"]:
                    if isinstance(param, dict) and param.get("in") in ("body", "formData"):
                        body_schema = param.get("schema", {}) or {}
            endpoints.append(
                {
                    "path": str(path),
                    "method": method.upper(),
                    "operation_id": str(operation.get("operationId", "")),
                    "summary": str(operation.get("summary", "")),
                    "parameters": normalized_params,
                    "auth_required": auth_required,
                    "auth_schemes": auth_schemes,
                    "security": security,
                    "body_schema": body_schema,
                    "tags": operation.get("tags", []),
                }
            )
    return endpoints


def endpoints_without_auth(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """Endpoints that declare no auth (potential exposure)."""
    return [e for e in extract_endpoints(parsed) if not e["auth_required"]]


def find_path_params(path: str) -> list[str]:
    """Extract {param} names from a path template."""
    return re.findall(r"\{([^}]+)\}", path or "")
