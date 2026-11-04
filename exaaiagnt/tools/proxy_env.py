"""Proxy env / CA helpers shared by HTTP wrappers and the proxy path.

Pure functions: build env dicts and argv fragments from explicit arguments
or EXAAI_PROXY* env vars. No network I/O.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse


def get_proxy_url() -> str | None:
    """Configured proxy URL (EXAAI_PROXY_URL or HTTPS_PROXY/HTTP_PROXY)."""
    for key in ("EXAAI_PROXY_URL", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        val = os.getenv(key, "").strip()
        if val:
            return val
    return None


def get_ca_bundle() -> str | None:
    for key in ("EXAAI_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"):
        val = os.getenv(key, "").strip()
        if val:
            return val
    return None


def proxy_env(proxy_url: str | None = None, ca_bundle: str | None = None) -> dict[str, str]:
    """Env dict wiring proxy + CA for subprocess tools (httpx, ffuf, ...)."""
    proxy = proxy_url or get_proxy_url()
    ca = ca_bundle or get_ca_bundle()
    env: dict[str, str] = {}
    if proxy:
        env.update(
            {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy}
        )
    if ca:
        env.update({"SSL_CERT_FILE": ca, "REQUESTS_CA_BUNDLE": ca, "EXAAI_CA_BUNDLE": ca})
    return env


def merge_env(base: dict[str, str] | None = None, **extra: str) -> dict[str, str]:
    env = dict(os.environ)
    if base:
        env.update(base)
    env.update({k: v for k, v in extra.items() if v})
    return env


def proxy_argv_flags(proxy_url: str | None = None) -> list[str]:
    """Extra argv for tools that accept ``-proxy <url>`` (httpx/katana/ffuf)."""
    proxy = proxy_url or get_proxy_url()
    return ["-proxy", proxy] if proxy else []


def validate_scope(url: str | None, scope=None) -> dict:
    """Scope allow/deny check with ScopeDecision evidence. No scope = allow."""
    if scope is None or not url:
        return {"allow": True, "rule_id": "no_scope", "reason": "no scope configured", "host": None}
    d = scope.check_url(url) if "://" in url else scope.check_host(url)
    return {"allow": d.allow, "rule_id": d.rule_id, "reason": d.reason, "host": d.host}


def parse_proxy_host(proxy_url: str | None) -> str | None:
    if not proxy_url:
        return None
    try:
        return urlparse(proxy_url).hostname
    except ValueError:
        return None
