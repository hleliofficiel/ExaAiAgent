"""ZAP daemon wrapper (Tier-B GPL, invoke-only). Argv-only, never shell=True."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import urllib.request
from typing import Any


DEFAULT_ZAP_API_BASE = "http://127.0.0.1:8090"
_INTERNAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _validated_base(base: str | None) -> str:
    candidate = (base or os.environ.get("ZAP_API_BASE") or DEFAULT_ZAP_API_BASE).rstrip("/")
    if not candidate.startswith(("http://", "https://")):
        raise ValueError("zap_api_base must be http(s)")
    host = candidate.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    if host not in _INTERNAL_HOSTS:
        raise ValueError("zap_api_base must be internal (127.0.0.1/localhost)")
    return candidate


def zap_daemon_status(api_base: str | None = None) -> dict[str, Any]:
    """Check whether a local ZAP daemon is reachable (no shell, no install attempt)."""
    try:
        base = _validated_base(api_base)
    except ValueError as exc:
        return {"success": False, "error": "invalid_api_base", "detail": str(exc)}
    if shutil.which("zaproxy") is None and shutil.which("zap.sh") is None:
        return {
            "success": False,
            "error": "zap_not_installed",
            "hint": "install ZAP (Tier-B GPL, invoke-only) — see docs/tools.md",
            "api_base": base,
        }
    try:
        with urllib.request.urlopen(f"{base}/JSON/core/view/version/", timeout=5) as resp:  # noqa: S310
            body = resp.read().decode(errors="replace")[:1000]
    except Exception as exc:  # noqa: BLE001
        return {
            "success": False,
            "error": "zap_not_running",
            "detail": str(exc)[:500],
            "api_base": base,
        }
    else:
        return {"success": True, "running": True, "api_base": base, "body": body}


def build_zap_daemon_argv(
    port: int = 8090, host: str = "127.0.0.1", api_key: str | None = None
) -> list[str]:
    """Build argv to start a *local-only* ZAP daemon. Never binds externally."""
    if host not in _INTERNAL_HOSTS:
        raise ValueError("zap daemon must bind to internal host only")
    if not 1 <= int(port) <= 65535:
        raise ValueError("invalid port")
    argv = [
        "zaproxy",
        "-daemon",
        "-host",
        host,
        "-port",
        str(port),
        "-config",
        "api.addrs.addr.name=.*",
        "-config",
        "api.addrs.addr.regex=true",
        "-config",
        "api.disablekey=true",
    ]
    if api_key:
        argv += ["-config", f"api.key={api_key}"]
    return argv


def start_zap_daemon(
    port: int = 8090, api_key: str | None = None, timeout: int = 30
) -> dict[str, Any]:
    """Start local ZAP daemon if binary present; fail gracefully otherwise."""
    if shutil.which("zaproxy") is None and shutil.which("zap.sh") is None:
        return {
            "success": False,
            "error": "zap_not_installed",
            "hint": "install ZAP (Tier-B GPL, invoke-only) — see docs/tools.md",
        }
    argv = build_zap_daemon_argv(port=port, api_key=api_key)
    try:
        proc = subprocess.Popen(  # noqa: S603
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        return {"success": False, "error": "zap_start_failed", "detail": str(exc)[:500]}
    deadline = time.time() + max(1, timeout)
    while time.time() < deadline:
        if zap_daemon_status(f"http://127.0.0.1:{port}").get("success"):
            return {"success": True, "running": True, "pid": proc.pid, "argv": argv}
        time.sleep(1)
    return {"success": False, "error": "zap_start_timeout", "pid": proc.pid, "argv": argv}
