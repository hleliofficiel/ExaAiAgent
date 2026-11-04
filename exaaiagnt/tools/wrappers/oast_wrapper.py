"""OAST / interactsh wrapper (Tier-A MIT, invoke-only).

Internal only: payloads/URLs are generated locally and never exfiltrated.
Detection is via a local interactsh-client polling its own session; if the
binary is missing we fail gracefully with ``interactsh_not_installed``.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import uuid
from typing import Any


_TOKEN_RE = re.compile(r"^[a-zA-Z0-9-]{8,128}$")


def new_oast_token() -> str:
    """Generate a local-only OAST token (no network, no external service)."""
    return uuid.uuid4().hex


def build_interactsh_argv(
    token: str | None = None,
    timeout: int = 30,
    oast_domain: str | None = None,
) -> list[str]:
    """Build argv for local interactsh-client. External domains are rejected."""
    tok = token or new_oast_token()
    if not _TOKEN_RE.match(tok):
        raise ValueError("invalid token")
    if oast_domain and oast_domain not in {"127.0.0.1", "localhost"}:
        raise ValueError("oast_domain must be internal; external OAST exfil is forbidden")
    argv = ["interactsh-client", "-n", "1", "-poll", "-json", "-timeout", str(timeout), "-id", tok]
    if oast_domain:
        argv += ["-oast-domain", oast_domain]
    return argv


def parse_interactsh_json(text: str) -> list[dict[str, Any]]:
    """Parse interactsh-client JSON output into records (tolerant, no crash)."""
    import json

    records: list[dict[str, Any]] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            records.append(obj)
        elif isinstance(obj, list):
            records.extend(x for x in obj if isinstance(x, dict))
    return records


def poll_interactsh(
    token: str | None = None, timeout: int = 30, oast_domain: str | None = None
) -> dict[str, Any]:
    """Poll local interactsh-client once. Graceful when binary is absent."""
    if shutil.which("interactsh-client") is None:
        return {
            "success": False,
            "error": "interactsh_not_installed",
            "hint": "install interactsh-client (Tier-A MIT) — see docs/tools.md",
        }
    argv = build_interactsh_argv(token=token, timeout=timeout, oast_domain=oast_domain)
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 30, check=False)  # noqa: S603
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout", "argv": argv}
    except OSError as exc:
        return {"success": False, "error": "interactsh_failed", "detail": str(exc)[:500]}
    interactions = parse_interactsh_json(r.stdout)
    return {
        "success": r.returncode == 0,
        "count": len(interactions),
        "interactions": interactions[:50],
        "stderr_tail": r.stderr[-1000:],
        "argv": argv,
    }
