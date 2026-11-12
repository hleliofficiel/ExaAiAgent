"""nuclei wrapper (Tier-A MIT, invoke-only).

Argv-only, scope-checked, SARIF-ready output -> evidence.
Templates: update via ``nuclei -update-templates`` (pinned release);
record the template version in scan evidence (see docs/tools.md).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from exaaiagnt.tools.proxy_env import merge_env, proxy_env, validate_scope


def build_nuclei_argv(
    target: str,
    severity: str = "medium,high,critical",
    timeout: int = 300,
    proxy_url: str | None = None,
    scope=None,
) -> list[str]:
    if not target:
        raise ValueError("target required")
    verdict = validate_scope(target, scope)
    if not verdict["allow"]:
        raise ValueError(f"scope_denied: {verdict['rule_id']}: {verdict['reason']}")
    _ = proxy_url  # nuclei uses env proxy via -proxy flag below when set
    extra_flags: list[str] = []
    if proxy_url:
        extra_flags = ["-proxy", proxy_url]
    return [
        "nuclei",
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-severity",
        severity,
        "-timeout",
        str(timeout),
        *extra_flags,
    ]


def parse_nuclei_jsonl(text: str) -> list[dict[str, Any]]:
    out = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def run_nuclei(
    target: str,
    severity: str = "medium,high,critical",
    timeout: int = 300,
    proxy_url: str | None = None,
    ca_bundle: str | None = None,
    scope=None,
    record_evidence: bool = False,
) -> dict[str, Any]:
    if shutil.which("nuclei") is None:
        return {
            "success": False,
            "error": "nuclei_not_installed",
            "hint": "install pinned static binary (MIT) — see docs/tools.md",
        }
    argv = build_nuclei_argv(target, severity, timeout, proxy_url=proxy_url, scope=scope)
    try:
        env = merge_env(proxy_env(proxy_url, ca_bundle))
        r = subprocess.run(  # noqa: S603
            argv, capture_output=True, text=True, timeout=timeout + 30, check=False, env=env
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout", "argv": argv}
    findings = parse_nuclei_jsonl(r.stdout)
    if record_evidence:
        try:
            from exaaiagnt.grounding import EvidenceStore

            EvidenceStore.instance().record("nuclei", {"argv": argv, "findings": findings[:50]})
        except Exception:  # nosec B110 - noqa: BLE001, S110 - evidence is best-effort  # best-effort
            pass
    return {
        "success": r.returncode == 0,
        "count": len(findings),
        "findings": findings[:50],
        "stderr_tail": r.stderr[-1000:],
    }
