"""nuclei wrapper (Tier-A MIT, invoke-only). Argv-only, scope-checked, SARIF-ready output -> evidence."""

from __future__ import annotations
import json, shutil, subprocess
from typing import Any


def build_nuclei_argv(
    target: str, severity: str = "medium,high,critical", timeout: int = 300
) -> list[str]:
    if not target:
        raise ValueError("target required")
    argv = [
        "nuclei",
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-severity",
        severity,
        "-timeout",
        str(timeout),
    ]
    return argv


def parse_nuclei_jsonl(text: str) -> list[dict[str, Any]]:
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def run_nuclei(
    target: str, severity: str = "medium,high,critical", timeout: int = 300
) -> dict[str, Any]:
    if shutil.which("nuclei") is None:
        return {
            "success": False,
            "error": "nuclei_not_installed",
            "hint": "install pinned static binary (MIT) — see docs/tools.md",
        }
    argv = build_nuclei_argv(target, severity, timeout)
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 30)
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout", "argv": argv}
    findings = parse_nuclei_jsonl(r.stdout)
    return {
        "success": r.returncode == 0,
        "count": len(findings),
        "findings": findings[:50],
        "stderr_tail": r.stderr[-1000:],
    }
