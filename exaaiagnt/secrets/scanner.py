"""Secret scanner: pattern detection in text with redaction (pure functions).

Detects AWS keys, private keys, generic credential assignments, and
common token formats. Findings never include the full secret value —
only a redacted preview and metadata (line, entropy hint, severity).
"""

from __future__ import annotations

import math
import re
from typing import Any


_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("aws_access_key_id", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "aws_secret_access_key",
        "high",
        re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"),
    ),
    (
        "private_key",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "generic_password",
        "medium",
        re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"']?([^\s\"'\n]{4,})"),
    ),
    (
        "generic_api_key",
        "medium",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{8,})"
        ),
    ),
    ("github_token", "high", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b")),
    ("slack_token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    (
        "jwt_token",
        "medium",
        re.compile(r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"),
    ),
    ("bearer_token", "medium", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")),
]


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def redact(value: str, keep: int = 4) -> str:
    """Redact a secret, keeping a short prefix for identification."""
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * min(len(value) - keep, 24)}"


def scan_text(text: str, source: str = "<memory>") -> list[dict[str, Any]]:
    """Scan text for secrets; returns redacted findings."""
    findings: list[dict[str, Any]] = []
    if not text:
        return findings
    lines = text.splitlines()
    for name, severity, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            secret = match.group(1) if match.groups() else match.group(0)
            # For Bearer, whole match is the value
            line_no = text[: match.start()].count("\n") + 1
            line_preview = lines[line_no - 1].strip()[:120] if line_no <= len(lines) else ""
            findings.append(
                {
                    "type": name,
                    "severity": severity,
                    "source": source,
                    "line": line_no,
                    "redacted": redact(secret),
                    "entropy": round(_entropy(secret), 2),
                    "line_preview_redacted": redact(line_preview, keep=0) if line_preview else "",
                }
            )
    # Sort by line then type, dedupe identical (type, line, redacted)
    seen: set[tuple[str, int, str]] = set()
    unique: list[dict[str, Any]] = []
    for finding in sorted(findings, key=lambda f: (f["line"], f["type"])):
        key = (str(finding["type"]), int(finding["line"]), str(finding["redacted"]))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def scan_files(files: dict[str, str]) -> list[dict[str, Any]]:
    """Scan {path: content} mapping; findings include the path."""
    all_findings: list[dict[str, Any]] = []
    for path, content in files.items():
        all_findings.extend(scan_text(content, source=path))
    return all_findings


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Count findings by severity and type."""
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for finding in findings:
        by_severity[str(finding.get("severity", "?"))] = (
            by_severity.get(str(finding.get("severity", "?")), 0) + 1
        )
        by_type[str(finding.get("type", "?"))] = by_type.get(str(finding.get("type", "?")), 0) + 1
    return {"total": len(findings), "by_severity": by_severity, "by_type": by_type}
