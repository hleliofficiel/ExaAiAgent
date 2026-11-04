"""Cloud/container/K8s config + tool-output parsers (pure functions).

Parsers normalize Prowler, ScoutSuite, kube-bench, Trivy, and Grype
outputs into a common finding shape:
{"source", "id", "severity", "status", "resource", "detail"}.
Config checks cover Dockerfile, docker-compose, and TLS settings.
"""

from __future__ import annotations

import json
import re
import ssl
from datetime import UTC, datetime
from typing import Any


def _finding(
    source: str, fid: str, severity: str, status: str, resource: str, detail: str
) -> dict[str, Any]:
    return {
        "source": source,
        "id": fid,
        "severity": severity,
        "status": status,
        "resource": resource,
        "detail": detail,
    }


def _load_json(data: dict[str, Any] | list[Any] | str) -> Any:
    if isinstance(data, dict | list):
        return data
    try:
        return json.loads(data or "")
    except json.JSONDecodeError:
        return {}


def parse_prowler(data: dict[str, Any] | list[Any] | str) -> list[dict[str, Any]]:
    """Prowler JSON output: list of checks with Status PASS/FAIL."""
    loaded = _load_json(data)
    items = (
        loaded
        if isinstance(loaded, list)
        else loaded.get("findings", [])
        if isinstance(loaded, dict)
        else []
    )
    findings = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", item.get("Status", ""))).upper()
        severity = str(item.get("severity", item.get("Severity", "medium"))).lower()
        findings.append(
            _finding(
                "prowler",
                str(item.get("check_id", item.get("CheckID", item.get("id", "")))),
                severity,
                "pass" if status == "PASS" else "fail" if status == "FAIL" else status.lower(),
                str(item.get("resource", item.get("resource_id", ""))),
                str(item.get("message", item.get("description", "")))[:300],
            )
        )
    return findings


def parse_scout_suite(data: dict[str, Any] | list[Any] | str) -> list[dict[str, Any]]:
    """ScoutSuite JSON: {"services": {svc: {"findings": {id: {level, desc}}}}."""
    loaded = _load_json(data)
    findings = []
    if not isinstance(loaded, dict):
        return findings
    services = loaded.get("services", loaded)
    if not isinstance(services, dict):
        return findings
    for service, service_data in services.items():
        if not isinstance(service_data, dict):
            continue
        checks = service_data.get("findings", {})
        if not isinstance(checks, dict):
            continue
        for check_id, check in checks.items():
            if not isinstance(check, dict):
                continue
            flagged = check.get("flagged_items", check.get("flagged", 0))
            level = str(check.get("level", "warning")).lower()
            severity = {"danger": "high", "warning": "medium"}.get(level, level)
            findings.append(
                _finding(
                    "scoutsuite",
                    str(check_id),
                    severity,
                    "fail" if flagged else "pass",
                    str(service),
                    str(check.get("description", check.get("desc", "")))[:300],
                )
            )
    return findings


def parse_kube_bench(data: dict[str, Any] | list[Any] | str) -> list[dict[str, Any]]:
    """kube-bench JSON: {"Controls": [{"id", "text", "tests": [{"status"}]}]}."""
    loaded = _load_json(data)
    findings = []
    controls = loaded.get("Controls", []) if isinstance(loaded, dict) else []
    for control in controls if isinstance(controls, list) else []:
        if not isinstance(control, dict):
            continue
        tests = control.get("tests", []) if isinstance(control.get("tests", []), list) else []
        worst = "pass"
        for test in tests:
            status = str(test.get("status", "")).upper() if isinstance(test, dict) else ""
            if status == "FAIL":
                worst = "fail"
                break
            if status == "WARN":
                worst = "warn"
        findings.append(
            _finding(
                "kube-bench",
                str(control.get("id", "")),
                "medium",
                worst,
                "node",
                str(control.get("text", ""))[:300],
            )
        )
    return findings


def parse_trivy(data: dict[str, Any] | list[Any] | str) -> list[dict[str, Any]]:
    """Trivy JSON: {"Results": [{"Vulnerabilities": [{VulnerabilityID, Severity}]}]}."""
    loaded = _load_json(data)
    findings = []
    results = (
        loaded.get("Results", [])
        if isinstance(loaded, dict)
        else loaded
        if isinstance(loaded, list)
        else []
    )
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target", ""))
        vulns = result.get("Vulnerabilities", []) or []
        for vuln in vulns if isinstance(vulns, list) else []:
            if not isinstance(vuln, dict):
                continue
            findings.append(
                _finding(
                    "trivy",
                    str(vuln.get("VulnerabilityID", "")),
                    str(vuln.get("Severity", "unknown")).lower(),
                    "fail",
                    target,
                    f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}: "
                    f"{str(vuln.get('Title', ''))[:200]}",
                )
            )
    return findings


def parse_grype(data: dict[str, Any] | list[Any] | str) -> list[dict[str, Any]]:
    """Grype JSON: {"matches": [{"vulnerability": {"id", "severity"}, "artifact": {"name"}}]}."""
    loaded = _load_json(data)
    findings = []
    matches = loaded.get("matches", []) if isinstance(loaded, dict) else []
    for match in matches if isinstance(matches, list) else []:
        if not isinstance(match, dict):
            continue
        vuln = (
            match.get("vulnerability", {})
            if isinstance(match.get("vulnerability", {}), dict)
            else {}
        )
        artifact = match.get("artifact", {}) if isinstance(match.get("artifact", {}), dict) else {}
        findings.append(
            _finding(
                "grype",
                str(vuln.get("id", "")),
                str(vuln.get("severity", "unknown")).lower(),
                "fail",
                str(artifact.get("name", "")),
                f"{artifact.get('version', '')}: {str(vuln.get('description', ''))[:200]}",
            )
        )
    return findings


def check_dockerfile(text: str) -> list[dict[str, Any]]:
    """Dockerfile checks: exposed ports, secrets, root user, latest tag."""
    findings: list[dict[str, Any]] = []
    lines = (text or "").splitlines()
    has_user = False
    for idx, raw in enumerate(lines, 1):
        line = raw.strip()
        upper = line.upper()
        if upper.startswith("EXPOSE"):
            ports = line.split()[1:]
            findings.append(
                _finding(
                    "dockerfile",
                    "exposed_ports",
                    "info",
                    "info",
                    f"line {idx}",
                    f"Exposes ports: {', '.join(ports)}",
                )
            )
            findings.extend(
                _finding(
                    "dockerfile",
                    "sensitive_port",
                    "medium",
                    "fail",
                    f"line {idx}",
                    f"Sensitive port exposed: {port}",
                )
                for port in ports
                if port in ("22", "2375", "2376", "3306", "5432", "6379", "27017")
            )
        if (re.search(r"(?i)(password|secret|api[_-]?key|token)\s*=", line) and "ARG" in upper) or (
            upper.startswith("ENV") and re.search(r"(?i)(password|secret|token)", line)
        ):
            findings.append(
                _finding(
                    "dockerfile",
                    "secret_in_image",
                    "high",
                    "fail",
                    f"line {idx}",
                    "Possible secret baked into image (ENV/ARG).",
                )
            )
        if upper.startswith("USER"):
            has_user = True
        if upper.startswith("FROM"):
            image = line.split()[-1] if line.split() else ""
            if image.endswith(":latest") or ":" not in image.split("/")[-1]:
                findings.append(
                    _finding(
                        "dockerfile",
                        "unpinned_image",
                        "low",
                        "warn",
                        f"line {idx}",
                        f"Base image not pinned: {image}",
                    )
                )
    if not has_user:
        findings.append(
            _finding(
                "dockerfile",
                "runs_as_root",
                "medium",
                "warn",
                "image",
                "No USER instruction; container may run as root.",
            )
        )
    return findings


def check_compose_ports(text: str) -> list[dict[str, Any]]:
    """docker-compose port exposure: host-bound sensitive ports."""
    findings: list[dict[str, Any]] = []
    for idx, raw in enumerate((text or "").splitlines(), 1):
        match = re.search(r'["\']?\s*(\d+):(\d+)', raw)
        if match and "ports:" not in raw.lower():
            host_port, container_port = match.groups()
            if container_port in ("22", "2375", "2376", "3306", "5432", "6379", "27017"):
                findings.append(
                    _finding(
                        "compose",
                        "sensitive_port",
                        "medium",
                        "fail",
                        f"line {idx}",
                        f"Sensitive port published: {host_port}:{container_port}",
                    )
                )
    return findings


def check_tls_config(config: dict[str, Any]) -> list[dict[str, Any]]:
    """TLS config checks: min version, protocols, cert expiry."""
    findings: list[dict[str, Any]] = []
    min_version = str(config.get("min_version", config.get("minVersion", ""))).upper()
    weak = {"TLSV1", "TLSV1.1", "SSL2", "SSL3", "SSLV2", "SSLV3"}
    if min_version in weak:
        findings.append(
            _finding(
                "tls",
                "weak_min_version",
                "high",
                "fail",
                "tls",
                f"Minimum TLS version too weak: {min_version}",
            )
        )
    elif min_version in ("TLSV1.2", "TLSV1.3"):
        findings.append(
            _finding(
                "tls", "min_version", "info", "pass", "tls", f"Minimum TLS version: {min_version}"
            )
        )
    else:
        findings.append(
            _finding(
                "tls", "min_version", "low", "warn", "tls", "Minimum TLS version not specified."
            )
        )
    protocols = config.get("protocols", [])
    if isinstance(protocols, list):
        findings.extend(
            _finding(
                "tls",
                "weak_protocol",
                "high",
                "fail",
                "tls",
                f"Weak protocol enabled: {protocol}",
            )
            for protocol in protocols
            if str(protocol).upper() in weak
        )
    expires = config.get("cert_expires", config.get("certExpiry", ""))
    if expires:
        try:
            expiry = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            days = (expiry - datetime.now(UTC)).days
            if days < 0:
                findings.append(
                    _finding(
                        "tls",
                        "cert_expired",
                        "critical",
                        "fail",
                        "tls",
                        f"Certificate expired {abs(days)} days ago.",
                    )
                )
            elif days < 30:
                findings.append(
                    _finding(
                        "tls",
                        "cert_expiring",
                        "medium",
                        "warn",
                        "tls",
                        f"Certificate expires in {days} days.",
                    )
                )
            else:
                findings.append(
                    _finding(
                        "tls",
                        "cert_expiry",
                        "info",
                        "pass",
                        "tls",
                        f"Certificate valid for {days} more days.",
                    )
                )
        except ValueError:
            findings.append(
                _finding(
                    "tls",
                    "cert_expiry",
                    "info",
                    "inconclusive",
                    "tls",
                    "Could not parse cert expiry date.",
                )
            )
    _ = ssl.TLSVersion  # keep ssl import meaningful for future handshake checks
    return findings
