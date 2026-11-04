"""SBOM: dependency parsing and CVE comparison (pure functions, no network).

Parsers accept file content as strings and return a normalized component
list: {"name", "version", "ecosystem", "source"}. CVEStore is a minimal
in-memory store; compare_cves matches components against it.
"""

from __future__ import annotations

import json
import re
from typing import Any


class CVEStore:
    """Minimal in-memory CVE store keyed by package name."""

    def __init__(self, entries: list[dict[str, Any]] | None = None) -> None:
        self._entries: list[dict[str, Any]] = list(entries or [])

    def add(self, cve_id: str, package: str, affected: str, severity: str = "medium") -> None:
        self._entries.append(
            {"id": cve_id, "package": package, "affected": affected, "severity": severity}
        )

    def all(self) -> list[dict[str, Any]]:
        return list(self._entries)

    def for_package(self, package: str) -> list[dict[str, Any]]:
        return [e for e in self._entries if e.get("package") == package]


def _normalize_name(name: str) -> str:
    return (name or "").strip().lower().replace("_", "-")


def parse_requirements(text: str) -> list[dict[str, Any]]:
    """Parse requirements.txt content (name==version, name>=version, bare)."""
    components: list[dict[str, Any]] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "--", "http", "git+", "file:")):
            continue
        line = line.split("#", 1)[0].strip().split(";", 1)[0].strip()
        if not line:
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]+\])?\s*(.*)$", line)
        if not match:
            continue
        name = match.group(1)
        spec = (match.group(3) or "").strip()
        version = ""
        version_match = re.search(r"(==|===|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9_.\-+]+)", spec)
        if version_match:
            version = version_match.group(2)
        elif spec and spec[0] in "=<>~!":
            version = spec.lstrip("=<>~! ")
        components.append(
            {
                "name": _normalize_name(name),
                "version": version,
                "ecosystem": "pypi",
                "source": "requirements.txt",
            }
        )
    return components


def parse_package_json(text: str) -> list[dict[str, Any]]:
    """Parse package.json dependencies/devDependencies."""
    components: list[dict[str, Any]] = []
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return components
    if not isinstance(data, dict):
        return components
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, version in sorted(deps.items()):
            components.append(
                {
                    "name": str(name).lower(),
                    "version": str(version).lstrip("^~>=< "),
                    "ecosystem": "npm",
                    "source": f"package.json:{section}",
                }
            )
    return components


def parse_cargo_lock(text: str) -> list[dict[str, Any]]:
    """Parse Cargo.lock-lite: [[package]] name/version blocks."""
    components: list[dict[str, Any]] = []
    blocks = re.split(r"\[\[package\]\]", text or "")
    for block in blocks:
        name_match = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        version_match = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if not name_match:
            continue
        components.append(
            {
                "name": name_match.group(1).lower(),
                "version": version_match.group(1) if version_match else "",
                "ecosystem": "cargo",
                "source": "Cargo.lock",
            }
        )
    return components


def _version_tuple(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in re.split(r"[.\-+_]", version or ""):
        try:
            parts.append(int(piece))
        except ValueError:
            break
    return tuple(parts) or (0,)


def _affected_match(version: str, affected: str) -> bool:  # noqa: PLR0911
    """Affected spec like '<2.0.0', '>=1.0,<2.0', '==1.2.3', or '*'."""
    spec = (affected or "").strip()
    if spec in ("", "*"):
        return True
    for clause_raw in spec.split(","):
        clause = clause_raw.strip()
        match = re.match(r"(==|>=|<=|>|<|!=)?\s*(.+)", clause)
        if not match:
            continue
        op, target = match.group(1) or "==", match.group(2).strip()
        current, bound = _version_tuple(version), _version_tuple(target)
        if op == "==" and current != bound:
            return False
        if op == "!=" and current == bound:
            return False
        if op == ">=" and current < bound:
            return False
        if op == "<=" and current > bound:
            return False
        if op == ">" and current <= bound:
            return False
        if op == "<" and current >= bound:
            return False
    return True


def compare_cves(components: list[dict[str, Any]], store: CVEStore) -> list[dict[str, Any]]:
    """Match components against the CVE store; returns vulnerability hits."""
    hits: list[dict[str, Any]] = []
    for component in components:
        name = _normalize_name(str(component.get("name", "")))
        version = str(component.get("version", ""))
        hits.extend(
            {
                "cve": str(entry.get("id", "")),
                "package": name,
                "version": version,
                "affected": str(entry.get("affected", "")),
                "severity": str(entry.get("severity", "medium")),
                "ecosystem": str(component.get("ecosystem", "")),
            }
            for entry in store.for_package(name)
            if _affected_match(version, str(entry.get("affected", "*")))
        )
    return hits


def to_cyclonedx_lite(components: list[dict[str, Any]]) -> dict[str, Any]:
    """Produce a minimal CycloneDX-shaped JSON document."""

    def _component(c: dict[str, Any]) -> dict[str, str]:
        ecosystem = str(c.get("ecosystem", "generic"))
        name = str(c.get("name", ""))
        version = str(c.get("version", ""))
        return {
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:{ecosystem}/{name}@{version}",
        }

    return {
        "bom-format": "CycloneDX",
        "spec-version": "1.5",
        "version": 1,
        "components": [_component(c) for c in components],
    }
