"""HAR import/export to EvidenceStore (offline, pure).

Import: parse a HAR 1.2 dict/file into normalized entries, optionally
record each entry in EvidenceStore. Export: build a HAR dict from
EvidenceStore records or from a list of normalized entries.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def normalize_har_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    req = entry.get("request") or {}
    resp = entry.get("response") or {}
    url = req.get("url")
    if not url:
        return None
    return {
        "method": req.get("method", "GET"),
        "url": url,
        "headers": {h.get("name", ""): h.get("value", "") for h in req.get("headers", [])},
        "body": req.get("postData", {}).get("text", "")
        if isinstance(req.get("postData"), dict)
        else "",
        "status_code": resp.get("status", 0),
        "response_headers": {
            h.get("name", ""): h.get("value", "") for h in resp.get("headers", [])
        },
        "response_body": resp.get("content", {}).get("text", "")
        if isinstance(resp.get("content"), dict)
        else "",
        "started_at": entry.get("startedDateTime", ""),
        "time_ms": entry.get("time", 0),
    }


def import_har(
    har: dict[str, Any] | str | Path, *, record_evidence: bool = False
) -> list[dict[str, Any]]:
    """Parse HAR (dict, JSON string, or path) -> normalized entries."""
    if isinstance(har, str | Path) and Path(har).exists():
        har = json.loads(Path(har).read_text())
    elif isinstance(har, str):
        har = json.loads(har)
    entries = har.get("log", {}).get("entries", []) if isinstance(har, dict) else []
    out = [e for e in (normalize_har_entry(x) for x in entries) if e]
    if record_evidence and out:
        try:
            from exaaiagnt.grounding import EvidenceStore

            for e in out:
                EvidenceStore.instance().record("har_import", e)
        except Exception:  # nosec B110 - noqa: BLE001, S110 - evidence is best-effort  # best-effort
            pass
    return out


def _har_entry(e: dict[str, Any]) -> dict[str, Any]:
    return {
        "startedDateTime": e.get("started_at", ""),
        "time": e.get("time_ms", 0),
        "request": {
            "method": e.get("method", "GET"),
            "url": e.get("url", ""),
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in (e.get("headers") or {}).items()],
            "queryString": [],
            "postData": {"mimeType": "text/plain", "text": e.get("body", "")},
            "headersSize": -1,
            "bodySize": len(e.get("body", "")),
        },
        "response": {
            "status": e.get("status_code", 0),
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": [
                {"name": k, "value": v} for k, v in (e.get("response_headers") or {}).items()
            ],
            "content": {
                "size": len(e.get("response_body", "")),
                "text": e.get("response_body", ""),
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(e.get("response_body", "")),
        },
        "cache": {},
        "timings": {"send": 0, "wait": 0, "receive": 0},
    }


def export_har(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a HAR 1.2 dict from normalized entries."""
    har_entries = [_har_entry(e) for e in entries]
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "exaaiagnt", "version": "3.1.1"},
            "entries": har_entries,
        }
    }


def export_har_from_store(agent_id: str | None = None) -> dict[str, Any]:
    """Export HAR from EvidenceStore records that look like HTTP entries."""
    from exaaiagnt.grounding import EvidenceStore

    entries = []
    for rec in EvidenceStore.instance().all():
        if agent_id and rec.agent_id != agent_id:
            continue
        excerpt = rec.output_excerpt or ""
        try:
            obj = json.loads(excerpt)
        except ValueError:
            continue
        if isinstance(obj, dict) and obj.get("url"):
            entries.append(
                {
                    "method": obj.get("method", "GET"),
                    "url": obj["url"],
                    "status_code": obj.get("status_code", 0),
                    "response_body": obj.get("response_body", ""),
                }
            )
    return export_har(entries)
