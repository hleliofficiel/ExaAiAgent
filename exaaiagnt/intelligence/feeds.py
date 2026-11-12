# ruff: noqa: S310 - fixed https feed URLs only, best-effort with timeout
"""CVE Intelligence feeds: FIRST EPSS, CISA KEV, OSV.dev.

All free, no API keys (GitHub token optional for GHSA).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _get_json(url: str, timeout: int = 15) -> dict:
    req = urllib.request.Request(
        url, headers={"User-Agent": "ExaAiAgent/3.0.1", "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - fixed https feed URLs (EPSS/KEV), no user input
        return json.loads(r.read().decode("utf-8", "replace"))


def fetch_epss(cve_ids: list[str], timeout: int = 15) -> dict[str, dict]:
    """Return {CVE: {epss, percentile, date}} for the given CVEs.

    Batched, <= 50 per call by EPSS docs practice.
    """
    out: dict[str, dict] = {}
    cves = [c.strip().upper() for c in (cve_ids or []) if c and c.strip()]
    for i in range(0, len(cves), 50):
        batch = cves[i : i + 50]
        q = urllib.parse.urlencode({"cve": ",".join(batch)})
        try:
            data = _get_json(f"{EPSS_URL}?{q}", timeout=timeout)
            for row in data.get("data", []):
                out[row.get("cve", "").upper()] = {
                    "epss": float(row.get("epss", 0) or 0),
                    "percentile": float(row.get("percentile", 0) or 0),
                    "date": row.get("date", ""),
                }
        except Exception as e:  # noqa: BLE001 - best-effort feed, error recorded in result
            out[f"_error_batch_{i}"] = {"error": str(e)}
    return out


def fetch_kev(timeout: int = 15) -> dict:
    """Return count, cves dict, catalogVersion and dateReleased."""
    try:
        data = _get_json(KEV_URL, timeout=timeout)
    except Exception as e:  # noqa: BLE001 - best-effort feed
        return {"count": 0, "cves": {}, "error": str(e)}
    cves: dict[str, dict] = {}
    for v in data.get("vulnerabilities", []):
        cid = (v.get("cveID") or "").upper()
        if cid:
            cves[cid] = {
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "date_added": v.get("dateAdded", ""),
                "ransomware_use": v.get("ransomwareUse", ""),
                "notes": v.get("notes", ""),
            }
    return {
        "count": int(data.get("count", len(cves))),
        "cves": cves,
        "catalogVersion": data.get("catalogVersion", ""),
        "dateReleased": data.get("dateReleased", ""),
    }


def fetch_osv(package: str, ecosystem: str, version: str, timeout: int = 15) -> list[dict]:
    """Query OSV.dev for a package/version. Returns vuln dicts."""
    if not package or not ecosystem or not version:
        return []
    body = json.dumps(
        {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    ).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=body,
        headers={"User-Agent": "ExaAiAgent/3.0.1", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - fixed https endpoint (api.osv.dev), no user-controlled scheme
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - best-effort feed
        return []
    return data.get("vulns", []) or []


def fetch_ghsa(ghsa_id: str, token: str | None = None, timeout: int = 15) -> dict:
    """GitHub Advisory by GHSA id (optional token raises rate limits)."""
    url = f"https://api.github.com/advisories/{ghsa_id}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ExaAiAgent/3.0.1",
            "Accept": "application/vnd.github+json",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - fixed https endpoint (api.github.com), no user-controlled scheme
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001 - best-effort feed
        return {"error": str(e)}
