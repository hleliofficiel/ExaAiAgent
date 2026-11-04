"""CVE Intelligence Pipeline: join pinned KB with EPSS + CISA KEV + OSV.

Provenance-stamped. No invented data: unknown stays unknown.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from exaaiagnt.intelligence.feeds import fetch_epss, fetch_kev, fetch_osv


def _now() -> str:
    return datetime.now(UTC).isoformat()


class IntelRecord(BaseModel):
    cve_id: str
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev_listed: bool = False
    kev_date_added: str = ""
    kev_ransomware_use: str = ""
    osv_ids: list[str] = Field(default_factory=list)
    ghsa_ids: list[str] = Field(default_factory=list)
    priority_score: float = 0.0
    sources: dict = Field(default_factory=dict)
    fetched_at: str = Field(default_factory=_now)


def combine_priority_score(
    epss: float | None, percentile: float | None, kev: bool, cvss: float | None
) -> float:
    """KEV overrides (patch-now, like BOD), else EPSS percentile dominates.

    CVSS breaks ties. Scale 0-100, documented + tested.
    """
    if kev:
        return 100.0
    p = (percentile or 0.0) * 100.0 * 0.7 + (epss or 0.0) * 30.0
    if cvss is not None:
        p += max(0.0, min(10.0, cvss)) * 0.5
    return round(max(0.0, min(100.0, p)), 2)


class CVEIntelPipeline:
    """Offline-safe: every network call is best-effort.

    On failure fields stay None/False with sources noting the error.
    Never invents.
    """

    def __init__(self, kev_cache: dict | None = None):
        self._kev: dict | None = kev_cache

    def kev(self) -> dict:
        if self._kev is None:
            self._kev = fetch_kev()
        return self._kev

    def enrich(
        self, cve_ids: list[str], cvss_by_cve: dict[str, float | None] | None = None
    ) -> dict[str, IntelRecord]:
        cvss_by_cve = cvss_by_cve or {}
        ep = fetch_epss(cve_ids)
        kev = self.kev()
        out: dict[str, IntelRecord] = {}
        for cid in [c.strip().upper() for c in (cve_ids or []) if c]:
            e = ep.get(cid, {}) if isinstance(ep.get(cid), dict) else {}
            k = kev.get("cves", {}).get(cid, {}) if isinstance(kev, dict) else {}
            epss = e.get("epss") if isinstance(e, dict) else None
            pct = e.get("percentile") if isinstance(e, dict) else None
            kev_hit = bool(k)
            out[cid] = IntelRecord(
                cve_id=cid,
                epss_score=epss,
                epss_percentile=pct,
                kev_listed=kev_hit,
                kev_date_added=k.get("date_added", ""),
                kev_ransomware_use=k.get("ransomware_use", ""),
                priority_score=combine_priority_score(epss, pct, kev_hit, cvss_by_cve.get(cid)),
                sources={
                    "epss": "FIRST EPSS API"
                    + (f" ({e.get('date', '')})" if isinstance(e, dict) and e.get("date") else ""),
                    "kev": "CISA KEV" + (f" v{kev.get('catalogVersion', '')}" if kev_hit else ""),
                    "kev_error": kev.get("error", "") if isinstance(kev, dict) else "",
                },
            )
        return out

    def osv_for_package(self, package: str, ecosystem: str, version: str) -> list[dict]:
        return fetch_osv(package, ecosystem, version)
