from __future__ import annotations

import json
import re
import threading
from pathlib import Path

from exaaiagnt.knowledge.schema import CVERecord


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_DATA = Path(__file__).parent / "data" / "cves.jsonl"
_lock = threading.Lock()


class CVEStore:
    _instance: CVEStore | None = None

    def __init__(self, path: Path | None = None):
        self.path = path or _DATA
        self._records: dict[str, CVERecord] = {}
        self._load()

    @classmethod
    def get(cls):
        if cls._instance is None:
            with _lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _load(self):
        if not self.path.exists():
            return
        for raw in self.path.read_text().splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                r = CVERecord(**json.loads(line))
            except (ValueError, TypeError):
                continue
            if CVE_RE.match(r.cve_id):
                self._records[r.cve_id.upper()] = r

    def lookup_cve(self, cve_id: str) -> CVERecord | None:
        if not cve_id or not CVE_RE.match(cve_id.strip().upper()):
            return None
        return self._records.get(cve_id.strip().upper())

    def _version_affected(self, pr, version: str) -> bool:
        def key(v: str):
            return [
                (0, int(tok)) if tok.isdigit() else (1, tok)
                for tok in v.replace("-", ".").split(".")
            ]

        try:
            cur = key(version)
            if pr.version_start and cur < key(pr.version_start):
                return False
            if pr.fixed_in and cur >= key(pr.fixed_in):
                return False
        except (ValueError, TypeError, AttributeError):
            return False
        return not (pr.version_end and cur > key(pr.version_end))

    def match_product(self, product: str, version: str | None = None) -> list[CVERecord]:
        p = (product or "").strip().lower()
        if not p:
            return []
        out = []
        for r in self._records.values():
            for pr in r.products:
                hay = (pr.product or "").lower()
                ven = (pr.vendor or "").lower()
                if p not in hay and p not in ven and hay not in p:
                    continue
                if version is None:
                    out.append(r)
                    break
                if self._version_affected(pr, version):
                    out.append(r)
                    break
        return out

    def check_exposure(
        self, product: str, version: str | None, evidence_id: str | None = None
    ) -> dict:
        recs = self.match_product(product, version)
        if not recs:
            return {
                "affected": False,
                "version_unknown": version is None,
                "cves": [],
                "reason": "no_matching_product_or_version_in_pinned_kb",
            }
        if version is None:
            return {
                "affected": False,
                "version_unknown": True,
                "cves": [r.cve_id for r in recs],
                "reason": "version_unknown: fingerprint required before claiming affected",
                "evidence_id": evidence_id,
            }
        return {
            "affected": True,
            "version_unknown": False,
            "cves": [r.cve_id for r in recs],
            "evidence_id": evidence_id,
            "details": [
                {
                    "cve_id": r.cve_id,
                    "cvss_v3": r.cvss_v3,
                    "cvss_v4": r.cvss_v4,
                    "kev_listed": r.kev_listed,
                    "epss_score": r.epss_score,
                    "references": r.references,
                    "source": r.source,
                    "last_updated": r.last_updated,
                }
                for r in recs
            ],
        }
