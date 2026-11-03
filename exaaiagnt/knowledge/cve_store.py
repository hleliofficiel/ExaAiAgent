from __future__ import annotations
import hashlib, json, re, threading
from pathlib import Path
from exaaiagnt.knowledge.schema import CVERecord, KnowledgeManifest

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_DATA = Path(__file__).parent / "data" / "cves.jsonl"
_instance = None
_lock = threading.Lock()

class CVEStore:
    def __init__(self, path: Path | None = None):
        self.path = path or _DATA
        self._records: dict[str, CVERecord] = {}
        self._load()
    @classmethod
    def get(cls):
        global _instance
        if _instance is None:
            with _lock:
                if _instance is None:
                    _instance = cls()
        return _instance
    def _load(self):
        if not self.path.exists(): return
        for line in self.path.read_text().splitlines():
            line=line.strip()
            if not line: continue
            try:
                r = CVERecord(**json.loads(line))
                if CVE_RE.match(r.cve_id): self._records[r.cve_id.upper()] = r
            except Exception: continue
    def lookup_cve(self, cve_id: str) -> CVERecord | None:
        if not cve_id or not CVE_RE.match(cve_id.strip().upper()): return None
        return self._records.get(cve_id.strip().upper())
    def match_product(self, product: str, version: str | None = None) -> list[CVERecord]:
        p = (product or "").lower()
        out=[]
        for r in self._records.values():
            if any(p and p in (pr.product.lower() or pr.vendor.lower()) for pr in r.products):
                out.append(r)
        return out
    def check_exposure(self, product: str, version: str | None, evidence_id: str | None = None) -> dict:
        recs = self.match_product(product, version)
        if not recs:
            return {"affected": False, "version_unknown": version is None, "cves": []}
        return {"affected": True, "version_unknown": version is None, "cves": [r.cve_id for r in recs], "evidence_id": evidence_id}
