from __future__ import annotations

import re

from exaaiagnt.grounding.evidence_store import EvidenceStore


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


class GateResult:
    def __init__(self, *, allow: bool, reason: str = ""):
        self.allow = allow
        self.reason = reason

    def __bool__(self):
        return self.allow


def validate_claim(
    evidence_ids: list[str], text: str = "", kb_lookup=None, *, vuln_type: str = ""
) -> GateResult:
    _ = vuln_type  # reserved for future vuln-specific grounding; unused for now
    if not evidence_ids:
        return GateResult(allow=False, reason="evidence_ids required: no citation, no claim")
    store = EvidenceStore.instance()
    recs = [store.get(e) for e in evidence_ids]
    if any(r is None for r in recs):
        return GateResult(allow=False, reason="unknown evidence_id")
    if not any(r.source_class == "primary" for r in recs):
        return GateResult(
            allow=False,
            reason=(
                "secondary evidence (web_search/think/notes) cannot confirm "
                "a finding; need primary tool evidence"
            ),
        )
    for m in CVE_RE.findall(text or ""):
        if kb_lookup is not None and kb_lookup(m) is None:
            return GateResult(allow=False, reason=f"unverified_cve: {m} not in pinned KB")
    return GateResult(allow=True, reason="grounded")


def extract_cves(text: str) -> list[str]:
    return CVE_RE.findall(text or "")
