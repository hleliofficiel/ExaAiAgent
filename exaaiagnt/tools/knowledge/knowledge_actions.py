from typing import Any
from exaaiagnt.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def cve_lookup(cve_id: str) -> dict[str, Any]:
    from exaaiagnt.knowledge import CVEStore

    r = CVEStore.get().lookup_cve(cve_id or "")
    return {"success": True, "found": r is not None, "record": r.model_dump() if r else None}


@register_tool(sandbox_execution=False)
def cve_match(product: str, version: str | None = None) -> dict[str, Any]:
    from exaaiagnt.knowledge import CVEStore

    recs = CVEStore.get().match_product(product or "", version)
    return {"success": True, "count": len(recs), "cves": [r.cve_id for r in recs]}


@register_tool(sandbox_execution=False)
def cve_exposure_check(
    product: str, version: str | None = None, evidence_id: str | None = None
) -> dict[str, Any]:
    from exaaiagnt.knowledge import CVEStore

    return {"success": True, **CVEStore.get().check_exposure(product or "", version, evidence_id)}
