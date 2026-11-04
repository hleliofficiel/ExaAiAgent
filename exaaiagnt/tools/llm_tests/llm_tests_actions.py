# ruff: noqa: TRY300
"""LLM/MCP/RAG test tool actions: manifest audit, injection, RAG provenance.

Thin @register_tool wrappers over exaaiagnt.llm_tests.mcp_rag and
exaaiagnt.verification.hardening. Pure and offline: no network, no LLM calls.
Every failure is a structured dict, not an raise.
"""

from __future__ import annotations

from typing import Any

from exaaiagnt.llm_tests.mcp_rag import (
    audit_mcp_manifest,
    detect_prompt_injection,
    evaluate_rag_corpus,
    manifest_passes,
)
from exaaiagnt.tools.registry import register_tool
from exaaiagnt.verification.hardening import harden_finding_text


@register_tool(sandbox_execution=False)
def audit_mcp_manifest_tool(manifest: dict[str, Any]) -> dict[str, Any]:
    """Audit an MCP server manifest dict for risky declarations (LLM01/03/06/10)."""
    try:
        findings = audit_mcp_manifest(manifest or {})
        return {
            "success": True,
            "passes": manifest_passes(manifest or {}),
            "findings": [
                {
                    "code": f.code,
                    "owasp_id": f.owasp_id,
                    "severity": f.severity,
                    "message": f.message,
                }
                for f in findings
            ],
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"audit_mcp_manifest_tool failed: {e}"}


@register_tool(sandbox_execution=False)
def detect_prompt_injection_tool(text: str) -> dict[str, Any]:
    """Flag text that tries to override instructions (LLM01 heuristic)."""
    try:
        result = detect_prompt_injection(text or "")
        return {
            "success": True,
            "is_injection": result.is_injection,
            "owasp_id": result.owasp_id,
            "markers": result.markers,
            "score": result.score,
            "severity": result.severity,
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"detect_prompt_injection_tool failed: {e}"}


@register_tool(sandbox_execution=False)
def evaluate_rag_corpus_tool(
    request_tenant: str,
    docs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Provenance + cross-tenant + manipulation check over a retrieved RAG corpus."""
    try:
        result = evaluate_rag_corpus(request_tenant, docs or [])
        return {
            "success": True,
            "clean": result["clean"],
            "doc_count": result["doc_count"],
            "findings": [
                {
                    "code": f.code,
                    "owasp_id": f.owasp_id,
                    "severity": f.severity,
                    "message": f.message,
                }
                for f in result["findings"]
            ],
            "cross_tenant_leaks": len(result["cross_tenant_leaks"]),
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"evaluate_rag_corpus_tool failed: {e}"}


@register_tool(sandbox_execution=False)
def harden_finding_text_tool(text: str) -> dict[str, Any]:
    """Injection + system-prompt/secret leak + manipulation check on finding text."""
    try:
        result = harden_finding_text(text or "")
        return {
            "success": True,
            "clean": result["clean"],
            "injection": result["injection"].is_injection,
            "leak": result["leak"].is_leak,
            "manipulation": result["manipulation"].is_suspicious,
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"harden_finding_text_tool failed: {e}"}
