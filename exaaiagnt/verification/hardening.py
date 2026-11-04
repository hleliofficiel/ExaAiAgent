"""Verification hardening helpers (additive; existing pipeline untouched).

These give callers a cheap, dependency-free way to strengthen a
``VerificationResult`` decision with LLM-era checks from
:mod:`exaaiagnt.llm_tests.mcp_rag`: an LLM-authored hypothesis must not
carry injected instructions, must not leak system-prompt/secret material
into the finding text, and retrieved RAG evidence must be provenance- and
tenant-clean. All functions are pure.
"""

from __future__ import annotations

from exaaiagnt.llm_tests.mcp_rag import (
    check_cross_tenant_leak,
    check_rag_document,
    detect_prompt_injection,
    detect_system_prompt_leak,
    semantic_manipulation_heuristics,
)


def harden_finding_text(text: str, known_fragments: list[str] | None = None) -> dict:
    """Run injection + leak + manipulation checks over finding text."""
    injection = detect_prompt_injection(text or "")
    leak = detect_system_prompt_leak(text or "", known_fragments=known_fragments)
    manipulation = semantic_manipulation_heuristics(text or "")
    return {
        "injection": injection,
        "leak": leak,
        "manipulation": manipulation,
        "clean": not (injection.is_injection or leak.is_leak or manipulation.is_suspicious),
    }


def harden_rag_evidence(request_tenant: str, docs: list[dict]) -> dict:
    """Provenance + cross-tenant check over RAG docs backing a finding."""
    per_doc = [check_rag_document(d) for d in (docs or [])]
    leaks = check_cross_tenant_leak(request_tenant, docs or [])
    findings = [f for sub in per_doc for f in sub] + leaks
    return {
        "findings": findings,
        "cross_tenant_leaks": leaks,
        "clean": not findings,
    }


def should_downgrade(hardening: dict) -> tuple[bool, str]:
    """Decide whether hardening output blocks ``confirmed`` status.

    Returns ``(downgrade, reason)``. High-severity injection, any secret
    leak, or a cross-tenant leak downgrades; low-signal heuristics do not.
    """
    injection = hardening.get("injection")
    leak = hardening.get("leak")
    rag = hardening.get("rag") or {}
    if leak is not None and leak.is_leak and leak.severity == "high":
        return True, "secret material in finding text (LLM02)"
    if injection is not None and injection.is_injection and injection.severity == "high":
        return True, f"high-severity prompt injection in finding text: {injection.markers}"
    if rag.get("cross_tenant_leaks"):
        return True, "RAG evidence contains cross-tenant documents (LLM08)"
    return False, ""
