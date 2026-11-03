"""Finding Verification Pipeline: Hypothesis -> Evidence -> Independent Verification -> Confidence -> Final Finding.
A finding can never be 'confirmed' from language alone: it needs primary evidence + independent check + confidence >= threshold."""
from __future__ import annotations
from pydantic import BaseModel, Field
from exaaiagnt.grounding.guardrails import validate_claim
from exaaiagnt.validation.confidence import ConfidenceFeatures, score_confidence

# OWASP LLM Top 10:2025 mapping for agent guardrails (principal separation: tool/target content is data, never instructions)
LLM_RISK_MAP = {
    "LLM01": "Prompt Injection — tool/target output wrapped as data, never instructions; injection markers flagged",
    "LLM02": "Sensitive Information Disclosure — secrets never in prompts/logs; reports redact tokens",
    "LLM03": "Supply Chain — pinned sandbox image, SBOM, third-party notices",
    "LLM04": "Data/Model Poisoning — CVE KB pinned + provenance-stamped, target content never ingested into KB",
    "LLM05": "Improper Output Handling — argv allowlist, no shell interpolation, schema-validated tool calls",
    "LLM06": "Excessive Agency — scope enforced in code, destructive actions need explicit flag, budgets hard-stop",
    "LLM07": "System Prompt Leakage — no secrets/policy internals in prompts; authz in deterministic code",
    "LLM08": "Vector/Embedding Weaknesses — KB is versioned JSONL with hashes, tenant-isolated per run",
    "LLM09": "Misinformation — no CVE/version/CVSS from memory; KB lookup or 'unknown'",
    "LLM10": "Unbounded Consumption — global token budget, per-tool timeouts, circuit breaker on repeated failures",
}

class VerificationResult(BaseModel):
    hypothesis: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    independent_check: str = ""   # must name a concrete tool/agent check, not 'the model said so'
    confidence_score: float = 0.0
    confidence_band: str = "suspected"
    final_status: str = "suspected"  # confirmed | suspected | false_positive
    reasons: list[str] = Field(default_factory=list)

def verify_finding(hypothesis: str, evidence_ids: list[str], independent_check: str, features: ConfidenceFeatures, threshold: float = 0.85, text: str = "", kb_lookup=None) -> VerificationResult:
    reasons: list[str] = []
    gate = validate_claim(evidence_ids or [], text=text or hypothesis, kb_lookup=kb_lookup)
    if not gate.allow:
        return VerificationResult(hypothesis=hypothesis, evidence_ids=evidence_ids or [], independent_check=independent_check, confidence_score=0.0, confidence_band="likely_false_positive", final_status="false_positive", reasons=[f"gate: {gate.reason}"])
    if not independent_check or len(independent_check.strip()) < 3:
        return VerificationResult(hypothesis=hypothesis, evidence_ids=evidence_ids, independent_check=independent_check, confidence_score=0.0, confidence_band="suspected", final_status="suspected", reasons=["no independent verification supplied — language alone cannot confirm"])
    score = score_confidence(features)
    final = "confirmed" if (score.band == "confirmed" and score.score >= threshold) else ("suspected" if score.score >= 0.35 else "false_positive")
    reasons.append(f"confidence {score.score} band={score.band} scorer={score.scorer_version}")
    reasons.extend(score.contributing_factors[:6])
    return VerificationResult(hypothesis=hypothesis, evidence_ids=evidence_ids, independent_check=independent_check, confidence_score=score.score, confidence_band=score.band, final_status=final, reasons=reasons)
