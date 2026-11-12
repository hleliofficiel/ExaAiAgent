"""Finding Verification Pipeline.

Hypothesis -> Evidence -> Independent Verification -> Confidence -> Final
Finding. A finding can never be 'confirmed' from language alone: it needs
primary evidence + independent check + confidence >= threshold.

LLM hardening (opt-in via ``rag_docs``/``known_fragments`` or the text itself):
high-severity injection, secret leaks, or cross-tenant RAG evidence
downgrade a would-be ``confirmed`` to ``suspected`` with a reason. Benign
text is unaffected, so existing callers keep their behavior.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from exaaiagnt.grounding.guardrails import validate_claim
from exaaiagnt.validation.confidence import ConfidenceFeatures, score_confidence


# OWASP LLM Top 10:2025 mapping for agent guardrails (principal separation:
# tool/target content is data, never instructions).
LLM_RISK_MAP = {
    "LLM01": "Prompt Injection: tool/target output wrapped as data, never instructions",
    "LLM02": "Sensitive Information Disclosure: secrets never in prompts/logs",
    "LLM03": "Supply Chain: pinned sandbox image, SBOM, third-party notices",
    "LLM04": "Data/Model Poisoning: CVE KB pinned + provenance-stamped",
    "LLM05": "Improper Output Handling: argv allowlist, no shell interpolation",
    "LLM06": "Excessive Agency: scope enforced in code, budgets hard-stop",
    "LLM07": "System Prompt Leakage: no secrets/policy internals in prompts",
    "LLM08": "Vector/Embedding Weaknesses: KB is versioned JSONL with hashes",
    "LLM09": "Misinformation: no CVE/version/CVSS from memory",
    "LLM10": "Unbounded Consumption: global token budget, per-tool timeouts",
}


class VerificationResult(BaseModel):
    hypothesis: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    independent_check: str = ""  # must name a concrete tool/agent check
    confidence_score: float = 0.0
    confidence_band: str = "suspected"
    final_status: str = "suspected"  # confirmed | suspected | false_positive
    reasons: list[str] = Field(default_factory=list)


def verify_finding(
    hypothesis: str,
    evidence_ids: list[str],
    independent_check: str,
    features: ConfidenceFeatures,
    threshold: float = 0.85,
    text: str = "",
    kb_lookup=None,
    rag_docs: list[dict] | None = None,
    request_tenant: str = "",
    known_fragments: list[str] | None = None,
) -> VerificationResult:
    reasons: list[str] = []
    gate = validate_claim(evidence_ids or [], text=text or hypothesis, kb_lookup=kb_lookup)
    if not gate.allow:
        return VerificationResult(
            hypothesis=hypothesis,
            evidence_ids=evidence_ids or [],
            independent_check=independent_check,
            confidence_score=0.0,
            confidence_band="likely_false_positive",
            final_status="false_positive",
            reasons=[f"gate: {gate.reason}"],
        )
    if not independent_check or len(independent_check.strip()) < 3:
        return VerificationResult(
            hypothesis=hypothesis,
            evidence_ids=evidence_ids,
            independent_check=independent_check,
            confidence_score=0.0,
            confidence_band="suspected",
            final_status="suspected",
            reasons=["no independent verification supplied: language alone cannot confirm"],
        )
    score = score_confidence(features)
    final = (
        "confirmed"
        if (score.band == "confirmed" and score.score >= threshold)
        else ("suspected" if score.score >= 0.35 else "false_positive")
    )
    reasons.append(f"confidence {score.score} band={score.band} scorer={score.scorer_version}")
    reasons.extend(score.contributing_factors[:6])
    # LLM hardening: never let injected/leaking text or tainted RAG evidence
    # confirm a finding. Lazy import keeps the pipeline import-light.
    if final == "confirmed":
        try:
            from exaaiagnt.verification.hardening import (
                harden_finding_text,
                harden_rag_evidence,
                should_downgrade,
            )

            hardening: dict = {"text": harden_finding_text(text or hypothesis, known_fragments)}
            if rag_docs:
                hardening["rag"] = harden_rag_evidence(request_tenant, rag_docs)
            downgrade, reason = should_downgrade(
                {
                    "injection": hardening["text"]["injection"],
                    "leak": hardening["text"]["leak"],
                    "rag": hardening.get("rag") or {},
                }
            )
            if downgrade:
                final = "suspected"
                reasons.append(f"hardening downgrade: {reason}")
        except Exception:  # nosec B110 - noqa: BLE001, S110 - hardening is best-effort, never breaks verify  # best-effort
            pass
    return VerificationResult(
        hypothesis=hypothesis,
        evidence_ids=evidence_ids,
        independent_check=independent_check,
        confidence_score=score.score,
        confidence_band=score.band,
        final_status=final,
        reasons=reasons,
    )
