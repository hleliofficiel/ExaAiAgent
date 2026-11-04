from __future__ import annotations

from pydantic import BaseModel, Field


SCORER_VERSION = "conf-v1"


class ConfidenceFeatures(BaseModel):
    evidence_class: str = "none"
    repeatable_runs: int = 0
    total_runs: int = 0
    baseline_similarity: float = 1.0
    status_delta: bool = False
    length_delta_ratio: float = 0.0
    timing_zscore: float | None = None
    corroborating_tools: int = 0
    corroborating_agents: int = 0
    kb_match: str = "none"
    waf_interference: bool = False
    auth_precondition_met: bool = False


class ConfidenceScore(BaseModel):
    score: float = 0.0
    band: str = "suspected"
    contributing_factors: list[str] = Field(default_factory=list)
    scorer_version: str = SCORER_VERSION


def score_confidence(f: ConfidenceFeatures) -> ConfidenceScore:
    factors = []
    s = 0.0
    rep = (f.repeatable_runs / f.total_runs) if f.total_runs else 0.0
    s += 0.25 * rep
    factors.append(f"repeatability={rep:.2f}")
    diff = 0.0
    if f.status_delta:
        diff += 0.5
    if f.length_delta_ratio > 0.1:
        diff += 0.3
    if f.baseline_similarity < 0.7:
        diff += 0.2
    s += 0.20 * min(diff, 1.0)
    factors.append(f"differential={diff:.2f}")
    ev = {
        "error_based": 0.5,
        "boolean_diff": 0.8,
        "time_delay": 0.7,
        "oob_callback": 1.0,
        "data_sample": 1.0,
        "screenshot": 0.6,
    }.get(f.evidence_class, 0.0)
    s += 0.20 * ev
    factors.append(f"evidence_class={f.evidence_class}({ev})")
    corr = min(1.0, (f.corroborating_tools + f.corroborating_agents) / 3)
    s += 0.15 * corr
    factors.append(f"corroboration={corr:.2f}")
    kb = {"exact_version": 1.0, "range": 0.6}.get(f.kb_match, 0.0)
    s += 0.10 * kb
    factors.append(f"kb={f.kb_match}")
    if f.auth_precondition_met:
        s += 0.10
        factors.append("auth_precondition")
    if f.waf_interference:
        s -= 0.15
        factors.append("waf_interference:-0.15")
    s = max(0.0, min(1.0, s))
    band = (
        "confirmed"
        if s >= 0.85
        else "probable"
        if s >= 0.60
        else "suspected"
        if s >= 0.35
        else "likely_false_positive"
    )
    return ConfidenceScore(score=round(s, 4), band=band, contributing_factors=factors)
