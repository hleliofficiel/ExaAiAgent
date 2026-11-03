from exaaiagnt.grounding import EvidenceStore
from exaaiagnt.validation import ConfidenceFeatures
from exaaiagnt.verification import verify_finding, LLM_RISK_MAP
def _ev():
    EvidenceStore.instance().clear()
    return EvidenceStore.instance().record("send_request", "HTTP 200 SQL syntax error near ' OR 1=1", args={"url": "https://example.com/?id=1"}).evidence_id
def test_confirmed_needs_everything():
    eid = _ev()
    f = ConfidenceFeatures(evidence_class="data_sample", repeatable_runs=3, total_runs=3, status_delta=True, baseline_similarity=0.2, corroborating_tools=2, kb_match="exact_version", auth_precondition_met=True)
    r = verify_finding("sqli", [eid], "nuclei sqli template + manual boolean diff", f)
    assert r.final_status == "confirmed" and r.confidence_score >= 0.85
def test_no_evidence_is_false_positive():
    f = ConfidenceFeatures(evidence_class="data_sample", repeatable_runs=3, total_runs=3)
    r = verify_finding("sqli", [], "nuclei", f)
    assert r.final_status == "false_positive"
def test_no_independent_check_cannot_confirm():
    eid = _ev()
    f = ConfidenceFeatures(evidence_class="data_sample", repeatable_runs=3, total_runs=3, status_delta=True, baseline_similarity=0.2, corroborating_tools=2, kb_match="exact_version", auth_precondition_met=True)
    r = verify_finding("sqli", [eid], "", f)
    assert r.final_status == "suspected"
def test_llm_risk_map_complete():
    assert set(LLM_RISK_MAP) == {f"LLM{i:02d}" for i in range(1, 11)}
