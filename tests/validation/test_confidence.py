from exaaiagnt.validation import ConfidenceFeatures, score_confidence, dedup_key, max_band_for


def test_score_confirmed():
    f = ConfidenceFeatures(
        evidence_class="data_sample",
        repeatable_runs=3,
        total_runs=3,
        status_delta=True,
        baseline_similarity=0.2,
        corroborating_tools=2,
        kb_match="exact_version",
        auth_precondition_met=True,
    )
    s = score_confidence(f)
    assert s.band == "confirmed" and s.score >= 0.85


def test_score_low():
    s = score_confidence(ConfidenceFeatures())
    assert s.band == "likely_false_positive"


def test_fp_rules():
    assert dedup_key("sqli", "u", "p", "c") == dedup_key("sqli", "u", "p", "c")
    assert max_band_for("xss", has_execution_context=False) == "suspected"
