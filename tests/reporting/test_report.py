from exaaiagnt.reporting import build_report
from exaaiagnt.reporting.report import to_sarif, normalize_severity
def test_build():
    r = build_report("https://example.com", [{"title":"t","content":"c","severity":"HIGH","evidence":["ev_1"]}], run_name="r1")
    assert r["schema"] == "exaai-report-v3"
    assert r["findings"][0]["severity"] == "high"
    assert r["summary"]["by_severity"]["high"] == 1
def test_dedup():
    r = build_report("https://example.com", [{"title":"t","content":"c"},{"title":"t","content":"c"}])
    assert r["summary"]["total"] == 1
def test_sarif():
    r = build_report("https://example.com", [{"title":"t","severity":"critical"}])
    s = to_sarif(r)
    assert s["version"] == "2.1.0" and len(s["runs"][0]["results"]) == 1
def test_norm():
    assert normalize_severity("bogus") == "info"
