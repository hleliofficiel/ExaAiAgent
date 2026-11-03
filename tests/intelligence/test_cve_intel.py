from exaaiagnt.intelligence import combine_priority_score, CVEIntelPipeline
def test_priority_kev_overrides():
    assert combine_priority_score(0.0, 0.0, True, 5.0) == 100.0
def test_priority_formula():
    s = combine_priority_score(0.5, 0.9, False, 10.0)
    assert abs(s - (0.9*100*0.7 + 0.5*30 + 10*0.5)) < 1e-9
def test_priority_clamps():
    assert 0 <= combine_priority_score(2.0, 2.0, False, 99.0) <= 100
    assert combine_priority_score(None, None, False, None) == 0.0
def test_pipeline_offline_safe(monkeypatch):
    import exaaiagnt.intelligence.cve_intel as m
    monkeypatch.setattr(m, "fetch_epss", lambda ids: {i: {"epss": 0.1, "percentile": 0.5, "date": "2026-11-03"} for i in ids})
    monkeypatch.setattr(m, "fetch_kev", lambda: {"count": 1, "cves": {"CVE-2024-3094": {"date_added": "2024-04-01", "ransomware_use": "Known", "vendor": "t", "product": "xz", "name": "n", "notes": ""}}, "catalogVersion": "2026.11.03"})
    p = CVEIntelPipeline()
    out = p.enrich(["CVE-2024-3094", "CVE-2099-99999"], {"CVE-2024-3094": 10.0})
    assert out["CVE-2024-3094"].kev_listed is True and out["CVE-2024-3094"].priority_score == 100.0
    assert out["CVE-2099-99999"].epss_score == 0.1 and out["CVE-2099-99999"].kev_listed is False
def test_pipeline_no_invention_on_network_failure(monkeypatch):
    import exaaiagnt.intelligence.cve_intel as m
    monkeypatch.setattr(m, "fetch_epss", lambda ids: {})
    monkeypatch.setattr(m, "fetch_kev", lambda: {"error": "offline", "cves": {}})
    out = CVEIntelPipeline().enrich(["CVE-2024-3094"])
    assert out["CVE-2024-3094"].epss_score is None and out["CVE-2024-3094"].kev_listed is False
