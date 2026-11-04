from exaaiagnt.grounding import EvidenceStore, validate_claim


def test_record_and_validate():
    EvidenceStore.instance().clear()
    rec = EvidenceStore.instance().record(
        "send_request", "HTTP 200 sqli error", args={"url": "https://example.com/?id=1"}
    )
    assert rec.evidence_id.startswith("ev_")
    assert rec.source_class == "primary"
    g = validate_claim([rec.evidence_id], text="sqli found")
    assert g.allow, g.reason


def test_secondary_rejected():
    EvidenceStore.instance().clear()
    rec = EvidenceStore.instance().record("think", "maybe vuln", args={})
    assert rec.source_class == "secondary"
    g = validate_claim([rec.evidence_id], text="x")
    assert not g.allow and "secondary" in g.reason


def test_no_evidence_rejected():
    g = validate_claim([], text="x")
    assert not g.allow


def test_invented_cve_rejected():
    EvidenceStore.instance().clear()
    rec = EvidenceStore.instance().record("send_request", "ok", args={"url": "https://example.com"})
    from exaaiagnt.knowledge import CVEStore

    g = validate_claim(
        [rec.evidence_id], text="CVE-2099-99999", kb_lookup=CVEStore.get().lookup_cve
    )
    assert not g.allow and "unverified_cve" in g.reason
