from exaaiagnt.knowledge import CVEStore
def test_lookup_seed():
    s = CVEStore.get()
    assert s.lookup_cve("CVE-2024-3094") is not None
def test_invented_returns_none():
    s = CVEStore.get()
    assert s.lookup_cve("CVE-2099-99999") is None
    assert s.lookup_cve("not-a-cve") is None
def test_match_product():
    s = CVEStore.get()
    assert s.match_product("xz")
