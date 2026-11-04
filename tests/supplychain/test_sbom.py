"""Offline tests for exaaiagnt.supplychain SBOM + CVE comparison."""

from exaaiagnt.supplychain.sbom import (
    CVEStore,
    compare_cves,
    parse_cargo_lock,
    parse_package_json,
    parse_requirements,
    to_cyclonedx_lite,
)


REQUIREMENTS = """
flask==2.0.1
requests>=2.28
numpy
# comment
-r other.txt
django~=4.2
"""

PACKAGE_JSON = """
{"dependencies": {"lodash": "^4.17.21", "express": "4.18.2"},
 "devDependencies": {"jest": "^29.0.0"}}
"""

CARGO_LOCK = """
[[package]]
name = "serde"
version = "1.0.164"

[[package]]
name = "tokio"
version = "1.35.0"
"""


def _store():
    store = CVEStore()
    store.add("CVE-2023-30803", "flask", "<2.3.2", "high")
    store.add("CVE-2021-23337", "lodash", "<=4.17.21", "high")
    store.add("CVE-2024-0001", "serde", "==1.0.164", "medium")
    return store


def test_parse_requirements():
    components = {c["name"]: c for c in parse_requirements(REQUIREMENTS)}
    assert components["flask"]["version"] == "2.0.1"
    assert components["requests"]["version"] == "2.28"
    assert components["numpy"]["version"] == ""
    assert components["django"]["ecosystem"] == "pypi"
    assert "other" not in components


def test_parse_package_json():
    components = {c["name"]: c for c in parse_package_json(PACKAGE_JSON)}
    assert components["lodash"]["version"] == "4.17.21"
    assert components["express"]["version"] == "4.18.2"
    assert components["jest"]["ecosystem"] == "npm"


def test_parse_cargo_lock():
    components = {c["name"]: c for c in parse_cargo_lock(CARGO_LOCK)}
    assert components["serde"]["version"] == "1.0.164"
    assert components["tokio"]["ecosystem"] == "cargo"


def test_compare_cves_hits():
    components = parse_requirements(REQUIREMENTS) + parse_package_json(PACKAGE_JSON)
    hits = compare_cves(components, _store())
    cves = {(h["package"], h["cve"]) for h in hits}
    assert ("flask", "CVE-2023-30803") in cves
    assert ("lodash", "CVE-2021-23337") in cves


def test_compare_cves_no_hit_for_patched():
    components = [{"name": "flask", "version": "3.0.0", "ecosystem": "pypi"}]
    assert compare_cves(components, _store()) == []


def test_compare_cves_cargo_exact():
    components = parse_cargo_lock(CARGO_LOCK)
    hits = compare_cves(components, _store())
    assert any(h["package"] == "serde" for h in hits)
    assert not any(h["package"] == "tokio" for h in hits)


def test_cyclonedx_lite():
    doc = to_cyclonedx_lite(parse_requirements("flask==2.0.1\n"))
    assert doc["bom-format"] == "CycloneDX"
    assert doc["components"][0]["name"] == "flask"
    assert doc["components"][0]["purl"] == "pkg:pypi/flask@2.0.1"
