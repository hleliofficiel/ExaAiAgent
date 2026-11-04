"""Offline tests for exaaiagnt.cloud checks and tool-output parsers."""

from exaaiagnt.cloud.checks import (
    check_compose_ports,
    check_dockerfile,
    check_tls_config,
    parse_grype,
    parse_kube_bench,
    parse_prowler,
    parse_scout_suite,
    parse_trivy,
)


def test_parse_prowler():
    findings = parse_prowler(
        [
            {
                "check_id": "s3_bucket_public",
                "status": "FAIL",
                "severity": "high",
                "resource": "bucket1",
                "message": "public bucket",
            },
            {"check_id": "iam_ok", "status": "PASS", "severity": "low"},
        ]
    )
    assert len(findings) == 2
    assert findings[0]["status"] == "fail"
    assert findings[1]["status"] == "pass"


def test_parse_scout_suite():
    data = {
        "services": {
            "IAM": {
                "findings": {
                    "iam-root-account": {
                        "level": "danger",
                        "flagged_items": 1,
                        "description": "root used",
                    },
                    "iam-ok": {"level": "warning", "flagged_items": 0, "description": "fine"},
                }
            }
        }
    }
    findings = parse_scout_suite(data)
    assert findings[0]["severity"] == "high"
    assert findings[0]["status"] == "fail"
    assert findings[1]["status"] == "pass"


def test_parse_kube_bench():
    data = {
        "Controls": [
            {"id": "4.1.1", "text": "ensure fs handled", "tests": [{"status": "FAIL"}]},
            {"id": "4.1.2", "text": "ok", "tests": [{"status": "PASS"}]},
        ]
    }
    findings = parse_kube_bench(data)
    assert findings[0]["status"] == "fail"
    assert findings[1]["status"] == "pass"


def test_parse_trivy():
    data = {
        "Results": [
            {
                "Target": "app:latest",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-1",
                        "Severity": "HIGH",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "Title": "overflow",
                    }
                ],
            }
        ]
    }
    findings = parse_trivy(data)
    assert len(findings) == 1
    assert findings[0]["id"] == "CVE-2021-1"
    assert findings[0]["severity"] == "high"


def test_parse_grype():
    data = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2022-2", "severity": "critical", "description": "rce"},
                "artifact": {"name": "log4j", "version": "2.14.0"},
            }
        ]
    }
    findings = parse_grype(data)
    assert findings[0]["resource"] == "log4j"
    assert findings[0]["severity"] == "critical"


def test_dockerfile_checks():
    dockerfile = "FROM ubuntu:latest\nEXPOSE 22 8080\nENV API_KEY=supersecretvalue\n"
    findings = check_dockerfile(dockerfile)
    ids = {f["id"] for f in findings}
    assert "unpinned_image" in ids
    assert "sensitive_port" in ids
    assert "secret_in_image" in ids
    assert "runs_as_root" in ids


def test_dockerfile_clean():
    dockerfile = "FROM ubuntu:22.04\nUSER appuser\nEXPOSE 8080\n"
    findings = check_dockerfile(dockerfile)
    assert not any(f["status"] == "fail" for f in findings)


def test_compose_ports():
    compose = 'services:\n  db:\n    ports:\n      - "5432:5432"\n'
    findings = check_compose_ports(compose)
    assert any(f["id"] == "sensitive_port" for f in findings)


def test_tls_weak_version():
    findings = check_tls_config({"min_version": "TLSv1.1"})
    assert any(f["id"] == "weak_min_version" and f["status"] == "fail" for f in findings)


def test_tls_good_and_expiring_cert():
    findings = check_tls_config({"min_version": "TLSv1.3", "cert_expires": "2030-01-01T00:00:00Z"})
    assert any(f["status"] == "pass" for f in findings)
    expired = check_tls_config({"min_version": "TLSv1.2", "cert_expires": "2020-01-01T00:00:00Z"})
    assert any(f["id"] == "cert_expired" for f in expired)
