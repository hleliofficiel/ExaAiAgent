"""Offline tests for exaaiagnt.secrets scanner."""

from exaaiagnt.secrets.scanner import redact, scan_files, scan_text, summarize


FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"
FAKE_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7"


def test_detects_aws_key():
    findings = scan_text(f"key = {FAKE_AWS}\n")
    assert any(f["type"] == "aws_access_key_id" for f in findings)
    # Full secret must never appear in findings
    assert all(FAKE_AWS not in str(f) for f in findings)


def test_detects_private_key():
    findings = scan_text(FAKE_PRIVATE_KEY)
    assert any(f["type"] == "private_key" and f["severity"] == "critical" for f in findings)


def test_detects_generic_password():
    findings = scan_text("password = hunter2hunter2\n")
    assert any(f["type"] == "generic_password" for f in findings)


def test_detects_github_token():
    findings = scan_text("ghp_1234567890abcdefghijklmnopqrstuv\n")
    assert any(f["type"] == "github_token" for f in findings)


def test_clean_text_has_no_findings():
    assert scan_text("hello world\nnothing sensitive here\n") == []


def test_redact():
    assert redact("abcdefghij", keep=4).startswith("abcd")
    assert "abcdefghij" not in redact("abcdefghij")
    assert redact("ab") == "**"


def test_scan_files_and_summary():
    findings = scan_files({"a.py": f"key={FAKE_AWS}", "b.py": "clean"})
    assert len(findings) == 1
    assert findings[0]["source"] == "a.py"
    summary = summarize(findings)
    assert summary["total"] == 1
    assert summary["by_type"]["aws_access_key_id"] == 1
    assert summary["by_severity"]["high"] == 1


def test_line_numbers():
    findings = scan_text(f"line1\nline2\nkey = {FAKE_AWS}\n")
    assert findings[0]["line"] == 3
