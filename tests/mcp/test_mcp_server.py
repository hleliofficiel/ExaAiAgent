"""Tests for the ExaAiAgent MCP stdio server (exaaiagnt/mcp_server.py)."""

from __future__ import annotations

import json

import pytest

from exaaiagnt import mcp_server


def test_tools_listed():
    tools = mcp_server.list_registered_mcp_tools()
    names = {t["name"] for t in tools}
    assert {"exaai_run_scan", "exaai_cve_lookup", "exaai_list_runs", "exaai_get_report"} <= names
    for tool in tools:
        assert tool["description"].strip(), tool["name"]
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert isinstance(schema.get("properties"), dict)
        assert schema["properties"]
        assert isinstance(schema.get("required"), list)
        for req in schema["required"]:
            assert req in schema["properties"]


async def test_exaai_get_report_sanitizes_run_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = await mcp_server.tool_exaai_get_report({"run_name": "../../etc"})
    assert result.isError
    assert "run_name" in result.content[0].text.lower()

    run_dir = tmp_path / "exaai_runs" / "demo"
    run_dir.mkdir(parents=True)
    report = {
        "schema": "exaai-report-v3",
        "run_name": "demo",
        "target": "https://example.com",
        "findings": [
            {
                "id": "abc123",
                "title": "SQLi in login",
                "severity": "high",
                "confidence": 0.9,
                "evidence_ids": ["ev-1", "ev-2"],
            },
            {
                "id": "def456",
                "title": "Missing header",
                "severity": "low",
                "confidence": 0.1,
            },
        ],
        "summary": {"total": 2, "by_severity": {"high": 1, "low": 1}},
    }
    (run_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")

    ok = await mcp_server.tool_exaai_get_report({"run_name": "demo"})
    assert not ok.isError
    text = ok.content[0].text
    assert "2 total (1 confirmed, 1 suspected)" in text
    assert "abc123" in text
    assert "ev-1" in text


async def test_exaai_run_scan_requires_targets(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("EXAAI_TARGETS", raising=False)
    result = await mcp_server.tool_exaai_run_scan({"target": "https://example.com"})
    assert result.isError
    assert "EXAAI_TARGETS" in result.content[0].text

    monkeypatch.setenv("EXAAI_TARGETS", "https://other.example.com")
    result = await mcp_server.tool_exaai_run_scan({"target": "https://example.com"})
    assert result.isError
    assert "not contained" in result.content[0].text


async def test_exaai_run_scan_invokes_pipeline(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("EXAAI_TARGETS", "https://example.com")
    monkeypatch.setattr(mcp_server, "_generate_run_name", lambda: "mcp_test_run")

    calls = []

    def fake_pipeline(argv, env_overrides):
        calls.append((argv, env_overrides))
        run_dir = tmp_path / "exaai_runs" / "mcp_test_run"
        run_dir.mkdir(parents=True)
        (run_dir / "report.json").write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "id": "f1",
                            "title": "XSS",
                            "severity": "medium",
                            "confidence": 0.95,
                            "evidence_ids": ["ev-9"],
                        }
                    ],
                    "summary": {"total": 1, "by_severity": {"medium": 1}},
                }
            ),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(mcp_server, "_invoke_scan_pipeline", fake_pipeline)
    result = await mcp_server.tool_exaai_run_scan(
        {"target": "https://example.com", "budget_max_tokens": 12345}
    )
    assert not result.isError
    argv, env_overrides = calls[0]
    assert "--target" in argv
    assert "https://example.com" in argv
    assert "-n" in argv
    assert env_overrides.get("EXAAI_MAX_SCAN_TOKENS") == "12345"
    assert "mcp_test_run" in result.content[0].text
    assert "ev-9" in result.content[0].text


async def test_cve_lookup_unknown_id():
    result = await mcp_server.tool_exaai_cve_lookup({"cve_id": "CVE-1999-0001"})
    # Must not raise; returns error-ish content for unknown ids.
    assert isinstance(result.content[0].text, str)
    assert result.content[0].text.strip()


async def test_cve_lookup_invalid_id():
    result = await mcp_server.tool_exaai_cve_lookup({"cve_id": "not-a-cve"})
    assert result.isError


def test_mcp_help_exits_zero(capsys):
    code = mcp_server.run_mcp_command(["--help"])
    assert code == 0
    out = capsys.readouterr().out
    assert "exaai mcp" in out


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
