"""Unit and TestClient tests for the dashboard admin API (v2.1).

No real network calls: urllib.request.urlopen is monkeypatched everywhere.
"""

import io
import json
import os
import zipfile
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from exaaiagnt import scan_control
from exaaiagnt.dashboard import admin, server


ALL_ENV_KEYS = [*admin.ENV_ALLOWLIST, "EXAAI_DASHBOARD_TOKEN"]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in ALL_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    yield
    scan_control.clear()


@pytest.fixture(autouse=True)
def reset_update_cache():
    admin.reset_update_cache()
    yield
    admin.reset_update_cache()


@pytest.fixture
def client():
    return TestClient(server.app)


class FakeResp:
    def __init__(self, status=200, body=b"{}"):
        self.status = status
        self._body = body

    def read(self, n=-1):  # noqa: ARG002 - signature must match file-like read
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_tracer(run_name="test-run"):
    class T:
        pass

    tracer = T()
    tracer.run_name = run_name
    tracer.start_time = datetime.now(UTC).isoformat()
    return tracer


# ---------- scan_control ----------


def test_scan_control_event_cycle():
    assert scan_control.should_stop() is False
    scan_control.request_stop()
    assert scan_control.should_stop() is True
    scan_control.clear()
    assert scan_control.should_stop() is False


# ---------- admin.discover_providers ----------


def test_discover_providers_empty_env():
    data = admin.discover_providers()
    assert data["active"] == {"provider": None, "model": None}
    names = {p["name"] for p in data["providers"]}
    assert names == {"openai", "anthropic", "gemini", "openrouter", "ollama", "azure", "litellm"}
    for p in data["providers"]:
        assert p["configured"] is False
        assert p["masked_key"] is None
        assert p["active"] is False


def test_discover_providers_openai_active(monkeypatch):
    monkeypatch.setenv("EXAAI_LLM_PROVIDER", "openai")
    monkeypatch.setenv("LITELLM_MODEL", "gpt-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-1234567890abcd")
    data = admin.discover_providers()
    assert data["active"] == {"provider": "openai", "model": "gpt-test"}
    openai = next(p for p in data["providers"] if p["name"] == "openai")
    assert openai["configured"] is True
    assert openai["masked_key"] == "sk-…abcd"
    assert "sk-test-1234567890abcd" not in json.dumps(data)
    assert openai["source"] == "OPENAI_API_KEY"
    assert openai["base"] == "https://api.openai.com"
    assert openai["active"] is True


def test_discover_providers_litellm_fallback(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "llm-key-00001111")
    data = admin.discover_providers()
    assert data["active"]["provider"] == "litellm"
    litellm = next(p for p in data["providers"] if p["name"] == "litellm")
    assert litellm["configured"] is True
    assert litellm["active"] is True


def test_masked_key_and_base_host():
    assert admin.masked_key(None) is None
    assert admin.masked_key("") is None
    assert admin.masked_key("sk-1234567890ab12") == "sk-…ab12"
    assert admin.base_host("https://api.example.com/v1/path?token=secret") == "https://api.example.com"
    assert admin.base_host(None) is None


# ---------- admin.test_provider (network mocked) ----------


def test_test_provider_ok(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-key-9999")
    calls = {}

    def fake_urlopen(req, timeout=0):
        calls["url"] = req.full_url
        calls["auth"] = req.headers.get("Authorization")
        calls["timeout"] = timeout
        return FakeResp(200, b'{"data": []}')

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = admin.test_provider("openai")
    assert result["ok"] is True
    assert isinstance(result["latency_ms"], int)
    assert calls["url"] == "https://api.openai.com/v1/models"
    assert calls["auth"] == "Bearer sk-secret-key-9999"
    assert calls["timeout"] == 4


def test_test_provider_ollama_uses_tags_and_no_auth(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_BASE", "http://localhost:11434")
    calls = {}

    def fake_urlopen(req, timeout=0):
        calls["url"] = req.full_url
        calls["auth"] = req.headers.get("Authorization")
        return FakeResp(200, b"{}")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = admin.test_provider("ollama")
    assert result["ok"] is True
    assert calls["url"] == "http://localhost:11434/api/tags"
    assert calls["auth"] is None


def test_test_provider_failure_never_leaks_key(monkeypatch):
    key = "sk-supersecretvalue-4242"
    monkeypatch.setenv("OPENAI_API_KEY", key)

    def fake_urlopen(req, timeout=0):
        raise OSError(f"boom while using {key}")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = admin.test_provider("openai")
    assert result["ok"] is False
    assert key not in result["detail"]
    assert "***" in result["detail"]


def test_test_provider_unknown_and_azure_unconfigured():
    assert admin.test_provider("bogus")["ok"] is False
    result = admin.test_provider("azure")
    assert result["ok"] is False
    assert "AZURE_API_BASE" in result["detail"]


# ---------- update check (network mocked) ----------


def test_update_check_available(monkeypatch):
    monkeypatch.setattr(admin, "_fetch_pypi_latest", lambda: "9.9.9")
    result = admin.get_update_status()
    assert result["current"]
    assert result["latest"] == "9.9.9"
    assert result["update_available"] is True
    assert result["cached"] is False
    assert result["url"] == "https://pypi.org/project/exaai-agent/"
    cached = admin.get_update_status()
    assert cached["cached"] is True


def test_update_check_not_available(monkeypatch):
    monkeypatch.setattr(admin, "_fetch_pypi_latest", lambda: "0.0.1")
    assert admin.get_update_status()["update_available"] is False


def test_update_check_error_degrades(monkeypatch):
    def boom():
        raise OSError("no network")

    monkeypatch.setattr(admin, "_fetch_pypi_latest", boom)
    result = admin.get_update_status()
    assert result["latest"] is None
    assert result["update_available"] is None
    assert result["checked_at"]


# ---------- audit log ----------


def test_audit_append_and_read(tmp_path):
    admin.append_audit("env_set", "OPENAI_API_KEY updated", cwd=tmp_path)
    admin.append_audit("provider_tested", "provider=openai ok=True", cwd=tmp_path)
    admin.append_audit("scan_stop_requested", "user requested scan stop", cwd=tmp_path)
    entries = admin.read_audit(2, cwd=tmp_path)
    assert len(entries) == 2
    assert entries[-1]["action"] == "scan_stop_requested"
    all_entries = admin.read_audit(100, cwd=tmp_path)
    assert len(all_entries) == 3
    assert all(set(e) == {"ts", "action", "detail"} for e in all_entries)


def test_audit_missing_file_and_malformed_lines(tmp_path):
    assert admin.read_audit(20, cwd=tmp_path) == []
    path = admin.audit_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('not json\n{"ts": "t", "action": "env_set", "detail": "d"}\n', encoding="utf-8")
    entries = admin.read_audit(20, cwd=tmp_path)
    assert entries == [{"ts": "t", "action": "env_set", "detail": "d"}]


# ---------- write_env_var ----------


def test_write_env_var_creates_and_chmods(tmp_path):
    backup = admin.write_env_var("OPENAI_API_KEY", "sk-value-1111", cwd=tmp_path)
    assert backup is None
    env_path = tmp_path / ".env"
    assert env_path.read_text(encoding="utf-8") == "OPENAI_API_KEY=sk-value-1111\n"
    assert (env_path.stat().st_mode & 0o777) == 0o600


def test_write_env_var_updates_and_backs_up(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("OTHER=keep\nOPENAI_API_KEY=old\n", encoding="utf-8")
    backup = admin.write_env_var("OPENAI_API_KEY", "sk-new-2222", cwd=tmp_path)
    assert backup is not None
    assert backup.is_file()
    assert backup.read_text(encoding="utf-8") == "OTHER=keep\nOPENAI_API_KEY=old\n"
    content = env_path.read_text(encoding="utf-8")
    assert "OTHER=keep" in content
    assert "OPENAI_API_KEY=sk-new-2222" in content
    assert "old" not in content
    assert (env_path.stat().st_mode & 0o777) == 0o600


def test_write_env_var_rejects_bad_input(tmp_path):
    with pytest.raises(ValueError, match="allowlist"):
        admin.write_env_var("NOT_ALLOWED", "x", cwd=tmp_path)
    with pytest.raises(ValueError, match="newlines"):
        admin.write_env_var("OPENAI_API_KEY", "a\nb", cwd=tmp_path)


# ---------- HTTP endpoints ----------


def test_api_providers_endpoint(client, monkeypatch):
    monkeypatch.setenv("EXAAI_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-live-key-3333")
    res = client.get("/api/providers")
    assert res.status_code == 200
    body = res.json()
    assert body["active"]["provider"] == "openai"
    assert "sk-live-key-3333" not in res.text


def test_api_providers_test_endpoint_and_audit(client, monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-audit-key-5555")
    monkeypatch.chdir(tmp_path)

    def fake_urlopen(req, timeout=0):
        return FakeResp(200, b"{}")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    res = client.post("/api/providers/test", json={"provider": "openai"})
    assert res.status_code == 200
    assert res.json()["ok"] is True
    audit = (tmp_path / "exaai_runs" / "_dashboard_audit.jsonl").read_text(encoding="utf-8")
    assert "provider_tested" in audit
    assert "sk-audit-key-5555" not in audit


def test_api_providers_env_put_and_audit(client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    res = client.put(
        "/api/providers/env", json={"key": "OPENAI_API_KEY", "value": "sk-put-key-6666"}
    )
    assert res.status_code == 200
    assert res.json() == {"ok": True, "restart_required": True}
    assert os.environ["OPENAI_API_KEY"] == "sk-put-key-6666"
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "OPENAI_API_KEY=sk-put-key-6666\n"
    audit = (tmp_path / "exaai_runs" / "_dashboard_audit.jsonl").read_text(encoding="utf-8")
    assert "env_set" in audit
    assert "sk-put-key-6666" not in audit


def test_api_providers_env_put_rejects_unlisted_key(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res = client.put("/api/providers/env", json={"key": "AWS_SECRET_ACCESS_KEY", "value": "x"})
    assert res.status_code == 400
    assert not (tmp_path / ".env").exists()


def test_api_scan_stop_and_audit(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res = client.post("/api/scan/stop")
    assert res.status_code == 200
    assert res.json() == {"ok": True, "detail": "stop requested"}
    assert scan_control.should_stop() is True
    scan_control.clear()
    audit = (tmp_path / "exaai_runs" / "_dashboard_audit.jsonl").read_text(encoding="utf-8")
    assert "scan_stop_requested" in audit


def test_api_update_endpoint(client, monkeypatch):
    monkeypatch.setattr(admin, "_fetch_pypi_latest", lambda: "99.0.0")
    res = client.get("/api/update")
    assert res.status_code == 200
    body = res.json()
    assert body["latest"] == "99.0.0"
    assert body["update_available"] is True
    assert body["cached"] is False


def test_api_audit_endpoint_limit(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for i in range(5):
        admin.append_audit("env_set", f"entry {i}", cwd=tmp_path)
    res = client.get("/api/audit?limit=3")
    assert res.status_code == 200
    assert len(res.json()) == 3
    assert res.json()[-1]["detail"] == "entry 4"
    res = client.get("/api/audit?limit=500")
    assert res.status_code == 200
    assert len(res.json()) == 5


def test_api_export_full_success(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "exaai_runs" / "test-run"
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text('{"ok": true}', encoding="utf-8")
    (run_dir / "report.md").write_text("# report", encoding="utf-8")
    monkeypatch.setattr(server, "get_global_tracer", lambda: _fake_tracer("test-run"))
    res = client.get("/api/export/full")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/zip"
    assert 'filename="exaai-run-test-run.zip"' in res.headers["content-disposition"]
    with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
        names = set(zf.namelist())
        assert {"report.json", "report.md", "manifest.json"} <= names
        manifest = json.loads(zf.read("manifest.json"))
        assert manifest["run_name"] == "test-run"
        assert set(manifest["files"]) == {"report.json", "report.md"}


def test_api_export_full_no_files_404(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "exaai_runs" / "test-run").mkdir(parents=True)
    monkeypatch.setattr(server, "get_global_tracer", lambda: _fake_tracer("test-run"))
    res = client.get("/api/export/full")
    assert res.status_code == 404


def test_api_export_full_no_active_run_404(client, monkeypatch):
    monkeypatch.setattr(server, "get_global_tracer", lambda: None)
    res = client.get("/api/export/full")
    assert res.status_code == 404


# ---------- executor stop wiring ----------


@pytest.mark.asyncio
async def test_execute_tool_raises_stop_scan_when_requested():
    from exaaiagnt.tools import executor

    scan_control.request_stop()
    with pytest.raises(scan_control.StopScan):
        await executor.execute_tool("nmap", None, target="127.0.0.1")
    scan_control.clear()


@pytest.mark.asyncio
async def test_process_tool_invocations_stops_before_next_tool(monkeypatch):
    from exaaiagnt.tools import executor

    called = []

    async def fake_invocation(tool_inv, agent_state=None):
        called.append(tool_inv["toolName"])
        scan_control.request_stop()  # simulate stop requested during first tool
        return {"ok": True}

    monkeypatch.setattr(executor, "execute_tool_invocation", fake_invocation)
    monkeypatch.setattr(
        executor, "_get_tracer_and_agent_id", lambda _state: (None, "agent-1")
    )
    history = []
    invocations = [
        {"toolName": "first_tool", "args": {}},
        {"toolName": "second_tool", "args": {}},
    ]
    result = await executor.process_tool_invocations(invocations, history, None)
    assert result is True
    assert called == ["first_tool"]
    content = history[-1]["content"]
    assert "Scan stopped by user request" in (content if isinstance(content, str) else str(content))
    scan_control.clear()
