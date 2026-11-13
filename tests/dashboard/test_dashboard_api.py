import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from exaaiagnt.dashboard import server


class FakeTracer:
    def __init__(self, run_name="test-run"):
        self.run_name = run_name
        self.run_id = run_name
        self.start_time = datetime.now(UTC).isoformat()
        self.end_time = None
        self.agents = {
            "agent-1": {
                "id": "agent-1",
                "name": "Recon Agent",
                "task": "recon",
                "status": "running",
                "role": "recon",
                "model": "test-model",
                "tool_executions": [1, 2],
            },
            "agent-2": {
                "id": "agent-2",
                "name": "Exploit Agent",
                "task": "exploit",
                "status": "completed",
                "tool_executions": [3],
            },
        }
        self.vulnerability_reports = [
            {
                "id": "vuln-0001",
                "title": "SQL injection in login",
                "content": "details",
                "severity": "high",
                "timestamp": "2026-11-13 00:00:00 UTC",
                "evidence_ids": ["exec-1"],
                "tool_name": "sqlmap",
                "confidence_band": "confirmed",
            },
            {
                "id": "vuln-0002",
                "title": "Reflected XSS",
                "content": "details",
                "severity": "medium",
                "timestamp": "2026-11-13 00:01:00 UTC",
            },
        ]
        self.tool_executions = {
            1: {
                "execution_id": 1,
                "agent_id": "agent-1",
                "tool_name": "nmap",
                "status": "completed",
                "timestamp": "2026-11-13T00:00:01+00:00",
                "started_at": "2026-11-13T00:00:01+00:00",
                "completed_at": "2026-11-13T00:00:02+00:00",
            },
            2: {
                "execution_id": 2,
                "agent_id": "agent-1",
                "tool_name": "httpx",
                "status": "completed",
                "timestamp": "2026-11-13T00:00:03+00:00",
                "started_at": "2026-11-13T00:00:03+00:00",
                "completed_at": "2026-11-13T00:00:04+00:00",
            },
            3: {
                "execution_id": 3,
                "agent_id": "agent-2",
                "tool_name": "sqlmap",
                "status": "completed",
                "timestamp": "2026-11-13T00:00:05+00:00",
                "started_at": "2026-11-13T00:00:05+00:00",
                "completed_at": "2026-11-13T00:00:06+00:00",
            },
        }
        self.chat_messages = [
            {
                "message_id": 1,
                "content": "hello",
                "role": "assistant",
                "agent_id": "agent-1",
                "timestamp": 1.0,
                "metadata": {},
            }
        ]


@pytest.fixture
def fake_tracer(monkeypatch):
    tracer = FakeTracer()
    monkeypatch.setattr(server, "get_global_tracer", lambda: tracer)
    return tracer


@pytest.fixture
def client(fake_tracer):
    return TestClient(server.app)


def test_stats_returns_expected_keys(client):
    res = client.get("/api/stats")
    assert res.status_code == 200
    body = res.json()
    for key in ("agents_count", "vulnerabilities", "tool_calls", "start_time", "run_name"):
        assert key in body
    assert body["agents_count"] == 2
    assert body["vulnerabilities"] == 2
    assert body["tool_calls"] == 3
    assert body["run_name"] == "test-run"


def test_state_returns_expected_keys(client):
    res = client.get("/api/state")
    assert res.status_code == 200
    body = res.json()
    for key in (
        "run_name",
        "agents",
        "confirmed",
        "suspected",
        "tool_calls",
        "start_time",
        "uptime_seconds",
        "vulnerabilities",
        "tool_executions",
        "counters",
    ):
        assert key in body
    assert body["run_name"] == "test-run"
    assert body["confirmed"] == 1
    assert body["suspected"] == 1
    assert body["tool_calls"] == 3
    assert body["agents"]["agent-1"]["status"] == "running"
    assert body["agents"]["agent-1"]["tool_calls"] == 2
    assert body["agents"]["agent-1"]["role"] == "recon"
    assert len(body["tool_executions"]) == 3
    assert body["tool_executions"][0]["tool_name"] == "nmap"
    assert body["counters"]["agents_running"] == 1
    assert body["counters"]["agents_completed"] == 1
    assert isinstance(body["uptime_seconds"], int | float)
    assert body["vulnerabilities"][0]["id"] == "vuln-0001"
    assert body["vulnerabilities"][0]["evidence_ids"] == ["exec-1"]


def test_vulnerabilities_returns_list(client):
    res = client.get("/api/vulnerabilities")
    assert res.status_code == 200
    body = res.json()
    assert isinstance(body, list)
    assert body[0]["title"] == "SQL injection in login"


def test_report_404_when_no_run(client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    res = client.get("/api/report")
    assert res.status_code == 404
    assert res.json()["detail"]


def test_report_404_for_unsafe_run_name(client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(server, "get_global_tracer", lambda: FakeTracer(run_name="../evil"))
    res = client.get("/api/report")
    assert res.status_code == 404


def test_report_200_when_report_exists(client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "exaai_runs" / "test-run"
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text(json.dumps({"schema": "exaai-report-v3"}))
    res = client.get("/api/report")
    assert res.status_code == 200
    assert res.json()["schema"] == "exaai-report-v3"


def test_export_sarif_streams_when_present(client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "exaai_runs" / "test-run"
    run_dir.mkdir(parents=True)
    (run_dir / "report.sarif").write_text(json.dumps({"version": "2.1.0"}))
    res = client.get("/api/export/sarif")
    assert res.status_code == 200
    assert res.json()["version"] == "2.1.0"


def test_export_sarif_404_when_missing(client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    res = client.get("/api/export/sarif")
    assert res.status_code == 404


def test_export_invalid_format_404(client):
    res = client.get("/api/export/exe")
    assert res.status_code == 404


def test_ws_receives_frame_with_compat_keys(client):
    with client.websocket_connect("/ws") as ws:
        data = ws.receive_json()
    for key in ("agents", "stats", "recent_logs", "events", "counters"):
        assert key in data
    assert data["stats"]["active"] == 1
    assert data["counters"]["tool_calls"] == 3
    assert isinstance(data["events"], list)


def test_token_required_blocks_api(client, monkeypatch):
    monkeypatch.setenv("EXAAI_DASHBOARD_TOKEN", "secret-token")
    res = client.get("/api/stats")
    assert res.status_code == 401


def test_token_required_allows_with_header(client, monkeypatch):
    monkeypatch.setenv("EXAAI_DASHBOARD_TOKEN", "secret-token")
    res = client.get("/api/stats", headers={"Authorization": "Bearer secret-token"})
    assert res.status_code == 200


def test_ws_rejected_with_4401_when_token_set_and_absent(client, monkeypatch):
    monkeypatch.setenv("EXAAI_DASHBOARD_TOKEN", "secret-token")
    with pytest.raises(WebSocketDisconnect) as exc_info, client.websocket_connect("/ws"):
        pass
    assert exc_info.value.code == 4401
