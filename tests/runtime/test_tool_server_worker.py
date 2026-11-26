import importlib

import pytest


def _load_tool_server(monkeypatch):
    monkeypatch.setenv("EXAAI_SANDBOX_MODE", "true")
    return importlib.import_module("exaaiagnt.runtime.tool_server")


@pytest.fixture
def crashing_tool(monkeypatch):
    from exaaiagnt.tools import registry

    def _boom() -> None:
        raise TypeError("boom: unexpected tool failure")

    monkeypatch.setitem(registry._tools_by_name, "zzz_boom_tool", _boom)
    return "zzz_boom_tool"


def test_worker_survives_unexpected_tool_exception(monkeypatch, crashing_tool) -> None:
    module = _load_tool_server(monkeypatch)
    agent_id = "pytest-worker-survival"
    request_queue, response_queue = module.ensure_agent_process(agent_id)
    try:
        request_queue.put({"tool_name": crashing_tool, "kwargs": {}})
        first = response_queue.get(timeout=60)
        assert "error" in first
        assert "boom" in first["error"]

        # The worker must still be alive and responsive for the next request.
        request_queue.put({"tool_name": "definitely_missing_tool", "kwargs": {}})
        second = response_queue.get(timeout=60)
        assert "error" in second
        assert "not found" in second["error"].lower()
    finally:
        module.agent_processes.pop(agent_id, None)
        queues = module.agent_queues.pop(agent_id, None)
        if queues:
            queues["request"].put(None)


def test_ensure_agent_process_restarts_dead_worker(monkeypatch) -> None:
    module = _load_tool_server(monkeypatch)
    agent_id = "pytest-worker-restart"
    request_queue, response_queue = module.ensure_agent_process(agent_id)
    first_process = module.agent_processes[agent_id]["process"]
    try:
        first_process.kill()  # SIGKILL: workers inherit the server's SIGTERM handler
        first_process.join(timeout=10)
        assert not first_process.is_alive()

        module.ensure_agent_process(agent_id)
        second_process = module.agent_processes[agent_id]["process"]
        assert second_process.pid != first_process.pid
        assert second_process.is_alive()
    finally:
        module.agent_processes.pop(agent_id, None)
        queues = module.agent_queues.pop(agent_id, None)
        if queues:
            queues["request"].put(None)
