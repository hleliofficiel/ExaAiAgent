"""The supervisor monitoring loop must actually start and stay idempotent."""

from __future__ import annotations

import asyncio

import pytest

from exaaiagnt.agents.agent_supervisor import AgentStatus, AgentSupervisor


@pytest.fixture
def sup():
    AgentSupervisor._instance = None
    s = AgentSupervisor()
    yield s
    AgentSupervisor._instance = None


@pytest.mark.asyncio
async def test_start_monitoring_creates_task_and_is_idempotent(sup):
    await sup.start_monitoring()
    try:
        assert sup._running is True
        first_task = sup._monitor_task
        assert first_task is not None
        assert not first_task.done()

        await sup.start_monitoring()
        assert sup._monitor_task is first_task
    finally:
        await sup.stop_monitoring()

    assert sup._running is False
    assert first_task.done()


@pytest.mark.asyncio
async def test_monitor_marks_inactive_agent_as_timed_out(sup):
    sup.register_agent("a1", "A")
    health = sup.get_health("a1")
    health.last_activity = 0  # long inactive
    sup._timeout_handlers["a1"] = 0.0

    await sup._check_agent_health()

    assert health.status in (AgentStatus.TIMEOUT, AgentStatus.RECOVERED)
    assert health.timeout_count == 1


@pytest.mark.asyncio
async def test_monitor_skips_completed_and_waiting_agents(sup):
    sup.register_agent("a1", "A")
    health = sup.get_health("a1")
    health.last_activity = 0
    sup._timeout_handlers["a1"] = 0.0

    health.status = AgentStatus.COMPLETED
    await sup._check_agent_health()
    assert health.status == AgentStatus.COMPLETED
    assert health.timeout_count == 0

    health.status = AgentStatus.WAITING
    await sup._check_agent_health()
    assert health.status == AgentStatus.WAITING
    assert health.timeout_count == 0


@pytest.mark.asyncio
async def test_monitoring_loop_survives_health_check_errors(sup, monkeypatch):
    async def boom():
        raise RuntimeError("check failed")

    monkeypatch.setattr(sup, "_check_agent_health", boom)
    monkeypatch.setattr(AgentSupervisor, "HEALTH_CHECK_INTERVAL", 0.01)

    await sup.start_monitoring()
    await asyncio.sleep(0.05)
    try:
        assert sup._monitor_task is not None
        assert not sup._monitor_task.done()
    finally:
        await sup.stop_monitoring()
