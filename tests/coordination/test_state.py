import json

import pytest

from exaaiagnt.coordination import (
    AgentHeartbeat,
    Budget,
    RunState,
    add_shared_item,
    dedup_items,
    dedup_key,
    dequeue,
    detect_stuck,
    enqueue,
    is_task_done,
    load_state,
    mark_task_complete,
    queue_depth,
    save_state,
    stuck_agents,
)


def test_save_load_resume_roundtrip(tmp_path):
    state = RunState(run_id="run-1", task="scan example.com")
    mark_task_complete(state, "t1")
    add_shared_item(state.shared_items, "endpoints", "https://example.com/a", "agent-1")
    enqueue(state.queue, {"id": "t2", "priority": 1, "depth": 0})
    path = tmp_path / "state.json"
    save_state(state, str(path))
    loaded = load_state(str(path))
    assert loaded.run_id == "run-1"
    assert is_task_done(loaded, "t1")
    assert loaded.shared_items[0]["value"] == "https://example.com/a"
    assert loaded.queue[0]["id"] == "t2"
    # file is valid JSON with the state version
    raw = json.loads(path.read_text())
    assert raw["state_version"] == 1


def test_load_corrupt_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"nope": true}')
    with pytest.raises(ValueError, match="invalid run-state"):
        load_state(str(bad))


def test_dedup_shared_items():
    items: list[dict] = []
    items, added1 = add_shared_item(items, "urls", "https://Example.com/A ", "a1")
    items, added2 = add_shared_item(items, "urls", "https://example.com/a", "a2")
    assert added1
    assert not added2
    assert len(items) == 1
    assert dedup_key("urls", "https://example.com/a") == items[0]["dedup_key"]
    # dedup_items collapses pre-existing dupes preserving order
    dupes = [*items, dict(items[0]), {"category": "urls", "value": "https://example.com/b"}]
    assert len(dedup_items(dupes)) == 2


def test_task_queue_priority_and_depth_limit():
    q: list[dict] = []
    enqueue(q, {"id": "low", "priority": 5, "depth": 0})
    enqueue(q, {"id": "high", "priority": 1, "depth": 1})
    enqueue(q, {"id": "mid", "priority": 3, "depth": 0})
    assert queue_depth(q) == 1
    assert dequeue(q)["id"] == "high"
    assert dequeue(q)["id"] == "mid"
    assert dequeue(q)["id"] == "low"
    assert dequeue(q) is None
    with pytest.raises(ValueError, match="max_depth"):
        enqueue([], {"id": "too-deep", "depth": 99}, max_depth=8)


def test_budget_tracker():
    b = Budget(max_tokens=100, max_cost_usd=1.0, max_tool_calls=5)
    assert not b.exhausted()
    b.charge(tokens=60, cost_usd=0.25, tool_calls=2)
    assert b.remaining() == {"tokens": 40, "cost_usd": 0.75, "tool_calls": 3}
    b.charge(tokens=50)
    assert b.exhausted()
    clone = Budget.from_dict(b.to_dict())
    assert clone.tokens_used == 110
    assert clone.exhausted()


def test_stuck_detector_heartbeat_vs_activity():
    now = 1000.0
    healthy = detect_stuck(AgentHeartbeat("a", last_heartbeat=990, last_activity=995), now=now)
    assert healthy.status == "healthy"
    assert healthy.heartbeat_alive

    stuck = detect_stuck(AgentHeartbeat("b", last_heartbeat=995, last_activity=100), now=now)
    # Alive (fresh heartbeat) but no activity for 900s > activity_timeout.
    assert stuck.status == "alive_but_stuck"
    assert stuck.heartbeat_alive
    assert stuck.activity_stale

    dead = detect_stuck(AgentHeartbeat("c", last_heartbeat=100, last_activity=100), now=now)
    assert dead.status == "dead"
    assert not dead.heartbeat_alive

    reports = stuck_agents([AgentHeartbeat("a", 990, 995), AgentHeartbeat("c", 100, 100)], now=now)
    assert [r.status for r in reports] == ["healthy", "dead"]
