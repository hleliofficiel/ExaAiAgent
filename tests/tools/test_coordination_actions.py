import json

from exaaiagnt.coordination.state import dequeue, enqueue
from exaaiagnt.tools.coordination import coordination_actions as ca


def _use_tmp_state(monkeypatch, tmp_path):
    path = tmp_path / "coordination_state.json"
    monkeypatch.setenv("EXAAI_COORDINATION_STATE", str(path))
    return path


def test_corrupt_state_file_is_preserved_and_surfaced(monkeypatch, tmp_path) -> None:
    path = _use_tmp_state(monkeypatch, tmp_path)
    path.write_text("{not valid json")

    result = ca.coordination_save_state(run_id="r1", task="t")

    assert result["success"] is True
    assert "warning" in result and "corrupt" in result["warning"]
    corrupt_files = list(tmp_path.glob("coordination_state.json.corrupt-*"))
    assert len(corrupt_files) == 1
    assert corrupt_files[0].read_text() == "{not valid json"


def test_duplicate_task_id_is_rejected(monkeypatch, tmp_path) -> None:
    _use_tmp_state(monkeypatch, tmp_path)
    assert ca.coordination_enqueue_task(task_id="t1")["success"] is True
    second = ca.coordination_enqueue_task(task_id="t1")
    assert second["success"] is False
    assert "duplicate" in second["message"]


def test_generated_ids_do_not_collide_after_dequeue() -> None:
    queue = []
    for _ in range(3):
        enqueue(queue, {})
    dequeue(queue)  # removes one, len(queue) == 2 with ids task_1, task_2 present
    enqueue(queue, {})
    ids = [t["id"] for t in queue]
    assert len(ids) == len(set(ids))


def test_dequeue_task_persists_and_prioritizes(monkeypatch, tmp_path) -> None:
    _use_tmp_state(monkeypatch, tmp_path)
    ca.coordination_enqueue_task(task_id="low", priority=5)
    ca.coordination_enqueue_task(task_id="high", priority=1)

    first = ca.coordination_dequeue_task()
    assert first["success"] is True
    assert first["task"]["id"] == "high"

    state = json.loads((tmp_path / "coordination_state.json").read_text())
    assert [t["id"] for t in state["queue"]] == ["low"]


def test_add_shared_item_dedups(monkeypatch, tmp_path) -> None:
    _use_tmp_state(monkeypatch, tmp_path)
    assert ca.coordination_add_shared_item(category="host", value="10.0.0.1")["added"] is True
    assert ca.coordination_add_shared_item(category="host", value="10.0.0.1")["added"] is False
    assert (
        ca.coordination_add_shared_item(category="host", value="10.0.0.2")["shared_item_count"] == 2
    )


def test_budget_charge_is_persistent(monkeypatch, tmp_path) -> None:
    _use_tmp_state(monkeypatch, tmp_path)
    first = ca.coordination_budget_charge(tokens=60000, max_tokens=100000)
    assert first["exhausted"] is False
    # Second call must see the first charge (persistent), so the budget now exhausts.
    second = ca.coordination_budget_charge(tokens=50000, max_tokens=100000)
    assert second["exhausted"] is True
    assert second["budget"]["tokens_used"] == 110000
