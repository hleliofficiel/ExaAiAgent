# ruff: noqa: TRY300
"""Coordination tool actions: RunState save/load, queue, budgets, stuck check.

Thin @register_tool wrappers over exaaiagnt.coordination.state. File-backed
state lives at EXAAI_COORDINATION_STATE (default ./coordination_state.json).
All tools are additive: they never mutate agent state or the registry beyond
registering themselves, and every failure is a structured dict, not an raise.
"""

from __future__ import annotations

import contextlib
import logging
import os
import time
from pathlib import Path
from typing import Any

from exaaiagnt.coordination.state import (
    AgentHeartbeat,
    Budget,
    RunState,
    add_shared_item,
    dequeue,
    detect_stuck,
    enqueue,
    load_state,
    mark_task_complete,
    save_state,
)
from exaaiagnt.tools.registry import register_tool

logger = logging.getLogger(__name__)


def _state_path() -> str:
    return os.getenv("EXAAI_COORDINATION_STATE", "./coordination_state.json")


@contextlib.contextmanager
def _state_lock():
    """Exclusive flock on a sidecar lock file around load-mutate-persist.

    Without it, concurrent agents each load the same state, mutate their copy
    and persist, silently losing each other's updates.
    """
    lock_path = Path(_state_path() + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import fcntl
    except ImportError:  # non-POSIX: best effort
        yield
        return
    with lock_path.open("a+") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _load_or_new(run_id: str = "default") -> tuple[RunState, str | None]:
    """Load state, or start fresh. A corrupt file is never silently dropped:
    it is renamed to ``<path>.corrupt-<ts>`` and the warning is returned so
    callers can surface it."""
    path = _state_path()
    if Path(path).exists():
        try:
            return load_state(path), None
        except Exception as e:  # noqa: BLE001 - any parse/shape failure means corrupt
            corrupt_path = f"{path}.corrupt-{int(time.time())}"
            with contextlib.suppress(OSError):
                os.replace(path, corrupt_path)
            warning = f"corrupt state file moved to {corrupt_path}: {e}; started fresh"
            logger.warning(warning)
            return RunState(run_id=run_id or "default"), warning
    return RunState(run_id=run_id or "default"), None


def _persist(state: RunState) -> str:
    return save_state(state, _state_path())


def _with_warning(result: dict[str, Any], warning: str | None) -> dict[str, Any]:
    if warning:
        result["warning"] = warning
    return result


@register_tool(sandbox_execution=False)
def coordination_save_state(run_id: str = "default", task: str = "") -> dict[str, Any]:
    """Create or update the persistent RunState and save it to disk."""
    try:
        with _state_lock():
            state, warning = _load_or_new(run_id)
            if task:
                state.task = task
            path = _persist(state)
        return _with_warning({"success": True, "run_id": state.run_id, "path": path}, warning)
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"coordination_save_state failed: {e}"}


@register_tool(sandbox_execution=False)
def coordination_load_state() -> dict[str, Any]:
    """Load the persistent RunState (status, completed tasks, queue depth)."""
    try:
        if not Path(_state_path()).exists():
            return {"success": True, "exists": False, "state": None}
        state = load_state(_state_path())
        return {
            "success": True,
            "exists": True,
            "run_id": state.run_id,
            "status": state.status,
            "completed_task_ids": list(state.completed_task_ids),
            "shared_item_count": len(state.shared_items),
            "queue": list(state.queue),
            "queue_depth": max((int(t.get("depth", 0)) for t in state.queue), default=0),
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"coordination_load_state failed: {e}"}


@register_tool(sandbox_execution=False)
def coordination_enqueue_task(
    task_id: str,
    title: str = "",
    priority: int = 0,
    depth: int = 0,
) -> dict[str, Any]:
    """Enqueue a task (depth > 8 is rejected so decomposition stays bounded)."""
    try:
        with _state_lock():
            state, warning = _load_or_new()
            enqueue(
                state.queue, {"id": task_id, "title": title, "priority": priority, "depth": depth}
            )
            _persist(state)
        return _with_warning(
            {"success": True, "task_id": task_id, "queue_size": len(state.queue)}, warning
        )
    except ValueError as e:
        return {"success": False, "message": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"coordination_enqueue_task failed: {e}"}


@register_tool(sandbox_execution=False)
def coordination_dequeue_task() -> dict[str, Any]:
    """Pop the highest-priority queued task from the persistent RunState."""
    try:
        with _state_lock():
            state, warning = _load_or_new()
            task = dequeue(state.queue)
            _persist(state)
        return _with_warning(
            {"success": True, "task": task, "queue_size": len(state.queue)}, warning
        )
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"coordination_dequeue_task failed: {e}"}


@register_tool(sandbox_execution=False)
def coordination_add_shared_item(
    category: str,
    value: str,
    source_agent: str = "",
) -> dict[str, Any]:
    """Add an item to persistent shared memory with dedup (agents share facts)."""
    try:
        with _state_lock():
            state, warning = _load_or_new()
            state.shared_items, added = add_shared_item(
                state.shared_items, category, value, source_agent
            )
            _persist(state)
        return _with_warning(
            {
                "success": True,
                "added": added,
                "shared_item_count": len(state.shared_items),
            },
            warning,
        )
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"coordination_add_shared_item failed: {e}"}


@register_tool(sandbox_execution=False)
def coordination_budget_charge(
    tokens: int = 0,
    cost_usd: float = 0.0,
    tool_calls: int = 0,
    max_tokens: int = 100000,
    max_cost_usd: float = 10.0,
    max_tool_calls: int = 1000,
) -> dict[str, Any]:
    """Persistently charge token/cost/tool-call usage to the run budget (LLM10).

    Unlike coordination_budget_check (stateless preview), the charge is saved
    to the RunState file, so limits hold across agents and process restarts.
    """
    try:
        with _state_lock():
            state, warning = _load_or_new()
            if state.budget_used:
                budget = Budget.from_dict(state.budget_used)
            else:
                budget = Budget(
                    max_tokens=max_tokens,
                    max_cost_usd=max_cost_usd,
                    max_tool_calls=max_tool_calls,
                )
            budget.charge(tokens=tokens, cost_usd=cost_usd, tool_calls=tool_calls)
            state.budget_used = budget.to_dict()
            _persist(state)
        return _with_warning(
            {
                "success": True,
                "exhausted": budget.exhausted(),
                "remaining": budget.remaining(),
                "token_fraction": budget.token_fraction,
                "cost_fraction": budget.cost_fraction,
                "budget": budget.to_dict(),
            },
            warning,
        )
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"coordination_budget_charge failed: {e}"}


@register_tool(sandbox_execution=False)
def coordination_mark_task_complete(task_id: str) -> dict[str, Any]:
    """Mark a task id as completed in the persistent RunState."""
    try:
        with _state_lock():
            state, warning = _load_or_new()
            mark_task_complete(state, task_id)
            _persist(state)
        return _with_warning(
            {"success": True, "task_id": task_id, "completed": list(state.completed_task_ids)},
            warning,
        )
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"coordination_mark_task_complete failed: {e}"}


@register_tool(sandbox_execution=False)
def coordination_budget_check(
    tokens_used: int = 0,
    cost_usd: float = 0.0,
    tool_calls: int = 0,
    max_tokens: int = 100000,
    max_cost_usd: float = 10.0,
    max_tool_calls: int = 1000,
) -> dict[str, Any]:
    """Check token/cost/tool-call budgets (LLM10 unbounded-consumption guard)."""
    try:
        budget = Budget(
            max_tokens=max_tokens,
            max_cost_usd=max_cost_usd,
            max_tool_calls=max_tool_calls,
        )
        budget.charge(tokens=tokens_used, cost_usd=cost_usd, tool_calls=tool_calls)
        return {
            "success": True,
            "exhausted": budget.exhausted(),
            "remaining": budget.remaining(),
            "token_fraction": budget.token_fraction,
            "cost_fraction": budget.cost_fraction,
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"coordination_budget_check failed: {e}"}


@register_tool(sandbox_execution=False)
def coordination_stuck_check(
    agent_id: str,
    seconds_since_heartbeat: float = 0.0,
    seconds_since_activity: float = 0.0,
) -> dict[str, Any]:
    """Classify an agent as healthy / alive_but_stuck / dead / suspect.

    Heartbeat and activity are separate signals: a live process with no
    activity is alive_but_stuck, a silent process is dead.
    """
    try:
        import time

        now = time.time()
        hb = AgentHeartbeat(
            agent_id=agent_id,
            last_heartbeat=now - seconds_since_heartbeat,
            last_activity=now - seconds_since_activity,
        )
        report = detect_stuck(hb, now=now)
        return {
            "success": True,
            "agent_id": report.agent_id,
            "status": report.status,
            "heartbeat_alive": report.heartbeat_alive,
            "activity_stale": report.activity_stale,
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"coordination_stuck_check failed: {e}"}
