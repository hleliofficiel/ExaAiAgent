"""Coordination state primitives: persistence, dedup, queue, budgets, health.

Pure functions over plain data — see :mod:`exaaiagnt.coordination.state`.
"""

from exaaiagnt.coordination.state import (
    STATE_VERSION,
    AgentHeartbeat,
    Budget,
    RunState,
    StuckReport,
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


__all__ = [
    "STATE_VERSION",
    "AgentHeartbeat",
    "Budget",
    "RunState",
    "StuckReport",
    "add_shared_item",
    "dedup_items",
    "dedup_key",
    "dequeue",
    "detect_stuck",
    "enqueue",
    "is_task_done",
    "load_state",
    "mark_task_complete",
    "queue_depth",
    "save_state",
    "stuck_agents",
]
