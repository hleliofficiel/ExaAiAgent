"""Persistent coordination state: save/load/resume, dedup, task queue,
token/cost budgets, and stuck-agent detection.

Pure functions + plain dataclasses over JSON-serializable data. The only
I/O is the explicit ``save_state``/``load_state`` pair, which writes one
JSON file (atomic temp-file + rename). No LLM, network, or global state.

Stuck detection deliberately separates *heartbeat* (the agent process is
alive and reporting) from *activity* (the agent is making progress:
iterations, tool calls, evidence). An agent can be alive-but-stuck
(heartbeating, no activity) or dead (no heartbeat) — those are different
signals and are reported separately.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path


STATE_VERSION = 1


# ---------------------------------------------------------------------------
# Persistent run state: save / load / resume
# ---------------------------------------------------------------------------


@dataclass
class RunState:
    run_id: str
    task: str = ""
    status: str = "running"  # running | paused | completed | failed
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    completed_task_ids: list[str] = field(default_factory=list)
    shared_items: list[dict] = field(default_factory=list)
    queue: list[dict] = field(default_factory=list)
    budget_used: dict = field(default_factory=dict)
    agents: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = dict(self.__dict__)
        data["state_version"] = STATE_VERSION
        return data

    @classmethod
    def from_dict(cls, data: dict) -> RunState:
        return cls(
            run_id=data["run_id"],
            task=data.get("task", ""),
            status=data.get("status", "running"),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            completed_task_ids=list(data.get("completed_task_ids") or []),
            shared_items=list(data.get("shared_items") or []),
            queue=list(data.get("queue") or []),
            budget_used=dict(data.get("budget_used") or {}),
            agents=list(data.get("agents") or []),
        )


def save_state(state: RunState, path: str) -> str:
    """Atomically write ``state`` as JSON to ``path``; returns ``path``."""
    state.updated_at = time.time()
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state.to_dict(), fh, indent=2, sort_keys=True)
        Path(tmp).replace(target)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(tmp).unlink()
        raise
    return path


def load_state(path: str) -> RunState:
    """Load a previously saved :class:`RunState`. Raises on corrupt data."""
    with Path(path).open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "run_id" not in data:
        raise ValueError(f"invalid run-state file: {path}")
    return RunState.from_dict(data)


def mark_task_complete(state: RunState, task_id: str) -> RunState:
    if task_id not in state.completed_task_ids:
        state.completed_task_ids.append(task_id)
    state.updated_at = time.time()
    return state


def is_task_done(state: RunState, task_id: str) -> bool:
    return task_id in state.completed_task_ids


# ---------------------------------------------------------------------------
# Shared-memory deduplication
# ---------------------------------------------------------------------------


def dedup_key(category: str, value: object) -> str:
    """Stable dedup key for a shared-memory item."""
    digest = hashlib.sha256(str(value).strip().lower().encode("utf-8")).hexdigest()[:16]
    return f"{category}:{digest}"


def add_shared_item(
    items: list[dict], category: str, value: object, source_agent: str = ""
) -> tuple[list[dict], bool]:
    """Add one item if its dedup key is new. Returns ``(items, added)``."""
    key = dedup_key(category, value)
    if any(it.get("dedup_key") == key for it in items):
        return items, False
    items.append(
        {
            "dedup_key": key,
            "category": category,
            "value": str(value),
            "source_agent": source_agent,
            "timestamp": time.time(),
        }
    )
    return items, True


def dedup_items(items: list[dict]) -> list[dict]:
    """Collapse an existing list to unique dedup keys, preserving order."""
    seen: set[str] = set()
    out: list[dict] = []
    for it in items:
        key = it.get("dedup_key") or dedup_key(str(it.get("category", "")), it.get("value", ""))
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


# ---------------------------------------------------------------------------
# Task queue with priority + depth limit
# ---------------------------------------------------------------------------


def enqueue(queue: list[dict], task: dict, max_depth: int = 8) -> list[dict]:
    """Enqueue ``task`` (``priority`` int, lower = first; ``depth`` int).

    Tasks whose ``depth`` exceeds ``max_depth`` are rejected (ValueError)
    so recursive decomposition cannot grow without bound (LLM06/LLM10).
    """
    depth = int(task.get("depth", 0))
    if depth > max_depth:
        raise ValueError(f"task depth {depth} exceeds max_depth {max_depth}")
    entry = {
        "id": str(task.get("id") or f"task_{len(queue)}"),
        "title": str(task.get("title") or task.get("id") or ""),
        "priority": int(task.get("priority", 0)),
        "depth": depth,
        "payload": task.get("payload"),
        "enqueued_at": time.time(),
    }
    queue.append(entry)
    return queue


def dequeue(queue: list[dict]) -> dict | None:
    """Pop the highest-priority (lowest number) task, or ``None``."""
    if not queue:
        return None
    # heapq on (priority, enqueued_at, index) keeps order deterministic.
    order = sorted(
        range(len(queue)),
        key=lambda i: (queue[i].get("priority", 0), queue[i].get("enqueued_at", 0), i),
    )
    idx = order[0]
    return queue.pop(idx)


def queue_depth(queue: list[dict]) -> int:
    return max((int(t.get("depth", 0)) for t in queue), default=0)


# ---------------------------------------------------------------------------
# Token / cost budget tracker (LLM10)
# ---------------------------------------------------------------------------


@dataclass
class Budget:
    max_tokens: int = 100_000
    max_cost_usd: float = 10.0
    tokens_used: int = 0
    cost_usd: float = 0.0
    tool_calls: int = 0
    max_tool_calls: int = 1000

    @property
    def token_fraction(self) -> float:
        return self.tokens_used / self.max_tokens if self.max_tokens else 1.0

    @property
    def cost_fraction(self) -> float:
        return self.cost_usd / self.max_cost_usd if self.max_cost_usd else 1.0

    def charge(self, tokens: int = 0, cost_usd: float = 0.0, tool_calls: int = 0) -> Budget:
        self.tokens_used += tokens
        self.cost_usd = round(self.cost_usd + cost_usd, 6)
        self.tool_calls += tool_calls
        return self

    def exhausted(self) -> bool:
        return (
            self.tokens_used >= self.max_tokens
            or self.cost_usd >= self.max_cost_usd
            or self.tool_calls >= self.max_tool_calls
        )

    def remaining(self) -> dict:
        return {
            "tokens": max(0, self.max_tokens - self.tokens_used),
            "cost_usd": round(max(0.0, self.max_cost_usd - self.cost_usd), 6),
            "tool_calls": max(0, self.max_tool_calls - self.tool_calls),
        }

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: dict) -> Budget:
        known = {k: v for k, v in (data or {}).items() if k in cls.__dataclass_fields__}
        return cls(**known)


# ---------------------------------------------------------------------------
# Stuck-agent detector: heartbeat vs activity
# ---------------------------------------------------------------------------


@dataclass
class AgentHeartbeat:
    agent_id: str
    last_heartbeat: float  # epoch seconds
    last_activity: float  # epoch seconds (iteration/tool call/evidence)
    iterations: int = 0


@dataclass
class StuckReport:
    agent_id: str
    heartbeat_alive: bool
    activity_stale: bool
    status: str  # healthy | alive_but_stuck | dead | suspect


def detect_stuck(
    agent: AgentHeartbeat,
    now: float | None = None,
    heartbeat_timeout: float = 60.0,
    activity_timeout: float = 300.0,
) -> StuckReport:
    """Classify an agent from heartbeat vs activity timestamps.

    - ``dead``: no heartbeat within ``heartbeat_timeout`` (process gone).
    - ``alive_but_stuck``: heartbeating but no activity within
      ``activity_timeout`` (looping / waiting forever).
    - ``suspect``: heartbeat fresh, activity borderline — treat as healthy
      but watch; kept distinct so callers can log differently.
    - ``healthy``: both fresh.
    """
    now = time.time() if now is None else now
    heartbeat_alive = (now - agent.last_heartbeat) <= heartbeat_timeout
    activity_stale = (now - agent.last_activity) > activity_timeout
    if not heartbeat_alive:
        status = "dead"
    elif activity_stale:
        status = "alive_but_stuck"
    elif (now - agent.last_activity) > activity_timeout / 2:
        status = "suspect"
    else:
        status = "healthy"
    return StuckReport(
        agent_id=agent.agent_id,
        heartbeat_alive=heartbeat_alive,
        activity_stale=activity_stale,
        status=status,
    )


def stuck_agents(
    agents: list[AgentHeartbeat],
    now: float | None = None,
    heartbeat_timeout: float = 60.0,
    activity_timeout: float = 300.0,
) -> list[StuckReport]:
    return [
        detect_stuck(
            a, now=now, heartbeat_timeout=heartbeat_timeout, activity_timeout=activity_timeout
        )
        for a in agents
    ]
