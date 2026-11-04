# Coordination State

`exaaiagnt/coordination/state.py`: pure, JSON-serializable coordination
primitives for multi-agent runs (no LLM, network, or global state; the only
I/O is the explicit save/load pair).

## Persistent run state

- `RunState` — one run: id, task, status, completed task ids, shared
  items, task queue, budget usage, agent snapshots.
- `save_state(state, path)` / `load_state(path)` — atomic write
  (temp file + rename, `STATE_VERSION = 1`); corrupt files raise
  `ValueError`. A loaded state resumes: completed tasks stay completed,
  the queue and shared items are intact.
- `mark_task_complete(state, task_id)` / `is_task_done(state, task_id)`.

## Shared-memory dedup

- `dedup_key(category, value)` — stable `category:sha256[:16]` key.
- `add_shared_item(items, category, value, source_agent)` — appends only
  if the key is new, returns `(items, added)`.
- `dedup_items(items)` — collapses duplicates in an existing list,
  preserving order. Prevents agents from re-scanning/re-reporting the
  same URL/endpoint.

## Task queue

- `enqueue(queue, task, max_depth=8)` — `task` carries `id`, `priority`
  (lower runs first), `depth`, optional `payload`. Depth beyond
  `max_depth` raises `ValueError` so recursive decomposition cannot grow
  unbounded (LLM06 Excessive Agency / LLM10 Unbounded Consumption).
- `dequeue(queue)` — pops the highest-priority task deterministically
  (priority, then enqueue time), `None` when empty.
- `queue_depth(queue)` — maximum task depth currently queued.

## Token / cost budget

`Budget(max_tokens, max_cost_usd, max_tool_calls)` with `charge(...)`,
`exhausted()`, `remaining()`, and JSON round-trip via `to_dict()` /
`from_dict()`. Charge every LLM + tool call; stop the run when
`exhausted()` is true (LLM10).

## Stuck-agent detection: heartbeat vs activity

`AgentHeartbeat(agent_id, last_heartbeat, last_activity, iterations)` and
`detect_stuck(agent, now, heartbeat_timeout=60, activity_timeout=300)`:

- **heartbeat** = the agent process is alive and reporting.
- **activity** = the agent is making progress (iteration, tool call,
  evidence recorded).

Statuses: `healthy` (both fresh), `suspect` (heartbeat fresh, activity
aging), `alive_but_stuck` (heartbeating, no activity — looping/waiting),
`dead` (no heartbeat — process gone). They are separate signals on
purpose: an agent can be alive-but-stuck, which a heartbeat-only check
would miss. `stuck_agents([...])` classifies a fleet at once.

## Tests

`tests/coordination/test_state.py` — save/load round-trip, dedup,
priority queue + depth limit, budget, heartbeat-vs-activity cases.
