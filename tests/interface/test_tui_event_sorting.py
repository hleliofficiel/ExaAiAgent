from argparse import Namespace

from exaaiagnt.interface.tui import ExaaiTUIApp


def _make_app() -> ExaaiTUIApp:
    args = Namespace(
        run_name="test-run",
        targets_info=[],
        instruction="",
        resolved_prompt_modules=None,
        local_sources=None,
    )
    return ExaaiTUIApp(args)


def test_gather_agent_events_handles_mixed_timestamp_types() -> None:
    app = _make_app()
    agent_id = "agent_test123"

    app.tracer.agents[agent_id] = {"id": agent_id, "name": "ExaaiAgent", "status": "running"}
    app.tracer.chat_messages.append(
        {
            "message_id": 1,
            "content": "add other agent fast",
            "role": "user",
            "agent_id": agent_id,
            "timestamp": 1774005575.0939898,
            "metadata": {},
        }
    )
    app.tracer.tool_executions[1] = {
        "execution_id": 1,
        "agent_id": agent_id,
        "tool_name": "scan_start_info",
        "args": {},
        "status": "completed",
        "result": {},
        "timestamp": "2026-03-20T11:16:44.046983+00:00",
        "started_at": "2026-03-20T11:16:44.046983+00:00",
        "completed_at": "2026-03-20T11:16:44.046987+00:00",
    }

    events = app._gather_agent_events(agent_id)

    assert len(events) == 2
    assert all(isinstance(event["timestamp"], float) for event in events)
    assert [event["type"] for event in events] == ["tool", "chat"]
    assert events[0]["timestamp"] <= events[1]["timestamp"]
