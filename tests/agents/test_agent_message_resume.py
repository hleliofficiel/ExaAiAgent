from exaaiagnt.agents.state import AgentState
from exaaiagnt.tools.agents_graph.agents_graph_actions import (
    _agent_graph,
    _agent_messages,
    _agent_states,
    agent_finish,
    send_user_message_to_agent,
)


def setup_function() -> None:
    _agent_graph["nodes"].clear()
    _agent_graph["edges"].clear()
    _agent_messages.clear()
    _agent_states.clear()


def test_send_user_message_resumes_waiting_agent() -> None:
    state = AgentState(agent_name="Child")
    state.enter_waiting_state()
    _agent_states[state.agent_id] = state
    _agent_graph["nodes"][state.agent_id] = {"id": state.agent_id, "name": "Child", "status": "waiting"}

    result = send_user_message_to_agent(state.agent_id, "status?")

    assert result["success"] is True
    assert state.is_waiting_for_input() is False
    assert _agent_graph["nodes"][state.agent_id]["status"] == "running"


def test_agent_finish_resumes_waiting_parent() -> None:
    parent = AgentState(agent_name="Parent")
    parent.enter_waiting_state()
    child = AgentState(agent_name="Child", parent_id=parent.agent_id)

    _agent_states[parent.agent_id] = parent
    _agent_states[child.agent_id] = child
    _agent_messages[parent.agent_id] = []
    _agent_graph["nodes"][parent.agent_id] = {
        "id": parent.agent_id,
        "name": "Parent",
        "status": "waiting",
        "parent_id": None,
    }
    _agent_graph["nodes"][child.agent_id] = {
        "id": child.agent_id,
        "name": "Child",
        "status": "running",
        "parent_id": parent.agent_id,
        "task": "test",
    }

    result = agent_finish(child, "done", findings=["f1"], success=True)

    assert result["agent_completed"] is True
    assert result["parent_notified"] is True
    assert parent.is_waiting_for_input() is False
    assert _agent_graph["nodes"][parent.agent_id]["status"] == "running"
    assert len(_agent_messages[parent.agent_id]) == 1
