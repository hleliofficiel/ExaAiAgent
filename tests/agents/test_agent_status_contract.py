from exaaiagnt.agents.state import AgentState
from exaaiagnt.tools.agents_graph import agents_graph_actions


def test_agent_finish_marks_agent_completed() -> None:
    agents_graph_actions._agent_graph["nodes"].clear()

    state = AgentState(agent_id="child-1", agent_name="Child", parent_id="root-1")
    agents_graph_actions._agent_graph["nodes"]["child-1"] = {
        "name": "Child",
        "parent_id": "root-1",
        "status": "running",
        "task": "validate finding",
    }
    agents_graph_actions._agent_graph["nodes"]["root-1"] = {
        "name": "Root",
        "parent_id": None,
        "status": "running",
        "task": "root task",
    }

    result = agents_graph_actions.agent_finish(
        agent_state=state,
        result_summary="done",
        findings=["confirmed"],
        success=True,
    )

    assert result["agent_completed"] is True
    assert agents_graph_actions._agent_graph["nodes"]["child-1"]["status"] == "completed"
