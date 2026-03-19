from exaaiagnt.agents.base_agent import BaseAgent
from exaaiagnt.agents.state import AgentState
from exaaiagnt.llm.config import LLMConfig
from exaaiagnt.tools.agents_graph import agents_graph_actions


class DummyAgent(BaseAgent):
    pass


class DummyTracer:
    def __init__(self) -> None:
        self.status_updates: list[tuple[str, str]] = []
        self.scan_config: dict[str, str] = {}

    def log_agent_creation(self, *args, **kwargs) -> None:
        return None

    def log_tool_execution_start(self, *args, **kwargs) -> int:
        return 1

    def update_tool_execution(self, *args, **kwargs) -> None:
        return None

    def update_agent_status(self, agent_id: str, status: str, error_message: str | None = None) -> None:
        self.status_updates.append((agent_id, status))


def test_check_agent_messages_resumes_waiting_agent_and_updates_graph(monkeypatch) -> None:
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_messages.clear()

    state = AgentState(agent_id="agent-1", agent_name="Dummy")
    state.enter_waiting_state()

    agents_graph_actions._agent_graph["nodes"]["agent-1"] = {"status": "waiting", "name": "Dummy"}
    agents_graph_actions._agent_messages["agent-1"] = [
        {"from": "user", "content": "resume", "read": False}
    ]

    tracer = DummyTracer()

    monkeypatch.setattr("exaaiagnt.telemetry.tracer.get_global_tracer", lambda: tracer)

    agent = DummyAgent({"llm_config": LLMConfig(prompt_modules=[]), "state": state})
    agent._check_agent_messages(state)

    assert state.waiting_for_input is False
    assert agents_graph_actions._agent_graph["nodes"]["agent-1"]["status"] == "running"
    assert ("agent-1", "running") in tracer.status_updates
