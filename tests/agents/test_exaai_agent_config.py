from exaaiagnt.agents.ExaaiAgent.exaai_agent import ExaaiAgent
from exaaiagnt.agents.state import AgentState
from exaaiagnt.llm.config import LLMConfig


def test_root_agent_merges_default_and_user_prompt_modules() -> None:
    agent = ExaaiAgent({"llm_config": LLMConfig(prompt_modules=["sql_injection"])})

    modules = agent.llm_config.prompt_modules

    assert "root_agent" in modules
    assert "sql_injection" in modules


def test_subagent_keeps_role_defaults_and_user_modules() -> None:
    state = AgentState(agent_name="ExaaiAgent", parent_id="parent-1")
    agent = ExaaiAgent(
        {
            "state": state,
            "llm_config": LLMConfig(prompt_modules=["waf_bypass"]),
        }
    )

    modules = agent.llm_config.prompt_modules

    assert "subdomain_enumeration" in modules
    assert "waf_bypass" in modules
