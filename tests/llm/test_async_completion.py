from types import SimpleNamespace

import pytest

from exaaiagnt.llm.config import LLMConfig
from exaaiagnt.llm.llm import LLM


@pytest.mark.asyncio
async def test_generate_uses_async_acompletion(monkeypatch):
    called = {"acompletion": False, "completion": False}

    async def fake_acompletion(**kwargs):
        called["acompletion"] = True
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="<function=wait_for_message></function>"))],
            usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
        )

    def fake_completion(**kwargs):
        called["completion"] = True
        raise AssertionError("sync completion should not be used")

    monkeypatch.setattr("litellm.acompletion", fake_acompletion)
    monkeypatch.setattr("litellm.completion", fake_completion)

    llm = LLM(LLMConfig(model_name="openai/gpt-5", timeout=5), agent_name=None)
    response = await llm.generate([{"role": "user", "content": "hello"}])

    assert called["acompletion"] is True
    assert called["completion"] is False
    assert response.content == "<function=wait_for_message></function>"
