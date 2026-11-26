"""Wire LLMFallbackManager into llm.py: transient failures can try other models.

Fallback is opt-in (EXAAI_LLM_FALLBACK / config.fallback_enabled); permanent
errors (bad key, unknown model) stay fail-fast either way.
"""

from __future__ import annotations

from unittest.mock import patch

import litellm
import pytest

from exaaiagnt.llm.config import LLMConfig
from exaaiagnt.llm.fallback import LLMFallbackManager
from exaaiagnt.llm.llm import LLM, _strip_cache_control


class _FakeController:
    def __init__(self):
        self.calls = 0

    def set_base_delay(self, delay):
        pass

    async def queue_request(self, fn, **_kwargs):
        self.calls += 1
        return await fn()


def _llm(fallback_enabled: bool) -> LLM:
    config = LLMConfig(model_name="openai/primary-model")
    config.fallback_enabled = fallback_enabled
    return LLM(config)


def _rate_limit() -> litellm.RateLimitError:
    return litellm.RateLimitError(
        message="rate limited", llm_provider="openai", model="primary-model"
    )


@pytest.mark.asyncio
async def test_fallback_disabled_keeps_fail_fast():
    llm = _llm(fallback_enabled=False)
    controller = _FakeController()

    async def fake_acompletion(**kwargs):
        raise _rate_limit()

    with (
        patch.object(llm, "_request_with_fallback_models") as fallback_mock,
        patch("litellm.acompletion", side_effect=fake_acompletion),
        patch("exaaiagnt.llm.llm.get_traffic_controller", return_value=controller),
        pytest.raises(litellm.RateLimitError),
    ):
        await llm._make_request([{"role": "user", "content": "hi"}])

    fallback_mock.assert_not_called()


@pytest.mark.asyncio
async def test_fallback_enabled_succeeds_on_alternate_model():
    llm = _llm(fallback_enabled=True)
    controller = _FakeController()
    manager = LLMFallbackManager(models=["openai/primary-model", "anthropic/backup-model"])
    seen_models = []

    async def fake_acompletion(**kwargs):
        seen_models.append(kwargs["model"])
        if kwargs["model"] == "openai/primary-model":
            raise _rate_limit()
        return litellm.ModelResponse()

    with (
        patch("litellm.acompletion", side_effect=fake_acompletion),
        patch("exaaiagnt.llm.llm.get_traffic_controller", return_value=controller),
        patch("exaaiagnt.llm.llm.get_fallback_manager", return_value=manager),
    ):
        response = await llm._make_request([{"role": "user", "content": "hi"}])

    assert isinstance(response, litellm.ModelResponse)
    assert seen_models == ["openai/primary-model", "anthropic/backup-model"]
    assert llm._total_stats.requests == 1
    assert llm._total_stats.failed_requests == 0


@pytest.mark.asyncio
async def test_permanent_error_never_triggers_fallback():
    llm = _llm(fallback_enabled=True)
    controller = _FakeController()

    async def fake_acompletion(**kwargs):
        raise litellm.AuthenticationError(
            message="bad key", llm_provider="openai", model="primary-model"
        )

    with (
        patch.object(llm, "_request_with_fallback_models") as fallback_mock,
        patch("litellm.acompletion", side_effect=fake_acompletion),
        patch("exaaiagnt.llm.llm.get_traffic_controller", return_value=controller),
        pytest.raises(litellm.AuthenticationError),
    ):
        await llm._make_request([{"role": "user", "content": "hi"}])

    fallback_mock.assert_not_called()
    assert llm._total_stats.failed_requests == 1


@pytest.mark.asyncio
async def test_fallback_exhausted_reraises_primary_error():
    llm = _llm(fallback_enabled=True)
    controller = _FakeController()
    manager = LLMFallbackManager(models=["openai/primary-model", "anthropic/backup-model"])

    async def fake_acompletion(**kwargs):
        raise _rate_limit()

    with (
        patch("litellm.acompletion", side_effect=fake_acompletion),
        patch("exaaiagnt.llm.llm.get_traffic_controller", return_value=controller),
        patch("exaaiagnt.llm.llm.get_fallback_manager", return_value=manager),
        pytest.raises(litellm.RateLimitError),
    ):
        await llm._make_request([{"role": "user", "content": "hi"}])

    assert llm._total_stats.failed_requests == 1


@pytest.mark.asyncio
async def test_fallback_strips_cache_control_and_reasoning_effort():
    llm = _llm(fallback_enabled=True)
    controller = _FakeController()
    manager = LLMFallbackManager(models=["openai/primary-model", "anthropic/backup-model"])
    captured = {}

    async def fake_acompletion(**kwargs):
        if kwargs["model"] == "openai/primary-model":
            raise _rate_limit()
        captured.update(kwargs)
        return litellm.ModelResponse()

    messages = [
        {"role": "system", "content": "sys"},
        {
            "role": "user",
            "content": [{"type": "text", "text": "hi", "cache_control": {"type": "ephemeral"}}],
        },
    ]

    with (
        patch("litellm.acompletion", side_effect=fake_acompletion),
        patch("exaaiagnt.llm.llm.get_traffic_controller", return_value=controller),
        patch("exaaiagnt.llm.llm.get_fallback_manager", return_value=manager),
        patch.object(LLM, "_should_include_reasoning_effort", return_value=True),
    ):
        await llm._make_request(messages)

    assert "reasoning_effort" not in captured
    for part in captured["messages"][1]["content"]:
        assert "cache_control" not in part


def test_strip_cache_control_leaves_plain_messages_untouched():
    messages = [{"role": "user", "content": "plain"}]
    assert _strip_cache_control(messages) == messages
