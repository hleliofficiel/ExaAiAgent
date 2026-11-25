import asyncio

import litellm
import pytest

from exaaiagnt.llm.llm_traffic_controller import _is_permanent_llm_error


def test_permanent_errors_classified():
    auth = litellm.AuthenticationError("bad key", llm_provider="openai", model="m")
    nf = litellm.NotFoundError("no model", llm_provider="openai", model="m")
    assert _is_permanent_llm_error(auth)
    assert _is_permanent_llm_error(nf)
    assert not _is_permanent_llm_error(RuntimeError("boom"))
    assert not _is_permanent_llm_error(
        litellm.RateLimitError("rate limit", llm_provider="openai", model="m")
    )


def test_auth_error_fails_fast():
    from exaaiagnt.llm.llm_traffic_controller import get_traffic_controller

    calls = []

    async def bad():
        calls.append(1)
        raise litellm.AuthenticationError("bad key", llm_provider="openai", model="m")

    async def run():
        c = get_traffic_controller()
        return await asyncio.wait_for(c.queue_request(bad, agent_id="t"), timeout=5)

    with pytest.raises(litellm.AuthenticationError):
        asyncio.run(run())
    assert len(calls) == 1
