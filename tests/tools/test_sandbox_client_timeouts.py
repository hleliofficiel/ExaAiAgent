from types import SimpleNamespace

import httpx
import pytest

from exaaiagnt.tools import executor


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self._payload


def _make_state():
    return SimpleNamespace(
        sandbox_id="sandbox-1",
        sandbox_token="token-1",
        sandbox_info={"tool_server_port": 1},
        agent_id="agent-1",
    )


def _patch_runtime(monkeypatch):
    async def _url(container_id, port):
        return "http://127.0.0.1:1"

    monkeypatch.setattr(
        executor, "get_runtime", lambda: SimpleNamespace(get_sandbox_url=_url)
    )


async def test_read_timeout_fails_without_retry(monkeypatch) -> None:
    _patch_runtime(monkeypatch)
    calls = []
    seen_timeouts = []

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, **kwargs):
            calls.append(url)
            seen_timeouts.append(kwargs.get("timeout"))
            raise httpx.ReadTimeout("slow tool")

    monkeypatch.setattr(executor.httpx, "AsyncClient", FakeClient)

    with pytest.raises(RuntimeError, match="Timed out waiting for the sandbox tool result"):
        await executor._execute_tool_in_sandbox("any_tool", _make_state())

    # A read timeout means the tool may still be running server-side; retrying
    # would execute it twice, so exactly one request is allowed.
    assert len(calls) == 1
    # The client timeout must exceed the tool server's own 630s ceiling.
    assert seen_timeouts[0] > 630


async def test_connect_error_is_retried_then_raises(monkeypatch) -> None:
    _patch_runtime(monkeypatch)

    async def _no_sleep(_seconds):
        return None

    import asyncio as _asyncio

    monkeypatch.setattr(_asyncio, "sleep", _no_sleep)

    calls = []

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, **_kwargs):
            calls.append(url)
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(executor.httpx, "AsyncClient", FakeClient)

    with pytest.raises(RuntimeError, match="unreachable after retries"):
        await executor._execute_tool_in_sandbox("any_tool", _make_state())

    assert len(calls) == 3
