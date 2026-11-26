import asyncio

import pytest

from exaaiagnt.tools import executor, registry


class TestCheckErrorResult:
    def test_dict_with_success_false_is_an_error(self) -> None:
        is_error, payload = executor._check_error_result({"success": False, "message": "nope"})
        assert is_error
        assert payload == {"success": False, "message": "nope"}

    def test_error_executing_string_is_an_error(self) -> None:
        is_error, payload = executor._check_error_result("Error executing nmap: boom")
        assert is_error
        assert payload == "Error executing nmap: boom"

    def test_dict_with_error_key_is_an_error(self) -> None:
        is_error, _ = executor._check_error_result({"error": "x"})
        assert is_error

    def test_plain_success_is_not_an_error(self) -> None:
        assert executor._check_error_result({"success": True, "result": "ok"}) == (False, None)
        assert executor._check_error_result("all good") == (False, None)
        assert executor._check_error_result(None) == (False, None)


async def test_async_tool_respects_timeout(monkeypatch) -> None:
    """Async tools must be bounded by EXAAI_TOOL_TIMEOUT like sync tools."""
    monkeypatch.setenv("EXAAI_TOOL_TIMEOUT", "0.1")

    async def _slow():
        await asyncio.sleep(5)
        return "done"

    monkeypatch.setitem(registry._tools_by_name, "zzz_slow_async_tool", _slow)

    with pytest.raises(TimeoutError):
        await executor._execute_tool_locally("zzz_slow_async_tool", None)
