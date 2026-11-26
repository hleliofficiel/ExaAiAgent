"""LOW-16: duplicate tool registration must not silently replace a tool."""

from __future__ import annotations

import logging

import pytest

from exaaiagnt.tools import registry


@pytest.fixture
def clean_registry():
    saved_tools = registry.tools[:]
    saved_by_name = dict(registry._tools_by_name)
    registry.tools.clear()
    registry._tools_by_name.clear()
    yield
    registry.tools[:] = saved_tools
    registry._tools_by_name.clear()
    registry._tools_by_name.update(saved_by_name)


def _make_func():
    def my_dup_tool() -> str:
        return "first"

    return my_dup_tool


def _make_other_func():
    def my_dup_tool() -> str:  # same name, different function object
        return "second"

    return my_dup_tool


def test_duplicate_registration_keeps_first_and_warns(clean_registry, caplog):
    first = _make_func()
    second = _make_other_func()

    registry.register_tool(first)
    with caplog.at_level(logging.WARNING, logger=registry.__name__):
        registry.register_tool(second)

    assert registry.get_tool_by_name("my_dup_tool") is first
    assert len(registry.tools) == 1
    assert any("Duplicate tool registration" in r.message for r in caplog.records)


def test_same_function_reregistration_is_quiet_noop(clean_registry, caplog):
    func = _make_func()

    registry.register_tool(func)
    with caplog.at_level(logging.WARNING, logger=registry.__name__):
        registry.register_tool(func)

    assert registry.get_tool_by_name("my_dup_tool") is func
    assert len(registry.tools) == 1
    assert not any("Duplicate tool registration" in r.message for r in caplog.records)
