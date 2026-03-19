from exaaiagnt.tools.registry import get_tool_names


def test_tools_registry_is_populated_after_importing_tools() -> None:
    import exaaiagnt.tools  # noqa: F401

    tool_names = get_tool_names()

    assert tool_names
    assert "scan_cluster" in tool_names
