import importlib


def test_tool_server_can_be_imported_without_cli_args(monkeypatch) -> None:
    monkeypatch.setenv("EXAAI_SANDBOX_MODE", "true")
    monkeypatch.delenv("EXAAI_TOOL_SERVER_TOKEN", raising=False)

    module = importlib.import_module("exaaiagnt.runtime.tool_server")

    assert module.EXPECTED_TOKEN == ""
    assert callable(module.parse_server_args)
