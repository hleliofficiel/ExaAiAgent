from argparse import Namespace

from exaaiagnt.interface.main import resolve_prompt_modules


def test_resolve_prompt_modules_uses_user_modules_when_present() -> None:
    args = Namespace(
        prompt_modules="graphql_security,waf_bypass",
        targets_info=[{"original": "https://example.com/graphql"}],
        instruction="",
    )

    assert resolve_prompt_modules(args) == ["graphql_security", "waf_bypass"]


def test_resolve_prompt_modules_auto_detects_modules() -> None:
    args = Namespace(
        prompt_modules=None,
        targets_info=[{"original": "https://example.com/graphql"}],
        instruction="test schema and queries",
    )

    modules = resolve_prompt_modules(args)

    assert modules is not None
    assert "graphql_security" in modules
