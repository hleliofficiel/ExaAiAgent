import sys

from exaaiagnt.interface.main import get_version, parse_arguments


def test_get_version_returns_semver_like_string() -> None:
    version = get_version()
    assert version.count(".") == 2


def test_parse_arguments_accepts_comma_separated_prompt_modules(monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "exaai",
            "--target",
            "https://example.com",
            "--prompt-modules",
            "graphql_security,waf_bypass",
        ],
    )

    args = parse_arguments()

    assert args.target == ["https://example.com"]
    assert args.prompt_modules == "graphql_security,waf_bypass"
    assert args.targets_info[0]["type"] == "web_application"
