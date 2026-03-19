from exaaiagnt.llm.utils import parse_tool_invocations


def test_parse_tool_invocations_keeps_multiple_function_calls() -> None:
    content = """
<function=first_tool>
<parameter=foo>bar</parameter>
</function>
<function=second_tool>
<parameter=baz>qux</parameter>
</function>
""".strip()

    invocations = parse_tool_invocations(content)

    assert invocations is not None
    assert [call["toolName"] for call in invocations] == ["first_tool", "second_tool"]
