import importlib.util, pathlib
_spec = importlib.util.spec_from_file_location("nuclei_wrapper", pathlib.Path(__file__).parent.parent / "exaaiagnt" / "tools" / "wrappers" / "nuclei_wrapper.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
build_nuclei_argv = _mod.build_nuclei_argv
parse_nuclei_jsonl = _mod.parse_nuclei_jsonl

def test_argv():
    a = build_nuclei_argv("https://example.com")
    assert a[0] == "nuclei" and "-jsonl" in a and "https://example.com" in a

def test_parse():
    assert parse_nuclei_jsonl('{"a":1}\nnotjson\n{"b":2}') == [{"a":1},{"b":2}]
