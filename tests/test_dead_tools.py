"""Tests for Priority 1: activation of the four previously-dead tools.

Loads each module in isolation (via importlib) to avoid pulling the full
exaaiagnt.tools package (which requires optional deps such as httpx).
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types


ROOT = pathlib.Path(__file__).parent.parent


def _load(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_all(monkeypatch=None):
    # registry is importable standalone (stdlib only)
    reg = _load("exaaiagnt.tools.registry", "exaaiagnt/tools/registry.py")
    # stub parent packages so `exaaiagnt.tools.registry` resolves
    pkg = types.ModuleType("exaaiagnt")
    pkg.__path__ = [str(ROOT / "exaaiagnt")]  # type: ignore[attr-defined]
    tools_pkg = types.ModuleType("exaaiagnt.tools")
    tools_pkg.__path__ = [str(ROOT / "exaaiagnt" / "tools")]  # type: ignore[attr-defined]
    tools_pkg.registry = reg
    sys.modules.setdefault("exaaiagnt", pkg)
    sys.modules.setdefault("exaaiagnt.tools", tools_pkg)
    sys.modules["exaaiagnt.tools.registry"] = reg
    reg.clear_registry()

    fuzz = _load("exaaiagnt.tools.smart_fuzzer", "exaaiagnt/tools/smart_fuzzer.py")
    analyzer = _load("exaaiagnt.tools.response_analyzer", "exaaiagnt/tools/response_analyzer.py")
    validator = _load("exaaiagnt.tools.vuln_validator", "exaaiagnt/tools/vuln_validator.py")
    waf = _load("exaaiagnt.tools.waf_bypass", "exaaiagnt/tools/waf_bypass.py")
    return reg, fuzz, analyzer, validator, waf


def test_dead_tools_registered_with_sandbox_flags():
    reg, *_ = _load_all()
    names = reg.get_tool_names()
    for expected in (
        "smart_fuzz_parameter_tool",
        "analyze_http_response_tool",
        "create_vulnerability_report_tool",
        "detect_waf_and_bypass_tool",
    ):
        assert expected in names, f"{expected} not registered (have {names})"
        assert reg.should_execute_in_sandbox(expected) is True


def test_smart_fuzz_tool_basic():
    reg, fuzz, *_ = _load_all()
    fn = reg.get_tool_by_name("smart_fuzz_parameter_tool")
    assert fn is not None
    out = fn("user_id", "123")
    assert out["success"] is True
    assert out["param_type"] == "numeric"
    assert out["count"] > 0
    assert any(p["category"] == "sql_injection" for p in out["payloads"])
    # invalid category is a structured error, not an exception
    assert fn("id", "1", categories="bogus")["success"] is False
    assert fn("", "1")["success"] is False


def test_response_analyzer_tool_basic():
    reg, _, analyzer, *_ = _load_all()
    fn = reg.get_tool_by_name("analyze_http_response_tool")
    assert fn is not None
    out = fn("SQL syntax error near 'x' (MySQL)", status_code=500)
    assert out["success"] is True
    assert out["detection_count"] >= 1
    assert any(d["type"] == "sql_error" for d in out["detections"])
    assert fn("x", status_code=999)["success"] is False
    assert fn("x", status_code=200, headers_json="{bad")["success"] is False


def test_vuln_validator_tool_basic():
    reg, _, _, validator, _ = _load_all()
    fn = reg.get_tool_by_name("create_vulnerability_report_tool")
    assert fn is not None
    out = fn(
        "sql_injection",
        "https://example.com/search",
        "q",
        "' OR 1=1--",
        "Database error in response",
    )
    assert out["success"] is True
    assert out["severity"] == "critical"
    assert out["cvss_score"] == 9.8
    assert out["poc_steps"]
    assert out["remediation"]
    assert fn("sql_injection", "notaurl", "q", "p", "e")["success"] is False


def test_waf_tool_basic():
    reg, _, _, _, waf = _load_all()
    fn = reg.get_tool_by_name("detect_waf_and_bypass_tool")
    assert fn is not None
    out = fn(403, "Attention Required! Cloudflare Ray ID 123", "' OR 1=1--")
    assert out["success"] is True
    assert out["detected"] is True
    assert out["waf_type"] == "cloudflare"
    assert out["bypass_count"] > 0
    assert out["bypass_headers"]
    assert fn(999, "x", "p")["success"] is False


def test_wrapper_argv_allowlist_and_graceful_missing():
    # ZAP / OAST / httpx-katana / nuclei builders never use shell=True and
    # fail gracefully when binaries are absent (structured dicts).
    from exaaiagnt.tools.wrappers import httpx_katana_wrapper as hk
    from exaaiagnt.tools.wrappers import nuclei_wrapper as nuc
    from exaaiagnt.tools.wrappers import oast_wrapper as oast
    from exaaiagnt.tools.wrappers import zap_wrapper as zap

    assert nuc.build_nuclei_argv("https://example.com")[0] == "nuclei"
    assert zap.build_zap_daemon_argv(port=8090)[0] == "zaproxy"
    try:
        zap.build_zap_daemon_argv(host="0.0.0.0")
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("external ZAP bind must be rejected")
    assert zap.zap_daemon_status()["error"] in {"zap_not_installed", "zap_not_running"}
    assert zap.start_zap_daemon(timeout=1)["error"] in {"zap_not_installed", "zap_start_timeout"}

    tok = oast.new_oast_token()
    assert oast.build_interactsh_argv(token=tok)[0] == "interactsh-client"
    try:
        oast.build_interactsh_argv(oast_domain="evil.example.com")
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("external OAST domain must be rejected")
    assert oast.poll_interactsh(timeout=1)["error"] == "interactsh_not_installed"

    assert hk.build_httpx_argv("https://example.com")[0] == "httpx"
    assert hk.build_katana_argv("https://example.com")[0] == "katana"
    assert hk.build_ffuf_argv("https://example.com/FUZZ", "/tmp/words.txt")[0] == "ffuf"
    for bad in (hk.build_httpx_argv,):
        try:
            bad("https://example.com", extra=["--evil-flag"])
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError("unknown flag must be rejected")
    assert hk.run_httpx("https://example.com")["error"] in {
        "httpx_not_installed",
        "timeout",
        "run_failed",
    }
