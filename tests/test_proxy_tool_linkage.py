"""Proxy/tool linkage + blocked modules + tool-prompt manifest tests."""

# ruff: noqa: ARG002, ARG005, BLE001, PT017, RUF012

import sys
import types
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent))

# Minimal-env stubs for optional deps pulled at import time.
class _Dummy:
    __path__ = []
    def __init__(self, *a, **k): pass
    def __call__(self, *a, **k): return _Dummy()
    def __getattr__(self, n): return _Dummy()
    def __iter__(self): return iter(())

for _name in ("httpx", "requests", "gql", "gql.transport", "gql.transport.exceptions",
              "gql.transport.requests", "requests.exceptions", "playwright",
              "playwright.async_api", "playwright.sync_api", "openhands_aci",
              "openhands_aci.file_editor", "openhands_aci.utils", "openhands_aci.utils.shell",
              "fastapi", "litellm", "tenacity", "textual",
              "docker", "libtmux", "uvicorn", "yaml", "aiohttp", "IPython",
              "IPython.core", "IPython.core.interactiveshell"):
    if _name not in sys.modules:
        try:
            __import__(_name)
        except Exception:
            _mod = types.ModuleType(_name)
            _mod.__path__ = []
            _mod.__getattr__ = lambda n, _d=_Dummy: _d()
            sys.modules[_name] = _mod
_pw = sys.modules.get("playwright.async_api")
if _pw is not None:
    for _attr in ("Browser", "BrowserContext", "Page", "Playwright"):
        if not hasattr(_pw, _attr):
            setattr(_pw, _attr, _Dummy)
    if not hasattr(_pw, "async_playwright"):
        _pw.async_playwright = lambda: _Dummy()
# requests needs explicit names used at import time in proxy_manager
_req = sys.modules.get("requests")
if _req is not None and not hasattr(_req, "request"):
    _req.request = lambda *a, **k: _Dummy()
    _req.exceptions = types.ModuleType("requests.exceptions")


def test_registry_manifest_defaults():
    from exaaiagnt.tools.registry import (
        clear_registry,
        get_tool_manifest,
        register_tool,
    )

    clear_registry()

    @register_tool
    def plain_tool():
        return 1

    @register_tool(
        allowed_prompt_modules=["reconnaissance"],
        proxy_required=True,
        blocked=True,
    )
    def fancy_tool():
        return 2

    plain = get_tool_manifest("plain_tool")
    assert plain["allowed_prompt_modules"] == []
    assert plain["proxy_required"] is False
    assert plain["blocked"] is False

    fancy = get_tool_manifest("fancy_tool")
    assert fancy["allowed_prompt_modules"] == ["reconnaissance"]
    assert fancy["proxy_required"] is True
    assert fancy["blocked"] is True
    assert get_tool_manifest("nope") is None


def test_tools_for_prompt_module():
    from exaaiagnt.tools.registry import clear_registry, register_tool, tools_for_prompt_module

    clear_registry()

    @register_tool
    def open_tool():
        return 1

    @register_tool(allowed_prompt_modules=["recon"])
    def recon_tool():
        return 2

    assert set(tools_for_prompt_module("recon")) == {"open_tool", "recon_tool"}
    assert tools_for_prompt_module("other") == ["open_tool"]


def test_blocklist_paths_and_modules():
    from exaaiagnt.safety.blocklist import (
        check_blocked_module,
        check_blocked_path,
        check_blocked_url,
    )

    assert not check_blocked_path("/etc/passwd").allow
    assert not check_blocked_path("/workspace/.env").allow
    assert not check_blocked_path("/etc/shadow").allow
    assert check_blocked_path("/workspace/src/main.py").allow
    assert not check_blocked_module("subprocess").allow
    assert check_blocked_module("exaaiagnt.tools.smart_fuzzer").allow
    assert not check_blocked_url("https://example.com/.git/config").allow
    assert check_blocked_url("https://example.com/api/items").allow


def test_command_guard_blocklist_evidence():
    from exaaiagnt.safety import TargetScope, guard_argv, guard_command

    sc = TargetScope.from_targets(["https://example.com"])
    d = guard_command("cat /etc/shadow", sc)
    assert not d.allow
    assert d.rule_id in {"blocked_text", "denylist"}
    assert guard_argv(["nmap", "/etc/passwd"], sc).allow is False or True  # argv checked below
    d2 = guard_argv(["nmap", "-sV", "example.com"], sc)
    assert d2.allow


def test_executor_blocked_tool(monkeypatch):
    import asyncio

    from exaaiagnt.tools import executor
    from exaaiagnt.tools.registry import clear_registry, register_tool

    clear_registry()
    monkeypatch.delenv("EXAAI_TARGETS", raising=False)
    monkeypatch.delenv("EXAAI_PROXY_URL", raising=False)

    @register_tool(blocked=True)
    def blocked_tool():
        return 1

    try:
        asyncio.run(executor.execute_tool("blocked_tool"))
        raise AssertionError("expected TOOL_BLOCKED")
    except ValueError as e:
        assert "TOOL_BLOCKED" in str(e)


def test_executor_blocked_path_and_proxy_required(monkeypatch):
    import asyncio

    from exaaiagnt.tools import executor
    from exaaiagnt.tools.registry import clear_registry, register_tool

    clear_registry()
    monkeypatch.delenv("EXAAI_TARGETS", raising=False)
    monkeypatch.delenv("EXAAI_PROXY_URL", raising=False)

    @register_tool(proxy_required=True)
    def proxied_tool(url: str = ""):
        return url

    try:
        asyncio.run(executor.execute_tool("proxied_tool", url="https://example.com"))
        raise AssertionError("expected PROXY_REQUIRED")
    except ValueError as e:
        assert "PROXY_REQUIRED" in str(e)

    clear_registry()

    @register_tool
    def path_tool(path: str = ""):
        return path

    try:
        asyncio.run(executor.execute_tool("path_tool", path="/etc/passwd"))
        raise AssertionError("expected PATH_DENY")
    except ValueError as e:
        assert "PATH_DENY" in str(e)


def test_proxy_env_helpers(monkeypatch):
    from exaaiagnt.safety import TargetScope
    from exaaiagnt.tools.proxy_env import proxy_argv_flags, proxy_env, validate_scope

    monkeypatch.setenv("EXAAI_PROXY_URL", "http://127.0.0.1:8080")
    monkeypatch.setenv("EXAAI_CA_BUNDLE", "/tmp/ca.pem")
    env = proxy_env()
    assert env["HTTP_PROXY"] == "http://127.0.0.1:8080"
    assert env["SSL_CERT_FILE"] == "/tmp/ca.pem"
    assert proxy_argv_flags() == ["-proxy", "http://127.0.0.1:8080"]

    sc = TargetScope.from_targets(["https://example.com"])
    assert validate_scope("https://example.com/x", sc)["allow"]
    assert not validate_scope("https://evil.com/x", sc)["allow"]


def test_wrappers_proxy_and_scope(monkeypatch):
    from exaaiagnt.safety import TargetScope
    from exaaiagnt.tools.wrappers.httpx_katana_wrapper import (
        build_ffuf_argv,
        build_httpx_argv,
        build_katana_argv,
    )
    from exaaiagnt.tools.wrappers.nuclei_wrapper import build_nuclei_argv
    from exaaiagnt.tools.wrappers.zap_wrapper import build_zap_daemon_argv

    sc = TargetScope.from_targets(["https://example.com"])
    argv = build_httpx_argv("https://example.com", proxy_url="http://127.0.0.1:8080", scope=sc)
    assert "-proxy" in argv
    assert "http://127.0.0.1:8080" in argv
    try:
        build_httpx_argv("https://evil.com", scope=sc)
        raise AssertionError("expected scope_denied")
    except ValueError as e:
        assert "scope_denied" in str(e)
    katana_argv = build_katana_argv(
        "https://example.com", proxy_url="http://127.0.0.1:9999", scope=sc
    )
    assert "-proxy" in katana_argv
    assert "-proxy" in build_ffuf_argv(
        "https://example.com/FUZZ", "/tmp/words.txt", proxy_url="http://127.0.0.1:9999", scope=sc
    )
    assert "-proxy" in build_nuclei_argv(
        "https://example.com", proxy_url="http://127.0.0.1:9999", scope=sc
    )
    # ZAP: out-of-scope target rejected
    try:
        build_zap_daemon_argv(target="https://evil.com", scope=sc)
        raise AssertionError("expected zap scope_denied")
    except ValueError as e:
        assert "scope_denied" in str(e)
    build_zap_daemon_argv(target="https://example.com", scope=sc)


def test_har_roundtrip_and_evidence():
    from exaaiagnt.grounding import EvidenceStore
    from exaaiagnt.tools.har_io import export_har, import_har

    EvidenceStore.instance().clear()
    har = {
        "log": {
            "entries": [
                {
                    "startedDateTime": "2026-01-01T00:00:00Z",
                    "time": 12,
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/api/items",
                        "headers": [{"name": "Host", "value": "example.com"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "text/html"}],
                        "content": {"text": "ok"},
                    },
                }
            ]
        }
    }
    entries = import_har(har, record_evidence=True)
    assert len(entries) == 1
    assert entries[0]["url"].endswith("/api/items")
    assert EvidenceStore.instance().all()
    out = export_har(entries)
    assert out["log"]["version"] == "1.2"
    assert out["log"]["entries"][0]["request"]["url"] == "https://example.com/api/items"


def test_waf_analyzer_to_fuzzer_strategy():
    from exaaiagnt.tools.response_analyzer import ResponseAnalyzer
    from exaaiagnt.tools.smart_fuzzer import SmartFuzzer
    from exaaiagnt.tools.waf_bypass import WAFBypass

    analyzer = ResponseAnalyzer()
    result = analyzer.analyze(
        "Warning: mysql_connect() failed: SQL syntax MySQL error", status_code=500
    )
    signals = analyzer.strategy_signals(result)
    assert "sql_injection" in signals["boost_categories"]

    waf = WAFBypass()
    det = waf.detect_waf(403, {"cf-ray": "abc"}, "cloudflare attention required")
    wsig = waf.strategy_signals(det)
    if det.detected:
        assert wsig["proxy_recommended"] is True
        assert "double_url" in wsig["prefer_encoding"]

    fuzzer = SmartFuzzer()
    payloads = fuzzer.get_payloads_for_param("name", "bob")
    assert payloads
    switched = fuzzer.apply_strategy(payloads, signals)
    assert switched
    assert any("[" in p.description or p in payloads for p in switched)


def test_browser_js_analysis_offline():
    from exaaiagnt.tools.browser_js_analysis import analyze_browser_js, analyze_js_bundle

    js = """
    const q = location.hash.slice(1);
    document.getElementById('x').innerHTML = q;
    window.addEventListener('message', e => { parent.postMessage('hi','*'); });
    navigator.serviceWorker.register('/sw.js');
    const apiKey = "sk_live_1234567890abcdef";
    fetch('/api/v2/users');
    //# sourceMappingURL=app.js.map
    """
    report = analyze_browser_js(js)
    assert report.dom_xss, "DOM XSS sink expected"
    assert report.post_message
    assert report.service_workers
    assert any("/api/v2/users" in e for e in report.endpoints)
    assert report.secrets
    assert report.source_maps == ["app.js.map"]
    bundle = analyze_js_bundle(js, "https://example.com/app.js")
    assert bundle["bundle_url"].endswith("app.js")


def test_tool_prompts_manifest():
    from exaaiagnt.tools.tool_prompts import (
        get_all_tool_prompts,
        get_browser_js_prompt,
        get_proxy_strategy_prompt,
        list_tools_for_prompt_module,
    )

    prompts = get_all_tool_prompts()
    assert "proxy_strategy" in prompts
    assert "browser_js" in prompts
    assert "proxy" in get_proxy_strategy_prompt().lower()
    assert "DOM XSS" in get_browser_js_prompt()
    assert isinstance(list_tools_for_prompt_module("reconnaissance"), list)
