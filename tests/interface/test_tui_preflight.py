from argparse import Namespace

from exaaiagnt.interface.tui import ExaaiTUIApp


def _make_app() -> ExaaiTUIApp:
    args = Namespace(
        run_name="test-run",
        targets_info=[],
        instruction="",
        resolved_prompt_modules=None,
        local_sources=None,
    )
    return ExaaiTUIApp(args)


def test_start_scan_if_ready_reports_docker_unavailable(monkeypatch) -> None:
    app = _make_app()
    app.scan_config["targets"] = [
        {"type": "web_application", "details": {}, "original": "https://example.com"}
    ]
    monkeypatch.setattr(ExaaiTUIApp, "_docker_available", staticmethod(lambda: "Docker down"))

    app._start_scan_if_ready()

    assert app._last_runtime_error == "Cannot start scan: Docker down"
    assert app._scan_thread is None


def test_status_is_not_an_error() -> None:
    app = _make_app()
    app._record_status("Target queued: https://example.com")
    assert app._last_runtime_error is None
    assert app._last_status == "Target queued: https://example.com"
    app._record_runtime_error("boom")
    assert app._last_status is None


def test_chat_text_not_treated_as_target_while_scan_running(monkeypatch) -> None:
    import threading

    app = _make_app()
    app.selected_agent_id = None
    ev = threading.Event()
    t = threading.Thread(target=ev.wait, daemon=True)
    t.start()
    app._scan_thread = t
    called = []
    monkeypatch.setattr(app, "_submit_new_target", lambda m: called.append(m) or True)
    try:
        app._send_user_message("hello agent, status?")
    finally:
        ev.set()
    assert called == []
    assert app._last_runtime_error is None
    assert "No agent selected" in (app._last_status or "")
