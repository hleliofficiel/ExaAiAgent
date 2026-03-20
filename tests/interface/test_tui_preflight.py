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
    app.scan_config["targets"] = [{"type": "web_application", "details": {}, "original": "https://example.com"}]

    def fake_check_docker_connection():
        raise RuntimeError("Docker not available")

    monkeypatch.setattr("exaaiagnt.interface.utils.check_docker_connection", fake_check_docker_connection)

    app._start_scan_if_ready()

    assert app._last_runtime_error == "Cannot start scan: Docker not available"
    assert app._scan_thread is None
