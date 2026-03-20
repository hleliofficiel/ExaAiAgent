import sys

from exaaiagnt.interface.cli import should_use_live_display


def test_should_use_live_display_false_without_tty(monkeypatch) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    monkeypatch.setenv("TERM", "xterm-256color")
    assert should_use_live_display() is False


def test_should_use_live_display_false_for_dumb_term(monkeypatch) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("TERM", "dumb")
    assert should_use_live_display() is False


def test_should_use_live_display_true_for_real_tty(monkeypatch) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("TERM", "xterm-256color")
    assert should_use_live_display() is True
