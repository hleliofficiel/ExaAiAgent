"""All user-visible version strings must agree with pyproject.toml.

pyproject.toml is the single source of truth; exaaiagnt.version reads it
via importlib.metadata with a hard-coded fallback for uninstalled runs.
"""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version = "(\d+\.\d+\.\d+)"', text, re.MULTILINE)
    assert m, "version field not found in pyproject.toml"
    return m.group(1)


def _fallback_version() -> str:
    text = (ROOT / "exaaiagnt" / "version.py").read_text(encoding="utf-8")
    m = re.search(r'__version__ = "(\d+\.\d+\.\d+)"', text)
    assert m, "fallback __version__ not found in exaaiagnt/version.py"
    return m.group(1)


def test_fallback_matches_pyproject() -> None:
    assert _fallback_version() == _pyproject_version()


def test_runtime_version_matches_pyproject() -> None:
    from exaaiagnt.version import __version__

    assert __version__ == _pyproject_version()


def test_readme_badge_matches_pyproject() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"version-(\d+\.\d+\.\d+)-", text)
    assert m, "version badge not found in README.md"
    assert m.group(1) == _pyproject_version()


def test_changelog_latest_matches_pyproject() -> None:
    text = (ROOT / "docs" / "CHANGELOG.md").read_text(encoding="utf-8")
    m = re.search(r"## \[(\d+\.\d+\.\d+)\]", text)
    assert m, "no release entry found in docs/CHANGELOG.md"
    assert m.group(1) == _pyproject_version()


def test_contributors_version_matches_pyproject() -> None:
    from exaaiagnt.contributors import __version__ as contributors_version

    assert contributors_version == _pyproject_version()


def test_no_hardcoded_version_in_banner_or_user_agents() -> None:
    """Banner and User-Agent strings must derive from the single source."""
    stale = []
    for rel in (
        "exaaiagnt/interface/cli.py",
        "exaaiagnt/intelligence/feeds.py",
        "exaaiagnt/contributors/github.py",
        "exaaiagnt/tools/har_io.py",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        stale.extend(
            f"{rel}: hard-coded version {m.group(1)}"
            for m in re.finditer(r"[vV]?(\d+\.\d+\.\d+)", text)
        )
    assert not stale, "; ".join(stale)
