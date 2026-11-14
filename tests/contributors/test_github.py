import io
import json
import urllib.error

import pytest

from exaaiagnt.contributors import github


class _Resp:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_get_user_parses(monkeypatch):
    monkeypatch.setenv("EXAAI_GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        github.urllib.request,
        "urlopen",
        lambda _req, timeout=4: _Resp(  # noqa: ARG005 - must accept timeout kwarg
            {"id": 42, "login": "octocat", "name": "Octo", "avatar_url": "a", "html_url": "p"}
        ),
    )
    u = github.get_user("octocat")
    assert u["github_id"] == 42
    assert u["login"] == "octocat"


def test_rate_limit_raises(monkeypatch):
    monkeypatch.delenv("EXAAI_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    def boom(req, timeout=4):
        raise urllib.error.HTTPError(req.full_url, 403, "rate", hdrs=None, fp=io.BytesIO(b"{}"))

    monkeypatch.setattr(github.urllib.request, "urlopen", boom)
    with pytest.raises(github.RateLimitError):
        github.get_user("octocat")


def test_http_500_raises_github_error(monkeypatch):
    monkeypatch.delenv("EXAAI_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    def boom(req, timeout=4):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", hdrs=None, fp=io.BytesIO(b"{}"))

    monkeypatch.setattr(github.urllib.request, "urlopen", boom)
    with pytest.raises(github.GitHubError):
        github.get_user("octocat")


def test_fetch_merged_prs_monkeypatched(monkeypatch):
    monkeypatch.setattr(
        github,
        "_get_json",
        lambda url, timeout=4: {  # noqa: ARG005 - signature must accept timeout kwarg
            "items": [
                {
                    "number": 1,
                    "title": "Fix bug",
                    "labels": [{"name": "bug"}],
                    "pull_request": {"html_url": "https://github.com/x/y/pull/1"},
                    "closed_at": "2026-01-01T00:00:00Z",
                    "user": {"login": "octocat", "id": 7},
                }
            ]
        }
        if "search" in url
        else [{"filename": "a.py", "status": "modified"}],
    )
    prs = github.fetch_merged_prs("x/y")
    assert prs[0]["author"] == "octocat"
    assert prs[0]["labels"] == ["bug"]
    assert prs[0]["files"] == [{"filename": "a.py", "status": "modified"}]
