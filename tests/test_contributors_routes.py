"""Route contract tests for the Contributor Achievement System dashboard API.

No network: engine.sync is monkeypatched; EXAAI_DATA_DIR points at a tmp dir.
"""

import os
from dataclasses import dataclass, field

import pytest
from fastapi.testclient import TestClient

from exaaiagnt.contributors import db, engine
from exaaiagnt.dashboard import server


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setenv("EXAAI_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("EXAAI_DASHBOARD_TOKEN", raising=False)
    return tmp_path / "contributors.db"


@pytest.fixture
def client(temp_db):
    return TestClient(server.app)


def _seed_earned(login="octocat", badge_id="first_contributor"):
    conn = db.connect()
    try:
        db.upsert_contributor(
            conn,
            github_id=1,
            login=login,
            name="Octo Cat",
            avatar_url="https://avatars.example/octocat",
            profile_url=f"https://github.com/{login}",
        )
        db.insert_event(
            conn,
            github_id=1,
            kind="pr_merged",
            ref="pr:test/repo#1",
            title="Add thing",
            url="https://github.com/test/repo/pull/1",
            merged_at="2026-01-01T00:00:00Z",
            verified_at="2026-11-13T00:00:00Z",
            files='[{"filename": "src/app.py", "status": "modified"}]',
        )
        engine.evaluate(1, conn=conn)
        conn.commit()
    finally:
        conn.close()


def test_list_contributors_empty(client):
    r = client.get("/api/contributors")
    assert r.status_code == 200
    assert r.json() == {"contributors": []}


def test_list_contributors_contract(client):
    _seed_earned()
    r = client.get("/api/contributors")
    assert r.status_code == 200
    data = r.json()["contributors"]
    assert len(data) == 1
    c = data[0]
    assert c["login"] == "octocat"
    assert c["name"] == "Octo Cat"
    assert c["level"] in {"Novice", "Contributor", "Veteran", "Maintainer", "Legend"}
    assert isinstance(c["points"], int)
    assert c["counts"]["merged_prs"] == 1
    assert any(b["id"] == "first_contributor" for b in c["badges"])
    badge = next(b for b in c["badges"] if b["id"] == "first_contributor")
    assert {"id", "name", "medal", "color", "awarded_at"} <= set(badge)


def test_get_contributor_404_and_200(client):
    assert client.get("/api/contributors/nobody").status_code == 404
    _seed_earned()
    r = client.get("/api/contributors/octocat")
    assert r.status_code == 200
    assert r.json()["login"] == "octocat"
    assert client.get("/api/contributors/bad login!").status_code in (400, 404, 422)


def test_achievements_catalog(client):
    r = client.get("/api/contributor-achievements")
    assert r.status_code == 200
    data = r.json()
    assert len(data["badges"]) == 10
    b = data["badges"][0]
    assert {"id", "name", "description", "color", "palette", "points", "criterion"} <= set(b)
    assert data["levels"] == {
        "Novice": 0,
        "Contributor": 100,
        "Veteran": 300,
        "Maintainer": 600,
        "Legend": 1000,
    }


@dataclass
class _FakeReport:
    repo: str = "o/n"
    user: str | None = None
    prs_seen: int = 2
    events_added: int = 3
    reviews_added: int = 1
    comments_added: int = 1
    achievements_awarded: list = field(default_factory=lambda: ["first_contributor"])
    errors: list = field(default_factory=list)
    rate_limited: bool = False


def test_sync_monkeypatched_no_network(client, monkeypatch):
    monkeypatch.setattr(server.contrib_engine, "sync", lambda *a, **k: _FakeReport())
    r = client.post("/api/contributors/sync", json={"user": None, "repo": "o/n"})
    assert r.status_code == 200
    data = r.json()
    assert data["contributors_seen"] == 0
    assert data["events_added"] == 3
    assert isinstance(data["achievements_awarded"], list)


def test_sync_rate_limited_returns_429(client, monkeypatch):
    monkeypatch.setattr(
        server.contrib_engine, "sync", lambda *a, **k: _FakeReport(rate_limited=True)
    )
    r = client.post("/api/contributors/sync", json={})
    assert r.status_code == 429
    assert "EXAAI_GITHUB_TOKEN" in r.json()["detail"]


def test_sync_bad_repo_400(client):
    assert client.post("/api/contributors/sync", json={"repo": "nope"}).status_code == 400


def test_grant_and_revoke_flow(client):
    r = client.post("/api/contributors/grant", json={"login": "octocat", "badge_id": "core_maintainer"})
    assert r.status_code == 200
    assert r.json()["badge_id"] == "core_maintainer"
    assert client.post(
        "/api/contributors/grant", json={"login": "octocat", "badge_id": "nope"}
    ).status_code == 400
    assert client.post(
        "/api/contributors/revoke", json={"login": "octocat", "badge_id": "core_maintainer"}
    ).status_code == 200
    assert client.post(
        "/api/contributors/revoke", json={"login": "octocat", "badge_id": "core_maintainer"}
    ).status_code == 404


def test_badge_svg_only_for_earned(client):
    assert client.get("/contributors/badge/octocat/first_contributor.svg").status_code == 404
    _seed_earned()
    r = client.get("/contributors/badge/octocat/first_contributor.svg")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")
    assert "<svg" in r.text
    assert client.get("/contributors/badge/octocat/core_maintainer.svg").status_code == 404


def test_contributors_page_200(client):
    r = client.get("/contributors")
    assert r.status_code == 200
    assert "Contributor Achievement System" in r.text


def test_api_routes_require_token_when_set(client, monkeypatch):
    monkeypatch.setenv("EXAAI_DASHBOARD_TOKEN", "sekret")
    r = client.get("/api/contributors")
    assert r.status_code == 401
    r = client.get("/api/contributors", headers={"Authorization": "Bearer sekret"})
    assert r.status_code == 200
    # Public routes stay public
    assert client.get("/contributors").status_code == 200
    assert client.get("/contributors/badge/octocat/first_contributor.svg").status_code == 404
