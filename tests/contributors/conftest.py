import json

import pytest

from exaaiagnt.contributors import db


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setenv("EXAAI_DATA_DIR", str(tmp_path))
    return tmp_path / "contributors.db"


def make_contributor(conn, github_id=1, login="octocat"):
    db.upsert_contributor(
        conn,
        github_id=github_id,
        login=login,
        name=login.title(),
        avatar_url=f"https://avatars.example/{login}",
        profile_url=f"https://github.com/{login}",
    )
    return github_id


def add_pr(
    conn,
    github_id,
    number,
    *,
    labels=None,
    title="A change",
    files=None,
    merged_at="2026-01-01T00:00:00Z",
):
    db.insert_event(
        conn,
        github_id=github_id,
        kind="pr_merged",
        ref=f"pr:test/repo#{number}",
        title=title,
        url=f"https://github.com/test/repo/pull/{number}",
        merged_at=merged_at,
        verified_at="2026-11-13T00:00:00Z",
        labels=json.dumps(labels or []),
        files=json.dumps(files or []),
    )


def add_review(conn, github_id, rid):
    db.insert_event(
        conn,
        github_id=github_id,
        kind="review",
        ref=f"review:{rid}",
        verified_at="2026-11-13T00:00:00Z",
    )


def add_comment(conn, github_id, cid, on_others=True):
    db.insert_event(
        conn,
        github_id=github_id,
        kind="issue_comment",
        ref=f"issue:1#comment-{cid}",
        verified_at="2026-11-13T00:00:00Z",
        on_others=1 if on_others else 0,
    )
