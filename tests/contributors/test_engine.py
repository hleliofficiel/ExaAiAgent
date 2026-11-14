import pytest

from exaaiagnt.contributors import badges, db, engine
from tests.contributors.conftest import add_comment, add_pr, add_review, make_contributor


def _fresh(conn):
    make_contributor(conn)


def test_first_contributor_awarded(temp_db):
    conn = db.connect()
    _fresh(conn)
    add_pr(conn, 1, 1, files=[{"filename": "src/app.py", "status": "modified"}])
    awarded = engine.evaluate(1, conn=conn)
    assert "first_contributor" in awarded
    assert "code_contributor" in awarded


def test_docs_only_pr_awards_docs_not_code(temp_db):
    conn = db.connect()
    _fresh(conn)
    add_pr(conn, 1, 1, files=[{"filename": "docs/guide.md", "status": "modified"}])
    awarded = engine.evaluate(1, conn=conn)
    assert "documentation_hero" in awarded
    assert "code_contributor" not in awarded


def test_docs_pr_with_py_changes_not_docs_only(temp_db):
    conn = db.connect()
    _fresh(conn)
    add_pr(
        conn,
        1,
        1,
        files=[
            {"filename": "docs/guide.md", "status": "modified"},
            {"filename": "exaaiagnt/x.py", "status": "modified"},
        ],
    )
    awarded = engine.evaluate(1, conn=conn)
    assert "documentation_hero" not in awarded
    assert "code_contributor" in awarded


def test_bug_hunter_by_label_and_title(temp_db):
    conn = db.connect()
    _fresh(conn)
    add_pr(
        conn,
        1,
        1,
        labels=["bug"],
        title="tweak",
        files=[{"filename": "a.py", "status": "modified"}],
    )
    awarded = engine.evaluate(1, conn=conn)
    assert "bug_hunter" in awarded


def test_bug_hunter_by_title_regex(temp_db):
    conn = db.connect()
    _fresh(conn)
    add_pr(
        conn,
        1,
        1,
        title="Hotfix: CVE-2026-1234 in parser",
        files=[{"filename": "a.py", "status": "modified"}],
    )
    awarded = engine.evaluate(1, conn=conn)
    assert "bug_hunter" in awarded


def test_feature_builder_by_added_file(temp_db):
    conn = db.connect()
    _fresh(conn)
    add_pr(conn, 1, 1, files=[{"filename": "new_module.py", "status": "added"}])
    awarded = engine.evaluate(1, conn=conn)
    assert "feature_builder" in awarded


def test_feature_builder_by_label(temp_db):
    conn = db.connect()
    _fresh(conn)
    add_pr(conn, 1, 1, labels=["feature"], files=[{"filename": "a.py", "status": "modified"}])
    awarded = engine.evaluate(1, conn=conn)
    assert "feature_builder" in awarded


def test_testing_champion(temp_db):
    conn = db.connect()
    _fresh(conn)
    add_pr(conn, 1, 1, files=[{"filename": "tests/test_x.py", "status": "modified"}])
    awarded = engine.evaluate(1, conn=conn)
    assert "testing_champion" in awarded


def test_top_contributor_needs_five(temp_db):
    conn = db.connect()
    _fresh(conn)
    for i in range(4):
        add_pr(conn, 1, i + 1, files=[{"filename": "a.py", "status": "modified"}])
    assert "top_contributor" not in engine.evaluate(1, conn=conn)
    add_pr(conn, 1, 5, files=[{"filename": "a.py", "status": "modified"}])
    assert "top_contributor" in engine.evaluate(1, conn=conn)


def test_community_hero(temp_db):
    conn = db.connect()
    _fresh(conn)
    for i in range(3):
        add_review(conn, 1, i)
    for i in range(2):
        add_comment(conn, 1, i)
    assert "community_hero" in engine.evaluate(1, conn=conn)


def test_open_source_advocate_needs_others_and_pr(temp_db):
    conn = db.connect()
    _fresh(conn)
    for i in range(3):
        add_comment(conn, 1, i, on_others=True)
    # no merged PR yet -> not awarded
    assert "open_source_advocate" not in engine.evaluate(1, conn=conn)
    add_pr(conn, 1, 1, files=[{"filename": "a.py", "status": "modified"}])
    assert "open_source_advocate" in engine.evaluate(1, conn=conn)


def test_open_source_advocate_ignores_own_issues(temp_db):
    conn = db.connect()
    _fresh(conn)
    for i in range(3):
        add_comment(conn, 1, i, on_others=False)
    add_pr(conn, 1, 1, files=[{"filename": "a.py", "status": "modified"}])
    assert "open_source_advocate" not in engine.evaluate(1, conn=conn)


def test_manual_grant_never_revoked_by_resync(temp_db):
    conn = db.connect()
    _fresh(conn)
    db.award(conn, github_id=1, badge_id="core_maintainer", source="manual", reason="test")
    engine.evaluate(1, conn=conn)
    got = db.get_achievements(conn, 1)
    assert any(a["badge_id"] == "core_maintainer" for a in got)


def test_sync_does_not_revoke(temp_db, monkeypatch):
    from exaaiagnt.contributors import github

    conn = db.connect()
    _fresh(conn)
    db.award(conn, github_id=1, badge_id="core_maintainer", source="manual", reason="keep")
    conn.commit()
    conn.close()

    monkeypatch.setattr(github, "fetch_merged_prs", lambda *_a, **_k: [])
    monkeypatch.setattr(github, "fetch_reviews", lambda *_a, **_k: [])
    monkeypatch.setattr(github, "fetch_issue_comments", lambda *_a, **_k: [])
    monkeypatch.setattr(
        github,
        "get_user",
        lambda login: {
            "github_id": 1,
            "login": login,
            "name": None,
            "avatar_url": None,
            "profile_url": None,
        },
    )
    report = engine.sync(repo="test/repo", user="octocat")
    conn = db.connect()
    got = db.get_achievements(conn, 1)
    assert any(a["badge_id"] == "core_maintainer" for a in got)
    assert report.rate_limited is False


def test_points_and_levels(temp_db):
    conn = db.connect()
    _fresh(conn)
    for i in range(5):
        add_pr(conn, 1, i + 1, files=[{"filename": "a.py", "status": "modified"}])
    engine.evaluate(1, conn=conn)
    pts = engine.points(1, conn=conn)
    # 5 merged PRs x 50 = 250; awards: first + code + top = 25 + 25 + 100 = 150 -> 400
    assert pts == 400
    assert engine.level(pts) == "Veteran"
    assert engine.level(0) == "Novice"
    assert engine.level(100) == "Contributor"
    assert engine.level(600) == "Maintainer"
    assert engine.level(1000) == "Legend"


def test_evaluate_idempotent(temp_db):
    conn = db.connect()
    _fresh(conn)
    add_pr(conn, 1, 1, files=[{"filename": "a.py", "status": "added"}])
    first = engine.evaluate(1, conn=conn)
    second = engine.evaluate(1, conn=conn)
    assert first
    assert second == []


def test_grant_revoke_cycle(temp_db):
    engine.grant("octocat", "core_maintainer", reason="lead", by="boss")
    p = engine.profile("octocat")
    # stub contributor was created deterministically
    assert "core_maintainer" in p["badges"]
    manual = [a for a in p["achievements"] if a["badge_id"] == "core_maintainer"]
    assert manual[0]["source"] == "manual"
    assert engine.revoke("octocat", "core_maintainer") is True
    assert engine.revoke("octocat", "core_maintainer") is False


def test_grant_unknown_badge_raises(temp_db):
    with pytest.raises(ValueError, match="unknown badge_id"):
        engine.grant("octocat", "not_a_badge")


def test_profile_not_found(temp_db):
    assert engine.profile("ghost") == {"login": "ghost", "found": False}


def test_all_badges_have_criteria_and_unique_ids():
    ids = [b.id for b in badges.BADGES]
    assert len(ids) == 10
    assert len(set(ids)) == 10
    for b in badges.BADGES:
        assert b.criteria
        assert b.points > 0
        assert b.name
    assert b.description
