from exaaiagnt.contributors import db
from exaaiagnt.interface.contributors_cli import export_markdown
from tests.contributors.conftest import add_pr, make_contributor


def test_export_lists_only_earned_badges(temp_db, capsys):
    conn = db.connect()
    make_contributor(conn, github_id=7, login="octocat")
    add_pr(conn, 7, 1, files=[{"filename": "a.py", "status": "modified"}])
    from exaaiagnt.contributors import engine

    engine.evaluate(7, conn=conn)
    conn.commit()
    conn.close()

    md = export_markdown("octocat")
    assert "first_contributor.svg" in md
    assert "code_contributor.svg" in md
    assert "bug_hunter.svg" not in md
    assert "core_maintainer.svg" not in md
    assert "https://github.com/hleliofficiel/ExaAiAgent/raw/main/contributor_system/badges/" in md
    assert "octocat" in md


def test_export_unknown_user(temp_db):
    md = export_markdown("ghost")
    assert "no contributor data" in md
