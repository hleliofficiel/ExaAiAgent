from exaaiagnt.contributors import db


def test_schema_created(temp_db):
    conn = db.connect()
    try:
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert {"contributors", "events", "achievements", "meta"} <= tables
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1
    finally:
        conn.close()


def test_upsert_event_idempotent(temp_db):
    conn = db.connect()
    try:
        from tests.contributors.conftest import make_contributor

        make_contributor(conn)
        assert db.insert_event(conn, github_id=1, kind="pr_merged", ref="pr:x#1", title="t") is True
        assert (
            db.insert_event(conn, github_id=1, kind="pr_merged", ref="pr:x#1", title="t2") is False
        )
        rows = conn.execute("SELECT * FROM events WHERE github_id=1").fetchall()
        assert len(rows) == 1
        assert rows[0]["title"] == "t2"  # metadata refreshed, no duplicate
    finally:
        conn.close()


def test_achievement_pk_and_source_check(temp_db):
    conn = db.connect()
    try:
        from tests.contributors.conftest import make_contributor

        make_contributor(conn)
        assert (
            db.award(conn, github_id=1, badge_id="first_contributor", source="auto", reason="r")
            is True
        )
        assert (
            db.award(conn, github_id=1, badge_id="first_contributor", source="auto", reason="r")
            is False
        )
        import sqlite3

        try:
            conn.execute(
                "INSERT INTO achievements(github_id, badge_id, source) VALUES (1,'x','bogus')"
            )
            raise AssertionError("CHECK constraint should reject bad source")
        except sqlite3.IntegrityError:
            pass
    finally:
        conn.close()


def test_env_override_path(temp_db):
    assert db.db_path().parent == temp_db.parent
    assert db.db_path().name == "contributors.db"
