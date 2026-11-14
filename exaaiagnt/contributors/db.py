"""SQLite store for the Contributor Achievement System.

Stdlib sqlite3 only. Path resolution order:

1. ``$EXAAI_DATA_DIR/contributors.db`` (env override, used by tests)
2. ``$XDG_DATA_HOME/exaai-agent/contributors.db``
3. ``~/.local/share/exaai-agent/contributors.db``

WAL mode, foreign keys ON, UNIQUE(github_id, kind, ref) for idempotent
re-syncs. Monotonic writes; achievements are never deleted by sync.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS contributors (
    github_id INTEGER PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    name TEXT,
    avatar_url TEXT,
    profile_url TEXT,
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    github_id INTEGER NOT NULL REFERENCES contributors(github_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('pr_merged','review','issue_comment')),
    ref TEXT NOT NULL,
    title TEXT,
    url TEXT,
    merged_at TEXT,
    verified_at TEXT,
    weight INTEGER NOT NULL DEFAULT 1,
    labels TEXT,
    files TEXT,
    on_others INTEGER NOT NULL DEFAULT 0,
    UNIQUE(github_id, kind, ref)
);

CREATE TABLE IF NOT EXISTS achievements (
    github_id INTEGER NOT NULL REFERENCES contributors(github_id) ON DELETE CASCADE,
    badge_id TEXT NOT NULL,
    awarded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    source TEXT NOT NULL CHECK(source IN ('auto','manual')),
    reason TEXT,
    PRIMARY KEY(github_id, badge_id)
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def db_path() -> Path:
    override = os.environ.get("EXAAI_DATA_DIR")
    if override:
        base = Path(override)
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        base = (
            Path(xdg) / "exaai-agent" if xdg else Path.home() / ".local" / "share" / "exaai-agent"
        )
    base.mkdir(parents=True, exist_ok=True)
    return base / "contributors.db"


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    p = Path(path) if path else db_path()
    conn = sqlite3.connect(str(p), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    return conn


def upsert_contributor(
    conn: sqlite3.Connection,
    *,
    github_id: int,
    login: str,
    name: str | None = None,
    avatar_url: str | None = None,
    profile_url: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO contributors(github_id, login, name, avatar_url, profile_url)
        VALUES (?,?,?,?,?)
        ON CONFLICT(github_id) DO UPDATE SET
            login=excluded.login,
            name=COALESCE(excluded.name, contributors.name),
            avatar_url=COALESCE(excluded.avatar_url, contributors.avatar_url),
            profile_url=COALESCE(excluded.profile_url, contributors.profile_url)
        """,
        (github_id, login, name, avatar_url, profile_url),
    )


def insert_event(
    conn: sqlite3.Connection,
    *,
    github_id: int,
    kind: str,
    ref: str,
    **kwargs,
) -> bool:
    """Strict insert-or-ignore. Returns True iff a new row was created."""
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO events(github_id, kind, ref, title, url, merged_at, verified_at,
                                     weight, labels, files, on_others)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            github_id,
            kind,
            ref,
            kwargs.get("title"),
            kwargs.get("url"),
            kwargs.get("merged_at"),
            kwargs.get("verified_at"),
            kwargs.get("weight", 1),
            kwargs.get("labels"),
            kwargs.get("files"),
            kwargs.get("on_others", 0),
        ),
    )
    if cur.rowcount == 1:
        return True
    # Row exists - refresh mutable metadata, keep original first-seen data.
    conn.execute(
        """
        UPDATE events SET
            title=COALESCE(?, title), url=COALESCE(?, url),
            merged_at=COALESCE(?, merged_at), verified_at=COALESCE(?, verified_at),
            labels=COALESCE(?, labels), files=COALESCE(?, files),
            on_others=MAX(?, on_others)
        WHERE github_id=? AND kind=? AND ref=?
        """,
        (
            kwargs.get("title"),
            kwargs.get("url"),
            kwargs.get("merged_at"),
            kwargs.get("verified_at"),
            kwargs.get("labels"),
            kwargs.get("files"),
            kwargs.get("on_others", 0),
            github_id,
            kind,
            ref,
        ),
    )
    return False


def award(
    conn: sqlite3.Connection,
    *,
    github_id: int,
    badge_id: str,
    source: str,
    reason: str | None = None,
) -> bool:
    """Insert achievement if absent. Returns True iff newly awarded."""
    cur = conn.execute(
        "INSERT OR IGNORE INTO achievements(github_id, badge_id, source, reason) VALUES (?,?,?,?)",
        (github_id, badge_id, source, reason),
    )
    return cur.rowcount == 1


def revoke_achievement(conn: sqlite3.Connection, *, github_id: int, badge_id: str) -> bool:
    cur = conn.execute(
        "DELETE FROM achievements WHERE github_id=? AND badge_id=?", (github_id, badge_id)
    )
    return cur.rowcount == 1


def get_contributor_by_login(conn: sqlite3.Connection, login: str):
    return conn.execute(
        "SELECT * FROM contributors WHERE login=? COLLATE NOCASE", (login,)
    ).fetchone()


def get_events(conn: sqlite3.Connection, github_id: int, kind: str | None = None):
    if kind:
        return conn.execute(
            "SELECT * FROM events WHERE github_id=? AND kind=? ORDER BY id", (github_id, kind)
        ).fetchall()
    return conn.execute(
        "SELECT * FROM events WHERE github_id=? ORDER BY id", (github_id,)
    ).fetchall()


def get_achievements(conn: sqlite3.Connection, github_id: int):
    return conn.execute(
        "SELECT * FROM achievements WHERE github_id=? ORDER BY awarded_at, badge_id", (github_id,)
    ).fetchall()


def all_contributors(conn: sqlite3.Connection):
    return conn.execute("SELECT * FROM contributors ORDER BY login COLLATE NOCASE").fetchall()


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def get_meta(conn: sqlite3.Connection, key: str):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None
