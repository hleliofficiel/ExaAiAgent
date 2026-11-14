"""Evaluation engine for the Contributor Achievement System.

Deterministic: badge criteria are pure functions of stored events. Sync never
revokes achievements; manual grants (source='manual') are never auto-revoked.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from exaaiagnt.contributors import badges as badge_defs
from exaaiagnt.contributors import db, github


BUG_TITLE_RE = re.compile(r"(?i)(fix|bug|hotfix|security fix|critical|cve)")

DOC_EXTS = (".md", ".markdown", ".rst", ".txt")
CODE_EXTS = (".py", ".ts")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _files_of(event) -> list[dict]:
    raw = event["files"] if "files" in event.keys() else None  # noqa: SIM118 - sqlite3.Row lacks __contains__
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return data if isinstance(data, list) else []


def _labels_of(event) -> list[str]:
    raw = event["labels"] if "labels" in event.keys() else None  # noqa: SIM118 - sqlite3.Row lacks __contains__
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return [str(raw)]
    return [str(x).lower() for x in data] if isinstance(data, list) else []


def _is_doc_file(path: str) -> bool:
    p = path.lower()
    return p.startswith("docs/") or p.endswith(DOC_EXTS)


def _is_test_file(path: str) -> bool:
    p = path.lower()
    return p.startswith(("tests/", "test")) or "/tests/" in p


def _pr_is_docs_only(event) -> bool:
    files = _files_of(event)
    paths = [f.get("filename", "") for f in files]
    if not paths:
        return False
    if any(p.lower().endswith(CODE_EXTS) for p in paths):
        return False
    return all(_is_doc_file(p) for p in paths) and any(_is_doc_file(p) for p in paths)


def _pr_is_code(event) -> bool:
    files = _files_of(event)
    if not files:
        # No file metadata available - count the merged PR as code (documented fallback).
        return True
    return not _pr_is_docs_only(event)


def _pr_is_bug(event) -> bool:
    labels = _labels_of(event)
    if "bug" in labels:
        return True
    title = (event["title"] or "") if "title" in event.keys() else ""  # noqa: SIM118
    return bool(BUG_TITLE_RE.search(title or ""))


def _pr_is_feature(event) -> bool:
    if "feature" in _labels_of(event):
        return True
    return any((f.get("status") == "added") for f in _files_of(event))


def _pr_touches_tests(event) -> bool:
    return any(_is_test_file(f.get("filename", "")) for f in _files_of(event))


@dataclass
class SyncReport:
    repo: str
    user: str | None
    prs_seen: int = 0
    events_added: int = 0
    reviews_added: int = 0
    comments_added: int = 0
    achievements_awarded: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    rate_limited: bool = False

    def to_dict(self) -> dict:
        return {
            "repo": self.repo,
            "user": self.user,
            "prs_seen": self.prs_seen,
            "events_added": self.events_added,
            "reviews_added": self.reviews_added,
            "comments_added": self.comments_added,
            "achievements_awarded": list(self.achievements_awarded),
            "errors": list(self.errors),
            "rate_limited": self.rate_limited,
        }


def _ensure_contributor(conn, user: dict) -> int:
    # Reuse an existing row by login when the GitHub id differs
    # (e.g. GraphQL Bot actors have no databaseId). Keeps FK references stable.
    row = conn.execute(
        "SELECT github_id FROM contributors WHERE login=? COLLATE NOCASE",
        (user["login"],),
    ).fetchone()
    if row:
        # refresh immutable name/avatar opportunistically
        conn.execute(
            "UPDATE contributors SET name=COALESCE(?, name), avatar_url=COALESCE(?, avatar_url), profile_url=COALESCE(?, profile_url) WHERE github_id=?",
            (user.get("name"), user.get("avatar_url"), user.get("profile_url"), row["github_id"]),
        )
        return int(row["github_id"])
    gid = int(user["github_id"])
    db.upsert_contributor(
        conn,
        github_id=gid,
        login=user["login"],
        name=user.get("name"),
        avatar_url=user.get("avatar_url"),
        profile_url=user.get("profile_url"),
    )
    return gid


def sync(  # noqa: PLR0912, PLR0915 - linear orchestration of fetch/store/evaluate phases
    repo: str = github.DEFAULT_REPO, user: str | None = None, since: str | None = None
) -> SyncReport:
    report = SyncReport(repo=repo, user=user)
    verified = _now()
    conn = db.connect()
    try:
        try:
            prs = github.fetch_merged_prs(repo, since=since)
        except github.RateLimitError as e:
            report.rate_limited = True
            report.errors.append(str(e))
            prs = []
        except github.GitHubError as e:
            report.errors.append(str(e))
            prs = []

        report.prs_seen = len(prs)
        touched_ids: set[int] = set()
        for pr in prs:
            author = pr.get("author")
            if user and (not author or author.lower() != user.lower()):
                continue
            gid = pr.get("author_id")
            info = pr.get("author_info")
            if info is None and author:
                try:
                    info = github.get_user(author)
                    gid = info["github_id"]
                except github.GitHubError as e:
                    report.errors.append(f"user lookup failed for {author}: {e}")
                    if gid is None:
                        continue
            if gid is None:
                continue
            gid = int(gid)
            if info is None:
                info = {
                    "github_id": gid,
                    "login": author or str(gid),
                    "name": None,
                    "avatar_url": None,
                    "profile_url": None,
                }
            _ensure_contributor(conn, info)
            touched_ids.add(gid)
            added = db.insert_event(
                conn,
                github_id=gid,
                kind="pr_merged",
                ref=f"pr:{repo}#{pr.get('number')}",
                title=pr.get("title"),
                url=pr.get("url"),
                merged_at=pr.get("merged_at"),
                verified_at=verified,
                weight=1,
                labels=json.dumps(pr.get("labels", [])),
                files=json.dumps(pr.get("files", [])),
            )
            report.events_added += 1 if added else 0

        # If a specific user was requested their reviews/comments are synced too,
        # even when they authored no merged PRs.
        targets: list[str] = [user] if user else []
        if not targets:
            targets = [r["login"] for r in db.all_contributors(conn)]
        for login in targets:
            row = conn.execute(
                "SELECT github_id FROM contributors WHERE login=? COLLATE NOCASE",
                (login,),
            ).fetchone()
            if row:
                gid = int(row["github_id"])
            else:
                try:
                    info = github.get_user(login)
                except github.RateLimitError as e:
                    report.rate_limited = True
                    report.errors.append(str(e))
                    continue
                except github.GitHubError as e:
                    report.errors.append(f"user lookup failed for {login}: {e}")
                    continue
                gid = _ensure_contributor(conn, info)
            try:
                reviews = github.fetch_reviews(repo, login)
            except github.RateLimitError as e:
                report.rate_limited = True
                report.errors.append(str(e))
                reviews = []
            except github.GitHubError as e:
                report.errors.append(f"reviews fetch failed for {login}: {e}")
                reviews = []
            for r in reviews:
                added = db.insert_event(
                    conn,
                    github_id=gid,
                    kind="review",
                    ref=r["ref"],
                    title=r.get("title"),
                    url=r.get("url"),
                    merged_at=None,
                    verified_at=verified,
                    weight=1,
                )
                report.reviews_added += 1 if added else 0
            try:
                comments = github.fetch_issue_comments(repo, login)
            except github.RateLimitError as e:
                report.rate_limited = True
                report.errors.append(str(e))
                comments = []
            except github.GitHubError as e:
                report.errors.append(f"comments fetch failed for {login}: {e}")
                comments = []
            for c in comments:
                added = db.insert_event(
                    conn,
                    github_id=gid,
                    kind="issue_comment",
                    ref=c["ref"],
                    title=c.get("title"),
                    url=c.get("url"),
                    merged_at=None,
                    verified_at=verified,
                    weight=1,
                    on_others=1 if c.get("on_others") else 0,
                )
                report.comments_added += 1 if added else 0

        # Evaluate achievements for everyone touched/known.
        for row in db.all_contributors(conn):
            new = evaluate(row["github_id"], conn=conn)
            report.achievements_awarded.extend(new)

        db.set_meta(conn, "last_sync", verified)
        db.set_meta(conn, "last_sync_repo", repo)
        conn.commit()
        return report
    finally:
        conn.close()


def _criteria_met(badge_id: str, events, pr_events) -> tuple[bool, str]:  # noqa: PLR0911 - flat dispatch, one return per badge
    prs = pr_events
    if badge_id == "first_contributor":
        return (len(prs) >= 1, f"{len(prs)} merged PR(s)")
    if badge_id == "code_contributor":
        n = sum(1 for e in prs if _pr_is_code(e))
        return (n >= 1, f"{n} non-docs merged PR(s)")
    if badge_id == "bug_hunter":
        n = sum(1 for e in prs if _pr_is_bug(e))
        return (n >= 1, f"{n} bug-like merged PR(s)")
    if badge_id == "documentation_hero":
        n = sum(1 for e in prs if _pr_is_docs_only(e))
        return (n >= 1, f"{n} docs-only merged PR(s)")
    if badge_id == "feature_builder":
        n = sum(1 for e in prs if _pr_is_feature(e))
        return (n >= 1, f"{n} feature merged PR(s)")
    if badge_id == "testing_champion":
        n = sum(1 for e in prs if _pr_touches_tests(e))
        return (n >= 1, f"{n} merged PR(s) touching tests")
    if badge_id == "top_contributor":
        return (len(prs) >= 5, f"{len(prs)} merged PR(s) (need 5)")
    if badge_id == "community_hero":
        n = sum(1 for e in events if e["kind"] in ("review", "issue_comment"))
        return (n >= 5, f"{n} review/comment event(s) (need 5)")
    if badge_id == "open_source_advocate":
        others = sum(1 for e in events if e["kind"] == "issue_comment" and e["on_others"])
        return (
            others >= 3 and len(prs) >= 1,
            f"{others} comment(s) on others' issues (need 3) + {len(prs)} merged PR(s)",
        )
    return (False, "unknown badge")


def evaluate(github_id: int, conn=None) -> list[str]:
    """Evaluate auto badges for a contributor. Returns newly awarded badge ids."""
    own = conn is None
    conn = conn or db.connect()
    try:
        events = db.get_events(conn, github_id)
        pr_events = [e for e in events if e["kind"] == "pr_merged"]
        awarded: list[str] = []
        for badge in badge_defs.BADGES:
            if badge.manual_only:
                continue
            met, reason = _criteria_met(badge.id, events, pr_events)
            if met and db.award(
                conn, github_id=github_id, badge_id=badge.id, source="auto", reason=reason
            ):
                awarded.append(badge.id)
        if own:
            conn.commit()
        return awarded
    finally:
        if own:
            conn.close()


def points(github_id: int, conn=None) -> int:
    own = conn is None
    conn = conn or db.connect()
    try:
        events = db.get_events(conn, github_id)
        achievements = db.get_achievements(conn, github_id)
        total = 0
        for e in events:
            if e["kind"] == "pr_merged":
                total += badge_defs.PR_POINTS
            elif e["kind"] == "review":
                total += badge_defs.REVIEW_POINTS
            elif e["kind"] == "issue_comment":
                total += badge_defs.COMMENT_POINTS
        badge_points = {b.id: b.points for b in badge_defs.BADGES}
        for a in achievements:
            total += badge_points.get(a["badge_id"], 0)
        return total
    finally:
        if own:
            conn.close()


def level(points_value: int) -> str:
    return badge_defs.level_for_points(points_value)


def profile(login: str) -> dict:
    conn = db.connect()
    try:
        row = db.get_contributor_by_login(conn, login)
        if not row:
            return {"login": login, "found": False}
        events = db.get_events(conn, row["github_id"])
        achievements = db.get_achievements(conn, row["github_id"])
        pts = points(row["github_id"], conn=conn)
        badge_ids = [a["badge_id"] for a in achievements]
        return {
            "found": True,
            "github_id": row["github_id"],
            "login": row["login"],
            "name": row["name"],
            "avatar_url": row["avatar_url"],
            "profile_url": row["profile_url"],
            "first_seen": row["first_seen"],
            "points": pts,
            "level": level(pts),
            "events": {
                "pr_merged": sum(1 for e in events if e["kind"] == "pr_merged"),
                "review": sum(1 for e in events if e["kind"] == "review"),
                "issue_comment": sum(1 for e in events if e["kind"] == "issue_comment"),
            },
            "badges": badge_ids,
            "achievements": [
                {
                    "badge_id": a["badge_id"],
                    "awarded_at": a["awarded_at"],
                    "source": a["source"],
                    "reason": a["reason"],
                }
                for a in achievements
            ],
        }
    finally:
        conn.close()


def grant(login: str, badge_id: str, reason: str | None = None, by: str = "admin") -> dict:
    if badge_id not in badge_defs.BADGES_BY_ID:
        raise ValueError(f"unknown badge_id: {badge_id}")
    conn = db.connect()
    try:
        row = db.get_contributor_by_login(conn, login)
        if not row:
            # Create a stub contributor record so grants work before first sync.
            import zlib

            gid = -(zlib.crc32(login.lower().encode()) + 1)  # deterministic negative stub id
            db.upsert_contributor(conn, github_id=gid, login=login)
            row = db.get_contributor_by_login(conn, login)
        db.award(
            conn,
            github_id=row["github_id"],
            badge_id=badge_id,
            source="manual",
            reason=reason or f"granted by {by}",
        )
        conn.commit()
        return {"login": login, "badge_id": badge_id, "source": "manual"}
    finally:
        conn.close()


def revoke(login: str, badge_id: str) -> bool:
    conn = db.connect()
    try:
        row = db.get_contributor_by_login(conn, login)
        if not row:
            return False
        ok = db.revoke_achievement(conn, github_id=row["github_id"], badge_id=badge_id)
        conn.commit()
        return ok
    finally:
        conn.close()
