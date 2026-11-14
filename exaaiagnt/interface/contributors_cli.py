"""`exaai contributors` CLI subgroup.

Registered from exaaiagnt/interface/main.py as a light branch (like `exaai mcp`),
so it never touches the scan/docker/TUI path.
"""

from __future__ import annotations

import argparse
import json
import sys

from rich.console import Console
from rich.table import Table

from exaaiagnt.contributors import badges as badge_defs
from exaaiagnt.contributors import db, engine
from exaaiagnt.contributors.github import DEFAULT_REPO


console = Console()
RAW_BASE = "https://github.com/hleliofficiel/ExaAiAgent/raw/main/contributor_system/badges"


def _print_profile(p: dict) -> int:
    if not p.get("found"):
        console.print(
            f"[yellow]No contributor data for '{p.get('login')}' - "
            "run 'exaai contributors sync' first.[/yellow]"
        )
        return 1
    console.print(f"[bold cyan]{p['login']}[/bold cyan] - {p.get('name') or ''}")
    console.print(f"Level: [bold]{p['level']}[/bold]  Points: {p['points']}")
    ev = p["events"]
    console.print(
        f"Events: {ev['pr_merged']} merged PRs, {ev['review']} reviews, "
        f"{ev['issue_comment']} issue comments"
    )
    if p["achievements"]:
        console.print("Badges:")
        for a in p["achievements"]:
            console.print(
                f"  - {a['badge_id']} ({a['source']}, {a['awarded_at']}) - {a.get('reason') or ''}"
            )
    else:
        console.print("Badges: none yet")
    return 0


def _cmd_list(args) -> int:
    conn = db.connect()
    try:
        rows = db.all_contributors(conn)
        if not rows:
            console.print("[yellow]No contributors yet - run 'exaai contributors sync'.[/yellow]")
            return 0
        table = Table(title=f"Contributors ({args.repo})")
        table.add_column("Login", style="cyan")
        table.add_column("Level")
        table.add_column("Points", justify="right")
        table.add_column("Badges", justify="right")
        for row in rows:
            pts = engine.points(row["github_id"], conn=conn)
            ach = db.get_achievements(conn, row["github_id"])
            table.add_row(row["login"], engine.level(pts), str(pts), str(len(ach)))
        console.print(table)
        return 0
    finally:
        conn.close()


def _cmd_badges(_args) -> int:
    table = Table(title="Contributor Badges")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Points", justify="right")
    table.add_column("Criteria")
    for b in badge_defs.BADGES:
        crit = b.criteria
        if crit.get("manual"):
            rule = "manual grant only"
        elif crit.get("kind") == "pr_merged":
            rule = f"merged PR >= {crit.get('min', 1)}" + (
                f" ({crit['rule']})" if crit.get("rule") else ""
            )
        elif crit.get("kind") == "review_or_comment":
            rule = f">= {crit.get('min')} reviews or issue comments"
        elif crit.get("kind") == "issue_comment":
            rule = f">= {crit.get('min_others')} comments on others' issues + >= 1 merged PR"
        else:
            rule = json.dumps(crit)
        table.add_row(b.id, b.name, str(b.points), rule)
    console.print(table)
    console.print("Levels: " + ", ".join(f"{n} {t}+" for n, t in badge_defs.LEVELS))
    return 0


def _cmd_profile(args) -> int:
    return _print_profile(engine.profile(args.login))


def _cmd_sync(args) -> int:
    report = engine.sync(repo=args.repo, user=args.user, since=args.since)
    console.print(f"[bold]Sync report[/bold] repo={report.repo} user={report.user or '*'}")
    console.print(f"  merged PRs seen: {report.prs_seen}")
    console.print(
        f"  events added: {report.events_added} "
        f"(reviews {report.reviews_added}, comments {report.comments_added})"
    )
    if report.achievements_awarded:
        console.print(f"  newly awarded: {', '.join(report.achievements_awarded)}")
    else:
        console.print("  newly awarded: none")
    if report.rate_limited:
        console.print(
            "[yellow]  rate-limited by GitHub API - set EXAAI_GITHUB_TOKEN "
            "for higher limits; partial results stored.[/yellow]"
        )
    for err in report.errors:
        console.print(f"[red]  error: {err}[/red]")
    if args.update:
        console.print(
            "[dim]  (--update: store refreshed in place; achievements never revoked)[/dim]"
        )
    return 0


def _cmd_grant(args) -> int:
    try:
        engine.grant(args.login, args.badge_id, reason=args.reason, by=args.by)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return 2
    console.print(f"[green]Granted {args.badge_id} to {args.login} (manual).[/green]")
    return 0


def _cmd_revoke(args) -> int:
    ok = engine.revoke(args.login, args.badge_id)
    if ok:
        console.print(f"[yellow]Revoked {args.badge_id} from {args.login}.[/yellow]")
        return 0
    console.print(f"[red]No such achievement {args.badge_id} for {args.login}.[/red]")
    return 1


def export_markdown(login: str) -> str:
    p = engine.profile(login)
    if not p.get("found"):
        return f"<!-- no contributor data for {login}; run 'exaai contributors sync' first -->\n"
    lines = [f"## {p['login']} - ExaAiAgent Contributor Achievements", ""]
    lines.append(f"**Level:** {p['level']} · **Points:** {p['points']}")
    lines.append("")
    badge_by_id = badge_defs.BADGES_BY_ID
    for badge_id in p["badges"]:
        b = badge_by_id.get(badge_id)
        if not b:
            continue
        url = f"{RAW_BASE}/{b.filename}"
        lines.append(
            f'<img src="{url}" width="128" alt="{b.name}" title="{b.name} - {b.description}" />'
        )
    lines.append("")
    lines.append("<!-- generated by: exaai contributors export " + login + " -->")
    return "\n".join(lines) + "\n"


def _cmd_export(args) -> int:
    sys.stdout.write(export_markdown(args.login))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exaai contributors", description="Contributor Achievement System"
    )
    sub = parser.add_subparsers(dest="contributors_command", required=True)

    p = sub.add_parser("list", help="List known contributors")
    p.add_argument("--repo", default=DEFAULT_REPO)
    p.set_defaults(func=_cmd_list)

    p = sub.add_parser("profile", help="Show a contributor profile")
    p.add_argument("login")
    p.set_defaults(func=_cmd_profile)

    p = sub.add_parser("sync", help="Sync GitHub events into the local DB and evaluate badges")
    p.add_argument("--repo", default=DEFAULT_REPO, help="owner/name (public repo only)")
    p.add_argument("--user", default=None, help="Only sync this GitHub login")
    p.add_argument("--since", default=None, help="Only PRs merged on/after YYYY-MM-DD")
    p.add_argument(
        "--update", action="store_true", help="Refresh stored data in place (default behaviour)"
    )
    p.set_defaults(func=_cmd_sync)

    p = sub.add_parser("grant", help="Manually grant a badge (e.g. core_maintainer)")
    p.add_argument("login")
    p.add_argument("badge_id")
    p.add_argument("--reason", default=None)
    p.add_argument("--by", default="admin")
    p.set_defaults(func=_cmd_grant)

    p = sub.add_parser("revoke", help="Revoke an achievement (manual or auto)")
    p.add_argument("login")
    p.add_argument("badge_id")
    p.add_argument("--reason", default=None)
    p.set_defaults(func=_cmd_revoke)

    p = sub.add_parser("badges", help="List all badges and their criteria")
    p.set_defaults(func=_cmd_badges)

    p = sub.add_parser("export", help="Print ready-to-paste Markdown for a profile README")
    p.add_argument("login")
    p.set_defaults(func=_cmd_export)

    return parser


def run_contributors(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
