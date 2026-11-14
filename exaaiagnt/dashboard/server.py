import asyncio
import contextlib
import logging
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from exaaiagnt import scan_control
from exaaiagnt.dashboard import admin
from exaaiagnt.telemetry.tracer import get_global_tracer


app = FastAPI(title="ExaAi Live Dashboard")

# Optional token gate: set EXAAI_DASHBOARD_TOKEN to require Bearer auth on /api/* and /ws.
# Unset keeps the default local-only (127.0.0.1) UX. The token is read per-request so
# tests (and runtime env changes) are honoured without rebuilding the app.


def _dashboard_token() -> str:
    return os.getenv("EXAAI_DASHBOARD_TOKEN", "")


from fastapi import Request  # noqa: E402


@app.middleware("http")
async def _dashboard_auth(request: Request, call_next):
    token = _dashboard_token()
    if (
        token
        and request.url.path.startswith("/api/")
        and request.headers.get("authorization", "") != f"Bearer {token}"
    ):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    return await call_next(request)


def _ws_authorized(websocket) -> bool:
    token = _dashboard_token()
    if not token:
        return True
    return websocket.headers.get("authorization", "") == f"Bearer {token}"


# Serve static files
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")

_RUN_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_EXPORT_FILES = {
    "json": ("report.json", "application/json"),
    "sarif": ("report.sarif", "application/sarif+json"),
    "csv": ("report.csv", "text/csv"),
    "html": ("report.html", "text/html"),
    "md": ("report.md", "text/markdown"),
}


def _active_run_dir(tracer) -> Path | None:
    """Locate the on-disk run directory for the active tracer, or None."""
    run_name = getattr(tracer, "run_name", None) if tracer else None
    if not run_name or not _RUN_NAME_RE.match(str(run_name)):
        return None
    return Path.cwd() / "exaai_runs" / str(run_name)


def _vuln_band(v: dict) -> str:
    band = (
        v.get("confidence_band")
        or v.get("final_status")
        or ("confirmed" if v.get("confirmed") else "suspected")
    )
    band = str(band).lower()
    return "confirmed" if band == "confirmed" else "suspected"


def _vuln_counts(vulns: list[dict]) -> tuple[int, int]:
    confirmed = sum(1 for v in vulns if _vuln_band(v) == "confirmed")
    return confirmed, len(vulns) - confirmed


def _uptime_seconds(tracer) -> float | None:
    start_raw = getattr(tracer, "start_time", None)
    if not start_raw:
        return None
    try:
        start = datetime.fromisoformat(str(start_raw).replace("Z", "+00:00"))
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        return max(0.0, (datetime.now(UTC) - start).total_seconds())
    except (ValueError, TypeError):
        return None


def _agent_summary(a: dict) -> dict:
    return {
        "role": a.get("role") or a.get("name") or a.get("task") or "agent",
        "status": a.get("status", "unknown"),
        "model": a.get("model"),
        "tool_calls": len(a.get("tool_executions", []) or []),
    }


def _tool_executions_list(tracer) -> list[dict]:
    executions = getattr(tracer, "tool_executions", {}) or {}
    items = list(executions.values()) if isinstance(executions, dict) else list(executions)
    items.sort(key=lambda e: (e.get("execution_id") or 0))
    return [
        {
            "execution_id": e.get("execution_id"),
            "agent_id": e.get("agent_id"),
            "tool_name": e.get("tool_name"),
            "status": e.get("status"),
            "timestamp": e.get("timestamp") or e.get("started_at"),
            "completed_at": e.get("completed_at"),
        }
        for e in items[-20:]
    ]


def _top_vulnerabilities(vulns: list[dict], limit: int = 5) -> list[dict]:
    ordered = sorted(
        vulns,
        key=lambda v: (
            _SEVERITY_ORDER.get(str(v.get("severity", "info")).lower(), 5),
            str(v.get("timestamp", "")),
        ),
    )
    return [
        {
            "id": v.get("id"),
            "title": v.get("title"),
            "severity": v.get("severity"),
            "evidence_ids": v.get("evidence_ids", []),
            "tool_name": v.get("tool_name") or v.get("agent"),
        }
        for v in ordered[:limit]
    ]


def _counters(tracer) -> dict:
    agents = getattr(tracer, "agents", {}) or {}
    vulns = getattr(tracer, "vulnerability_reports", []) or []
    confirmed, suspected = _vuln_counts(vulns)
    return {
        "confirmed": confirmed,
        "suspected": suspected,
        "tool_calls": len(getattr(tracer, "tool_executions", {}) or {}),
        "agents_running": sum(1 for a in agents.values() if a.get("status") == "running"),
        "agents_completed": sum(1 for a in agents.values() if a.get("status") == "completed"),
        "agents_failed": sum(1 for a in agents.values() if a.get("status") == "failed"),
    }


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        with contextlib.suppress(ValueError):
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            with contextlib.suppress(Exception):
                await connection.send_text(message)


manager = ConnectionManager()


@app.get("/")
async def get_dashboard():
    html_path = Path(__file__).parent / "templates" / "index.html"
    return HTMLResponse(content=html_path.read_text())


@app.get("/api/stats")
async def get_stats():
    tracer = get_global_tracer()
    if not tracer:
        return {"status": "Waiting for agent..."}

    return {
        "agents_count": len(tracer.agents),
        "vulnerabilities": len(tracer.vulnerability_reports),
        "tool_calls": len(tracer.tool_executions),
        "start_time": tracer.start_time,
        "run_name": tracer.run_name,
    }


@app.get("/api/vulnerabilities")
async def get_vulns():
    tracer = get_global_tracer()
    if not tracer:
        return []
    return tracer.vulnerability_reports


@app.get("/api/state")
async def get_state():
    tracer = get_global_tracer()
    if not tracer:
        return {
            "status": "Waiting for agent...",
            "run_name": None,
            "agents": {},
            "confirmed": 0,
            "suspected": 0,
            "tool_calls": 0,
            "start_time": None,
            "uptime_seconds": None,
            "vulnerabilities": [],
            "tool_executions": [],
            "counters": {
                "confirmed": 0,
                "suspected": 0,
                "tool_calls": 0,
                "agents_running": 0,
                "agents_completed": 0,
                "agents_failed": 0,
            },
        }

    vulns = list(getattr(tracer, "vulnerability_reports", []) or [])
    confirmed, suspected = _vuln_counts(vulns)
    agents = getattr(tracer, "agents", {}) or {}
    return {
        "run_name": tracer.run_name,
        "start_time": tracer.start_time,
        "uptime_seconds": _uptime_seconds(tracer),
        "agents": {aid: _agent_summary(a) for aid, a in agents.items()},
        "confirmed": confirmed,
        "suspected": suspected,
        "tool_calls": len(getattr(tracer, "tool_executions", {}) or {}),
        "vulnerabilities": _top_vulnerabilities(vulns),
        "tool_executions": _tool_executions_list(tracer),
        "counters": _counters(tracer),
    }


@app.get("/api/report")
async def get_report():
    tracer = get_global_tracer()
    run_dir = _active_run_dir(tracer)
    if run_dir is None:
        return JSONResponse({"detail": "No active run or invalid run name"}, status_code=404)
    report_path = run_dir / "report.json"
    if not report_path.is_file():
        return JSONResponse({"detail": "report.json not found for active run"}, status_code=404)
    from fastapi.responses import FileResponse

    return FileResponse(report_path, media_type="application/json", filename="report.json")


@app.get("/api/export/full")
async def export_full():
    tracer = get_global_tracer()
    run_dir = _active_run_dir(tracer)
    if run_dir is None:
        return JSONResponse({"detail": "No active run or invalid run name"}, status_code=404)
    run_name = getattr(tracer, "run_name", None)
    try:
        built = admin.build_full_export(run_dir, str(run_name))
    except OSError:
        logging.getLogger(__name__).exception("full export failed")
        return JSONResponse({"detail": "export failed"}, status_code=500)
    if built is None:
        return JSONResponse({"detail": "No report files found for active run"}, status_code=404)
    payload, _files = built
    filename = f"exaai-run-{run_name}.zip"
    return Response(
        content=payload,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/export/{fmt}")
async def export_report(fmt: str):
    spec = _EXPORT_FILES.get(fmt)
    if spec is None:
        return JSONResponse({"detail": f"Unsupported export format: {fmt}"}, status_code=404)
    filename, media_type = spec
    tracer = get_global_tracer()
    run_dir = _active_run_dir(tracer)
    if run_dir is None:
        return JSONResponse({"detail": "No active run or invalid run name"}, status_code=404)
    path = run_dir / filename
    if not path.is_file():
        return JSONResponse({"detail": f"{filename} not found for active run"}, status_code=404)
    from fastapi.responses import FileResponse

    return FileResponse(path, media_type=media_type, filename=filename)


class ProviderTestIn(BaseModel):
    provider: str


class EnvVarIn(BaseModel):
    key: str
    value: str


def _audit_safe(action: str, detail: str) -> None:
    try:
        admin.append_audit(action, detail)
    except OSError:
        logging.getLogger(__name__).warning("audit log append failed for action=%s", action)


@app.get("/api/providers")
async def get_providers():
    try:
        return admin.discover_providers()
    except Exception:
        logging.getLogger(__name__).exception("providers discovery failed")
        return JSONResponse({"detail": "providers discovery failed"}, status_code=500)


@app.post("/api/providers/test")
async def test_provider_endpoint(body: ProviderTestIn):
    try:
        result = await asyncio.to_thread(admin.test_provider, body.provider)
    except Exception:
        logging.getLogger(__name__).exception("provider test failed")
        return JSONResponse({"detail": "provider test failed"}, status_code=500)
    _audit_safe(
        "provider_tested",
        f"provider={str(body.provider).strip().lower()} ok={bool(result.get('ok'))}",
    )
    return result


@app.put("/api/providers/env")
async def put_provider_env(body: EnvVarIn):
    if body.key not in admin.ENV_ALLOWLIST:
        return JSONResponse({"detail": f"key not in allowlist: {body.key}"}, status_code=400)
    try:
        admin.write_env_var(body.key, body.value)
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    except OSError:
        logging.getLogger(__name__).exception(".env write failed")
        return JSONResponse({"detail": ".env write failed"}, status_code=500)
    os.environ[body.key] = body.value
    _audit_safe("env_set", f"{body.key} updated")
    return {"ok": True, "restart_required": True}


@app.post("/api/scan/stop")
async def request_scan_stop():
    scan_control.request_stop()
    _audit_safe("scan_stop_requested", "user requested scan stop")
    return {"ok": True, "detail": "stop requested"}


@app.get("/api/update")
async def get_update():
    try:
        return await asyncio.to_thread(admin.get_update_status)
    except Exception:
        logging.getLogger(__name__).exception("update check failed")
        return JSONResponse({"detail": "update check failed"}, status_code=500)


@app.get("/api/audit")
async def get_audit(limit: int = 20):
    limit = max(1, min(int(limit), 100))
    try:
        return admin.read_audit(limit)
    except Exception:
        logging.getLogger(__name__).exception("audit read failed")
        return JSONResponse({"detail": "audit read failed"}, status_code=500)


def _diff_events(prev: dict, tracer) -> list[dict]:
    """Derive events by diffing current tracer state against the previous tick."""
    events: list[dict] = []
    now = datetime.now(UTC).isoformat()

    vulns = list(getattr(tracer, "vulnerability_reports", []) or [])
    for v in vulns:
        key = v.get("id") or v.get("title")
        if key and key not in prev["vuln_ids"]:
            events.append(
                {
                    "type": "vulnerability",
                    "ts": now,
                    "summary": f"New finding: {v.get('title', 'untitled')}",
                    "severity": str(v.get("severity", "info")).lower(),
                }
            )

    agents = getattr(tracer, "agents", {}) or {}
    for aid, a in agents.items():
        status = a.get("status", "unknown")
        old_status = prev["agent_status"].get(aid)
        if old_status is None:
            events.append(
                {
                    "type": "agent_started",
                    "ts": now,
                    "summary": f"Agent started: {a.get('name') or a.get('task') or aid}",
                }
            )
        elif old_status != status:
            if status == "completed":
                events.append(
                    {
                        "type": "agent_completed",
                        "ts": now,
                        "summary": f"Agent completed: {a.get('name') or a.get('task') or aid}",
                    }
                )
            elif status == "failed":
                events.append(
                    {
                        "type": "agent_failed",
                        "ts": now,
                        "summary": f"Agent failed: {a.get('name') or a.get('task') or aid}",
                        "severity": "high",
                    }
                )

    executions = getattr(tracer, "tool_executions", {}) or {}
    exec_items = list(executions.values()) if isinstance(executions, dict) else list(executions)
    for e in exec_items:
        eid = e.get("execution_id")
        if eid is None:
            continue
        status = e.get("status")
        old = prev["exec_status"].get(eid)
        if status == "completed" and old != "completed":
            events.append(
                {
                    "type": "tool_completed",
                    "ts": now,
                    "summary": f"Tool completed: {e.get('tool_name', 'unknown')}",
                }
            )

    return events


def _snapshot_state(tracer) -> dict:
    vulns = list(getattr(tracer, "vulnerability_reports", []) or [])
    agents = getattr(tracer, "agents", {}) or {}
    executions = getattr(tracer, "tool_executions", {}) or {}
    exec_items = list(executions.values()) if isinstance(executions, dict) else list(executions)
    return {
        "vuln_ids": {
            (v.get("id") or v.get("title")) for v in vulns if (v.get("id") or v.get("title"))
        },
        "agent_status": {aid: a.get("status", "unknown") for aid, a in agents.items()},
        "exec_status": {
            e.get("execution_id"): e.get("status")
            for e in exec_items
            if e.get("execution_id") is not None
        },
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if not _ws_authorized(websocket):
        await websocket.close(code=4401)
        return
    await manager.connect(websocket)
    prev_state: dict | None = None
    events: list[dict] = []
    try:
        while True:
            # Send updates every second
            tracer = get_global_tracer()
            if tracer:
                current = _snapshot_state(tracer)
                if prev_state is None:
                    # First tick establishes a baseline; do not replay history as events.
                    prev_state = current
                else:
                    new_events = _diff_events(prev_state, tracer)
                    events.extend(new_events)
                    events = events[-20:]
                    prev_state = current

                data = {
                    "agents": tracer.agents,
                    "stats": {
                        "active": sum(
                            1 for a in tracer.agents.values() if a.get("status") == "running"
                        ),
                        "completed": sum(
                            1 for a in tracer.agents.values() if a.get("status") == "completed"
                        ),
                        "failed": sum(
                            1 for a in tracer.agents.values() if a.get("status") == "failed"
                        ),
                    },
                    "recent_logs": tracer.chat_messages[-10:] if tracer.chat_messages else [],
                    "events": list(events),
                    "counters": _counters(tracer),
                }
                await websocket.send_json(data)
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        logging.exception("WebSocket error")
        manager.disconnect(websocket)


# ================= Contributor Achievement System =================
# All /api/contributors* routes sit under /api so the existing EXAAI_DASHBOARD_TOKEN
# middleware applies. The HTML page and badge SVG cards are intentionally public.
from exaaiagnt.contributors import badges as badge_defs  # noqa: E402
from exaaiagnt.contributors import db as contrib_db  # noqa: E402
from exaaiagnt.contributors import engine as contrib_engine  # noqa: E402
from exaaiagnt.contributors import github as contrib_github  # noqa: E402
from exaaiagnt.dashboard import contributors_assets  # noqa: E402

_badges_assets_dir = Path(__file__).resolve().parents[2] / "contributor_system" / "badges"
if _badges_assets_dir.is_dir():
    app.mount(
        "/assets/badges",
        StaticFiles(directory=_badges_assets_dir),
        name="contributor-badges",
    )

_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _badge_dict(badge, awarded_at=None):
    d = {
        "id": badge.id,
        "name": badge.name,
        "medal": badge.icon,
        "color": badge.color,
        "description": badge.description,
        "points": badge.points,
    }
    if awarded_at is not None:
        d["awarded_at"] = awarded_at
    return d


def _contributor_summary(p: dict) -> dict:
    badges_out = []
    for a in p.get("achievements", []):
        b = badge_defs.BADGES_BY_ID.get(a.get("badge_id"))
        if b is None:
            continue
        badges_out.append(_badge_dict(b, a.get("awarded_at")))
    return {
        "login": p.get("login"),
        "name": p.get("name"),
        "avatar_url": p.get("avatar_url"),
        "profile_url": p.get("profile_url"),
        "level": p.get("level"),
        "points": p.get("points", 0),
        "badges": badges_out,
        "counts": {"merged_prs": (p.get("events") or {}).get("pr_merged", 0)},
    }


def _achievement_keys() -> dict:
    """Snapshot {(github_id, badge_id): login} for pre/post-sync attribution."""
    keys: dict = {}
    try:
        conn = contrib_db.connect()
        try:
            rows = conn.execute(
                "SELECT a.github_id, a.badge_id, c.login FROM achievements a "
                "JOIN contributors c ON c.github_id = a.github_id"
            ).fetchall()
            for r in rows:
                keys[(r["github_id"], r["badge_id"])] = r["login"]
        finally:
            conn.close()
    except Exception:
        logging.exception("contributors: achievement snapshot failed")
    return keys


@app.get("/api/contributors")
async def get_contributors():
    deadline = time.monotonic() + 5.0
    out: list[dict] = []
    try:
        conn = contrib_db.connect()
        try:
            logins = [r["login"] for r in contrib_db.all_contributors(conn)]
        finally:
            conn.close()
    except Exception:
        logging.exception("contributors: database unavailable")
        return {"contributors": []}
    for login in logins:
        if time.monotonic() > deadline:
            logging.warning(
                "contributors: 5s soft cap reached; skipping %d login(s)",
                len(logins) - len(out),
            )
            break
        try:
            p = contrib_engine.profile(login)
            if not p.get("found"):
                continue
            out.append(_contributor_summary(p))
        except Exception:
            logging.warning("contributors: profile failed for %s", login, exc_info=True)
    out.sort(key=lambda c: c.get("points", 0), reverse=True)
    return {"contributors": out}


@app.get("/api/contributors/{login}")
async def get_contributor(login: str):
    if not _LOGIN_RE.match(login):
        return JSONResponse({"detail": "invalid login"}, status_code=400)
    try:
        p = contrib_engine.profile(login)
    except Exception:
        logging.exception("contributors: profile failed for %s", login)
        return JSONResponse({"detail": "profile unavailable"}, status_code=500)
    if not p.get("found"):
        return JSONResponse({"detail": "contributor not found"}, status_code=404)
    return _contributor_summary(p)


@app.get("/api/contributor-achievements")
async def get_contributor_achievements():
    badges_out = []
    for b in badge_defs.BADGES:
        d = _badge_dict(b)
        d["palette"] = dict(b.palette)
        d["criterion"] = b.description
        d["criteria"] = b.criteria
        d["manual_only"] = b.manual_only
        badges_out.append(d)
    return {
        "badges": badges_out,
        "levels": {name: threshold for name, threshold in badge_defs.LEVELS},
    }


class ContributorSyncIn(BaseModel):
    user: str | None = None
    repo: str | None = None


@app.post("/api/contributors/sync")
async def sync_contributors(body: ContributorSyncIn):
    repo = (body.repo or contrib_github.DEFAULT_REPO).strip()
    if not _REPO_RE.match(repo):
        return JSONResponse({"detail": "repo must look like 'owner/name'"}, status_code=400)
    user = body.user.strip() if body.user else None
    if user and not _LOGIN_RE.match(user):
        return JSONResponse({"detail": "invalid user login"}, status_code=400)
    before = _achievement_keys()
    try:
        report = await asyncio.wait_for(
            asyncio.to_thread(contrib_engine.sync, repo, user, None),
            timeout=120,
        )
    except TimeoutError:
        logging.warning("contributors: sync timed out after 120s")
        return JSONResponse({"detail": "Sync timed out after 120s"}, status_code=504)
    except contrib_github.RateLimitError:
        return JSONResponse(
            {"detail": "GitHub rate limited — set EXAAI_GITHUB_TOKEN"}, status_code=429
        )
    except contrib_github.GitHubError as e:
        logging.warning("contributors: GitHub error during sync: %s", e)
        return JSONResponse({"detail": f"GitHub error: {e}"}, status_code=502)
    except Exception:
        logging.exception("contributors: sync failed")
        return JSONResponse({"detail": "sync failed"}, status_code=500)
    if report.rate_limited:
        return JSONResponse(
            {"detail": "GitHub rate limited — set EXAAI_GITHUB_TOKEN"}, status_code=429
        )
    after = _achievement_keys()
    awarded = [f"{login}:{badge_id}" for (gid, badge_id), login in after.items() if (gid, badge_id) not in before]
    try:
        conn = contrib_db.connect()
        try:
            contributors_seen = len(contrib_db.all_contributors(conn))
        finally:
            conn.close()
    except Exception:
        contributors_seen = 0
    return {
        "repo": report.repo,
        "user": report.user,
        "contributors_seen": contributors_seen,
        "prs_seen": report.prs_seen,
        "events_added": report.events_added,
        "reviews_added": report.reviews_added,
        "comments_added": report.comments_added,
        "achievements_awarded": awarded,
        "errors": report.errors,
        "rate_limited": report.rate_limited,
    }


class ContributorGrantIn(BaseModel):
    login: str
    badge_id: str
    reason: str | None = None


@app.post("/api/contributors/grant")
async def grant_contributor_badge(body: ContributorGrantIn):
    login = body.login.strip()
    if not _LOGIN_RE.match(login):
        return JSONResponse({"detail": "invalid login"}, status_code=400)
    if body.badge_id not in badge_defs.BADGES_BY_ID:
        return JSONResponse({"detail": f"unknown badge_id: {body.badge_id}"}, status_code=400)
    try:
        return contrib_engine.grant(login, body.badge_id, reason=body.reason, by="dashboard")
    except ValueError as e:
        return JSONResponse({"detail": str(e)}, status_code=400)
    except Exception:
        logging.exception("contributors: grant failed for %s/%s", login, body.badge_id)
        return JSONResponse({"detail": "grant failed"}, status_code=500)


class ContributorRevokeIn(BaseModel):
    login: str
    badge_id: str


@app.post("/api/contributors/revoke")
async def revoke_contributor_badge(body: ContributorRevokeIn):
    login = body.login.strip()
    if not _LOGIN_RE.match(login):
        return JSONResponse({"detail": "invalid login"}, status_code=400)
    if body.badge_id not in badge_defs.BADGES_BY_ID:
        return JSONResponse({"detail": f"unknown badge_id: {body.badge_id}"}, status_code=400)
    try:
        ok = contrib_engine.revoke(login, body.badge_id)
    except Exception:
        logging.exception("contributors: revoke failed for %s/%s", login, body.badge_id)
        return JSONResponse({"detail": "revoke failed"}, status_code=500)
    if not ok:
        return JSONResponse({"detail": "achievement not found or not revoked"}, status_code=404)
    return {"revoked": True, "login": login, "badge_id": body.badge_id}


@app.get("/contributors/badge/{login}/{badge_id}.svg")
async def contributor_badge_card(login: str, badge_id: str):
    if not _LOGIN_RE.match(login) or badge_id not in badge_defs.BADGES_BY_ID:
        return JSONResponse({"detail": "not found"}, status_code=404)
    earned = False
    canonical = login
    try:
        conn = contrib_db.connect()
        try:
            row = contrib_db.get_contributor_by_login(conn, login)
            if row is not None:
                canonical = row["login"]
                earned = any(
                    a["badge_id"] == badge_id
                    for a in contrib_db.get_achievements(conn, row["github_id"])
                )
        finally:
            conn.close()
    except Exception:
        logging.exception("contributors: badge card lookup failed for %s/%s", login, badge_id)
        return JSONResponse({"detail": "unavailable"}, status_code=500)
    if not earned:
        return JSONResponse({"detail": "badge not earned"}, status_code=404)
    svg = contributors_assets.render_badge_card(canonical, badge_id)
    if svg is None:
        return JSONResponse({"detail": "badge artwork unavailable"}, status_code=404)
    return Response(
        svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/contributors", response_class=HTMLResponse)
async def contributors_page():
    html_path = Path(__file__).parent / "templates" / "contributors.html"
    return FileResponse(
        html_path,
        media_type="text/html",
        headers={"Cache-Control": "public, max-age=300"},
    )


def start_dashboard(host="127.0.0.1", port=8000):
    """Start the dashboard server in a background thread or process."""
    config = uvicorn.Config(app, host=host, port=port, log_level="error")
    server = uvicorn.Server(config)
    # We'll run this in a thread from the main agent
    import threading

    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    return t
