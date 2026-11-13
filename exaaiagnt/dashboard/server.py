import asyncio
import contextlib
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response
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


def start_dashboard(host="127.0.0.1", port=8000):
    """Start the dashboard server in a background thread or process."""
    config = uvicorn.Config(app, host=host, port=port, log_level="error")
    server = uvicorn.Server(config)
    # We'll run this in a thread from the main agent
    import threading

    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    return t
