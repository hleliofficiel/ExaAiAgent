import asyncio
import logging
import os

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from exaaiagnt.telemetry.tracer import get_global_tracer


app = FastAPI(title="ExaAi Live Dashboard")

# Serve static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()

@app.get("/")
async def get_dashboard():
    html_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    with open(html_path) as f:
        return HTMLResponse(content=f.read())

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
        "run_name": tracer.run_name
    }

@app.get("/api/vulnerabilities")
async def get_vulns():
    tracer = get_global_tracer()
    if not tracer:
        return []
    return tracer.vulnerability_reports

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Send updates every second
            tracer = get_global_tracer()
            if tracer:
                data = {
                    "agents": tracer.agents,
                    "stats": {
                        "active": sum(1 for a in tracer.agents.values() if a.get("status") == "running"),
                        "completed": sum(1 for a in tracer.agents.values() if a.get("status") == "completed"),
                        "failed": sum(1 for a in tracer.agents.values() if a.get("status") == "failed"),
                    },
                    "recent_logs": tracer.chat_messages[-10:] if tracer.chat_messages else []
                }
                await websocket.send_json(data)
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logging.exception(f"WebSocket error: {e}")
        manager.disconnect(websocket)

def start_dashboard(host="0.0.0.0", port=8000):
    """Start the dashboard server in a background thread or process."""
    config = uvicorn.Config(app, host=host, port=port, log_level="error")
    server = uvicorn.Server(config)
    # We'll run this in a thread from the main agent
    import threading
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    return t
