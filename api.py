"""
MySpeedify Web & Telemetry API (v2)

Local-only control plane. Protection against other websites / local processes:
  * random per-launch token, exchanged once via  /?token=...  for an HttpOnly SameSite=Strict cookie
  * Host header allow-list (blocks DNS rebinding)
  * Origin allow-list on HTTP and WebSocket (WebSockets are NOT covered by CORS)
  * the API never drives the daemon: it only reads its snapshot and sets simple attributes
"""

import asyncio
import hmac
import json
import logging
import os
import random
import secrets
from typing import Literal, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .daemon import ClientDaemon

logger = logging.getLogger("MySpeedify.API")

DEV = os.environ.get("MYSPEEDIFY_DEV") == "1"
COOKIE = "msp_session"

app = FastAPI(title="MySpeedify VPN Controller")

daemon_instance: Optional[ClientDaemon] = None
API_TOKEN: str = ""
ALLOWED_HOSTS: set = set()
ALLOWED_ORIGINS: set = set()

is_simulating = False
sim_task: Optional[asyncio.Task] = None


class ModeRequest(BaseModel):
    mode: Literal["speed", "redundant", "failover"]


class AdapterToggleRequest(BaseModel):
    ip: str = Field(max_length=45)
    enabled: bool


class AdapterPriorityRequest(BaseModel):
    ip: str = Field(max_length=45)
    priority: int = Field(ge=0, le=2)


def _token_ok(value: Optional[str]) -> bool:
    return bool(value) and hmac.compare_digest(value.encode(), API_TOKEN.encode())


def _no_daemon():
    return JSONResponse({"error": "Daemon not initialized"}, status_code=503)


@app.middleware("http")
async def guard(request, call_next):
    if request.headers.get("host", "") not in ALLOWED_HOSTS:
        return PlainTextResponse("Forbidden host", status_code=403)
    origin = request.headers.get("origin")
    if origin is not None and origin not in ALLOWED_ORIGINS:
        return PlainTextResponse("Forbidden origin", status_code=403)
    if request.url.path == "/" and _token_ok(request.query_params.get("token")):
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(COOKIE, API_TOKEN, httponly=True, samesite="strict", path="/")
        return resp
    if not _token_ok(request.cookies.get(COOKIE)):
        return PlainTextResponse("Unauthorized: open the URL printed at startup", status_code=401)
    return await call_next(request)


@app.get("/api/status")
async def get_status():
    if not daemon_instance:
        return _no_daemon()
    return daemon_instance.get_telemetry()


@app.post("/api/mode")
async def set_mode(req: ModeRequest):
    if not daemon_instance:
        return _no_daemon()
    return {"success": daemon_instance.set_bonding_mode(req.mode), "mode": req.mode}


@app.post("/api/adapter/toggle")
async def toggle_adapter(req: AdapterToggleRequest):
    if not daemon_instance:
        return _no_daemon()
    return {"success": daemon_instance.toggle_adapter(req.ip, req.enabled)}


@app.post("/api/adapter/priority")
async def set_adapter_priority(req: AdapterPriorityRequest):
    if not daemon_instance:
        return _no_daemon()
    return {"success": daemon_instance.set_adapter_priority(req.ip, req.priority)}


@app.post("/api/adapters/refresh")
async def refresh_adapters():
    if not daemon_instance:
        return _no_daemon()
    daemon_instance.refresh_paths()          # scanner thread + I/O thread apply it
    return daemon_instance.get_telemetry()


@app.post("/api/toggle-simulation")
async def toggle_simulation():
    global is_simulating, sim_task
    if not DEV:
        return JSONResponse({"error": "Not available"}, status_code=404)
    is_simulating = not is_simulating
    if is_simulating and (not sim_task or sim_task.done()):
        sim_task = asyncio.create_task(simulate_traffic_loop())
    return {"is_simulating": is_simulating}


async def simulate_traffic_loop():
    """DEV only: synthetic counters for UI demos."""
    while is_simulating and daemon_instance and daemon_instance.is_running:
        for _pid, (_sock, adapter) in list(daemon_instance.paths.items()):
            if not adapter.enabled:
                continue
            burst = random.randint(30_000, 180_000)
            adapter.total_tx_bytes += burst
            adapter.total_rx_bytes += burst * 2
            daemon_instance.total_tx_bytes += burst
            daemon_instance.total_rx_bytes += burst * 2
            adapter.latency_ms = max(5.0, adapter.latency_ms + random.uniform(-2.0, 2.0))
            adapter.jitter_ms = max(0.5, random.uniform(0.8, 3.2))
        await asyncio.sleep(0.25)


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if (websocket.headers.get("host", "") not in ALLOWED_HOSTS
            or (origin is not None and origin not in ALLOWED_ORIGINS)
            or not _token_ok(websocket.cookies.get(COOKIE))):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    try:
        while True:
            if daemon_instance:
                data = dict(daemon_instance.get_telemetry())   # copy: the snapshot is shared
                data["is_simulating"] = is_simulating
                await websocket.send_text(json.dumps(data))
            await asyncio.sleep(0.25)                          # 4 Hz is plenty for the dashboard
    except (WebSocketDisconnect, RuntimeError):
        pass


def init_api(daemon: ClientDaemon, ui_dir: str, port: int) -> str:
    """Wires the daemon, returns the one-time login token for the dashboard URL."""
    global daemon_instance, API_TOKEN
    daemon_instance = daemon
    API_TOKEN = secrets.token_urlsafe(32)
    ALLOWED_HOSTS.update({f"127.0.0.1:{port}", f"localhost:{port}"})
    ALLOWED_ORIGINS.update({f"http://127.0.0.1:{port}", f"http://localhost:{port}"})
    if os.path.exists(ui_dir):
        app.mount("/", StaticFiles(directory=ui_dir, html=True), name="ui")
    return API_TOKEN
