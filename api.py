"""
MySpeedify Web & Telemetry API (v2)

Local-only control plane. Protection against other websites / local processes:
  * random per-launch token, exchanged once via  /?token=...  for an HttpOnly SameSite=Strict cookie
  * Host header allow-list (blocks DNS rebinding)
  * Origin allow-list on HTTP and WebSocket (WebSockets are NOT covered by CORS)
  * the API never drives the daemon: it only reads its snapshot and sets simple attributes
"""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import hmac
import json
import logging
import os
import random
import secrets
from typing import AsyncGenerator, Literal, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

if __package__:
    from .daemon import ClientDaemon
else:
    from daemon import ClientDaemon

logger = logging.getLogger("MySpeedify.API")

DEV = os.environ.get("MYSPEEDIFY_DEV") == "1"
COOKIE = "msp_session"


@dataclass
class APIState:
    daemon: Optional[ClientDaemon] = None
    token: str = ""
    allowed_hosts: set[str] = field(default_factory=set)
    allowed_origins: set[str] = field(default_factory=set)
    is_simulating: bool = False
    sim_task: Optional[asyncio.Task[None]] = None


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    yield
    state: APIState = application.state.runtime
    state.is_simulating = False
    task = state.sim_task
    state.sim_task = None
    if task is not None:
        if not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="MySpeedify VPN Controller", lifespan=lifespan)
app.state.runtime = APIState()


class ModeRequest(BaseModel):
    mode: Literal["speed", "redundant", "failover"]


class AdapterToggleRequest(BaseModel):
    ip: str = Field(max_length=45)
    enabled: bool


class AdapterPriorityRequest(BaseModel):
    ip: str = Field(max_length=45)
    priority: int = Field(ge=0, le=2)


def _token_ok(value: Optional[str]) -> bool:
    token = app.state.runtime.token
    return bool(value) and hmac.compare_digest(value.encode(), token.encode())


def _no_daemon():
    return JSONResponse({"error": "Daemon not initialized"}, status_code=503)


@app.middleware("http")
async def guard(request, call_next):
    state: APIState = request.app.state.runtime
    if request.headers.get("host", "") not in state.allowed_hosts:
        return PlainTextResponse("Forbidden host", status_code=403)
    origin = request.headers.get("origin")
    if origin is not None and origin not in state.allowed_origins:
        return PlainTextResponse("Forbidden origin", status_code=403)
    if request.url.path == "/" and _token_ok(request.query_params.get("token")):
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(COOKIE, state.token, httponly=True, samesite="strict", path="/")
        return resp
    if not _token_ok(request.cookies.get(COOKIE)):
        return PlainTextResponse("Unauthorized: open the URL printed at startup", status_code=401)
    return await call_next(request)


@app.get("/api/status")
async def get_status():
    state: APIState = app.state.runtime
    daemon = state.daemon
    if daemon is None:
        return _no_daemon()
    data = dict(daemon.get_telemetry())
    data["is_simulating"] = state.is_simulating
    data["dev_mode"] = DEV
    return data


@app.post("/api/mode")
async def set_mode(req: ModeRequest):
    daemon = app.state.runtime.daemon
    if daemon is None:
        return _no_daemon()
    return {"success": daemon.set_bonding_mode(req.mode), "mode": req.mode}


@app.post("/api/adapter/toggle")
async def toggle_adapter(req: AdapterToggleRequest):
    daemon = app.state.runtime.daemon
    if daemon is None:
        return _no_daemon()
    return {"success": daemon.toggle_adapter(req.ip, req.enabled)}


@app.post("/api/adapter/priority")
async def set_adapter_priority(req: AdapterPriorityRequest):
    daemon = app.state.runtime.daemon
    if daemon is None:
        return _no_daemon()
    return {"success": daemon.set_adapter_priority(req.ip, req.priority)}


@app.post("/api/adapters/refresh")
async def refresh_adapters():
    daemon = app.state.runtime.daemon
    if daemon is None:
        return _no_daemon()
    daemon.refresh_paths()          # scanner thread + I/O thread apply it
    return daemon.get_telemetry()


@app.post("/api/toggle-simulation")
async def toggle_simulation():
    if not DEV:
        return JSONResponse({"error": "Not available"}, status_code=404)
    state: APIState = app.state.runtime
    state.is_simulating = not state.is_simulating
    if state.is_simulating and (not state.sim_task or state.sim_task.done()):
        state.sim_task = asyncio.create_task(simulate_traffic_loop())
    return {"is_simulating": state.is_simulating}


async def simulate_traffic_loop():
    """DEV only: synthetic counters for UI demos."""
    state: APIState = app.state.runtime
    while (
        state.is_simulating
        and state.daemon is not None
        and state.daemon.is_running
    ):
        for _, (_, adapter) in list(state.daemon.paths.items()):
            if not adapter.enabled:
                continue
            burst = random.randint(30_000, 180_000)
            adapter.total_tx_bytes += burst
            adapter.total_rx_bytes += burst * 2
            state.daemon.total_tx_bytes += burst
            state.daemon.total_rx_bytes += burst * 2
            adapter.latency_ms = max(5.0, adapter.latency_ms + random.uniform(-2.0, 2.0))
            adapter.jitter_ms = max(0.5, random.uniform(0.8, 3.2))
        await asyncio.sleep(0.25)


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    state: APIState = websocket.app.state.runtime
    origin = websocket.headers.get("origin")
    if (websocket.headers.get("host", "") not in state.allowed_hosts
            or (origin is not None and origin not in state.allowed_origins)
            or not _token_ok(websocket.cookies.get(COOKIE))):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    try:
        while True:
            if state.daemon is not None:
                data = dict(state.daemon.get_telemetry())   # copy: the snapshot is shared
                data["is_simulating"] = state.is_simulating
                data["dev_mode"] = DEV
                await websocket.send_text(json.dumps(data))
            await asyncio.sleep(0.25)                          # 4 Hz is plenty for the dashboard
    except (WebSocketDisconnect, RuntimeError):
        pass


def init_api(daemon: ClientDaemon, ui_dir: str, port: int) -> str:
    """Wires the daemon, returns the one-time login token for the dashboard URL."""
    state: APIState = app.state.runtime
    state.daemon = daemon
    state.token = secrets.token_urlsafe(32)
    state.allowed_hosts.update({f"127.0.0.1:{port}", f"localhost:{port}"})
    state.allowed_origins.update({f"http://127.0.0.1:{port}", f"http://localhost:{port}"})
    if os.path.exists(ui_dir):
        app.mount("/", StaticFiles(directory=ui_dir, html=True), name="ui")
    return state.token
