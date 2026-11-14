"""
MySpeedify Web & Telemetry API Server
Serves the Dashboard UI and provides WebSocket / REST streams for real-time control and analytics.
"""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import json
import logging
import os
import random
from typing import AsyncGenerator, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .daemon import ClientDaemon

logger = logging.getLogger("MySpeedify.API")


@dataclass
class APIState:
    daemon: Optional[ClientDaemon] = None
    active_websockets: set[WebSocket] = field(default_factory=set)
    is_simulating: bool = False
    sim_task: Optional[asyncio.Task[None]] = None
    daemon_task: Optional[asyncio.Task[None]] = None


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    state: APIState = application.state.runtime
    if state.daemon is not None:
        state.daemon_task = asyncio.create_task(daemon_background_loop())
    try:
        yield
    finally:
        state.is_simulating = False
        tasks = (state.sim_task, state.daemon_task)
        for task in tasks:
            if task is not None and not task.done():
                task.cancel()
        for task in tasks:
            if task is not None:
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        state.sim_task = None
        state.daemon_task = None
        state.active_websockets.clear()


app = FastAPI(title="MySpeedify VPN Controller", lifespan=lifespan)
app.state.runtime = APIState()

class ModeRequest(BaseModel):
    mode: str

class AdapterToggleRequest(BaseModel):
    ip: str
    enabled: bool

class AdapterPriorityRequest(BaseModel):
    ip: str
    priority: int

class ConnectRequest(BaseModel):
    server_host: str = "127.0.0.1"
    server_port: int = 51820
    passphrase: str
@app.get("/api/status")
async def get_status():
    daemon = app.state.runtime.daemon
    if daemon is None:
        return {"error": "Daemon not initialized"}
    return daemon.get_telemetry()

@app.post("/api/mode")
async def set_mode(req: ModeRequest):
    daemon = app.state.runtime.daemon
    if daemon is None:
        return {"error": "Daemon not initialized"}
    success = daemon.set_bonding_mode(req.mode)
    return {"success": success, "mode": req.mode}

@app.post("/api/adapter/toggle")
async def toggle_adapter(req: AdapterToggleRequest):
    daemon = app.state.runtime.daemon
    if daemon is None:
        return {"error": "Daemon not initialized"}
    success = daemon.toggle_adapter(req.ip, req.enabled)
    return {"success": success}

@app.post("/api/adapter/priority")
async def set_adapter_priority(req: AdapterPriorityRequest):
    daemon = app.state.runtime.daemon
    if daemon is None:
        return {"error": "Daemon not initialized"}
    success = daemon.set_adapter_priority(req.ip, req.priority)
    return {"success": success}

@app.post("/api/adapters/refresh")
async def refresh_adapters():
    daemon = app.state.runtime.daemon
    if daemon is None:
        return {"error": "Daemon not initialized"}
    daemon.refresh_paths()
    return daemon.get_telemetry()

@app.post("/api/toggle-simulation")
async def toggle_simulation():
    state: APIState = app.state.runtime
    state.is_simulating = not state.is_simulating
    if state.is_simulating and (not state.sim_task or state.sim_task.done()):
        state.sim_task = asyncio.create_task(simulate_traffic_loop())
    return {"is_simulating": state.is_simulating}

async def simulate_traffic_loop():
    """Generates synthetic multi-path traffic for interactive UI demonstration"""
    state: APIState = app.state.runtime
    logger.info("Started synthetic traffic simulation for UI demonstration.")
    
    while (
        state.is_simulating
        and state.daemon is not None
        and state.daemon.is_running
    ):
        try:
            daemon = state.daemon
            if daemon is None:
                return
            # Generate simulated bursts across active adapters
            for _, (_, adapter) in daemon.paths.items():
                if not adapter.enabled:
                    continue
                    
                # Simulate packet burst with realistic latency jitter
                burst_size = random.randint(30_000, 180_000)  # bytes per tick
                adapter.total_tx_bytes += burst_size
                adapter.total_rx_bytes += burst_size * 2
                daemon.total_tx_bytes += burst_size
                daemon.total_rx_bytes += burst_size * 2
                
                # Jitter simulation
                adapter.latency_ms = max(5.0, adapter.latency_ms + random.uniform(-2.0, 2.0))
                adapter.jitter_ms = max(0.5, random.uniform(0.8, 3.2))
                adapter.loss_pct = max(0.0, min(5.0, adapter.loss_pct + random.uniform(-0.2, 0.2)))

            # Inject simulated synthetic IP packet into virtual TUN
            dummy_ip = b'E\x00\x004\x00\x01\x00\x00@\x06\x00\x00\n\x08\x00\x02\x08\x08\x08\x08' + (b'X' * 1200)
            daemon.tun.inject_simulated_packet(dummy_ip)

            await asyncio.sleep(0.05)  # 20 ticks / sec
        except Exception as e:
            logger.debug(f"Sim error: {e}")
            await asyncio.sleep(0.1)

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    state: APIState = websocket.app.state.runtime
    await websocket.accept()
    state.active_websockets.add(websocket)
    try:
        while True:
            if state.daemon is not None:
                # Step daemon non-blocking I/O
                state.daemon.step()
                telemetry = state.daemon.get_telemetry()
                telemetry["is_simulating"] = state.is_simulating
                await websocket.send_text(json.dumps(telemetry))
            await asyncio.sleep(0.05)  # 20 FPS real-time stream
    except WebSocketDisconnect:
        state.active_websockets.discard(websocket)
    except Exception:
        logger.exception("Telemetry websocket failed")
        state.active_websockets.discard(websocket)

async def daemon_background_loop():
    state: APIState = app.state.runtime
    while state.daemon is not None and state.daemon.is_running:
        try:
            state.daemon.step()
            await asyncio.sleep(0.01)
        except Exception as e:
            logger.debug(f"Daemon loop error: {e}")
            await asyncio.sleep(0.05)

def init_api(daemon: ClientDaemon, ui_dir: str):
    app.state.runtime.daemon = daemon
    if os.path.exists(ui_dir):
        app.mount("/", StaticFiles(directory=ui_dir, html=True), name="ui")
