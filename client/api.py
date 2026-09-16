"""
MySpeedify Web & Telemetry API Server
Serves the Dashboard UI and provides WebSocket / REST streams for real-time control and analytics.
"""

import asyncio
import json
import logging
import os
import random
import time
from typing import Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from .daemon import ClientDaemon
from core.scheduler import BondingMode

logger = logging.getLogger("MySpeedify.API")

app = FastAPI(title="MySpeedify VPN Controller")

# Global daemon instance reference
daemon_instance: ClientDaemon = None
active_websockets: Set[WebSocket] = set()

# Simulation traffic generator state
is_simulating: bool = False
sim_task: asyncio.Task = None

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
    passphrase: str = "myspeedify_secret_key_2026"

@app.get("/api/status")
async def get_status():
    if not daemon_instance:
        return {"error": "Daemon not initialized"}
    return daemon_instance.get_telemetry()

@app.post("/api/mode")
async def set_mode(req: ModeRequest):
    if not daemon_instance:
        return {"error": "Daemon not initialized"}
    success = daemon_instance.set_bonding_mode(req.mode)
    return {"success": success, "mode": req.mode}

@app.post("/api/adapter/toggle")
async def toggle_adapter(req: AdapterToggleRequest):
    if not daemon_instance:
        return {"error": "Daemon not initialized"}
    success = daemon_instance.toggle_adapter(req.ip, req.enabled)
    return {"success": success}

@app.post("/api/adapter/priority")
async def set_adapter_priority(req: AdapterPriorityRequest):
    if not daemon_instance:
        return {"error": "Daemon not initialized"}
    success = daemon_instance.set_adapter_priority(req.ip, req.priority)
    return {"success": success}

@app.post("/api/adapters/refresh")
async def refresh_adapters():
    if not daemon_instance:
        return {"error": "Daemon not initialized"}
    daemon_instance.refresh_paths()
    return daemon_instance.get_telemetry()

@app.post("/api/toggle-simulation")
async def toggle_simulation():
    global is_simulating, sim_task
    is_simulating = not is_simulating
    if is_simulating and (not sim_task or sim_task.done()):
        sim_task = asyncio.create_task(simulate_traffic_loop())
    return {"is_simulating": is_simulating}

async def simulate_traffic_loop():
    """Generates synthetic multi-path traffic for interactive UI demonstration"""
    global is_simulating
    logger.info("Started synthetic traffic simulation for UI demonstration.")
    
    while is_simulating and daemon_instance and daemon_instance.is_running:
        try:
            # Generate simulated bursts across active adapters
            for path_id, (sock, adapter) in daemon_instance.paths.items():
                if not adapter.enabled:
                    continue
                    
                # Simulate packet burst with realistic latency jitter
                burst_size = random.randint(30_000, 180_000)  # bytes per tick
                adapter.total_tx_bytes += burst_size
                adapter.total_rx_bytes += burst_size * 2
                daemon_instance.total_tx_bytes += burst_size
                daemon_instance.total_rx_bytes += burst_size * 2
                
                # Jitter simulation
                adapter.latency_ms = max(5.0, adapter.latency_ms + random.uniform(-2.0, 2.0))
                adapter.jitter_ms = max(0.5, random.uniform(0.8, 3.2))
                adapter.loss_pct = max(0.0, min(5.0, adapter.loss_pct + random.uniform(-0.2, 0.2)))

            # Inject simulated synthetic IP packet into virtual TUN
            dummy_ip = b'E\x00\x004\x00\x01\x00\x00@\x06\x00\x00\n\x08\x00\x02\x08\x08\x08\x08' + (b'X' * 1200)
            daemon_instance.tun.inject_simulated_packet(dummy_ip)

            await asyncio.sleep(0.05)  # 20 ticks / sec
        except Exception as e:
            logger.debug(f"Sim error: {e}")
            await asyncio.sleep(0.1)

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    active_websockets.add(websocket)
    try:
        while True:
            if daemon_instance:
                # Step daemon non-blocking I/O
                daemon_instance.step()
                telemetry = daemon_instance.get_telemetry()
                telemetry["is_simulating"] = is_simulating
                await websocket.send_text(json.dumps(telemetry))
            await asyncio.sleep(0.05)  # 20 FPS real-time stream
    except WebSocketDisconnect:
        active_websockets.discard(websocket)
    except Exception as e:
        active_websockets.discard(websocket)

async def daemon_background_loop():
    while daemon_instance and daemon_instance.is_running:
        try:
            daemon_instance.step()
            await asyncio.sleep(0.01)
        except Exception as e:
            logger.debug(f"Daemon loop error: {e}")
            await asyncio.sleep(0.05)

@app.on_event("startup")
async def on_startup():
    asyncio.create_task(daemon_background_loop())

def init_api(daemon: ClientDaemon, ui_dir: str):
    global daemon_instance
    daemon_instance = daemon
    if os.path.exists(ui_dir):
        app.mount("/", StaticFiles(directory=ui_dir, html=True), name="ui")
