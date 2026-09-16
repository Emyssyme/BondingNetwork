"""
MySpeedify - Next-Gen Channel Bonding VPN
Entry point executable for Client Daemon, GUI Dashboard, and Relay Server.
"""

import sys
import os
import argparse
import uvicorn
import logging
import webbrowser
import threading
import time

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from client.daemon import ClientDaemon
from client.api import app, init_api
from server.relay import RelayServer
from core.scheduler import BondingMode

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("MySpeedify.Main")

def run_server(host: str, port: int, passphrase: str):
    logger.info(f"=== Starting MySpeedify Relay Server on {host}:{port} ===")
    server = RelayServer(host=host, port=port, passphrase=passphrase)
    server.run_forever()

def run_client(server_host: str, server_port: int, passphrase: str, mode: str, ui_port: int, no_browser: bool):
    logger.info(f"=== Starting MySpeedify Client Daemon ===")
    bonding_mode = BondingMode(mode)
    
    # Initialize background Relay Server in thread for local development / zero-config demo
    if server_host == "127.0.0.1" or server_host == "localhost":
        logger.info("Initializing Local Aggregator Relay Node...")
        relay = RelayServer(host="127.0.0.1", port=server_port, passphrase=passphrase)
        relay_thread = threading.Thread(target=relay.run_forever, daemon=True)
        relay_thread.start()
        time.sleep(0.3)

    daemon = ClientDaemon(
        server_host=server_host,
        server_port=server_port,
        passphrase=passphrase,
        mode=bonding_mode
    )
    daemon.start()

    # Mount UI and start API server
    ui_dir = os.path.join(BASE_DIR, "ui")
    init_api(daemon, ui_dir)

    dashboard_url = f"http://127.0.0.1:{ui_port}"
    logger.info(f"==================================================")
    logger.info(f"  MySpeedify Dashboard: {dashboard_url}")
    logger.info(f"==================================================")

    if not no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(dashboard_url)).start()

    uvicorn.run(app, host="127.0.0.1", port=ui_port, log_level="warning")

def main():
    parser = argparse.ArgumentParser(description="MySpeedify - Channel Bonding VPN")
    parser.add_argument("--server", action="store_true", help="Run as Relay Server instead of Client")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Relay Server host (for --server mode)")
    parser.add_argument("--server-host", type=str, default="127.0.0.1", help="Target VPN Relay Server Host")
    parser.add_argument("--port", type=int, default=51820, help="Relay Server UDP Port")
    parser.add_argument("--passphrase", type=str, default="myspeedify_secret_key_2026", help="Tunnel encryption passphrase")
    parser.add_argument("--mode", type=str, default="speed", choices=["speed", "redundant", "failover"], help="Bonding mode")
    parser.add_argument("--ui-port", type=int, default=8088, help="Dashboard UI Port")
    parser.add_argument("--no-browser", action="store_true", help="Don't automatically open browser")

    args = parser.parse_args()

    if args.server:
        run_server(host=args.host, port=args.port, passphrase=args.passphrase)
    else:
        run_client(
            server_host=args.server_host,
            server_port=args.port,
            passphrase=args.passphrase,
            mode=args.mode,
            ui_port=args.ui_port,
            no_browser=args.no_browser
        )

if __name__ == "__main__":
    main()
