import argparse
import logging
import logging.handlers
import os
from pathlib import Path
import sys

import uvicorn

import api
from core.secret import load_secret
from daemon import ClientDaemon


def _configure_logging() -> None:
    log_dir = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "MySpeedify"
    log_dir.mkdir(parents=True, exist_ok=True)
    level_name = os.environ.get("MYSPEEDIFY_LOG_LEVEL", "INFO").upper()
    level = logging.getLevelName(level_name)
    if not isinstance(level, int):
        raise ValueError(f"Invalid MYSPEEDIFY_LOG_LEVEL: {level_name}")
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.handlers.RotatingFileHandler(
                log_dir / "client.log",
                maxBytes=2_000_000,
                backupCount=3,
                encoding="utf-8",
            ),
        ],
        force=True,
    )


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main() -> None:
    _configure_logging()
    parser = argparse.ArgumentParser(description="Run the MySpeedify client and local dashboard.")
    parser.add_argument("--server-host", default="127.0.0.1", help="Relay hostname or IPv4 address")
    parser.add_argument("--port", type=_port, default=51820, help="Relay UDP port")
    parser.add_argument("--dashboard-port", type=_port, default=8088, help="Local dashboard port")
    args = parser.parse_args()

    secret = load_secret()
    if not secret:
        parser.error("configure MYSPEEDIFY_SECRET_FILE or MYSPEEDIFY_SECRET before starting")

    daemon = ClientDaemon(server_host=args.server_host, server_port=args.port, secret=secret)
    ui_dir = str(Path(__file__).resolve().parent / "ui")
    try:
        daemon.start()
        token = api.init_api(daemon, ui_dir, args.dashboard_port)
        print(
            f"MySpeedify dashboard: http://127.0.0.1:{args.dashboard_port}/?token={token}",
            flush=True,
        )
        uvicorn.run(api.app, host="127.0.0.1", port=args.dashboard_port)
        if daemon.fatal_error:
            raise SystemExit(1)
    finally:
        daemon.stop()


if __name__ == "__main__":
    main()
