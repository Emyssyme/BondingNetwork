import argparse
import atexit
import ctypes
import ipaddress
import logging
import logging.handlers
import os
from pathlib import Path
import socket
import signal
import sys
from ctypes import wintypes

import uvicorn

if os.name == "nt":
    import msvcrt
else:
    import fcntl

import api
from core.adapter import AdapterManager
from core.secret import load_secret
from core.tun import create_tun
from core.tun.routes import PhysicalPath, TunnelNetworkConfig
from daemon import ClientDaemon

CTRL_CLOSE_EVENT = 2
CTRL_LOGOFF_EVENT = 5
CTRL_SHUTDOWN_EVENT = 6

logger = logging.getLogger("MySpeedify.Client")


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


def _loopback_host(value: str) -> str:
    candidate = value.strip()
    if candidate in {"localhost", "127.0.0.1", "::1"}:
        return candidate
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("dashboard host must be a loopback address") from exc
    if ip.is_loopback:
        return str(ip)
    raise argparse.ArgumentTypeError("dashboard host must be a loopback address")


def acquire_instance_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = open(lock_path, "w", encoding="utf-8")
    try:
        if os.name == "nt":
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        lock_file.close()
        raise RuntimeError("Another MySpeedify instance is already running") from exc
    return lock_file


def _prepare_shutdown(daemon, lock_file):
    if daemon is not None:
        try:
            daemon.stop()
        except Exception:
            logging.exception("Error while stopping MySpeedify client during shutdown")
    if lock_file is not None:
        try:
            lock_file.close()
        except Exception:
            pass


def _cleanup_stale_network_state(server_host: str) -> None:
    try:
        relay_ip = socket.gethostbyname(server_host)
    except OSError as exc:
        logger.warning(
            "Could not resolve relay host %s; cleanup will omit relay-specific routes: %s",
            server_host,
            exc,
        )
        relay_ip = "127.0.0.1"
        paths = []
    else:
        paths = [
            PhysicalPath(adapter.interface_name, adapter.ip, adapter.if_index)
            for adapter in AdapterManager().get_active_adapters()
        ]

    TunnelNetworkConfig(create_tun(), relay_ip, paths).cleanup_stale()


def _make_console_control_handler(shutdown):
    def handle(control_type):
        if control_type not in {
            CTRL_CLOSE_EVENT,
            CTRL_LOGOFF_EVENT,
            CTRL_SHUTDOWN_EVENT,
        }:
            return False
        shutdown()
        return True

    return handle


def _register_console_control_handler(shutdown):
    if os.name != "nt":
        return None
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    callback = callback_type(_make_console_control_handler(shutdown))
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetConsoleCtrlHandler.argtypes = [callback_type, wintypes.BOOL]
    kernel32.SetConsoleCtrlHandler.restype = wintypes.BOOL
    if not kernel32.SetConsoleCtrlHandler(callback, True):
        raise ctypes.WinError(ctypes.get_last_error())
    return kernel32, callback


def _unregister_console_control_handler(registration) -> None:
    if registration is None:
        return
    kernel32, callback = registration
    if not kernel32.SetConsoleCtrlHandler(callback, False):
        raise ctypes.WinError(ctypes.get_last_error())


def _create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the MySpeedify client and local dashboard.")
    parser.add_argument(
        "--server-host",
        default=os.environ.get("MYSPEEDIFY_SERVER_HOST", "127.0.0.1"),
        help="Relay hostname or IPv4 address",
    )
    parser.add_argument(
        "--port",
        type=_port,
        default=os.environ.get("MYSPEEDIFY_SERVER_PORT", "51820"),
        help="Relay UDP port",
    )
    parser.add_argument("--dashboard-host", type=_loopback_host, default="127.0.0.1", help="Dashboard bind host; must stay on loopback")
    parser.add_argument("--dashboard-port", type=_port, default=8088, help="Local dashboard port")
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove stale MySpeedify firewall and tunnel routing state",
    )
    return parser


def main() -> None:
    _configure_logging()
    parser = _create_argument_parser()
    args = parser.parse_args()

    lock_path = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "MySpeedify" / "instance.lock"
    try:
        lock_file = acquire_instance_lock(lock_path)
    except RuntimeError as exc:
        parser.error(str(exc))

    if args.cleanup:
        try:
            _cleanup_stale_network_state(args.server_host)
        except (OSError, RuntimeError, ValueError) as exc:
            parser.error(f"Could not clean stale MySpeedify network state: {exc}")
        finally:
            lock_file.close()
        return

    secret = load_secret()
    if not secret:
        parser.error("configure MYSPEEDIFY_SECRET_FILE or MYSPEEDIFY_SECRET before starting")

    daemon = ClientDaemon(server_host=args.server_host, server_port=args.port, secret=secret)
    ui_dir = str(Path(__file__).resolve().parent / "ui")

    def _handle_shutdown(signum=None, frame=None):
        _prepare_shutdown(daemon, lock_file)
        raise SystemExit(0 if signum is None else 128 + signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle_shutdown)
        except (AttributeError, ValueError):
            pass
    atexit.register(_prepare_shutdown, daemon, lock_file)

    console_registration = _register_console_control_handler(
        lambda: _prepare_shutdown(daemon, lock_file),
    )
    try:
        daemon.start()
        token = api.init_api(daemon, ui_dir, args.dashboard_port, args.dashboard_host)
        if args.dashboard_host == "::1":
            dashboard_url = f"http://[::1]:{args.dashboard_port}/?token={token}"
        else:
            dashboard_url = f"http://{args.dashboard_host}:{args.dashboard_port}/?token={token}"
        print(f"MySpeedify dashboard: {dashboard_url}", flush=True)
        uvicorn.run(api.app, host=args.dashboard_host, port=args.dashboard_port, access_log=False)
        if daemon.fatal_error:
            raise SystemExit(1)
    finally:
        try:
            _unregister_console_control_handler(console_registration)
        finally:
            _prepare_shutdown(daemon, lock_file)


if __name__ == "__main__":
    main()
