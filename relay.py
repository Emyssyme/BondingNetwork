"""
MySpeedify Aggregation Relay Server (v2)

 * No session state is created before a valid PSK-authenticated HANDSHAKE_INIT.
 * Paths are registered only from authenticated (AEAD-verified) packets.
 * Uplink: decrypt -> reorder -> source-IP check -> write to server TUN (kernel NAT/iptables does the rest).
 * Downlink: read TUN -> find session by destination IP -> schedule across the session's live paths -> encrypt.
"""

import logging
import os
import platform
import select
import socket
import sys
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag

from core.protocol import Packet, PacketType, PacketFlag, HEADER_SIZE
from core.crypto_v2 import derive_psk, TunnelCrypto
from core.handshake import (
    INIT_LEGACY_SIZE, MAX_SKEW_MS, parse_init, parse_init_client_id, build_resp,
)
from core.replay import ReplayWindow
from core.reorder import ReorderBuffer
from core.scheduler import PacketScheduler, BondingMode
from core.adapter import NetworkAdapter
from core.prober import LinkProber
from core.secret import is_valid_client_id, load_client_secrets, load_secret
from core.tun import TUN_MTU

logger = logging.getLogger("MySpeedify.RelayServer")

BATCH = 64
MAX_SESSIONS = 253          # one /24 pool: 10.8.0.2 .. 10.8.0.254
SESSION_TTL = 120.0         # seconds without authenticated traffic
PATH_TTL = 10.0             # a path with no authenticated packet for this long gets no downlink
INIT_REPLAY_TTL = 2 * MAX_SKEW_MS / 1000.0
INIT_REPLAY_CACHE_LIMIT = MAX_SESSIONS * 16


def _parse_metrics_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError("MYSPEEDIFY_METRICS_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("MYSPEEDIFY_METRICS_PORT must be between 1 and 65535")
    return port


class ClientSession:
    def __init__(self, session_id: int, crypto: TunnelCrypto, client_nonce: bytes,
                 client_public_key: bytes, resp_payload: bytes, tunnel_ip: str,
                 client_id: str | None = None):
        self.session_id = session_id
        self.client_id = client_id
        self.crypto = crypto
        self.client_nonce = client_nonce
        self.client_public_key = client_public_key
        self.resp_payload = resp_payload            # cached: INIT retransmits get the same RESP
        self.tunnel_ip = tunnel_ip
        self.ip_bytes = socket.inet_aton(tunnel_ip)
        self.reorder_buffer = ReorderBuffer()
        self.prober = LinkProber()
        self.scheduler = PacketScheduler(self.prober, mode=BondingMode.SPEED)
        # path_id -> (remote_ip, remote_port, last_seen_monotonic, adapter)
        self.paths: Dict[int, Tuple[str, int, float, NetworkAdapter]] = {}
        self.replay_windows: Dict[Tuple[int, int], ReplayWindow] = {}
        self.seq_counter = 0
        self.last_activity = time.monotonic()

    def update_path(self, path_id: int, addr: Tuple[str, int]):
        now = time.monotonic()
        self.last_activity = now
        old = self.paths.get(path_id)
        if old is None:
            adapter = NetworkAdapter(name=f"Path-{path_id}", ip=addr[0])
            logger.info("Session %s registered Path #%d from %s:%d", self.session_id, path_id, *addr)
        else:
            adapter = old[3]
        self.paths[path_id] = (addr[0], addr[1], now, adapter)


class RelayServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 51820,
        secret: str | None = "",
        tun=None,
        client_secrets: dict[str, str] | None = None,
        metrics_port: int | None = None,
    ):
        self.host = host
        self.port = port
        if metrics_port is None:
            configured_metrics_port = os.environ.get("MYSPEEDIFY_METRICS_PORT")
            if configured_metrics_port is not None:
                metrics_port = _parse_metrics_port(configured_metrics_port)
        elif not 0 <= metrics_port <= 65535:
            raise ValueError("metrics_port must be between 0 and 65535")
        self.metrics_port = metrics_port
        if client_secrets is None:
            client_secrets = load_client_secrets()
        self.psk = derive_psk(secret) if secret else None
        self.client_psks: Dict[str, bytes] = {}
        seen_client_secrets: set[str] = set()
        for client_id, client_secret in client_secrets.items():
            if not isinstance(client_id, str) or not is_valid_client_id(client_id):
                raise ValueError("Client secrets contain an invalid client ID")
            if not isinstance(client_secret, str) or len(client_secret) < 16:
                raise ValueError("Each client secret must contain at least 16 characters")
            if client_secret == secret or client_secret in seen_client_secrets:
                raise ValueError("Each client must have a unique secret")
            seen_client_secrets.add(client_secret)
            self.client_psks[client_id] = derive_psk(client_secret)
        if self.psk is None and not self.client_psks:
            raise ValueError(
                "A relay passphrase is required, or a per-client secret must be configured via "
                "MYSPEEDIFY_SECRET/MYSPEEDIFY_SECRET_FILE or "
                "MYSPEEDIFY_CLIENT_SECRETS_FILE."
            )
        self.tun = tun                              # LinuxTun or None (handshake/probes still work)
        self.sock: Optional[socket.socket] = None
        self.is_running = False
        self.sessions: Dict[int, ClientSession] = {}
        self.by_ip: Dict[bytes, ClientSession] = {}
        self._free_ips: List[str] = [f"10.8.0.{i}" for i in range(254, 1, -1)]
        self.total_packets_routed = 0
        self.total_bytes_routed = 0
        self.auth_failures_total = 0
        self.sessions_created_total = 0
        self.sessions_expired_total = 0
        self._metrics_lock = threading.Lock()
        self._metrics_httpd: Optional[ThreadingHTTPServer] = None
        self._metrics_thread: Optional[threading.Thread] = None
        self._last_gc = time.monotonic()
        self._seen_init_nonces: OrderedDict[Tuple[Optional[str], int, bytes], float] = OrderedDict()

    # ---------------------------------------------------------------- lifecycle
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if platform.system() == "Windows" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            except OSError:
                pass
            sock.bind((self.host, self.port))
            sock.setblocking(False)
            self.sock = sock
            self._start_metrics_server()
        except Exception:
            self._stop_metrics_server()
            sock.close()
            self.sock = None
            raise
        self.is_running = True
        logger.info("Relay listening on UDP %s:%d (TUN: %s)", self.host, self.port,
                    "enabled" if self.tun else "disabled")
        if self._metrics_httpd is not None:
            logger.info(
                "Relay metrics available on http://127.0.0.1:%d/metrics",
                self._metrics_httpd.server_address[1],
            )

    def stop(self):
        self.is_running = False
        self._stop_metrics_server()
        if self.sock:
            self.sock.close()
        if self.tun:
            self.tun.close()
        logger.info("Relay stopped.")

    def _start_metrics_server(self) -> None:
        if self.metrics_port is None:
            return

        relay = self

        class MetricsHandler(BaseHTTPRequestHandler):
            server_version = "MySpeedifyMetrics"
            sys_version = ""

            def do_GET(self) -> None:
                if self.path != "/metrics":
                    self.send_error(404)
                    return
                body = relay.metrics_text().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                logger.debug("Metrics HTTP: " + format, *args)

        httpd = ThreadingHTTPServer(("127.0.0.1", self.metrics_port), MetricsHandler)
        httpd.daemon_threads = True
        thread = threading.Thread(
            target=httpd.serve_forever,
            name="myspeedify-metrics",
            daemon=True,
        )
        try:
            thread.start()
        except Exception:
            httpd.server_close()
            raise
        self._metrics_httpd = httpd
        self._metrics_thread = thread

    def _stop_metrics_server(self) -> None:
        httpd = self._metrics_httpd
        thread = self._metrics_thread
        self._metrics_httpd = None
        self._metrics_thread = None
        if httpd is None:
            return
        if thread is not None and thread.is_alive():
            httpd.shutdown()
        httpd.server_close()
        if thread is not None:
            thread.join(timeout=1.0)

    def metrics_text(self) -> str:
        with self._metrics_lock:
            values = (
                ("sessions_active", len(self.sessions)),
                ("sessions_created_total", self.sessions_created_total),
                ("sessions_expired_total", self.sessions_expired_total),
                ("packets_routed_total", self.total_packets_routed),
                ("bytes_routed_total", self.total_bytes_routed),
                ("authentication_failures_total", self.auth_failures_total),
            )
        metrics = []
        for name, value in values:
            metric_name = "myspeedify_relay_" + name
            kind = "gauge" if name == "sessions_active" else "counter"
            metrics.extend((
                f"# HELP {metric_name} MySpeedify relay {name.replace('_', ' ')}",
                f"# TYPE {metric_name} {kind}",
                f"{metric_name} {value}",
            ))
        return "\n".join(metrics) + "\n"

    def _record_auth_failure(self) -> None:
        with self._metrics_lock:
            self.auth_failures_total += 1

    def run_forever(self):
        self.start()
        try:
            while self.is_running:
                try:
                    self.step()
                except Exception:
                    logger.exception("Relay loop error")
                    time.sleep(0.01)
        except KeyboardInterrupt:
            self.stop()

    # --------------------------------------------------------------------- loop
    def step(self):
        if not self.is_running or not self.sock:
            return
        waitlist = [self.sock] + ([self.tun] if self.tun else [])
        readable, _, _ = select.select(waitlist, [], [], 0.002)

        if self.sock in readable:
            for _ in range(BATCH):
                try:
                    data, addr = self.sock.recvfrom(2048)
                except (BlockingIOError, InterruptedError):
                    break
                except ConnectionResetError:
                    continue
                except OSError:
                    break
                self._handle_incoming(data, addr)

        if self.tun and self.tun in readable:
            for _ in range(BATCH):
                ip_pkt = self.tun.read()
                if not ip_pkt:
                    break
                self._handle_downlink(ip_pkt)

        for s in list(self.sessions.values()):
            for payload in s.reorder_buffer.flush_expired():
                self._to_tun(s, payload)

        now = time.monotonic()
        if now - self._last_gc > 5.0:
            self._last_gc = now
            self._expire_idle_sessions(now)
        self._probe_sessions()

    def _expire_idle_sessions(self, now: float) -> None:
        for session in [
            session for session in self.sessions.values()
            if now - session.last_activity > SESSION_TTL
        ]:
            with self._metrics_lock:
                self.sessions_expired_total += 1
            logger.info("Session %s expired", session.session_id)
            self._drop_session(session)

    # ------------------------------------------------------------------ uplink
    def _handle_incoming(self, raw: bytes, addr: Tuple[str, int]):
        pkt = Packet.deserialize(raw)
        if not pkt:
            return
        if pkt.pkt_type == PacketType.HANDSHAKE_INIT:
            self._handle_init(pkt, addr)
            return

        session = self.sessions.get(pkt.session_id)
        if session is None:
            return  # unknown session: drop silently, create nothing
        try:
            plain = session.crypto.decrypt(pkt.payload, pkt.seq_num, pkt.path_id,
                                           int(pkt.pkt_type), raw[:HEADER_SIZE])
        except InvalidTag:
            self._record_auth_failure()
            return  # spoofed / corrupted: do NOT touch session state
        replay_window = session.replay_windows.setdefault(
            (pkt.path_id, int(pkt.pkt_type)), ReplayWindow(),
        )
        if not replay_window.accept(pkt.seq_num):
            return
        session.update_path(pkt.path_id, addr)  # only after authentication

        if pkt.pkt_type == PacketType.PROBE_REQ:
            resp = Packet(PacketType.PROBE_RESP, session.session_id, path_id=pkt.path_id,
                          flags=PacketFlag.PROBE, seq_num=pkt.seq_num)
            aad = resp.header_bytes()
            resp.payload = session.crypto.encrypt(plain, resp.seq_num, resp.path_id,
                                                  int(PacketType.PROBE_RESP), aad)
            self.sock.sendto(resp.serialize(), addr)
        elif pkt.pkt_type == PacketType.PROBE_RESP:
            session.prober.handle_probe_response(pkt.path_id, plain)
            path = session.paths.get(pkt.path_id)
            if path is not None:
                metrics = session.prober.get_path_metrics(pkt.path_id)
                path[3].latency_ms = metrics.avg_rtt_ms
                path[3].jitter_ms = metrics.jitter_ms
                path[3].loss_pct = metrics.loss_rate * 100.0
        elif pkt.pkt_type == PacketType.DATA:
            if pkt.flags & PacketFlag.REDUNDANT:
                session.scheduler.set_mode(BondingMode.REDUNDANT)
            elif pkt.flags & PacketFlag.FAILOVER:
                session.scheduler.set_mode(BondingMode.FAILOVER)
            else:
                session.scheduler.set_mode(BondingMode.SPEED)
            with self._metrics_lock:
                self.total_packets_routed += 1
                self.total_bytes_routed += len(raw)
            for ready in session.reorder_buffer.push(pkt.seq_num, plain):
                self._to_tun(session, ready)

    def _probe_sessions(self):
        if not self.sock:
            return
        now = time.monotonic()
        for session in list(self.sessions.values()):
            active_path_ids = [
                path_id
                for path_id, path in session.paths.items()
                if now - path[2] < PATH_TTL
            ]
            if not active_path_ids or not session.prober.should_probe():
                continue
            for path_id, pkt in session.prober.generate_probes(
                active_path_ids, session.session_id,
            ):
                path = session.paths.get(path_id)
                if path is None:
                    continue
                plaintext = pkt.payload
                pkt.payload = b""
                aad = pkt.header_bytes()
                pkt.payload = session.crypto.encrypt(
                    plaintext, pkt.seq_num, path_id, int(PacketType.PROBE_REQ), aad,
                )
                try:
                    self.sock.sendto(pkt.serialize(), (path[0], path[1]))
                except OSError as e:
                    logger.debug(
                        "Relay probe send error for session %s path %d: %s",
                        session.session_id, path_id, e,
                    )

    def _to_tun(self, session: ClientSession, ip_pkt: bytes):
        if not self.tun:
            return
        # anti-spoofing: IPv4 only, source must be the address assigned to this session
        if len(ip_pkt) < 20 or (ip_pkt[0] >> 4) != 4 or ip_pkt[12:16] != session.ip_bytes:
            return
        self.tun.write(ip_pkt)

    # --------------------------------------------------------------- handshake
    def _handle_init(self, pkt: Packet, addr: Tuple[str, int]):
        if len(pkt.payload) == INIT_LEGACY_SIZE:
            client_id = None
            psk = self.psk
        else:
            client_id = parse_init_client_id(pkt.payload)
            if client_id is None:
                self._record_auth_failure()
                return
            psk = self.client_psks.get(client_id)
        if psk is None:
            self._record_auth_failure()
            return
        parsed = parse_init(psk, pkt.session_id, pkt.payload)
        if parsed is None:
            self._record_auth_failure()
            return  # bad MAC / stale timestamp: no state, no reply
        cpub, cnonce = parsed
        now = time.monotonic()
        self._expire_init_replay_cache(now)
        sess = self.sessions.get(pkt.session_id)
        if sess is not None and sess.client_id != client_id:
            return
        if sess is not None and sess.client_nonce == cnonce:
            if sess.client_public_key != cpub:
                return
            resp_payload = sess.resp_payload        # retransmitted INIT
        else:
            replay_key = (client_id, pkt.session_id, cnonce)
            if replay_key in self._seen_init_nonces:
                return
            if len(self._seen_init_nonces) >= INIT_REPLAY_CACHE_LIMIT:
                logger.warning("INIT replay cache is full; refusing new session")
                return
            if sess is not None:
                self._drop_session(sess)
            if len(self.sessions) >= MAX_SESSIONS or not self._free_ips:
                logger.warning("Session limit reached, INIT refused")
                return
            ip = self._free_ips.pop()
            built = build_resp(psk, pkt.session_id, cpub, cnonce, ip)
            if built is None:
                self._free_ips.append(ip)
                return
            resp_payload, crypto = built
            sess = ClientSession(
                pkt.session_id, crypto, cnonce, cpub, resp_payload, ip, client_id,
            )
            with self._metrics_lock:
                self.sessions[pkt.session_id] = sess
                self.by_ip[sess.ip_bytes] = sess
                self.sessions_created_total += 1
            self._seen_init_nonces[replay_key] = now + INIT_REPLAY_TTL
            logger.info(
                "Session %s established for client %s, tunnel IP %s",
                pkt.session_id, client_id or "legacy", ip,
            )
        resp = Packet(PacketType.HANDSHAKE_RESP, pkt.session_id, path_id=pkt.path_id,
                      seq_num=0, payload=resp_payload)
        self.sock.sendto(resp.serialize(), addr)

    def _expire_init_replay_cache(self, now: float) -> None:
        while self._seen_init_nonces:
            replay_key, expires_at = next(iter(self._seen_init_nonces.items()))
            if expires_at > now:
                break
            del self._seen_init_nonces[replay_key]

    def _drop_session(self, s: ClientSession):
        with self._metrics_lock:
            self.sessions.pop(s.session_id, None)
            self.by_ip.pop(s.ip_bytes, None)
            self._free_ips.append(s.tunnel_ip)

    # ---------------------------------------------------------------- downlink
    def _handle_downlink(self, ip_pkt: bytes):
        if len(ip_pkt) < 20 or (ip_pkt[0] >> 4) != 4:
            return
        s = self.by_ip.get(ip_pkt[16:20])
        if s is None:
            return
        now = time.monotonic()
        live = [(pid, st[3]) for pid, st in s.paths.items() if now - st[2] < PATH_TTL]
        if not live:
            return
        s.seq_counter += 1
        for pid, pkt in s.scheduler.schedule(payload=ip_pkt, seq_num=s.seq_counter,
                                             session_id=s.session_id, active_adapters=live):
            rip, rport, _, _ = s.paths[pid]
            aad = pkt.header_bytes()
            pkt.payload = s.crypto.encrypt(ip_pkt, pkt.seq_num, pid, int(PacketType.DATA), aad)
            try:
                self.sock.sendto(pkt.serialize(), (rip, rport))
            except OSError:
                pass


def create_server_tun():
    """Linux-only server TUN (10.8.0.1/24). Returns None elsewhere or if MYSPEEDIFY_SERVER_TUN=0."""
    if (platform.system() != "Linux" or not os.path.exists("/dev/net/tun")
            or os.environ.get("MYSPEEDIFY_SERVER_TUN", "1") == "0"):
        return None
    from core.tun.linux import LinuxTun
    tun = LinuxTun("msps0")
    tun.open(ip="10.8.0.1", netmask="255.255.255.0", mtu=TUN_MTU)
    return tun


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    secret = load_secret()
    client_secrets = load_client_secrets()
    if not secret and not client_secrets:
        sys.exit(
            "Set MYSPEEDIFY_SECRET_FILE/MYSPEEDIFY_SECRET for legacy clients, "
            "or MYSPEEDIFY_CLIENT_SECRETS_FILE for per-client authentication."
        )
    RelayServer(
        secret=secret,
        client_secrets=client_secrets,
        tun=create_server_tun(),
    ).run_forever()
