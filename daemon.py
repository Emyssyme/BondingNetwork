"""
MySpeedify Client Daemon (v2)

Threading model: exactly ONE I/O thread ("msp-io") owns paths, sockets, scheduler, reorder buffer,
crypto and the TUN. A second thread only scans OS adapters (slow). Other threads (API) never touch
daemon state: they read an immutable telemetry snapshot published atomically by the I/O thread.
"""

import logging
import secrets
import select
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag

from core.protocol import Packet, PacketType, HEADER_SIZE
from core.crypto import derive_psk
from core.handshake import ClientHandshake
from core.reorder import ReorderBuffer
from core.adapter import AdapterManager, NetworkAdapter
from core.socket_bind import create_bound_udp_socket
from core.prober import LinkProber
from core.scheduler import PacketScheduler, BondingMode
from core.tun import create_tun, TUN_MTU

logger = logging.getLogger("MySpeedify.Client")

BATCH = 64            # max packets drained per source per loop iteration
SNAPSHOT_EVERY = 0.25
SCAN_EVERY = 3.0


class ClientDaemon:
    def __init__(self, server_host: str = "127.0.0.1", server_port: int = 51820,
                 secret: str = "", mode: BondingMode = BondingMode.SPEED):
        self.psk = derive_psk(secret)  # raises if secret is empty/short
        self.server_host = server_host
        self.server_port = server_port
        self.server_addr = (socket.gethostbyname(server_host), server_port)

        self.session_id: int = secrets.randbits(32) or 1
        self.crypto = None                      # set once the handshake completes
        self.tunnel_ip: Optional[str] = None
        self.tun = None
        self._hs = ClientHandshake(self.psk, self.session_id)
        self._last_init = 0.0

        self.adapter_mgr = AdapterManager()
        self.prober = LinkProber(interval_seconds=0.4)
        self.scheduler = PacketScheduler(prober=self.prober, mode=mode)
        self.reorder_buffer = ReorderBuffer(max_buffer_size=2048, max_hold_time_ms=30.0)

        # path_id -> (socket, adapter). Mutated ONLY by the I/O thread.
        self.paths: Dict[int, Tuple[socket.socket, NetworkAdapter]] = {}
        self._sock_map: Dict[socket.socket, Tuple[int, NetworkAdapter]] = {}
        self._read_socks: List[socket.socket] = []

        self.seq_counter = 0
        self.is_running = False
        self.fatal_error: Optional[str] = None
        self.last_rx = 0.0
        self._busy = False

        self.start_time = time.time()
        self.total_tx_bytes = self.total_rx_bytes = 0
        self.total_tx_packets = self.total_rx_packets = 0
        self.auth_failures = 0
        self.last_rate_time = time.monotonic()
        self.current_upload_mbps = self.current_download_mbps = 0.0

        self._scan_now = threading.Event()
        self._scan_result: Optional[List[NetworkAdapter]] = None
        self._snapshot: dict = {}
        self._err_last: Dict[str, float] = {}
        self._thread: Optional[threading.Thread] = None
        self._scan_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------ lifecycle
    def start(self):
        logger.info("Starting MySpeedify Client (session %s) -> %s", self.session_id, self.server_addr)
        self._scan_result = self.adapter_mgr.refresh_adapters()
        self._apply_adapters(self._scan_result)
        self._scan_result = None
        self.is_running = True
        self._snapshot = self._build_telemetry()
        self._scan_thread = threading.Thread(target=self._scan_loop, name="msp-scan", daemon=True)
        self._thread = threading.Thread(target=self._run, name="msp-io", daemon=True)
        self._scan_thread.start()
        self._thread.start()

    def stop(self):
        self.is_running = False
        self._scan_now.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        if self.tun:
            self.tun.close()
        for sock, _ in list(self.paths.values()):
            try:
                sock.close()
            except Exception:
                pass
        logger.info("MySpeedify Client stopped.")

    def _log_error(self, key: str, msg: str):
        """Logs with traceback at most once per 5 s per key (never silent, never a flood)."""
        now = time.monotonic()
        if now - self._err_last.get(key, 0.0) > 5.0:
            self._err_last[key] = now
            logger.exception(msg)

    # --------------------------------------------------------- adapter scan
    def _scan_loop(self):
        """Separate thread: OS/registry scans are slow and must never stall packet I/O."""
        while self.is_running:
            self._scan_now.wait(SCAN_EVERY)
            self._scan_now.clear()
            if not self.is_running:
                break
            try:
                self._scan_result = self.adapter_mgr.refresh_adapters()
            except Exception:
                self._log_error("scan", "Adapter scan failed")

    def refresh_paths(self):
        """Thread-safe: asks the scanner to run now (applied by the I/O thread)."""
        self._scan_now.set()

    def _alloc_path_id(self) -> Optional[int]:
        for pid in range(1, 256):
            if pid not in self.paths:
                return pid
        return None

    def _apply_adapters(self, adapters: List[NetworkAdapter]):
        """I/O thread only. Paths are keyed by adapter identity (not IP: the simulated adapter shares one)."""
        current = {id(a) for a in adapters}
        changed = False
        for pid, (sock, adp) in list(self.paths.items()):
            if id(adp) not in current:
                try:
                    sock.close()
                except Exception:
                    pass
                del self.paths[pid]
                self.prober.paths.pop(pid, None)
                changed = True
                logger.info("Removed Path #%d [%s] (%s)", pid, adp.name, adp.ip)
        have = {id(adp) for _, adp in self.paths.values()}
        for adp in adapters:
            if id(adp) in have:
                continue
            pid = self._alloc_path_id()
            if pid is None:
                logger.warning("Path limit (255) reached")
                break
            try:
                sock = create_bound_udp_socket(local_ip=adp.ip, port=0)
            except Exception as e:
                logger.warning("Failed to bind socket for [%s] (%s): %s", adp.name, adp.ip, e)
                continue
            self.paths[pid] = (sock, adp)
            changed = True
            logger.info("Initialized Path #%d on [%s] (%s)", pid, adp.name, adp.ip)
        if changed:
            self._sock_map = {s: (pid, adp) for pid, (s, adp) in self.paths.items()}
            self._read_socks = list(self._sock_map)

    # ------------------------------------------------------- control (any thread; plain attribute writes)
    def set_bonding_mode(self, mode_str: str) -> bool:
        try:
            self.scheduler.set_mode(BondingMode(mode_str.lower()))
            logger.info("Bonding mode: %s", mode_str.upper())
            return True
        except ValueError:
            return False

    def toggle_adapter(self, ip: str, enabled: bool) -> bool:
        adp = self.adapter_mgr.get_adapter(ip)
        if adp:
            adp.enabled = enabled
            return True
        return False

    def set_adapter_priority(self, ip: str, priority: int) -> bool:
        adp = self.adapter_mgr.get_adapter(ip)
        if adp:
            adp.priority = priority
            return True
        return False

    # ----------------------------------------------------------- I/O thread
    def _run(self):
        last_snap = 0.0
        while self.is_running:
            try:
                scan = self._scan_result
                if scan is not None:
                    self._scan_result = None
                    self._apply_adapters(scan)
                self._io_iteration()
                now = time.monotonic()
                if now - last_snap >= SNAPSHOT_EVERY:
                    last_snap = now
                    self._update_rates()
                    self._snapshot = self._build_telemetry()
            except Exception:
                self._log_error("loop", "I/O loop error")
                time.sleep(0.02)

    def _io_iteration(self):
        busy = False
        now = time.monotonic()

        if self.crypto is None:
            self._handshake_tick(now)
        else:
            self._probe_tick()

        # --- ingress: block in select only when idle; drain each socket in a batch
        if self._read_socks:
            readable, _, _ = select.select(self._read_socks, [], [], 0.0 if self._busy else 0.001)
            for sock in readable:
                entry = self._sock_map.get(sock)
                if entry is None:
                    continue
                pid, adp = entry
                for _ in range(BATCH):
                    try:
                        data, _addr = sock.recvfrom(2048)
                    except (BlockingIOError, InterruptedError):
                        break
                    except ConnectionResetError:  # Windows: ICMP port-unreachable surfaced on UDP
                        continue
                    except OSError:
                        break
                    busy = True
                    self._on_datagram(data, pid, adp)
        else:
            time.sleep(0.005)

        if self.crypto is not None and self.tun is not None:
            for payload in self.reorder_buffer.flush_expired():
                self.tun.write(payload)
            for _ in range(BATCH):
                pkt = self.tun.read()
                if not pkt:
                    break
                busy = True
                self._send_ip_packet(pkt)

        self._busy = busy

    # ------------------------------------------------------------ handshake
    def _handshake_tick(self, now: float):
        if now - self._last_init < 1.0:
            return
        self._last_init = now
        init = self._hs.build_init()
        for pid, (sock, adp) in list(self.paths.items()):
            if not adp.enabled:
                continue
            pkt = Packet(PacketType.HANDSHAKE_INIT, self.session_id, path_id=pid, seq_num=0, payload=init)
            try:
                sock.sendto(pkt.serialize(), self.server_addr)
            except OSError as e:
                logger.debug("INIT send error on path %d: %s", pid, e)

    def _on_handshake_resp(self, pkt: Packet):
        if self.crypto is not None:
            return
        res = self._hs.process_resp(pkt.payload)
        if res is None:
            logger.debug("Invalid HANDSHAKE_RESP ignored")
            return
        crypto, ip = res
        try:
            tun = create_tun()
            tun.open(ip=ip, netmask="255.255.255.0", mtu=TUN_MTU)
        except Exception as e:
            self.fatal_error = f"Cannot open TUN interface (run as Administrator/root?): {e}"
            logger.error(self.fatal_error)
            self.is_running = False
            return
        self.tun = tun
        self.tunnel_ip = ip
        self.last_rx = time.monotonic()
        self.crypto = crypto
        logger.info("Handshake complete, tunnel IP %s", ip)

    # --------------------------------------------------------------- probes
    def _seal_and_send(self, sock: socket.socket, pkt: Packet, plaintext: bytes) -> int:
        pkt.payload = b""
        aad = pkt.header_bytes()
        pkt.payload = self.crypto.encrypt(plaintext, pkt.seq_num, pkt.path_id, int(pkt.pkt_type), aad)
        raw = pkt.serialize()
        sock.sendto(raw, self.server_addr)
        return len(raw)

    def _probe_tick(self):
        if not self.prober.should_probe():
            return
        ids = [pid for pid, (_, adp) in self.paths.items() if adp.enabled]
        for pid, pkt in self.prober.generate_probes(ids, self.session_id):
            sock, _ = self.paths[pid]
            try:
                self._seal_and_send(sock, pkt, pkt.payload)
            except OSError as e:
                logger.debug("Probe send error on path %d: %s", pid, e)

    # --------------------------------------------------------------- ingress
    def _on_datagram(self, data: bytes, pid: int, adp: NetworkAdapter):
        pkt = Packet.deserialize(data)
        if not pkt or pkt.session_id != self.session_id:
            return
        if pkt.pkt_type == PacketType.HANDSHAKE_RESP:
            self._on_handshake_resp(pkt)
            return
        if self.crypto is None:
            return
        try:
            plain = self.crypto.decrypt(pkt.payload, pkt.seq_num, pkt.path_id,
                                        int(pkt.pkt_type), data[:HEADER_SIZE])
        except InvalidTag:
            self.auth_failures += 1
            return

        self.last_rx = time.monotonic()
        adp.total_rx_bytes += len(data)
        self.total_rx_bytes += len(data)
        self.total_rx_packets += 1

        if pkt.pkt_type == PacketType.PROBE_RESP:
            self.prober.handle_probe_response(pid, plain)
            m = self.prober.get_path_metrics(pid)
            adp.latency_ms, adp.jitter_ms = m.avg_rtt_ms, m.jitter_ms
            adp.loss_pct, adp.weight = m.loss_rate * 100.0, m.weight
        elif pkt.pkt_type == PacketType.DATA and self.tun is not None:
            for ready in self.reorder_buffer.push(pkt.seq_num, plain):
                self.tun.write(ready)

    # ---------------------------------------------------------------- egress
    def _send_ip_packet(self, ip_payload: bytes):
        active = [(pid, adp) for pid, (_, adp) in self.paths.items() if adp.enabled]
        if not active:
            return
        self.seq_counter += 1  # incremented only when the packet is really scheduled (no artificial gaps)
        seq = self.seq_counter
        for pid, pkt in self.scheduler.schedule(payload=b"", seq_num=seq,
                                                session_id=self.session_id, active_adapters=active):
            sock, adp = self.paths[pid]
            try:
                n = self._seal_and_send(sock, pkt, ip_payload)
            except OSError as e:
                logger.debug("Send error on path %d: %s", pid, e)
                continue
            adp.total_tx_bytes += n
            self.total_tx_bytes += n
            self.total_tx_packets += 1

    # ------------------------------------------------------------ telemetry
    def _update_rates(self):
        now = time.monotonic()
        if now - self.last_rate_time < 0.5:
            return
        # adapter.update_rates() keeps its own "last sample" in bytes_sent/bytes_recv; the daemon must
        # only bump total_* counters (bumping both made every delta 0 -> reported speed always ~0).
        for _, adp in list(self.paths.values()):
            adp.update_rates(adp.total_tx_bytes, adp.total_rx_bytes)
        up = sum(a.upload_speed_bps for _, a in list(self.paths.values()) if a.enabled)
        down = sum(a.download_speed_bps for _, a in list(self.paths.values()) if a.enabled)
        self.current_upload_mbps = round(up / 1e6, 2)
        self.current_download_mbps = round(down / 1e6, 2)
        self.last_rate_time = now

    def _build_telemetry(self) -> dict:
        adapters = []
        for pid, (_, adp) in list(self.paths.items()):
            d = adp.to_dict()
            d["path_id"] = pid
            adapters.append(d)
        lat = [a["latency_ms"] for a in adapters if a["enabled"] and a["latency_ms"] > 0]
        connected = self.crypto is not None and (time.monotonic() - self.last_rx) < 5.0
        if self.fatal_error:
            state = "error"
        elif self.crypto is None:
            state = "connecting"
        else:
            state = "connected" if connected else "disconnected"
        return {
            "session_id": self.session_id,
            "state": state,
            "error": self.fatal_error,
            "is_connected": connected,
            "tunnel_ip": self.tunnel_ip,
            "mode": self.scheduler.mode.value,
            "server": f"{self.server_host}:{self.server_port}",
            "uptime_seconds": int(time.time() - self.start_time),
            "upload_mbps": self.current_upload_mbps,
            "download_mbps": self.current_download_mbps,
            "bonded_latency_ms": round(min(lat), 1) if lat else 0.0,
            "total_tx_mb": round(self.total_tx_bytes / 1e6, 2),
            "total_rx_mb": round(self.total_rx_bytes / 1e6, 2),
            "auth_failures": self.auth_failures,
            "reorder_stats": self.reorder_buffer.stats(),
            "adapters": adapters,
        }

    def get_telemetry(self) -> dict:
        """Latest immutable snapshot (safe from any thread; treat as read-only, copy before editing)."""
        return self._snapshot
