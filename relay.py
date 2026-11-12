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
import time
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag

from core.protocol import Packet, PacketType, PacketFlag, HEADER_SIZE
from core.crypto import derive_psk, TunnelCrypto
from core.handshake import parse_init, build_resp
from core.reorder import ReorderBuffer
from core.scheduler import PacketScheduler, BondingMode
from core.adapter import NetworkAdapter
from core.prober import LinkProber
from core.secret import load_secret
from core.tun import TUN_MTU

logger = logging.getLogger("MySpeedify.RelayServer")

BATCH = 64
MAX_SESSIONS = 253          # one /24 pool: 10.8.0.2 .. 10.8.0.254
SESSION_TTL = 120.0         # seconds without authenticated traffic
PATH_TTL = 10.0             # a path with no authenticated packet for this long gets no downlink


class ClientSession:
    def __init__(self, session_id: int, crypto: TunnelCrypto, client_nonce: bytes,
                 resp_payload: bytes, tunnel_ip: str):
        self.session_id = session_id
        self.crypto = crypto
        self.client_nonce = client_nonce
        self.resp_payload = resp_payload            # cached: INIT retransmits get the same RESP
        self.tunnel_ip = tunnel_ip
        self.ip_bytes = socket.inet_aton(tunnel_ip)
        self.reorder_buffer = ReorderBuffer()
        self.prober = LinkProber()
        self.scheduler = PacketScheduler(self.prober, mode=BondingMode.SPEED)
        # path_id -> (remote_ip, remote_port, last_seen_monotonic, adapter)
        self.paths: Dict[int, Tuple[str, int, float, NetworkAdapter]] = {}
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
    def __init__(self, host: str = "0.0.0.0", port: int = 51820, secret: str = "", tun=None):
        self.host = host
        self.port = port
        self.psk = derive_psk(secret)               # refuses empty/short secrets
        self.tun = tun                              # LinuxTun or None (handshake/probes still work)
        self.sock: Optional[socket.socket] = None
        self.is_running = False
        self.sessions: Dict[int, ClientSession] = {}
        self.by_ip: Dict[bytes, ClientSession] = {}
        self._free_ips: List[str] = [f"10.8.0.{i}" for i in range(254, 1, -1)]
        self.total_packets_routed = 0
        self.total_bytes_routed = 0
        self._last_gc = time.monotonic()

    # ---------------------------------------------------------------- lifecycle
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if platform.system() == "Windows" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        self.sock.bind((self.host, self.port))
        self.sock.setblocking(False)
        self.is_running = True
        logger.info("Relay listening on UDP %s:%d (TUN: %s)", self.host, self.port,
                    "enabled" if self.tun else "disabled")

    def stop(self):
        self.is_running = False
        if self.sock:
            self.sock.close()
        if self.tun:
            self.tun.close()
        logger.info("Relay stopped.")

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
            for s in [s for s in self.sessions.values() if now - s.last_activity > SESSION_TTL]:
                logger.info("Session %s expired", s.session_id)
                self._drop_session(s)

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
            return  # spoofed / corrupted: do NOT touch session state
        session.update_path(pkt.path_id, addr)  # only after authentication

        if pkt.pkt_type == PacketType.PROBE_REQ:
            resp = Packet(PacketType.PROBE_RESP, session.session_id, path_id=pkt.path_id,
                          flags=PacketFlag.PROBE, seq_num=pkt.seq_num)
            aad = resp.header_bytes()
            resp.payload = session.crypto.encrypt(plain, resp.seq_num, resp.path_id,
                                                  int(PacketType.PROBE_RESP), aad)
            self.sock.sendto(resp.serialize(), addr)
        elif pkt.pkt_type == PacketType.DATA:
            # mirror "redundant" so downlink uses the same strategy (speed/failover not signalled yet)
            if pkt.flags & PacketFlag.REDUNDANT:
                session.scheduler.set_mode(BondingMode.REDUNDANT)
            elif session.scheduler.mode == BondingMode.REDUNDANT:
                session.scheduler.set_mode(BondingMode.SPEED)
            self.total_packets_routed += 1
            self.total_bytes_routed += len(raw)
            for ready in session.reorder_buffer.push(pkt.seq_num, plain):
                self._to_tun(session, ready)

    def _to_tun(self, session: ClientSession, ip_pkt: bytes):
        if not self.tun:
            return
        # anti-spoofing: IPv4 only, source must be the address assigned to this session
        if len(ip_pkt) < 20 or (ip_pkt[0] >> 4) != 4 or ip_pkt[12:16] != session.ip_bytes:
            return
        self.tun.write(ip_pkt)

    # --------------------------------------------------------------- handshake
    def _handle_init(self, pkt: Packet, addr: Tuple[str, int]):
        parsed = parse_init(self.psk, pkt.session_id, pkt.payload)
        if parsed is None:
            return  # bad MAC / stale timestamp: no state, no reply
        cpub, cnonce = parsed
        sess = self.sessions.get(pkt.session_id)
        if sess is not None and sess.client_nonce == cnonce:
            resp_payload = sess.resp_payload        # retransmitted INIT
        else:
            if sess is not None:
                self._drop_session(sess)
            if len(self.sessions) >= MAX_SESSIONS or not self._free_ips:
                logger.warning("Session limit reached, INIT refused")
                return
            ip = self._free_ips.pop()
            built = build_resp(self.psk, pkt.session_id, cpub, cnonce, ip)
            if built is None:
                self._free_ips.append(ip)
                return
            resp_payload, crypto = built
            sess = ClientSession(pkt.session_id, crypto, cnonce, resp_payload, ip)
            self.sessions[pkt.session_id] = sess
            self.by_ip[sess.ip_bytes] = sess
            logger.info("Session %s established, tunnel IP %s", pkt.session_id, ip)
        resp = Packet(PacketType.HANDSHAKE_RESP, pkt.session_id, path_id=pkt.path_id,
                      seq_num=0, payload=resp_payload)
        self.sock.sendto(resp.serialize(), addr)

    def _drop_session(self, s: ClientSession):
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
        for pid, pkt in s.scheduler.schedule(payload=b"", seq_num=s.seq_counter,
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
    if not secret:
        sys.exit("Set MYSPEEDIFY_SECRET_FILE (preferred) or MYSPEEDIFY_SECRET. No default secret exists.")
    RelayServer(secret=secret, tun=create_server_tun()).run_forever()
