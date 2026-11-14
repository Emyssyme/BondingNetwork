"""
MySpeedify Aggregation Relay Server
Aggregates multipath uplink streams from clients, reassembles IP packets,
and schedules downlink traffic back across available client paths.
"""

import socket
import select
import time
import logging
import random
from typing import Dict, Tuple, Optional
from core.protocol import Packet, PacketType, PacketFlag, ProbeData
from core.crypto import TunnelCrypto
from core.reorder import ReorderBuffer
from core.scheduler import PacketScheduler, BondingMode
from core.adapter import NetworkAdapter
from core.prober import LinkProber
from core.secret import load_secret

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("MySpeedify.RelayServer")

class ClientSession:
    def __init__(self, session_id: int, crypto: TunnelCrypto):
        self.session_id = session_id
        self.crypto = crypto
        self.reorder_buffer = ReorderBuffer()
        self.prober = LinkProber()
        self.scheduler = PacketScheduler(self.prober, mode=BondingMode.SPEED)
        
        # Maps path_id -> (remote_ip, remote_port, last_seen_time, dummy_adapter)
        self.paths: Dict[int, Tuple[str, int, float, NetworkAdapter]] = {}
        self.seq_counter: int = 0
        self.last_activity: float = time.time()

    def update_path(self, path_id: int, addr: Tuple[str, int]):
        now = time.time()
        self.last_activity = now
        if path_id not in self.paths:
            adapter = NetworkAdapter(name=f"Path-{path_id}", ip=addr[0])
            self.paths[path_id] = (addr[0], addr[1], now, adapter)
            logger.info(f"Client [{self.session_id}] registered Path #{path_id} from {addr[0]}:{addr[1]}")
        else:
            _, _, _, adapter = self.paths[path_id]
            self.paths[path_id] = (addr[0], addr[1], now, adapter)


class RelayServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 51820,
        passphrase: Optional[str] = None,
    ):
        if passphrase is None:
            passphrase = load_secret()
        if not passphrase:
            raise ValueError(
                "A relay passphrase is required via the constructor or "
                "MYSPEEDIFY_SECRET/MYSPEEDIFY_SECRET_FILE."
            )
        self.host = host
        self.port = port
        self.crypto = TunnelCrypto.from_passphrase(passphrase)
        self.sock: Optional[socket.socket] = None
        self.is_running: bool = False
        self.sessions: Dict[int, ClientSession] = {}
        
        # Telemetry
        self.total_packets_routed: int = 0
        self.total_bytes_routed: int = 0

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.setblocking(False)
        self.is_running = True
        logger.info(f"MySpeedify Relay Server listening on UDP {self.host}:{self.port}")

    def step(self):
        if not self.is_running or not self.sock:
            return

        readable, _, _ = select.select([self.sock], [], [], 0.002)
        if readable:
            try:
                data, addr = self.sock.recvfrom(4096)
                self._handle_incoming(data, addr)
            except BlockingIOError:
                pass
            except Exception as e:
                logger.debug(f"Relay recv error: {e}")

    def _handle_incoming(self, raw_data: bytes, addr: Tuple[str, int]):
        pkt = Packet.deserialize(raw_data)
        if not pkt:
            return

        session_id = pkt.session_id
        if session_id not in self.sessions:
            self.sessions[session_id] = ClientSession(session_id, self.crypto)
            
        session = self.sessions[session_id]
        session.update_path(pkt.path_id, addr)

        # Handle Link Probe: immediately echo response
        if pkt.pkt_type == PacketType.PROBE_REQ:
            resp_pkt = Packet(
                pkt_type=PacketType.PROBE_RESP,
                session_id=session_id,
                path_id=pkt.path_id,
                flags=PacketFlag.PROBE,
                seq_num=0,
                payload=pkt.payload
            )
            self.sock.sendto(resp_pkt.serialize(), addr)
            return

        # Handle Data Uplink Packet
        if pkt.pkt_type == PacketType.DATA:
            try:
                decrypted = self.crypto.decrypt(pkt.payload, pkt.seq_num, pkt.path_id)
                ready_packets = session.reorder_buffer.push(pkt.seq_num, decrypted)
                
                self.total_packets_routed += 1
                self.total_bytes_routed += len(raw_data)
                
                # In full Linux NAT mode, packets are written to Server TUN (/dev/net/tun)
                # and routed to the internet.
            except Exception as e:
                logger.debug(f"Relay decryption error: {e}")

    def stop(self):
        self.is_running = False
        if self.sock:
            self.sock.close()
        logger.info("MySpeedify Relay Server stopped.")

    def run_forever(self):
        self.start()
        try:
            while self.is_running:
                self.step()
        except KeyboardInterrupt:
            self.stop()

if __name__ == "__main__":
    server = RelayServer()
    server.run_forever()
