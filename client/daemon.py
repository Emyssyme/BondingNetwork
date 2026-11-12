"""
MySpeedify Client Daemon
Core orchestration engine for multipath packet transmission, reordering, encryption, and telemetry.
"""

import asyncio
import socket
import select
import time
import logging
import random
import threading
from typing import Dict, List, Tuple, Optional

from core.protocol import Packet, PacketType, PacketFlag, ProbeData
from core.crypto import TunnelCrypto
from core.reorder import ReorderBuffer
from core.adapter import AdapterManager, NetworkAdapter
from core.socket_bind import create_bound_udp_socket
from core.prober import LinkProber
from core.scheduler import PacketScheduler, BondingMode
from core.tun.wintun import WintunInterface

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("MySpeedify.Client")

class ClientDaemon:
    def __init__(
        self,
        server_host: str = "127.0.0.1",
        server_port: int = 51820,
        passphrase: str = "myspeedify_secret_key_2026",
        mode: BondingMode = BondingMode.SPEED
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.server_addr = (server_host, server_port)
        
        self.session_id: int = random.randint(100000, 999999)
        self.crypto = TunnelCrypto.from_passphrase(passphrase)
        self.adapter_mgr = AdapterManager()
        self.prober = LinkProber(interval_seconds=0.4)
        self.scheduler = PacketScheduler(prober=self.prober, mode=mode)
        self.reorder_buffer = ReorderBuffer(max_buffer_size=2048, max_hold_time_ms=30.0)
        self.tun = WintunInterface()
        
        # Sockets keyed by path_id (1-indexed)
        # path_id -> (socket, NetworkAdapter)
        self.paths: Dict[int, Tuple[socket.socket, NetworkAdapter]] = {}
        
        self.seq_counter: int = 0
        self.is_running: bool = False
        self.is_connected: bool = False
        
        # Telemetry stats
        self.start_time: float = time.time()
        self.total_tx_bytes: int = 0
        self.total_rx_bytes: int = 0
        self.total_tx_packets: int = 0
        self.total_rx_packets: int = 0
        
        self.last_rate_time: float = time.time()
        self.last_adapter_scan_time: float = time.time()
        self.current_upload_mbps: float = 0.0
        self.current_download_mbps: float = 0.0

    def start(self):
        """Initializes sockets, TUN interface, and starts the processing loop in a background thread"""
        logger.info(f"Starting MySpeedify Client (Session: {self.session_id}) -> Target: {self.server_addr}")
        self.tun.open(ip="10.8.0.2")
        self.refresh_paths()
        self.is_running = True
        self.is_connected = True
        
        # Start high-performance dedicated background worker thread
        self._worker_thread = threading.Thread(target=self._background_loop, daemon=True)
        self._worker_thread.start()

    def _background_loop(self):
        while self.is_running:
            try:
                now = time.time()
                if now - self.last_adapter_scan_time > 3.0:
                    self.refresh_paths()
                    self.last_adapter_scan_time = now
                self.step()
                time.sleep(0.005)
            except Exception as e:
                logger.debug(f"Daemon worker loop error: {e}")
                time.sleep(0.02)

    def _init_paths(self):
        self.refresh_paths()

    def refresh_paths(self):
        """Scans for adapter changes and dynamically adds new sockets or removes disconnected ones"""
        adapters = self.adapter_mgr.refresh_adapters()
        new_adapter_ips = {adp.ip: adp for adp in adapters}

        # 1. Remove paths for adapters that no longer exist
        for pid, (sock, adp) in list(self.paths.items()):
            if adp.ip not in new_adapter_ips:
                try:
                    sock.close()
                except Exception:
                    pass
                del self.paths[pid]
                logger.info(f"Removed Path #{pid} [{adp.name}] ({adp.ip}) - Adapter disconnected")

        # 2. Add paths for newly discovered adapters
        existing_ips = {adp.ip for _, (_, adp) in self.paths.items()}
        for adapter in adapters:
            if adapter.ip not in existing_ips:
                next_idx = max(self.paths.keys(), default=0) + 1
                try:
                    sock = create_bound_udp_socket(local_ip=adapter.ip, port=0)
                    self.paths[next_idx] = (sock, adapter)
                    logger.info(f"Initialized Path #{next_idx} on [{adapter.name}] ({adapter.ip})")
                except Exception as e:
                    logger.warning(f"Failed to bind socket for adapter [{adapter.name}] ({adapter.ip}): {e}")

    def set_bonding_mode(self, mode_str: str):
        try:
            mode = BondingMode(mode_str.lower())
            self.scheduler.set_mode(mode)
            logger.info(f"Switched bonding mode to: {mode.value.upper()}")
            return True
        except ValueError:
            logger.error(f"Invalid bonding mode: {mode_str}")
            return False

    def toggle_adapter(self, ip: str, enabled: bool):
        adapter = self.adapter_mgr.get_adapter(ip)
        if adapter:
            adapter.enabled = enabled
            logger.info(f"Adapter {adapter.name} ({ip}) enabled={enabled}")
            return True
        return False

    def set_adapter_priority(self, ip: str, priority: int):
        adapter = self.adapter_mgr.get_adapter(ip)
        if adapter:
            adapter.priority = priority
            return True
        return False

    def get_server_addr(self) -> Tuple[str, int]:
        """Resolves dynamic DDNS hostnames (e.g. arghire.go.ro) to target IP address"""
        now = time.time()
        if not hasattr(self, '_resolved_ip') or (now - getattr(self, '_last_dns_time', 0)) > 15.0:
            try:
                self._resolved_ip = socket.gethostbyname(self.server_host)
                self._last_dns_time = now
            except Exception:
                if not hasattr(self, '_resolved_ip'):
                    self._resolved_ip = self.server_host
        return (self._resolved_ip, self.server_port)

    def step(self):
        """Single non-blocking iteration of the packet I/O engine"""
        if not self.is_running:
            return

        now = time.time()
        
        # 1. Check if prober needs to send latency/jitter probes
        if self.prober.should_probe():
            active_path_ids = [pid for pid, (_, adp) in self.paths.items() if adp.enabled]
            probes = self.prober.generate_probes(active_path_ids, self.session_id)
            target_addr = self.get_server_addr()
            for path_id, pkt in probes:
                if path_id in self.paths:
                    sock, adapter = self.paths[path_id]
                    raw_bytes = pkt.serialize()
                    try:
                        sock.sendto(raw_bytes, target_addr)
                    except Exception as e:
                        logger.debug(f"Probe send error on path {path_id}: {e}")

        # 2. Ingress: Read incoming UDP packets across all active physical sockets
        read_sockets = [sock for sock, adp in self.paths.values() if adp.enabled]
        if read_sockets:
            readable, _, _ = select.select(read_sockets, [], [], 0.002)
            for sock in readable:
                # Find path_id and adapter
                path_id = None
                adapter = None
                for pid, (s, adp) in self.paths.items():
                    if s == sock:
                        path_id = pid
                        adapter = adp
                        break
                        
                if not path_id:
                    continue

                try:
                    data, addr = sock.recvfrom(4096)
                    self._handle_ingress_packet(data, path_id, adapter)
                except BlockingIOError:
                    pass
                except Exception as e:
                    logger.debug(f"Socket recv error: {e}")

        # 3. Flush expired packets from reorder buffer to virtual TUN
        ready_payloads = self.reorder_buffer.flush_expired()
        for payload in ready_payloads:
            self.tun.write(payload)

        # 4. Egress: Read raw IP packets from virtual TUN and bond them out
        tun_pkt = self.tun.read()
        if tun_pkt:
            self._handle_egress_packet(tun_pkt)

        # 5. Periodic telemetry update
        self._update_telemetry()

    def _handle_ingress_packet(self, raw_data: bytes, path_id: int, adapter: NetworkAdapter):
        pkt = Packet.deserialize(raw_data)
        if not pkt or pkt.session_id != self.session_id:
            return

        adapter.bytes_recv += len(raw_data)
        adapter.total_rx_bytes += len(raw_data)
        self.total_rx_bytes += len(raw_data)
        self.total_rx_packets += 1

        # Probe response
        if pkt.pkt_type == PacketType.PROBE_RESP:
            self.prober.handle_probe_response(path_id, pkt.payload)
            m = self.prober.get_path_metrics(path_id)
            adapter.latency_ms = m.avg_rtt_ms
            adapter.jitter_ms = m.jitter_ms
            adapter.loss_pct = m.loss_rate * 100.0
            adapter.weight = m.weight
            return

        # Data packet
        if pkt.pkt_type == PacketType.DATA:
            try:
                decrypted = self.crypto.decrypt(pkt.payload, pkt.seq_num, pkt.path_id)
                ready_packets = self.reorder_buffer.push(pkt.seq_num, decrypted)
                for ready in ready_packets:
                    self.tun.write(ready)
            except Exception as e:
                logger.debug(f"Decryption error on seq {pkt.seq_num}: {e}")

    def _handle_egress_packet(self, ip_payload: bytes):
        self.seq_counter += 1
        seq = self.seq_counter
        
        active_paths = [(pid, adp) for pid, (_, adp) in self.paths.items() if adp.enabled]
        if not active_paths:
            return

        # Schedule packet across paths
        scheduled = self.scheduler.schedule(
            payload=b'',  # Will encrypt per path
            seq_num=seq,
            session_id=self.session_id,
            active_adapters=active_paths
        )

        target_addr = self.get_server_addr()
        for path_id, pkt in scheduled:
            encrypted_payload = self.crypto.encrypt(ip_payload, seq, path_id)
            pkt.payload = encrypted_payload
            raw_bytes = pkt.serialize()
            
            sock, adapter = self.paths[path_id]
            try:
                sock.sendto(raw_bytes, target_addr)
                adapter.bytes_sent += len(raw_bytes)
                adapter.total_tx_bytes += len(raw_bytes)
                self.total_tx_bytes += len(raw_bytes)
                self.total_tx_packets += 1
            except Exception as e:
                logger.debug(f"Send error on path {path_id}: {e}")

    def _update_telemetry(self):
        now = time.time()
        elapsed = now - self.last_rate_time
        if elapsed >= 0.5:
            # Update each adapter rate — update_rates() reads psutil directly, no args needed
            for _, adapter in self.paths.values():
                adapter.update_rates()
                
            total_up_bps = sum(adp.upload_speed_bps for _, adp in self.paths.values() if adp.enabled)
            total_down_bps = sum(adp.download_speed_bps for _, adp in self.paths.values() if adp.enabled)
            
            self.current_upload_mbps = round(total_up_bps / 1_000_000.0, 2)
            self.current_download_mbps = round(total_down_bps / 1_000_000.0, 2)
            self.last_rate_time = now

    def get_telemetry(self) -> dict:
        """Returns JSON-serializable live stats for the Dashboard UI"""
        self._update_telemetry()
        adapters_list = []
        for path_id, (_, adapter) in self.paths.items():
            d = adapter.to_dict()
            d["path_id"] = path_id
            adapters_list.append(d)

        # Calculate bonded latency (lowest active latency)
        active_latencies = [a["latency_ms"] for a in adapters_list if a["enabled"] and a["latency_ms"] > 0]
        bonded_latency = min(active_latencies) if active_latencies else 0.0

        return {
            "session_id": self.session_id,
            "is_connected": self.is_connected,
            "mode": self.scheduler.mode.value,
            "server": f"{self.server_host}:{self.server_port}",
            "uptime_seconds": int(time.time() - self.start_time),
            "upload_mbps": self.current_upload_mbps,
            "download_mbps": self.current_download_mbps,
            "bonded_latency_ms": round(bonded_latency, 1),
            "total_tx_mb": round(self.total_tx_bytes / 1_000_000.0, 2),
            "total_rx_mb": round(self.total_rx_bytes / 1_000_000.0, 2),
            "reorder_stats": self.reorder_buffer.stats(),
            "adapters": adapters_list
        }

    def stop(self):
        self.is_running = False
        self.is_connected = False
        self.tun.close()
        for sock, _ in self.paths.values():
            try:
                sock.close()
            except Exception:
                pass
        logger.info("MySpeedify Client stopped.")
