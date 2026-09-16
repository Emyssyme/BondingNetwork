"""
Active Link Prober & Quality Telemetry Engine
Sends periodic probe packets on each physical link to measure real-time RTT, jitter, loss %,
and computes dynamic weights for the multipath scheduler.
"""

import time
from typing import Dict, Optional, Tuple
from collections import deque
from .protocol import Packet, PacketType, PacketFlag, ProbeData

class PathMetrics:
    def __init__(self, path_id: int, window_size: int = 30):
        self.path_id: int = path_id
        self.window_size: int = window_size
        
        # Sliding windows for RTT and Loss
        self.rtt_history: deque[float] = deque(maxlen=window_size)
        self.sent_probes: Dict[int, float] = {}  # probe_seq -> send_timestamp
        self.total_probes_sent: int = 0
        self.total_probes_lost: int = 0
        
        # Computed metrics
        self.avg_rtt_ms: float = 20.0
        self.min_rtt_ms: float = 20.0
        self.jitter_ms: float = 1.0
        self.loss_rate: float = 0.0
        self.weight: float = 1.0
        self.last_alive: float = time.time()

    def record_probe_sent(self, probe_seq: int) -> bytes:
        now = time.time()
        self.sent_probes[probe_seq] = now
        self.total_probes_sent += 1
        
        # Clean up stale unacknowledged probes older than 3 seconds (mark as loss)
        stale_cutoff = now - 3.0
        stale_keys = [k for k, t in self.sent_probes.items() if t < stale_cutoff]
        for k in stale_keys:
            del self.sent_probes[k]
            self.total_probes_lost += 1
            
        self._update_loss_rate()
        return ProbeData.encode(send_time=now, probe_index=probe_seq)

    def record_probe_response(self, probe_data: bytes) -> float:
        now = time.time()
        self.last_alive = now
        send_time, probe_seq, _ = ProbeData.decode(probe_data)
        
        if probe_seq in self.sent_probes:
            orig_send_time = self.sent_probes.pop(probe_seq)
            rtt = (now - orig_send_time) * 1000.0  # ms
            self.rtt_history.append(rtt)
            self._update_metrics()
            return rtt
        return 0.0

    def _update_loss_rate(self):
        recent_total = min(self.total_probes_sent, self.window_size)
        if recent_total > 0:
            self.loss_rate = min(1.0, len(self.sent_probes) / recent_total)
        else:
            self.loss_rate = 0.0

    def _update_metrics(self):
        if not self.rtt_history:
            return
            
        self.avg_rtt_ms = sum(self.rtt_history) / len(self.rtt_history)
        self.min_rtt_ms = min(self.rtt_history)
        
        # Compute RFC 3550 style jitter
        if len(self.rtt_history) >= 2:
            diffs = [abs(self.rtt_history[i] - self.rtt_history[i - 1]) for i in range(1, len(self.rtt_history))]
            self.jitter_ms = sum(diffs) / len(diffs)
            
        self._update_loss_rate()
        
        # Dynamic link weight: higher weight = faster/lower latency and lower loss
        # Weight ~ 1 / (avg_rtt * (1 + 10 * loss_rate))
        effective_rtt = max(1.0, self.avg_rtt_ms) * (1.0 + 5.0 * self.loss_rate)
        self.weight = max(0.1, min(10.0, 100.0 / effective_rtt))


class LinkProber:
    def __init__(self, interval_seconds: float = 0.5):
        self.interval: float = interval_seconds
        self.last_probe_time: float = 0.0
        self.probe_seq_counter: int = 1
        self.paths: Dict[int, PathMetrics] = {}

    def get_path_metrics(self, path_id: int) -> PathMetrics:
        if path_id not in self.paths:
            self.paths[path_id] = PathMetrics(path_id)
        return self.paths[path_id]

    def should_probe(self) -> bool:
        return (time.time() - self.last_probe_time) >= self.interval

    def generate_probes(self, active_path_ids: list[int], session_id: int) -> list[Tuple[int, Packet]]:
        """Generates probe request packets for all active paths"""
        now = time.time()
        self.last_probe_time = now
        packets = []
        
        for path_id in active_path_ids:
            metrics = self.get_path_metrics(path_id)
            seq = self.probe_seq_counter
            self.probe_seq_counter += 1
            payload = metrics.record_probe_sent(seq)
            
            pkt = Packet(
                pkt_type=PacketType.PROBE_REQ,
                session_id=session_id,
                path_id=path_id,
                flags=PacketFlag.PROBE,
                seq_num=0,
                payload=payload
            )
            packets.append((path_id, pkt))
            
        return packets

    def handle_probe_response(self, path_id: int, payload: bytes):
        metrics = self.get_path_metrics(path_id)
        metrics.record_probe_response(payload)
