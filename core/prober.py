"""
Active Link Prober & Quality Telemetry Engine
Sends periodic probe packets on each physical link to measure real-time RTT, jitter, loss %,
and computes dynamic weights for the multipath scheduler.
"""

import time
from statistics import median
from typing import Dict, Optional, Tuple
from collections import deque
from .protocol import Packet, PacketType, PacketFlag, ProbeData

ACTIVE_PROBE_WINDOW_SECONDS = 5.0
IDLE_PROBE_INTERVAL_SECONDS = 5.0


class PathMetrics:
    PROBE_TIMEOUT_SECONDS = 3.0

    def __init__(self, path_id: int, window_size: int = 30):
        self.path_id: int = path_id
        self.window_size: int = window_size
        
        # Sliding windows for RTT and Loss
        self.rtt_history: deque[float] = deque(maxlen=window_size)
        self.sent_probes: Dict[int, float] = {}  # probe_seq -> send_timestamp
        self._probe_sizes: Dict[int, int] = {}
        self._probe_train_ids: Dict[int, int] = {}
        self._capacity_trains: Dict[int, dict] = {}
        self.capacity_history: deque[float] = deque(maxlen=window_size)
        self.capacity_bps: Optional[float] = None
        self.total_probes_sent: int = 0
        self.total_probes_lost: int = 0
        self.probe_outcomes: deque[bool] = deque(maxlen=window_size)
        
        # Computed metrics
        self.avg_rtt_ms: float = 20.0
        self.min_rtt_ms: float = 20.0
        self.jitter_ms: float = 1.0
        self.loss_rate: float = 0.0
        self.weight: float = 1.0
        self.first_probe_sent_at: float = 0.0
        self.last_alive: float = 0.0

    def record_probe_sent(
        self,
        probe_seq: int,
        *,
        sent_at: Optional[float] = None,
        pad_size: int = 0,
        train_id: Optional[int] = None,
        train_size: int = 0,
    ) -> bytes:
        now = time.monotonic() if sent_at is None else sent_at
        if not self.first_probe_sent_at:
            self.first_probe_sent_at = now
        self.sent_probes[probe_seq] = now
        self._probe_sizes[probe_seq] = ProbeData.SIZE + pad_size
        if train_id is not None:
            train = self._capacity_trains.setdefault(
                train_id, {"expected": train_size, "samples": []},
            )
            train["expected"] = train_size
            self._probe_train_ids[probe_seq] = train_id
        self.total_probes_sent += 1
        self._expire_stale_probes(now)
        self._update_metrics()
        return ProbeData.encode(
            send_time=time.time(), probe_index=probe_seq, pad_size=pad_size,
        )

    def record_probe_response(self, probe_data: bytes) -> float:
        now = time.monotonic()
        probe_seq = ProbeData.decode(probe_data)[1]
        if self._expire_stale_probes(now):
            self._update_metrics()
        
        if probe_seq in self.sent_probes:
            orig_send_time = self.sent_probes.pop(probe_seq)
            self.last_alive = now
            self.probe_outcomes.append(True)
            rtt = (now - orig_send_time) * 1000.0  # ms
            self.rtt_history.append(rtt)
            self._record_capacity_response(probe_seq, rtt)
            self._update_metrics()
            return rtt
        return 0.0

    def _record_capacity_response(self, probe_seq: int, rtt_ms: float) -> None:
        train_id = self._probe_train_ids.pop(probe_seq, None)
        probe_size = self._probe_sizes.pop(probe_seq, 0)
        if train_id is None:
            return
        train = self._capacity_trains.get(train_id)
        if train is None:
            return

        train["samples"].append((probe_seq, rtt_ms, probe_size))
        if len(train["samples"]) < train["expected"]:
            return

        samples = sorted(train["samples"])
        rtt_span_seconds = (samples[-1][1] - samples[0][1]) / 1000.0
        if rtt_span_seconds >= 0.0001:
            transferred_bytes = sum(sample[2] for sample in samples[1:])
            estimate = transferred_bytes * 8.0 / rtt_span_seconds
            if estimate > 0:
                self.capacity_history.append(estimate)
                self.capacity_bps = median(self.capacity_history)
        del self._capacity_trains[train_id]

    def _expire_stale_probes(self, now: float) -> int:
        stale_cutoff = now - self.PROBE_TIMEOUT_SECONDS
        stale_keys = [seq for seq, sent_at in self.sent_probes.items()
                      if sent_at < stale_cutoff]
        for seq in stale_keys:
            del self.sent_probes[seq]
            self._probe_sizes.pop(seq, None)
            train_id = self._probe_train_ids.pop(seq, None)
            if train_id is not None:
                self._capacity_trains.pop(train_id, None)
                self._probe_train_ids = {
                    pending_seq: pending_train
                    for pending_seq, pending_train in self._probe_train_ids.items()
                    if pending_train != train_id
                }
            self.total_probes_lost += 1
            self.probe_outcomes.append(False)
        return len(stale_keys)

    def _update_loss_rate(self):
        if self.probe_outcomes:
            lost = sum(not received for received in self.probe_outcomes)
            self.loss_rate = lost / len(self.probe_outcomes)
        else:
            self.loss_rate = 0.0

    def _update_metrics(self):
        if self.rtt_history:
            self.avg_rtt_ms = sum(self.rtt_history) / len(self.rtt_history)
            self.min_rtt_ms = min(self.rtt_history)

            # Compute RFC 3550 style jitter
            if len(self.rtt_history) >= 2:
                diffs = [
                    abs(self.rtt_history[i] - self.rtt_history[i - 1])
                    for i in range(1, len(self.rtt_history))
                ]
                self.jitter_ms = sum(diffs) / len(diffs)
            
        self._update_loss_rate()
        if not self.rtt_history and not self.probe_outcomes:
            return
        
        self.weight = max(0.1, 1.0 / (1.0 + 5.0 * self.loss_rate))


class LinkProber:
    CAPACITY_TRAIN_SIZE = 4
    CAPACITY_PROBE_PADDING = 1024

    def __init__(self, interval_seconds: float = 0.5):
        self.interval: float = interval_seconds
        self.last_probe_time: Optional[float] = None
        self.probe_seq_counter: int = 1
        self.paths: Dict[int, PathMetrics] = {}

    def get_path_metrics(self, path_id: int) -> PathMetrics:
        if path_id not in self.paths:
            self.paths[path_id] = PathMetrics(path_id)
        return self.paths[path_id]

    def should_probe(self, interval_seconds: Optional[float] = None) -> bool:
        interval = self.interval if interval_seconds is None else interval_seconds
        return (
            self.last_probe_time is None
            or time.monotonic() - self.last_probe_time >= interval
        )

    def generate_probes(
        self,
        active_path_ids: list[int],
        session_id: int,
        *,
        capacity: bool = True,
    ) -> list[Tuple[int, Packet]]:
        """Generates lightweight liveness probes or padded capacity trains."""
        now = time.monotonic()
        self.last_probe_time = now
        packets = []
        
        for path_id in active_path_ids:
            metrics = self.get_path_metrics(path_id)
            train_size = self.CAPACITY_TRAIN_SIZE if capacity else 1
            train_id = self.probe_seq_counter if capacity else None
            pad_size = self.CAPACITY_PROBE_PADDING if capacity else 0
            for _ in range(train_size):
                seq = self.probe_seq_counter
                self.probe_seq_counter += 1
                payload = metrics.record_probe_sent(
                    seq,
                    sent_at=now,
                    pad_size=pad_size,
                    train_id=train_id,
                    train_size=train_size if capacity else 0,
                )
                pkt = Packet(
                    pkt_type=PacketType.PROBE_REQ,
                    session_id=session_id,
                    path_id=path_id,
                    flags=PacketFlag.PROBE,
                    seq_num=seq,
                    payload=payload
                )
                packets.append((path_id, pkt))
            
        return packets

    def handle_probe_response(self, path_id: int, payload: bytes):
        metrics = self.get_path_metrics(path_id)
        metrics.record_probe_response(payload)
