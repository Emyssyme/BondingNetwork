"""
Multipath Packet Scheduler
Distributes tunnel traffic across multiple physical network interfaces according to the chosen bonding mode.
"""

from enum import Enum
from typing import List, Dict, Tuple, Optional
from .protocol import Packet, PacketType, PacketFlag
from .adapter import NetworkAdapter
from .prober import LinkProber

class BondingMode(str, Enum):
    SPEED = "speed"            # Dynamic Capacity & Latency Weighted Bonding
    REDUNDANT = "redundant"    # Duplicate Stream Protection (0% packet loss)
    FAILOVER = "failover"      # Primary Link with instantaneous Hot Standby

class PacketScheduler:
    def __init__(self, prober: LinkProber, mode: BondingMode = BondingMode.SPEED):
        self.prober: LinkProber = prober
        self.mode: BondingMode = mode
        self.round_robin_idx: int = 0
        self.deficit_counters: Dict[int, float] = {}  # Deficit Round Robin counters

    def set_mode(self, mode: BondingMode):
        self.mode = mode

    def schedule(
        self,
        payload: bytes,
        seq_num: int,
        session_id: int,
        active_adapters: List[Tuple[int, NetworkAdapter]],  # [(path_id, adapter)]
        is_urgent: bool = False
    ) -> List[Tuple[int, Packet]]:
        """
        Schedules an IP packet across one or multiple network paths.
        Returns a list of (path_id, Packet) tuples to transmit.
        """
        if not active_adapters:
            return []

        # If Redundant mode is active OR if packet is flagged urgent (e.g. DNS, TCP Handshake)
        if self.mode == BondingMode.REDUNDANT or is_urgent:
            # Replicate packet across all active paths
            result = []
            for path_id, _ in active_adapters:
                flags = PacketFlag.REDUNDANT if self.mode == BondingMode.REDUNDANT else PacketFlag.URGENT
                pkt = Packet(
                    pkt_type=PacketType.DATA,
                    session_id=session_id,
                    path_id=path_id,
                    flags=flags,
                    seq_num=seq_num,
                    payload=payload
                )
                result.append((path_id, pkt))
            return result

        # Failover Mode: Pick highest priority path with lowest loss
        if self.mode == BondingMode.FAILOVER:
            # Sort by priority (1 is highest), then by loss/latency
            sorted_adapters = sorted(
                active_adapters,
                key=lambda item: (
                    -item[1].priority,
                    self.prober.get_path_metrics(item[0]).loss_rate,
                    self.prober.get_path_metrics(item[0]).avg_rtt_ms
                )
            )
            best_path_id, _ = sorted_adapters[0]
            pkt = Packet(
                pkt_type=PacketType.DATA,
                session_id=session_id,
                path_id=best_path_id,
                flags=PacketFlag.NONE,
                seq_num=seq_num,
                payload=payload
            )
            return [(best_path_id, pkt)]

        # Speed Mode (Dynamic Weighted Deficit Round-Robin)
        chosen_path_id = self._select_weighted_path(active_adapters)
        pkt = Packet(
            pkt_type=PacketType.DATA,
            session_id=session_id,
            path_id=chosen_path_id,
            flags=PacketFlag.NONE,
            seq_num=seq_num,
            payload=payload
        )
        return [(chosen_path_id, pkt)]

    def _select_weighted_path(self, active_adapters: List[Tuple[int, NetworkAdapter]]) -> int:
        if len(active_adapters) == 1:
            return active_adapters[0][0]

        # Update weights from prober & adapter user weight
        total_weight = 0.0
        weights = {}
        for path_id, adapter in active_adapters:
            m = self.prober.get_path_metrics(path_id)
            # Combine adapter priority weight and live network quality weight
            w = max(0.1, adapter.weight * m.weight * (1.0 - m.loss_rate * 0.8))
            weights[path_id] = w
            total_weight += w

        # Deficit Round Robin quantum distribution
        quantum = 1000.0  # Base bytes/quantum unit
        for path_id, _ in active_adapters:
            w = weights.get(path_id, 1.0)
            self.deficit_counters[path_id] = self.deficit_counters.get(path_id, 0.0) + (w / total_weight) * quantum

        # Pick path with highest deficit counter
        best_path_id = max(active_adapters, key=lambda item: self.deficit_counters.get(item[0], 0.0))[0]
        self.deficit_counters[best_path_id] = max(0.0, self.deficit_counters.get(best_path_id, 0.0) - quantum)
        
        return best_path_id
