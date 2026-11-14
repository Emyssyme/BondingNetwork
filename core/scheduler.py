"""
Multipath Packet Scheduler
Distributes tunnel traffic across multiple physical network interfaces according to the chosen bonding mode.
"""

from enum import Enum
from collections import OrderedDict
import os
import struct
import time
from typing import List, Dict, Tuple, Optional
from .protocol import Packet, PacketType, PacketFlag
from .adapter import NetworkAdapter
from .prober import LinkProber

FlowKey = Tuple[int, int, Tuple[bytes, int], Tuple[bytes, int]]


def _extract_flow_key(payload: bytes) -> Optional[FlowKey]:
    if not payload:
        return None

    version = payload[0] >> 4
    if version == 4:
        if len(payload) < 20:
            return None
        header_length = (payload[0] & 0x0F) * 4
        total_length = struct.unpack_from("!H", payload, 2)[0]
        if (
            header_length < 20
            or total_length < header_length + 4
            or total_length > len(payload)
            or struct.unpack_from("!H", payload, 6)[0] & 0x3FFF
        ):
            return None
        protocol = payload[9]
        source = payload[12:16]
        destination = payload[16:20]
        transport_offset = header_length
        packet_end = total_length
    elif version == 6:
        if len(payload) < 40:
            return None
        payload_length = struct.unpack_from("!H", payload, 4)[0]
        packet_end = 40 + payload_length
        if payload_length < 4 or packet_end > len(payload):
            return None
        source = payload[8:24]
        destination = payload[24:40]
        protocol = payload[6]
        transport_offset = 40

        for _ in range(8):
            if protocol in (0, 43, 60):
                if transport_offset + 2 > packet_end:
                    return None
                extension_length = (payload[transport_offset + 1] + 1) * 8
            elif protocol == 51:
                if transport_offset + 2 > packet_end:
                    return None
                extension_length = (payload[transport_offset + 1] + 2) * 4
            elif protocol == 44:
                return None
            else:
                break

            if (
                extension_length < 8
                or transport_offset + extension_length > packet_end
            ):
                return None
            protocol = payload[transport_offset]
            transport_offset += extension_length
    else:
        return None

    if protocol not in (6, 17):
        return None
    if protocol == 6:
        if transport_offset + 20 > packet_end:
            return None
        tcp_header_length = (payload[transport_offset + 12] >> 4) * 4
        if (
            tcp_header_length < 20
            or transport_offset + tcp_header_length > packet_end
        ):
            return None
    else:
        if transport_offset + 8 > packet_end:
            return None
        udp_length = struct.unpack_from("!H", payload, transport_offset + 4)[0]
        if udp_length < 8 or transport_offset + udp_length > packet_end:
            return None

    source_port, destination_port = struct.unpack_from(
        "!HH", payload, transport_offset,
    )
    source_endpoint = (source, source_port)
    destination_endpoint = (destination, destination_port)
    if destination_endpoint < source_endpoint:
        source_endpoint, destination_endpoint = destination_endpoint, source_endpoint
    return version, protocol, source_endpoint, destination_endpoint


class BondingMode(str, Enum):
    SPEED = "speed"            # Dynamic Capacity & Latency Weighted Bonding
    REDUNDANT = "redundant"    # Duplicate Stream Protection (0% packet loss)
    FAILOVER = "failover"      # Primary Link with instantaneous Hot Standby

class PacketScheduler:
    FAILOVER_PROBE_TIMEOUT_SECONDS = 3.0
    FAILOVER_MAX_LOSS_RATE = 0.5
    FAILBACK_HYSTERESIS_SECONDS = 3.0
    FLOW_PIN_IDLE_SECONDS = 120.0
    MAX_PINNED_FLOWS = 1024
    PRIORITY_ORDER = {1: 0, 2: 1, 0: 2}

    def __init__(
        self,
        prober: LinkProber,
        mode: BondingMode = BondingMode.SPEED,
        flow_pinning: Optional[bool] = None,
    ):
        self.prober: LinkProber = prober
        self.mode: BondingMode = mode
        self.flow_pinning = (
            os.environ.get("MYSPEEDIFY_FLOW_PINNING") == "1"
            if flow_pinning is None
            else flow_pinning
        )
        self._flow_pins: OrderedDict[FlowKey, Tuple[int, float]] = OrderedDict()
        self.round_robin_idx: int = 0
        self.deficit_counters: Dict[int, float] = {}  # Deficit Round Robin counters
        self._failover_path_id: Optional[int] = None
        self._failback_candidate_id: Optional[int] = None
        self._failback_candidate_since: Optional[float] = None

    def set_mode(self, mode: BondingMode):
        if self.mode != mode:
            self._failover_path_id = None
            self._failback_candidate_id = None
            self._failback_candidate_since = None
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
        active_adapters = [
            (path_id, adapter)
            for path_id, adapter in active_adapters
            if adapter.enabled
        ]
        if not active_adapters:
            return []

        # If Redundant mode is active OR if packet is flagged urgent (e.g. DNS, TCP Handshake)
        if self.mode == BondingMode.REDUNDANT or is_urgent:
            # Replicate packet across all active paths
            result = []
            for path_id, _ in active_adapters:
                flags = PacketFlag.REDUNDANT if self.mode == BondingMode.REDUNDANT else PacketFlag.URGENT
                if self.mode == BondingMode.FAILOVER:
                    flags |= PacketFlag.FAILOVER
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

        # Failover mode keeps the current tier and delays failback to a better tier.
        if self.mode == BondingMode.FAILOVER:
            best_path_id = self._select_failover_path(active_adapters)
            if best_path_id is None:
                return []
            pkt = Packet(
                pkt_type=PacketType.DATA,
                session_id=session_id,
                path_id=best_path_id,
                flags=PacketFlag.FAILOVER,
                seq_num=seq_num,
                payload=payload
            )
            return [(best_path_id, pkt)]

        # Speed Mode (Dynamic Weighted Deficit Round-Robin)
        flow_key = _extract_flow_key(payload) if self.flow_pinning else None
        if flow_key is None:
            chosen_path_id = self._select_weighted_path(active_adapters, len(payload))
        else:
            chosen_path_id = self._select_flow_pinned_path(
                flow_key, active_adapters, len(payload),
            )
        pkt = Packet(
            pkt_type=PacketType.DATA,
            session_id=session_id,
            path_id=chosen_path_id,
            flags=PacketFlag.NONE,
            seq_num=seq_num,
            payload=payload
        )
        return [(chosen_path_id, pkt)]

    def _select_flow_pinned_path(
        self,
        flow_key: FlowKey,
        active_adapters: List[Tuple[int, NetworkAdapter]],
        packet_size: int,
    ) -> int:
        now = time.monotonic()
        while self._flow_pins:
            _, (_, last_used) = next(iter(self._flow_pins.items()))
            if now - last_used <= self.FLOW_PIN_IDLE_SECONDS:
                break
            self._flow_pins.popitem(last=False)

        active_path_ids = {path_id for path_id, _ in active_adapters}
        pinned = self._flow_pins.get(flow_key)
        if pinned is not None:
            path_id, _ = pinned
            if path_id in active_path_ids:
                self._flow_pins.move_to_end(flow_key)
                self._flow_pins[flow_key] = (path_id, now)
                return path_id
            del self._flow_pins[flow_key]

        path_id = self._select_weighted_path(active_adapters, packet_size)
        if len(self._flow_pins) >= self.MAX_PINNED_FLOWS:
            self._flow_pins.popitem(last=False)
        self._flow_pins[flow_key] = (path_id, now)
        return path_id

    def _select_failover_path(
        self, active_adapters: List[Tuple[int, NetworkAdapter]]
    ) -> Optional[int]:
        now = time.monotonic()
        confirmed = []
        provisional = []
        for path_id, adapter in active_adapters:
            metrics = self.prober.get_path_metrics(path_id)
            probing = bool(metrics.first_probe_sent_at)
            unproven_within_grace = (
                probing
                and metrics.last_alive == 0.0
                and now - metrics.first_probe_sent_at <= self.FAILOVER_PROBE_TIMEOUT_SECONDS
            )
            has_recent_response = (
                metrics.last_alive > 0.0
                and now - metrics.last_alive <= self.FAILOVER_PROBE_TIMEOUT_SECONDS
            )
            never_probed = not probing and metrics.last_alive == 0.0
            if has_recent_response and metrics.loss_rate < self.FAILOVER_MAX_LOSS_RATE:
                confirmed.append((path_id, adapter, metrics))
            elif never_probed or unproven_within_grace:
                provisional.append((path_id, adapter, metrics))

        viable = confirmed or provisional
        if not viable:
            self._failover_path_id = None
            self._clear_failback_candidate()
            return None

        viable.sort(key=lambda item: (
            self.PRIORITY_ORDER.get(item[1].priority, len(self.PRIORITY_ORDER)),
            item[2].loss_rate,
            item[2].avg_rtt_ms,
            item[0],
        ))
        best_path_id, best_adapter, _ = viable[0]
        current = next(
            (item for item in viable if item[0] == self._failover_path_id),
            None,
        )
        if current is None:
            self._failover_path_id = best_path_id
            self._clear_failback_candidate()
            return best_path_id

        current_priority = self.PRIORITY_ORDER.get(
            current[1].priority, len(self.PRIORITY_ORDER),
        )
        best_priority = self.PRIORITY_ORDER.get(
            best_adapter.priority, len(self.PRIORITY_ORDER),
        )
        if best_path_id == self._failover_path_id or best_priority >= current_priority:
            self._clear_failback_candidate()
            return self._failover_path_id

        if self._failback_candidate_id != best_path_id:
            self._failback_candidate_id = best_path_id
            self._failback_candidate_since = now
            return self._failover_path_id

        if (
            self._failback_candidate_since is not None
            and now - self._failback_candidate_since >= self.FAILBACK_HYSTERESIS_SECONDS
        ):
            self._failover_path_id = best_path_id
            self._clear_failback_candidate()
            return best_path_id
        return self._failover_path_id

    def _clear_failback_candidate(self) -> None:
        self._failback_candidate_id = None
        self._failback_candidate_since = None

    def _select_weighted_path(
        self,
        active_adapters: List[Tuple[int, NetworkAdapter]],
        packet_size: int,
    ) -> int:
        if len(active_adapters) == 1:
            return active_adapters[0][0]

        # Update weights from prober & adapter user weight
        total_weight = 0.0
        weights = {}
        for path_id, adapter in active_adapters:
            m = self.prober.get_path_metrics(path_id)
            # adapter.weight is the manual factor; m.weight already includes live quality and loss.
            w = max(0.1, adapter.weight) * m.weight
            weights[path_id] = w
            total_weight += w

        # Add each path's share of this packet's byte cost, then charge the selected path.
        packet_size = max(1, packet_size)
        for path_id, _ in active_adapters:
            w = weights.get(path_id, 1.0)
            self.deficit_counters[path_id] = (
                self.deficit_counters.get(path_id, 0.0)
                + (w / total_weight) * packet_size
            )

        # Pick path with highest deficit counter
        best_path_id = max(active_adapters, key=lambda item: self.deficit_counters.get(item[0], 0.0))[0]
        self.deficit_counters[best_path_id] -= packet_size
        
        return best_path_id
