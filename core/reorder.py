"""
Adaptive Sliding-Window Packet Reorder & Jitter Buffer
Ensures packets delivered across disparate latency paths (e.g. 10ms Ethernet, 35ms Wi-Fi, 70ms 5G)
are sequenced properly before injection into the virtual TUN interface.
"""

import time
import heapq
from typing import List, Tuple, Optional

class ReorderBuffer:
    def __init__(self, max_buffer_size: int = 2048, max_hold_time_ms: float = 25.0):
        """
        :param max_buffer_size: Max number of out-of-order packets to hold before forcing delivery.
        :param max_hold_time_ms: Max time (ms) to wait for a missing sequence number before skipping it.
        """
        self.max_buffer_size = max_buffer_size
        self.max_hold_time = max_hold_time_ms / 1000.0  # seconds
        
        self.expected_seq: int = 0
        self.initialized: bool = False
        
        # Priority queue storing (seq_num, arrival_time, payload)
        self.heap: List[Tuple[int, float, bytes]] = []
        self.seen_seqs = set()
        
        # Statistics
        self.delivered_count: int = 0
        self.out_of_order_count: int = 0
        self.dropped_duplicate_count: int = 0
        self.gap_skip_count: int = 0

    def reset(self, initial_seq: int = 0):
        self.expected_seq = initial_seq
        self.initialized = True
        self.heap.clear()
        self.seen_seqs.clear()

    def push(self, seq_num: int, payload: bytes) -> List[bytes]:
        """
        Pushes an incoming packet into the buffer.
        Returns a list of payloads ready for in-order delivery.
        """
        now = time.time()
        
        if not self.initialized:
            self.expected_seq = seq_num
            self.initialized = True
        
        # Check for duplicates or already delivered packets
        if seq_num < self.expected_seq:
            self.dropped_duplicate_count += 1
            return []
            
        if seq_num in self.seen_seqs:
            self.dropped_duplicate_count += 1
            return []
            
        self.seen_seqs.add(seq_num)
        heapq.heappush(self.heap, (seq_num, now, payload))
        
        if seq_num != self.expected_seq:
            self.out_of_order_count += 1
            
        return self._drain(now)

    def flush_expired(self) -> List[bytes]:
        """Called periodically (e.g. every 5ms) to release packets stuck behind a lost packet"""
        if not self.heap:
            return []
        return self._drain(time.time(), force_expired=True)

    def _drain(self, now: float, force_expired: bool = False) -> List[bytes]:
        ready: List[bytes] = []
        
        while self.heap:
            seq_num, arrival_time, payload = self.heap[0]
            
            # Exact match: in-order packet
            if seq_num == self.expected_seq:
                heapq.heappop(self.heap)
                self.seen_seqs.discard(seq_num)
                self.expected_seq += 1
                self.delivered_count += 1
                ready.append(payload)
                continue
            
            # Sequence gap detected (seq_num > expected_seq)
            age = now - arrival_time
            # If the oldest queued packet has exceeded max hold time, or buffer is full, skip missing seq
            if age >= self.max_hold_time or len(self.heap) >= self.max_buffer_size or force_expired:
                # Gap skip: advance expected_seq to this packet's seq
                skipped_gaps = seq_num - self.expected_seq
                self.gap_skip_count += max(1, skipped_gaps)
                self.expected_seq = seq_num
                
                heapq.heappop(self.heap)
                self.seen_seqs.discard(seq_num)
                self.expected_seq += 1
                self.delivered_count += 1
                ready.append(payload)
            else:
                # Still waiting for missing packets within hold window
                break
                
        # Clean up stale items in seen_seqs
        if len(self.seen_seqs) > self.max_buffer_size * 2:
            self.seen_seqs = {s for s in self.seen_seqs if s >= self.expected_seq}
            
        return ready

    def stats(self) -> dict:
        return {
            "expected_seq": self.expected_seq,
            "buffered_packets": len(self.heap),
            "delivered": self.delivered_count,
            "out_of_order": self.out_of_order_count,
            "duplicates_dropped": self.dropped_duplicate_count,
            "gap_skips": self.gap_skip_count
        }
