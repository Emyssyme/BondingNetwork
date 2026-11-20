"""
MySpeedify Protocol Specification
Binary Packet Framing for Multipath Bonding VPN

Header Layout (20 Bytes):
+--------------------+--------------------+--------------------+
| Magic (2B) 0x5350  | Version (1B) 0x01  | PacketType (1B)    |
+--------------------+--------------------+--------------------+
| SessionID (4B UInt32)                                        |
+--------------------+--------------------+--------------------+
| PathID (1B UInt8)  | Flags (1B UInt8)   | Reserved (2B)      |
+--------------------+--------------------+--------------------+
| SequenceNumber (8B UInt64)                                   |
+--------------------+--------------------+--------------------+
| Payload (N Bytes: Encrypted IP Packet / Control Data)        |
+--------------------+--------------------+--------------------+
"""

import struct
import time
from enum import IntEnum

MAGIC = 0x5350  # 'SP' in ASCII
PROTOCOL_VERSION = 0x01
HEADER_FORMAT = "!HBBIBB2sQ"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 20 bytes

class PacketType(IntEnum):
    HANDSHAKE_INIT = 0x01
    HANDSHAKE_RESP = 0x02
    DATA = 0x10
    PROBE_REQ = 0x20
    PROBE_RESP = 0x21
    ACK = 0x30
    HEARTBEAT = 0x40
    DISCONNECT = 0xFF

class PacketFlag(IntEnum):
    NONE = 0x00
    REDUNDANT = 0x01      # Packet was duplicated for stream protection
    URGENT = 0x02         # Low-latency packet (DNS, TCP SYN/ACK, VoIP)
    PROBE = 0x04          # Diagnostic probe packet
    COMPRESSED = 0x08     # Compressed payload
    FAILOVER = 0x10       # Client requests primary/standby downlink scheduling
    PRIORITY_SECONDARY = 0x20
    PRIORITY_BACKUP = 0x40


_PATH_PRIORITY_MASK = PacketFlag.PRIORITY_SECONDARY | PacketFlag.PRIORITY_BACKUP


def encode_path_priority(flags: int, priority: int) -> int:
    if priority not in (0, 1, 2):
        raise ValueError("Path priority must be 0, 1, or 2")
    encoded = int(flags) & ~int(_PATH_PRIORITY_MASK)
    if priority == 2:
        encoded |= int(PacketFlag.PRIORITY_SECONDARY)
    elif priority == 0:
        encoded |= int(PacketFlag.PRIORITY_BACKUP)
    return encoded


def decode_path_priority(flags: int) -> int | None:
    priority_bits = int(flags) & int(_PATH_PRIORITY_MASK)
    if priority_bits == int(PacketFlag.PRIORITY_SECONDARY):
        return 2
    if priority_bits == int(PacketFlag.PRIORITY_BACKUP):
        return 0
    if priority_bits == 0:
        return 1
    return None

class Packet:
    __slots__ = (
        'version', 'pkt_type', 'session_id', 'path_id',
        'flags', 'seq_num', 'payload', 'timestamp'
    )

    def __init__(
        self,
        pkt_type: PacketType,
        session_id: int,
        path_id: int = 0,
        flags: int = PacketFlag.NONE,
        seq_num: int = 0,
        payload: bytes = b'',
        version: int = PROTOCOL_VERSION
    ):
        self.version = version
        self.pkt_type = pkt_type
        self.session_id = session_id
        self.path_id = path_id
        self.flags = flags
        self.seq_num = seq_num
        self.payload = payload
        self.timestamp = time.time()

    def header_bytes(self) -> bytes:
        return struct.pack(
            HEADER_FORMAT, MAGIC, self.version, int(self.pkt_type), self.session_id,
            self.path_id, int(self.flags), b'\x00\x00', self.seq_num
        )

    def serialize(self) -> bytes:
        return self.header_bytes() + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> 'Packet | None':
        if len(data) < HEADER_SIZE:
            return None
        
        magic, version, pkt_type_val, session_id, path_id, flags, _, seq_num = struct.unpack(
            HEADER_FORMAT, data[:HEADER_SIZE]
        )
        
        if magic != MAGIC:
            return None
        
        try:
            pkt_type = PacketType(pkt_type_val)
        except ValueError:
            return None

        payload = data[HEADER_SIZE:]
        return cls(
            pkt_type=pkt_type,
            session_id=session_id,
            path_id=path_id,
            flags=flags,
            seq_num=seq_num,
            payload=payload,
            version=version
        )

    def __repr__(self) -> str:
        return (
            f"<Packet type={self.pkt_type.name} session={self.session_id} "
            f"path={self.path_id} seq={self.seq_num} len={len(self.payload)}>"
        )


class ProbeData:
    """Structure for RTT and Capacity measurement probes"""
    FORMAT = "!dQI"  # send_time (double), probe_index (uint64), padding_len (uint32)
    SIZE = struct.calcsize(FORMAT)

    @staticmethod
    def encode(send_time: float, probe_index: int, pad_size: int = 0) -> bytes:
        header = struct.pack(ProbeData.FORMAT, send_time, probe_index, pad_size)
        return header + (b'\x00' * pad_size)

    @staticmethod
    def decode(data: bytes) -> tuple[float, int, int]:
        if len(data) < ProbeData.SIZE:
            return 0.0, 0, 0
        send_time, probe_index, pad_size = struct.unpack(ProbeData.FORMAT, data[:ProbeData.SIZE])
        return send_time, probe_index, pad_size
