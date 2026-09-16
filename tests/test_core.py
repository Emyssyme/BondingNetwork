"""
Unit & Integration Tests for MySpeedify Core Engine
"""

import unittest
import time
from core.protocol import Packet, PacketType, PacketFlag, ProbeData
from core.crypto import TunnelCrypto
from core.reorder import ReorderBuffer
from core.scheduler import PacketScheduler, BondingMode
from core.adapter import NetworkAdapter
from core.prober import LinkProber

class TestMySpeedifyCore(unittest.TestCase):

    def test_protocol_framing(self):
        """Tests packet serialization and deserialization"""
        original_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = Packet(
            pkt_type=PacketType.DATA,
            session_id=123456,
            path_id=2,
            flags=PacketFlag.URGENT,
            seq_num=987654321,
            payload=original_payload
        )
        
        raw_bytes = pkt.serialize()
        self.assertGreater(len(raw_bytes), len(original_payload))
        
        deserialized = Packet.deserialize(raw_bytes)
        self.assertIsNotNone(deserialized)
        self.assertEqual(deserialized.pkt_type, PacketType.DATA)
        self.assertEqual(deserialized.session_id, 123456)
        self.assertEqual(deserialized.path_id, 2)
        self.assertEqual(deserialized.flags, PacketFlag.URGENT)
        self.assertEqual(deserialized.seq_num, 987654321)
        self.assertEqual(deserialized.payload, original_payload)

    def test_crypto_aead(self):
        """Tests ChaCha20-Poly1305 encryption and authentication"""
        crypto = TunnelCrypto.from_passphrase("test_password_123")
        plaintext = b"Super secret channel bonding IP packet payload"
        seq_num = 42
        path_id = 1
        
        ciphertext = crypto.encrypt(plaintext, seq_num=seq_num, path_id=path_id)
        self.assertNotEqual(ciphertext, plaintext)
        
        decrypted = crypto.decrypt(ciphertext, seq_num=seq_num, path_id=path_id)
        self.assertEqual(decrypted, plaintext)

    def test_reorder_buffer_out_of_order(self):
        """Tests reassembly when packets arrive out of order (e.g. 0, 2, 1, 3)"""
        reorder = ReorderBuffer(max_hold_time_ms=50.0)
        reorder.reset(initial_seq=0)
        
        # Seq 0 arrives
        res0 = reorder.push(0, b"pkt_0")
        self.assertEqual(res0, [b"pkt_0"])
        
        # Seq 2 arrives before Seq 1 (out of order)
        res2 = reorder.push(2, b"pkt_2")
        self.assertEqual(res2, [])  # Should hold until seq 1 arrives
        
        # Seq 1 arrives
        res1 = reorder.push(1, b"pkt_1")
        # Should now deliver seq 1 and seq 2 in order!
        self.assertEqual(res1, [b"pkt_1", b"pkt_2"])
        
        # Seq 3 arrives
        res3 = reorder.push(3, b"pkt_3")
        self.assertEqual(res3, [b"pkt_3"])

    def test_reorder_buffer_duplicate_suppression(self):
        """Tests that Redundant mode duplicate packets are cleanly dropped"""
        reorder = ReorderBuffer()
        reorder.reset(initial_seq=10)
        
        res_first = reorder.push(10, b"data_10")
        self.assertEqual(res_first, [b"data_10"])
        
        # Duplicate arrives
        res_dup = reorder.push(10, b"data_10")
        self.assertEqual(res_dup, [])
        self.assertEqual(reorder.dropped_duplicate_count, 1)

    def test_scheduler_modes(self):
        """Tests Speed, Redundant, and Failover packet scheduling"""
        prober = LinkProber()
        scheduler = PacketScheduler(prober=prober, mode=BondingMode.SPEED)
        
        adp1 = NetworkAdapter("Wi-Fi", "192.168.1.50", is_wifi=True)
        adp2 = NetworkAdapter("Cellular", "10.0.0.50", is_cellular=True)
        active = [(1, adp1), (2, adp2)]
        
        # 1. Speed Mode: distributes packets
        scheduled_speed = scheduler.schedule(b"test", seq_num=1, session_id=999, active_adapters=active)
        self.assertEqual(len(scheduled_speed), 1)
        
        # 2. Redundant Mode: replicates across all paths
        scheduler.set_mode(BondingMode.REDUNDANT)
        scheduled_red = scheduler.schedule(b"test", seq_num=2, session_id=999, active_adapters=active)
        self.assertEqual(len(scheduled_red), 2)
        self.assertEqual(scheduled_red[0][0], 1)
        self.assertEqual(scheduled_red[1][0], 2)
        self.assertEqual(scheduled_red[0][1].flags, PacketFlag.REDUNDANT)

        # 3. Failover Mode: picks single best path
        scheduler.set_mode(BondingMode.FAILOVER)
        scheduled_failover = scheduler.schedule(b"test", seq_num=3, session_id=999, active_adapters=active)
        self.assertEqual(len(scheduled_failover), 1)

if __name__ == "__main__":
    unittest.main()
