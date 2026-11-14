"""
Unit & Integration Tests for MySpeedify Core Engine
"""

import unittest
import socket
import struct
from unittest.mock import patch
from core.protocol import Packet, PacketType, PacketFlag
from core.crypto import TunnelCrypto
from core.reorder import ReorderBuffer
from core.replay import ReplayWindow
from core.scheduler import PacketScheduler, BondingMode
from core.adapter import NetworkAdapter
from core.prober import LinkProber


def _ipv4_udp_packet(source, destination, source_port, destination_port):
    packet = bytearray(28)
    packet[0] = 0x45
    struct.pack_into("!H", packet, 2, len(packet))
    packet[9] = 17
    packet[12:16] = socket.inet_aton(source)
    packet[16:20] = socket.inet_aton(destination)
    struct.pack_into("!HH", packet, 20, source_port, destination_port)
    struct.pack_into("!H", packet, 24, 8)
    return bytes(packet)


def _ipv4_tcp_packet(source, destination, source_port, destination_port):
    packet = bytearray(40)
    packet[0] = 0x45
    struct.pack_into("!H", packet, 2, len(packet))
    packet[9] = 6
    packet[12:16] = socket.inet_aton(source)
    packet[16:20] = socket.inet_aton(destination)
    struct.pack_into("!HH", packet, 20, source_port, destination_port)
    packet[32] = 0x50
    return bytes(packet)


def _ipv6_udp_packet(
    source, destination, source_port, destination_port, destination_options=False,
):
    extension_length = 8 if destination_options else 0
    packet = bytearray(48 + extension_length)
    packet[0] = 0x60
    struct.pack_into("!H", packet, 4, 8 + extension_length)
    packet[6] = 60 if destination_options else 17
    packet[8:24] = socket.inet_pton(socket.AF_INET6, source)
    packet[24:40] = socket.inet_pton(socket.AF_INET6, destination)
    transport_offset = 40
    if destination_options:
        packet[40] = 17
        transport_offset += extension_length
    struct.pack_into(
        "!HH", packet, transport_offset, source_port, destination_port,
    )
    struct.pack_into("!H", packet, transport_offset + 4, 8)
    return bytes(packet)


class TestMySpeedifyCore(unittest.TestCase):

    def test_replay_window_rejects_repeats_and_out_of_window_sequences(self):
        window = ReplayWindow(size=4)

        self.assertTrue(window.accept(10))
        self.assertTrue(window.accept(8))
        self.assertFalse(window.accept(8))
        self.assertTrue(window.accept(14))
        self.assertFalse(window.accept(10))
        self.assertFalse(window.accept(-1))

    def test_adapter_rates_use_path_counters(self):
        with patch("core.adapter.time.monotonic", side_effect=[99.0, 100.0, 101.0]), \
                patch("core.adapter.psutil.net_io_counters", side_effect=AssertionError):
            adapter = NetworkAdapter("Wi-Fi", "192.168.1.50", is_wifi=True)
            adapter.update_rates(0, 0)
            adapter.update_rates(500, 1000)

        self.assertEqual(adapter.upload_speed_bps, 4000.0)
        self.assertEqual(adapter.download_speed_bps, 8000.0)
        self.assertEqual(adapter.total_tx_bytes, 0)
        self.assertEqual(adapter.total_rx_bytes, 0)

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
        self.assertEqual(reorder.stats()["delayed"], 0)
        
        # Seq 1 arrives
        res1 = reorder.push(1, b"pkt_1")
        # Should now deliver seq 1 and seq 2 in order!
        self.assertEqual(res1, [b"pkt_1", b"pkt_2"])
        self.assertEqual(reorder.stats()["delayed"], 1)
        
        # Seq 3 arrives
        res3 = reorder.push(3, b"pkt_3")
        self.assertEqual(res3, [b"pkt_3"])

    def test_reorder_buffer_initializes_from_first_packet_and_separates_duplicates(self):
        reorder = ReorderBuffer()

        self.assertEqual(reorder.push(42, b"first"), [b"first"])
        self.assertEqual(reorder.push(42, b"duplicate"), [])
        self.assertEqual(reorder.stats()["delayed"], 0)
        self.assertEqual(reorder.stats()["duplicates_dropped"], 1)
        self.assertEqual(reorder.stats()["expected_seq"], 43)

    def test_reorder_buffer_reports_next_expiry_deadline(self):
        reorder = ReorderBuffer(max_hold_time_ms=30.0)
        reorder.reset(initial_seq=0)

        with patch("core.reorder.time.time", return_value=100.0):
            self.assertEqual(reorder.push(1, b"held"), [])
        with patch("core.reorder.time.time", return_value=100.012):
            self.assertAlmostEqual(reorder.time_until_expiry(), 0.018)
        with patch("core.reorder.time.time", return_value=100.04):
            self.assertEqual(reorder.time_until_expiry(), 0.0)

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
        self.assertTrue(scheduled_failover[0][1].flags & PacketFlag.FAILOVER)

    def test_speed_weight_combines_manual_and_dynamic_factors_by_bytes(self):
        prober = LinkProber()
        scheduler = PacketScheduler(prober=prober, mode=BondingMode.SPEED)
        primary = NetworkAdapter("Primary", "192.0.2.1")
        secondary = NetworkAdapter("Secondary", "192.0.2.2")
        primary.weight = 2.0
        secondary.weight = 1.0
        prober.get_path_metrics(1).weight = 2.0
        prober.get_path_metrics(2).weight = 1.0

        sent_bytes = {1: 0, 2: 0}
        active = [(1, primary), (2, secondary)]
        for seq_num in range(1, 301):
            payload = bytes(200 + (seq_num % 5) * 250)
            path_id = scheduler.schedule(
                payload, seq_num, 9, active,
            )[0][0]
            sent_bytes[path_id] += len(payload)

        self.assertGreater(sent_bytes[1], sent_bytes[2] * 3)
        self.assertLess(sent_bytes[1], sent_bytes[2] * 5)

    def test_flow_pinning_keeps_reverse_packets_on_eligible_path(self):
        prober = LinkProber()
        scheduler = PacketScheduler(prober=prober, flow_pinning=True)
        active = [
            (1, NetworkAdapter("Primary", "192.0.2.1")),
            (2, NetworkAdapter("Secondary", "192.0.2.2")),
        ]
        packet = _ipv4_udp_packet("192.0.2.10", "198.51.100.20", 12345, 443)
        reverse_packet = _ipv4_udp_packet(
            "198.51.100.20", "192.0.2.10", 443, 12345,
        )

        with patch("core.scheduler.time.monotonic", return_value=100.0):
            pinned_path = scheduler.schedule(packet, 1, 7, active)[0][0]
            other_path = 2 if pinned_path == 1 else 1
            prober.get_path_metrics(pinned_path).weight = 0.1
            prober.get_path_metrics(other_path).weight = 10.0

            for seq_num, flow_packet in enumerate(
                (reverse_packet, packet, reverse_packet), start=2,
            ):
                selected = scheduler.schedule(flow_packet, seq_num, 7, active)
                self.assertEqual(selected[0][0], pinned_path)

    def test_flow_pinning_handles_ipv4_tcp(self):
        prober = LinkProber()
        scheduler = PacketScheduler(prober, flow_pinning=True)
        active = [
            (1, NetworkAdapter("Primary", "192.0.2.1")),
            (2, NetworkAdapter("Secondary", "192.0.2.2")),
        ]
        packet = _ipv4_tcp_packet("192.0.2.10", "198.51.100.20", 443, 53000)

        with patch("core.scheduler.time.monotonic", return_value=100.0):
            pinned_path = scheduler.schedule(packet, 1, 7, active)[0][0]
            other_path = 2 if pinned_path == 1 else 1
            prober.get_path_metrics(pinned_path).weight = 0.1
            prober.get_path_metrics(other_path).weight = 10.0
            selected = scheduler.schedule(packet, 2, 7, active)

        self.assertEqual(selected[0][0], pinned_path)

    def test_flow_pinning_reassigns_when_path_is_unavailable(self):
        scheduler = PacketScheduler(LinkProber(), flow_pinning=True)
        packet = _ipv6_udp_packet(
            "2001:db8::1", "2001:db8::2", 12345, 443,
            destination_options=True,
        )
        path_one = (1, NetworkAdapter("Primary", "192.0.2.1"))
        path_two = (2, NetworkAdapter("Secondary", "192.0.2.2"))

        with patch("core.scheduler.time.monotonic", return_value=100.0):
            self.assertEqual(scheduler.schedule(packet, 1, 7, [path_one])[0][0], 1)
            self.assertEqual(scheduler.schedule(packet, 2, 7, [path_two])[0][0], 2)
            selected = scheduler.schedule(packet, 3, 7, [path_one, path_two])

        self.assertEqual(selected[0][0], 2)

    def test_flow_pinning_falls_back_for_fragments_and_malformed_packets(self):
        scheduler = PacketScheduler(LinkProber(), flow_pinning=True)
        active = [
            (1, NetworkAdapter("Primary", "192.0.2.1")),
            (2, NetworkAdapter("Secondary", "192.0.2.2")),
        ]
        fragmented = bytearray(
            _ipv4_udp_packet("192.0.2.10", "198.51.100.20", 12345, 443),
        )
        struct.pack_into("!H", fragmented, 6, 0x2000)
        malformed = bytearray(
            _ipv4_udp_packet("192.0.2.10", "198.51.100.20", 12345, 443),
        )
        struct.pack_into("!H", malformed, 24, 50)

        with patch("core.scheduler.time.monotonic", return_value=100.0):
            scheduler.schedule(bytes(fragmented), 1, 7, active)
            scheduler.schedule(bytes(malformed), 2, 7, active)
            scheduler.schedule(b"not an IP packet", 3, 7, active)

        self.assertFalse(scheduler._flow_pins)

    def test_flow_pin_cache_evicts_the_least_recently_used_flow(self):
        prober = LinkProber()
        scheduler = PacketScheduler(prober, flow_pinning=True)
        scheduler.MAX_PINNED_FLOWS = 2
        path_one = (1, NetworkAdapter("Primary", "192.0.2.1"))
        path_two = (2, NetworkAdapter("Secondary", "192.0.2.2"))
        flows = [
            _ipv4_udp_packet("192.0.2.10", "198.51.100.20", port, 443)
            for port in (10001, 10002, 10003)
        ]

        with patch(
            "core.scheduler.time.monotonic",
            side_effect=[100.0, 101.0, 102.0, 103.0, 104.0],
        ):
            scheduler.schedule(flows[0], 1, 7, [path_one])
            scheduler.schedule(flows[1], 2, 7, [path_one])
            scheduler.schedule(flows[0], 3, 7, [path_one])
            scheduler.schedule(flows[2], 4, 7, [path_one])
            prober.get_path_metrics(1).weight = 0.1
            prober.get_path_metrics(2).weight = 10.0
            selected = scheduler.schedule(flows[1], 5, 7, [path_one, path_two])

        self.assertEqual(len(scheduler._flow_pins), 2)
        self.assertEqual(selected[0][0], 2)

    def test_flow_pinning_is_opt_in_and_can_be_enabled_by_environment(self):
        self.assertFalse(PacketScheduler(LinkProber()).flow_pinning)
        with patch.dict("os.environ", {"MYSPEEDIFY_FLOW_PINNING": "1"}):
            scheduler = PacketScheduler(LinkProber())

        self.assertTrue(scheduler.flow_pinning)

    def test_probe_loss_window_counts_expired_probes_and_recovers(self):
        metrics = LinkProber().get_path_metrics(1)
        with patch("core.prober.time.monotonic", side_effect=[100.0, 104.0, 104.1, 104.2, 104.3]):
            metrics.record_probe_sent(1)
            probe_two = metrics.record_probe_sent(2)
            self.assertEqual(metrics.loss_rate, 1.0)

            metrics.record_probe_response(probe_two)
            self.assertEqual(metrics.loss_rate, 0.5)
            probe_three = metrics.record_probe_sent(3)
            metrics.record_probe_response(probe_three)

        self.assertAlmostEqual(metrics.loss_rate, 1.0 / 3.0)
        self.assertEqual(metrics.last_alive, 104.3)

    def test_expired_probe_loss_reduces_dynamic_weight_without_response(self):
        metrics = LinkProber().get_path_metrics(1)
        with patch(
            "core.prober.time.monotonic",
            side_effect=[10.0, 10.01, 11.0, 14.01],
        ):
            probe = metrics.record_probe_sent(1)
            self.assertEqual(metrics.weight, 1.0)
            metrics.record_probe_response(probe)
            healthy_weight = metrics.weight

            metrics.record_probe_sent(2)
            metrics.record_probe_sent(3)

        self.assertEqual(metrics.loss_rate, 0.5)
        self.assertLess(metrics.weight, healthy_weight)

    def test_probe_schedule_uses_monotonic_clock(self):
        prober = LinkProber(interval_seconds=0.5)
        with patch(
            "core.prober.time.monotonic",
            side_effect=[100.0, 100.1, 100.5],
        ), patch("core.prober.time.time", side_effect=AssertionError):
            prober.generate_probes([], session_id=1)
            self.assertFalse(prober.should_probe())
            self.assertTrue(prober.should_probe())

    def test_late_probe_response_does_not_mark_path_alive(self):
        metrics = LinkProber().get_path_metrics(1)
        with patch("core.prober.time.monotonic", side_effect=[100.0, 104.0, 104.1]):
            probe = metrics.record_probe_sent(1)
            metrics.record_probe_sent(2)
            metrics.record_probe_response(probe)

        self.assertEqual(metrics.last_alive, 0.0)
        self.assertEqual(metrics.loss_rate, 1.0)

    def test_failover_uses_priority_tiers_and_excludes_disabled_paths(self):
        prober = LinkProber()
        scheduler = PacketScheduler(prober=prober, mode=BondingMode.FAILOVER)
        primary = NetworkAdapter("Primary", "192.0.2.1")
        primary.priority = 1
        primary.enabled = False
        secondary = NetworkAdapter("Secondary", "192.0.2.2")
        secondary.priority = 2
        backup = NetworkAdapter("Backup", "192.0.2.3")
        backup.priority = 0

        with patch("core.scheduler.time.monotonic", return_value=100.0):
            selected = scheduler.schedule(
                b"test", seq_num=1, session_id=7,
                active_adapters=[(1, primary), (2, secondary), (3, backup)],
            )

        self.assertEqual([path_id for path_id, _ in selected], [2])

    def test_failover_prefers_confirmed_secondary_to_unresponsive_primary(self):
        prober = LinkProber()
        scheduler = PacketScheduler(prober=prober, mode=BondingMode.FAILOVER)
        primary = NetworkAdapter("Primary", "192.0.2.1")
        primary.priority = 1
        secondary = NetworkAdapter("Secondary", "192.0.2.2")
        secondary.priority = 2
        primary_metrics = prober.get_path_metrics(1)
        primary_metrics.first_probe_sent_at = 99.0
        secondary_metrics = prober.get_path_metrics(2)
        secondary_metrics.first_probe_sent_at = 99.0
        secondary_metrics.last_alive = 100.0

        with patch("core.scheduler.time.monotonic", return_value=100.0):
            selected = scheduler.schedule(
                b"test", seq_num=1, session_id=7,
                active_adapters=[(1, primary), (2, secondary)],
            )

        self.assertEqual([path_id for path_id, _ in selected], [2])

    def test_failover_switches_on_path_loss_and_hysteretically_fails_back(self):
        prober = LinkProber()
        scheduler = PacketScheduler(prober=prober, mode=BondingMode.FAILOVER)
        primary = NetworkAdapter("Primary", "192.0.2.1")
        primary.priority = 1
        secondary = NetworkAdapter("Secondary", "192.0.2.2")
        secondary.priority = 2
        primary_metrics = prober.get_path_metrics(1)
        secondary_metrics = prober.get_path_metrics(2)
        primary_metrics.first_probe_sent_at = 90.0
        primary_metrics.last_alive = 90.0
        secondary_metrics.first_probe_sent_at = 90.0
        secondary_metrics.last_alive = 100.0
        active = [(1, primary), (2, secondary)]

        now = [100.0]
        with patch("core.scheduler.time.monotonic", side_effect=lambda: now[0]):
            # The primary is already stale, so fail over immediately.
            selected = scheduler.schedule(b"test", 1, 7, active)
            self.assertEqual([path_id for path_id, _ in selected], [2])

            # A recovered primary must remain healthy for the full hysteresis.
            now[0] = 101.0
            primary_metrics.last_alive = 101.0
            secondary_metrics.last_alive = 101.0
            selected = scheduler.schedule(b"test", 2, 7, active)
            self.assertEqual([path_id for path_id, _ in selected], [2])
            now[0] = 103.9
            primary_metrics.last_alive = 103.9
            secondary_metrics.last_alive = 103.9
            selected = scheduler.schedule(b"test", 3, 7, active)
            self.assertEqual([path_id for path_id, _ in selected], [2])
            now[0] = 104.1
            primary_metrics.last_alive = 104.1
            secondary_metrics.last_alive = 104.1
            selected = scheduler.schedule(b"test", 4, 7, active)

        self.assertEqual([path_id for path_id, _ in selected], [1])

    def test_failover_avoids_path_with_excessive_measured_loss(self):
        prober = LinkProber()
        scheduler = PacketScheduler(prober=prober, mode=BondingMode.FAILOVER)
        primary = NetworkAdapter("Primary", "192.0.2.1")
        primary.priority = 1
        secondary = NetworkAdapter("Secondary", "192.0.2.2")
        secondary.priority = 2
        primary_metrics = prober.get_path_metrics(1)
        secondary_metrics = prober.get_path_metrics(2)
        primary_metrics.first_probe_sent_at = 90.0
        primary_metrics.last_alive = 100.0
        primary_metrics.loss_rate = 0.5
        secondary_metrics.first_probe_sent_at = 90.0
        secondary_metrics.last_alive = 100.0

        with patch("core.scheduler.time.monotonic", return_value=100.0):
            selected = scheduler.schedule(
                b"test", seq_num=1, session_id=7,
                active_adapters=[(1, primary), (2, secondary)],
            )

        self.assertEqual([path_id for path_id, _ in selected], [2])

if __name__ == "__main__":
    unittest.main()
