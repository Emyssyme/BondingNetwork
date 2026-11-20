import os
import unittest
import urllib.request
from collections import OrderedDict
from urllib.error import HTTPError
from unittest.mock import Mock, patch

from core.adapter import NetworkAdapter
from core.handshake import ClientHandshake
from core.protocol import Packet, PacketType
from core.scheduler import BondingMode
from daemon import ClientDaemon
from relay import ClientSession, IP_REUSE_COOLDOWN, RelayServer, SESSION_TTL


class TestRelayDownlinkAndProbes(unittest.TestCase):
    def setUp(self):
        self.secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        self.client_addr = ("127.0.0.1", 49152)
        self.client_sock = Mock()
        self.adapter = NetworkAdapter("Primary", "192.0.2.10")
        self.adapter.priority = 1

        with patch("daemon.AdapterManager"), patch("daemon.create_tun"), \
                patch("daemon.TunnelNetworkConfig"):
            self.client = ClientDaemon(server_host="127.0.0.1", secret=self.secret)
            self.relay = RelayServer(secret=self.secret)

        self.relay.sock = Mock()
        self.client.server_addr = ("127.0.0.1", 51820)
        self.client.paths = {1: (self.client_sock, self.adapter)}
        init = Packet(
            PacketType.HANDSHAKE_INIT,
            self.client.session_id,
            path_id=1,
            payload=self.client._hs.build_init(),
        )
        self.relay._handle_init(init, self.client_addr)
        response = Packet.deserialize(self.relay.sock.sendto.call_args.args[0])
        if response is None:
            self.fail("Relay returned an invalid handshake response")
        with patch("daemon.create_tun"), patch("daemon.TunnelNetworkConfig"):
            self.client._on_handshake_resp(response)
        self.session = self.relay.sessions[self.client.session_id]

    def test_client_bonding_mode_controls_relay_downlink(self):
        secondary = NetworkAdapter("Secondary", "198.51.100.10")
        secondary.priority = 2
        secondary_sock = Mock()
        self.client.paths[2] = (secondary_sock, secondary)
        self.client.scheduler.set_mode(BondingMode.REDUNDANT)
        self.client._send_ip_packet(b"register both paths")
        for sock, source_port in (
            (self.client_sock, self.client_addr[1]),
            (secondary_sock, 49153),
        ):
            for call in sock.sendto.call_args_list:
                self.relay._handle_incoming(
                    call.args[0], ("127.0.0.1", source_port),
                )

        self.assertEqual(self.session.paths[1][3].priority, 1)
        self.assertEqual(self.session.paths[2][3].priority, 2)

        for mode in (BondingMode.SPEED, BondingMode.FAILOVER, BondingMode.REDUNDANT):
            with self.subTest(mode=mode):
                self.client_sock.reset_mock()
                secondary_sock.reset_mock()
                self.client.scheduler.set_mode(mode)
                self.client._send_ip_packet(b"client packet")
                for sock, source_port in (
                    (self.client_sock, self.client_addr[1]),
                    (secondary_sock, 49153),
                ):
                    for call in sock.sendto.call_args_list:
                        self.relay._handle_incoming(
                            call.args[0], ("127.0.0.1", source_port),
                        )
                self.assertEqual(self.session.scheduler.mode, mode)

                payload = bytearray(20)
                payload[0] = 0x45
                payload[16:20] = self.session.ip_bytes
                self.relay.sock.reset_mock()
                self.relay._handle_downlink(bytes(payload))
                sent_paths = [
                    call.args[1]
                    for call in self.relay.sock.sendto.call_args_list
                ]
                self.assertEqual(
                    len(sent_paths),
                    2 if mode == BondingMode.REDUNDANT else 1,
                )
                if mode == BondingMode.FAILOVER:
                    self.assertEqual(sent_paths, [self.client_addr])

    def test_client_rejects_replayed_authenticated_packets_before_refreshing_liveness(self):
        packet = Packet(
            PacketType.PROBE_REQ,
            self.client.session_id,
            path_id=1,
            seq_num=77,
        )
        plaintext = b"probe"
        aad = packet.header_bytes()
        packet.payload = self.session.crypto.encrypt(
            plaintext, packet.seq_num, packet.path_id,
            int(packet.pkt_type), aad,
        )
        raw = packet.serialize()

        with patch("daemon.time.monotonic", side_effect=[100.0, 200.0]):
            self.client._on_datagram(raw, 1, self.adapter)
            self.client._on_datagram(raw, 1, self.adapter)

        self.assertEqual(self.client.last_rx, 100.0)
        self.assertEqual(self.client.total_rx_packets, 1)

    def test_authenticated_disconnect_releases_session(self):
        self.client._send_disconnect()
        disconnect = Packet.deserialize(self.client_sock.sendto.call_args.args[0])
        self.assertIsNotNone(disconnect)
        self.assertEqual(disconnect.pkt_type, PacketType.DISCONNECT)

        self.relay._handle_incoming(
            self.client_sock.sendto.call_args.args[0], self.client_addr,
        )

        self.assertNotIn(self.client.session_id, self.relay.sessions)
        self.assertEqual(len(self.relay._quarantined_ips), 1)

    def test_relay_rejects_new_paths_after_per_session_limit(self):
        for path_id in range(1, 34):
            packet = Packet(
                PacketType.DATA,
                self.client.session_id,
                path_id=path_id,
                seq_num=path_id,
            )
            plaintext = b"test"
            aad = packet.header_bytes()
            packet.payload = self.client.crypto.encrypt(
                plaintext, packet.seq_num, packet.path_id,
                int(packet.pkt_type), aad,
            )
            self.relay._handle_incoming(
                packet.serialize(), ("127.0.0.1", 49000 + path_id),
            )

        self.assertEqual(len(self.session.paths), 32)
        self.assertNotIn(33, self.session.paths)
        self.assertNotIn((33, int(PacketType.DATA)), self.session.replay_windows)

    def test_replayed_authenticated_packet_cannot_move_a_path(self):
        self.client._send_ip_packet(b"test payload")
        raw_packet = self.client_sock.sendto.call_args.args[0]
        self.relay._handle_incoming(raw_packet, self.client_addr)
        original_path = self.session.paths[1]

        self.relay._handle_incoming(raw_packet, ("127.0.0.1", 49199))

        self.assertEqual(self.session.paths[1], original_path)
        self.assertEqual(self.session.replay_windows[(1, int(PacketType.DATA))]._highest, 1)

    def test_same_redundant_sequence_is_accepted_on_distinct_paths(self):
        secondary = NetworkAdapter("Secondary", "198.51.100.10")
        self.client.paths[2] = (Mock(), secondary)
        self.client.scheduler.set_mode(BondingMode.REDUNDANT)
        self.client._send_ip_packet(b"replicated packet")
        path_packets = [
            call.args[0]
            for sock in (self.client_sock, self.client.paths[2][0])
            for call in sock.sendto.call_args_list
        ]

        for raw_packet in path_packets:
            packet = Packet.deserialize(raw_packet)
            self.relay._handle_incoming(
                raw_packet,
                (self.client_addr[0], self.client_addr[1] + packet.path_id),
            )

        self.assertIn(1, self.session.paths)
        self.assertIn(2, self.session.paths)
        self.assertEqual(self.session.reorder_buffer.delivered_count, 1)

    def test_init_retransmits_only_while_session_is_live(self):
        init = Packet(
            PacketType.HANDSHAKE_INIT,
            self.client.session_id,
            path_id=1,
            payload=self.client._hs.build_init(),
        )
        original_session = self.session
        original_response = original_session.resp_payload

        self.relay._handle_init(init, self.client_addr)
        retransmitted = Packet.deserialize(self.relay.sock.sendto.call_args.args[0])

        self.assertIs(self.relay.sessions[self.client.session_id], original_session)
        self.assertEqual(retransmitted.payload, original_response)

        self.relay._drop_session(original_session)
        self.relay.sock.reset_mock()
        self.relay._handle_init(init, self.client_addr)

        self.assertNotIn(self.client.session_id, self.relay.sessions)
        self.relay.sock.sendto.assert_not_called()

    def test_relay_probes_are_answered_and_update_server_metrics(self):
        self.client._probe_tick()
        client_probe = self.client_sock.sendto.call_args.args[0]
        self.relay._handle_incoming(client_probe, self.client_addr)
        relay_response = self.relay.sock.sendto.call_args.args[0]
        self.client._on_datagram(relay_response, 1, self.adapter)

        self.relay.sock.reset_mock()
        self.session.prober.last_probe_time = 0.0
        self.relay._probe_sessions()
        self.assertEqual(
            self.relay.sock.sendto.call_count,
            self.session.prober.CAPACITY_TRAIN_SIZE,
        )

        server_probe = self.relay.sock.sendto.call_args.args[0]
        self.client._on_datagram(server_probe, 1, self.adapter)
        client_response = self.client_sock.sendto.call_args.args[0]
        self.relay._handle_incoming(client_response, self.client_addr)

        metrics = self.session.prober.get_path_metrics(1)
        self.assertGreater(metrics.last_alive, 0.0)
        self.assertEqual(len(metrics.rtt_history), 1)
        self.assertEqual(metrics.loss_rate, 0.0)
        path_metrics = self.session.paths[1][3]
        self.assertEqual(path_metrics.latency_ms, metrics.avg_rtt_ms)
        self.assertEqual(path_metrics.loss_pct, 0.0)

    def test_relay_reorder_hold_tracks_per_session_latency_spread(self):
        self.session.update_path(1, self.client_addr)
        fast = self.session.paths[1][3]
        fast.latency_ms = 12.0
        fast.jitter_ms = 2.0
        slow = NetworkAdapter("Secondary", "198.51.100.10")
        slow.latency_ms = 150.0
        slow.jitter_ms = 5.0
        self.session.paths[2] = ("127.0.0.1", 49153, 100.0, slow)

        self.session.tune_reorder_hold()

        self.assertAlmostEqual(self.session.reorder_buffer.max_hold_time, 0.094)


class TestRelayClientCredentials(unittest.TestCase):
    def test_init_replay_cache_is_bounded_per_authenticated_client(self):
        alice_secret = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"
        relay = RelayServer(
            secret=None,
            client_secrets={"alice": alice_secret},
        )
        relay.sock = Mock()
        session_id = 1234

        with patch("relay.INIT_RATE_LIMIT_PER_CLIENT", 100):
            for _ in range(65):
                handshake = ClientHandshake(
                    relay.client_psks["alice"], session_id, "alice",
                )
                init = Packet(
                    PacketType.HANDSHAKE_INIT,
                    session_id,
                    payload=handshake.build_init(),
                )
                relay._handle_init(init, ("127.0.0.1", 49152))

        self.assertEqual(relay._init_cache_counts["alice"], 64)
        self.assertEqual(len(relay._seen_init_nonces), 64)
        self.assertEqual(relay.sessions[session_id].tunnel_ip, "10.8.0.2")

    def test_new_init_rate_limit_counts_only_distinct_accepted_nonces(self):
        alice_secret = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"
        relay = RelayServer(
            secret=None,
            client_secrets={"alice": alice_secret},
        )
        relay.sock = Mock()
        session_id = 5678

        for _ in range(9):
            handshake = ClientHandshake(
                relay.client_psks["alice"], session_id, "alice",
            )
            init = Packet(
                PacketType.HANDSHAKE_INIT,
                session_id,
                payload=handshake.build_init(),
            )
            relay._handle_init(init, ("127.0.0.1", 49152))

        self.assertEqual(relay.sessions_created_total, 8)
        self.assertEqual(relay._init_cache_counts["alice"], 8)

    def test_per_client_session_limit_blocks_exhaustion(self):
        alice_secret = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"
        with patch("daemon.AdapterManager"):
            relay = RelayServer(
                secret=None,
                client_secrets={"alice": alice_secret},
            )
        relay.sock = Mock()
        relay._sessions_by_client.clear()
        relay._free_ips = [f"10.8.0.{i}" for i in range(2, 10)]
        with patch.object(relay, "_seen_init_nonces", OrderedDict()), \
                patch("relay.MAX_CLIENT_SESSIONS", 1):
            alice = ClientDaemon(secret=alice_secret, client_id="alice")
            first = Packet(PacketType.HANDSHAKE_INIT, alice.session_id, payload=alice._hs.build_init())
            relay._handle_init(first, ("127.0.0.1", 49152))
            self.assertIn(alice.session_id, relay.sessions)

            second_client = ClientDaemon(secret=alice_secret, client_id="alice")
            second_client.session_id += 1
            second_client._hs = ClientHandshake(second_client.psk, second_client.session_id, second_client.client_id)
            second = Packet(PacketType.HANDSHAKE_INIT, second_client.session_id, payload=second_client._hs.build_init())
            relay._handle_init(second, ("127.0.0.1", 49153))

            self.assertNotIn(second_client.session_id, relay.sessions)
            self.assertEqual(relay._sessions_by_client["alice"], 1)

    def test_per_client_only_relay_rejects_legacy_handshake(self):
        with patch("daemon.AdapterManager"):
            client = ClientDaemon(secret="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8")
            relay = RelayServer(
                secret=None,
                client_secrets={"alice": "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"},
            )
        relay.sock = Mock()
        init = Packet(
            PacketType.HANDSHAKE_INIT,
            client.session_id,
            payload=client._hs.build_init(),
        )

        relay._handle_init(init, ("127.0.0.1", 49152))

        self.assertNotIn(client.session_id, relay.sessions)
        relay.sock.sendto.assert_not_called()

    def test_per_client_key_authenticates_identity_and_wrong_key_creates_no_state(self):
        alice_secret = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"
        shared_secret = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
        with patch("daemon.AdapterManager"):
            alice = ClientDaemon(secret=alice_secret, client_id="alice")
            relay = RelayServer(
                secret=shared_secret,
                client_secrets={"alice": alice_secret, "bob": "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8"},
            )
            impersonating_client = ClientDaemon(secret=alice_secret, client_id="bob")

        relay.sock = Mock()
        impersonation_init = Packet(
            PacketType.HANDSHAKE_INIT,
            impersonating_client.session_id,
            payload=impersonating_client._hs.build_init(),
        )
        relay._handle_init(impersonation_init, ("127.0.0.1", 49152))
        self.assertNotIn(impersonating_client.session_id, relay.sessions)
        self.assertEqual(relay.auth_failures_total, 1)
        relay.sock.sendto.assert_not_called()

        init = Packet(
            PacketType.HANDSHAKE_INIT,
            alice.session_id,
            payload=alice._hs.build_init(),
        )
        relay._handle_init(init, ("127.0.0.1", 49153))

        self.assertEqual(relay.sessions[alice.session_id].client_id, "alice")
        self.assertEqual(relay.sessions_created_total, 1)
        relay.sock.sendto.assert_called_once()

        bob = ClientDaemon(
            secret="YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8",
            client_id="bob",
        )
        bob.session_id = alice.session_id
        bob._hs = ClientHandshake(bob.psk, bob.session_id, bob.client_id)
        bob_init = Packet(
            PacketType.HANDSHAKE_INIT,
            bob.session_id,
            payload=bob._hs.build_init(),
        )
        alice_session = relay.sessions[alice.session_id]
        relay.sock.reset_mock()
        relay._handle_init(bob_init, ("127.0.0.1", 49154))

        self.assertIs(relay.sessions[alice.session_id], alice_session)
        relay.sock.sendto.assert_not_called()


class TestRelayMetrics(unittest.TestCase):
    def test_conntrack_flush_targets_only_the_reassigned_tunnel_source(self):
        relay = RelayServer(secret="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8")
        relay.tun = Mock()
        with patch("relay.platform.system", return_value="Linux"), \
                patch("relay.subprocess.run", return_value=Mock(returncode=0)) as run:
            relay._flush_tunnel_ip_conntrack("10.8.0.2")

        self.assertEqual(
            run.call_args.args[0],
            ["conntrack", "-D", "--orig-src", "10.8.0.2"],
        )

    def test_metrics_endpoint_is_loopback_only_and_exposes_aggregate_counters(self):
        relay = RelayServer(
            host="127.0.0.1",
            port=0,
            secret="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            client_secrets={"alice": "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"},
            metrics_port=0,
        )
        relay.total_packets_routed = 3
        relay.total_bytes_routed = 480
        relay.auth_failures_total = 2
        relay.sessions_created_total = 1
        relay.sessions_expired_total = 1
        relay.start()
        try:
            metrics_server = relay._metrics_httpd
            if metrics_server is None:
                self.fail("Metrics server did not start")
            self.assertEqual(metrics_server.server_address[0], "127.0.0.1")
            url = "http://127.0.0.1:{}/metrics".format(
                metrics_server.server_address[1],
            )
            with urllib.request.urlopen(url, timeout=2) as response:
                body = response.read().decode("utf-8")

            self.assertIn("myspeedify_relay_sessions_active 0", body)
            self.assertIn("myspeedify_relay_sessions_created_total 1", body)
            self.assertIn("myspeedify_relay_sessions_expired_total 1", body)
            self.assertIn("myspeedify_relay_packets_routed_total 3", body)
            self.assertIn("myspeedify_relay_bytes_routed_total 480", body)
            self.assertIn("myspeedify_relay_authentication_failures_total 2", body)
            self.assertNotIn("alice", body)
            self.assertNotIn(
                "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8",
                body,
            )
            with self.assertRaises(HTTPError) as error:
                urllib.request.urlopen(url + "/unexpected", timeout=2)
            self.assertEqual(error.exception.code, 404)
            error.exception.close()
        finally:
            relay.stop()

    def test_expired_session_updates_expiration_counter(self):
        relay = RelayServer(secret="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8")
        session = ClientSession(
            77, Mock(), b"nonce", b"public-key", b"response", "10.8.0.2",
        )
        session.last_activity = 100.0
        relay._free_ips.remove(session.tunnel_ip)
        relay.sessions[session.session_id] = session
        relay.by_ip[session.ip_bytes] = session

        relay._expire_idle_sessions(100.0 + SESSION_TTL + 1.0)

        self.assertEqual(relay.sessions_expired_total, 1)
        self.assertEqual(len(relay.sessions), 0)
        self.assertEqual(relay._free_ips.count(session.tunnel_ip), 0)
        self.assertEqual(
            relay._quarantined_ips[-1],
            (100.0 + SESSION_TTL + 1.0 + IP_REUSE_COOLDOWN, session.tunnel_ip),
        )
        relay._release_quarantined_ips(
            100.0 + SESSION_TTL + 1.0 + IP_REUSE_COOLDOWN,
        )
        self.assertEqual(relay._free_ips.count(session.tunnel_ip), 1)

    def test_invalid_metrics_port_fails_explicitly(self):
        with patch.dict(os.environ, {"MYSPEEDIFY_METRICS_PORT": "invalid"}):
            with self.assertRaisesRegex(ValueError, "MYSPEEDIFY_METRICS_PORT"):
                RelayServer(secret="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8")


if __name__ == "__main__":
    unittest.main()
