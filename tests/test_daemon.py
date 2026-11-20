import unittest
import socket
from unittest.mock import Mock, patch

from core.protocol import Packet, PacketType
from core.tun.routes import PhysicalPath
from daemon import ClientDaemon
from relay import RelayServer


class TestClientReconnect(unittest.TestCase):
    def test_handshake_installs_full_tunnel_before_publishing_session(self):
        with patch("daemon.AdapterManager"), patch("daemon.create_tun") as create_tun, \
                patch("daemon.TunnelNetworkConfig") as network_config_type:
            daemon = ClientDaemon(
                server_host="relay.example",
                secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            )
            tun = Mock()
            create_tun.return_value = tun
            config = network_config_type.return_value
            adapter = Mock(
                interface_name="Ethernet",
                ip="192.0.2.10",
                if_index=4,
            )
            daemon.paths = {1: (Mock(), adapter)}
            daemon.server_addr = ("198.51.100.10", daemon.server_port)
            session_crypto = object()
            config.install.side_effect = lambda: self.assertIsNone(daemon.crypto)

            with patch.object(
                daemon._hs, "process_resp", return_value=(session_crypto, "10.8.0.2")
            ):
                daemon._on_handshake_resp(Packet(
                    PacketType.HANDSHAKE_RESP,
                    daemon.session_id,
                    payload=b"response",
                ))

        tun.open.assert_called_once_with(
            ip="10.8.0.2", netmask="255.255.255.0", mtu=1380,
        )
        network_config_type.assert_called_once_with(
            tun,
            "198.51.100.10",
            [PhysicalPath("Ethernet", "192.0.2.10", 4)],
        )
        config.install.assert_called_once_with()
        self.assertIs(daemon.tun, tun)
        self.assertIs(daemon.crypto, session_crypto)

    def test_route_setup_failure_closes_new_tun_and_fails_connection(self):
        with patch("daemon.AdapterManager"), patch("daemon.create_tun") as create_tun, \
                patch("daemon.TunnelNetworkConfig") as network_config_type:
            daemon = ClientDaemon(
                server_host="relay.example",
                secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            )
            daemon.is_running = True
            tun = Mock()
            create_tun.return_value = tun
            config = network_config_type.return_value
            config.install.side_effect = RuntimeError("route policy failed")
            daemon.server_addr = ("198.51.100.10", daemon.server_port)
            with patch.object(
                daemon._hs, "process_resp", return_value=(object(), "10.8.0.2")
            ):
                daemon._on_handshake_resp(Packet(
                    PacketType.HANDSHAKE_RESP,
                    daemon.session_id,
                    payload=b"response",
                ))

        tun.close.assert_called_once_with()
        config.close.assert_called_once_with()
        self.assertIsNone(daemon.tun)
        self.assertIsNone(daemon.crypto)
        self.assertFalse(daemon.is_running)
        self.assertIn("route policy failed", daemon.fatal_error)

    def test_shutdown_restores_network_settings_before_closing_tun(self):
        with patch("daemon.AdapterManager"):
            daemon = ClientDaemon(secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        calls = []
        daemon.network_config = Mock()
        daemon.network_config.close.side_effect = lambda: calls.append("network")
        daemon.tun = Mock()
        daemon.tun.close.side_effect = lambda: calls.append("tun")

        daemon.stop()

        self.assertEqual(calls, ["network", "tun"])
        self.assertIsNone(daemon.network_config)
        self.assertIsNone(daemon.tun)

    def test_idle_session_restarts_handshake_and_keeps_tun_open(self):
        with patch("daemon.AdapterManager"):
            daemon = ClientDaemon(server_host="127.0.0.1", secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")

        tun = Mock()
        daemon.tun = tun
        daemon.tunnel_ip = "10.8.0.2"
        daemon.crypto = object()
        daemon.last_rx = 1.0
        daemon.seq_counter = 50
        daemon.reorder_buffer.reset(initial_seq=100)
        old_handshake = daemon._hs
        old_prober = daemon.prober

        with patch("daemon.time.monotonic", return_value=12.0), \
                patch("daemon.time.sleep"), \
                patch.object(daemon, "_handshake_tick") as handshake_tick:
            daemon._io_iteration()

        self.assertIsNone(daemon.crypto)
        self.assertIsNot(daemon._hs, old_handshake)
        self.assertEqual(daemon.seq_counter, 0)
        self.assertTrue(daemon.reorder_buffer.initialized)
        self.assertEqual(daemon.reorder_buffer.expected_seq, 1)
        self.assertIsNot(daemon.prober, old_prober)
        self.assertIs(daemon.scheduler.prober, daemon.prober)
        self.assertIs(daemon.tun, tun)
        handshake_tick.assert_called_once()

        relay = RelayServer(host="127.0.0.1", secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        relay.sock = Mock()
        relay._free_ips.pop()  # another session receives 10.8.0.2 after a relay restart
        init = Packet(
            PacketType.HANDSHAKE_INIT,
            daemon.session_id,
            path_id=1,
            payload=daemon._hs.build_init(),
        )
        relay._handle_init(init, ("127.0.0.1", 51821))
        response = Packet.deserialize(relay.sock.sendto.call_args.args[0])
        if response is None:
            self.fail("Relay returned an invalid handshake response")
        daemon._on_handshake_resp(response)

        self.assertIsNotNone(daemon.crypto)
        self.assertEqual(daemon.tunnel_ip, "10.8.0.3")
        self.assertEqual(relay.sessions[daemon.session_id].tunnel_ip, "10.8.0.3")
        self.assertIs(daemon.tun, tun)
        tun.open.assert_not_called()
        tun.set_ip.assert_called_once_with(
            "10.8.0.3", netmask="255.255.255.0", mtu=1380
        )

    def test_reorder_hold_tracks_active_path_latency_spread(self):
        with patch("daemon.AdapterManager"):
            daemon = ClientDaemon(secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        fast = Mock(enabled=True, latency_ms=12.0, jitter_ms=2.0)
        slow = Mock(enabled=True, latency_ms=150.0, jitter_ms=5.0)
        daemon.paths = {1: (Mock(), fast), 2: (Mock(), slow)}

        daemon._tune_reorder_hold()

        self.assertAlmostEqual(daemon.reorder_buffer.max_hold_time, 0.094)

    def test_fatal_io_shutdown_publishes_error_snapshot(self):
        with patch("daemon.AdapterManager"):
            daemon = ClientDaemon(secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        daemon.is_running = True

        def stop_with_error():
            daemon.fatal_error = "TUN setup failed"
            daemon.is_running = False

        with patch.object(daemon, "_io_iteration", side_effect=stop_with_error):
            daemon._run()

        self.assertEqual(daemon.get_telemetry()["state"], "error")
        self.assertEqual(daemon.get_telemetry()["error"], "TUN setup failed")

    def test_repeated_handshake_failures_log_a_rate_limited_diagnostic(self):
        with patch("daemon.AdapterManager"):
            daemon = ClientDaemon(secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        sock = Mock()
        adapter = Mock(enabled=True)
        daemon.paths = {1: (sock, adapter)}
        daemon.server_addr = ("198.51.100.10", daemon.server_port)

        with patch("daemon.logger.warning") as warning:
            for attempt in range(1, 7):
                daemon._handshake_tick(float(attempt))
            daemon._handshake_tick(36.0)

        self.assertEqual(warning.call_count, 2)
        self.assertIn("clock synchronization", warning.call_args.args[0])
        self.assertEqual(sock.sendto.call_count, 7)

    def test_initial_handshake_renews_nonce_after_no_response(self):
        with patch("daemon.AdapterManager"):
            daemon = ClientDaemon(
                secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            )
        sock = Mock()
        daemon.paths = {1: (sock, Mock(enabled=True))}
        daemon.server_addr = ("198.51.100.10", daemon.server_port)
        original_handshake = daemon._hs

        daemon._handshake_tick(1.0)
        first_init = sock.sendto.call_args.args[0]
        daemon._handshake_tick(61.0)
        second_init = sock.sendto.call_args.args[0]

        self.assertIsNot(daemon._hs, original_handshake)
        self.assertNotEqual(first_init, second_init)
        self.assertEqual(sock.sendto.call_count, 2)

    def test_idle_probes_are_small_and_active_traffic_restores_capacity_trains(self):
        with patch("daemon.AdapterManager"):
            daemon = ClientDaemon(
                secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            )
        daemon.paths = {1: (Mock(), Mock(enabled=True))}
        daemon._last_data_activity = 0.0
        sent = []

        def capture_probe(sock, packet, plaintext):
            sent.append(packet)

        with patch.object(daemon, "_seal_and_send", side_effect=capture_probe), \
                patch("daemon.time.monotonic", side_effect=[10.0, 10.0]):
            daemon._probe_tick()
        self.assertEqual(len(sent), 1)
        self.assertEqual(len(sent[0].payload), 20)

        with patch.object(daemon, "_seal_and_send", side_effect=capture_probe), \
                patch("daemon.time.monotonic", side_effect=[14.9, 14.9]):
            daemon._probe_tick()
        self.assertEqual(len(sent), 1)

        daemon._last_data_activity = 14.9
        with patch.object(daemon, "_seal_and_send", side_effect=capture_probe), \
                patch("daemon.time.monotonic", side_effect=[15.0, 15.0, 15.0]):
            daemon._probe_tick()
        self.assertEqual(len(sent), 5)
        self.assertTrue(all(len(packet.payload) == 1044 for packet in sent[1:]))

    def test_select_waits_for_linux_tun_readiness_instead_of_polling(self):
        with patch("daemon.AdapterManager"):
            daemon = ClientDaemon(secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        tun = Mock()
        tun.fileno.return_value = 7
        tun.read.return_value = None
        daemon.tun = tun
        daemon.crypto = object()
        daemon.last_rx = 100.0
        daemon._busy = False

        with patch("daemon.time.monotonic", return_value=101.0), \
                patch("daemon.select.select", return_value=([tun], [], [])) as select_call:
            daemon._io_iteration()

        self.assertIn(tun, select_call.call_args.args[0])
        self.assertEqual(select_call.call_args.args[3], 0.05)
        tun.read.assert_called_once_with()

    def test_select_waits_for_wintun_read_event_socket(self):
        with patch("daemon.AdapterManager"):
            daemon = ClientDaemon(secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        read_socket, write_socket = socket.socketpair()
        self.addCleanup(read_socket.close)
        self.addCleanup(write_socket.close)
        tun = Mock()
        tun.read_wait_socket = read_socket
        tun.fileno.return_value = 7
        tun.read.return_value = None
        daemon.tun = tun
        daemon.crypto = object()
        daemon.last_rx = 100.0
        daemon._busy = False

        with patch("daemon.time.monotonic", return_value=101.0), \
                patch(
                   "daemon.select.select",
                   return_value=([read_socket], [], []),
                ) as select_call:
            daemon._io_iteration()

        self.assertIn(read_socket, select_call.call_args.args[0])
        tun.read.assert_called_once_with()

    def test_dns_refresh_is_periodic_and_preserves_last_good_address(self):
        with patch("daemon.AdapterManager"), \
                patch("daemon.socket.gethostbyname") as resolve:
            daemon = ClientDaemon(
                server_host="relay.example",
                secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            )
            resolve.assert_not_called()

            resolve.side_effect = [
                "198.51.100.10",
                socket.gaierror("temporary DNS failure"),
                "198.51.100.20",
            ]
            with patch("daemon.time.monotonic", side_effect=[100.0, 114.0, 115.0, 130.0]):
                daemon._refresh_server_addr()
                self.assertEqual(daemon.server_addr, ("198.51.100.10", daemon.server_port))
                daemon._refresh_server_addr()
                resolve.assert_called_once_with("relay.example")
                daemon._refresh_server_addr()
                self.assertEqual(daemon.server_addr, ("198.51.100.10", daemon.server_port))
                daemon._refresh_server_addr()

        self.assertEqual(daemon.server_addr, ("198.51.100.20", daemon.server_port))
        self.assertEqual(resolve.call_count, 3)

    def test_dns_refresh_updates_relay_route_before_publishing_new_address(self):
        with patch("daemon.AdapterManager"), \
                patch("daemon.socket.gethostbyname", return_value="198.51.100.20"):
            daemon = ClientDaemon(
                server_host="relay.example",
                secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            )
            daemon.server_addr = ("198.51.100.10", daemon.server_port)
            daemon.network_config = Mock()
            with patch("daemon.time.monotonic", return_value=100.0):
                daemon._refresh_server_addr()

        daemon.network_config.update_relay.assert_called_once_with("198.51.100.20")
        self.assertEqual(daemon.server_addr, ("198.51.100.20", daemon.server_port))

    def test_dns_refresh_allows_private_relays_and_rejects_unusable_addresses(self):
        with patch("daemon.AdapterManager"), \
                patch("daemon.socket.gethostbyname", return_value="10.8.0.1"):
            daemon = ClientDaemon(
                server_host="relay.example",
                secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            )
            with patch("daemon.time.monotonic", return_value=100.0):
                daemon._refresh_server_addr()

        self.assertEqual(daemon.server_addr, ("10.8.0.1", daemon.server_port))

        with patch("daemon.AdapterManager"), \
                patch("daemon.socket.gethostbyname", return_value="0.0.0.0"):
            invalid = ClientDaemon(
                server_host="relay.example",
                secret="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            )
            with patch("daemon.time.monotonic", return_value=100.0):
                invalid._refresh_server_addr()

        self.assertIsNone(invalid.server_addr)

if __name__ == "__main__":
    unittest.main()
