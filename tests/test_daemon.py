import unittest
import socket
from unittest.mock import Mock, patch

from core.protocol import Packet, PacketType
from core.tun.routes import PhysicalPath
from daemon import ClientDaemon
from relay import RelayServer
from client.daemon import ClientDaemon as LegacyClientDaemon


class TestClientReconnect(unittest.TestCase):
    def test_handshake_installs_full_tunnel_before_publishing_session(self):
        with patch("daemon.AdapterManager"), patch("daemon.create_tun") as create_tun, \
                patch("daemon.TunnelNetworkConfig") as network_config_type:
            daemon = ClientDaemon(
                server_host="relay.example",
                secret="unit-test-secret-0123456789",
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
                secret="unit-test-secret-0123456789",
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
            daemon = ClientDaemon(secret="unit-test-secret-0123456789")
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
            daemon = ClientDaemon(server_host="127.0.0.1", secret="unit-test-secret-0123456789")

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
        self.assertFalse(daemon.reorder_buffer.initialized)
        self.assertIsNot(daemon.prober, old_prober)
        self.assertIs(daemon.scheduler.prober, daemon.prober)
        self.assertIs(daemon.tun, tun)
        handshake_tick.assert_called_once()

        relay = RelayServer(host="127.0.0.1", secret="unit-test-secret-0123456789")
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

    def test_repeated_handshake_failures_log_a_rate_limited_diagnostic(self):
        with patch("daemon.AdapterManager"):
            daemon = ClientDaemon(secret="unit-test-secret-0123456789")
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

    def test_select_waits_for_linux_tun_readiness_instead_of_polling(self):
        with patch("daemon.AdapterManager"):
            daemon = ClientDaemon(secret="unit-test-secret-0123456789")
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
            daemon = ClientDaemon(secret="unit-test-secret-0123456789")
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

    def test_legacy_loop_waits_for_tun_readiness(self):
        with patch("client.daemon.AdapterManager"):
            daemon = LegacyClientDaemon(passphrase="unit-test-secret-0123456789")
        tun = Mock()
        tun.read_wait_socket = None
        tun.fileno.return_value = 7
        tun.read.return_value = None
        daemon.tun = tun
        daemon.paths = {}
        daemon.is_running = True
        daemon.prober.should_probe = Mock(return_value=False)

        with patch("client.daemon.select.select", return_value=([tun], [], [])) as select_call, \
                patch.object(daemon, "_update_telemetry"):
            daemon.step()

        self.assertIn(tun, select_call.call_args.args[0])
        self.assertEqual(select_call.call_args.args[3], 0.05)
        tun.read.assert_called_once_with()

    def test_legacy_loop_drains_large_tun_bursts_without_losing_readiness(self):
        with patch("client.daemon.AdapterManager"):
            daemon = LegacyClientDaemon(passphrase="unit-test-secret-0123456789")
        tun = Mock()
        tun.read_wait_socket = None
        tun.fileno.return_value = 7
        tun.read.side_effect = [b"packet"] * 65 + [None]
        daemon.tun = tun
        daemon.paths = {}
        daemon.is_running = True
        daemon.prober.should_probe = Mock(return_value=False)
        daemon._handle_egress_packet = Mock()

        with patch(
            "client.daemon.select.select",
            side_effect=[([tun], [], []), ([], [], [])],
        ) as select_call, patch.object(daemon, "_update_telemetry"):
            daemon.step()
            self.assertTrue(daemon._tun_drain_pending)
            daemon.step()

        self.assertEqual(daemon._handle_egress_packet.call_count, 65)
        self.assertFalse(daemon._tun_drain_pending)
        self.assertEqual(select_call.call_args_list[1].args[3], 0.0)

    def test_dns_refresh_is_periodic_and_preserves_last_good_address(self):
        with patch("daemon.AdapterManager"), \
                patch("daemon.socket.gethostbyname") as resolve:
            daemon = ClientDaemon(
                server_host="relay.example",
                secret="unit-test-secret-0123456789",
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
                secret="unit-test-secret-0123456789",
            )
            daemon.server_addr = ("198.51.100.10", daemon.server_port)
            daemon.network_config = Mock()
            with patch("daemon.time.monotonic", return_value=100.0):
                daemon._refresh_server_addr()

        daemon.network_config.update_relay.assert_called_once_with("198.51.100.20")
        self.assertEqual(daemon.server_addr, ("198.51.100.20", daemon.server_port))

    def test_legacy_client_dns_runs_outside_the_io_loop(self):
        with patch("client.daemon.AdapterManager"), \
                patch("client.daemon.socket.gethostbyname") as resolve:
            daemon = LegacyClientDaemon(
                server_host="relay.example",
                passphrase="unit-test-secret-0123456789",
            )
            resolve.assert_not_called()
            self.assertIsNone(daemon.get_server_addr())

            resolve.side_effect = [
                "198.51.100.10",
                socket.gaierror("temporary DNS failure"),
                "198.51.100.20",
            ]
            daemon._resolve_server_addr()
            self.assertEqual(daemon.get_server_addr(), ("198.51.100.10", daemon.server_port))
            daemon._resolve_server_addr()
            self.assertEqual(daemon.get_server_addr(), ("198.51.100.10", daemon.server_port))
            daemon._resolve_server_addr()

        self.assertEqual(daemon.get_server_addr(), ("198.51.100.20", daemon.server_port))
        self.assertEqual(resolve.call_count, 3)

    def test_legacy_start_installs_full_tunnel_before_starting_workers(self):
        adapter = Mock(
            interface_name="eth0",
            ip="192.0.2.10",
            if_index=2,
            name="Ethernet",
        )
        tun_order = []
        with patch("client.daemon.platform.system", return_value="Windows"), \
                patch("client.daemon.WintunInterface") as tun_type, \
                patch("client.daemon.AdapterManager") as manager_type, \
                patch("client.daemon.create_bound_udp_socket") as create_socket, \
                patch(
                    "client.daemon.socket.gethostbyname",
                    return_value="198.51.100.10",
                ), \
                patch("client.daemon.TunnelNetworkConfig") as config_type, \
                patch("client.daemon.threading.Thread") as thread_type:
            tun = tun_type.return_value
            sock = Mock()
            create_socket.return_value = sock
            manager_type.return_value.refresh_adapters.return_value = [adapter]
            daemon = LegacyClientDaemon(passphrase="test-only-legacy-passphrase")
            config = config_type.return_value
            config.install.side_effect = lambda: self.assertFalse(daemon.is_connected)
            config.close.side_effect = lambda: tun_order.append("network")
            tun.close.side_effect = lambda: tun_order.append("tun")

            daemon.start()

            tun.open.assert_called_once_with(ip="10.8.0.2")
            config_type.assert_called_once_with(
                tun,
                "198.51.100.10",
                [PhysicalPath("eth0", "192.0.2.10", 2)],
            )
            config.install.assert_called_once_with()
            self.assertTrue(daemon.is_connected)
            self.assertEqual(thread_type.return_value.start.call_count, 2)

            daemon.stop()

        self.assertEqual(tun_order, ["network", "tun"])
        sock.close.assert_called_once_with()

    def test_legacy_start_fails_closed_when_relay_dns_is_unavailable(self):
        adapter = Mock(
            interface_name="eth0",
            ip="192.0.2.10",
            if_index=2,
            name="Ethernet",
        )
        with patch("client.daemon.platform.system", return_value="Windows"), \
                patch("client.daemon.WintunInterface") as tun_type, \
                patch("client.daemon.AdapterManager") as manager_type, \
                patch("client.daemon.create_bound_udp_socket") as create_socket, \
                patch(
                    "client.daemon.socket.gethostbyname",
                    side_effect=socket.gaierror("DNS unavailable"),
                ), \
                patch("client.daemon.TunnelNetworkConfig") as config_type:
            sock = Mock()
            create_socket.return_value = sock
            manager_type.return_value.refresh_adapters.return_value = [adapter]
            daemon = LegacyClientDaemon(passphrase="test-only-legacy-passphrase")

            with self.assertRaisesRegex(RuntimeError, "before resolving the relay"):
                daemon.start()

        tun_type.return_value.open.assert_not_called()
        tun_type.return_value.close.assert_called_once_with()
        config_type.assert_not_called()
        sock.close.assert_called_once_with()
        self.assertFalse(daemon.is_running)
        self.assertFalse(daemon.is_connected)

    def test_legacy_route_install_failure_closes_tun_and_path_sockets(self):
        adapter = Mock(
            interface_name="eth0",
            ip="192.0.2.10",
            if_index=2,
            name="Ethernet",
        )
        with patch("client.daemon.platform.system", return_value="Windows"), \
                patch("client.daemon.WintunInterface") as tun_type, \
                patch("client.daemon.AdapterManager") as manager_type, \
                patch("client.daemon.create_bound_udp_socket") as create_socket, \
                patch(
                    "client.daemon.socket.gethostbyname",
                    return_value="198.51.100.10",
                ), \
                patch("client.daemon.TunnelNetworkConfig") as config_type, \
                patch("client.daemon.threading.Thread") as thread_type:
            tun = tun_type.return_value
            sock = Mock()
            create_socket.return_value = sock
            manager_type.return_value.refresh_adapters.return_value = [adapter]
            config = config_type.return_value
            config.install.side_effect = RuntimeError("route policy failed")
            daemon = LegacyClientDaemon(passphrase="test-only-legacy-passphrase")

            with self.assertRaisesRegex(RuntimeError, "route policy failed"):
                daemon.start()

        config.close.assert_called_once_with()
        tun.close.assert_called_once_with()
        sock.close.assert_called_once_with()
        thread_type.assert_not_called()
        self.assertFalse(daemon.is_running)
        self.assertFalse(daemon.is_connected)

    def test_legacy_dns_refresh_updates_route_before_publishing_new_address(self):
        with patch("client.daemon.AdapterManager"):
            daemon = LegacyClientDaemon(
                server_host="relay.example",
                passphrase="test-only-legacy-passphrase",
            )
        daemon.network_config = Mock()
        daemon.server_addr = ("198.51.100.10", daemon.server_port)
        daemon.network_config.update_relay.side_effect = lambda ip: self.assertEqual(
            daemon.server_addr, ("198.51.100.10", daemon.server_port),
        )

        with patch(
            "client.daemon.socket.gethostbyname",
            return_value="198.51.100.20",
        ):
            daemon._resolve_server_addr()

        daemon.network_config.update_relay.assert_called_once_with("198.51.100.20")
        self.assertEqual(daemon.server_addr, ("198.51.100.20", daemon.server_port))

    def test_legacy_path_changes_update_relay_route_exceptions(self):
        old_adapter = Mock(
            interface_name="eth0",
            ip="192.0.2.10",
            if_index=2,
            name="Ethernet",
        )
        new_adapter = Mock(
            interface_name="eth1",
            ip="203.0.113.10",
            if_index=3,
            name="Wi-Fi",
        )
        old_sock, new_sock = Mock(), Mock()
        with patch("client.daemon.AdapterManager") as manager_type, \
                patch("client.daemon.create_bound_udp_socket", return_value=new_sock):
            daemon = LegacyClientDaemon(passphrase="test-only-legacy-passphrase")
            daemon.network_config = Mock()
            daemon.paths = {1: (old_sock, old_adapter)}
            manager_type.return_value.refresh_adapters.return_value = [new_adapter]

            daemon.refresh_paths()

        daemon.network_config.remove_path.assert_called_once_with(
            PhysicalPath("eth0", "192.0.2.10", 2),
        )
        daemon.network_config.add_path.assert_called_once_with(
            PhysicalPath("eth1", "203.0.113.10", 3),
        )
        old_sock.close.assert_called_once_with()
        self.assertEqual(daemon.paths[1], (new_sock, new_adapter))


if __name__ == "__main__":
    unittest.main()
