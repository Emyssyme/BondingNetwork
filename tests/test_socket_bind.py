import os
import socket
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core.adapter import AdapterManager, get_windows_interface_indices
from core.socket_bind import IP_UNICAST_IF, create_bound_udp_socket


class FakeSocket:
    def __init__(self):
        self.options = []
        self.bind = Mock()
        self.setblocking = Mock()
        self.close = Mock()

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))


class TestSocketBinding(unittest.TestCase):
    def test_windows_interface_indices_are_mapped_by_adapter_alias(self):
        output = (
            '[{"InterfaceAlias":"Wi-Fi","InterfaceIndex":5},'
            '{"InterfaceAlias":"Ethernet","InterfaceIndex":7}]'
        )
        with patch("core.adapter.platform.system", return_value="Windows"), \
                patch.dict(os.environ, {"SystemRoot": "C:\\Windows"}), \
                patch(
                    "core.adapter.subprocess.run",
                    return_value=SimpleNamespace(stdout=output.encode("utf-8")),
                ) as run:
            indices = get_windows_interface_indices()

        self.assertEqual(indices, {"Wi-Fi": 5, "Ethernet": 7})
        self.assertTrue(run.call_args.args[0][0].lower().endswith("powershell.exe"))
        self.assertIn("OutputEncoding", run.call_args.args[0][-1])

    def test_windows_socket_is_bound_to_interface_index(self):
        fake_socket = FakeSocket()
        with patch("core.socket_bind.platform.system", return_value="Windows"), \
                patch("core.socket_bind.socket.socket", return_value=fake_socket), \
                patch("core.socket_bind.socket.if_nametoindex", return_value=12):
            sock = create_bound_udp_socket("192.0.2.10", interface_name="Ethernet")

        self.assertIs(sock, fake_socket)
        self.assertIn(
            (socket.IPPROTO_IP, IP_UNICAST_IF, b"\x00\x00\x00\x0c"),
            fake_socket.options,
        )
        fake_socket.bind.assert_called_once_with(("192.0.2.10", 0))
        fake_socket.setblocking.assert_called_once_with(False)

    def test_linux_socket_is_bound_to_device(self):
        fake_socket = FakeSocket()
        with patch("core.socket_bind.platform.system", return_value="Linux"), \
                patch("core.socket_bind.socket.socket", return_value=fake_socket), \
                patch.object(socket, "SO_BINDTODEVICE", 25, create=True):
            sock = create_bound_udp_socket("192.0.2.10", interface_name="eth0")

        self.assertIs(sock, fake_socket)
        self.assertIn(
            (socket.SOL_SOCKET, 25, b"eth0\0"),
            fake_socket.options,
        )
        fake_socket.bind.assert_called_once_with(("192.0.2.10", 0))

    def test_bind_failure_closes_socket_without_wildcard_fallback(self):
        fake_socket = FakeSocket()
        fake_socket.bind.side_effect = OSError("address unavailable")
        with patch("core.socket_bind.platform.system", return_value="Windows"), \
                patch("core.socket_bind.socket.socket", return_value=fake_socket), \
                patch("core.socket_bind.socket.if_nametoindex", return_value=12), \
                self.assertRaisesRegex(OSError, "address unavailable"):
            create_bound_udp_socket("192.0.2.10", interface_name="Ethernet")

        fake_socket.bind.assert_called_once_with(("192.0.2.10", 0))
        fake_socket.close.assert_called_once_with()

    def test_simulated_adapter_keeps_primary_physical_interface(self):
        addresses = {
            "Ethernet": [SimpleNamespace(family=socket.AF_INET, address="192.0.2.10")]
        }
        stats = {"Ethernet": SimpleNamespace(isup=True)}
        with patch.dict(os.environ, {"MYSPEEDIFY_SIMULATE_PATHS": "1"}), \
                patch("core.adapter.psutil.net_if_addrs", return_value=addresses), \
                patch("core.adapter.psutil.net_if_stats", return_value=stats), \
                patch("core.adapter.get_windows_adapter_descriptions", return_value={}), \
                patch(
                    "core.adapter.get_windows_interface_indices",
                    return_value={"Ethernet": 12},
                ), \
                patch("core.adapter.socket.if_nametoindex", side_effect=AssertionError):
            adapters = AdapterManager().get_active_adapters()

        self.assertEqual(len(adapters), 2)
        self.assertTrue(all(adapter.interface_name == "Ethernet" for adapter in adapters))
        self.assertTrue(all(adapter.if_index == 12 for adapter in adapters))


if __name__ == "__main__":
    unittest.main()
