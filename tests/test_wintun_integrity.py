import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from core.tun.wintun_integrity import verify_wintun_dll
from core.tun.wintun import WintunInterface as LegacyWintunInterface
from core.tun.wintun_v2 import WintunInterface


class TestWintunIntegrity(unittest.TestCase):
    def test_accepts_the_pinned_digest(self):
        contents = b"trusted test DLL bytes"
        expected = hashlib.sha256(contents).hexdigest()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "wintun.dll"
            path.write_bytes(contents)
            with patch("core.tun.wintun_integrity.WINTUN_SHA256", expected):
                verify_wintun_dll(str(path))

    def test_existing_adapter_is_opened_before_attempting_creation(self):
        dll = Mock()
        dll.WintunOpenAdapter.return_value = 11
        dll.WintunStartSession.return_value = 22
        dll.WintunGetReadWaitEvent.return_value = 33
        tun = WintunInterface()
        notifier = Mock()

        with patch.object(tun, "_load_dll", return_value=dll), \
                patch("core.tun.wintun_v2.subprocess.run", return_value=Mock(returncode=0)), \
                patch(
                    "core.tun.wintun_v2.create_wintun_read_notifier",
                    return_value=notifier,
                ) as create_notifier:
            self.assertTrue(tun.open())

        dll.WintunOpenAdapter.assert_called_once_with(tun.adapter_name)
        dll.WintunCreateAdapter.assert_not_called()
        dll.WintunStartSession.assert_called_once_with(11, 0x400000)
        create_notifier.assert_called_once_with(33)

    def test_missing_adapter_is_created_when_open_fails(self):
        dll = Mock()
        dll.WintunOpenAdapter.return_value = None
        dll.WintunCreateAdapter.return_value = 11
        dll.WintunStartSession.return_value = 22
        dll.WintunGetReadWaitEvent.return_value = 33
        tun = WintunInterface()
        notifier = Mock()

        with patch.object(tun, "_load_dll", return_value=dll), \
                patch("core.tun.wintun_v2.subprocess.run", return_value=Mock(returncode=0)), \
                patch(
                    "core.tun.wintun_v2.create_wintun_read_notifier",
                    return_value=notifier,
                ) as create_notifier:
            self.assertTrue(tun.open())

        dll.WintunCreateAdapter.assert_called_once_with(
            tun.adapter_name, tun.tunnel_type, None,
        )
        create_notifier.assert_called_once_with(33)

    def test_wintun_mtu_configuration_failure_closes_adapter_and_raises(self):
        dll = Mock()
        dll.WintunOpenAdapter.return_value = 11
        dll.WintunStartSession.return_value = 22
        dll.WintunGetReadWaitEvent.return_value = 33
        tun = WintunInterface()
        address_result = Mock(returncode=0, stdout="", stderr="")
        mtu_result = Mock(returncode=1, stdout="", stderr="Access is denied")

        with patch.object(
            tun, "_load_dll", return_value=dll,
        ), patch(
            "core.tun.wintun_v2.subprocess.run",
            side_effect=(address_result, mtu_result),
        ), patch(
            "core.tun.wintun_v2.create_wintun_read_notifier",
            return_value=Mock(),
        ), self.assertRaisesRegex(
            RuntimeError, "netsh set MTU failed: Access is denied",
        ):
            tun.open()

        dll.WintunEndSession.assert_called_once_with(22)
        dll.WintunCloseAdapter.assert_called_once_with(11)
        self.assertFalse(tun.is_open)

    def test_wintun_ip_change_restores_previous_configuration_on_failure(self):
        tun = WintunInterface()
        tun.is_open = True
        previous = tun.ip, tun.netmask, tun.mtu

        with patch.object(
            tun, "_configure", side_effect=(RuntimeError("MTU denied"), None),
        ) as configure, self.assertRaisesRegex(RuntimeError, "MTU denied"):
            tun.set_ip("10.8.0.3", mtu=1300)

        configure.assert_has_calls([call(), call()])
        self.assertEqual((tun.ip, tun.netmask, tun.mtu), previous)

    def test_legacy_wintun_uses_driver_read_event(self):
        tun = LegacyWintunInterface()
        tun._dll = Mock()
        tun._session_handle = 22
        tun._dll.WintunGetReadWaitEvent.return_value = 33
        notifier = Mock()

        with patch(
            "core.tun.wintun.create_wintun_read_notifier",
            return_value=notifier,
        ) as create_notifier:
            tun._start_read_notifier()

        create_notifier.assert_called_once_with(33)
        self.assertIs(tun.read_wait_socket, notifier.socket)

    def test_legacy_route_commands_pass_adapter_as_an_argument(self):
        adapter_name = 'MySpeedify"; echo unsafe'
        tun = LegacyWintunInterface(adapter_name=adapter_name)

        with patch(
            "core.tun.wintun.subprocess.run",
            return_value=Mock(returncode=0, stdout="", stderr=""),
        ) as run:
            tun._configure_routes()

        self.assertEqual(
            run.call_args_list,
            [
                call(
                    [
                        "netsh", "interface", "ip", "set", "address",
                        f"name={adapter_name}", "static", tun.ip, tun.netmask,
                    ],
                    capture_output=True,
                    check=False,
                    text=True,
                ),
                call(
                    [
                        "netsh", "interface", "ipv4", "set", "subinterface",
                        adapter_name, f"mtu={tun.mtu}", "store=active",
                    ],
                    capture_output=True,
                    check=False,
                    text=True,
                ),
            ],
        )

    def test_legacy_wintun_reports_network_configuration_failure(self):
        tun = LegacyWintunInterface()
        result = Mock(returncode=1, stdout="", stderr="Access is denied")

        with patch("core.tun.wintun.subprocess.run", return_value=result) as run:
            message = "netsh interface ip set address.*Access is denied"
            with self.assertRaisesRegex(RuntimeError, message):
                tun._configure_routes()

        run.assert_called_once()

    def test_legacy_ip_change_restores_previous_configuration_on_failure(self):
        tun = LegacyWintunInterface()
        tun._dll = Mock()
        tun.is_open = True
        previous = tun.ip, tun.netmask, tun.mtu

        with patch.object(
            tun, "_configure_routes", side_effect=(RuntimeError("MTU denied"), None),
        ) as configure, self.assertRaisesRegex(RuntimeError, "MTU denied"):
            tun.set_ip("10.8.0.3", mtu=1300)

        configure.assert_has_calls([call(), call()])
        self.assertEqual((tun.ip, tun.netmask, tun.mtu), previous)

    def test_rejects_unexpected_digest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "wintun.dll"
            path.write_bytes(b"modified DLL")
            with self.assertRaisesRegex(RuntimeError, "integrity check failed"):
                verify_wintun_dll(str(path))


if __name__ == "__main__":
    unittest.main()
