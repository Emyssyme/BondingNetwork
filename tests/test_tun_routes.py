import subprocess
import unittest
from unittest.mock import Mock, patch

from core.tun.routes import PhysicalPath, TunnelNetworkConfig


class TestTunnelNetworkConfig(unittest.TestCase):
    def test_linux_installs_full_tunnel_and_restores_settings(self):
        tun = Mock()
        tun.name = "msp0"
        path = PhysicalPath("eth0", "192.0.2.10", 2)
        with patch("core.tun.routes.platform.system", return_value="Linux"):
            config = TunnelNetworkConfig(tun, "198.51.100.10", [path])
        commands = []

        def run(*command):
            commands.append(command)
            output = "default via 192.0.2.1 dev eth0\n" if command[:5] == (
                "ip", "-4", "route", "show", "default"
            ) else ""
            if command == ("resolvectl", "dns", "msp0"):
                output = "Link 7 (msp0): 9.9.9.9\n"
            elif command == ("resolvectl", "domain", "msp0"):
                output = "Link 7 (msp0): corp.example\n"
            return subprocess.CompletedProcess(command, 0, output, "")

        with patch.object(config, "_run", side_effect=run), \
                patch.object(config, "_allocate_linux_ids", return_value=(24000, 10000)):
            config.install()
            self.assertIn(
                ("ip", "-4", "route", "add", "0.0.0.0/1", "dev", "msp0"),
                commands,
            )
            self.assertIn(
                ("ip", "-4", "route", "add", "128.0.0.0/1", "dev", "msp0"),
                commands,
            )
            self.assertIn(("resolvectl", "dns", "msp0", "1.1.1.1"), commands)
            self.assertIn(("resolvectl", "domain", "msp0", "~."), commands)
            self.assertTrue(any(command[0] == "ip6tables" and "-I" in command for command in commands))
            self.assertTrue(any(
                command[:4] == ("ip", "-4", "rule", "add")
                and "198.51.100.10/32" in command
                for command in commands
            ))

            config.close()

        self.assertIn(("resolvectl", "revert", "msp0"), commands)
        self.assertIn(("resolvectl", "dns", "msp0", "9.9.9.9"), commands)
        self.assertIn(("resolvectl", "domain", "msp0", "corp.example"), commands)
        self.assertIn(
            ("ip", "-4", "route", "del", "0.0.0.0/1", "dev", "msp0"),
            commands,
        )
        self.assertTrue(any(command[0] == "ip6tables" and "-D" in command for command in commands))

    def test_linux_setup_failure_rolls_back_installed_routes(self):
        tun = Mock()
        tun.name = "msp0"
        path = PhysicalPath("eth0", "192.0.2.10", 2)
        with patch("core.tun.routes.platform.system", return_value="Linux"):
            config = TunnelNetworkConfig(tun, "198.51.100.10", [path])
        commands = []

        def run(*command):
            commands.append(command)
            if command[:5] == ("ip", "-4", "route", "show", "default"):
                return subprocess.CompletedProcess(command, 0, "default via 192.0.2.1 dev eth0\n", "")
            if command[:5] == ("ip", "-4", "route", "add", "128.0.0.0/1"):
                raise RuntimeError("route failure")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(config, "_run", side_effect=run), \
                patch.object(config, "_allocate_linux_ids", return_value=(24000, 10000)):
            with self.assertRaisesRegex(RuntimeError, "route failure"):
                config.install()

        self.assertIn(
            ("ip", "-4", "route", "del", "0.0.0.0/1", "dev", "msp0"),
            commands,
        )
        self.assertTrue(any(
            command[:4] == ("ip", "-4", "rule", "del")
            for command in commands
        ))
        self.assertTrue(any(command[0] == "ip6tables" and "-D" in command for command in commands))

    def test_failed_cleanup_is_reported_and_can_be_retried(self):
        tun = Mock()
        tun.name = "msp0"
        path = PhysicalPath("eth0", "192.0.2.10", 2)
        with patch("core.tun.routes.platform.system", return_value="Linux"):
            config = TunnelNetworkConfig(tun, "198.51.100.10", [path])
        failed_once = [False]

        def run(*command):
            if command[:5] == ("ip", "-4", "route", "show", "default"):
                return subprocess.CompletedProcess(command, 0, "default via 192.0.2.1 dev eth0\n", "")
            if command == ("resolvectl", "revert", "msp0") and not failed_once[0]:
                failed_once[0] = True
                raise RuntimeError("temporary DNS restore failure")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(config, "_run", side_effect=run), \
                patch.object(config, "_allocate_linux_ids", return_value=(24000, 10000)):
            config.install()
            with self.assertRaisesRegex(RuntimeError, "temporary DNS restore failure"):
                config.close()
            config.close()

        self.assertTrue(failed_once[0])

    def test_linux_relay_change_replaces_exceptions_and_adds_paths(self):
        tun = Mock()
        tun.name = "msp0"
        first = PhysicalPath("eth0", "192.0.2.10", 2)
        second = PhysicalPath("eth1", "203.0.113.10", 3)
        with patch("core.tun.routes.platform.system", return_value="Linux"):
            config = TunnelNetworkConfig(tun, "198.51.100.10", [first])
        commands = []

        def run(*command):
            commands.append(command)
            if command[:5] == ("ip", "-4", "route", "show", "default"):
                interface = command[-1]
                gateway = "192.0.2.1" if interface == "eth0" else "203.0.113.1"
                return subprocess.CompletedProcess(
                    command, 0, f"default via {gateway} dev {interface}\n", "",
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(config, "_run", side_effect=run), \
                patch.object(
                    config, "_allocate_linux_ids",
                    side_effect=[(24000, 10000), (24001, 10001), (24002, 10002)],
                ):
            config.install()
            config.update_relay("198.51.100.11")
            config.add_path(second)
            config.remove_path(second)
            config.close()

        new_route_add = commands.index((
            "ip", "-4", "route", "add", "198.51.100.11/32",
            "via", "192.0.2.1", "dev", "eth0", "onlink",
            "table", "24001",
        ))
        old_rule_delete = commands.index((
            "ip", "-4", "rule", "del", "priority", "10000",
            "from", "192.0.2.10/32", "to", "198.51.100.10/32",
            "table", "24000",
        ))
        self.assertLess(new_route_add, old_rule_delete)
        self.assertIn((
            "ip", "-4", "route", "add", "198.51.100.11/32",
            "via", "203.0.113.1", "dev", "eth1", "onlink",
            "table", "24002",
        ), commands)
        self.assertIn((
            "ip", "-4", "route", "del", "198.51.100.11/32",
            "via", "203.0.113.1", "dev", "eth1", "table", "24002",
        ), commands)

    def test_windows_restores_dns_and_removes_kill_switch(self):
        tun = Mock()
        tun.adapter_name = "MySpeedifyVPN"
        path = PhysicalPath("Ethernet", "192.0.2.10", 12)
        with patch("core.tun.routes.platform.system", return_value="Windows"):
            config = TunnelNetworkConfig(tun, "198.51.100.10", [path])
        commands = []
        scripts = []

        def run(*command):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        def powershell(script):
            scripts.append(script)
            if "Get-NetAdapter" in script:
                return "3"
            if "Get-NetRoute" in script:
                return "192.0.2.1"
            if "Get-DnsClientServerAddress" in script:
                return '["9.9.9.9"]'
            return ""

        with patch.object(config, "_run", side_effect=run), \
                patch.object(config, "_powershell", side_effect=powershell):
            config.install()
            self.assertTrue(any(
                command[:2] == ("route.exe", "ADD")
                and command[2] == "0.0.0.0"
                and command[4] == "128.0.0.0"
                for command in commands
            ))
            self.assertTrue(any(
                command[0] == "netsh.exe" and "add" in command
                for command in commands
            ))
            self.assertTrue(any("ServerAddresses '1.1.1.1'" in script for script in scripts))

            config.close()

        self.assertTrue(any(
            command[0] == "netsh.exe" and "delete" in command
            for command in commands
        ))
        self.assertTrue(any(
            "ServerAddresses @('9.9.9.9')" in script
            for script in scripts
        ))
        self.assertTrue(any(
            command[:2] == ("route.exe", "DELETE")
            and command[2] == "0.0.0.0"
            for command in commands
        ))


if __name__ == "__main__":
    unittest.main()
