import ipaddress
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

    def test_linux_installs_ipv4_kill_switch_with_relay_exception(self):
        tun = Mock()
        tun.name = "msp0"
        path = PhysicalPath("eth0", "192.0.2.10", 2)
        with patch("core.tun.routes.platform.system", return_value="Linux"):
            config = TunnelNetworkConfig(tun, "198.51.100.10", [path])
        commands = []

        def run(*command):
            commands.append(command)
            if command[:2] in { ("iptables", "-w"), ("ip6tables", "-w") }:
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[:5] == ("ip", "-4", "route", "show", "default"):
                return subprocess.CompletedProcess(command, 0, "default via 192.0.2.1 dev eth0\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(config, "_run", side_effect=run), \
                patch.object(config, "_allocate_linux_ids", return_value=(24000, 10000)):
            config.install()

            self.assertTrue(any(
                command[:4] == ("iptables", "-w", "-I", "OUTPUT")
                and "198.51.100.10" in command
                and "ACCEPT" in command
                for command in commands
            ))
            self.assertTrue(any(
                command[:4] == ("iptables", "-w", "-I", "OUTPUT")
                and "!" in command
                and "DROP" in command
                for command in commands
            ))

            config.close()
            self.assertTrue(any(
                command[:4] == ("iptables", "-w", "-D", "OUTPUT")
                and "198.51.100.10" in command
                and "ACCEPT" in command
                for command in commands
            ))

    def test_linux_skips_paths_without_default_route(self):
        tun = Mock()
        tun.name = "msp0"
        valid = PhysicalPath("eth0", "192.0.2.10", 2)
        invalid = PhysicalPath("eth1", "203.0.113.10", 3)
        with patch("core.tun.routes.platform.system", return_value="Linux"):
            config = TunnelNetworkConfig(tun, "198.51.100.10", [valid, invalid])
        commands = []

        def run(*command):
            commands.append(command)
            if command[:5] == ("ip", "-4", "route", "show", "default"):
                output = "default via 192.0.2.1 dev eth0\n" if command[-1] == "eth0" else ""
                return subprocess.CompletedProcess(command, 0, output, "")
            if command == ("ip", "-4", "rule", "show"):
                return subprocess.CompletedProcess(command, 0, "", "")
            if command == ("ip6tables", "-w", "-S", "OUTPUT"):
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(config, "_run", side_effect=run), \
                patch.object(config, "_allocate_linux_ids", return_value=(24000, 10000)):
            config.install()

        self.assertEqual({path.interface_name for path in config._paths.values()}, {"eth0"})
        self.assertIn(("ip", "-4", "route", "add", "0.0.0.0/1", "dev", "msp0"), commands)

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
            "table", "24001", "proto", "99",
        ))
        old_rule_delete = commands.index((
            "ip", "-4", "rule", "del", "priority", "10000",
            "from", "192.0.2.10/32", "to", "198.51.100.10/32",
            "table", "24000", "protocol", "99",
        ))
        self.assertLess(new_route_add, old_rule_delete)
        self.assertIn((
            "ip", "-4", "route", "add", "198.51.100.11/32",
            "via", "203.0.113.1", "dev", "eth1", "onlink",
            "table", "24002", "proto", "99",
        ), commands)
        self.assertIn((
            "ip", "-4", "route", "del", "198.51.100.11/32",
            "via", "203.0.113.1", "dev", "eth1", "table", "24002",
            "proto", "99",
        ), commands)

    def test_linux_startup_cleans_only_myspeedify_owned_residues(self):
        tun = Mock()
        tun.name = "msp0"
        path = PhysicalPath("eth0", "192.0.2.10", 2)
        with patch("core.tun.routes.platform.system", return_value="Linux"):
            config = TunnelNetworkConfig(tun, "198.51.100.10", [path])
        commands = []

        def run(*command):
            commands.append(command)
            if command == ("ip", "-4", "rule", "show"):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "10000: from 192.0.2.10 to 198.51.100.10 "
                    "lookup 24000 proto 99\n"
                    "10001: from all to 198.51.100.10 lookup 24001 proto 99\n"
                    "40000: from 192.0.2.10 to 198.51.100.10 "
                    "lookup 24000 proto 99\n"
                    "200: from all lookup main\n",
                    "",
                )
            if command == ("ip6tables", "-w", "-S", "OUTPUT"):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "-A OUTPUT -o msp0 -m comment --comment msp-123-1234abcd -j DROP\n"
                    "-A OUTPUT -o eth1 -m comment --comment msp-foreign -j DROP\n"
                    "-A OUTPUT -o eth0 -j ACCEPT\n",
                    "",
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(config, "_run", side_effect=run):
            config._cleanup_stale()

        self.assertIn(
            (
                "ip", "-4", "rule", "del", "priority", "10000",
                "from", "192.0.2.10", "to", "198.51.100.10", "table", "24000",
            ),
            commands,
        )
        self.assertIn(
            ("ip", "-4", "route", "flush", "table", "24000", "to", "198.51.100.10/32"),
            commands,
        )
        self.assertNotIn(
            (
                "ip", "-4", "rule", "del", "priority", "10001",
                "from", "all", "to", "198.51.100.10", "table", "24001",
            ),
            commands,
        )
        self.assertNotIn(
            (
                "ip", "-4", "rule", "del", "priority", "40000",
                "from", "192.0.2.10", "to", "198.51.100.10", "table", "24000",
            ),
            commands,
        )
        self.assertIn(
            ("ip6tables", "-w", "-D", "OUTPUT", "-o", "msp0", "-m", "comment",
             "--comment", "msp-123-1234abcd", "-j", "DROP"),
            commands,
        )
        self.assertNotIn(
            (
                "ip6tables", "-w", "-D", "OUTPUT", "-o", "eth1", "-m", "comment",
                "--comment", "msp-foreign", "-j", "DROP",
            ),
            commands,
        )
        self.assertNotIn(
            ("ip6tables", "-w", "-D", "OUTPUT", "-o", "eth0", "-j", "ACCEPT"),
            commands,
        )

    def test_windows_startup_removes_owned_rules_and_routes_only_on_tun(self):
        tun = Mock()
        tun.adapter_name = "MySpeedifyVPN"
        with patch("core.tun.routes.platform.system", return_value="Windows"):
            config = TunnelNetworkConfig(tun, "198.51.100.10", [])
        commands = []
        scripts = []

        def run(*command):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        def powershell(script):
            scripts.append(script)
            return ""

        with patch.object(config, "_run", side_effect=run), \
                patch.object(config, "_powershell", side_effect=powershell), \
                patch.object(config, "_interface_index", return_value=17):
            config._cleanup_stale()

        self.assertTrue(any(
            "Get-NetFirewallRule -DisplayName 'MySpeedify-*'" in script
            and "Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop" in script
            for script in scripts
        ))
        self.assertEqual(
            sum("Remove-NetRoute" in script for script in scripts),
            2,
        )
        self.assertTrue(all("-InterfaceIndex 17" in script for script in scripts if "Remove-NetRoute" in script))
        self.assertTrue(all(
            "-DestinationPrefix" not in script
            and "Where-Object { $_.DestinationPrefix -eq" in script
            for script in scripts if "Remove-NetRoute" in script
        ))

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
                "New-NetFirewallRule" in script
                and "-Action Allow" in script
                and "-RemoteAddress @('198.51.100.10')" in script
                and "-InterfaceAlias 'Ethernet'" in script
                for script in scripts
            ))
            self.assertTrue(any(
                "New-NetFirewallRule" in script
                and "-Action Block" in script
                and "-InterfaceAlias 'Ethernet'" in script
                and "'198.51.100.10'" not in script
                for script in scripts
            ))
            self.assertTrue(any(
                "New-NetFirewallRule" in script
                and "-InterfaceAlias 'MySpeedifyVPN'" in script
                and "-RemoteAddress @('0.0.0.0/0')" in script
                for script in scripts
            ))
            self.assertTrue(any(
                "New-NetFirewallRule" in script
                and "-Action Block" in script
                and "-RemoteAddress @('::/1','8000::/1')" in script
                for script in scripts
            ))
            self.assertTrue(any("ServerAddresses '1.1.1.1'" in script for script in scripts))

            config.close()

        self.assertTrue(any(
            "Remove-NetFirewallRule -DisplayName 'MySpeedify-IPv4-Block-" in script
            and "-Confirm:$false -ErrorAction Stop" in script
            for script in scripts
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

    def test_windows_ipv4_firewall_blocklist_excludes_only_relay(self):
        tun = Mock()
        tun.adapter_name = "MySpeedifyVPN"
        with patch("core.tun.routes.platform.system", return_value="Windows"):
            config = TunnelNetworkConfig(tun, "198.51.100.10", [])

        networks = [
            ipaddress.ip_network(value)
            for value in config._windows_ipv4_blocklist("198.51.100.10")
        ]
        relay_ip = ipaddress.ip_address("198.51.100.10")

        self.assertFalse(any(relay_ip in network for network in networks))
        self.assertEqual(sum(network.num_addresses for network in networks), (1 << 32) - 1)

    def test_windows_dynamic_path_gets_and_removes_scoped_firewall_rules(self):
        tun = Mock()
        tun.adapter_name = "MySpeedifyVPN"
        first = PhysicalPath("Ethernet", "192.0.2.10", 12)
        second = PhysicalPath("Ethernet 2", "203.0.113.10", 13)
        with patch("core.tun.routes.platform.system", return_value="Windows"):
            config = TunnelNetworkConfig(tun, "198.51.100.10", [first])
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
                return "[]"
            return ""

        with patch.object(config, "_run", side_effect=run), \
                patch.object(config, "_powershell", side_effect=powershell):
            config.install()
            config.add_path(second)
            config.remove_path(second)
            config.close()

        self.assertTrue(any(
            "New-NetFirewallRule" in script
            and "-InterfaceAlias 'Ethernet 2'" in script
            and "-Action Block" in script
            for script in scripts
        ))
        self.assertTrue(any(
            "Remove-NetFirewallRule -DisplayName 'MySpeedify-IPv4-Block-" in script
            for script in scripts
        ))
        self.assertTrue(any(
            command[:2] == ("route.exe", "ADD")
            and command[2] == "198.51.100.10"
            and "13" in command
            for command in commands
        ))


if __name__ == "__main__":
    unittest.main()
