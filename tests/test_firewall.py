import shlex
import subprocess
import unittest
from unittest.mock import patch

from server.firewall import BLOCKED_DESTINATIONS, LinuxFirewall, OWNER_MARKER


class FakeIptables:
    def __init__(self):
        self.chains = {
            ("iptables", "filter", "INPUT"): ["-A INPUT -j EXISTING_INPUT"],
            ("iptables", "filter", "FORWARD"): ["-A FORWARD -j EXISTING_FORWARD"],
            ("iptables", "nat", "POSTROUTING"): ["-A POSTROUTING -j EXISTING_NAT"],
            ("iptables", "mangle", "FORWARD"): ["-A FORWARD -j EXISTING_MANGLE"],
            ("ip6tables", "filter", "FORWARD"): ["-A FORWARD -j EXISTING_IPV6"],
        }
        self.fail_once_on = None

    def run(self, command, capture_output, text):
        tool, _, _, table, *args = command
        op = args[0]
        if self.fail_once_on == (tool, table, tuple(args)):
            self.fail_once_on = None
            return subprocess.CompletedProcess(command, 1, "", "injected failure")

        if op == "-S":
            chain = args[1]
            rules = self.chains.get((tool, table, chain))
            if rules is None:
                return subprocess.CompletedProcess(
                    command, 1, "", "iptables: No chain/target/match by that name.",
                )
            header = "" if chain in {"INPUT", "FORWARD", "POSTROUTING"} else f"-N {chain}\n"
            return subprocess.CompletedProcess(command, 0, header + "\n".join(rules), "")

        if op == "-N":
            self.chains[(tool, table, args[1])] = []
        elif op == "-F":
            self.chains[(tool, table, args[1])] = []
        elif op == "-X":
            del self.chains[(tool, table, args[1])]
        elif op == "-A":
            chain = args[1]
            rule = "-A " + chain + (" " + shlex.join(args[2:]) if len(args) > 2 else "")
            self.chains[(tool, table, chain)].append(rule)
        elif op == "-I":
            chain, position = args[1], int(args[2])
            rule = "-A " + chain + " " + shlex.join(args[3:])
            self.chains[(tool, table, chain)].insert(position - 1, rule)
        elif op == "-C":
            chain = args[1]
            expected = "-A " + chain + " " + shlex.join(args[2:])
            if expected in self.chains.get((tool, table, chain), []):
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(
                command, 1, "", "Bad rule (does a matching rule exist in that chain?)",
            )
        elif op == "-D":
            chain = args[1]
            expected = "-A " + chain + " " + shlex.join(args[2:])
            self.chains[(tool, table, chain)].remove(expected)
        else:
            return subprocess.CompletedProcess(command, 2, "", f"unexpected operation {op}")
        return subprocess.CompletedProcess(command, 0, "", "")


class TestLinuxFirewall(unittest.TestCase):
    def setUp(self):
        self.runner = FakeIptables()
        self.firewall = LinuxFirewall("eth0")
        self.subprocess_patch = patch(
            "server.firewall.subprocess.run", side_effect=self.runner.run,
        )
        self.subprocess_patch.start()
        self.addCleanup(self.subprocess_patch.stop)

    def test_installs_scoped_protected_rules_without_replacing_host_chains(self):
        self.firewall.install()
        self.firewall.install()

        input_rules = self.runner.chains[("iptables", "filter", "MSP_INPUT")]
        forward_rules = self.runner.chains[("iptables", "filter", "MSP_FORWARD")]
        nat_rules = self.runner.chains[("iptables", "nat", "MSP_POSTROUTING")]
        mss_rules = self.runner.chains[("iptables", "mangle", "MSP_MSS")]
        ipv6_rules = self.runner.chains[("ip6tables", "filter", "MSP6_FORWARD")]

        self.assertIn("-A MSP_INPUT -i msps0 -j DROP", input_rules)
        self.assertIn(
            "-A MSP_INPUT -i eth0 -p udp --dport 51820 -j ACCEPT",
            input_rules,
        )
        self.assertTrue(
            any("168.63.129.16/32" in rule for rule in forward_rules)
        )
        for network in BLOCKED_DESTINATIONS:
            self.assertTrue(any(f"-d {network} -j DROP" in rule for rule in forward_rules))
        self.assertTrue(
            any(
                shlex.split(rule) == [
                    "-A", "MSP_FORWARD", "-i", "msps0", "!",
                    "-s", "10.8.0.0/24", "-j", "DROP",
                ]
                for rule in forward_rules
            )
        )
        self.assertTrue(any("-i msps0 -j DROP" in rule for rule in forward_rules))
        self.assertIn("-A MSP6_FORWARD -o msps0 -j DROP", ipv6_rules)
        self.assertIn(
            "-A MSP_POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE",
            nat_rules,
        )
        self.assertEqual(sum("TCPMSS" in rule for rule in mss_rules), 2)
        self.assertEqual(len(ipv6_rules), 3)
        self.assertTrue(any(OWNER_MARKER in rule for rule in forward_rules))

        self.assertEqual(
            self.runner.chains[("iptables", "filter", "FORWARD")],
            [
                "-A FORWARD -j MSP_FORWARD",
                "-A FORWARD -j EXISTING_FORWARD",
            ],
        )
        self.assertIn(
            "-A POSTROUTING -j EXISTING_NAT",
            self.runner.chains[("iptables", "nat", "POSTROUTING")],
        )
        self.assertEqual(
            self.runner.chains[("iptables", "filter", "INPUT")],
            [
                "-A INPUT -j MSP_INPUT",
                "-A INPUT -j EXISTING_INPUT",
            ],
        )
        self.assertEqual(
            self.runner.chains[("iptables", "filter", "INPUT")].count(
                "-A INPUT -j MSP_INPUT",
            ),
            1,
        )

    def test_refuses_to_modify_an_unowned_chain(self):
        self.runner.chains[("iptables", "filter", "MSP_FORWARD")] = [
            "-A MSP_FORWARD -j ACCEPT",
        ]

        with self.assertRaisesRegex(RuntimeError, "not owned by MySpeedify"):
            self.firewall.install()

        self.assertEqual(
            self.runner.chains[("iptables", "filter", "MSP_FORWARD")],
            ["-A MSP_FORWARD -j ACCEPT"],
        )
        self.assertNotIn(("iptables", "filter", "MSP_INPUT"), self.runner.chains)
        self.assertNotIn(
            "-A INPUT -j MSP_INPUT",
            self.runner.chains[("iptables", "filter", "INPUT")],
        )

    def test_remove_preserves_jump_to_an_unowned_chain(self):
        self.runner.chains[("iptables", "filter", "MSP_FORWARD")] = [
            "-A MSP_FORWARD -j ACCEPT",
        ]
        self.runner.chains[("iptables", "filter", "FORWARD")].insert(
            0, "-A FORWARD -j MSP_FORWARD",
        )

        with self.assertRaisesRegex(RuntimeError, "unowned firewall chain"):
            self.firewall.remove()

        self.assertIn(
            "-A FORWARD -j MSP_FORWARD",
            self.runner.chains[("iptables", "filter", "FORWARD")],
        )
        self.assertEqual(
            self.runner.chains[("iptables", "filter", "MSP_FORWARD")],
            ["-A MSP_FORWARD -j ACCEPT"],
        )

    def test_remove_deletes_only_owned_chains_and_jumps(self):
        self.firewall.install()

        self.firewall.remove()

        self.assertNotIn(("iptables", "filter", "MSP_INPUT"), self.runner.chains)
        self.assertNotIn(("iptables", "filter", "MSP_FORWARD"), self.runner.chains)
        self.assertNotIn(("iptables", "nat", "MSP_POSTROUTING"), self.runner.chains)
        self.assertNotIn(("iptables", "mangle", "MSP_MSS"), self.runner.chains)
        self.assertNotIn(("ip6tables", "filter", "MSP6_FORWARD"), self.runner.chains)
        self.assertEqual(
            self.runner.chains[("iptables", "filter", "INPUT")],
            ["-A INPUT -j EXISTING_INPUT"],
        )
        self.assertEqual(
            self.runner.chains[("iptables", "filter", "FORWARD")],
            [
                "-A FORWARD -j EXISTING_FORWARD",
            ],
        )

    def test_failed_install_rolls_back_created_chains_and_jumps(self):
        self.runner.fail_once_on = (
            "iptables", "filter", ("-A", "MSP_FORWARD", "-i", "msps0", "!", "-s", "10.8.0.0/24", "-j", "DROP"),
        )

        with self.assertRaisesRegex(RuntimeError, "injected failure"):
            self.firewall.install()

        self.assertNotIn(("iptables", "filter", "MSP_INPUT"), self.runner.chains)
        self.assertNotIn(("iptables", "filter", "MSP_FORWARD"), self.runner.chains)
        self.assertEqual(
            self.runner.chains[("iptables", "filter", "INPUT")],
            ["-A INPUT -j EXISTING_INPUT"],
        )
        self.assertEqual(
            self.runner.chains[("iptables", "filter", "FORWARD")],
            ["-A FORWARD -j EXISTING_FORWARD"],
        )

    def test_rejects_invalid_interface_and_port(self):
        with self.assertRaises(ValueError):
            LinuxFirewall("eth0;iptables")
        with self.assertRaises(ValueError):
            LinuxFirewall("eth0", "eth0")
        with self.assertRaises(ValueError):
            LinuxFirewall("eth0", port=65536)


if __name__ == "__main__":
    unittest.main()
