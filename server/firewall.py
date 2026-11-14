"""Install MySpeedify's narrowly scoped Linux forwarding rules."""

import argparse
import logging
import re
import shlex
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple

logger = logging.getLogger("MySpeedify.Firewall")

OWNER_MARKER = "myspeedify-managed-v1"
CLIENT_NETWORK = "10.8.0.0/24"
BLOCKED_DESTINATIONS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "168.63.129.16/32",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)


@dataclass(frozen=True)
class ChainSpec:
    tool: str
    table: str
    chain: str
    parent: str
    rules: Tuple[Tuple[str, ...], ...]


@dataclass
class ChainChange:
    spec: ChainSpec
    created: bool
    original_rules: List[str]
    jump_inserted: bool = False


class LinuxFirewall:
    def __init__(self, wan_interface: str, tun_interface: str = "msps0", port: int = 51820):
        self.wan_interface = self._validate_interface(wan_interface, "WAN")
        self.tun_interface = self._validate_interface(tun_interface, "TUN")
        if self.wan_interface == self.tun_interface:
            raise ValueError("WAN and TUN interfaces must be different")
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid UDP port: {port}")
        self.port = port

    def install(self) -> None:
        changes: List[ChainChange] = []
        try:
            for spec in self._chain_specs():
                change = self._replace_owned_chain(spec)
                changes.append(change)
                self._ensure_jump(spec, change)
        except Exception:
            self._rollback(changes)
            raise

    def remove(self) -> None:
        errors = []
        for spec in reversed(self._chain_specs()):
            try:
                result = self._inspect_chain(spec)
                if result is None:
                    continue
                if OWNER_MARKER not in result.stdout:
                    raise RuntimeError(
                        f"Refusing to remove unowned firewall chain {spec.chain}"
                    )
                self._remove_jump(spec)
                self._run(spec.tool, spec.table, "-F", spec.chain)
                self._run(spec.tool, spec.table, "-X", spec.chain)
            except Exception as e:
                errors.append(e)
        if errors:
            raise RuntimeError(f"Could not remove MySpeedify firewall rules: {errors[0]}")

    def _chain_specs(self) -> Tuple[ChainSpec, ...]:
        tun = self.tun_interface
        wan = self.wan_interface
        subnet = CLIENT_NETWORK
        input_rules = (
            ("-i", tun, "-j", "DROP"),
            ("-i", wan, "-p", "udp", "--dport", str(self.port), "-j", "ACCEPT"),
        )

        forward_rules = [
            ("-i", tun, "!", "-s", subnet, "-j", "DROP"),
        ]
        forward_rules.extend(
            ("-i", tun, "-d", destination, "-j", "DROP")
            for destination in BLOCKED_DESTINATIONS
        )
        forward_rules.extend((
            (
                "-i", tun, "-o", wan, "-s", subnet,
                "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED",
                "-j", "ACCEPT",
            ),
            (
                "-i", wan, "-o", tun, "-d", subnet,
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                "-j", "ACCEPT",
            ),
            ("-i", tun, "-j", "DROP"),
            ("-o", tun, "-j", "DROP"),
        ))

        return (
            ChainSpec("iptables", "filter", "MSP_INPUT", "INPUT", input_rules),
            ChainSpec(
                "iptables", "filter", "MSP_FORWARD", "FORWARD",
                tuple(forward_rules),
            ),
            ChainSpec(
                "iptables", "nat", "MSP_POSTROUTING", "POSTROUTING",
                (("-s", subnet, "-o", wan, "-j", "MASQUERADE"),),
            ),
            ChainSpec(
                "iptables", "mangle", "MSP_MSS", "FORWARD",
                (
                    (
                        "-i", tun, "-o", wan, "-p", "tcp",
                        "--tcp-flags", "SYN,RST", "SYN",
                        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
                    ),
                    (
                        "-i", wan, "-o", tun, "-p", "tcp",
                        "--tcp-flags", "SYN,RST", "SYN",
                        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
                    ),
                ),
            ),
            ChainSpec(
                "ip6tables", "filter", "MSP6_FORWARD", "FORWARD",
                (("-i", tun, "-j", "DROP"), ("-o", tun, "-j", "DROP")),
            ),
        )

    def _replace_owned_chain(self, spec: ChainSpec) -> ChainChange:
        result = self._inspect_chain(spec)
        if result is not None:
            if OWNER_MARKER not in result.stdout:
                raise RuntimeError(
                    f"Firewall chain {spec.chain} exists but is not owned by MySpeedify"
                )
            original_rules = [
                line for line in result.stdout.splitlines()
                if line.startswith(f"-A {spec.chain} ")
            ]
            created = False
        else:
            self._run(spec.tool, spec.table, "-N", spec.chain)
            original_rules = []
            created = True

        try:
            self._run(spec.tool, spec.table, "-F", spec.chain)
            for rule in spec.rules:
                self._run(spec.tool, spec.table, "-A", spec.chain, *rule)
            self._run(
                spec.tool, spec.table, "-A", spec.chain,
                "-m", "comment", "--comment", OWNER_MARKER, "-j", "RETURN",
            )
        except Exception:
            self._restore_chain(spec, created, original_rules)
            raise

        return ChainChange(spec, created, original_rules)

    def _inspect_chain(
        self, spec: ChainSpec
    ) -> Optional[subprocess.CompletedProcess]:
        result = self._run(spec.tool, spec.table, "-S", spec.chain, check=False)
        if result.returncode == 0:
            return result
        if "No chain/target/match by that name" in result.stderr:
            return None
        raise RuntimeError(
            f"Could not inspect firewall chain {spec.chain}: "
            f"{result.stderr.strip()}"
        )

    def _ensure_jump(self, spec: ChainSpec, change: ChainChange) -> None:
        if not self._jump_exists(spec):
            self._run(
                spec.tool, spec.table, "-I", spec.parent, "1", "-j", spec.chain,
            )
            change.jump_inserted = True

    def _remove_jump(self, spec: ChainSpec) -> None:
        while self._jump_exists(spec):
            self._run(
                spec.tool, spec.table, "-D", spec.parent, "-j", spec.chain,
            )

    def _jump_exists(self, spec: ChainSpec) -> bool:
        result = self._run(
            spec.tool, spec.table, "-C", spec.parent, "-j", spec.chain,
            check=False,
        )
        if result.returncode == 0:
            return True
        if "Bad rule" in result.stderr or "matching rule exist" in result.stderr:
            return False
        raise RuntimeError(
            f"Could not inspect firewall jump to {spec.chain}: "
            f"{result.stderr.strip()}"
        )

    def _restore_chain(
        self, spec: ChainSpec, created: bool, original_rules: List[str]
    ) -> None:
        try:
            self._run(spec.tool, spec.table, "-F", spec.chain)
            if created:
                self._run(spec.tool, spec.table, "-X", spec.chain)
            else:
                for line in original_rules:
                    self._run(spec.tool, spec.table, *shlex.split(line))
        except Exception:
            logger.exception("Could not restore firewall chain %s", spec.chain)

    def _rollback(self, changes: List[ChainChange]) -> None:
        for change in reversed(changes):
            if change.jump_inserted:
                try:
                    self._run(
                        change.spec.tool, change.spec.table, "-D",
                        change.spec.parent, "-j", change.spec.chain,
                    )
                except Exception:
                    logger.exception(
                        "Could not remove firewall jump for %s", change.spec.chain,
                    )
            self._restore_chain(
                change.spec, change.created, change.original_rules,
            )

    def _run(
        self, tool: str, table: str, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess:
        command = [tool, "-w", "-t", table, *args]
        result = subprocess.run(command, capture_output=True, text=True)
        if check and result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"{' '.join(command)} failed: {detail}")
        return result

    @staticmethod
    def _validate_interface(value: str, label: str) -> str:
        if (
            not value
            or len(value) > 15
            or re.fullmatch(r"[A-Za-z0-9_.:-]+", value) is None
        ):
            raise ValueError(f"Invalid {label} interface name: {value!r}")
        return value


def detect_wan_interface() -> str:
    result = subprocess.run(
        ["ip", "-4", "route", "get", "1.1.1.1"],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Could not detect the IPv4 WAN interface: {detail}")
    parts = result.stdout.split()
    try:
        interface = parts[parts.index("dev") + 1]
    except (ValueError, IndexError) as e:
        raise RuntimeError(
            f"Could not parse IPv4 WAN interface from: {result.stdout.strip()}"
        ) from e
    return LinuxFirewall._validate_interface(interface, "WAN")


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "remove"))
    parser.add_argument("--wan", default="auto")
    parser.add_argument("--tun", default="msps0")
    parser.add_argument("--port", type=int, default=51820)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    wan = detect_wan_interface() if args.wan == "auto" else args.wan
    firewall = LinuxFirewall(wan, args.tun, args.port)
    if args.action == "install":
        firewall.install()
    else:
        firewall.remove()


if __name__ == "__main__":
    main()
