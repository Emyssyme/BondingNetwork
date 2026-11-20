"""Runtime routing, DNS, and IPv6 policy for the client TUN."""

import ipaddress
import json
import logging
import os
import platform
import re
import shlex
import socket
import subprocess
import threading
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from core.windows import system_executable

logger = logging.getLogger("MySpeedify.TunnelRoutes")


@dataclass(frozen=True)
class PhysicalPath:
    interface_name: str
    local_ip: str
    if_index: Optional[int]

    @property
    def key(self) -> Tuple[str, str]:
        return self.interface_name, self.local_ip


class TunnelNetworkConfig:
    def __init__(
        self,
        tun,
        relay_ip: str,
        paths: Iterable[PhysicalPath],
        dns_server: str = "1.1.1.1",
    ):
        self.tun = tun
        self.relay_ip = str(ipaddress.IPv4Address(relay_ip))
        self.dns_server = str(ipaddress.IPv4Address(dns_server))
        self.system = platform.system()
        self._lock = threading.RLock()
        self._cleanups: List[Callable[[], None]] = []
        self._path_counts: Dict[Tuple[str, str], int] = {}
        self._paths: Dict[Tuple[str, str], PhysicalPath] = {}
        self._path_cleanups: Dict[Tuple[str, str], List[Callable[[], None]]] = {}
        self._retired_path_cleanups: List[Callable[[], None]] = []
        self._installed = False
        for path in paths:
            self._path_counts[path.key] = self._path_counts.get(path.key, 0) + 1
            self._paths[path.key] = path

    def install(self) -> None:
        with self._lock:
            if self._installed:
                return
            try:
                if not self._paths:
                    raise RuntimeError("Cannot enable full-tunnel routes without a physical path")
                filtered = self._paths_with_default_route()
                if not filtered:
                    raise RuntimeError("Cannot enable full-tunnel routes without a valid physical path")
                if len(filtered) != len(self._paths):
                    logger.warning(
                        "Skipping %d physical path(s) without a usable IPv4 default route: %s",
                        len(self._paths) - len(filtered),
                        ", ".join(path.interface_name for path in self._paths.values() if path not in filtered),
                    )
                    self._paths = {path.key: path for path in filtered}
                    self._path_counts = {path.key: self._path_counts.get(path.key, 1) for path in filtered}
                self._cleanup_stale()
                if self.system == "Linux":
                    self._install_linux()
                elif self.system == "Windows":
                    self._install_windows()
                else:
                    raise RuntimeError(f"Full-tunnel routing is unsupported on {self.system}")
                self._installed = True
            except Exception:
                try:
                    self._run_cleanups()
                except Exception:
                    logger.exception("Could not fully roll back failed tunnel network configuration")
                raise

    def update_relay(self, relay_ip: str) -> None:
        relay_ip = str(ipaddress.IPv4Address(relay_ip))
        with self._lock:
            if not self._installed or relay_ip == self.relay_ip:
                return

            new_cleanups: Dict[Tuple[str, str], List[Callable[[], None]]] = {}
            try:
                for key, path in self._paths.items():
                    new_cleanups[key] = self._install_path_route(relay_ip, path)
            except Exception:
                self._cleanup_path_map(new_cleanups)
                raise

            old_cleanups = self._path_cleanups
            self._path_cleanups = new_cleanups
            self.relay_ip = relay_ip
            for actions in old_cleanups.values():
                errors = self._cleanup_actions(actions)
                if errors:
                    self._retired_path_cleanups.extend(action for action, _ in errors)
                    logger.error(
                        "Could not remove old relay exception routes: %s", errors[0][1],
                    )

    def add_path(self, path: PhysicalPath) -> None:
        with self._lock:
            self._path_counts[path.key] = self._path_counts.get(path.key, 0) + 1
            self._paths[path.key] = path
            if not self._installed or path.key in self._path_cleanups:
                return
            try:
                self._path_cleanups[path.key] = self._install_path_route(self.relay_ip, path)
            except Exception:
                self._path_counts[path.key] -= 1
                if self._path_counts[path.key] == 0:
                    del self._path_counts[path.key]
                    del self._paths[path.key]
                raise

    def remove_path(self, path: PhysicalPath) -> None:
        with self._lock:
            count = self._path_counts.get(path.key, 0)
            if count > 1:
                self._path_counts[path.key] = count - 1
                return
            self._path_counts.pop(path.key, None)
            self._paths.pop(path.key, None)
            actions = self._path_cleanups.pop(path.key, [])
            errors = self._cleanup_actions(actions)
            if errors:
                self._retired_path_cleanups.extend(action for action, _ in errors)
                raise RuntimeError(f"Could not remove physical path route: {errors[0][1]}")

    def close(self) -> None:
        with self._lock:
            self._run_cleanups()
            self._installed = False

    def cleanup_stale(self) -> None:
        """Remove persisted state left by an interrupted tunnel process."""
        with self._lock:
            self._cleanup_stale()

    def _install_linux(self) -> None:
        tun_name = self.tun.name
        comment = f"msp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        relay_comment = f"msp-relay-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._run(
            "ip6tables", "-w", "-I", "OUTPUT", "1",
            "!", "-o", "lo", "!", "-o", tun_name,
            "-m", "comment", "--comment", comment, "-j", "DROP",
        )
        self._cleanups.append(lambda: self._run(
            "ip6tables", "-w", "-D", "OUTPUT",
            "!", "-o", "lo", "!", "-o", tun_name,
            "-m", "comment", "--comment", comment, "-j", "DROP",
        ))

        self._run(
            "iptables", "-w", "-I", "OUTPUT", "1",
            "-d", self.relay_ip, "-m", "comment", "--comment", relay_comment,
            "-j", "ACCEPT",
        )
        self._cleanups.append(lambda: self._run(
            "iptables", "-w", "-D", "OUTPUT",
            "-d", self.relay_ip, "-m", "comment", "--comment", relay_comment,
            "-j", "ACCEPT",
        ))
        self._run(
            "iptables", "-w", "-I", "OUTPUT", "2",
            "!", "-o", "lo", "!", "-o", tun_name,
            "-m", "comment", "--comment", comment, "-j", "DROP",
        )
        self._cleanups.append(lambda: self._run(
            "iptables", "-w", "-D", "OUTPUT",
            "!", "-o", "lo", "!", "-o", tun_name,
            "-m", "comment", "--comment", comment, "-j", "DROP",
        ))

        self._cleanups.append(self._clear_path_routes)
        for key, path in self._paths.items():
            self._path_cleanups[key] = self._install_linux_path(self.relay_ip, path)

        for prefix in ("0.0.0.0/1", "128.0.0.0/1"):
            self._run("ip", "-4", "route", "add", prefix, "dev", tun_name)
            self._cleanups.append(lambda route=prefix: self._run(
                "ip", "-4", "route", "del", route, "dev", tun_name,
            ))

        dns_before = self._resolvectl_values("dns", tun_name)
        domains_before = self._resolvectl_values("domain", tun_name)
        self._cleanups.append(
            lambda: self._restore_linux_resolver(tun_name, dns_before, domains_before)
        )
        self._run("resolvectl", "dns", tun_name, self.dns_server)
        self._run("resolvectl", "domain", tun_name, "~.")

    def _install_windows(self) -> None:
        tun_alias = self.tun.adapter_name
        tunnel_allow_name = f"MySpeedify-IPv4-Tunnel-Allow-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._cleanups.append(self._add_windows_firewall_rule(
            name=tunnel_allow_name,
            action="Allow",
            remote_addresses=["0.0.0.0/0"],
            interface_alias=tun_alias,
        ))

        ipv6_rule_name = f"MySpeedify-IPv6-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._cleanups.append(self._add_windows_firewall_rule(
            name=ipv6_rule_name,
            action="Block",
            remote_addresses=["::/1", "8000::/1"],
        ))

        self._cleanups.append(self._clear_path_routes)
        for key, path in self._paths.items():
            self._path_cleanups[key] = self._install_path_route(self.relay_ip, path)

        tun_index = self._interface_index(self.tun.adapter_name)
        for destination, mask in (
            ("0.0.0.0", "128.0.0.0"),
            ("128.0.0.0", "128.0.0.0"),
        ):
            self._run(
                system_executable("route.exe"), "ADD", destination, "MASK", mask, "0.0.0.0",
                "IF", str(tun_index), "METRIC", "1",
            )
            self._cleanups.append(lambda dst=destination, msk=mask: self._run(
                system_executable("route.exe"), "DELETE", dst, "MASK", msk, "0.0.0.0", "IF", str(tun_index),
            ))

        dns_before = self._windows_dns(tun_index)
        self._cleanups.append(lambda: self._restore_windows_dns(tun_index, dns_before))
        self._powershell(
            f"Set-DnsClientServerAddress -InterfaceIndex {tun_index} "
            f"-ServerAddresses '{self.dns_server}'"
        )

    def _paths_with_default_route(self) -> List[PhysicalPath]:
        valid: List[PhysicalPath] = []
        for path in self._paths.values():
            try:
                if self.system == "Linux":
                    route_output = self._run(
                        "ip", "-4", "route", "show", "default", "dev", path.interface_name,
                    ).stdout
                    if not route_output.strip():
                        continue
                elif self.system == "Windows":
                    gateway = self._powershell(
                        "$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
                        f"-InterfaceIndex {(path.if_index or self._interface_index(path.interface_name))} | "
                        "Sort-Object RouteMetric | Select-Object -First 1; if ($null -eq $r) { exit 1 }; $r.NextHop"
                    )
                    if not gateway:
                        continue
                else:
                    raise RuntimeError(f"Full-tunnel routing is unsupported on {self.system}")
                valid.append(path)
            except Exception:
                logger.warning("Skipping physical path %s because it has no usable IPv4 default route", path.interface_name)
        return valid

    def _install_path_route(self, relay_ip: str, path: PhysicalPath) -> List[Callable[[], None]]:
        if self.system == "Linux":
            return self._install_linux_path(relay_ip, path)
        if self.system == "Windows":
            actions = self._install_windows_path(relay_ip, path)
            try:
                actions.extend(self._install_windows_path_firewall(relay_ip, path))
            except Exception:
                errors = self._cleanup_actions(actions)
                self._retired_path_cleanups.extend(action for action, _ in errors)
                raise
            return actions
        raise RuntimeError(f"Interface routes are unsupported on {self.system}")

    def _install_linux_path(
        self, relay_ip: str, path: PhysicalPath
    ) -> List[Callable[[], None]]:
        route_output = self._run(
            "ip", "-4", "route", "show", "default", "dev", path.interface_name,
        ).stdout
        if not route_output.strip():
            raise RuntimeError(f"No physical IPv4 default route on {path.interface_name}")
        route = route_output.splitlines()[0].split()
        try:
            route_device = route[route.index("dev") + 1]
        except (ValueError, IndexError) as e:
            raise RuntimeError(f"Could not determine route to relay via {path.interface_name}") from e
        if route_device != path.interface_name:
            raise RuntimeError(
                f"Relay route for {path.local_ip} uses {route_device}, "
                f"not {path.interface_name}"
            )

        gateway = None
        if "via" in route:
            gateway = route[route.index("via") + 1]
        table, priority = self._allocate_linux_ids()
        actions: List[Callable[[], None]] = []
        try:
            if gateway:
                self._run(
                    "ip", "-4", "route", "add", f"{relay_ip}/32",
                    "via", gateway, "dev", path.interface_name, "onlink",
                    "table", str(table), "proto", "99",
                )
                actions.append(lambda: self._run(
                    "ip", "-4", "route", "del", f"{relay_ip}/32",
                    "via", gateway, "dev", path.interface_name, "table", str(table),
                    "proto", "99",
                ))
            else:
                self._run(
                    "ip", "-4", "route", "add", f"{relay_ip}/32",
                    "dev", path.interface_name, "scope", "link", "table", str(table),
                    "proto", "99",
                )
                actions.append(lambda: self._run(
                    "ip", "-4", "route", "del", f"{relay_ip}/32",
                    "dev", path.interface_name, "table", str(table), "proto", "99",
                ))
            self._run(
                "ip", "-4", "rule", "add", "priority", str(priority),
                "from", f"{path.local_ip}/32", "to", f"{relay_ip}/32",
                "table", str(table), "protocol", "99",
            )
            actions.append(lambda: self._run(
                "ip", "-4", "rule", "del", "priority", str(priority),
                "from", f"{path.local_ip}/32", "to", f"{relay_ip}/32",
                "table", str(table), "protocol", "99",
            ))
            return actions
        except Exception:
            errors = self._cleanup_actions(actions)
            self._retired_path_cleanups.extend(action for action, _ in errors)
            raise

    def _install_windows_path(
        self, relay_ip: str, path: PhysicalPath
    ) -> List[Callable[[], None]]:
        index = path.if_index or self._interface_index(path.interface_name)
        gateway = self._powershell(
            "$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
            f"-InterfaceIndex {index} | Sort-Object RouteMetric | "
            "Select-Object -First 1; if ($null -eq $r) { throw 'No physical default route' }; "
            "$r.NextHop"
        )
        if not gateway:
            raise RuntimeError(f"No IPv4 gateway found for {path.interface_name}")
        gateway = str(ipaddress.IPv4Address(gateway))
        self._run(
            system_executable("route.exe"), "ADD", relay_ip, "MASK", "255.255.255.255",
            gateway, "IF", str(index), "METRIC", "1",
        )
        return [lambda: self._run(
            system_executable("route.exe"), "DELETE", relay_ip, "MASK", "255.255.255.255",
            gateway, "IF", str(index),
        )]

    def _install_windows_path_firewall(
        self, relay_ip: str, path: PhysicalPath
    ) -> List[Callable[[], None]]:
        actions: List[Callable[[], None]] = []
        try:
            allow_name = f"MySpeedify-IPv4-Allow-{os.getpid()}-{uuid.uuid4().hex[:8]}"
            actions.append(self._add_windows_firewall_rule(
                name=allow_name,
                action="Allow",
                remote_addresses=[relay_ip],
                interface_alias=path.interface_name,
            ))

            block_name = f"MySpeedify-IPv4-Block-{os.getpid()}-{uuid.uuid4().hex[:8]}"
            actions.append(self._add_windows_firewall_rule(
                name=block_name,
                action="Block",
                remote_addresses=self._windows_ipv4_blocklist(relay_ip),
                interface_alias=path.interface_name,
            ))
            return actions
        except Exception:
            errors = self._cleanup_actions(actions)
            self._retired_path_cleanups.extend(action for action, _ in errors)
            raise

    def _add_windows_firewall_rule(
        self,
        name: str,
        action: str,
        remote_addresses: List[str],
        interface_alias: Optional[str] = None,
    ) -> Callable[[], None]:
        quoted_addresses = ",".join(self._powershell_quote(value) for value in remote_addresses)
        interface_filter = (
            f" -InterfaceAlias {self._powershell_quote(interface_alias)}"
            if interface_alias is not None
            else ""
        )
        self._powershell(
            f"New-NetFirewallRule -DisplayName {self._powershell_quote(name)} "
            f"-Direction Outbound -Action {action} -Profile Any -Enabled True "
            f"-Protocol Any -RemoteAddress @({quoted_addresses}){interface_filter} "
            "-ErrorAction Stop | Out-Null"
        )
        return lambda: self._powershell(
            f"Remove-NetFirewallRule -DisplayName {self._powershell_quote(name)} "
            "-Confirm:$false -ErrorAction Stop"
        )

    @staticmethod
    def _powershell_quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    @staticmethod
    def _windows_ipv4_blocklist(relay_ip: str) -> List[str]:
        relay = ipaddress.IPv4Address(relay_ip)
        relay_value = int(relay)
        all_addresses = (1 << 32) - 1
        blocked = []
        if relay_value:
            blocked.extend(ipaddress.summarize_address_range(
                ipaddress.IPv4Address(0),
                ipaddress.IPv4Address(relay_value - 1),
            ))
        if relay_value < all_addresses:
            blocked.extend(ipaddress.summarize_address_range(
                ipaddress.IPv4Address(relay_value + 1),
                ipaddress.IPv4Address(all_addresses),
            ))
        return [str(network) for network in blocked]

    def _cleanup_stale(self) -> None:
        if self.system == "Linux":
            self._cleanup_linux_stale()
        elif self.system == "Windows":
            self._cleanup_windows_stale()

    def _cleanup_linux_stale(self) -> None:
        rules = self._run("ip", "-4", "rule", "show").stdout
        path_addresses = {f"{path.local_ip}/32" for path in self._paths.values()}
        relay_address = f"{self.relay_ip}/32"
        for line in rules.splitlines():
            priority = re.match(r"\s*(\d+):", line)
            source = re.search(r"\bfrom\s+(\S+)", line)
            destination = re.search(r"\bto\s+(\S+)", line)
            table = re.search(r"\b(?:lookup|table)\s+(\d+)\b", line)
            tagged = re.search(r"\b(?:protocol|proto)\s+99\b", line)
            if not (priority and source and destination and table):
                continue
            priority_id = int(priority.group(1))
            table_id = int(table.group(1))
            managed_ids = (
                10000 <= priority_id < 30000
                and 20000 <= table_id < 30000
            )
            managed_prefixes = True
            try:
                networks = [
                    ipaddress.ip_network(value, strict=False)
                    for value in (source.group(1), destination.group(1))
                ]
                managed_prefixes = all(
                    isinstance(network, ipaddress.IPv4Network)
                    and network.prefixlen == 32
                    for network in networks
                )
            except ValueError:
                managed_prefixes = False
            owns_rule = managed_ids and (
                (bool(tagged) and managed_prefixes)
                or (
                    source.group(1) in path_addresses
                    and destination.group(1) == relay_address
                )
            )
            if not owns_rule:
                continue
            self._run(
                "ip", "-4", "rule", "del", "priority", priority.group(1),
                "from", source.group(1), "to", destination.group(1),
                "table", str(table_id),
            )
            self._run(
                "ip", "-4", "route", "flush", "table", str(table_id),
                "to", f"{destination.group(1)}/32",
            )

        for chain, command in (("ip6tables", "-S"), ("iptables", "-S")):
            output = self._run(chain, "-w", command, "OUTPUT").stdout
            for line in output.splitlines():
                try:
                    args = shlex.split(line)
                except ValueError:
                    continue
                if len(args) < 3 or args[0] != "-A" or args[1] != "OUTPUT":
                    continue
                try:
                    comment_index = args.index("--comment")
                    comment = args[comment_index + 1]
                except (ValueError, IndexError):
                    continue
                if re.fullmatch(r"msp(?:-relay)?-\d+-[0-9a-f]{8}", comment):
                    self._run(chain, "-w", "-D", "OUTPUT", *args[2:])

    def _cleanup_windows_stale(self) -> None:
        self._powershell(
            "Get-NetFirewallRule -DisplayName 'MySpeedify-*' | "
            "Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop"
        )

        try:
            tun_index = self._interface_index(self.tun.adapter_name)
        except RuntimeError:
            logger.info("No MySpeedify tunnel adapter found during stale-state cleanup")
        else:
            for destination in ("0.0.0.0/1", "128.0.0.0/1"):
                self._powershell(
                    f"Get-NetRoute -InterfaceIndex {tun_index} -AddressFamily IPv4 "
                    "-ErrorAction SilentlyContinue | "
                    f"Where-Object {{ $_.DestinationPrefix -eq '{destination}' }} | "
                    "ForEach-Object { Remove-NetRoute -InputObject $_ "
                    "-Confirm:$false -ErrorAction Stop }"
                )
        for path in self._paths.values():
            index = path.if_index or self._interface_index(path.interface_name)
            self._powershell(
                f"Get-NetRoute -InterfaceIndex {index} -AddressFamily IPv4 "
                "-ErrorAction SilentlyContinue | "
                f"Where-Object {{ $_.DestinationPrefix -eq '{self.relay_ip}/32' "
                " -and $_.RouteMetric -eq 1 } | "
                "ForEach-Object { Remove-NetRoute -InputObject $_ "
                "-Confirm:$false -ErrorAction Stop }"
            )

    def _allocate_linux_ids(self) -> Tuple[int, int]:
        rules = self._run("ip", "-4", "rule", "show").stdout
        priorities = {
            int(match) for match in re.findall(r"^\s*(\d+):", rules, re.MULTILINE)
        }
        tables = {
            int(match) for match in re.findall(r"\b(?:lookup|table)\s+(\d+)\b", rules)
        }
        priority = next((p for p in range(10000, 30000) if p not in priorities), None)
        if priority is None:
            raise RuntimeError("No free IPv4 policy-rule priority is available")

        for table in range(20000, 30000):
            if table in tables:
                continue
            result = subprocess.run(
                ["ip", "-4", "route", "show", "table", str(table)],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and not result.stdout.strip():
                return table, priority
        raise RuntimeError("No unused IPv4 routing table is available")

    def _interface_index(self, interface_name: str) -> int:
        if self.system == "Windows":
            escaped_name = interface_name.replace("'", "''")
            value = self._powershell(
                f"(Get-NetAdapter -Name '{escaped_name}' -ErrorAction Stop).ifIndex"
            )
            try:
                index = int(value)
            except ValueError as e:
                raise RuntimeError(
                    f"Could not determine interface index for {interface_name}: {value!r}"
                ) from e
            if index <= 0:
                raise RuntimeError(f"Invalid interface index for {interface_name}: {index}")
            return index
        try:
            index = socket.if_nametoindex(interface_name)
        except OSError as e:
            raise RuntimeError(f"Could not determine interface index for {interface_name}") from e
        if index <= 0:
            raise RuntimeError(f"Invalid interface index for {interface_name}: {index}")
        return index

    def _windows_dns(self, interface_index: int) -> List[str]:
        raw = self._powershell(
            f"$a = @((Get-DnsClientServerAddress -InterfaceIndex {interface_index} "
            "-AddressFamily IPv4).ServerAddresses); ConvertTo-Json -InputObject $a -Compress"
        )
        if not raw:
            return []
        values = json.loads(raw)
        if values is None:
            return []
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            raise RuntimeError(f"Unexpected Windows DNS server data: {values!r}")
        return [str(ipaddress.IPv4Address(value)) for value in values if value]

    def _resolvectl_values(self, setting: str, interface_name: str) -> List[str]:
        output = self._run("resolvectl", setting, interface_name).stdout.strip()
        if not output:
            return []
        _, separator, values = output.partition(":")
        if not separator:
            raise RuntimeError(f"Unexpected resolvectl {setting} output: {output}")
        return values.split()

    def _restore_linux_resolver(
        self, interface_name: str, dns_servers: List[str], domains: List[str]
    ) -> None:
        self._run("resolvectl", "revert", interface_name)
        if dns_servers:
            self._run("resolvectl", "dns", interface_name, *dns_servers)
        if domains:
            self._run("resolvectl", "domain", interface_name, *domains)

    def _restore_windows_dns(self, interface_index: int, servers: List[str]) -> None:
        if not servers:
            self._powershell(
                f"Set-DnsClientServerAddress -InterfaceIndex {interface_index} "
                "-ResetServerAddresses"
            )
            return
        values = ",".join(f"'{server}'" for server in servers)
        self._powershell(
            f"Set-DnsClientServerAddress -InterfaceIndex {interface_index} "
            f"-ServerAddresses @({values})"
        )

    def _powershell(self, script: str) -> str:
        return self._run(
            system_executable(
                "WindowsPowerShell", "v1.0", "powershell.exe",
            ),
            "-NoProfile", "-NonInteractive", "-Command", script,
        ).stdout.strip()

    def _run(self, *command: str):
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"{' '.join(command)} failed: {detail}")
        return result

    def _clear_path_routes(self) -> None:
        actions = [
            action
            for group in self._path_cleanups.values()
            for action in group
        ] + self._retired_path_cleanups
        errors = self._cleanup_actions(actions)
        failed_actions = {id(action) for action, _ in errors}
        self._path_cleanups = {
            key: [action for action in group if id(action) in failed_actions]
            for key, group in self._path_cleanups.items()
            if any(id(action) in failed_actions for action in group)
        }
        self._retired_path_cleanups = [
            action for action in self._retired_path_cleanups
            if id(action) in failed_actions
        ]
        if errors:
            raise RuntimeError(f"Could not restore a relay route: {errors[0][1]}")

    def _cleanup_path_map(
        self, path_map: Dict[Tuple[str, str], List[Callable[[], None]]]
    ) -> None:
        for actions in path_map.values():
            errors = self._cleanup_actions(actions)
            if errors:
                self._retired_path_cleanups.extend(action for action, _ in errors)
                logger.error("Could not roll back a path route: %s", errors[0][1])
        path_map.clear()

    def _run_cleanups(self) -> None:
        errors = self._cleanup_actions(self._cleanups)
        failed_actions = {id(action) for action, _ in errors}
        self._cleanups = [
            action for action in self._cleanups if id(action) in failed_actions
        ]
        if errors:
            raise RuntimeError(f"Could not restore tunnel network settings: {errors[0][1]}")

    @staticmethod
    def _cleanup_actions(
        actions: List[Callable[[], None]],
    ) -> List[Tuple[Callable[[], None], Exception]]:
        errors = []
        for action in reversed(actions):
            try:
                action()
            except Exception as e:
                errors.append((action, e))
        return errors
