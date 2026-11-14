"""Runtime routing, DNS, and IPv6 policy for the client TUN."""

import ipaddress
import json
import logging
import os
import platform
import re
import socket
import subprocess
import threading
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple

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

    def _install_linux(self) -> None:
        tun_name = self.tun.name
        comment = f"msp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
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
        rule_name = f"MySpeedify-IPv6-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._run(
            "netsh.exe", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=out", "action=block",
            "remoteip=::/0", "profile=any", "enable=yes",
        )
        self._cleanups.append(lambda: self._run(
            "netsh.exe", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        ))

        self._cleanups.append(self._clear_path_routes)
        for key, path in self._paths.items():
            self._path_cleanups[key] = self._install_windows_path(self.relay_ip, path)

        tun_index = self._interface_index(self.tun.adapter_name)
        for destination, mask in (
            ("0.0.0.0", "128.0.0.0"),
            ("128.0.0.0", "128.0.0.0"),
        ):
            self._run(
                "route.exe", "ADD", destination, "MASK", mask, "0.0.0.0",
                "IF", str(tun_index), "METRIC", "1",
            )
            self._cleanups.append(lambda dst=destination, msk=mask: self._run(
                "route.exe", "DELETE", dst, "MASK", msk, "0.0.0.0", "IF", str(tun_index),
            ))

        dns_before = self._windows_dns(tun_index)
        self._cleanups.append(lambda: self._restore_windows_dns(tun_index, dns_before))
        self._powershell(
            f"Set-DnsClientServerAddress -InterfaceIndex {tun_index} "
            f"-ServerAddresses '{self.dns_server}'"
        )

    def _install_path_route(self, relay_ip: str, path: PhysicalPath) -> List[Callable[[], None]]:
        if self.system == "Linux":
            return self._install_linux_path(relay_ip, path)
        if self.system == "Windows":
            return self._install_windows_path(relay_ip, path)
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
                    "table", str(table),
                )
                actions.append(lambda: self._run(
                    "ip", "-4", "route", "del", f"{relay_ip}/32",
                    "via", gateway, "dev", path.interface_name, "table", str(table),
                ))
            else:
                self._run(
                    "ip", "-4", "route", "add", f"{relay_ip}/32",
                    "dev", path.interface_name, "scope", "link", "table", str(table),
                )
                actions.append(lambda: self._run(
                    "ip", "-4", "route", "del", f"{relay_ip}/32",
                    "dev", path.interface_name, "table", str(table),
                ))
            self._run(
                "ip", "-4", "rule", "add", "priority", str(priority),
                "from", f"{path.local_ip}/32", "to", f"{relay_ip}/32",
                "table", str(table),
            )
            actions.append(lambda: self._run(
                "ip", "-4", "rule", "del", "priority", str(priority),
                "from", f"{path.local_ip}/32", "to", f"{relay_ip}/32",
                "table", str(table),
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
            "route.exe", "ADD", relay_ip, "MASK", "255.255.255.255",
            gateway, "IF", str(index), "METRIC", "1",
        )
        return [lambda: self._run(
            "route.exe", "DELETE", relay_ip, "MASK", "255.255.255.255",
            gateway, "IF", str(index),
        )]

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
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script,
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
