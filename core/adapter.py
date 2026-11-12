"""
Network Adapter Discovery & Telemetry Engine
Identifies physical network interfaces (Wi-Fi, Ethernet, Cellular, USB Hotspots)
and tracks real-time throughput, MTU, IP, and adapter states.
"""

import os
import socket
import psutil
import time
import subprocess
import platform
from typing import Dict, List, Optional

class NetworkAdapter:
    def __init__(self, name: str, ip: str, is_wifi: bool = False, is_cellular: bool = False, description: str = ""):
        self.name: str = name
        self.ip: str = ip
        self.description: str = description
        self.is_wifi: bool = is_wifi
        self.is_cellular: bool = is_cellular
        self.enabled: bool = True
        self.priority: int = 1  # 1 = Normal/Primary, 2 = Secondary, 0 = Backup
        self.weight: float = 1.0  # Dynamic traffic weighting for speed bonding
        
        # Real-time metrics
        self.latency_ms: float = 0.0
        self.jitter_ms: float = 0.0
        self.loss_pct: float = 0.0
        self.status: str = "Active"  # "Active", "Degraded", "Disconnected", "Testing"
        
        # Live Throughput Tracking
        self.bytes_sent: int = 0
        self.bytes_recv: int = 0
        self.last_check_time: float = time.time()
        self.upload_speed_bps: float = 0.0
        self.download_speed_bps: float = 0.0
        
        # Total aggregated session bytes
        self.total_tx_bytes: int = 0
        self.total_rx_bytes: int = 0
        
        # Speed history for sliding-window smoothing — initialized here to survive adapter rescans
        self._speed_hist_up: list = []
        self._speed_hist_down: list = []
        self._last_sys_tx: Optional[int] = None
        self._last_sys_rx: Optional[int] = None

    def update_rates(self):
        """Reads per-NIC byte counters from psutil and updates smoothed speed estimates.
        Uses a 5-sample sliding window with outlier (spike) trimming.
        History is preserved across adapter rescans because it's initialized in __init__.
        """
        now = time.time()
        elapsed = now - self.last_check_time
        if elapsed < 0.5:
            # Don't update more often than every 0.5s to avoid noise from tiny deltas
            return
        
        nic_counters = psutil.net_io_counters(pernic=True)
        stats = nic_counters.get(self.name)
        
        if stats:
            sys_tx = stats.bytes_sent
            sys_rx = stats.bytes_recv
            
            if self._last_sys_tx is not None and self._last_sys_rx is not None:
                delta_tx = max(0, sys_tx - self._last_sys_tx)
                delta_rx = max(0, sys_rx - self._last_sys_rx)
                
                # Guard against counter resets (e.g. NIC reconnect) — skip that sample
                max_plausible_bytes = 1_250_000_000 * elapsed  # 10 Gbps max
                if delta_tx > max_plausible_bytes or delta_rx > max_plausible_bytes:
                    # Counter likely reset; just update baseline and skip this sample
                    self._last_sys_tx = sys_tx
                    self._last_sys_rx = sys_rx
                    self.last_check_time = now
                    return
                
                instant_up_bps   = (delta_tx * 8.0) / elapsed
                instant_down_bps = (delta_rx * 8.0) / elapsed
                
                self._speed_hist_up.append(instant_up_bps)
                self._speed_hist_down.append(instant_down_bps)
                
                # Sliding window: keep last 6 samples (~3 seconds at 0.5s intervals)
                self._speed_hist_up   = self._speed_hist_up[-6:]
                self._speed_hist_down = self._speed_hist_down[-6:]
                
                self.upload_speed_bps   = self._smooth(self._speed_hist_up)
                self.download_speed_bps = self._smooth(self._speed_hist_down)
                
                self.total_tx_bytes += delta_tx
                self.total_rx_bytes += delta_rx
            
            self._last_sys_tx = sys_tx
            self._last_sys_rx = sys_rx
        
        self.last_check_time = now
    
    @staticmethod
    def _smooth(samples: list) -> float:
        """Median of samples — robust against isolated spikes."""
        if not samples:
            return 0.0
        if len(samples) == 1:
            return samples[0]
        s = sorted(samples)
        mid = len(s) // 2
        if len(s) % 2 == 1:
            return s[mid]
        return (s[mid - 1] + s[mid]) / 2.0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ip": self.ip,
            "description": self.description,
            "is_wifi": self.is_wifi,
            "is_cellular": self.is_cellular,
            "enabled": self.enabled,
            "priority": self.priority,
            "weight": round(self.weight, 2),
            "latency_ms": round(self.latency_ms, 1),
            "jitter_ms": round(self.jitter_ms, 1),
            "loss_pct": round(self.loss_pct, 1),
            "status": self.status,
            "upload_speed_mbps": round(self.upload_speed_bps / 1_000_000.0, 2),
            "download_speed_mbps": round(self.download_speed_bps / 1_000_000.0, 2),
            "total_tx_mb": round(self.total_tx_bytes / 1_000_000.0, 2),
            "total_rx_mb": round(self.total_rx_bytes / 1_000_000.0, 2),
        }


def get_windows_adapter_descriptions() -> Dict[str, str]:
    """Helper to retrieve detailed hardware driver descriptions from Windows Registry"""
    descs = {}
    if platform.system() != "Windows":
        return descs
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}')
        class_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}')
        i = 0
        while True:
            try:
                guid = winreg.EnumKey(key, i)
                i += 1
                try:
                    conn_key = winreg.OpenKey(key, rf'{guid}\Connection')
                    name, _ = winreg.QueryValueEx(conn_key, 'Name')
                    j = 0
                    desc = ''
                    while True:
                        try:
                            sub = winreg.EnumKey(class_key, j)
                            j += 1
                            sk = winreg.OpenKey(class_key, sub)
                            try:
                                inst_id, _ = winreg.QueryValueEx(sk, 'NetCfgInstanceId')
                                if inst_id.lower() == guid.lower():
                                    desc, _ = winreg.QueryValueEx(sk, 'DriverDesc')
                                    break
                            except FileNotFoundError: pass
                        except OSError: break
                    descs[name] = desc
                except (FileNotFoundError, OSError): pass
            except OSError: break
    except Exception:
        pass
    return descs


class AdapterManager:
    def __init__(self):
        self.adapters: Dict[str, NetworkAdapter] = {}
        self.refresh_adapters()

    def refresh_adapters(self) -> List[NetworkAdapter]:
        """Scans the operating system for usable IPv4 network interfaces"""
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        win_descs = get_windows_adapter_descriptions()
        
        ignored_keywords = [
            'loopback', 'wsl', 'veth', 'docker', 'hyper-v', 
            'virtual', 'vmware', 'vbox', 'wintun', 'tap', 'tun', 'npcap',
            'openvpn', 'vpn', 'wireguard', 'wan miniport', 'kernel debug',
            'ras async', 'zerotier', 'tailscale', 'hamachi', 'myspeedify'
        ]
        cellular_keywords = [
            'cellular', 'lte', 'mobile', 'rndis', 'remote ndis', 'samsung mobile',
            'apple mobile', 'iphone', 'android', 'usb ndis', 'usb ethernet', 'huawei',
            'zte', 'quectel', 'sierra', 'qualcomm', 'broadband', 'wwan', '5g', '4g', '3g'
        ]
        wifi_keywords = ['wi-fi', 'wifi', 'wlan', 'wireless', '802.11']

        found_ips = set()
        
        for iface_name, addrs in net_if_addrs.items():
            lower_name = iface_name.lower()
            desc = win_descs.get(iface_name, "")
            lower_desc = desc.lower()

            if any(k in lower_name or k in lower_desc for k in ignored_keywords):
                continue
                
            # Check if interface is up
            stats = net_if_stats.get(iface_name)
            if not stats or not stats.isup:
                continue

            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127.") and not addr.address.startswith("169.254."):
                    ip = addr.address
                    if ip in found_ips:
                        continue
                    found_ips.add(ip)
                    
                    is_wifi = any(k in lower_name or k in lower_desc for k in wifi_keywords)
                    is_cellular = any(k in lower_name or k in lower_desc for k in cellular_keywords)
                    
                    if ip not in self.adapters:
                        adapter = NetworkAdapter(
                            name=iface_name,
                            ip=ip,
                            is_wifi=is_wifi,
                            is_cellular=is_cellular,
                            description=desc
                        )
                        self.adapters[ip] = adapter
                    else:
                        self.adapters[ip].name = iface_name
                        self.adapters[ip].description = desc
                        self.adapters[ip].is_wifi = is_wifi
                        self.adapters[ip].is_cellular = is_cellular

        # Remove adapters that are no longer present
        for ip in list(self.adapters.keys()):
            if ip not in found_ips and ip != "127.0.0.2":
                del self.adapters[ip]

        # If running on local dev machine with only one primary interface, add a simulated secondary path
        # for bonding demonstration if only 1 physical NIC is found
        if len(self.adapters) == 1 and os.environ.get("MYSPEEDIFY_SIMULATE_PATHS", "0") == "1":
            primary_ip = list(self.adapters.keys())[0]
            sim_ip = "127.0.0.2"
            if sim_ip not in self.adapters:
                self.adapters[sim_ip] = NetworkAdapter(
                    name="Cellular / 5G Backup (Simulated)",
                    ip=primary_ip,  # uses primary route for UDP packets but distinct channel identifier
                    is_wifi=False,
                    is_cellular=True,
                    description="Simulated Secondary Multi-Path Connection"
                )

        return list(self.adapters.values())

    def get_adapter(self, ip: str) -> Optional[NetworkAdapter]:
        return self.adapters.get(ip)

    def get_active_adapters(self) -> List[NetworkAdapter]:
        return [a for a in self.adapters.values() if a.enabled]
