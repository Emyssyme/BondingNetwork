"""
Wintun driver interface for Windows (real data-plane).

Requires wintun.dll (amd64/x86/arm64 build from wintun.net) placed next to this file,
and an elevated (Administrator) process. The DLL is loaded ONLY from this directory
(no PATH / CWD search -> no DLL planting).

Set MYSPEEDIFY_DEV=1 to get an in-memory loopback instead (UI demo / tests only).
"""

import ctypes
import logging
import os
import platform
import subprocess
import time
from ctypes import wintypes
from typing import Optional

from .base import BaseTunInterface

logger = logging.getLogger("MySpeedify.Wintun")

_RING_CAPACITY = 0x400000  # 4 MiB


class WintunInterface(BaseTunInterface):
    def __init__(self, adapter_name: str = "MySpeedifyVPN", tunnel_type: str = "MySpeedify"):
        self.adapter_name = adapter_name
        self.tunnel_type = tunnel_type
        self.ip = "10.8.0.2"
        self.netmask = "255.255.255.0"
        self.mtu = 1380
        self.is_open = False
        self._dll = None
        self._adapter = None
        self._session = None
        self._loopback = False
        self._rx_queue: list = []

    # ------------------------------------------------------------------ setup
    def _load_dll(self):
        if platform.system() != "Windows":
            return None
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wintun.dll")
        if not os.path.exists(path):
            return None
        d = ctypes.WinDLL(path, use_last_error=True)
        vp = ctypes.c_void_p
        d.WintunCreateAdapter.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, vp]
        d.WintunCreateAdapter.restype = vp
        d.WintunCloseAdapter.argtypes = [vp]
        d.WintunCloseAdapter.restype = None
        d.WintunStartSession.argtypes = [vp, wintypes.DWORD]
        d.WintunStartSession.restype = vp
        d.WintunEndSession.argtypes = [vp]
        d.WintunEndSession.restype = None
        d.WintunReceivePacket.argtypes = [vp, ctypes.POINTER(wintypes.DWORD)]
        d.WintunReceivePacket.restype = vp
        d.WintunReleaseReceivePacket.argtypes = [vp, vp]
        d.WintunReleaseReceivePacket.restype = None
        d.WintunAllocateSendPacket.argtypes = [vp, wintypes.DWORD]
        d.WintunAllocateSendPacket.restype = vp
        d.WintunSendPacket.argtypes = [vp, vp]
        d.WintunSendPacket.restype = None
        return d

    def open(self, ip: str = "10.8.0.2", netmask: str = "255.255.255.0", mtu: int = 1380) -> bool:
        self.ip, self.netmask, self.mtu = ip, netmask, mtu
        self._dll = self._load_dll()

        if self._dll is None:
            if os.environ.get("MYSPEEDIFY_DEV") == "1":
                logger.warning("wintun.dll unavailable: DEV loopback interface (no real traffic)")
                self._loopback = True
                self.is_open = True
                return True
            raise RuntimeError("wintun.dll not found next to core/tun/wintun.py (or not running on Windows)")

        self._adapter = self._dll.WintunCreateAdapter(self.adapter_name, self.tunnel_type, None)
        if not self._adapter:
            raise ctypes.WinError(ctypes.get_last_error())  # usually: not running as Administrator
        self._session = self._dll.WintunStartSession(self._adapter, _RING_CAPACITY)
        if not self._session:
            err = ctypes.WinError(ctypes.get_last_error())
            self._dll.WintunCloseAdapter(self._adapter)
            self._adapter = None
            raise err
        self.is_open = True
        try:
            self._configure()
        except Exception:
            self.close()
            raise
        logger.info("Wintun adapter '%s' up: %s mtu=%d", self.adapter_name, ip, mtu)
        return True

    def _configure(self):
        addr_cmd = ["netsh", "interface", "ip", "set", "address",
                    f"name={self.adapter_name}", "static", self.ip, self.netmask]
        last = None
        for _ in range(10):  # the adapter can take a moment to be visible to netsh
            last = subprocess.run(addr_cmd, capture_output=True, text=True)
            if last.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError(f"netsh set address failed: {last.stdout.strip()} {last.stderr.strip()}")
        subprocess.run(["netsh", "interface", "ipv4", "set", "subinterface", self.adapter_name,
                        f"mtu={self.mtu}", "store=active"], capture_output=True)

    # --------------------------------------------------------------------- I/O
    def read(self, size: int = 2048) -> Optional[bytes]:
        if not self.is_open:
            return None
        if self._loopback:
            return self._rx_queue.pop(0) if self._rx_queue else None
        n = wintypes.DWORD(0)
        ptr = self._dll.WintunReceivePacket(self._session, ctypes.byref(n))
        if not ptr:
            return None  # ERROR_NO_MORE_ITEMS: nothing to read
        data = ctypes.string_at(ptr, n.value)
        self._dll.WintunReleaseReceivePacket(self._session, ptr)
        return data

    def write(self, packet: bytes) -> bool:
        if not self.is_open:
            return False
        if self._loopback:
            return True
        ptr = self._dll.WintunAllocateSendPacket(self._session, len(packet))
        if not ptr:
            return False  # ring buffer full
        ctypes.memmove(ptr, packet, len(packet))
        self._dll.WintunSendPacket(self._session, ptr)
        return True

    def inject_simulated_packet(self, packet: bytes):
        """DEV only (UI traffic simulation)."""
        if self._loopback:
            self._rx_queue.append(packet)

    def close(self):
        if not self.is_open:
            return
        self.is_open = False
        if self._dll:
            if self._session:
                self._dll.WintunEndSession(self._session)
                self._session = None
            if self._adapter:
                self._dll.WintunCloseAdapter(self._adapter)
                self._adapter = None
        logger.info("Closed virtual adapter '%s'", self.adapter_name)
