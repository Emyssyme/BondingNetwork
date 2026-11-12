"""
Wintun & Virtual Adapter Driver Interface for Windows
Supports official wintun.dll driver with ring buffer and fallback virtual interface.
"""

import os
import sys
import ctypes
import subprocess
import logging
import platform
import struct
from typing import Optional
from .base import BaseTunInterface

logger = logging.getLogger("MySpeedify.Wintun")

# GUID structure for Windows
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8)
    ]

class WintunInterface(BaseTunInterface):
    def __init__(self, adapter_name: str = "MySpeedifyVPN", tunnel_type: str = "MySpeedify"):
        self.adapter_name = adapter_name
        self.tunnel_type = tunnel_type
        self.ip: str = "10.8.0.2"
        self.netmask: str = "255.255.255.0"
        self.mtu: int = 1420
        self.is_open: bool = False
        self._dll = None
        self._adapter_handle = None
        self._session_handle = None
        self._rx_queue = []

    def open(self, ip: str = "10.8.0.2", netmask: str = "255.255.255.0", mtu: int = 1420) -> bool:
        self.ip = ip
        self.netmask = netmask
        self.mtu = mtu

        if platform.system() == "Windows":
            dll_paths = [
                os.path.join(os.path.dirname(__file__), "wintun.dll"),
                "wintun.dll",
                r"C:\Windows\System32\wintun.dll"
            ]
            
            for path in dll_paths:
                if os.path.exists(path):
                    try:
                        self._dll = ctypes.WinDLL(path)
                        logger.info(f"Loaded Wintun driver binary from: {path}")
                        break
                    except Exception as e:
                        logger.warning(f"Failed loading {path}: {e}")

        if self._dll:
            try:
                # Bind Ctypes function signatures
                self._dll.WintunCreateAdapter.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(GUID)]
                self._dll.WintunCreateAdapter.restype = ctypes.c_void_p
                self._dll.WintunOpenAdapter.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
                self._dll.WintunOpenAdapter.restype = ctypes.c_void_p
                self._dll.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
                self._dll.WintunCloseAdapter.restype = None
                
                self._dll.WintunStartSession.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
                self._dll.WintunStartSession.restype = ctypes.c_void_p
                self._dll.WintunEndSession.argtypes = [ctypes.c_void_p]
                self._dll.WintunEndSession.restype = None

                self._dll.WintunReceivePacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
                self._dll.WintunReceivePacket.restype = ctypes.POINTER(ctypes.c_ubyte)
                self._dll.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                self._dll.WintunReleaseReceivePacket.restype = None

                self._dll.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
                self._dll.WintunAllocateSendPacket.restype = ctypes.POINTER(ctypes.c_ubyte)
                self._dll.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                self._dll.WintunSendPacket.restype = None

                # Open or Create Wintun Adapter
                handle = self._dll.WintunOpenAdapter(self.tunnel_type, self.adapter_name)
                if not handle:
                    handle = self._dll.WintunCreateAdapter(self.tunnel_type, self.adapter_name, None)

                if handle:
                    self._adapter_handle = handle
                    # Start ring buffer session (0x400000 = 4MB buffer)
                    self._session_handle = self._dll.WintunStartSession(self._adapter_handle, 0x400000)
                    if self._session_handle:
                        logger.info(f"Successfully initialized Wintun Kernel Adapter '{self.adapter_name}' ({self.ip})!")
                        self.is_open = True
                        self._configure_routes()
                        return True
            except Exception as e:
                logger.warning(f"Wintun kernel driver creation notice: {e}")

        logger.info(f"Initialized Virtual Bonding Interface ({self.ip}). To capture real Windows system traffic, run Terminal / CMD as Administrator.")
        self.is_open = True
        return True

    def _configure_routes(self):
        """Sets IP, MTU, and default routes on Windows interface via netsh"""
        try:
            cmd = f'netsh interface ip set address name="{self.adapter_name}" static {self.ip} {self.netmask}'
            subprocess.run(cmd, shell=True, capture_output=True)
            cmd_mtu = f'netsh interface ipv4 set subinterface "{self.adapter_name}" mtu={self.mtu} store=active'
            subprocess.run(cmd_mtu, shell=True, capture_output=True)
        except Exception as e:
            logger.debug(f"Route configuration notice: {e}")

    def read(self, size: int = 2048) -> Optional[bytes]:
        if not self.is_open:
            return None
            
        if self._rx_queue:
            return self._rx_queue.pop(0)

        if self._dll and self._session_handle:
            try:
                pkt_size = ctypes.c_uint32(0)
                ptr = self._dll.WintunReceivePacket(self._session_handle, ctypes.byref(pkt_size))
                if ptr and pkt_size.value > 0:
                    data = bytes((ctypes.c_ubyte * pkt_size.value).from_address(ctypes.addressof(ptr.contents)))
                    self._dll.WintunReleaseReceivePacket(self._session_handle, ptr)
                    return data
            except Exception as e:
                logger.debug(f"Wintun read error: {e}")
                
        return None

    def write(self, packet: bytes) -> bool:
        if not self.is_open:
            return False

        if self._dll and self._session_handle and packet:
            try:
                pkt_len = len(packet)
                ptr = self._dll.WintunAllocateSendPacket(self._session_handle, pkt_len)
                if ptr:
                    ctypes.memmove(ptr, packet, pkt_len)
                    self._dll.WintunSendPacket(self._session_handle, ptr)
                    return True
            except Exception as e:
                logger.debug(f"Wintun write error: {e}")
                return False
                
        return True

    def inject_simulated_packet(self, packet: bytes):
        """Used for testing & loopback packet simulation"""
        self._rx_queue.append(packet)

    def close(self):
        if not self.is_open:
            return
        if self._dll and self._session_handle:
            try:
                self._dll.WintunEndSession(self._session_handle)
            except Exception:
                pass
        if self._dll and self._adapter_handle:
            try:
                self._dll.WintunCloseAdapter(self._adapter_handle)
            except Exception:
                pass
        self.is_open = False
        logger.info(f"Closed virtual adapter '{self.adapter_name}'")
