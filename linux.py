"""Linux TUN device (/dev/net/tun). Requires CAP_NET_ADMIN (root)."""

import fcntl
import logging
import os
import struct
import subprocess
from typing import Optional

from .base import BaseTunInterface

logger = logging.getLogger("MySpeedify.LinuxTun")

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


class LinuxTun(BaseTunInterface):
    def __init__(self, name: str = "msp0"):
        self.name = name
        self.fd: Optional[int] = None
        self.is_open = False

    def open(self, ip: str = "10.8.0.2", netmask: str = "255.255.255.0", mtu: int = 1380) -> bool:
        fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        try:
            fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH22x", self.name.encode(), IFF_TUN | IFF_NO_PI))
            prefix = sum(bin(int(o)).count("1") for o in netmask.split("."))
            subprocess.run(["ip", "addr", "replace", f"{ip}/{prefix}", "dev", self.name],
                           check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", "dev", self.name, "mtu", str(mtu), "up"],
                           check=True, capture_output=True)
        except Exception:
            os.close(fd)
            raise
        self.fd = fd
        self.is_open = True
        logger.info("TUN %s up: %s/%d mtu=%d", self.name, ip, prefix, mtu)
        return True

    def fileno(self) -> int:
        return self.fd

    def read(self, size: int = 2048) -> Optional[bytes]:
        if not self.is_open:
            return None
        try:
            return os.read(self.fd, max(size, 2048))
        except BlockingIOError:
            return None

    def write(self, packet: bytes) -> bool:
        if not self.is_open:
            return False
        try:
            os.write(self.fd, packet)
            return True
        except (BlockingIOError, OSError):
            return False

    def close(self):
        if self.is_open:
            self.is_open = False
            os.close(self.fd)
            logger.info("TUN %s closed", self.name)
