"""
Virtual Network Interface Base Layer
"""

from abc import ABC, abstractmethod
from typing import Optional

class BaseTunInterface(ABC):
    @abstractmethod
    def open(self, ip: str = "10.8.0.2", netmask: str = "255.255.255.0", mtu: int = 1420) -> bool:
        """Initializes and activates the TUN device"""
        pass

    @abstractmethod
    def read(self, size: int = 2048) -> Optional[bytes]:
        """Reads a single raw IP packet from the OS network stack"""
        pass

    @abstractmethod
    def write(self, packet: bytes) -> bool:
        """Injects a raw IP packet into the OS network stack"""
        pass

    @abstractmethod
    def close(self):
        """Tears down the virtual interface and restores routing"""
        pass
