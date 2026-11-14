import platform
from .base import BaseTunInterface

TUN_MTU = 1380  # 1380 + 64 B tunnel overhead (20 hdr + 16 tag + 28 IP/UDP) = 1444 < 1492 (PPPoE)


def create_tun() -> BaseTunInterface:
    system = platform.system()
    if system == "Linux":
        from .linux import LinuxTun
        return LinuxTun(name="msp0")
    from .wintun_v2 import WintunInterface  # Windows (or dev loopback when MYSPEEDIFY_DEV=1)
    return WintunInterface()
