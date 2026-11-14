"""
Per-Interface Socket Binding Engine
Enables independent UDP tunnel sockets bound directly to specific physical NICs,
bypassing the operating system's single default route table.
"""

import socket
import struct
import platform
import logging
from typing import Optional

logger = logging.getLogger("MySpeedify.SocketBind")

# Windows socket option constant for IP_UNICAST_IF
IP_UNICAST_IF = 31

def create_bound_udp_socket(
    local_ip: str = "0.0.0.0",
    port: int = 0,
    interface_name: Optional[str] = None,
    if_index: Optional[int] = None,
) -> socket.socket:
    """
    Creates a non-blocking UDP socket bound to a local address and physical interface.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        except OSError as e:
            logger.debug("Could not expand socket buffer: %s", e)

        system = platform.system()
        if system == "Windows":
            if if_index is None and interface_name:
                if_index = socket.if_nametoindex(interface_name)
            if (if_index is None or if_index <= 0) and local_ip != "0.0.0.0":
                raise OSError(f"Could not determine interface index for {interface_name!r}")
            if if_index is not None:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    IP_UNICAST_IF,
                    struct.pack("!I", if_index),
                )
        elif system == "Linux":
            if interface_name:
                option = getattr(socket, "SO_BINDTODEVICE", None)
                if option is None:
                    raise OSError("SO_BINDTODEVICE is unavailable on this Linux platform")
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    option,
                    interface_name.encode("utf-8") + b"\0",
                )
            elif local_ip != "0.0.0.0":
                raise OSError("interface_name is required to bind a socket to a local IP on Linux")
        elif interface_name or if_index is not None or local_ip != "0.0.0.0":
            raise OSError(f"Interface binding is not implemented on {system}")

        sock.bind((local_ip, port))
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise
