"""
Per-Interface Socket Binding Engine
Enables independent UDP tunnel sockets bound directly to specific physical NICs,
bypassing the operating system's single default route table.
"""

import socket
import struct
import platform
import logging

logger = logging.getLogger("MySpeedify.SocketBind")

# Windows socket option constant for IP_UNICAST_IF
IP_UNICAST_IF = 31

def create_bound_udp_socket(local_ip: str = "0.0.0.0", port: int = 0, if_index: int = 0) -> socket.socket:
    """
    Creates a non-blocking UDP socket explicitly bound to a local IP/interface.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Enable address reuse
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Increase socket buffer sizes for high-throughput bonding (4MB buffers)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except Exception as e:
        logger.debug(f"Could not expand socket buffer: {e}")

    # Bind to local IP
    try:
        sock.bind((local_ip, port))
    except Exception as e:
        logger.warning(f"Failed to bind socket to {local_ip}:{port}: {e}")
        # Fallback to wildcard bind
        sock.bind(("0.0.0.0", 0))

    # Windows specific interface binding (IP_UNICAST_IF) if interface index is provided
    if platform.system() == "Windows" and if_index > 0:
        try:
            # IP_UNICAST_IF expects interface index in network byte order
            sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", if_index))
        except Exception as e:
            logger.debug(f"IP_UNICAST_IF failed on if_index {if_index}: {e}")

    sock.setblocking(False)
    return sock
