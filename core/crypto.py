"""
Cryptography & Tunnel Security Engine

ChaCha20-Poly1305 AEAD with:
  * per-session, per-direction keys (derived in core/handshake.py from a random 256-bit PSK)
  * nonce = direction(1) | path_id(1) | packet_type(1) | 0(1) | seq(8)  -> unique per key
  * the 20-byte packet header is authenticated as AAD (session_id, type, flags, path, seq)
"""

import base64
import binascii
import re
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

DIR_C2S = 0
DIR_S2C = 1
_NONCE_FMT = "!BBBBQ"  # 12 bytes
_SECRET_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def derive_psk(secret: str) -> bytes:
    """Decode a 256-bit URL-safe base64 secret; passphrases are not accepted."""
    if not isinstance(secret, str) or not _SECRET_PATTERN.fullmatch(secret):
        raise ValueError(
            "Secret must be a 32-byte URL-safe base64 value; generate one with "
            "secrets.token_urlsafe(32)"
        )
    try:
        key = base64.urlsafe_b64decode(secret + "=")
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Secret is not valid URL-safe base64") from exc
    if (
        len(key) != 32
        or base64.urlsafe_b64encode(key).decode("ascii").rstrip("=") != secret
    ):
        raise ValueError("Secret must encode exactly 32 bytes")
    return key


class TunnelCrypto:
    def __init__(self, send_key: bytes, recv_key: bytes, send_dir: int, recv_dir: int):
        if len(send_key) != 32 or len(recv_key) != 32:
            raise ValueError("Keys must be exactly 32 bytes")
        self._send = ChaCha20Poly1305(send_key)
        self._recv = ChaCha20Poly1305(recv_key)
        self._send_dir = send_dir
        self._recv_dir = recv_dir

    @staticmethod
    def _nonce(direction: int, path_id: int, ptype: int, seq: int) -> bytes:
        return struct.pack(_NONCE_FMT, direction, path_id & 0xFF, ptype & 0xFF, 0, seq)

    def encrypt(self, plaintext: bytes, seq: int, path_id: int, ptype: int, aad: bytes) -> bytes:
        return self._send.encrypt(self._nonce(self._send_dir, path_id, ptype, seq), plaintext, aad)

    def decrypt(self, ciphertext: bytes, seq: int, path_id: int, ptype: int, aad: bytes) -> bytes:
        """Raises cryptography.exceptions.InvalidTag on tampering / wrong key."""
        return self._recv.decrypt(self._nonce(self._recv_dir, path_id, ptype, seq), ciphertext, aad)
