"""
Cryptography & Tunnel Security Engine (v2)

ChaCha20-Poly1305 AEAD with:
  * per-session, per-direction keys (derived in core/handshake.py, never from the passphrase alone)
  * nonce = direction(1) | path_id(1) | packet_type(1) | 0(1) | seq(8)  -> unique per key
  * the 20-byte packet header is authenticated as AAD (session_id, type, flags, path, seq)
"""

import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DIR_C2S = 0
DIR_S2C = 1
_NONCE_FMT = "!BBBBQ"  # 12 bytes
MIN_SECRET_LEN = 16


def derive_psk(secret: str) -> bytes:
    """Stretches the shared secret into a 32-byte pre-shared key (authenticates the handshake)."""
    if not secret or len(secret) < MIN_SECRET_LEN:
        raise ValueError(f"Secret must be at least {MIN_SECRET_LEN} characters")
    kdf = Scrypt(salt=b"myspeedify-psk-v2", length=32, n=2 ** 15, r=8, p=1)
    return kdf.derive(secret.encode("utf-8"))


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
