"""
Cryptography & Tunnel Security Engine
Uses ChaCha20-Poly1305 AEAD (RFC 8439) for ultra-low-overhead authenticated encryption.
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class TunnelCrypto:
    def __init__(self, key: bytes = None, use_aes: bool = False):
        """
        Initializes tunnel encryption engine.
        Key must be 32 bytes (256 bits). If None, generates a random key.
        """
        if key is None:
            self.key = os.urandom(32)
        else:
            if len(key) != 32:
                raise ValueError("Key must be exactly 32 bytes (256 bits)")
            self.key = key
            
        self.use_aes = use_aes
        if self.use_aes:
            self.cipher = AESGCM(self.key)
        else:
            self.cipher = ChaCha20Poly1305(self.key)

    @classmethod
    def from_passphrase(cls, passphrase: str, salt: bytes = b'myspeedify_bonding_salt') -> 'TunnelCrypto':
        """Derives a 256-bit key from a user passphrase using HKDF-SHA256"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'myspeedify-tunnel-v1',
        )
        key = hkdf.derive(passphrase.encode('utf-8'))
        return cls(key=key)

    def _make_nonce(self, seq_num: int, path_id: int) -> bytes:
        """
        Constructs a unique 12-byte (96-bit) nonce using sequence number and path ID.
        Prevents nonce reuse.
        """
        # 8 bytes sequence number + 1 byte path_id + 3 bytes zero padding
        return struct.pack("!QBB2s", seq_num, path_id, 0, b'\x00\x00')

    def encrypt(self, plaintext: bytes, seq_num: int, path_id: int, associated_data: bytes = b'') -> bytes:
        """Encrypts plaintext with authenticated associated data (AAD)"""
        nonce = self._make_nonce(seq_num, path_id)
        return self.cipher.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, seq_num: int, path_id: int, associated_data: bytes = b'') -> bytes:
        """Decrypts and authenticates ciphertext. Raises InvalidTag if tampering occurred."""
        nonce = self._make_nonce(seq_num, path_id)
        return self.cipher.decrypt(nonce, ciphertext, associated_data)
