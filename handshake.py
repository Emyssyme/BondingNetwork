"""
Authenticated ephemeral X25519 handshake (PSK-authenticated, forward secret).

  INIT (client -> relay): client_pub(32) | client_nonce(16) | timestamp_ms(8) | MAC(32)
  RESP (relay -> client): server_pub(32) | server_nonce(16) | assigned_ip(4)  | MAC(32)

MAC = HMAC-SHA256(PSK, label | session_id | ...). The relay creates NO state before the INIT MAC
verifies. Session keys = HKDF(X25519 shared || PSK, salt = client_nonce || server_nonce), split in
two directional keys, so a new session never reuses a (key, nonce) pair.
"""

import hashlib
import hmac
import os
import socket
import struct
import time
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .crypto import TunnelCrypto, DIR_C2S, DIR_S2C

_INIT = struct.Struct("!32s16sQ")
_RESP = struct.Struct("!32s16s4s")
_MAC = 32
MAX_SKEW_MS = 300_000  # INIT timestamp tolerance (5 min)


def _pub(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _mac(psk: bytes, label: bytes, *parts: bytes) -> bytes:
    h = hmac.new(psk, label, hashlib.sha256)
    for p in parts:
        h.update(p)
    return h.digest()


def _exchange(priv: X25519PrivateKey, peer_pub: bytes) -> Optional[bytes]:
    try:
        return priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    except ValueError:
        return None


def _keys(psk: bytes, shared: bytes, cnonce: bytes, snonce: bytes, sid: int) -> Tuple[bytes, bytes]:
    okm = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=cnonce + snonce,
        info=b"msp-v2" + struct.pack("!I", sid),
    ).derive(shared + psk)
    return okm[:32], okm[32:]  # (client->server, server->client)


class ClientHandshake:
    def __init__(self, psk: bytes, session_id: int):
        self.psk = psk
        self.session_id = session_id
        self._priv = X25519PrivateKey.generate()
        self._pub = _pub(self._priv)
        self._nonce = os.urandom(16)

    def build_init(self) -> bytes:
        body = _INIT.pack(self._pub, self._nonce, int(time.time() * 1000))
        return body + _mac(self.psk, b"init", struct.pack("!I", self.session_id), body)

    def process_resp(self, payload: bytes) -> Optional[Tuple[TunnelCrypto, str]]:
        if len(payload) != _RESP.size + _MAC:
            return None
        body, mac = payload[:-_MAC], payload[-_MAC:]
        expected = _mac(self.psk, b"resp", struct.pack("!I", self.session_id), self._nonce, body)
        if not hmac.compare_digest(mac, expected):
            return None
        spub, snonce, ip = _RESP.unpack(body)
        shared = _exchange(self._priv, spub)
        if shared is None:
            return None
        c2s, s2c = _keys(self.psk, shared, self._nonce, snonce, self.session_id)
        return TunnelCrypto(c2s, s2c, DIR_C2S, DIR_S2C), socket.inet_ntoa(ip)


def parse_init(psk: bytes, session_id: int, payload: bytes) -> Optional[Tuple[bytes, bytes]]:
    """Relay side. Returns (client_pub, client_nonce) only if the MAC and timestamp are valid."""
    if len(payload) != _INIT.size + _MAC:
        return None
    body, mac = payload[:-_MAC], payload[-_MAC:]
    expected = _mac(psk, b"init", struct.pack("!I", session_id), body)
    if not hmac.compare_digest(mac, expected):
        return None
    cpub, cnonce, ts_ms = _INIT.unpack(body)
    if abs(int(time.time() * 1000) - ts_ms) > MAX_SKEW_MS:
        return None
    return cpub, cnonce


def build_resp(psk: bytes, session_id: int, cpub: bytes, cnonce: bytes,
               assigned_ip: str) -> Optional[Tuple[bytes, TunnelCrypto]]:
    priv = X25519PrivateKey.generate()
    shared = _exchange(priv, cpub)
    if shared is None:
        return None
    snonce = os.urandom(16)
    body = _RESP.pack(_pub(priv), snonce, socket.inet_aton(assigned_ip))
    mac = _mac(psk, b"resp", struct.pack("!I", session_id), cnonce, body)
    c2s, s2c = _keys(psk, shared, cnonce, snonce, session_id)
    return body + mac, TunnelCrypto(s2c, c2s, DIR_S2C, DIR_C2S)
