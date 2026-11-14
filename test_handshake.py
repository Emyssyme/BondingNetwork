"""Tests for the v2 handshake/crypto. Replaces test_crypto_aead in tests/test_core.py."""
import time
import unittest
from unittest import mock

from cryptography.exceptions import InvalidTag

from core.crypto_v2 import derive_psk
from core.handshake import ClientHandshake, parse_init, parse_init_client_id, build_resp

SECRET = "unit-test-secret-0123456789"


def _session(sid=4242, secret=SECRET):
    psk = derive_psk(secret)
    cl = ClientHandshake(psk, sid)
    cpub, cnonce = parse_init(psk, sid, cl.build_init())
    payload, srv = build_resp(psk, sid, cpub, cnonce, "10.8.0.2")
    crypto, ip = cl.process_resp(payload)
    return crypto, srv, ip


class TestHandshake(unittest.TestCase):
    def test_roundtrip_both_directions_with_aad(self):
        cli, srv, ip = _session()
        self.assertEqual(ip, "10.8.0.2")
        aad = b"H" * 20
        ct = cli.encrypt(b"uplink", 1, 1, 0x10, aad)
        self.assertEqual(srv.decrypt(ct, 1, 1, 0x10, aad), b"uplink")
        ct = srv.encrypt(b"downlink", 1, 1, 0x10, aad)
        self.assertEqual(cli.decrypt(ct, 1, 1, 0x10, aad), b"downlink")

    def test_directions_use_different_keys_same_nonce_fields(self):
        cli, srv, _ = _session()
        aad = b"H" * 20
        self.assertNotEqual(cli.encrypt(b"x" * 16, 7, 1, 0x10, aad),
                            srv.encrypt(b"x" * 16, 7, 1, 0x10, aad))

    def test_header_tampering_detected(self):
        cli, srv, _ = _session()
        ct = cli.encrypt(b"data", 1, 1, 0x10, b"A" * 20)
        with self.assertRaises(InvalidTag):
            srv.decrypt(ct, 1, 1, 0x10, b"B" * 20)

    def test_path_seq_type_bound_to_nonce(self):
        cli, srv, _ = _session()
        ct = cli.encrypt(b"data", 5, 1, 0x10, b"")
        for args in ((6, 1, 0x10), (5, 2, 0x10), (5, 1, 0x20)):
            with self.assertRaises(InvalidTag):
                srv.decrypt(ct, *args, b"")

    def test_new_session_new_keys(self):
        a, _, _ = _session()
        b, _, _ = _session()
        self.assertNotEqual(a.encrypt(b"same", 1, 1, 0x10, b""), b.encrypt(b"same", 1, 1, 0x10, b""))

    def test_wrong_secret_rejected(self):
        cl = ClientHandshake(derive_psk(SECRET), 1)
        self.assertIsNone(parse_init(derive_psk("another-secret-0123456789"), 1, cl.build_init()))

    def test_init_bound_to_session_id_and_stale_rejected(self):
        psk = derive_psk(SECRET)
        init = ClientHandshake(psk, 1).build_init()
        self.assertIsNone(parse_init(psk, 2, init))
        with mock.patch("core.handshake.time.time", return_value=time.time() + 3600):
            self.assertIsNone(parse_init(psk, 1, init))

    def test_client_identity_is_included_in_authenticated_init(self):
        psk = derive_psk(SECRET)
        client = ClientHandshake(psk, 1, client_id="alice")
        init = client.build_init()

        self.assertEqual(parse_init_client_id(init), "alice")
        parsed = parse_init(psk, 1, init)
        if parsed is None:
            self.fail("Per-client INIT failed authentication")
        self.assertIsNone(parse_init(derive_psk("different-client-secret"), 1, init))
        tampered = b"\x05alixe" + init[6:]
        self.assertIsNone(parse_init(psk, 1, tampered))
        cpub, cnonce = parsed
        response, server_crypto = build_resp(psk, 1, cpub, cnonce, "10.8.0.2")
        processed = client.process_resp(response)
        if processed is None:
            self.fail("Per-client handshake response failed authentication")
        client_crypto, tunnel_ip = processed
        self.assertEqual(tunnel_ip, "10.8.0.2")
        aad = b"H" * 20
        ciphertext = client_crypto.encrypt(b"client data", 1, 1, 0x10, aad)
        self.assertEqual(
            server_crypto.decrypt(ciphertext, 1, 1, 0x10, aad),
            b"client data",
        )

    def test_legacy_init_has_no_client_identity(self):
        init = ClientHandshake(derive_psk(SECRET), 1).build_init()

        self.assertIsNone(parse_init_client_id(init))
        self.assertIsNotNone(parse_init(derive_psk(SECRET), 1, init))

    def test_short_secret_refused(self):
        with self.assertRaises(ValueError):
            derive_psk("short")


if __name__ == "__main__":
    unittest.main()
