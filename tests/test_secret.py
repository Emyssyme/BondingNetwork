import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from client.daemon import ClientDaemon
from core.secret import load_client_secrets, load_secret
from server.relay import RelayServer


class TestSecretLoading(unittest.TestCase):
    def test_reads_secret_file_and_strips_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("test-only-secret-value\n", encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)

            self.assertEqual(load_secret(str(path)), "test-only-secret-value")

    def test_rejects_secret_file_accessible_to_group_or_others(self):
        if os.name != "posix":
            self.skipTest("POSIX file mode validation only")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("test-only-secret-value", encoding="utf-8")
            path.chmod(0o640)

            with self.assertRaisesRegex(PermissionError, "chmod 600"):
                load_secret(str(path))

    def test_rejects_symbolic_link_secret_file(self):
        if os.name != "posix":
            self.skipTest("POSIX symbolic-link validation only")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            link = Path(directory) / "secret"
            target.write_text("test-only-secret-value", encoding="utf-8")
            target.chmod(0o600)
            link.symlink_to(target)

            with self.assertRaisesRegex(PermissionError, "symbolic link"):
                load_secret(str(link))

    def test_reads_per_client_secret_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clients.json"
            path.write_text(
                '{"alice":"alice-test-secret-0123456789",'
                '"bob":"bob-test-secret-0123456789"}',
                encoding="utf-8",
            )
            if os.name == "posix":
                path.chmod(0o600)

            self.assertEqual(
                load_client_secrets(str(path)),
                {
                    "alice": "alice-test-secret-0123456789",
                    "bob": "bob-test-secret-0123456789",
                },
            )

    def test_rejects_invalid_per_client_secret_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clients.json"
            path.write_text('{"bad id":"client-secret-0123456789"}', encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "client ID"):
                load_client_secrets(str(path))

    def test_rejects_reused_per_client_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clients.json"
            path.write_text(
                '{"alice":"same-client-secret-0123456789",'
                '"bob":"same-client-secret-0123456789"}',
                encoding="utf-8",
            )
            if os.name == "posix":
                path.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "unique"):
                load_client_secrets(str(path))

    def test_runtime_components_require_a_configured_secret(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "passphrase is required"):
                ClientDaemon()
            with self.assertRaisesRegex(ValueError, "passphrase is required"):
                RelayServer()


if __name__ == "__main__":
    unittest.main()
