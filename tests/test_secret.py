import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from daemon import ClientDaemon
from core.secret import load_client_secrets, load_secret
from relay import RelayServer
from server.rotate_secret import rotate_secret_file


class TestSecretLoading(unittest.TestCase):
    def test_reads_secret_file_and_strips_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n", encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)

            self.assertEqual(load_secret(str(path)), "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")

    def test_rejects_legacy_passphrase_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("weak-passphrase", encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "32-byte URL-safe base64"):
                load_secret(str(path))

    def test_rejects_secret_file_accessible_to_group_or_others(self):
        if os.name != "posix":
            self.skipTest("POSIX file mode validation only")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", encoding="utf-8")
            path.chmod(0o640)

            with self.assertRaisesRegex(PermissionError, "chmod 600"):
                load_secret(str(path))

    def test_rejects_symbolic_link_secret_file(self):
        if os.name != "posix":
            self.skipTest("POSIX symbolic-link validation only")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            link = Path(directory) / "secret"
            target.write_text("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", encoding="utf-8")
            target.chmod(0o600)
            link.symlink_to(target)

            with self.assertRaisesRegex(PermissionError, "symbolic link"):
                load_secret(str(link))

    def test_reads_per_client_secret_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clients.json"
            path.write_text(
                '{"alice":"QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8",'
                '"bob":"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8"}',
                encoding="utf-8",
            )
            if os.name == "posix":
                path.chmod(0o600)

            self.assertEqual(
                load_client_secrets(str(path)),
                {
                    "alice": "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8",
                    "bob": "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8",
                },
            )

    def test_rejects_invalid_per_client_secret_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clients.json"
            path.write_text('{"bad id":"gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8"}', encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "client ID"):
                load_client_secrets(str(path))

    def test_rejects_reused_per_client_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clients.json"
            path.write_text(
                '{"alice":"QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8",'
                '"bob":"QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"}',
                encoding="utf-8",
            )
            if os.name == "posix":
                path.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "unique"):
                load_client_secrets(str(path))

    def test_rejects_non_random_format_per_client_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clients.json"
            path.write_text('{"alice":"short"}', encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "32-byte URL-safe base64"):
                load_client_secrets(str(path))

    def test_runtime_components_require_a_configured_secret(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "32-byte URL-safe base64"):
                ClientDaemon()
            with self.assertRaisesRegex(ValueError, "random 256-bit relay secret"):
                RelayServer()

    def test_secret_rotation_reverts_file_and_restarts_old_service_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n", encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)
            restart_errors = [RuntimeError("new secret startup failed"), None]
            restart_calls = []

            def restart_service():
                restart_calls.append(True)
                error = restart_errors.pop(0)
                if error is not None:
                    raise error

            with self.assertRaisesRegex(
                RuntimeError,
                "previous secret was restored and the relay restarted",
            ):
                rotate_secret_file(
                    path,
                    restart_service,
                    secret_factory=lambda: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
                )

            self.assertEqual(path.read_text(encoding="utf-8"), "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n")
            self.assertEqual(len(restart_calls), 2)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_secret_rotation_keeps_new_secret_after_successful_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n", encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)
            restart_calls = []

            rotate_secret_file(
                path,
                restart_service=lambda: restart_calls.append(True),
                secret_factory=lambda: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            )

            self.assertEqual(path.read_text(encoding="utf-8"), "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\n")
            self.assertEqual(restart_calls, [True])

    def test_secret_rotation_refuses_invalid_generated_key_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            previous = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n"
            path.write_text(previous, encoding="utf-8")
            restart_calls = []

            with self.assertRaisesRegex(ValueError, "canonical 32-byte"):
                rotate_secret_file(
                    path,
                    restart_service=lambda: restart_calls.append(True),
                    secret_factory=lambda: "too-weak",
                )

            self.assertEqual(path.read_text(encoding="utf-8"), previous)
            self.assertEqual(restart_calls, [])

    def test_secret_rotation_reports_failed_rollback_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n", encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)

            def restart_service():
                raise RuntimeError("service unavailable")

            with self.assertRaisesRegex(
                RuntimeError,
                "previous secret was restored, but its restart also failed",
            ):
                rotate_secret_file(
                    path,
                    restart_service,
                    secret_factory=lambda: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
                )

            self.assertEqual(path.read_text(encoding="utf-8"), "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n")

    def test_secret_rotation_refuses_insecure_existing_file(self):
        if os.name != "posix":
            self.skipTest("POSIX file mode validation only")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n", encoding="utf-8")
            path.chmod(0o640)

            with self.assertRaisesRegex(PermissionError, "group/others"):
                rotate_secret_file(path, lambda: None)

    def test_secret_rotation_refuses_symbolic_link(self):
        if os.name != "posix":
            self.skipTest("POSIX symbolic-link validation only")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            path = Path(directory) / "secret"
            target.write_text("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n", encoding="utf-8")
            target.chmod(0o600)
            path.symlink_to(target)

            with self.assertRaisesRegex(PermissionError, "regular, non-symlink"):
                rotate_secret_file(path, lambda: None)


if __name__ == "__main__":
    unittest.main()
