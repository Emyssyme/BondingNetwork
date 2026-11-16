import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from client.daemon import ClientDaemon
from core.secret import load_client_secrets, load_secret
from server.relay import RelayServer
from server.rotate_secret import rotate_secret_file


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

    def test_secret_rotation_reverts_file_and_restarts_old_service_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("previous-secret-value\n", encoding="utf-8")
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
                    secret_factory=lambda: "new-unique-secret-value",
                )

            self.assertEqual(path.read_text(encoding="utf-8"), "previous-secret-value\n")
            self.assertEqual(len(restart_calls), 2)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_secret_rotation_keeps_new_secret_after_successful_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("previous-secret-value\n", encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)
            restart_calls = []

            rotate_secret_file(
                path,
                restart_service=lambda: restart_calls.append(True),
                secret_factory=lambda: "new-unique-secret-value",
            )

            self.assertEqual(path.read_text(encoding="utf-8"), "new-unique-secret-value\n")
            self.assertEqual(restart_calls, [True])

    def test_secret_rotation_reports_failed_rollback_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("previous-secret-value\n", encoding="utf-8")
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
                    secret_factory=lambda: "new-unique-secret-value",
                )

            self.assertEqual(path.read_text(encoding="utf-8"), "previous-secret-value\n")

    def test_secret_rotation_refuses_insecure_existing_file(self):
        if os.name != "posix":
            self.skipTest("POSIX file mode validation only")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("previous-secret-value\n", encoding="utf-8")
            path.chmod(0o640)

            with self.assertRaisesRegex(PermissionError, "group/others"):
                rotate_secret_file(path, lambda: None)

    def test_secret_rotation_refuses_symbolic_link(self):
        if os.name != "posix":
            self.skipTest("POSIX symbolic-link validation only")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            path = Path(directory) / "secret"
            target.write_text("previous-secret-value\n", encoding="utf-8")
            target.chmod(0o600)
            path.symlink_to(target)

            with self.assertRaisesRegex(PermissionError, "regular, non-symlink"):
                rotate_secret_file(path, lambda: None)


if __name__ == "__main__":
    unittest.main()
