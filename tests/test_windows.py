import os
import unittest
from unittest.mock import patch

from core.windows import system_executable


class TestWindowsExecutablePath(unittest.TestCase):
    def test_windows_executable_is_resolved_under_system32(self):
        with patch("core.windows.os.name", "nt"), \
                patch.dict(os.environ, {"SystemRoot": r"C:\Windows"}):
            executable = system_executable("WindowsPowerShell", "v1.0", "powershell.exe")

        self.assertEqual(
            executable,
            os.path.join(r"C:\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        )

    def test_missing_system_root_fails_explicitly(self):
        with patch("core.windows.os.name", "nt"), \
                patch.dict(os.environ, {}, clear=True), \
                self.assertRaisesRegex(RuntimeError, "SystemRoot is not set"):
            system_executable("route.exe")


if __name__ == "__main__":
    unittest.main()
