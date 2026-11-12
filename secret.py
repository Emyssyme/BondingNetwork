"""Loads the tunnel secret from the environment / a file. Never from source code or argv."""

import os
import stat
import logging

logger = logging.getLogger("MySpeedify.Secret")


def load_secret(secret_file: str | None = None) -> str | None:
    path = secret_file or os.environ.get("MYSPEEDIFY_SECRET_FILE")
    if path:
        try:
            if os.name == "posix" and os.stat(path).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                logger.warning("Secret file %s is accessible by group/others; run: chmod 600 %s", path, path)
        except OSError:
            pass
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip() or None
    return os.environ.get("MYSPEEDIFY_SECRET") or None
