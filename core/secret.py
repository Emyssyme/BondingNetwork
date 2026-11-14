"""Loads the tunnel secret from the environment / a file. Never from source code or argv."""

import json
import os
import re
import stat

_CLIENT_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")


def is_valid_client_id(client_id: str) -> bool:
    return bool(_CLIENT_ID_PATTERN.fullmatch(client_id))


def _read_secret_file(path: str) -> str:
    if os.name == "posix":
        path_stat = os.lstat(path)
        if stat.S_ISLNK(path_stat.st_mode):
            raise PermissionError("Secret file must not be a symbolic link")
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or path_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        ):
            raise PermissionError(
                "Secret file must be regular and inaccessible to "
                "group/others (chmod 600)."
            )
        fd: int | None = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        try:
            file_stat = os.fstat(fd)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            ):
                raise PermissionError(
                    "Secret file must be regular and inaccessible to "
                    "group/others (chmod 600)."
                )
            stream = os.fdopen(fd, "r", encoding="utf-8")
            fd = None
            with stream:
                return stream.read()
        finally:
            if fd is not None:
                os.close(fd)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_secret(secret_file: str | None = None) -> str | None:
    path = secret_file or os.environ.get("MYSPEEDIFY_SECRET_FILE")
    if path:
        return _read_secret_file(path).strip() or None
    return os.environ.get("MYSPEEDIFY_SECRET") or None


def _unique_client_entries(pairs: list[tuple[str, object]]) -> dict[str, object]:
    entries: dict[str, object] = {}
    for client_id, secret in pairs:
        if client_id in entries:
            raise ValueError("Client secrets file contains a duplicate client ID")
        entries[client_id] = secret
    return entries


def load_client_secrets(secret_file: str | None = None) -> dict[str, str]:
    """Load per-client secrets from a protected JSON object keyed by client ID."""
    path = secret_file or os.environ.get("MYSPEEDIFY_CLIENT_SECRETS_FILE")
    if not path:
        return {}
    try:
        entries = json.loads(
            _read_secret_file(path),
            object_pairs_hook=_unique_client_entries,
        )
    except json.JSONDecodeError as exc:
        raise ValueError("Client secrets file must contain valid JSON") from exc
    if not isinstance(entries, dict) or not entries:
        raise ValueError("Client secrets file must contain a non-empty JSON object")
    secrets: dict[str, str] = {}
    seen_secrets: set[str] = set()
    for client_id, secret in entries.items():
        if not isinstance(client_id, str) or not is_valid_client_id(client_id):
            raise ValueError("Client secrets file contains an invalid client ID")
        if not isinstance(secret, str) or len(secret) < 16:
            raise ValueError("Each client secret must contain at least 16 characters")
        if secret in seen_secrets:
            raise ValueError("Each client must have a unique secret")
        seen_secrets.add(secret)
        secrets[client_id] = secret
    return secrets
