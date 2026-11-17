"""Safely rotate the Linux relay secret and restart its systemd service."""

import base64
import binascii
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

SECRET_DIR = Path("/etc/myspeedify")
SECRET_FILE = SECRET_DIR / "secret"
SERVICE = "myspeedify-server.service"
_SECRET_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def _validate_new_secret(secret: str) -> None:
    if not isinstance(secret, str) or not _SECRET_PATTERN.fullmatch(secret):
        raise ValueError("New secret must be a canonical 32-byte URL-safe base64 key")
    try:
        key = base64.urlsafe_b64decode(secret + "=")
    except (ValueError, binascii.Error) as exc:
        raise ValueError("New secret is not valid URL-safe base64") from exc
    if len(key) != 32 or base64.urlsafe_b64encode(key).decode("ascii").rstrip("=") != secret:
        raise ValueError("New secret must encode exactly 32 bytes")


def _read_existing_secret(path: Path) -> tuple[bytes, os.stat_result]:
    path_stat = path.lstat()
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
        raise PermissionError("Existing secret must be a regular, non-symlink file")
    if os.name == "posix" and path_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError("Existing secret must not be accessible to group/others")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        opened_stat = os.fstat(fd)
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or opened_stat.st_dev != path_stat.st_dev
            or opened_stat.st_ino != path_stat.st_ino
            or (
                os.name == "posix"
                and opened_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            )
        ):
            raise PermissionError("Secret file changed or is not securely accessible")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            contents = stream.read()
        if not contents.strip():
            raise ValueError("Existing secret file is empty")
        return contents, opened_stat
    finally:
        if fd >= 0:
            os.close(fd)


def _atomic_replace(
    path: Path,
    contents: bytes,
    mode: int,
    owner: tuple[int, int] | None,
) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        if owner is not None:
            os.chown(temporary_path, *owner)
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def rotate_secret_file(
    path: Path,
    restart_service: Callable[[], None],
    owner: tuple[int, int] | None = None,
    secret_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
) -> None:
    previous_secret, previous_stat = _read_existing_secret(path)
    new_secret_value = secret_factory()
    _validate_new_secret(new_secret_value)
    new_secret = (new_secret_value + "\n").encode("utf-8")
    _atomic_replace(path, new_secret, 0o600, owner)

    try:
        restart_service()
    except (OSError, RuntimeError, subprocess.SubprocessError) as restart_error:
        previous_owner = (previous_stat.st_uid, previous_stat.st_gid) if owner is not None else None
        try:
            _atomic_replace(
                path,
                previous_secret,
                stat.S_IMODE(previous_stat.st_mode),
                previous_owner,
            )
        except (OSError, RuntimeError, ValueError) as restore_error:
            raise RuntimeError(
                f"Relay restart with the new secret failed and the previous secret "
                f"could not be restored: {restore_error}"
            ) from restart_error
        try:
            restart_service()
        except (OSError, RuntimeError, subprocess.SubprocessError) as rollback_restart_error:
            raise RuntimeError(
                f"Relay restart with the new secret failed; the previous secret "
                f"was restored, but its restart also failed: {rollback_restart_error}"
            ) from restart_error
        raise RuntimeError(
            "Relay restart with the new secret failed; the previous secret was "
            "restored and the relay restarted"
        ) from restart_error


def _run_systemctl(action: str) -> None:
    result = subprocess.run(
        ["systemctl", action, SERVICE],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise RuntimeError(f"systemctl {action} failed: {detail}")


def main() -> int:
    if os.name != "posix" or os.geteuid() != 0:
        print("Run secret rotation with sudo/root.", file=sys.stderr)
        return 1

    try:
        directory_stat = SECRET_DIR.lstat()
        if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(directory_stat.st_mode):
            raise PermissionError("Secret directory must be a real directory, not a symlink")
        if directory_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError("Secret directory must not be writable by group/others")

        import pwd

        account = pwd.getpwnam("myspeedify")
        _run_systemctl("cat")
        rotate_secret_file(
            SECRET_FILE,
            restart_service=lambda: _run_systemctl("restart"),
            owner=(account.pw_uid, account.pw_gid),
        )
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, KeyError) as exc:
        print(f"Secret rotation failed: {exc}", file=sys.stderr)
        return 1

    print(
        "Secret rotated and relay restarted. Transfer the value in "
        f"{SECRET_FILE} securely to every client."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
