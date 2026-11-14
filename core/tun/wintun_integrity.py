import hashlib
import hmac
import os


WINTUN_SHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"


def verify_wintun_dll(path: str) -> None:
    digest = hashlib.sha256()
    with open(path, "rb") as dll_file:
        for chunk in iter(lambda: dll_file.read(1024 * 1024), b""):
            digest.update(chunk)
    if not hmac.compare_digest(digest.hexdigest(), WINTUN_SHA256):
        raise RuntimeError(
            f"Wintun DLL integrity check failed for {os.path.basename(path)}"
        )
