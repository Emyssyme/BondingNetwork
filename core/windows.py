import os


def system_executable(*parts: str) -> str:
    if os.name != "nt":
        return os.path.join(*parts)

    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise RuntimeError("SystemRoot is not set; cannot resolve a Windows system executable")
    return os.path.join(system_root, "System32", *parts)
