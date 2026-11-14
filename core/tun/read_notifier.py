"""Bridge a native tunnel read event into a selectable socket."""

import ctypes
import socket
import threading
from ctypes import wintypes
from typing import Callable, Optional


class TunReadNotifier:
    def __init__(
        self,
        wait_for_event: Optional[Callable[[int], bool]] = None,
        wait_timeout_ms: int = 100,
    ):
        self._reader, self._writer = socket.socketpair()
        self._reader.setblocking(False)
        self._writer.setblocking(False)
        self._wait_for_event = wait_for_event
        self._wait_timeout_ms = wait_timeout_ms
        self._stop = threading.Event()
        self._resume = threading.Event()
        self._resume.set()
        self._error: Optional[Exception] = None
        self._thread = None
        if wait_for_event is not None:
            self._thread = threading.Thread(
                target=self._watch_event,
                name="msp-tun-event",
                daemon=True,
            )
            self._thread.start()

    @property
    def socket(self) -> socket.socket:
        return self._reader

    def fileno(self) -> int:
        return self._reader.fileno()

    def notify(self) -> None:
        try:
            self._writer.send(b"\x00")
        except BlockingIOError:
            pass

    def drain(self) -> None:
        while True:
            try:
                if not self._reader.recv(4096):
                    break
            except BlockingIOError:
                break
        if self._error is not None:
            error = self._error
            self._error = None
            raise RuntimeError("Tunnel read-event wait failed") from error

    def resume(self) -> None:
        self._resume.set()

    def close(self) -> None:
        self._stop.set()
        self._resume.set()
        if self._thread is not None:
            self._thread.join(timeout=self._wait_timeout_ms / 1000.0 + 1.0)
            if self._thread.is_alive():
                raise RuntimeError("Tunnel read-event watcher did not stop")
        self._reader.close()
        self._writer.close()

    def _watch_event(self) -> None:
        while not self._stop.is_set():
            try:
                ready = self._wait_for_event(self._wait_timeout_ms)
                if ready:
                    if self._stop.is_set():
                        return
                    self._resume.clear()
                    self.notify()
                    self._resume.wait()
            except Exception as error:
                self._error = error
                self.notify()
                return


def create_wintun_read_notifier(event_handle: int) -> TunReadNotifier:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    wait_for_single_object = kernel32.WaitForSingleObject
    wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    wait_for_single_object.restype = wintypes.DWORD

    def wait_for_event(timeout_ms: int) -> bool:
        result = wait_for_single_object(event_handle, timeout_ms)
        if result == 0:
            return True
        if result == 258:
            return False
        raise ctypes.WinError(ctypes.get_last_error())

    return TunReadNotifier(wait_for_event)
