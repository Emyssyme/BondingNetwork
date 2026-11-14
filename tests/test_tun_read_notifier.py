import select
import threading
import unittest

from core.tun.read_notifier import TunReadNotifier


class TestTunReadNotifier(unittest.TestCase):
    def test_selectable_socket_wakes_when_native_event_is_signaled(self):
        native_event = threading.Event()

        def wait_for_event(timeout_ms):
            return native_event.wait(timeout_ms / 1000)

        notifier = TunReadNotifier(wait_for_event, wait_timeout_ms=20)
        self.addCleanup(notifier.close)

        self.assertEqual(select.select([notifier.socket], [], [], 0)[0], [])
        native_event.set()
        readable = select.select([notifier.socket], [], [], 1.0)[0]
        self.assertEqual(readable, [notifier.socket])
        notifier.drain()
        self.assertEqual(select.select([notifier.socket], [], [], 0.05)[0], [])

        notifier.resume()
        readable = select.select([notifier.socket], [], [], 1.0)[0]
        self.assertEqual(readable, [notifier.socket])
        native_event.clear()
        notifier.drain()
        notifier.resume()
        self.assertEqual(select.select([notifier.socket], [], [], 0)[0], [])

    def test_direct_notification_wakes_without_a_watcher_thread(self):
        notifier = TunReadNotifier()
        self.addCleanup(notifier.close)

        notifier.notify()

        self.assertEqual(
            select.select([notifier.socket], [], [], 0)[0],
            [notifier.socket],
        )
        notifier.drain()
        self.assertEqual(select.select([notifier.socket], [], [], 0)[0], [])


if __name__ == "__main__":
    unittest.main()
