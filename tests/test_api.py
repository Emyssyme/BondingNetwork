import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

import api
import main


class TestDashboardAPI(unittest.TestCase):
    def test_status_reports_connection_and_dev_flags(self):
        daemon = Mock()
        daemon.get_telemetry.return_value = {"state": "disconnected", "is_connected": False}
        state = api.APIState(daemon=daemon)
        with patch.object(api.app.state, "runtime", state), patch("api.DEV", True):
            status = asyncio.run(api.get_status())

        self.assertEqual(status["state"], "disconnected")
        self.assertFalse(status["is_connected"])
        self.assertTrue(status["dev_mode"])
        self.assertFalse(status["is_simulating"])

    def test_simulation_endpoint_is_unavailable_outside_dev_mode(self):
        with patch("api.DEV", False):
            response = asyncio.run(api.toggle_simulation())

        self.assertEqual(response.status_code, 404)

    def test_api_lifespan_cancels_background_simulation_task(self):
        async def exercise_lifespan():
            state = api.APIState()
            with patch.object(api.app.state, "runtime", state):
                task = asyncio.create_task(asyncio.sleep(60))
                state.sim_task = task
                async with api.lifespan(api.app):
                    pass
                return state, task

        state, task = asyncio.run(exercise_lifespan())

        self.assertTrue(task.cancelled())
        self.assertIsNone(state.sim_task)

    def test_guard_rejects_invalid_host_origin_and_one_time_token(self):
        daemon = Mock()
        daemon.get_telemetry.return_value = {"state": "disconnected", "is_connected": False}
        state = api.APIState(daemon=daemon)
        state.token = "session-token"
        state.login_token = "login-token"
        state.allowed_hosts = {"127.0.0.1:8088", "localhost:8088"}
        state.allowed_origins = {"http://127.0.0.1:8088", "http://localhost:8088"}

        with patch.object(api.app.state, "runtime", state):
            client = TestClient(api.app, follow_redirects=False)

            response = client.get("/", headers={"host": "example.com"})
            self.assertEqual(response.status_code, 403)

            response = client.get("/", headers={"host": "127.0.0.1:8088", "origin": "https://evil.test"})
            self.assertEqual(response.status_code, 403)

            response = client.get("/?token=login-token", headers={"host": "127.0.0.1:8088"})
            self.assertEqual(response.status_code, 303)
            self.assertEqual(response.cookies.get("msp_session"), "session-token")

            response = client.get("/?token=login-token", headers={"host": "127.0.0.1:8088"})
            self.assertEqual(response.status_code, 401)

    def test_dashboard_hosts_remain_loopback_only(self):
        hosts, origins = api._dashboard_hosts(8088, "::1")
        self.assertIn("[::1]:8088", hosts)
        self.assertIn("http://[::1]:8088", origins)
        with self.assertRaisesRegex(ValueError, "loopback"):
            api._dashboard_hosts(8088, "0.0.0.0")

        self.assertEqual(main._loopback_host("127.0.0.1"), "127.0.0.1")
        with self.assertRaisesRegex(Exception, "loopback"):
            main._loopback_host("0.0.0.0")

    def test_shutdown_cleanup_stops_daemon_and_closes_lock(self):
        daemon = Mock()
        lock_file = Mock()
        main._prepare_shutdown(daemon, lock_file)
        daemon.stop.assert_called_once_with()
        lock_file.close.assert_called_once_with()

    def test_instance_lock_prevents_parallel_clients(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_file = Path(tmpdir) / "instance.lock"
            first = main.acquire_instance_lock(lock_file)
            self.assertIsNotNone(first)
            with self.assertRaisesRegex(RuntimeError, "Another MySpeedify instance is already running"):
                main.acquire_instance_lock(lock_file)
            first.close()


if __name__ == "__main__":
    unittest.main()
