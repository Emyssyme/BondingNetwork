import asyncio
import unittest
from unittest.mock import Mock, patch

import api
from client import api as legacy_api


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

    def test_legacy_api_lifespan_cancels_background_tasks(self):
        async def exercise_lifespan():
            daemon = Mock()
            daemon.is_running = True
            state = legacy_api.APIState(daemon=daemon)
            with patch.object(legacy_api.app.state, "runtime", state):
                task = asyncio.create_task(asyncio.sleep(60))
                state.sim_task = task
                async with legacy_api.lifespan(legacy_api.app):
                    daemon_task = state.daemon_task
                    await asyncio.sleep(0)
                    pass
                return state, task, daemon_task, daemon

        state, task, daemon_task, daemon = asyncio.run(exercise_lifespan())

        self.assertTrue(task.cancelled())
        self.assertIsNotNone(daemon_task)
        self.assertTrue(daemon_task.cancelled())
        self.assertTrue(daemon.step.called)
        self.assertIsNone(state.sim_task)
        self.assertIsNone(state.daemon_task)


if __name__ == "__main__":
    unittest.main()
