from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from homelabctl.config import load_service
from homelabctl.health import HealthCheckResult, check_health


class HealthTests(unittest.TestCase):
    def _service(self, root: Path):
        path = root / "service.yaml"
        path.write_text(
            """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: api}
spec:
  driver: process
  process:
    command: [python, app.py]
  health:
    startupPeriodSeconds: 30
    checks:
      - {name: api-port, type: tcp, host: 127.0.0.1, port: 8080, processOwned: true}
""",
            encoding="utf-8",
        )
        return load_service(path)

    def test_failed_check_is_unhealthy(self):
        with tempfile.TemporaryDirectory() as temp:
            service = self._service(Path(temp))
            with (
                patch(
                    "homelabctl.health.runtime_state",
                    return_value=("healthy", "running", {"startedAge": 60}),
                ),
                patch(
                    "homelabctl.health._tcp_check",
                    return_value=HealthCheckResult("api-port", False, "not listening"),
                ),
            ):
                result = check_health(service)
            self.assertEqual(result.state, "unhealthy")

    def test_failed_check_during_grace_is_starting(self):
        with tempfile.TemporaryDirectory() as temp:
            service = self._service(Path(temp))
            with (
                patch(
                    "homelabctl.health.runtime_state",
                    return_value=("healthy", "running", {"startedAge": 2}),
                ),
                patch(
                    "homelabctl.health._tcp_check",
                    return_value=HealthCheckResult("api-port", False, "not listening"),
                ),
            ):
                result = check_health(service)
            self.assertEqual(result.state, "starting")


if __name__ == "__main__":
    unittest.main()
