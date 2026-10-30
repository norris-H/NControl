from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from homelabctl.system_info import cpu_temperature, system_snapshot


class SystemInfoTests(unittest.TestCase):
    def test_cpu_temperature_prefers_cpu_sensor_over_nvme(self):
        sensors = {
            "nvme": [SimpleNamespace(current=72.0, label="Composite")],
            "cpu_thermal": [SimpleNamespace(current=53.25, label="CPU")],
        }
        with patch(
            "homelabctl.system_info.psutil.sensors_temperatures",
            return_value=sensors,
            create=True,
        ):
            result = cpu_temperature()
        self.assertTrue(result["available"])
        self.assertEqual(result["celsius"], 53.2)
        self.assertEqual(result["source"], "CPU")

    def test_cpu_temperature_is_optional(self):
        with patch(
            "homelabctl.system_info.psutil.sensors_temperatures",
            return_value={},
            create=True,
        ):
            result = cpu_temperature()
        self.assertFalse(result["available"])
        self.assertIsNone(result["celsius"])

    def test_system_snapshot_contains_portable_resource_metrics(self):
        with tempfile.TemporaryDirectory() as temp:
            snapshot = system_snapshot(Path(temp))
        self.assertIn("hostname", snapshot["host"])
        self.assertGreaterEqual(snapshot["cpu"]["percent"], 0)
        self.assertGreater(snapshot["memory"]["total"], 0)
        self.assertGreater(snapshot["disk"]["total"], 0)
        self.assertGreaterEqual(snapshot["uptimeSeconds"], 0)
        self.assertIn("received", snapshot["network"])


if __name__ == "__main__":
    unittest.main()
