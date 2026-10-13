from __future__ import annotations

import tempfile
import unittest
import warnings
from pathlib import Path

from homelabctl.config import load_service
from homelabctl.process_control import start, status, stop


SERVICE = """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: sleeper}
spec:
  driver: process
  process:
    command:
      - "{python}"
      - -c
      - "import time; print('ready', flush=True); time.sleep(60)"
    startupGraceSeconds: 0.1
    stopTimeoutSeconds: 1
"""


class ProcessControlTests(unittest.TestCase):
    def test_start_status_and_stop(self):
        with tempfile.TemporaryDirectory() as temp:
            service_file = Path(temp) / "service.yaml"
            service_file.write_text(SERVICE, encoding="utf-8")
            service = load_service(service_file)
            self.addCleanup(stop, service)

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", ResourceWarning)
                self.assertEqual(start(service), 0)
            self.assertEqual(status(service), 0)
            self.assertTrue((Path(temp) / ".ncontrol" / "process.json").exists())
            self.assertEqual(stop(service), 0)
            self.assertEqual(status(service), 3)
            self.assertIn("ready", (Path(temp) / "logs" / "service.log").read_text())


if __name__ == "__main__":
    unittest.main()
