from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from homelabctl.boot import set_service_autostart
from homelabctl.config import load_service


class BootTests(unittest.TestCase):
    def test_set_service_autostart_is_persistent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "services" / "web" / "service.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(
                """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: web}
spec:
  driver: docker
  docker: {container: web}
""",
                encoding="utf-8",
            )
            set_service_autostart(root, "web", True)
            self.assertTrue(load_service(path).autostart)
            set_service_autostart(root, "web", False)
            self.assertFalse(load_service(path).autostart)


if __name__ == "__main__":
    unittest.main()
