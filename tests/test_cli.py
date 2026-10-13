from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from homelabctl.cli import main


WIREGUARD = """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: wireguard}
spec:
  driver: wireguard
  wireguard:
    interfaces:
      - {name: wg0, role: server, config: config/wg0.conf}
"""


class CliSafetyTests(unittest.TestCase):
    def test_layout_migrate_keeps_service_available(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "services" / "web" / "service.yaml"
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
            self.assertEqual(main(["--root", temp, "layout", "migrate"]), 0)
            self.assertEqual(main(["--root", temp, "validate", "web"]), 0)
            self.assertTrue(
                (Path(temp) / "local" / "services" / "web" / "service.yaml").exists()
            )

    def test_boot_enable_updates_service(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "services" / "web" / "service.yaml"
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
            self.assertEqual(main(["--root", temp, "boot", "enable", "web"]), 0)
            self.assertTrue(
                yaml.safe_load(path.read_text(encoding="utf-8"))["spec"]["autostart"]
            )

    def test_wireguard_subcommands_only_read_their_own_arguments(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "services" / "wireguard" / "service.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(WIREGUARD, encoding="utf-8")
            with patch("homelabctl.drivers.wireguard._is_windows", return_value=False):
                self.assertEqual(
                    main(
                        [
                            "--root", temp, "--dry-run", "wireguard",
                            "import-peers", "wireguard", "wg0",
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    main(
                        [
                            "--root", temp, "--dry-run", "wireguard",
                            "connection-status", "wireguard", "link",
                        ]
                    ),
                    0,
                )


if __name__ == "__main__":
    unittest.main()
