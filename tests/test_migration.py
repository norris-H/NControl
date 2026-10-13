from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from homelabctl.config import load_service
from homelabctl.migration import migration_checks, record_machine, update_wireguard_public_host


class MigrationTests(unittest.TestCase):
    def test_record_machine_marks_current_host(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            record_machine(root)
            marker = root / "local" / ".ncontrol" / "machine-id"
            self.assertTrue(marker.read_text(encoding="utf-8").strip())

    def test_updates_wireguard_endpoint_and_generated_clients(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / "services" / "wireguard"
            (directory / "config").mkdir(parents=True)
            (directory / "secrets" / "clients").mkdir(parents=True)
            service_path = directory / "service.yaml"
            service_path.write_text(
                """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: wireguard}
spec:
  driver: wireguard
  wireguard:
    interfaces:
      - name: wg0
        role: server
        config: config/wg0.conf
        peerManagement:
          addressPool: 10.10.0.0/24
          publicEndpoint: 203.0.113.10:51820
          clientOutputDirectory: secrets/clients
          accessProfiles:
            local: {allowedIPs: [10.10.0.0/24]}
""",
                encoding="utf-8",
            )
            (directory / "config" / "wg0.conf").write_text(
                "[Interface]\nAddress = 10.10.0.1/32\nPrivateKey = secret\n",
                encoding="utf-8",
            )
            client = directory / "secrets" / "clients" / "phone.conf"
            client.write_text(
                "[Peer]\nEndpoint = 203.0.113.10:51820\n",
                encoding="utf-8",
            )

            service_count, client_count = update_wireguard_public_host(root, "vpn.new.test")

            self.assertEqual((service_count, client_count), (1, 1))
            service = load_service(service_path)
            endpoint = service.spec["wireguard"]["interfaces"][0]["peerManagement"][
                "publicEndpoint"
            ]
            self.assertEqual(endpoint, "vpn.new.test:51820")
            self.assertIn("vpn.new.test:51820", client.read_text(encoding="utf-8"))

    def test_inactive_x86_frp_is_only_a_warning_on_arm(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / "services" / "frps"
            (directory / "package").mkdir(parents=True)
            (directory / "config").mkdir()
            (directory / "package" / "frps").write_text("binary", encoding="utf-8")
            (directory / "config" / "frps.toml").write_text("bindPort = 7000\n", encoding="utf-8")
            (directory / "service.yaml").write_text(
                """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: frps}
spec:
  driver: process
  autostart: false
  process:
    command: [package/frps, -c, config/frps.toml]
  config:
    files: [config/frps.toml]
""",
                encoding="utf-8",
            )
            with patch("homelabctl.migration.platform.machine", return_value="aarch64"):
                results = migration_checks(root)
            frp = [result for result in results if "FRP 程序" in result.message]
            self.assertEqual(len(frp), 1)
            self.assertEqual(frp[0].level, "warning")


if __name__ == "__main__":
    unittest.main()
