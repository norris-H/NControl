from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from homelabctl.config import find_service, load_service
from homelabctl.errors import ConfigError


VALID = """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata:
  name: web
spec:
  driver: docker
  docker:
    container: web
"""


class ConfigTests(unittest.TestCase):
    def test_load_and_find_service(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "services" / "web" / "service.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(VALID, encoding="utf-8")
            service = find_service(Path(temp), "web")
            self.assertEqual(service.driver, "docker")

    def test_prefers_node_local_services(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "local" / "services" / "web" / "service.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(VALID, encoding="utf-8")
            service = find_service(Path(temp), "web")
            self.assertEqual(service.path, path)

    def test_rejects_unknown_driver(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.yaml"
            path.write_text(VALID.replace("driver: docker", "driver: magic"), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_service(path)

    def test_rejects_invalid_backup_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.yaml"
            path.write_text(VALID + "  backup:\n    paths: data\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_service(path)

    def test_rejects_invalid_autostart(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.yaml"
            path.write_text(
                VALID.replace("driver: docker", "autostart: sometimes\n  driver: docker"),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_service(path)

    def test_accepts_start_order(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.yaml"
            path.write_text(
                VALID.replace("driver: docker", "startOrder: 20\n  driver: docker"),
                encoding="utf-8",
            )
            self.assertEqual(load_service(path).start_order, 20)

    def test_rejects_invalid_start_order(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.yaml"
            path.write_text(
                VALID.replace("driver: docker", "startOrder: -1\n  driver: docker"),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_service(path)

    def test_accepts_health_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.yaml"
            path.write_text(
                VALID
                + "  health:\n"
                + "    checks:\n"
                + "      - {name: api, type: http, url: http://127.0.0.1:8080/health}\n"
                + "      - {name: port, type: tcp, host: 127.0.0.1, port: 8080}\n",
                encoding="utf-8",
            )
            service = load_service(path)
            self.assertEqual(len(service.spec["health"]["checks"]), 2)

    def test_wireguard_accepts_client_and_server_interfaces(self):
        body = """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: wireguard}
spec:
  driver: wireguard
  wireguard:
    interfaces:
      - {name: wg0, role: server, config: config/wg0.conf}
      - {name: wg1, role: client, config: config/wg1.conf}
"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.yaml"
            path.write_text(body, encoding="utf-8")
            service = load_service(path)
            self.assertEqual(len(service.spec["wireguard"]["interfaces"]), 2)

    def test_wireguard_accepts_connections_and_peer_management(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.yaml"
            path.write_text(
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
          publicEndpoint: vpn.example.test:51820
          defaultAccessProfile: linked
          accessProfiles:
            linked:
              allowedIPs: [10.10.0.0/24, 192.168.31.0/24]
      - {name: wg1, role: client, config: config/wg1.conf}
    connections:
      - name: wg0-to-wg1
        from: wg0
        to: wg1
        sourceNetwork: 10.10.0.0/24
""",
                encoding="utf-8",
            )
            service = load_service(path)
            self.assertEqual(
                service.spec["wireguard"]["connections"][0]["name"],
                "wg0-to-wg1",
            )

    def test_process_driver_accepts_portable_command(self):
        body = """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: worker}
spec:
  driver: process
  workingDirectory: source
  process:
    command: ["{python}", app.py]
    platformCommands:
      windows: ["{python}", app.py, --windows]
    environment:
      DATA_DIR: "{serviceDir}/data"
    environmentFromFiles:
      TOKEN: secrets/token.txt
"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.yaml"
            path.write_text(body, encoding="utf-8")
            service = load_service(path)
            self.assertEqual(service.driver, "process")

    def test_process_runtime_files_must_be_portable(self):
        body = """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: worker}
spec:
  driver: process
  process:
    command: ["{python}", app.py]
    stateFile: ../worker.pid
"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.yaml"
            path.write_text(body, encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_service(path)


if __name__ == "__main__":
    unittest.main()

