from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys
from unittest.mock import patch

from homelabctl.config import load_service
from homelabctl.drivers import get_driver


class DriverTests(unittest.TestCase):
    def _service(self, body: str):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "service.yaml"
        path.write_text(body, encoding="utf-8")
        return load_service(path)

    def test_compose_stop_is_non_destructive(self):
        service = self._service("""\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: app}
spec:
  driver: compose
  compose: {file: compose.yaml}
""")
        argv = get_driver(service).plans("stop")[0].argv
        self.assertIn("stop", argv)
        self.assertNotIn("down", argv)

    def test_systemd_user_mode(self):
        service = self._service("""\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: worker}
spec:
  driver: systemd
  systemd: {unit: worker.service, user: true}
""")
        with patch("homelabctl.drivers.wireguard._is_windows", return_value=False):
            argv = get_driver(service).plans("status")[0].argv
        self.assertEqual(argv[:3], ("systemctl", "--user", "status"))

    def test_systemd_system_start_uses_non_interactive_sudo(self):
        service = self._service("""\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: api}
spec:
  driver: systemd
  systemd: {unit: api.service}
""")
        driver = get_driver(service)
        self.assertEqual(
            driver.plans("start")[0].argv,
            ("sudo", "-n", "systemctl", "start", "api.service"),
        )
        self.assertEqual(
            driver.plans("status")[0].argv,
            ("systemctl", "status", "api.service"),
        )

    def test_script_is_an_argv_array(self):
        service = self._service("""\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: custom}
spec:
  driver: script
  script:
    commands:
      start: [python3, app.py]
""")
        argv = get_driver(service).plans("start")[0].argv
        self.assertEqual(argv, ("python3", "app.py"))

    def test_script_expands_portable_tokens(self):
        service = self._service("""\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: custom}
spec:
  driver: script
  script:
    commands:
      start: ["{python}", manage.py, start, "{serviceDir}"]
""")
        argv = get_driver(service).plans("start")[0].argv
        self.assertEqual(argv[0], sys.executable)
        self.assertEqual(argv[1:3], ("manage.py", "start"))
        self.assertEqual(Path(argv[3]), service.directory)

    def test_wireguard_status_is_read_only_and_non_interactive(self):
        service = self._service("""\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: wg0}
spec:
  driver: wireguard
  wireguard:
    interface: wg0
    config: config/wg0.conf
""")
        with patch("homelabctl.drivers.wireguard._is_windows", return_value=False):
            argv = get_driver(service).plans("status")[0].argv
        self.assertEqual(argv, ("sudo", "-n", "wg", "show", "wg0"))

    def test_wireguard_combines_client_and_server(self):
        service = self._service("""\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: wireguard}
spec:
  driver: wireguard
  wireguard:
    interfaces:
      - {name: wg0, role: server, config: config/wg0.conf}
      - {name: wg1, role: client, config: config/wg1.conf}
""")
        driver = get_driver(service)
        with patch("homelabctl.drivers.wireguard._is_windows", return_value=False):
            self.assertEqual(
                [plan.argv for plan in driver.plans("status")],
                [
                    ("sudo", "-n", "wg", "show", "wg0"),
                    ("sudo", "-n", "wg", "show", "wg1"),
                ],
            )
        self.assertEqual(
            driver.config_values(),
            ["config/wg0.conf", "config/wg1.conf"],
        )

    def test_wireguard_windows_uses_tunnel_services(self):
        service = self._service("""\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: wireguard}
spec:
  driver: wireguard
  wireguard:
    interface: wg0
    config: config/wg0.conf
""")
        driver = get_driver(service)
        with patch("homelabctl.drivers.wireguard._is_windows", return_value=True):
            start = driver.plans("start")[0].argv
            stop = driver.plans("stop")[0].argv
            status = driver.plans("status")[0].argv
        self.assertEqual(start[1], "/installtunnelservice")
        self.assertEqual(stop[-2:], ("/uninstalltunnelservice", "wg0"))
        self.assertEqual(status, ("sc.exe", "query", "WireGuardTunnel$wg0"))

    def test_wireguard_auto_connection_wraps_interface_lifecycle(self):
        service = self._service("""\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: wireguard}
spec:
  driver: wireguard
  wireguard:
    interfaces:
      - {name: wg0, role: server, config: config/wg0.conf}
      - {name: wg1, role: client, config: config/wg1.conf}
    connections:
      - name: wg0-to-wg1
        from: wg0
        to: wg1
        sourceNetwork: 10.10.0.0/24
        autoConnect: true
""")
        driver = get_driver(service)
        with patch("homelabctl.drivers.wireguard._is_windows", return_value=False):
            start = [plan.argv for plan in driver.plans("start")]
            stop = [plan.argv for plan in driver.plans("stop")]
        self.assertEqual(start[0][-3:-1], ("wg-quick", "up"))
        self.assertEqual(start[-1][-2:], ("connect", "wg0-to-wg1"))
        self.assertEqual(stop[0][-2:], ("disconnect", "wg0-to-wg1"))
        self.assertEqual(stop[1][-3:-1], ("wg-quick", "down"))

    def test_process_driver_uses_ncontrol_runtime(self):
        service = self._service("""\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: worker}
spec:
  driver: process
  process:
    command: ["{python}", worker.py]
""")
        argv = get_driver(service).plans("stop")[0].argv
        self.assertEqual(argv[0], sys.executable)
        self.assertEqual(argv[1:4], ("-m", "homelabctl.process_control", "stop"))


if __name__ == "__main__":
    unittest.main()

