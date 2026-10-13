from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from homelabctl.audit import audit_services


class AuditTests(unittest.TestCase):
    def test_detects_tcp_port_conflict(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("one", "two"):
                path = root / "services" / name / "service.yaml"
                path.parent.mkdir(parents=True)
                path.write_text(
                    f"""\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {{name: {name}}}
spec:
  driver: process
  process:
    command: [python, app.py]
  health:
    checks:
      - {{name: port, type: tcp, host: 127.0.0.1, port: 8080}}
""",
                    encoding="utf-8",
                )
            results = audit_services(root)
            self.assertTrue(any("端口冲突" in result.message for result in results))

    def test_detects_wireguard_duplicate_keys_and_networks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / "services" / "wireguard"
            (directory / "config").mkdir(parents=True)
            (directory / "service.yaml").write_text(
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
          publicEndpoint: vpn.test:51820
          accessProfiles:
            local: {allowedIPs: [10.10.0.0/24]}
      - name: wg1
        role: server
        config: config/wg1.conf
        peerManagement:
          addressPool: 10.10.0.128/25
          publicEndpoint: vpn.test:51821
          accessProfiles:
            local: {allowedIPs: [10.10.0.128/25]}
""",
                encoding="utf-8",
            )
            for name, address, port in (
                ("wg0", "10.10.0.1/32", 51820),
                ("wg1", "10.10.0.129/32", 51821),
            ):
                (directory / "config" / f"{name}.conf").write_text(
                    f"[Interface]\nAddress = {address}\nPrivateKey = same-secret\nListenPort = {port}\n",
                    encoding="utf-8",
                )
            results = audit_services(root)
            self.assertTrue(any("网段重叠" in result.message for result in results))
            self.assertTrue(any("密钥重复" in result.message for result in results))


if __name__ == "__main__":
    unittest.main()
