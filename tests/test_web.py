from __future__ import annotations

from http.client import HTTPConnection
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from urllib.parse import urlencode

import yaml

from homelabctl.errors import HomelabError
from homelabctl.web_control import (
    enable,
    load_config,
    read_token,
    rotate_token,
    start,
    status,
    stop,
)
from homelabctl.web_server import NControlHTTPServer, WebBackend


SERVICE = """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: demo, description: Web test service}
spec:
  driver: script
  script:
    commands:
      start: ["{python}", -c, "print('started')"]
      stop: ["{python}", -c, "print('stopped')"]
      status: ["{python}", -c, "raise SystemExit(3)"]
      logs: ["{python}", -c, "print('web log ready')"]
"""


def make_root(base: str) -> Path:
    root = Path(base)
    service = root / "local" / "services" / "demo" / "service.yaml"
    service.parent.mkdir(parents=True)
    service.write_text(SERVICE, encoding="utf-8")
    return root


class WebControlTests(unittest.TestCase):
    def test_web_is_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_root(temp)
            current = status(root)
            self.assertFalse(current.enabled)
            self.assertFalse(current.running)
            self.assertEqual(current.bind, "127.0.0.1")
            self.assertFalse((root / "local" / "web.yaml").exists())

    def test_enable_persists_only_node_local_config_and_token(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_root(temp)
            token = enable(root, "127.0.0.1", 18765)
            self.assertEqual(read_token(root), token)
            self.assertEqual(load_config(root)["port"], 18765)
            self.assertTrue((root / "local" / "web.yaml").exists())
            self.assertTrue((root / "local" / "secrets" / "web-token.txt").exists())
            self.assertNotEqual(rotate_token(root), token)

    def test_enable_rejects_public_wildcard(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_root(temp)
            with self.assertRaises(HomelabError):
                enable(root, "0.0.0.0", 8765)

    def test_background_lifecycle_and_token_rotation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_root(temp)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = int(probe.getsockname()[1])
            first_token = enable(root, "127.0.0.1", port)
            try:
                first = start(root)
                self.assertTrue(first.running)
                connection = HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/login")
                response = connection.getresponse()
                response.read()
                connection.close()
                self.assertEqual(response.status, 200)

                second_token = rotate_token(root)
                second = status(root)
                self.assertNotEqual(second_token, first_token)
                self.assertTrue(second.running)
                self.assertNotEqual(second.pid, first.pid)
            finally:
                stop(root)

    def test_backend_uses_existing_drivers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_root(temp)
            backend = WebBackend(root)
            dashboard = backend.dashboard()
            self.assertEqual(dashboard["services"][0]["name"], "demo")
            self.assertEqual(dashboard["services"][0]["health"]["state"], "stopped")
            self.assertIn("web log ready", backend.logs("demo")["output"])
            result = backend.service_action(
                "demo", {"action": "set-autostart", "enabled": True}
            )
            self.assertTrue(result["ok"])
            definition = yaml.safe_load(
                (root / "local" / "services" / "demo" / "service.yaml").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(definition["spec"]["autostart"])


class WebHttpSecurityTests(unittest.TestCase):
    def test_login_cookie_csrf_and_assets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = make_root(temp)
            token = enable(root)
            server = NControlHTTPServer(("127.0.0.1", 0), root, token)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            try:
                connection.request("GET", "/api/dashboard")
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 401)

                body = urlencode({"token": token})
                connection.request(
                    "POST",
                    "/login",
                    body,
                    {"Content-Type": "application/x-www-form-urlencoded"},
                )
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 303)
                cookie = response.getheader("Set-Cookie").split(";", 1)[0]
                self.assertIn("HttpOnly", response.getheader("Set-Cookie"))

                connection.request("GET", "/api/dashboard", headers={"Cookie": cookie})
                response = connection.getresponse()
                dashboard = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertTrue(dashboard["csrf"])

                connection.request("GET", "/assets/app.js", headers={"Cookie": cookie})
                response = connection.getresponse()
                asset = response.read()
                self.assertEqual(response.status, 200)
                self.assertIn(b"initialize", asset)

                connection.request(
                    "POST",
                    "/api/services/demo/action",
                    json.dumps({"action": "start"}),
                    {"Cookie": cookie, "Content-Type": "application/json"},
                )
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 403)
            finally:
                connection.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
