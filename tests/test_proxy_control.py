from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from homelabctl.errors import HomelabError
from homelabctl.proxy_control import (
    DEFAULT_NO_PROXY,
    apply_process_environment,
    disable,
    load_settings,
    save_settings,
)


class ProxyControlTests(unittest.TestCase):
    def test_proxy_is_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as temp:
            current = load_settings(Path(temp))
            self.assertFalse(current.enabled)
            self.assertEqual(current.host, "127.0.0.1")
            self.assertEqual(current.port, 7890)

    def test_proxy_is_node_local_and_keeps_address_when_disabled(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            current = save_settings(
                root,
                enabled=True,
                host="192.168.1.2",
                port=7897,
            )
            self.assertEqual(current.url, "http://192.168.1.2:7897")
            self.assertTrue((root / "local" / "proxy.yaml").exists())
            disabled = disable(root)
            self.assertFalse(disabled.enabled)
            self.assertEqual(disabled.host, "192.168.1.2")
            self.assertEqual(disabled.port, 7897)

    def test_proxy_rejects_hostname_wildcard_and_bad_port(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for host, port in (
                ("localhost", 7890),
                ("0.0.0.0", 7890),
                ("127.0.0.1", 0),
            ):
                with self.subTest(host=host, port=port):
                    with self.assertRaises(HomelabError):
                        save_settings(root, enabled=True, host=host, port=port)

    def test_enabled_proxy_is_applied_to_ncontrol_and_managed_children(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            save_settings(root, enabled=True, host="192.168.1.2", port=7897)
            with patch.dict(os.environ, {}, clear=True):
                apply_process_environment(root)
                self.assertEqual(os.environ["HTTP_PROXY"], "http://192.168.1.2:7897")
                self.assertEqual(os.environ["https_proxy"], "http://192.168.1.2:7897")
                self.assertEqual(os.environ["NO_PROXY"], DEFAULT_NO_PROXY)

    def test_disabling_proxy_removes_inherited_proxy_variables(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.dict(
                os.environ,
                {"HTTP_PROXY": "http://old:1", "https_proxy": "http://old:1"},
                clear=True,
            ):
                apply_process_environment(root)
                self.assertNotIn("HTTP_PROXY", os.environ)
                self.assertNotIn("https_proxy", os.environ)


if __name__ == "__main__":
    unittest.main()
