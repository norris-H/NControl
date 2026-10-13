from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from homelabctl.errors import HomelabError
from homelabctl.layout import (
    layout_status,
    migrate_local_layout,
    runtime_directory,
    services_directory,
)


class LayoutTests(unittest.TestCase):
    def test_legacy_services_remain_compatible(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            legacy = root / "services"
            legacy.mkdir()
            self.assertEqual(services_directory(root), legacy)
            self.assertEqual(runtime_directory(root), root / ".ncontrol")

    def test_migrate_moves_services_and_runtime_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            service = root / "services" / "demo"
            service.mkdir(parents=True)
            (service / "service.yaml").write_text("demo\n", encoding="utf-8")
            state = root / ".ncontrol"
            state.mkdir()
            (state / "machine-id").write_text("machine\n", encoding="utf-8")

            migrate_local_layout(root)

            self.assertFalse((root / "services").exists())
            self.assertEqual(
                (root / "local" / "services" / "demo" / "service.yaml").read_text(
                    encoding="utf-8"
                ),
                "demo\n",
            )
            self.assertEqual(
                (root / "local" / ".ncontrol" / "machine-id").read_text(
                    encoding="utf-8"
                ),
                "machine\n",
            )
            mode, path = layout_status(root)
            self.assertEqual(mode, "本机独立目录")
            self.assertEqual(path, root / "local" / "services")
            self.assertTrue((root / "local" / "node.yaml").exists())

    def test_refuses_ambiguous_service_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "services").mkdir()
            (root / "local" / "services").mkdir(parents=True)
            with self.assertRaises(HomelabError):
                services_directory(root)
            with self.assertRaises(HomelabError):
                migrate_local_layout(root)


if __name__ == "__main__":
    unittest.main()
