from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from textual.widgets import Button, DataTable, RichLog, Static

from homelabctl.tui import (
    AddWireGuardPeerScreen,
    ConfirmActionScreen,
    ConnectWireGuardServerScreen,
    CreateWireGuardServerScreen,
    MigrationScreen,
    NControlApp,
    StopConfirmScreen,
    WebManagerScreen,
    WireGuardManagerScreen,
    WireGuardConnectionScreen,
    WireGuardQrScreen,
)
from homelabctl.updates import UpdateInfo
from homelabctl.web_control import stop as stop_web


SERVICE = """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata:
  name: web
  description: Test service
spec:
  driver: docker
  autostart: true
  docker:
    container: web
"""

WIREGUARD_SERVICE = """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: wireguard, description: Test WireGuard}
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
            linked: {description: 连接网络, allowedIPs: [10.10.0.0/24]}
      - {name: wg1, role: client, config: config/wg1.conf}
    connections:
      - {name: wg0-to-wg1, from: wg0, to: wg1, sourceNetwork: 10.10.0.0/24}
"""


@unittest.skipIf(os.name == "nt", "Textual headless tests hang in this Windows sandbox")
class TuiTests(unittest.TestCase):
    def test_web_key_opens_disabled_web_manager(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "services" / "web" / "service.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(SERVICE, encoding="utf-8")

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.press("v")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, WebManagerScreen)
                    self.assertIn(
                        "默认关闭",
                        str(app.screen.query_one("#web-summary", Static).render()),
                    )
                    await pilot.click("#web-apply")
                    await app.workers.wait_for_complete()
                    self.assertTrue(
                        yaml.safe_load((Path(temp) / "web.yaml").read_text(encoding="utf-8"))[
                            "enabled"
                        ]
                    )
                    self.assertIn(
                        "运行中",
                        str(app.screen.query_one("#web-summary", Static).render()),
                    )
                    self.assertNotIn(
                        "尚未生成",
                        str(app.screen.query_one("#web-token-value", Static).render()),
                    )
                    await asyncio.to_thread(stop_web, Path(temp))
                    app.screen.dismiss(None)

            asyncio.run(scenario())

    def test_update_key_opens_confirmation_when_update_is_available(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "services" / "web" / "service.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(SERVICE, encoding="utf-8")
            info = UpdateInfo(
                "available",
                "a" * 40,
                "b" * 40,
                behind=2,
                remote_url="https://github.com/example/NControl.git",
                detail="发现 2 个新提交",
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)) as pilot:
                    with patch("homelabctl.tui.check_for_updates", return_value=info):
                        await pilot.press("u")
                        await pilot.pause()
                        self.assertIsInstance(app.screen, ConfirmActionScreen)
                        app.screen.dismiss(False)

            asyncio.run(scenario())

    def test_migration_screen_can_open_automatically(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "services" / "web" / "service.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(SERVICE, encoding="utf-8")

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False, open_migration=True)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.pause()
                    self.assertIsInstance(app.screen, MigrationScreen)
                    self.assertEqual(app.focused.id, "migration-report")
                    await pilot.press("h")
                    self.assertEqual(app.focused.id, "migration-host")
                    app.screen.dismiss(None)

            asyncio.run(scenario())

    def test_migration_wireguard_action_opens_confirmation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "services" / "web" / "service.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(SERVICE, encoding="utf-8")

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False, open_migration=True)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.pause()
                    self.assertIsInstance(app.screen, MigrationScreen)
                    await pilot.press("w")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, ConfirmActionScreen)
                    app.screen.dismiss(False)

            asyncio.run(scenario())

    def test_dashboard_shows_autostart_service(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "services" / "web" / "service.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(SERVICE, encoding="utf-8")

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)) as pilot:
                    table = app.query_one("#services", DataTable)
                    self.assertEqual(table.row_count, 1)
                    self.assertGreaterEqual(table.columns["status"].width, 16)
                    self.assertEqual(app.selected_name, "web")
                    detail = app.query_one("#detail", Static)
                    self.assertIn("已启用", str(detail.render()))

            asyncio.run(scenario())

    def test_service_details_hide_original_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "services" / "web"
            directory.mkdir(parents=True)
            (directory / "service.yaml").write_text(SERVICE, encoding="utf-8")
            (directory / "adoption.yaml").write_text(
                "originalPath: /srv/legacy-web\nports: [8080]\n",
                encoding="utf-8",
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)):
                    detail = str(app.query_one("#detail", Static).render())
                    self.assertNotIn("原始目录", detail)
                    self.assertNotIn("/srv/legacy-web", detail)
                    self.assertIn("8080", detail)

            asyncio.run(scenario())

    def test_dashboard_loads_selected_service_logs_automatically(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "services" / "web"
            directory.mkdir(parents=True)
            (directory / "service.yaml").write_text(
                """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: web, description: Test service}
spec:
  driver: script
  script:
    commands:
      logs: ["{python}", -c, "print('campus log ready')"]
""",
                encoding="utf-8",
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.pause()
                    await app.workers.wait_for_complete()
                    output = app.query_one("#output", RichLog)
                    self.assertIn("web", output.border_title)
                    self.assertIn(
                        "campus log ready",
                        "\n".join(line.text for line in output.lines),
                    )

            asyncio.run(scenario())

    def test_stop_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "services" / "web" / "service.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(SERVICE, encoding="utf-8")

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.press("x")
                    self.assertIsInstance(app.screen, StopConfirmScreen)
                    cancel = app.screen.query_one("#cancel", Button)
                    confirm = app.screen.query_one("#confirm", Button)
                    self.assertTrue(cancel.has_focus)
                    await pilot.press("right")
                    self.assertTrue(confirm.has_focus)
                    await pilot.press("left")
                    self.assertTrue(cancel.has_focus)
                    await pilot.press("tab")
                    self.assertTrue(confirm.has_focus)
                    app.screen.dismiss(None)

            asyncio.run(scenario())

    def test_clear_logs_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "services" / "web" / "service.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(
                """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: web, description: Test service}
spec:
  driver: process
  process:
    command: ["{python}", -c, "print('ready')"]
""",
                encoding="utf-8",
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.press("k")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, ConfirmActionScreen)
                    self.assertEqual(
                        app.screen.query_one("#confirm", Button).label.plain,
                        "清空日志",
                    )
                    app.screen.dismiss(False)

            asyncio.run(scenario())

    def test_wireguard_manager_opens_add_peer_form(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "services" / "wireguard"
            (directory / "config").mkdir(parents=True)
            (directory / "service.yaml").write_text(WIREGUARD_SERVICE, encoding="utf-8")
            (directory / "config" / "wg0.conf").write_text(
                "[Interface]\nAddress = 10.10.0.1/32\n", encoding="utf-8"
            )
            (directory / "config" / "wg1.conf").write_text(
                "[Interface]\n", encoding="utf-8"
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.press("w")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, WireGuardManagerScreen)
                    await pilot.press("a")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, AddWireGuardPeerScreen)
                    app.screen.dismiss(None)

            asyncio.run(scenario())

    def test_wireguard_manager_focuses_and_switches_regions(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "services" / "wireguard"
            (directory / "config").mkdir(parents=True)
            (directory / "service.yaml").write_text(WIREGUARD_SERVICE, encoding="utf-8")
            (directory / "config" / "wg0.conf").write_text(
                "[Interface]\nAddress = 10.10.0.1/32\n", encoding="utf-8"
            )
            (directory / "config" / "wg1.conf").write_text(
                "[Interface]\nAddress = 192.168.7.3/32\n", encoding="utf-8"
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.press("w")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, WireGuardManagerScreen)
                    self.assertEqual(app.focused.id, "wg0-items")
                    self.assertIn(
                        "N 新建服务端",
                        str(app.screen.query_one("#wg-actions").render()),
                    )
                    app.screen.action_focus_next_table()
                    await pilot.pause()
                    self.assertEqual(app.focused.id, "wg1-items")
                    self.assertIn(
                        "J 连接其他服务端",
                        str(app.screen.query_one("#wg-actions").render()),
                    )
                    self.assertIn(
                        "D 删除客户端",
                        str(app.screen.query_one("#wg-actions").render()),
                    )
                    self.assertNotIn(
                        "N 新建服务端",
                        str(app.screen.query_one("#wg-actions").render()),
                    )
                    app.screen.action_focus_previous_table()
                    await pilot.pause()
                    self.assertEqual(app.focused.id, "wg0-items")
                    await pilot.press("ctrl+i")
                    await pilot.pause()
                    self.assertEqual(app.focused.id, "wg1-items")
                    await pilot.press("ctrl+i")
                    await pilot.pause()
                    self.assertEqual(app.focused.id, "wg-connections")
                    self.assertIn(
                        "A 添加连接",
                        str(app.screen.query_one("#wg-actions").render()),
                    )
                    self.assertNotIn(
                        "J 连接其他服务端",
                        str(app.screen.query_one("#wg-actions").render()),
                    )

            asyncio.run(scenario())

    def test_wireguard_manager_opens_server_and_client_creation_forms(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "services" / "wireguard"
            (directory / "config").mkdir(parents=True)
            (directory / "service.yaml").write_text(WIREGUARD_SERVICE, encoding="utf-8")
            (directory / "config" / "wg0.conf").write_text(
                "[Interface]\nAddress = 10.10.0.1/32\n", encoding="utf-8"
            )
            (directory / "config" / "wg1.conf").write_text(
                "[Interface]\nAddress = 192.168.7.3/32\n", encoding="utf-8"
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.press("w")
                    await pilot.pause()
                    await pilot.press("n")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, CreateWireGuardServerScreen)
                    self.assertEqual(
                        app.screen.query_one("#server-interface").value,
                        "wg2",
                    )
                    app.screen.dismiss(None)
                    await pilot.pause()
                    app.screen.action_focus_next_table()
                    await pilot.pause()
                    await pilot.press("j")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, ConnectWireGuardServerScreen)
                    app.screen.dismiss(None)

            asyncio.run(scenario())

    def test_wireguard_manager_edits_and_confirms_server_deletion(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "services" / "wireguard"
            (directory / "config").mkdir(parents=True)
            (directory / "service.yaml").write_text(WIREGUARD_SERVICE, encoding="utf-8")
            (directory / "config" / "wg0.conf").write_text(
                "[Interface]\nAddress = 10.10.0.1/32\nListenPort = 51820\n",
                encoding="utf-8",
            )
            (directory / "config" / "wg1.conf").write_text(
                "[Interface]\nAddress = 192.168.7.3/32\n", encoding="utf-8"
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.press("w")
                    await pilot.pause()
                    await pilot.press("e")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, CreateWireGuardServerScreen)
                    self.assertTrue(app.screen.editing)
                    app.screen.dismiss(None)
                    await pilot.pause()
                    await pilot.press("d")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, ConfirmActionScreen)
                    app.screen.dismiss(False)

            asyncio.run(scenario())

    def test_wireguard_server_shows_contextual_connect_and_disconnect(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "services" / "wireguard"
            (directory / "config").mkdir(parents=True)
            (directory / "service.yaml").write_text(WIREGUARD_SERVICE, encoding="utf-8")
            (directory / "config" / "wg0.conf").write_text(
                "[Interface]\nAddress = 10.10.0.1/32\n", encoding="utf-8"
            )
            (directory / "config" / "wg1.conf").write_text(
                "[Interface]\nAddress = 192.168.7.3/32\n", encoding="utf-8"
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.press("w")
                    await pilot.pause()
                    screen = app.screen
                    self.assertIsInstance(screen, WireGuardManagerScreen)
                    screen.interface_states["wg0"] = "disconnected"
                    screen._update_action_bar()
                    self.assertIn("C 连接服务端", str(screen.query_one("#wg-actions").render()))
                    screen.interface_states["wg0"] = "connected"
                    screen._update_action_bar()
                    self.assertIn("X 断开服务端", str(screen.query_one("#wg-actions").render()))
                    await pilot.press("x")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, ConfirmActionScreen)
                    app.screen.dismiss(False)

            asyncio.run(scenario())

    def test_wireguard_traffic_snapshot_updates_speed_and_handshake(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "services" / "wireguard"
            (directory / "config").mkdir(parents=True)
            (directory / "service.yaml").write_text(WIREGUARD_SERVICE, encoding="utf-8")
            (directory / "config" / "wg0.conf").write_text(
                "[Interface]\nAddress = 10.10.0.1/32\n\n"
                "[Peer]\nPublicKey = existing-public\nAllowedIPs = 10.10.0.2/32\n",
                encoding="utf-8",
            )
            (directory / "config" / "wg1.conf").write_text(
                "[Interface]\nAddress = 192.168.7.3/32\n", encoding="utf-8"
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(140, 40)) as pilot:
                    await pilot.press("w")
                    await pilot.pause()
                    screen = app.screen
                    self.assertIsInstance(screen, WireGuardManagerScreen)
                    first = {
                        "sampledAt": 1000,
                        "interfaces": [{
                            "name": "wg0", "running": True,
                            "receivedBytes": 2048, "sentBytes": 4096,
                            "latestHandshake": 999,
                            "peers": [{
                                "publicKey": "existing-public",
                                "latestHandshake": 999,
                                "receivedBytes": 2048,
                                "sentBytes": 4096,
                            }],
                        }],
                        "connections": [{
                            "name": "wg0-to-wg1", "available": True,
                            "forwardBytes": 1000, "returnBytes": 500,
                        }],
                    }
                    second = {
                        "sampledAt": 1002,
                        "interfaces": [{
                            "name": "wg0", "running": True,
                            "receivedBytes": 4096, "sentBytes": 8192,
                            "latestHandshake": 1001,
                            "peers": [{
                                "publicKey": "existing-public",
                                "latestHandshake": 1001,
                                "receivedBytes": 4096,
                                "sentBytes": 8192,
                            }],
                        }],
                        "connections": [{
                            "name": "wg0-to-wg1", "available": True,
                            "forwardBytes": 3000, "returnBytes": 1500,
                        }],
                    }
                    screen._traffic_previous.clear()
                    screen._apply_traffic_snapshot(first)
                    screen._apply_traffic_snapshot(second)
                    peer_key = "peer:wg0:unregistered:existing-pub"
                    peer_table = screen.query_one("#wg0-items", DataTable)
                    self.assertIn("刚刚握手", str(peer_table.get_cell(peer_key, "status")))
                    self.assertIn("K/s", str(peer_table.get_cell(peer_key, "speed")))
                    connection_table = screen.query_one("#wg-connections", DataTable)
                    self.assertIn(
                        "/s",
                        str(connection_table.get_cell("connection:wg0-to-wg1", "speed")),
                    )

            asyncio.run(scenario())

    def test_wireguard_network_connection_forms_are_contextual(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "services" / "wireguard"
            (directory / "config").mkdir(parents=True)
            (directory / "service.yaml").write_text(WIREGUARD_SERVICE, encoding="utf-8")
            (directory / "config" / "wg0.conf").write_text(
                "[Interface]\nAddress = 10.10.0.1/32\n", encoding="utf-8"
            )
            (directory / "config" / "wg1.conf").write_text(
                "[Interface]\nAddress = 192.168.7.3/32\n\n"
                "[Peer]\nPublicKey = remote\nAllowedIPs = 192.168.7.0/24\n",
                encoding="utf-8",
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(140, 40)) as pilot:
                    await pilot.press("w")
                    await pilot.pause()
                    manager = app.screen
                    self.assertIsInstance(manager, WireGuardManagerScreen)
                    manager.action_focus_next_table()
                    manager.action_focus_next_table()
                    await pilot.pause()
                    await pilot.press("a")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, WireGuardConnectionScreen)
                    self.assertFalse(app.screen.editing)
                    app.screen.dismiss(None)
                    await pilot.pause()
                    await pilot.press("e")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, WireGuardConnectionScreen)
                    self.assertTrue(app.screen.editing)
                    app.screen.dismiss(None)
                    await pilot.pause()
                    await pilot.press("x")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, ConfirmActionScreen)
                    app.screen.dismiss(False)

            asyncio.run(scenario())

    def test_wireguard_manager_reloads_definition_when_reopened(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "services" / "wireguard"
            (directory / "config").mkdir(parents=True)
            service_path = directory / "service.yaml"
            service_path.write_text(WIREGUARD_SERVICE, encoding="utf-8")
            (directory / "config" / "wg0.conf").write_text(
                "[Interface]\nAddress = 10.10.0.1/32\n", encoding="utf-8"
            )
            (directory / "config" / "wg1.conf").write_text(
                "[Interface]\nAddress = 192.168.7.3/32\n", encoding="utf-8"
            )

            async def scenario() -> None:
                app = NControlApp(Path(temp), auto_refresh=False)
                async with app.run_test(size=(140, 40)) as pilot:
                    value = yaml.safe_load(service_path.read_text(encoding="utf-8"))
                    value["spec"]["wireguard"]["connections"].append({
                        "name": "new-link",
                        "from": "wg1",
                        "to": "wg0",
                        "sourceNetwork": "192.168.7.0/24",
                        "destinationNetworks": ["10.10.0.0/24"],
                        "mode": "masquerade",
                        "allowReturnTraffic": True,
                    })
                    service_path.write_text(
                        yaml.safe_dump(value, allow_unicode=True, sort_keys=False),
                        encoding="utf-8",
                    )
                    await pilot.press("w")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, WireGuardManagerScreen)
                    self.assertIn("connection:new-link", app.screen.row_values)
                    app.screen.dismiss(None)

            asyncio.run(scenario())

    def test_wireguard_qr_uses_a_dedicated_full_screen(self):
        async def scenario() -> None:
            app = NControlApp(Path("."), auto_refresh=False)
            async with app.run_test(size=(80, 24)) as pilot:
                app.push_screen(WireGuardQrScreen("phone", "█▀▄\n"))
                await pilot.pause()
                self.assertIsInstance(app.screen, WireGuardQrScreen)
                self.assertIn("phone", str(app.screen.query_one("#qr-title").render()))
                app.screen.dismiss(None)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
