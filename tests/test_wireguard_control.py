from __future__ import annotations

import base64
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from homelabctl.config import load_service
from homelabctl.errors import HomelabError
from homelabctl.wireguard_control import (
    _rule_specs,
    _legacy_rule,
    _sync_peer_route,
    add_connection,
    add_peer,
    client_interface_settings,
    create_server_interface,
    create_client_interface,
    delete_client_interface,
    delete_server_interface,
    delete_connection,
    edit_server_interface,
    edit_client_interface,
    edit_connection,
    interface_addresses,
    interface_peer_networks,
    import_peers,
    import_client_interface,
    interface_status,
    list_peer_records,
    parse_wireguard_config,
    render_terminal_qr,
    start_interface,
    stop_interface,
    sync_interface_runtime,
    traffic_snapshot,
)


SERVICE = """\
apiVersion: homelabctl/v1alpha1
kind: Service
metadata: {name: wireguard}
spec:
  driver: wireguard
  wireguard:
    sudo: true
    interfaces:
      - name: wg0
        role: server
        config: config/wg0.conf
        peerManagement:
          addressPool: 10.10.0.0/24
          publicEndpoint: vpn.example.test:51820
          serverPublicKeyFile: secrets/wg0/public.key
          defaultAccessProfile: linked
          accessProfiles:
            server-only:
              allowedIPs: [10.10.0.1/32]
            linked:
              allowedIPs: [10.10.0.0/24, 192.168.31.0/24]
      - name: wg1
        role: client
        config: config/wg1.conf
    connections:
      - name: wg0-to-wg1
        from: wg0
        to: wg1
        sourceNetwork: 10.10.0.0/24
        mode: masquerade
        allowReturnTraffic: true
        autoConnect: true
"""


WG0 = """\
[Interface]
Address = 10.10.0.1/32
PrivateKey = server-private
ListenPort = 51820

[Peer]
PublicKey = existing-public
AllowedIPs = 10.10.0.2/32
PersistentKeepalive = 25
"""

CLIENT_PRIVATE_KEY = base64.b64encode(bytes(range(32))).decode("ascii")
CLIENT_PUBLIC_KEY = base64.b64encode(bytes(range(32, 64))).decode("ascii")
REMOTE_PUBLIC_KEY = base64.b64encode(bytes(range(64, 96))).decode("ascii")
NEW_REMOTE_PUBLIC_KEY = base64.b64encode(bytes(range(96, 128))).decode("ascii")
PRESHARED_KEY = base64.b64encode(bytes(range(128, 160))).decode("ascii")


class WireGuardControlTests(unittest.TestCase):
    def _service(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        directory = Path(temp.name)
        path = directory / "service.yaml"
        path.write_text(SERVICE, encoding="utf-8")
        (directory / "config").mkdir()
        (directory / "config" / "wg0.conf").write_text(WG0, encoding="utf-8")
        (directory / "config" / "wg1.conf").write_text("[Interface]\n", encoding="utf-8")
        (directory / "secrets" / "wg0").mkdir(parents=True)
        (directory / "secrets" / "wg0" / "public.key").write_text(
            "server-public\n", encoding="utf-8"
        )
        return load_service(path), directory

    def test_parser_handles_repeated_peer_sections(self):
        service, _ = self._service()
        interface, peers = parse_wireguard_config(service.directory / "config" / "wg0.conf")
        self.assertEqual(interface["Address"], "10.10.0.1/32")
        self.assertEqual(peers[0].public_key, "existing-public")
        self.assertEqual(peers[0].allowed_ips, ("10.10.0.2/32",))

    def test_terminal_qr_is_generated_without_system_qrencode(self):
        rendered = render_terminal_qr("[Interface]\nAddress = 10.10.0.9/32\n")
        self.assertTrue(any(character in rendered for character in "█▀▄"))
        self.assertLess(max(len(line) for line in rendered.splitlines()), 70)
        self.assertGreater(rendered.count("\n"), 10)

    def test_connection_maps_to_three_tagged_rules(self):
        connection = {
            "name": "wg0-to-wg1",
            "from": "wg0",
            "to": "wg1",
            "sourceNetwork": "10.10.0.0/24",
        }
        rules = _rule_specs(connection)
        self.assertEqual(len(rules), 3)
        rendered = " ".join(" ".join(rule) for _, _, rule in rules)
        self.assertIn("ncontrol:wg0-to-wg1:forward", rendered)
        self.assertIn("RELATED,ESTABLISHED", rendered)
        self.assertIn("MASQUERADE", rendered)
        legacy = _legacy_rule(rules[0][2])
        self.assertNotIn("--comment", legacy)
        self.assertEqual(
            legacy,
            ("-i", "wg0", "-o", "wg1", "-j", "ACCEPT"),
        )

    def test_import_is_metadata_only(self):
        service, _ = self._service()
        original = (service.directory / "config" / "wg0.conf").read_text(encoding="utf-8")
        self.assertEqual(import_peers(service, "wg0"), 1)
        self.assertEqual(
            (service.directory / "config" / "wg0.conf").read_text(encoding="utf-8"),
            original,
        )
        records = list_peer_records(service, "wg0")
        self.assertFalse(records[0]["managed"])
        self.assertEqual(records[0]["address"], "10.10.0.2/32")

    def test_sync_peer_route_uses_wireguard_interface(self):
        service, _ = self._service()
        with patch("homelabctl.wireguard_control._run") as run:
            run.return_value = subprocess.CompletedProcess((), 0, "", "")
            _sync_peer_route(service, "wg0", "10.10.0.6/32")

        self.assertEqual(
            run.call_args.args[0],
            ("sudo", "-n", "ip", "route", "replace", "10.10.0.6/32", "dev", "wg0"),
        )

    def test_interface_addresses_read_from_config(self):
        service, _ = self._service()
        self.assertEqual(interface_addresses(service, "wg0"), "10.10.0.1/32")

    def test_interface_peer_networks_read_from_config(self):
        service, directory = self._service()
        (directory / "config" / "wg1.conf").write_text(
            "[Interface]\nAddress = 192.168.7.3/32\n\n"
            "[Peer]\nPublicKey = remote\nAllowedIPs = 192.168.31.0/24, 192.168.7.0/24\n",
            encoding="utf-8",
        )
        self.assertEqual(
            interface_peer_networks(service, "wg1"),
            ("192.168.31.0/24", "192.168.7.0/24"),
        )

    def test_add_peer_allocates_address_and_writes_marked_block(self):
        service, directory = self._service()

        def fake_run(argv, *, input_text=None, check=False):
            values = tuple(argv)
            if values[-2:] == ("wg", "genkey"):
                return subprocess.CompletedProcess(values, 0, "client-private\n", "")
            if values[-2:] == ("wg", "pubkey"):
                self.assertEqual(input_text, "client-private\n")
                return subprocess.CompletedProcess(values, 0, "client-public\n", "")
            if "show" in values:
                return subprocess.CompletedProcess(values, 1, "", "not running")
            return subprocess.CompletedProcess(values, 0, "", "")

        with patch("homelabctl.wireguard_control._run", side_effect=fake_run):
            client_path = add_peer(service, "wg0", "new-phone")

        server_config = (directory / "config" / "wg0.conf").read_text(encoding="utf-8")
        self.assertIn("# NControl peer: new-phone", server_config)
        self.assertIn("AllowedIPs = 10.10.0.3/32", server_config)
        client_config = client_path.read_text(encoding="utf-8")
        self.assertIn("PrivateKey = client-private", client_config)
        self.assertIn("PublicKey = server-public", client_config)
        self.assertIn("192.168.31.0/24", client_config)
        metadata = yaml.safe_load((directory / "peers" / "new-phone.yaml").read_text(encoding="utf-8"))
        self.assertTrue(metadata["managed"])
        self.assertEqual(metadata["address"], "10.10.0.3/32")

    def test_create_server_interface_writes_config_and_service_definition(self):
        service, directory = self._service()
        calls: list[tuple[str, ...]] = []

        def fake_run(argv, *, input_text=None, check=False):
            values = tuple(argv)
            calls.append(values)
            if values == ("wg", "genkey"):
                return subprocess.CompletedProcess(values, 0, "new-private\n", "")
            if values == ("wg", "pubkey"):
                self.assertEqual(input_text, "new-private\n")
                return subprocess.CompletedProcess(values, 0, "new-public\n", "")
            if values[-3:] == ("wg", "show", "wg2"):
                return subprocess.CompletedProcess(values, 1, "", "not running")
            return subprocess.CompletedProcess(values, 0, "", "")

        with patch("homelabctl.wireguard_control._run", side_effect=fake_run):
            create_server_interface(
                service,
                "wg2",
                "10.20.0.1",
                "10.20.0.0/24",
                51821,
                "vpn.example.test:51821",
            )

        config = (directory / "config" / "wg2.conf").read_text(encoding="utf-8")
        self.assertIn("Address = 10.20.0.1/32", config)
        self.assertIn("PrivateKey = new-private", config)
        self.assertIn("ListenPort = 51821", config)
        self.assertEqual(
            (directory / "secrets" / "wg2" / "public.key").read_text(encoding="utf-8"),
            "new-public\n",
        )
        reloaded = load_service(directory / "service.yaml")
        interface = reloaded.spec["wireguard"]["interfaces"][-1]
        self.assertEqual(interface["name"], "wg2")
        self.assertEqual(interface["role"], "server")
        self.assertEqual(interface["peerManagement"]["addressPool"], "10.20.0.0/24")
        self.assertIn(
            ("sudo", "-n", "wg-quick", "up", str(directory / "config" / "wg2.conf")),
            calls,
        )

    def test_import_client_interface_copies_config_and_registers_it(self):
        service, directory = self._service()
        source = directory / "remote-client.conf"
        source.write_text(
            "[Interface]\n"
            "Address = 10.30.0.2/32\n"
            "PrivateKey = imported-private\n\n"
            "[Peer]\n"
            "PublicKey = remote-public\n"
            "AllowedIPs = 10.30.0.0/24\n"
            "Endpoint = remote.example.test:51820\n",
            encoding="utf-8",
        )

        def fake_run(argv, *, input_text=None, check=False):
            values = tuple(argv)
            if values[-3:] == ("wg", "show", "wg2"):
                return subprocess.CompletedProcess(values, 1, "", "not running")
            return subprocess.CompletedProcess(values, 0, "", "")

        with patch("homelabctl.wireguard_control._run", side_effect=fake_run):
            import_client_interface(service, "wg2", str(source))

        copied = (directory / "config" / "wg2.conf").read_text(encoding="utf-8")
        self.assertIn("Endpoint = remote.example.test:51820", copied)
        reloaded = load_service(directory / "service.yaml")
        interface = reloaded.spec["wireguard"]["interfaces"][-1]
        self.assertEqual(
            interface,
            {"name": "wg2", "role": "client", "config": "config/wg2.conf"},
        )

    def test_manual_client_creation_generates_public_key_and_settings(self):
        service, directory = self._service()
        calls: list[tuple[str, ...]] = []

        def fake_run(argv, *, input_text=None, check=False):
            values = tuple(argv)
            calls.append(values)
            if values == ("wg", "genkey"):
                return subprocess.CompletedProcess(values, 0, CLIENT_PRIVATE_KEY + "\n", "")
            if values == ("wg", "pubkey"):
                self.assertEqual(input_text, CLIENT_PRIVATE_KEY + "\n")
                return subprocess.CompletedProcess(values, 0, CLIENT_PUBLIC_KEY + "\n", "")
            if values[-3:] == ("wg", "show", "wg2"):
                return subprocess.CompletedProcess(values, 1, "", "not running")
            return subprocess.CompletedProcess(values, 0, "", "")

        with patch("homelabctl.wireguard_control._run", side_effect=fake_run):
            public_key = create_client_interface(
                service,
                "wg2",
                "192.168.7.2/32",
                REMOTE_PUBLIC_KEY,
                "qnap.example.test:51820",
                "192.168.7.0/24, 10.20.0.0/24",
                10,
                PRESHARED_KEY,
            )
            reloaded = load_service(directory / "service.yaml")
            settings = client_interface_settings(reloaded, "wg2")

        self.assertEqual(public_key, CLIENT_PUBLIC_KEY)
        self.assertEqual(settings["public_key"], CLIENT_PUBLIC_KEY)
        self.assertEqual(settings["peer_public_key"], REMOTE_PUBLIC_KEY)
        self.assertEqual(settings["endpoint"], "qnap.example.test:51820")
        self.assertEqual(settings["allowed_ips"], "192.168.7.0/24, 10.20.0.0/24")
        self.assertEqual(settings["preshared_key_configured"], "true")
        config = (directory / "config" / "wg2.conf").read_text(encoding="utf-8")
        self.assertIn(f"PrivateKey = {CLIENT_PRIVATE_KEY}", config)
        self.assertIn(f"PresharedKey = {PRESHARED_KEY}", config)
        self.assertIn("PersistentKeepalive = 10", config)
        self.assertIn(
            ("sudo", "-n", "wg-quick", "up", str(directory / "config" / "wg2.conf")),
            calls,
        )

    def test_client_interface_can_be_edited_without_exposing_private_key(self):
        service, directory = self._service()
        config = directory / "config" / "wg1.conf"
        config.write_text(
            "[Interface]\n"
            "Address = 192.168.7.2/32\n"
            f"PrivateKey = {CLIENT_PRIVATE_KEY}\n\n"
            "[Peer]\n"
            f"PublicKey = {REMOTE_PUBLIC_KEY}\n"
            f"PresharedKey = {PRESHARED_KEY}\n"
            "Endpoint = old-qnap.example.test:51820\n"
            "AllowedIPs = 192.168.7.0/24\n"
            "PersistentKeepalive = 10\n",
            encoding="utf-8",
        )
        calls: list[tuple[str, ...]] = []

        def fake_run(argv, *, input_text=None, check=False):
            values = tuple(argv)
            calls.append(values)
            if values == ("wg", "pubkey"):
                return subprocess.CompletedProcess(values, 0, CLIENT_PUBLIC_KEY + "\n", "")
            if values[-3:] == ("wg", "show", "wg1"):
                return subprocess.CompletedProcess(values, 0, "", "")
            return subprocess.CompletedProcess(values, 0, "", "")

        with patch("homelabctl.wireguard_control._run", side_effect=fake_run):
            edit_client_interface(
                service,
                "wg1",
                "192.168.7.3/32",
                NEW_REMOTE_PUBLIC_KEY,
                "new-qnap.example.test:51821",
                "192.168.7.0/24, 10.30.0.0/24",
                25,
                "-",
            )
            settings = client_interface_settings(service, "wg1")

        updated = config.read_text(encoding="utf-8")
        self.assertIn("Address = 192.168.7.3/32", updated)
        self.assertIn(f"PublicKey = {NEW_REMOTE_PUBLIC_KEY}", updated)
        self.assertIn("Endpoint = new-qnap.example.test:51821", updated)
        self.assertNotIn("PresharedKey", updated)
        self.assertNotIn(CLIENT_PRIVATE_KEY, str(settings))
        self.assertEqual(settings["public_key"], CLIENT_PUBLIC_KEY)
        self.assertIn(
            ("sudo", "-n", "wg-quick", "down", str(config)),
            calls,
        )
        self.assertIn(
            ("sudo", "-n", "wg-quick", "up", str(config)),
            calls,
        )

    def test_edit_server_interface_restarts_and_updates_definition(self):
        service, directory = self._service()
        calls: list[tuple[str, ...]] = []

        def fake_run(argv, *, input_text=None, check=False):
            values = tuple(argv)
            calls.append(values)
            return subprocess.CompletedProcess(values, 0, "", "")

        with patch("homelabctl.wireguard_control._run", side_effect=fake_run):
            edit_server_interface(
                service,
                "wg0",
                "10.10.0.1",
                "10.10.0.0/24",
                51822,
                "new-vpn.example.test:51822",
            )

        config = (directory / "config" / "wg0.conf").read_text(encoding="utf-8")
        self.assertIn("ListenPort = 51822", config)
        reloaded = load_service(directory / "service.yaml")
        management = reloaded.spec["wireguard"]["interfaces"][0]["peerManagement"]
        self.assertEqual(management["publicEndpoint"], "new-vpn.example.test:51822")
        self.assertIn(
            ("sudo", "-n", "wg-quick", "down", str(directory / "config" / "wg0.conf")),
            calls,
        )
        self.assertIn(
            ("sudo", "-n", "wg-quick", "up", str(directory / "config" / "wg0.conf")),
            calls,
        )

    def test_delete_server_interface_archives_generated_files(self):
        service, directory = self._service()

        def create_run(argv, *, input_text=None, check=False):
            values = tuple(argv)
            if values == ("wg", "genkey"):
                return subprocess.CompletedProcess(values, 0, "delete-private\n", "")
            if values == ("wg", "pubkey"):
                return subprocess.CompletedProcess(values, 0, "delete-public\n", "")
            if values[-3:] == ("wg", "show", "wg2"):
                return subprocess.CompletedProcess(values, 1, "", "not running")
            return subprocess.CompletedProcess(values, 0, "", "")

        with patch("homelabctl.wireguard_control._run", side_effect=create_run):
            create_server_interface(
                service,
                "wg2",
                "10.20.0.1",
                "10.20.0.0/24",
                51821,
                "vpn.example.test:51821",
            )

        reloaded = load_service(directory / "service.yaml")
        with patch("homelabctl.wireguard_control._run") as run:
            run.return_value = subprocess.CompletedProcess((), 1, "", "not running")
            delete_server_interface(reloaded, "wg2")

        final = load_service(directory / "service.yaml")
        self.assertNotIn(
            "wg2",
            [item["name"] for item in final.spec["wireguard"]["interfaces"]],
        )
        archived = list(
            (directory / "secrets" / "revoked" / "interfaces").glob(
                "*-wg2/config/wg2.conf"
            )
        )
        self.assertEqual(len(archived), 1)

    def test_delete_server_interface_blocks_referenced_interface(self):
        service, _ = self._service()
        with self.assertRaisesRegex(Exception, "wg0-to-wg1"):
            delete_server_interface(service, "wg0")

    def test_delete_client_interface_archives_config(self):
        service, directory = self._service()
        raw = yaml.safe_load((directory / "service.yaml").read_text(encoding="utf-8"))
        raw["spec"]["wireguard"]["connections"] = []
        raw["spec"]["config"] = {
            "files": [
                "config/wg0.conf",
                "config/wg1.conf",
                "secrets/wg1/private.key",
            ]
        }
        raw["spec"]["health"] = {
            "checks": [
                {
                    "name": "wg1-check",
                    "type": "wireguard-handshake",
                    "interface": "wg1",
                }
            ]
        }
        (directory / "service.yaml").write_text(
            yaml.safe_dump(raw, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        service = load_service(directory / "service.yaml")

        with patch("homelabctl.wireguard_control._run") as run:
            run.return_value = subprocess.CompletedProcess((), 1, "", "not running")
            delete_client_interface(service, "wg1")

        final = load_service(directory / "service.yaml")
        self.assertNotIn(
            "wg1",
            [item["name"] for item in final.spec["wireguard"]["interfaces"]],
        )
        self.assertEqual(final.spec["config"]["files"], ["config/wg0.conf"])
        self.assertEqual(final.spec["health"]["checks"], [])
        archived = list(
            (directory / "secrets" / "revoked" / "interfaces").glob(
                "*-wg1/config/wg1.conf"
            )
        )
        self.assertEqual(len(archived), 1)

    def test_delete_client_interface_blocks_referenced_interface(self):
        service, _ = self._service()
        with self.assertRaisesRegex(Exception, "wg0-to-wg1"):
            delete_client_interface(service, "wg1")

    def test_single_server_interface_can_start_and_stop(self):
        service, directory = self._service()
        calls: list[tuple[str, ...]] = []
        running = False

        def fake_run(argv, *, input_text=None, check=False):
            nonlocal running
            values = tuple(argv)
            calls.append(values)
            if values[-3:] == ("wg", "show", "wg0"):
                return subprocess.CompletedProcess(values, 0 if running else 1, "", "")
            if "wg-quick" in values and "up" in values:
                running = True
            elif "wg-quick" in values and "down" in values:
                running = False
            return subprocess.CompletedProcess(values, 0, "", "")

        with patch("homelabctl.wireguard_control._run", side_effect=fake_run):
            self.assertFalse(interface_status(service, "wg0", quiet=True))
            start_interface(service, "wg0")
            self.assertTrue(interface_status(service, "wg0", quiet=True))
            stop_interface(service, "wg0")
            self.assertFalse(interface_status(service, "wg0", quiet=True))

        config_path = str(directory / "config" / "wg0.conf")
        self.assertIn(("sudo", "-n", "wg-quick", "up", config_path), calls)
        self.assertIn(("sudo", "-n", "wg-quick", "down", config_path), calls)

    def test_sync_interface_applies_persistent_peers_without_restart(self):
        service, _ = self._service()
        calls: list[tuple[str, ...]] = []

        def fake_run(argv, *, input_text=None, check=False):
            values = tuple(argv)
            calls.append(values)
            return subprocess.CompletedProcess(values, 0, "", "")

        with patch("homelabctl.wireguard_control._run", side_effect=fake_run):
            count = sync_interface_runtime(service, "wg0")

        self.assertEqual(count, 1)
        self.assertIn(
            (
                "sudo",
                "-n",
                "wg",
                "set",
                "wg0",
                "peer",
                "existing-public",
                "allowed-ips",
                "10.10.0.2/32",
                "persistent-keepalive",
                "25",
            ),
            calls,
        )
        self.assertNotIn("wg-quick", {value for call in calls for value in call})

    def test_sudo_failure_is_not_reported_as_disconnected(self):
        service, _ = self._service()

        def fake_run(argv, *, input_text=None, check=False):
            values = tuple(argv)
            return subprocess.CompletedProcess(
                values,
                1,
                "",
                "sudo: a password is required",
            )

        with patch("homelabctl.wireguard_control._run", side_effect=fake_run):
            with self.assertRaisesRegex(HomelabError, "按 M.*按 W"):
                interface_status(service, "wg0", quiet=True)

    def test_traffic_snapshot_reports_peer_and_connection_counters(self):
        service, _ = self._service()

        def fake_run(argv, *, input_text=None, check=False):
            values = tuple(argv)
            if values[-4:] == ("wg", "show", "wg0", "dump"):
                return subprocess.CompletedProcess(
                    values,
                    0,
                    "server-private\tserver-public\t51820\toff\n"
                    "existing-public\t(none)\t198.51.100.8:9999\t"
                    "10.10.0.2/32\t100\t2048\t4096\t25\n",
                    "",
                )
            if values[-4:] == ("wg", "show", "wg1", "dump"):
                return subprocess.CompletedProcess(
                    values, 0, "client-private\tclient-public\t50000\toff\n", ""
                )
            if values[-2:] == ("iptables-save", "-c"):
                return subprocess.CompletedProcess(
                    values,
                    0,
                    '[4:1200] -A FORWARD -i wg0 -o wg1 -m comment '
                    '--comment "ncontrol:wg0-to-wg1:forward" -j ACCEPT\n'
                    '[3:800] -A FORWARD -i wg1 -o wg0 -m comment '
                    '--comment "ncontrol:wg0-to-wg1:return" -j ACCEPT\n',
                    "",
                )
            return subprocess.CompletedProcess(values, 1, "", "missing")

        with patch("homelabctl.wireguard_control._run", side_effect=fake_run):
            snapshot = traffic_snapshot(service)

        wg0 = snapshot["interfaces"][0]
        self.assertTrue(wg0["running"])
        self.assertEqual(wg0["receivedBytes"], 2048)
        self.assertEqual(wg0["sentBytes"], 4096)
        self.assertEqual(wg0["peers"][0]["latestHandshake"], 100)
        connection = snapshot["connections"][0]
        self.assertTrue(connection["available"])
        self.assertEqual(connection["forwardBytes"], 1200)
        self.assertEqual(connection["returnBytes"], 800)
        self.assertNotIn("server-private", str(snapshot))

    def test_network_connection_can_be_added_edited_and_deleted(self):
        service, directory = self._service()

        add_connection(
            service,
            "wg1-to-wg0",
            "wg1",
            "wg0",
            "192.168.7.0/24",
            "10.10.0.0/24",
            True,
            False,
        )
        reloaded = load_service(directory / "service.yaml")
        added = next(
            item
            for item in reloaded.spec["wireguard"]["connections"]
            if item["name"] == "wg1-to-wg0"
        )
        self.assertEqual(added["from"], "wg1")
        self.assertEqual(added["to"], "wg0")

        with patch("homelabctl.wireguard_control._run") as run:
            run.return_value = subprocess.CompletedProcess((), 1, "", "missing")
            edit_connection(
                reloaded,
                "wg1-to-wg0",
                "wg1",
                "wg0",
                "192.168.31.0/24",
                "10.10.0.0/24",
                False,
                True,
            )
        edited_service = load_service(directory / "service.yaml")
        edited = next(
            item
            for item in edited_service.spec["wireguard"]["connections"]
            if item["name"] == "wg1-to-wg0"
        )
        self.assertEqual(edited["sourceNetwork"], "192.168.31.0/24")
        self.assertFalse(edited["allowReturnTraffic"])
        self.assertTrue(edited["autoConnect"])

        with patch("homelabctl.wireguard_control._run") as run:
            run.return_value = subprocess.CompletedProcess((), 1, "", "missing")
            delete_connection(edited_service, "wg1-to-wg0")
        final = load_service(directory / "service.yaml")
        self.assertNotIn(
            "wg1-to-wg0",
            [item["name"] for item in final.spec["wireguard"]["connections"]],
        )
        archived = list(
            (directory / "secrets" / "revoked" / "connections").glob(
                "*-wg1-to-wg0.yaml"
            )
        )
        self.assertEqual(len(archived), 1)

    def test_connection_destinations_update_managed_client_routes(self):
        service, directory = self._service()
        (directory / "peers").mkdir()
        (directory / "secrets" / "clients").mkdir(parents=True)
        (directory / "peers" / "phone.yaml").write_text(
            "id: phone\n"
            "name: phone\n"
            "interface: wg0\n"
            "publicKey: phone-public\n"
            "profile: linked\n"
            "clientConfig: secrets/clients/phone.conf\n"
            "managed: true\n",
            encoding="utf-8",
        )
        client_path = directory / "secrets" / "clients" / "phone.conf"
        client_path.write_text(
            "[Interface]\nAddress = 10.10.0.6/32\nPrivateKey = private\n\n"
            "[Peer]\nPublicKey = server-public\n"
            "Endpoint = vpn.example.test:51820\n"
            "AllowedIPs = 10.10.0.0/24, 192.168.31.0/24\n",
            encoding="utf-8",
        )

        add_connection(
            service,
            "wg0-extra-route",
            "wg0",
            "wg1",
            "10.10.0.0/24",
            "172.16.0.0/16",
            True,
            False,
        )

        rendered = client_path.read_text(encoding="utf-8")
        self.assertIn("172.16.0.0/16", rendered)


if __name__ == "__main__":
    unittest.main()
