from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import load_all, resolve_declared_paths
from .models import CheckResult, ServiceDefinition
from .wireguard_control import parse_wireguard_config


@dataclass(frozen=True)
class PortUse:
    service: str
    label: str
    protocol: str
    port: int


@dataclass(frozen=True)
class NetworkUse:
    service: str
    interface: str
    label: str
    network: ipaddress.IPv4Network


def _health_ports(service: ServiceDefinition) -> list[PortUse]:
    values: list[PortUse] = []
    for index, check in enumerate(service.spec.get("health", {}).get("checks", [])):
        check_type = check.get("type")
        port: int | None = None
        if check_type == "tcp":
            port = int(check["port"])
        elif check_type == "http":
            parsed = urlparse(str(check["url"]))
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port is not None:
            values.append(
                PortUse(
                    service.name,
                    str(check.get("name", f"health-{index + 1}")),
                    "tcp",
                    port,
                )
            )
    return values


def _wireguard_inventory(
    service: ServiceDefinition,
) -> tuple[list[PortUse], list[NetworkUse], list[tuple[str, str]]]:
    ports: list[PortUse] = []
    networks: list[NetworkUse] = []
    keys: list[tuple[str, str]] = []
    section = service.spec.get("wireguard", {})
    interfaces = section.get("interfaces", [])
    if not isinstance(interfaces, list):
        return ports, networks, keys
    for raw in interfaces:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name", "?"))
        try:
            config_path = resolve_declared_paths(service, [str(raw["config"])])[0]
            interface_values, peers = parse_wireguard_config(config_path)
        except (OSError, KeyError, ValueError):
            continue
        listen_port = interface_values.get("ListenPort")
        if listen_port and str(listen_port).isdigit():
            ports.append(PortUse(service.name, name, "udp", int(listen_port)))
        for value in str(interface_values.get("Address", "")).split(","):
            if not value.strip():
                continue
            try:
                network = ipaddress.ip_interface(value.strip()).network
            except ValueError:
                continue
            if network.version == 4:
                networks.append(NetworkUse(service.name, name, "接口地址", network))
        private_key = str(interface_values.get("PrivateKey", "")).strip()
        if private_key:
            fingerprint = hashlib.sha256(private_key.encode("utf-8")).hexdigest()
            keys.append((f"{service.name}/{name}", fingerprint))
        management = raw.get("peerManagement")
        if isinstance(management, dict) and management.get("addressPool"):
            try:
                pool = ipaddress.ip_network(str(management["addressPool"]), strict=False)
            except ValueError:
                pass
            else:
                if pool.version == 4:
                    networks.append(NetworkUse(service.name, name, "地址池", pool))
        if raw.get("role") == "client":
            for peer_index, peer in enumerate(peers):
                for value in peer.allowed_ips:
                    try:
                        network = ipaddress.ip_network(value.strip(), strict=False)
                    except ValueError:
                        continue
                    if network.version == 4:
                        networks.append(
                            NetworkUse(service.name, name, f"客户端路由 {peer_index + 1}", network)
                        )
        public_path = service.directory / "secrets" / name / "public.key"
        try:
            public_value = public_path.read_text(encoding="utf-8").strip()
        except OSError:
            public_value = ""
        if public_value:
            fingerprint = hashlib.sha256(public_value.encode("utf-8")).hexdigest()
            keys.append((f"{service.name}/{name} 公钥", f"public:{fingerprint}"))
    return ports, networks, keys


def audit_services(root: Path) -> list[CheckResult]:
    services = load_all(root)
    results: list[CheckResult] = []
    ports: list[PortUse] = []
    networks: list[NetworkUse] = []
    keys: list[tuple[str, str]] = []
    for service in services:
        ports.extend(_health_ports(service))
        if service.driver == "wireguard":
            item_ports, item_networks, item_keys = _wireguard_inventory(service)
            ports.extend(item_ports)
            networks.extend(item_networks)
            keys.extend(item_keys)

    port_conflicts = 0
    for index, left in enumerate(ports):
        for right in ports[index + 1 :]:
            if left.protocol != right.protocol or left.port != right.port:
                continue
            if left.service == right.service and left.label == right.label:
                continue
            port_conflicts += 1
            results.append(
                CheckResult(
                    "error",
                    f"端口冲突: {left.protocol.upper()} {left.port} 同时用于 "
                    f"{left.service}/{left.label} 和 {right.service}/{right.label}",
                )
            )

    network_conflicts = 0
    for index, left in enumerate(networks):
        for right in networks[index + 1 :]:
            if left.interface == right.interface and left.service == right.service:
                continue
            if not left.network.overlaps(right.network):
                continue
            network_conflicts += 1
            results.append(
                CheckResult(
                    "warning",
                    f"网段重叠: {left.service}/{left.interface} {left.network}（{left.label}）与 "
                    f"{right.service}/{right.interface} {right.network}（{right.label}）",
                )
            )

    duplicate_pairs: set[tuple[str, str]] = set()
    for index, (left_name, left_key) in enumerate(keys):
        for right_name, right_key in keys[index + 1 :]:
            if left_key != right_key or left_name.split(" ")[0] == right_name.split(" ")[0]:
                continue
            left_interface = left_name.split(" ")[0]
            right_interface = right_name.split(" ")[0]
            pair = tuple(sorted((left_interface, right_interface)))
            if pair in duplicate_pairs:
                continue
            duplicate_pairs.add(pair)
            results.append(
                CheckResult(
                    "error",
                    f"WireGuard 密钥重复: {left_interface} 与 {right_interface} 使用相同密钥",
                )
            )

    if not port_conflicts:
        results.append(CheckResult("ok", f"端口检查通过，共识别 {len(ports)} 个监听端口"))
    if not network_conflicts:
        results.append(CheckResult("ok", f"网段检查通过，共识别 {len(networks)} 个网段"))
    if not duplicate_pairs:
        results.append(CheckResult("ok", "WireGuard 密钥未发现重复"))
    return results

