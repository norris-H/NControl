from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from .config import load_service, resolve_declared_paths
from .errors import ConfigError, HomelabError
from .models import ServiceDefinition


PEER_START = "# NControl peer: "
PEER_END = "# NControl peer-end: "


@dataclass(frozen=True)
class ParsedPeer:
    public_key: str
    allowed_ips: tuple[str, ...]
    persistent_keepalive: str | None = None


def _run(
    argv: Iterable[str],
    *,
    input_text: str | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            tuple(argv),
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        raise HomelabError(f"找不到可执行程序: {tuple(argv)[0]}") from exc
    if check and result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or f"退出码 {result.returncode}"
        raise HomelabError(f"命令执行失败: {message}")
    return result


def _wireguard_service(path: Path) -> ServiceDefinition:
    service = load_service(path)
    if service.driver != "wireguard":
        raise HomelabError(f"{service.name} 不是 WireGuard 服务")
    return service


def _section(service: ServiceDefinition) -> dict[str, Any]:
    return service.spec["wireguard"]


def _interfaces(service: ServiceDefinition) -> list[dict[str, Any]]:
    section = _section(service)
    values = section.get("interfaces")
    if isinstance(values, list):
        return values
    return [
        {
            "name": section["interface"],
            "role": "server",
            "config": section["config"],
        }
    ]


def _interface(service: ServiceDefinition, name: str) -> dict[str, Any]:
    for value in _interfaces(service):
        if value.get("name") == name:
            return value
    raise HomelabError(f"未找到 WireGuard 接口: {name}")


def _connection(service: ServiceDefinition, name: str) -> dict[str, Any]:
    values = _section(service).get("connections", [])
    for value in values:
        if isinstance(value, dict) and value.get("name") == name:
            return value
    raise HomelabError(f"未找到 WireGuard 网络连接: {name}")


def _sudo_prefix(service: ServiceDefinition) -> tuple[str, ...]:
    return ("sudo", "-n") if _section(service).get("sudo", True) else ()


def _wg_show(
    service: ServiceDefinition,
    interface_name: str,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    result = _run(
        (*_sudo_prefix(service), "wg", "show", interface_name, *arguments)
    )
    if result.returncode == 0:
        return result
    detail = (result.stderr or result.stdout).strip()
    normalized = detail.lower()
    permission_markers = (
        "password is required",
        "a terminal is required",
        "not in the sudoers",
        "not allowed to execute",
        "permission denied",
    )
    if _sudo_prefix(service) and any(marker in normalized for marker in permission_markers):
        raise HomelabError(
            "NControl 没有 WireGuard 免交互权限；请返回主界面按 M，"
            "再按 W 配置 WireGuard 主机"
        )
    return result


def _sync_peer_route(
    service: ServiceDefinition,
    interface_name: str,
    address: str,
) -> None:
    """Ensure a hot-added peer has a kernel route through its WireGuard interface.

    wg-quick creates these routes when an interface is brought up from its
    config file, but ``wg set`` (used for zero-downtime peer changes) only
    updates WireGuard's peer table.  Without this explicit route, replies to a
    newly added client follow the server's default route instead of wg0.
    """
    network = ipaddress.ip_interface(address).network
    result = _run(
        (
            *_sudo_prefix(service),
            "ip", "route", "replace", str(network),
            "dev", interface_name,
        )
    )
    if result.returncode != 0:
        raise HomelabError(
            f"客户端路由更新失败: "
            f"{result.stderr.strip() or result.stdout.strip() or result.returncode}"
        )


def _remove_peer_route(
    service: ServiceDefinition,
    interface_name: str,
    address: str,
) -> None:
    network = ipaddress.ip_interface(address).network
    _run(
        (
            *_sudo_prefix(service),
            "ip", "route", "del", str(network),
            "dev", interface_name,
        )
    )


def _rule_specs(connection: dict[str, Any]) -> list[tuple[str, str, tuple[str, ...]]]:
    name = str(connection["name"])
    source = str(connection["sourceNetwork"])
    inbound = str(connection["from"])
    outbound = str(connection["to"])
    rules = [
        (
            "filter",
            "FORWARD",
            (
                "-i", inbound, "-o", outbound,
                "-m", "comment", "--comment", f"ncontrol:{name}:forward",
                "-j", "ACCEPT",
            ),
        ),
    ]
    if connection.get("allowReturnTraffic", True):
        rules.append((
            "filter",
            "FORWARD",
            (
                "-i", outbound, "-o", inbound,
                "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
                "-m", "comment", "--comment", f"ncontrol:{name}:return",
                "-j", "ACCEPT",
            ),
        ))
    rules.append((
            "nat",
            "POSTROUTING",
            (
                "-s", source, "-o", outbound,
                "-m", "comment", "--comment", f"ncontrol:{name}:nat",
                "-j", "MASQUERADE",
            ),
        ))
    return rules


def _iptables_argv(
    service: ServiceDefinition,
    table: str,
    action: str,
    chain: str,
    rule: tuple[str, ...],
) -> tuple[str, ...]:
    table_args = ("-t", table) if table != "filter" else ()
    position = ("1",) if action == "-I" else ()
    return (
        *_sudo_prefix(service),
        "iptables",
        "-w",
        "5",
        *table_args,
        action,
        chain,
        *position,
        *rule,
    )


def _legacy_rule(rule: tuple[str, ...]) -> tuple[str, ...]:
    values = list(rule)
    try:
        index = values.index("--comment")
    except ValueError:
        return rule
    # The generated form is always: -m comment --comment <tag>.
    del values[index - 2:index + 2]
    return tuple(values)


def _rule_state(
    service: ServiceDefinition,
    table: str,
    chain: str,
    rule: tuple[str, ...],
) -> tuple[bool, bool]:
    managed = _run(_iptables_argv(service, table, "-C", chain, rule)).returncode == 0
    legacy = False
    if not managed:
        legacy = (
            _run(_iptables_argv(service, table, "-C", chain, _legacy_rule(rule))).returncode
            == 0
        )
    return managed, legacy


def connection_status(service: ServiceDefinition, name: str, *, quiet: bool = False) -> bool:
    connection = _connection(service, name)
    forwarding = False
    try:
        forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    except OSError:
        pass
    states: list[tuple[bool, bool]] = []
    for table, chain, rule in _rule_specs(connection):
        states.append(_rule_state(service, table, chain, rule))
    complete = forwarding and all(managed or legacy for managed, legacy in states)
    if not quiet:
        print(f"IPv4 转发: {'已开启' if forwarding else '未开启'}")
        labels = ["正向转发"]
        if connection.get("allowReturnTraffic", True):
            labels.append("返回流量")
        labels.append("NAT")
        for label, (managed, legacy) in zip(labels, states):
            state = "已由 NControl 管理" if managed else "旧规则已生效" if legacy else "缺失"
            print(f"{label}: {state}")
        if complete and any(legacy for _, legacy in states):
            print("旧规则已生效，但尚未由 NControl 接管")
    return complete


def connect(service: ServiceDefinition, name: str) -> None:
    connection = _connection(service, name)
    for interface_name in (str(connection["from"]), str(connection["to"])):
        result = _wg_show(service, interface_name)
        if result.returncode != 0:
            raise HomelabError(f"接口 {interface_name} 未运行，已阻止建立连接")
    try:
        forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    except OSError as exc:
        raise HomelabError("无法检查 IPv4 转发状态") from exc
    if forwarding != "1":
        raise HomelabError("IPv4 转发未开启；为避免隐藏修改系统设置，NControl 不会自动开启")

    added: list[tuple[str, str, tuple[str, ...]]] = []
    try:
        for table, chain, rule in _rule_specs(connection):
            managed, legacy = _rule_state(service, table, chain, rule)
            if managed or legacy:
                continue
            _run(_iptables_argv(service, table, "-I", chain, rule), check=True)
            added.append((table, chain, rule))
    except HomelabError:
        for table, chain, rule in reversed(added):
            _run(_iptables_argv(service, table, "-D", chain, rule))
        raise
    print(f"网络连接 {name} 已启用")


def disconnect(service: ServiceDefinition, name: str) -> None:
    connection = _connection(service, name)
    if any(
        legacy
        for table, chain, rule in _rule_specs(connection)
        for _, legacy in [_rule_state(service, table, chain, rule)]
    ):
        raise HomelabError("检测到未标记的旧规则；请先执行“接管旧规则”，避免误删")
    for table, chain, rule in reversed(_rule_specs(connection)):
        while _run(_iptables_argv(service, table, "-C", chain, rule)).returncode == 0:
            _run(_iptables_argv(service, table, "-D", chain, rule), check=True)
    print(f"网络连接 {name} 已断开")


def adopt_connection(service: ServiceDefinition, name: str) -> None:
    connection = _connection(service, name)
    pending: list[tuple[str, str, tuple[str, ...]]] = []
    for table, chain, rule in _rule_specs(connection):
        managed, legacy = _rule_state(service, table, chain, rule)
        if not managed:
            if not legacy:
                raise HomelabError("旧规则不完整，已阻止接管；请先检查连接状态")
            pending.append((table, chain, rule))

    converted: list[tuple[str, str, tuple[str, ...]]] = []
    try:
        for table, chain, rule in pending:
            _run(_iptables_argv(service, table, "-I", chain, rule), check=True)
            legacy_rule = _legacy_rule(rule)
            try:
                while _run(
                    _iptables_argv(service, table, "-C", chain, legacy_rule)
                ).returncode == 0:
                    _run(
                        _iptables_argv(service, table, "-D", chain, legacy_rule),
                        check=True,
                    )
            except HomelabError:
                _run(_iptables_argv(service, table, "-D", chain, rule))
                raise
            converted.append((table, chain, rule))
    except HomelabError:
        # Restore the exact legacy rules before removing their managed replacements.
        for table, chain, rule in reversed(converted):
            if _run(
                _iptables_argv(service, table, "-C", chain, _legacy_rule(rule))
            ).returncode != 0:
                _run(
                    _iptables_argv(service, table, "-I", chain, _legacy_rule(rule))
                )
            _run(_iptables_argv(service, table, "-D", chain, rule))
        raise
    print(f"网络连接 {name} 已接管，转换 {len(converted)} 条旧规则")


def parse_wireguard_config(path: Path) -> tuple[dict[str, str], list[ParsedPeer]]:
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    section = ""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise HomelabError(f"无法读取 WireGuard 配置: {path}") from exc
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.lower() == "[interface]":
            section = "interface"
            current = None
            continue
        if line.lower() == "[peer]":
            section = "peer"
            current = {}
            peers.append(current)
            continue
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if section == "interface":
            interface[key] = value
        elif section == "peer" and current is not None:
            current[key] = value
    parsed: list[ParsedPeer] = []
    for peer in peers:
        public_key = peer.get("PublicKey")
        if not public_key:
            continue
        allowed = tuple(
            value.strip() for value in peer.get("AllowedIPs", "").split(",") if value.strip()
        )
        parsed.append(
            ParsedPeer(
                public_key=public_key,
                allowed_ips=allowed,
                persistent_keepalive=peer.get("PersistentKeepalive"),
            )
        )
    return interface, parsed


def _service_path(service: ServiceDefinition, value: str) -> Path:
    return resolve_declared_paths(service, [value])[0]


def interface_addresses(service: ServiceDefinition, interface_name: str) -> str:
    """Return the configured address field for a WireGuard interface."""
    interface = _interface(service, interface_name)
    config_path = _service_path(service, str(interface["config"]))
    values, _ = parse_wireguard_config(config_path)
    return values.get("Address", "未配置")


def interface_peer_networks(
    service: ServiceDefinition,
    interface_name: str,
) -> tuple[str, ...]:
    """Return the destination networks configured behind an interface peer."""
    interface = _interface(service, interface_name)
    config_path = _service_path(service, str(interface["config"]))
    _, peers = parse_wireguard_config(config_path)
    values = {allowed for peer in peers for allowed in peer.allowed_ips}
    return tuple(sorted(values))


def _management(interface: dict[str, Any]) -> dict[str, Any]:
    value = interface.get("peerManagement")
    if not isinstance(value, dict):
        raise HomelabError(f"接口 {interface.get('name')} 未启用客户端管理")
    return value


def _managed_directory(
    service: ServiceDefinition,
    management: dict[str, Any],
    field: str,
    default: str,
) -> Path:
    path = _service_path(service, str(management.get(field, default)))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _peer_records(service: ServiceDefinition, interface: dict[str, Any]) -> list[dict[str, Any]]:
    management = _management(interface)
    directory = _managed_directory(service, management, "metadataDirectory", "peers")
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.yaml")):
        try:
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(value, dict) and value.get("interface") == interface.get("name"):
            value["_metadataPath"] = str(path)
            records.append(value)
    return records


def list_peer_records(service: ServiceDefinition, interface_name: str) -> list[dict[str, Any]]:
    interface = _interface(service, interface_name)
    records = _peer_records(service, interface)
    config_path = _service_path(service, str(interface["config"]))
    _, configured = parse_wireguard_config(config_path)
    by_key = {str(record.get("publicKey")): record for record in records}
    result: list[dict[str, Any]] = []
    for peer in configured:
        record = dict(by_key.get(peer.public_key, {}))
        record.setdefault("id", "unregistered")
        record.setdefault("name", "未登记客户端")
        record.setdefault("managed", False)
        record["publicKey"] = peer.public_key
        record["allowedIPs"] = list(peer.allowed_ips)
        result.append(record)
    return result


def _peer_id(name: str) -> str:
    ascii_name = name.encode("ascii", errors="ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9_.-]+", "-", ascii_name).strip("-.")
    if not slug:
        slug = f"peer-{hashlib.sha256(name.encode('utf-8')).hexdigest()[:10]}"
    return slug[:64]


def _atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def _validate_new_interface_name(service: ServiceDefinition, name: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", name):
        raise HomelabError("接口名必须为 1-15 位字母、数字、点、下划线或连字符")
    if any(str(item.get("name")) == name for item in _interfaces(service)):
        raise HomelabError(f"WireGuard 接口已存在: {name}")


def _append_interface(service: ServiceDefinition, interface: dict[str, Any]) -> None:
    original = service.path.read_text(encoding="utf-8")
    raw = copy.deepcopy(service.raw)
    section = raw["spec"]["wireguard"]
    interfaces = section.get("interfaces")
    if not isinstance(interfaces, list):
        raise HomelabError("旧版单接口配置无法直接追加接口，请先转换为 interfaces 格式")
    interfaces.append(interface)
    rendered = yaml.safe_dump(raw, allow_unicode=True, sort_keys=False)
    mode = service.path.stat().st_mode & 0o777
    _atomic_write(service.path, rendered, mode=mode)
    try:
        load_service(service.path)
    except Exception:
        _atomic_write(service.path, original, mode=mode)
        raise


def _start_new_interface(
    service: ServiceDefinition,
    interface_name: str,
    config_path: Path,
) -> str | None:
    running = _wg_show(service, interface_name)
    if running.returncode == 0:
        return None
    result = _run((*_sudo_prefix(service), "wg-quick", "up", str(config_path)))
    if result.returncode != 0:
        return result.stderr.strip() or result.stdout.strip() or f"退出码 {result.returncode}"
    return None


def interface_status(
    service: ServiceDefinition,
    interface_name: str,
    *,
    quiet: bool = False,
) -> bool:
    _interface(service, interface_name)
    running = _wg_show(service, interface_name).returncode == 0
    if not quiet:
        print(f"接口 {interface_name}: {'已连接' if running else '已断开'}")
    return running


def sync_interface_runtime(service: ServiceDefinition, interface_name: str) -> int:
    """Apply persistent server peers to a live interface without restarting it."""
    interface = _interface(service, interface_name)
    if interface.get("role") != "server":
        raise HomelabError("只能同步服务端接口的客户端配置")
    if _wg_show(service, interface_name).returncode != 0:
        raise HomelabError(f"WireGuard 服务端 {interface_name} 尚未运行")

    config_path = _service_path(service, str(interface["config"]))
    _, peers = parse_wireguard_config(config_path)
    for peer in peers:
        command = (
            *_sudo_prefix(service),
            "wg",
            "set",
            interface_name,
            "peer",
            peer.public_key,
            "allowed-ips",
            ",".join(peer.allowed_ips),
        )
        if peer.persistent_keepalive:
            command = (
                *command,
                "persistent-keepalive",
                peer.persistent_keepalive,
            )
        _run(command, check=True)
        for allowed_ip in peer.allowed_ips:
            _sync_peer_route(service, interface_name, allowed_ip)
    print(f"服务端 {interface_name} 已同步 {len(peers)} 个客户端到运行接口")
    return len(peers)


def start_interface(service: ServiceDefinition, interface_name: str) -> None:
    interface = _interface(service, interface_name)
    if interface.get("role") != "server":
        raise HomelabError("此操作只用于单独控制服务端接口")
    if interface_status(service, interface_name, quiet=True):
        sync_interface_runtime(service, interface_name)
        return
    config_path = _service_path(service, str(interface["config"]))
    result = _run((*_sudo_prefix(service), "wg-quick", "up", str(config_path)))
    if result.returncode != 0:
        raise HomelabError(
            f"服务端 {interface_name} 连接失败: "
            f"{result.stderr.strip() or result.stdout.strip() or result.returncode}"
        )
    print(f"WireGuard 服务端 {interface_name} 已连接")


def stop_interface(service: ServiceDefinition, interface_name: str) -> None:
    interface = _interface(service, interface_name)
    if interface.get("role") != "server":
        raise HomelabError("此操作只用于单独控制服务端接口")
    if not interface_status(service, interface_name, quiet=True):
        print(f"WireGuard 服务端 {interface_name} 已断开")
        return
    config_path = _service_path(service, str(interface["config"]))
    result = _run((*_sudo_prefix(service), "wg-quick", "down", str(config_path)))
    if result.returncode != 0:
        raise HomelabError(
            f"服务端 {interface_name} 断开失败: "
            f"{result.stderr.strip() or result.stdout.strip() or result.returncode}"
        )
    print(f"WireGuard 服务端 {interface_name} 已断开；配置和客户端资料保持不变")


def traffic_snapshot(service: ServiceDefinition) -> dict[str, Any]:
    """Return WireGuard and managed-forwarding counters without exposing private keys."""
    sampled_at = time.time()
    interfaces: list[dict[str, Any]] = []
    for interface in _interfaces(service):
        name = str(interface["name"])
        result = _wg_show(service, name, "dump")
        item: dict[str, Any] = {
            "name": name,
            "running": result.returncode == 0,
            "receivedBytes": 0,
            "sentBytes": 0,
            "latestHandshake": 0,
            "peers": [],
        }
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            for line in lines[1:]:
                values = line.split("\t")
                if len(values) < 8:
                    continue
                try:
                    latest = int(values[4])
                    received = int(values[5])
                    sent = int(values[6])
                except ValueError:
                    continue
                peer = {
                    "publicKey": values[0],
                    "endpoint": "" if values[2] == "(none)" else values[2],
                    "allowedIPs": [] if values[3] == "(none)" else values[3].split(","),
                    "latestHandshake": latest,
                    "receivedBytes": received,
                    "sentBytes": sent,
                }
                item["peers"].append(peer)
                item["receivedBytes"] += received
                item["sentBytes"] += sent
                item["latestHandshake"] = max(item["latestHandshake"], latest)
        interfaces.append(item)

    connections: dict[str, dict[str, Any]] = {
        str(value["name"]): {
            "name": str(value["name"]),
            "available": False,
            "forwardBytes": 0,
            "returnBytes": 0,
        }
        for value in _section(service).get("connections", [])
        if isinstance(value, dict) and value.get("name")
    }
    if connections:
        counters = _run((*_sudo_prefix(service), "iptables-save", "-c"))
        if counters.returncode == 0:
            pattern = re.compile(
                r'^\[(\d+):(\d+)\]\s+-A\s+FORWARD\b.*?'
                r'--comment\s+"?ncontrol:([^"\s]+):(forward|return)"?'
            )
            for line in counters.stdout.splitlines():
                match = pattern.search(line)
                if not match:
                    continue
                _, byte_value, name, direction = match.groups()
                if name not in connections:
                    continue
                connections[name]["available"] = True
                field = "forwardBytes" if direction == "forward" else "returnBytes"
                connections[name][field] += int(byte_value)

    return {
        "sampledAt": sampled_at,
        "interfaces": interfaces,
        "connections": list(connections.values()),
    }


def create_server_interface(
    service: ServiceDefinition,
    interface_name: str,
    address: str,
    address_pool: str,
    listen_port: int,
    public_endpoint: str,
) -> None:
    _validate_new_interface_name(service, interface_name)
    try:
        pool = ipaddress.ip_network(address_pool, strict=False)
        server = ipaddress.ip_interface(address if "/" in address else f"{address}/32")
    except ValueError as exc:
        raise HomelabError("服务端地址或地址池格式无效") from exc
    if pool.version != 4 or server.version != 4:
        raise HomelabError("目前只支持 IPv4 WireGuard 地址")
    if server.ip not in pool:
        raise HomelabError(f"服务端地址 {server.ip} 不在地址池 {pool} 内")
    if not 1 <= listen_port <= 65535:
        raise HomelabError("监听端口必须在 1-65535 之间")
    if not public_endpoint.strip() or ":" not in public_endpoint:
        raise HomelabError("公网入口格式应为 主机名或IP:端口")

    config_value = f"config/{interface_name}.conf"
    public_key_value = f"secrets/{interface_name}/public.key"
    config_path = _service_path(service, config_value)
    public_key_path = _service_path(service, public_key_value)
    if config_path.exists() or public_key_path.exists():
        raise HomelabError(f"接口 {interface_name} 的配置或密钥文件已存在")

    private_key = _run(("wg", "genkey"), check=True).stdout.strip()
    public_key = _run(("wg", "pubkey"), input_text=f"{private_key}\n", check=True).stdout.strip()
    if not private_key or not public_key:
        raise HomelabError("WireGuard 密钥生成失败")

    server_address = f"{server.ip}/32"
    config = "\n".join(
        [
            "[Interface]",
            f"Address = {server_address}",
            f"PrivateKey = {private_key}",
            f"ListenPort = {listen_port}",
            "",
        ]
    )
    interface = {
        "name": interface_name,
        "role": "server",
        "config": config_value,
        "peerManagement": {
            "addressPool": str(pool),
            "publicEndpoint": public_endpoint.strip(),
            "serverPublicKeyFile": public_key_value,
            "metadataDirectory": f"peers/{interface_name}",
            "clientOutputDirectory": f"secrets/clients/{interface_name}",
            "defaultAccessProfile": "wireguard-network",
            "accessProfiles": {
                "server-only": {
                    "description": "仅访问 WireGuard 服务端",
                    "allowedIPs": [server_address],
                },
                "wireguard-network": {
                    "description": "访问整个 WireGuard 网段",
                    "allowedIPs": [str(pool)],
                },
            },
        },
    }

    _atomic_write(config_path, config)
    _atomic_write(public_key_path, f"{public_key}\n")
    try:
        _append_interface(service, interface)
    except Exception:
        config_path.unlink(missing_ok=True)
        public_key_path.unlink(missing_ok=True)
        raise

    start_error = _start_new_interface(service, interface_name, config_path)
    print(f"已新建 WireGuard 服务端 {interface_name}: {server_address}")
    print(f"公网入口: {public_endpoint.strip()}")
    if start_error:
        print(f"配置已保存，但接口启动失败: {start_error}")
    else:
        print("接口已启动；NControl 未修改云防火墙或安全组")


def import_client_interface(
    service: ServiceDefinition,
    interface_name: str,
    source_config: str,
) -> None:
    _validate_new_interface_name(service, interface_name)
    source_path = Path(source_config).expanduser().resolve()
    try:
        content = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise HomelabError(f"无法读取客户端配置: {source_path}") from exc
    interface_values, peers = parse_wireguard_config(source_path)
    if not interface_values.get("PrivateKey") or not interface_values.get("Address"):
        raise HomelabError("客户端配置缺少 Interface.PrivateKey 或 Address")
    if not peers:
        raise HomelabError("客户端配置没有有效的 Peer")
    if not re.search(r"(?im)^\s*Endpoint\s*=\s*\S+", content):
        raise HomelabError("客户端配置缺少 Peer.Endpoint")

    config_value = f"config/{interface_name}.conf"
    config_path = _service_path(service, config_value)
    if config_path.exists():
        raise HomelabError(f"目标配置已存在: {config_path}")
    _atomic_write(config_path, content.rstrip() + "\n")
    try:
        _append_interface(
            service,
            {"name": interface_name, "role": "client", "config": config_value},
        )
    except Exception:
        config_path.unlink(missing_ok=True)
        raise

    start_error = _start_new_interface(service, interface_name, config_path)
    print(f"已导入 WireGuard 客户端 {interface_name}: {interface_values['Address']}")
    if start_error:
        print(f"配置已保存，但接口启动失败: {start_error}")
    else:
        print("客户端接口已启动")


def _connection_definition(
    service: ServiceDefinition,
    name: str,
    source: str,
    target: str,
    source_network: str,
    destination_networks: str,
    allow_return_traffic: bool,
    auto_connect: bool,
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        raise HomelabError("连接名称只能包含字母、数字、点、下划线和连字符")
    interface_names = {str(item.get("name")) for item in _interfaces(service)}
    if source not in interface_names or target not in interface_names:
        raise HomelabError("来源接口或目标接口不存在")
    if source == target:
        raise HomelabError("来源接口和目标接口不能相同")
    try:
        network = ipaddress.ip_network(source_network, strict=False)
    except ValueError as exc:
        raise HomelabError("来源网段格式无效") from exc
    if network.version != 4:
        raise HomelabError("目前只支持 IPv4 来源网段")
    destinations: list[str] = []
    for value in destination_networks.split(","):
        candidate = value.strip()
        if not candidate:
            continue
        try:
            destination = ipaddress.ip_network(candidate, strict=False)
        except ValueError as exc:
            raise HomelabError(f"目标网段格式无效: {candidate}") from exc
        if destination.version != 4:
            raise HomelabError("目前只支持 IPv4 目标网段")
        normalized = str(destination)
        if normalized not in destinations:
            destinations.append(normalized)
    return {
        "name": name,
        "from": source,
        "to": target,
        "sourceNetwork": str(network),
        "destinationNetworks": destinations,
        "mode": "masquerade",
        "allowReturnTraffic": allow_return_traffic,
        "autoConnect": auto_connect,
    }


def _write_service_raw(service: ServiceDefinition, raw: dict[str, Any]) -> ServiceDefinition:
    original = service.path.read_text(encoding="utf-8")
    mode = service.path.stat().st_mode & 0o777
    _atomic_write(
        service.path,
        yaml.safe_dump(raw, allow_unicode=True, sort_keys=False),
        mode=mode,
    )
    try:
        return load_service(service.path)
    except Exception:
        _atomic_write(service.path, original, mode=mode)
        raise


def _combined_allowed_ips(
    base_values: Iterable[Any],
    connections: Iterable[dict[str, Any]],
    interface_name: str,
) -> list[str]:
    result: list[str] = []
    for value in base_values:
        rendered = str(value)
        if rendered not in result:
            result.append(rendered)
    for connection in connections:
        if connection.get("from") != interface_name:
            continue
        for value in connection.get("destinationNetworks", []):
            rendered = str(value)
            if rendered not in result:
                result.append(rendered)
    return result


def _effective_client_allowed_ips(
    service: ServiceDefinition,
    interface_name: str,
    profile_name: str,
) -> list[str]:
    interface = _interface(service, interface_name)
    management = _management(interface)
    profile = management.get("accessProfiles", {}).get(profile_name)
    if not isinstance(profile, dict) or not isinstance(profile.get("allowedIPs"), list):
        raise HomelabError(f"未找到客户端权限模板: {profile_name}")
    return _combined_allowed_ips(
        profile["allowedIPs"],
        _section(service).get("connections", []),
        interface_name,
    )


def sync_managed_client_routes(
    service: ServiceDefinition,
    interface_names: set[str],
) -> int:
    updated = 0
    for interface_name in interface_names:
        try:
            interface = _interface(service, interface_name)
        except HomelabError:
            continue
        if interface.get("role") != "server" or not isinstance(
            interface.get("peerManagement"), dict
        ):
            continue
        for record in _peer_records(service, interface):
            if not record.get("managed") or not isinstance(record.get("clientConfig"), str):
                continue
            profile_name = str(record.get("profile", ""))
            try:
                allowed_ips = _effective_client_allowed_ips(
                    service, interface_name, profile_name
                )
            except HomelabError:
                continue
            client_path = _service_path(service, str(record["clientConfig"]))
            if not client_path.exists():
                continue
            original = client_path.read_text(encoding="utf-8")
            rendered = _replace_config_setting(
                original, "Peer", "AllowedIPs", ", ".join(allowed_ips)
            )
            if rendered != original:
                _atomic_write(client_path, rendered)
                updated += 1
    return updated


def add_connection(
    service: ServiceDefinition,
    name: str,
    source: str,
    target: str,
    source_network: str,
    destination_networks: str,
    allow_return_traffic: bool,
    auto_connect: bool,
) -> None:
    if any(item.get("name") == name for item in _section(service).get("connections", [])):
        raise HomelabError(f"网络连接已存在: {name}")
    definition = _connection_definition(
        service,
        name,
        source,
        target,
        source_network,
        destination_networks,
        allow_return_traffic,
        auto_connect,
    )
    raw = copy.deepcopy(service.raw)
    raw["spec"]["wireguard"].setdefault("connections", []).append(definition)
    updated_service = _write_service_raw(service, raw)
    updated_clients = sync_managed_client_routes(updated_service, {source})
    print(f"已添加网络连接 {name}: {source} → {target}")
    print("连接定义已保存；请在界面中选择“启用连接”使规则生效")
    if updated_clients:
        print(f"已更新 {updated_clients} 份客户端配置；已部署客户端需重新导入")


def _connection_rule_ownership(
    service: ServiceDefinition,
    connection: dict[str, Any],
) -> tuple[bool, bool]:
    states = [_rule_state(service, table, chain, rule) for table, chain, rule in _rule_specs(connection)]
    has_legacy = any(legacy for _, legacy in states)
    fully_managed = bool(states) and all(managed for managed, _ in states)
    return fully_managed, has_legacy


def edit_connection(
    service: ServiceDefinition,
    name: str,
    source: str,
    target: str,
    source_network: str,
    destination_networks: str,
    allow_return_traffic: bool,
    auto_connect: bool,
) -> None:
    original_definition = _connection(service, name)
    definition = _connection_definition(
        service,
        name,
        source,
        target,
        source_network,
        destination_networks,
        allow_return_traffic,
        auto_connect,
    )
    was_active, has_legacy = _connection_rule_ownership(service, original_definition)
    if has_legacy:
        raise HomelabError("连接仍使用未标记的旧规则，请先接管后再编辑")
    had_managed_rules = any(
        _rule_state(service, table, chain, rule)[0]
        for table, chain, rule in _rule_specs(original_definition)
    )
    if had_managed_rules:
        disconnect(service, name)

    original_service = service.path.read_text(encoding="utf-8")
    service_mode = service.path.stat().st_mode & 0o777
    raw = copy.deepcopy(service.raw)
    values = raw["spec"]["wireguard"].get("connections", [])
    for index, value in enumerate(values):
        if value.get("name") == name:
            values[index] = definition
            break
    try:
        updated_service = _write_service_raw(service, raw)
        updated_clients = sync_managed_client_routes(
            updated_service,
            {str(original_definition["from"]), source},
        )
        if was_active:
            connect(updated_service, name)
    except Exception as exc:
        _atomic_write(service.path, original_service, mode=service_mode)
        if was_active:
            try:
                connect(service, name)
            except HomelabError as restore_exc:
                raise HomelabError(
                    f"编辑失败，原定义已恢复，但旧规则恢复失败: {restore_exc}"
                ) from exc
        raise
    print(f"已更新网络连接 {name}: {source} → {target}")
    if was_active:
        print("连接已按新配置重新启用")
    if updated_clients:
        print(f"已更新 {updated_clients} 份客户端配置；已部署客户端需重新导入")


def delete_connection(service: ServiceDefinition, name: str) -> None:
    definition = _connection(service, name)
    was_active, has_legacy = _connection_rule_ownership(service, definition)
    if has_legacy:
        raise HomelabError("连接仍使用未标记的旧规则，请先接管后再删除")
    had_managed_rules = any(
        _rule_state(service, table, chain, rule)[0]
        for table, chain, rule in _rule_specs(definition)
    )
    if had_managed_rules:
        disconnect(service, name)

    original_service = service.path.read_text(encoding="utf-8")
    service_mode = service.path.stat().st_mode & 0o777
    raw = copy.deepcopy(service.raw)
    raw["spec"]["wireguard"]["connections"] = [
        value
        for value in raw["spec"]["wireguard"].get("connections", [])
        if value.get("name") != name
    ]
    try:
        updated_service = _write_service_raw(service, raw)
        updated_clients = sync_managed_client_routes(
            updated_service, {str(definition["from"])}
        )
    except Exception as exc:
        _atomic_write(service.path, original_service, mode=service_mode)
        if was_active:
            try:
                connect(service, name)
            except HomelabError as restore_exc:
                raise HomelabError(
                    f"删除失败，原定义已恢复，但旧规则恢复失败: {restore_exc}"
                ) from exc
        raise

    archive = service.directory / "secrets" / "revoked" / "connections"
    archive.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_path = archive / f"{timestamp}-{name}.yaml"
    try:
        _atomic_write(
            archive_path,
            yaml.safe_dump(definition, allow_unicode=True, sort_keys=False),
        )
        print(f"已删除网络连接 {name}；原定义已归档到 {archive_path}")
    except OSError as exc:
        print(f"已删除网络连接 {name}，但归档失败: {exc}")
    if updated_clients:
        print(f"已更新 {updated_clients} 份客户端配置；已部署客户端需重新导入")


def server_interface_settings(
    service: ServiceDefinition,
    interface_name: str,
) -> dict[str, str]:
    interface = _interface(service, interface_name)
    if interface.get("role") != "server":
        raise HomelabError(f"接口 {interface_name} 不是服务端接口")
    management = _management(interface)
    config_path = _service_path(service, str(interface["config"]))
    values, _ = parse_wireguard_config(config_path)
    return {
        "interface": interface_name,
        "address": values.get("Address", ""),
        "address_pool": str(management.get("addressPool", "")),
        "listen_port": values.get("ListenPort", ""),
        "public_endpoint": str(management.get("publicEndpoint", "")),
    }


def _replace_config_setting(content: str, section: str, key: str, value: str) -> str:
    lines = content.splitlines()
    target = section.casefold()
    active = False
    insert_at: int | None = None
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if active:
                insert_at = index
                break
            active = stripped[1:-1].strip().casefold() == target
            if active:
                insert_at = index + 1
            continue
        if active:
            name, separator, _ = stripped.partition("=")
            if separator and name.strip().casefold() == key.casefold():
                lines[index] = f"{key} = {value}"
                return "\n".join(lines).rstrip() + "\n"
            insert_at = index + 1
    if insert_at is None:
        raise HomelabError(f"WireGuard 配置缺少 [{section}] 段")
    lines.insert(insert_at, f"{key} = {value}")
    return "\n".join(lines).rstrip() + "\n"


def _validate_server_values(
    address: str,
    address_pool: str,
    listen_port: int,
    public_endpoint: str,
) -> tuple[ipaddress.IPv4Interface, ipaddress.IPv4Network]:
    try:
        pool = ipaddress.ip_network(address_pool, strict=False)
        server = ipaddress.ip_interface(address if "/" in address else f"{address}/32")
    except ValueError as exc:
        raise HomelabError("服务端地址或地址池格式无效") from exc
    if pool.version != 4 or server.version != 4:
        raise HomelabError("目前只支持 IPv4 WireGuard 地址")
    if server.ip not in pool:
        raise HomelabError(f"服务端地址 {server.ip} 不在地址池 {pool} 内")
    if not 1 <= listen_port <= 65535:
        raise HomelabError("监听端口必须在 1-65535 之间")
    if not public_endpoint.strip() or ":" not in public_endpoint:
        raise HomelabError("公网入口格式应为 主机名或IP:端口")
    return server, pool


def edit_server_interface(
    service: ServiceDefinition,
    interface_name: str,
    address: str,
    address_pool: str,
    listen_port: int,
    public_endpoint: str,
) -> None:
    interface = _interface(service, interface_name)
    if interface.get("role") != "server":
        raise HomelabError("只能编辑服务端接口")
    management = _management(interface)
    server, pool = _validate_server_values(
        address, address_pool, listen_port, public_endpoint
    )
    config_path = _service_path(service, str(interface["config"]))
    original_config = config_path.read_text(encoding="utf-8")
    _, peers = parse_wireguard_config(config_path)
    for peer in peers:
        for allowed in peer.allowed_ips:
            try:
                network = ipaddress.ip_network(allowed, strict=False)
            except ValueError:
                continue
            if network.version == 4 and not network.subnet_of(pool):
                raise HomelabError(
                    f"现有客户端地址 {network} 不在新地址池 {pool} 内，已阻止修改"
                )
            if network.prefixlen == network.max_prefixlen and network.network_address == server.ip:
                raise HomelabError(f"服务端地址 {server.ip} 已被现有客户端使用")

    server_address = f"{server.ip}/32"
    updated_config = _replace_config_setting(
        original_config, "Interface", "Address", server_address
    )
    updated_config = _replace_config_setting(
        updated_config, "Interface", "ListenPort", str(listen_port)
    )

    original_service = service.path.read_text(encoding="utf-8")
    raw = copy.deepcopy(service.raw)
    updated_interface = next(
        item
        for item in raw["spec"]["wireguard"]["interfaces"]
        if item.get("name") == interface_name
    )
    updated_management = updated_interface["peerManagement"]
    updated_management["addressPool"] = str(pool)
    updated_management["publicEndpoint"] = public_endpoint.strip()
    profiles = updated_management.get("accessProfiles", {})
    if isinstance(profiles.get("server-only"), dict):
        profiles["server-only"]["allowedIPs"] = [server_address]
    if isinstance(profiles.get("wireguard-network"), dict):
        profiles["wireguard-network"]["allowedIPs"] = [str(pool)]
    rendered_service = yaml.safe_dump(raw, allow_unicode=True, sort_keys=False)
    service_mode = service.path.stat().st_mode & 0o777

    client_updates: dict[Path, tuple[str, str]] = {}
    for record in _peer_records(service, interface):
        if not record.get("managed") or not isinstance(record.get("clientConfig"), str):
            continue
        client_path = _service_path(service, str(record["clientConfig"]))
        if not client_path.exists():
            continue
        original_client = client_path.read_text(encoding="utf-8")
        updated_client = _replace_config_setting(
            original_client, "Peer", "Endpoint", public_endpoint.strip()
        )
        profile_name = str(record.get("profile", ""))
        profile = profiles.get(profile_name)
        if isinstance(profile, dict) and isinstance(profile.get("allowedIPs"), list):
            allowed_ips = _combined_allowed_ips(
                profile["allowedIPs"],
                raw["spec"]["wireguard"].get("connections", []),
                interface_name,
            )
            updated_client = _replace_config_setting(
                updated_client,
                "Peer",
                "AllowedIPs",
                ", ".join(allowed_ips),
            )
        client_updates[client_path] = (original_client, updated_client)

    was_running = _wg_show(service, interface_name).returncode == 0
    if was_running:
        down = _run((*_sudo_prefix(service), "wg-quick", "down", str(config_path)))
        if down.returncode != 0:
            raise HomelabError(
                "接口停止失败，未修改配置: "
                + (down.stderr.strip() or down.stdout.strip() or str(down.returncode))
            )

    try:
        _atomic_write(config_path, updated_config)
        for client_path, (_, updated_client) in client_updates.items():
            _atomic_write(client_path, updated_client)
        _atomic_write(service.path, rendered_service, mode=service_mode)
        load_service(service.path)
        if was_running:
            up = _run((*_sudo_prefix(service), "wg-quick", "up", str(config_path)))
            if up.returncode != 0:
                raise HomelabError(
                    "新配置启动失败: "
                    + (up.stderr.strip() or up.stdout.strip() or str(up.returncode))
                )
    except Exception as exc:
        _atomic_write(config_path, original_config)
        for client_path, (original_client, _) in client_updates.items():
            _atomic_write(client_path, original_client)
        _atomic_write(service.path, original_service, mode=service_mode)
        if was_running:
            _run((*_sudo_prefix(service), "wg-quick", "up", str(config_path)))
        if isinstance(exc, HomelabError):
            raise HomelabError(f"编辑未生效，已恢复原配置: {exc}") from exc
        raise

    print(f"已更新 WireGuard 服务端 {interface_name}: {server_address}")
    if was_running:
        print("接口已使用新配置重新启动")
    if client_updates:
        print(f"已同步更新 {len(client_updates)} 份本地客户端配置；已部署客户端需重新导入")


def _delete_interface(
    service: ServiceDefinition,
    interface_name: str,
    *,
    required_role: str,
    role_label: str,
) -> None:
    interface = _interface(service, interface_name)
    if interface.get("role") != required_role:
        raise HomelabError(f"只能从这里删除{role_label}接口")
    references = [
        str(item.get("name"))
        for item in _section(service).get("connections", [])
        if item.get("from") == interface_name or item.get("to") == interface_name
    ]
    if references:
        raise HomelabError(
            f"接口仍被网络连接引用（{', '.join(references)}），请先处理这些连接"
        )
    if len(_interfaces(service)) <= 1:
        raise HomelabError("WireGuard 服务至少要保留一个接口")

    config_path = _service_path(service, str(interface["config"]))
    was_running = _wg_show(service, interface_name).returncode == 0
    if was_running:
        down = _run((*_sudo_prefix(service), "wg-quick", "down", str(config_path)))
        if down.returncode != 0:
            raise HomelabError(
                "接口停止失败，已阻止删除: "
                + (down.stderr.strip() or down.stdout.strip() or str(down.returncode))
            )

    original_service = service.path.read_text(encoding="utf-8")
    raw = copy.deepcopy(service.raw)
    raw["spec"]["wireguard"]["interfaces"] = [
        item
        for item in raw["spec"]["wireguard"]["interfaces"]
        if item.get("name") != interface_name
    ]
    config_section = raw["spec"].get("config")
    if isinstance(config_section, dict) and isinstance(config_section.get("files"), list):
        interface_config = (
            str(interface.get("config", "")).replace("\\", "/").lstrip("./")
        )
        secret_prefix = f"secrets/{interface_name}/"
        config_section["files"] = [
            value
            for value in config_section["files"]
            if not (
                isinstance(value, str)
                and (
                    value.replace("\\", "/").lstrip("./") == interface_config
                    or value.replace("\\", "/").lstrip("./").startswith(secret_prefix)
                )
            )
        ]
    health = raw["spec"].get("health")
    if isinstance(health, dict) and isinstance(health.get("checks"), list):
        health["checks"] = [
            check
            for check in health["checks"]
            if not isinstance(check, dict) or check.get("interface") != interface_name
        ]
    service_mode = service.path.stat().st_mode & 0o777
    try:
        _atomic_write(
            service.path,
            yaml.safe_dump(raw, allow_unicode=True, sort_keys=False),
            mode=service_mode,
        )
        load_service(service.path)
    except Exception:
        _atomic_write(service.path, original_service, mode=service_mode)
        if was_running:
            _run((*_sudo_prefix(service), "wg-quick", "up", str(config_path)))
        raise

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = service.directory / "secrets" / "revoked" / "interfaces" / f"{timestamp}-{interface_name}"
    paths = [config_path]
    management = interface.get("peerManagement")
    if isinstance(management, dict):
        for field in ("serverPublicKeyFile", "metadataDirectory", "clientOutputDirectory"):
            value = management.get(field)
            if isinstance(value, str) and value:
                paths.append(_service_path(service, value))
    archived = 0
    for path in paths:
        if not path.exists() or not path.is_relative_to(service.directory.resolve()):
            continue
        relative = path.relative_to(service.directory.resolve())
        destination = archive / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(path), str(destination))
            archived += 1
        except OSError as exc:
            print(f"警告: 无法归档 {path}: {exc}")
    print(f"已删除 WireGuard {role_label} {interface_name}，归档 {archived} 项到 {archive}")


def delete_server_interface(service: ServiceDefinition, interface_name: str) -> None:
    _delete_interface(
        service,
        interface_name,
        required_role="server",
        role_label="服务端",
    )


def delete_client_interface(service: ServiceDefinition, interface_name: str) -> None:
    _delete_interface(
        service,
        interface_name,
        required_role="client",
        role_label="客户端",
    )


def import_peers(service: ServiceDefinition, interface_name: str) -> int:
    interface = _interface(service, interface_name)
    management = _management(interface)
    directory = _managed_directory(service, management, "metadataDirectory", "peers")
    existing = _peer_records(service, interface)
    known = {str(item.get("publicKey")) for item in existing}
    config_path = _service_path(service, str(interface["config"]))
    _, peers = parse_wireguard_config(config_path)
    created = 0
    for peer in peers:
        if peer.public_key in known:
            continue
        address = peer.allowed_ips[0] if peer.allowed_ips else "unknown"
        base = f"existing-{address.split('/')[0].replace(':', '-')}"
        peer_id = _peer_id(base)
        path = directory / f"{peer_id}.yaml"
        suffix = 2
        while path.exists():
            path = directory / f"{peer_id}-{suffix}.yaml"
            suffix += 1
        record = {
            "id": path.stem,
            "name": base,
            "interface": interface_name,
            "address": address,
            "publicKey": peer.public_key,
            "managed": False,
            "importedAt": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write(path, yaml.safe_dump(record, allow_unicode=True, sort_keys=False))
        created += 1
    print(f"已识别 {len(peers)} 个客户端，新增 {created} 条只读登记信息")
    return created


def _allocate_address(
    interface_values: dict[str, str],
    peers: list[ParsedPeer],
    pool_value: str,
    requested: str | None,
) -> str:
    pool = ipaddress.ip_network(pool_value, strict=False)
    used: set[ipaddress._BaseAddress] = set()
    for value in interface_values.get("Address", "").split(","):
        if value.strip():
            used.add(ipaddress.ip_interface(value.strip()).ip)
    for peer in peers:
        for value in peer.allowed_ips:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            if network.prefixlen == network.max_prefixlen:
                used.add(network.network_address)
    if requested:
        candidate = ipaddress.ip_interface(
            requested if "/" in requested else f"{requested}/{pool.max_prefixlen}"
        )
        if candidate.ip not in pool:
            raise HomelabError(f"地址 {candidate.ip} 不在地址池 {pool} 内")
        if candidate.ip in used:
            raise HomelabError(f"地址 {candidate.ip} 已被使用")
        return f"{candidate.ip}/{pool.max_prefixlen}"
    for candidate in pool.hosts():
        if candidate not in used:
            return f"{candidate}/{pool.max_prefixlen}"
    raise HomelabError(f"地址池 {pool} 已无可用地址")


def _server_public_key(
    service: ServiceDefinition,
    interface: dict[str, Any],
    management: dict[str, Any],
) -> str:
    value = management.get("serverPublicKeyFile")
    if isinstance(value, str) and value:
        try:
            key = _service_path(service, value).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise HomelabError("无法读取服务端公钥文件") from exc
        if key:
            return key
    result = _wg_show(service, str(interface["name"]), "public-key")
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    raise HomelabError("无法取得服务端公钥；请配置 serverPublicKeyFile")


def add_peer(
    service: ServiceDefinition,
    interface_name: str,
    name: str,
    *,
    requested_address: str | None = None,
    profile_name: str | None = None,
) -> Path:
    interface = _interface(service, interface_name)
    if interface.get("role") != "server":
        raise HomelabError("只能在服务端接口上添加客户端")
    management = _management(interface)
    profiles = management["accessProfiles"]
    profile_name = profile_name or management.get("defaultAccessProfile") or next(iter(profiles))
    if profile_name not in profiles:
        raise HomelabError(f"未找到权限模板: {profile_name}")
    if any(record.get("name") == name for record in _peer_records(service, interface)):
        raise HomelabError(f"客户端名称已存在: {name}")

    config_path = _service_path(service, str(interface["config"]))
    interface_values, peers = parse_wireguard_config(config_path)
    address = _allocate_address(
        interface_values,
        peers,
        str(management["addressPool"]),
        requested_address,
    )
    private_key = _run(("wg", "genkey"), check=True).stdout.strip()
    public_key = _run(("wg", "pubkey"), input_text=f"{private_key}\n", check=True).stdout.strip()
    if not private_key or not public_key:
        raise HomelabError("WireGuard 密钥生成失败")

    metadata_directory = _managed_directory(service, management, "metadataDirectory", "peers")
    output_directory = _managed_directory(
        service, management, "clientOutputDirectory", "secrets/clients"
    )
    peer_id = _peer_id(name)
    metadata_path = metadata_directory / f"{peer_id}.yaml"
    client_path = output_directory / f"{peer_id}.conf"
    if metadata_path.exists() or client_path.exists():
        raise HomelabError(f"客户端标识已存在: {peer_id}")

    server_public_key = _server_public_key(service, interface, management)
    allowed_ips = _effective_client_allowed_ips(service, interface_name, str(profile_name))
    keepalive = int(management.get("persistentKeepalive", 25))
    dns = profiles[profile_name].get("dns") or management.get("dns")
    client_lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}",
    ]
    if dns:
        client_lines.append(f"DNS = {dns}")
    client_lines.extend(
        [
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
            f"Endpoint = {management['publicEndpoint']}",
            f"AllowedIPs = {', '.join(allowed_ips)}",
            f"PersistentKeepalive = {keepalive}",
            "",
        ]
    )

    server_keepalive = int(management.get("serverPersistentKeepalive", 0))
    server_lines = [
        f"{PEER_START}{peer_id}",
        "[Peer]",
        f"PublicKey = {public_key}",
        f"AllowedIPs = {address}",
    ]
    if server_keepalive:
        server_lines.append(f"PersistentKeepalive = {server_keepalive}")
    server_lines.extend([f"{PEER_END}{peer_id}", ""])

    original = config_path.read_text(encoding="utf-8")
    updated = original.rstrip() + "\n\n" + "\n".join(server_lines)
    record = {
        "id": peer_id,
        "name": name,
        "interface": interface_name,
        "address": address,
        "publicKey": public_key,
        "profile": profile_name,
        "clientConfig": str(client_path.relative_to(service.directory)),
        "managed": True,
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }

    _atomic_write(client_path, "\n".join(client_lines))
    _atomic_write(metadata_path, yaml.safe_dump(record, allow_unicode=True, sort_keys=False))
    try:
        _atomic_write(config_path, updated)
    except Exception:
        metadata_path.unlink(missing_ok=True)
        client_path.unlink(missing_ok=True)
        raise

    runtime = _wg_show(service, interface_name)
    if runtime.returncode == 0:
        command = (
            *_sudo_prefix(service),
            "wg", "set", interface_name,
            "peer", public_key,
            "allowed-ips", address,
        )
        if server_keepalive:
            command = (*command, "persistent-keepalive", str(server_keepalive))
        result = _run(command)
        if result.returncode != 0:
            raise HomelabError(
                f"客户端已写入持久配置，但热更新失败: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        _sync_peer_route(service, interface_name, address)
    print(f"已添加客户端 {name}: {address}")
    print(f"客户端配置: {client_path}")
    return client_path


def _remove_marked_peer(content: str, peer_id: str) -> str:
    start = f"{PEER_START}{peer_id}"
    end = f"{PEER_END}{peer_id}"
    start_index = content.find(start)
    end_index = content.find(end)
    if start_index < 0 or end_index < start_index:
        raise HomelabError("客户端不是 NControl 创建的可管理配置，已阻止删除")
    end_index += len(end)
    while end_index < len(content) and content[end_index] in "\r\n":
        end_index += 1
    return content[:start_index].rstrip() + "\n" + content[end_index:]


def remove_peer(service: ServiceDefinition, interface_name: str, peer_id: str) -> None:
    interface = _interface(service, interface_name)
    management = _management(interface)
    records = _peer_records(service, interface)
    record = next((item for item in records if item.get("id") == peer_id), None)
    if record is None:
        raise HomelabError(f"未找到客户端: {peer_id}")
    if not record.get("managed"):
        raise HomelabError("这是从旧配置导入的只读客户端，已阻止删除")
    config_path = _service_path(service, str(interface["config"]))
    original = config_path.read_text(encoding="utf-8")
    updated = _remove_marked_peer(original, peer_id)
    _atomic_write(config_path, updated)

    public_key = str(record["publicKey"])
    runtime = _wg_show(service, interface_name)
    if runtime.returncode == 0:
        try:
            _run(
                (*_sudo_prefix(service), "wg", "set", interface_name, "peer", public_key, "remove"),
                check=True,
            )
            _remove_peer_route(service, interface_name, str(record["address"]))
        except HomelabError:
            _atomic_write(config_path, original)
            raise

    revoked = service.directory / "secrets" / "revoked"
    revoked.mkdir(parents=True, exist_ok=True)
    client_value = record.get("clientConfig")
    if isinstance(client_value, str):
        client_path = _service_path(service, client_value)
        if client_path.exists():
            os.replace(client_path, revoked / f"{peer_id}.conf")
    metadata_path = Path(str(record["_metadataPath"]))
    os.replace(metadata_path, revoked / f"{peer_id}.yaml")
    print(f"已撤销客户端 {record.get('name', peer_id)}；原配置已移入 {revoked}")


def export_peer(service: ServiceDefinition, interface_name: str, peer_id: str, *, qr: bool) -> None:
    path = peer_client_config_path(service, interface_name, peer_id)
    if qr:
        print(render_terminal_qr(path.read_text(encoding="utf-8")), end="")
    else:
        print(path)


def peer_client_config_path(
    service: ServiceDefinition,
    interface_name: str,
    peer_id: str,
) -> Path:
    interface = _interface(service, interface_name)
    record = next(
        (item for item in _peer_records(service, interface) if item.get("id") == peer_id),
        None,
    )
    if record is None or not isinstance(record.get("clientConfig"), str):
        raise HomelabError("该客户端没有可导出的私有配置")
    path = _service_path(service, str(record["clientConfig"]))
    if not path.exists():
        raise HomelabError(f"找不到客户端配置: {path}")
    return path


def peer_qr_text(service: ServiceDefinition, interface_name: str, peer_id: str) -> str:
    path = peer_client_config_path(service, interface_name, peer_id)
    return render_terminal_qr(path.read_text(encoding="utf-8"))


def render_terminal_qr(value: str) -> str:
    """Render a QR code using Unicode blocks; no system qrencode is needed."""
    try:
        import qrcode
    except ImportError as exc:
        raise HomelabError("缺少 qrcode Python 依赖，请重新运行 bootstrap.sh") from exc

    code = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,
        border=4,
    )
    code.add_data(value)
    code.make(fit=True)
    # qrcode's inverted ASCII mode is designed for a dark terminal: the
    # quiet zone and white modules are rendered as white blocks, while the
    # data modules remain the black terminal background.
    import io

    output = io.StringIO()
    code.print_ascii(out=output, invert=True)
    return output.getvalue()


def _bool_argument(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "yes", "1"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    raise argparse.ArgumentTypeError("必须是 true 或 false")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("service_file", type=Path)
    sub = parser.add_subparsers(dest="operation", required=True)
    for operation in ("connection-status", "connect", "disconnect", "adopt-connection"):
        command = sub.add_parser(operation)
        command.add_argument("name")
    for operation in (
        "interface-status",
        "start-interface",
        "stop-interface",
        "sync-interface",
    ):
        command = sub.add_parser(operation)
        command.add_argument("interface")
    traffic = sub.add_parser("traffic")
    traffic.add_argument("--json", action="store_true")
    for operation in ("add-connection", "edit-connection"):
        command = sub.add_parser(operation)
        command.add_argument("name")
        command.add_argument("source")
        command.add_argument("target")
        command.add_argument("source_network")
        command.add_argument("destination_networks")
        command.add_argument("allow_return", type=_bool_argument)
        command.add_argument("auto_connect", type=_bool_argument)
    delete_connection_parser = sub.add_parser("delete-connection")
    delete_connection_parser.add_argument("name")
    create_server = sub.add_parser("create-server")
    create_server.add_argument("interface")
    create_server.add_argument("address")
    create_server.add_argument("address_pool")
    create_server.add_argument("listen_port", type=int)
    create_server.add_argument("public_endpoint")
    edit_server = sub.add_parser("edit-server")
    edit_server.add_argument("interface")
    edit_server.add_argument("address")
    edit_server.add_argument("address_pool")
    edit_server.add_argument("listen_port", type=int)
    edit_server.add_argument("public_endpoint")
    delete_server = sub.add_parser("delete-server")
    delete_server.add_argument("interface")
    delete_client = sub.add_parser("delete-client")
    delete_client.add_argument("interface")
    import_client = sub.add_parser("import-client")
    import_client.add_argument("interface")
    import_client.add_argument("source_config")
    peers = sub.add_parser("peers")
    peers.add_argument("interface")
    peers.add_argument("--json", action="store_true")
    imported = sub.add_parser("import-peers")
    imported.add_argument("interface")
    add = sub.add_parser("add-peer")
    add.add_argument("interface")
    add.add_argument("name")
    add.add_argument("--address")
    add.add_argument("--profile")
    remove = sub.add_parser("remove-peer")
    remove.add_argument("interface")
    remove.add_argument("peer_id")
    export = sub.add_parser("export-peer")
    export.add_argument("interface")
    export.add_argument("peer_id")
    export.add_argument("--qr", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        service = _wireguard_service(args.service_file.resolve())
        if args.operation == "connection-status":
            return 0 if connection_status(service, args.name) else 3
        if args.operation == "interface-status":
            return 0 if interface_status(service, args.interface) else 3
        if args.operation == "traffic":
            snapshot = traffic_snapshot(service)
            print(json.dumps(snapshot, ensure_ascii=False))
            return 0
        if args.operation == "add-connection":
            add_connection(
                service,
                args.name,
                args.source,
                args.target,
                args.source_network,
                args.destination_networks,
                args.allow_return,
                args.auto_connect,
            )
        elif args.operation == "edit-connection":
            edit_connection(
                service,
                args.name,
                args.source,
                args.target,
                args.source_network,
                args.destination_networks,
                args.allow_return,
                args.auto_connect,
            )
        elif args.operation == "delete-connection":
            delete_connection(service, args.name)
        elif args.operation == "start-interface":
            start_interface(service, args.interface)
        elif args.operation == "stop-interface":
            stop_interface(service, args.interface)
        elif args.operation == "sync-interface":
            sync_interface_runtime(service, args.interface)
        elif args.operation == "create-server":
            create_server_interface(
                service,
                args.interface,
                args.address,
                args.address_pool,
                args.listen_port,
                args.public_endpoint,
            )
        elif args.operation == "edit-server":
            edit_server_interface(
                service,
                args.interface,
                args.address,
                args.address_pool,
                args.listen_port,
                args.public_endpoint,
            )
        elif args.operation == "delete-server":
            delete_server_interface(service, args.interface)
        elif args.operation == "delete-client":
            delete_client_interface(service, args.interface)
        elif args.operation == "import-client":
            import_client_interface(service, args.interface, args.source_config)
        elif args.operation == "connect":
            connect(service, args.name)
        elif args.operation == "disconnect":
            disconnect(service, args.name)
        elif args.operation == "adopt-connection":
            adopt_connection(service, args.name)
        elif args.operation == "peers":
            records = list_peer_records(service, args.interface)
            if args.json:
                print(json.dumps(records, ensure_ascii=False))
            else:
                for record in records:
                    address = record.get("address") or ",".join(record.get("allowedIPs", []))
                    mode = "可管理" if record.get("managed") else "只读导入"
                    print(f"{record.get('id')}\t{record.get('name')}\t{address}\t{mode}")
        elif args.operation == "import-peers":
            import_peers(service, args.interface)
        elif args.operation == "add-peer":
            add_peer(
                service,
                args.interface,
                args.name,
                requested_address=args.address,
                profile_name=args.profile,
            )
        elif args.operation == "remove-peer":
            remove_peer(service, args.interface, args.peer_id)
        elif args.operation == "export-peer":
            export_peer(service, args.interface, args.peer_id, qr=args.qr)
        return 0
    except (HomelabError, ConfigError, OSError, ValueError) as exc:
        print(f"错误: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
