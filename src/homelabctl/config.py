from __future__ import annotations

import re
import ipaddress
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import yaml

from .errors import ConfigError
from .layout import services_directory
from .models import ServiceDefinition

API_VERSION = "homelabctl/v1alpha1"
SUPPORTED_DRIVERS = {
    "compose",
    "docker",
    "frp",
    "process",
    "script",
    "systemd",
    "wireguard",
}
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{field} 必须是一个对象")
    return value


def load_service(path: Path) -> ServiceDefinition:
    path = path.resolve()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"找不到配置文件: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML 解析失败: {path}: {exc}") from exc

    root = _mapping(data, str(path))
    if root.get("apiVersion") != API_VERSION:
        raise ConfigError(f"{path}: apiVersion 必须是 {API_VERSION}")
    if root.get("kind") != "Service":
        raise ConfigError(f"{path}: kind 必须是 Service")

    metadata = _mapping(root.get("metadata"), "metadata")
    spec = _mapping(root.get("spec"), "spec")
    name = metadata.get("name")
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        raise ConfigError(f"{path}: metadata.name 格式无效")
    driver = spec.get("driver")
    if driver not in SUPPORTED_DRIVERS:
        choices = ", ".join(sorted(SUPPORTED_DRIVERS))
        raise ConfigError(f"{path}: spec.driver 必须是: {choices}")

    _validate_driver_fields(path, driver, spec)
    return ServiceDefinition(
        path=path,
        name=name,
        description=str(metadata.get("description", "")),
        driver=driver,
        spec=spec,
        raw=root,
    )


def _validate_driver_fields(path: Path, driver: str, spec: dict[str, Any]) -> None:
    if not isinstance(spec.get("autostart", False), bool):
        raise ConfigError(f"{path}: spec.autostart 必须是布尔值")

    start_order = spec.get("startOrder", 50)
    if not isinstance(start_order, int) or isinstance(start_order, bool) or start_order < 0:
        raise ConfigError(f"{path}: spec.startOrder 必须是非负整数")

    working_directory = spec.get("workingDirectory", ".")
    if not isinstance(working_directory, str) or not working_directory.strip():
        raise ConfigError(f"{path}: spec.workingDirectory 必须是非空字符串")

    config = spec.get("config", {})
    if not isinstance(config, dict):
        raise ConfigError(f"{path}: spec.config 必须是一个对象")
    _validate_string_list(path, config.get("files", []), "spec.config.files")
    allow_external = config.get("allowExternalConfig", False)
    if not isinstance(allow_external, bool):
        raise ConfigError(f"{path}: spec.config.allowExternalConfig 必须是布尔值")

    backup = spec.get("backup", {})
    if not isinstance(backup, dict):
        raise ConfigError(f"{path}: spec.backup 必须是一个对象")
    _validate_string_list(path, backup.get("paths", []), "spec.backup.paths")
    _validate_string_list(path, backup.get("exclude", []), "spec.backup.exclude")
    _validate_health(path, driver, spec)

    sections = {
        "docker": ("docker", "container"),
        "compose": ("compose", "file"),
        "systemd": ("systemd", "unit"),
        "frp": ("frp", "config"),
    }
    if driver in sections:
        section_name, required = sections[driver]
        section = _mapping(spec.get(section_name), f"spec.{section_name}")
        if not isinstance(section.get(required), str) or not section[required].strip():
            raise ConfigError(f"{path}: spec.{section_name}.{required} 不能为空")
    if driver == "script":
        section = _mapping(spec.get("script"), "spec.script")
        commands = _mapping(section.get("commands"), "spec.script.commands")
        if not commands:
            raise ConfigError(f"{path}: spec.script.commands 至少需要一个操作")
    if driver == "process":
        _validate_process(path, spec)
    if driver == "wireguard":
        _validate_wireguard(path, spec)


def _validate_health(path: Path, driver: str, spec: dict[str, Any]) -> None:
    health = spec.get("health", {})
    if not isinstance(health, dict):
        raise ConfigError(f"{path}: spec.health 必须是一个对象")
    startup = health.get("startupPeriodSeconds", 15)
    if not isinstance(startup, (int, float)) or isinstance(startup, bool) or startup < 0:
        raise ConfigError(f"{path}: spec.health.startupPeriodSeconds 必须是非负数")
    checks = health.get("checks", [])
    if not isinstance(checks, list):
        raise ConfigError(f"{path}: spec.health.checks 必须是数组")
    names: set[str] = set()
    for index, raw in enumerate(checks):
        prefix = f"{path}: spec.health.checks[{index}]"
        check = _mapping(raw, prefix)
        check_type = check.get("type")
        if check_type not in {"http", "tcp", "wireguard-handshake", "ping"}:
            raise ConfigError(f"{prefix}.type 必须是 http、tcp、wireguard-handshake 或 ping")
        name = check.get("name", f"check-{index + 1}")
        if not isinstance(name, str) or not name.strip() or name in names:
            raise ConfigError(f"{prefix}.name 必须是非空且不重复的字符串")
        names.add(name)
        timeout = check.get("timeoutSeconds", 3)
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ConfigError(f"{prefix}.timeoutSeconds 必须是正数")
        if check_type == "http":
            url = check.get("url")
            if not isinstance(url, str) or urlparse(url).scheme not in {"http", "https"}:
                raise ConfigError(f"{prefix}.url 必须是 http 或 https 地址")
            if not isinstance(check.get("processOwned", False), bool):
                raise ConfigError(f"{prefix}.processOwned 必须是布尔值")
            if check.get("processOwned", False) and driver != "process":
                raise ConfigError(f"{prefix}.processOwned 只适用于 process 驱动")
            statuses = check.get("expectedStatuses", [])
            if not isinstance(statuses, list) or not all(
                isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599
                for value in statuses
            ):
                raise ConfigError(f"{prefix}.expectedStatuses 必须是 HTTP 状态码数组")
        elif check_type == "tcp":
            if not isinstance(check.get("host"), str) or not check["host"].strip():
                raise ConfigError(f"{prefix}.host 不能为空")
            port = check.get("port")
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise ConfigError(f"{prefix}.port 必须是 1-65535 的整数")
            if not isinstance(check.get("processOwned", False), bool):
                raise ConfigError(f"{prefix}.processOwned 必须是布尔值")
            if check.get("processOwned", False) and driver != "process":
                raise ConfigError(f"{prefix}.processOwned 只适用于 process 驱动")
        elif check_type == "wireguard-handshake":
            if driver != "wireguard":
                raise ConfigError(f"{prefix} 只适用于 wireguard 驱动")
            if not isinstance(check.get("interface"), str) or not check["interface"].strip():
                raise ConfigError(f"{prefix}.interface 不能为空")
            age = check.get("maxAgeSeconds", 180)
            if not isinstance(age, (int, float)) or isinstance(age, bool) or age <= 0:
                raise ConfigError(f"{prefix}.maxAgeSeconds 必须是正数")
        elif check_type == "ping":
            if not isinstance(check.get("host"), str) or not check["host"].strip():
                raise ConfigError(f"{prefix}.host 不能为空")
            interface = check.get("interface")
            if interface is not None and (not isinstance(interface, str) or not interface.strip()):
                raise ConfigError(f"{prefix}.interface 必须是非空字符串")


def _validate_command(value: Any, field: str) -> None:
    if not (
        isinstance(value, list)
        and value
        and all(isinstance(item, str) and item for item in value)
    ):
        raise ConfigError(f"{field} 必须是非空字符串数组")


def _validate_process(path: Path, spec: dict[str, Any]) -> None:
    section = _mapping(spec.get("process"), "spec.process")
    _validate_command(section.get("command"), f"{path}: spec.process.command")

    platform_commands = section.get("platformCommands", {})
    if not isinstance(platform_commands, dict):
        raise ConfigError(f"{path}: spec.process.platformCommands 必须是一个对象")
    for platform_name, command in platform_commands.items():
        if platform_name not in {"linux", "macos", "windows"}:
            raise ConfigError(f"{path}: 不支持的平台命令: {platform_name}")
        _validate_command(
            command,
            f"{path}: spec.process.platformCommands.{platform_name}",
        )

    prepare_command = section.get("prepareCommand")
    if prepare_command is not None:
        _validate_command(prepare_command, f"{path}: spec.process.prepareCommand")
    platform_prepare = section.get("platformPrepareCommands", {})
    if not isinstance(platform_prepare, dict):
        raise ConfigError(
            f"{path}: spec.process.platformPrepareCommands 必须是一个对象"
        )
    for platform_name, command in platform_prepare.items():
        if platform_name not in {"linux", "macos", "windows"}:
            raise ConfigError(f"{path}: 不支持的平台准备命令: {platform_name}")
        _validate_command(
            command,
            f"{path}: spec.process.platformPrepareCommands.{platform_name}",
        )

    for field in ("environment", "environmentFromFiles"):
        values = section.get(field, {})
        if not isinstance(values, dict) or not all(
            isinstance(key, str)
            and key
            and isinstance(value, str)
            and value
            for key, value in values.items()
        ):
            raise ConfigError(f"{path}: spec.process.{field} 必须是非空字符串键值对象")

    for field, default in (
        ("stateFile", ".ncontrol/process.json"),
        ("logFile", "logs/service.log"),
    ):
        value = section.get(field, default)
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{path}: spec.process.{field} 必须是非空字符串")
        candidate = Path(value)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ConfigError(f"{path}: spec.process.{field} 必须位于服务目录内")

    for field, default in (("startupGraceSeconds", 0.5), ("stopTimeoutSeconds", 10)):
        value = section.get(field, default)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ConfigError(f"{path}: spec.process.{field} 必须是非负数")


def _validate_wireguard(path: Path, spec: dict[str, Any]) -> None:
    section = _mapping(spec.get("wireguard"), "spec.wireguard")
    interfaces = section.get("interfaces")
    if interfaces is None:
        for field in ("interface", "config"):
            if not isinstance(section.get(field), str) or not section[field].strip():
                raise ConfigError(f"{path}: spec.wireguard.{field} 不能为空")
        return

    if not isinstance(interfaces, list) or not interfaces:
        raise ConfigError(f"{path}: spec.wireguard.interfaces 必须是非空数组")
    names: set[str] = set()
    for index, value in enumerate(interfaces):
        item = _mapping(value, f"spec.wireguard.interfaces[{index}]")
        name = item.get("name")
        if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
            raise ConfigError(
                f"{path}: spec.wireguard.interfaces[{index}].name 格式无效"
            )
        if name in names:
            raise ConfigError(f"{path}: WireGuard 接口名重复: {name}")
        names.add(name)
        if item.get("role") not in {"client", "server"}:
            raise ConfigError(
                f"{path}: spec.wireguard.interfaces[{index}].role 必须是 client 或 server"
            )
        config = item.get("config")
        if not isinstance(config, str) or not config.strip():
            raise ConfigError(
                f"{path}: spec.wireguard.interfaces[{index}].config 不能为空"
            )
        peer_management = item.get("peerManagement")
        if peer_management is not None:
            _validate_wireguard_peer_management(path, index, peer_management)

    connections = section.get("connections", [])
    if not isinstance(connections, list):
        raise ConfigError(f"{path}: spec.wireguard.connections 必须是数组")
    connection_names: set[str] = set()
    for index, value in enumerate(connections):
        item = _mapping(value, f"spec.wireguard.connections[{index}]")
        name = item.get("name")
        if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
            raise ConfigError(
                f"{path}: spec.wireguard.connections[{index}].name 格式无效"
            )
        if name in connection_names:
            raise ConfigError(f"{path}: WireGuard 连接名重复: {name}")
        connection_names.add(name)
        for field in ("from", "to"):
            if item.get(field) not in names:
                raise ConfigError(
                    f"{path}: spec.wireguard.connections[{index}].{field} "
                    "必须引用已声明的接口"
                )
        if item["from"] == item["to"]:
            raise ConfigError(f"{path}: WireGuard 连接的 from 和 to 不能相同")
        _validate_network(
            path,
            item.get("sourceNetwork"),
            f"spec.wireguard.connections[{index}].sourceNetwork",
        )
        destination_networks = item.get("destinationNetworks", [])
        if not isinstance(destination_networks, list):
            raise ConfigError(
                f"{path}: spec.wireguard.connections[{index}].destinationNetworks 必须是数组"
            )
        for network_index, network in enumerate(destination_networks):
            _validate_network(
                path,
                network,
                f"spec.wireguard.connections[{index}].destinationNetworks[{network_index}]",
            )
        if item.get("mode", "masquerade") != "masquerade":
            raise ConfigError(
                f"{path}: spec.wireguard.connections[{index}].mode "
                "目前只支持 masquerade"
            )
        for field in ("allowReturnTraffic", "autoConnect"):
            if field in item and not isinstance(item[field], bool):
                raise ConfigError(
                    f"{path}: spec.wireguard.connections[{index}].{field} 必须是布尔值"
                )


def _validate_network(path: Path, value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{path}: {field} 不能为空")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ConfigError(f"{path}: {field} 不是有效网段") from exc
    if network.version != 4:
        raise ConfigError(f"{path}: {field} 目前只支持 IPv4")


def _validate_wireguard_peer_management(
    path: Path,
    interface_index: int,
    value: Any,
) -> None:
    prefix = f"spec.wireguard.interfaces[{interface_index}].peerManagement"
    section = _mapping(value, prefix)
    for field in ("addressPool", "publicEndpoint"):
        if not isinstance(section.get(field), str) or not section[field].strip():
            raise ConfigError(f"{path}: {prefix}.{field} 不能为空")
    _validate_network(path, section["addressPool"], f"{prefix}.addressPool")
    for field in (
        "metadataDirectory",
        "clientOutputDirectory",
        "serverPublicKeyFile",
        "defaultAccessProfile",
    ):
        if field in section and (
            not isinstance(section[field], str) or not section[field].strip()
        ):
            raise ConfigError(f"{path}: {prefix}.{field} 必须是非空字符串")
    profiles = _mapping(section.get("accessProfiles", {}), f"{prefix}.accessProfiles")
    if not profiles:
        raise ConfigError(f"{path}: {prefix}.accessProfiles 至少需要一个权限模板")
    for profile_name, profile_value in profiles.items():
        if not isinstance(profile_name, str) or not NAME_PATTERN.fullmatch(profile_name):
            raise ConfigError(f"{path}: {prefix}.accessProfiles 模板名格式无效")
        profile = _mapping(profile_value, f"{prefix}.accessProfiles.{profile_name}")
        allowed = profile.get("allowedIPs")
        if not isinstance(allowed, list) or not allowed:
            raise ConfigError(
                f"{path}: {prefix}.accessProfiles.{profile_name}.allowedIPs "
                "必须是非空数组"
            )
        for index, network in enumerate(allowed):
            _validate_network(
                path,
                network,
                f"{prefix}.accessProfiles.{profile_name}.allowedIPs[{index}]",
            )
    default_profile = section.get("defaultAccessProfile")
    if default_profile is not None and default_profile not in profiles:
        raise ConfigError(f"{path}: {prefix}.defaultAccessProfile 未定义")


def _validate_string_list(path: Path, value: Any, field: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConfigError(f"{path}: {field} 必须是字符串数组")


def discover_services(root: Path) -> list[Path]:
    service_root = services_directory(root)
    if not service_root.exists():
        return []
    return sorted(service_root.glob("*/service.yaml"))


def load_all(root: Path) -> list[ServiceDefinition]:
    services: list[ServiceDefinition] = []
    names: set[str] = set()
    for path in discover_services(root):
        service = load_service(path)
        if service.name in names:
            raise ConfigError(f"服务名重复: {service.name}")
        names.add(service.name)
        services.append(service)
    return services


def find_service(root: Path, name: str) -> ServiceDefinition:
    matches = [service for service in load_all(root) if service.name == name]
    if not matches:
        raise ConfigError(f"找不到服务: {name}")
    return matches[0]


def resolve_declared_paths(service: ServiceDefinition, values: Iterable[str]) -> list[Path]:
    allow_external = bool(service.spec.get("config", {}).get("allowExternalConfig", False))
    base = service.directory.resolve()
    resolved: list[Path] = []
    for value in values:
        candidate = Path(value)
        path = candidate.resolve() if candidate.is_absolute() else (base / candidate).resolve()
        if not allow_external and not path.is_relative_to(base):
            raise ConfigError(
                f"{service.name}: 配置路径超出服务目录: {value}; "
                "如确有需要，请设置 spec.config.allowExternalConfig: true"
            )
        resolved.append(path)
    return resolved

