from __future__ import annotations

import getpass
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
from typing import Any

import yaml

from .audit import audit_services
from .config import load_all, load_service, resolve_declared_paths
from .drivers import get_driver
from .errors import HomelabError
from .layout import runtime_directory
from .models import CheckResult, ServiceDefinition
from .security import check_config_paths


def machine_id() -> str:
    if os.name != "nt":
        try:
            value = Path("/etc/machine-id").read_text(encoding="ascii").strip()
        except OSError:
            value = ""
        if value:
            return value
    return f"{platform.node()}:{platform.machine()}:{platform.system()}"


def record_machine(root: Path) -> None:
    path = runtime_directory(root) / "machine-id"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(machine_id() + "\n", encoding="utf-8")
    os.replace(temporary, path)
    if os.name != "nt":
        path.chmod(0o600)


def wireguard_public_hosts(root: Path) -> list[str]:
    hosts: list[str] = []
    for service in load_all(root):
        if service.driver != "wireguard":
            continue
        for interface in service.spec.get("wireguard", {}).get("interfaces", []):
            management = interface.get("peerManagement") if isinstance(interface, dict) else None
            if not isinstance(management, dict):
                continue
            endpoint = str(management.get("publicEndpoint", ""))
            host, separator, _ = endpoint.rpartition(":")
            if separator and host:
                normalized = host[1:-1] if host.startswith("[") and host.endswith("]") else host
                if normalized not in hosts:
                    hosts.append(normalized)
    return hosts


def _platform_command(service: ServiceDefinition) -> list[str]:
    process = service.spec.get("process", {})
    platforms = process.get("platformCommands", {})
    return list(platforms.get("linux", process.get("command", [])))


def migration_checks(root: Path) -> list[CheckResult]:
    root = root.resolve()
    services = load_all(root)
    results: list[CheckResult] = []
    required = {"python3"}
    has_wireguard = False
    for service in services:
        if service.driver == "process":
            command = _platform_command(service)
            if command:
                executable = str(command[0])
                if executable not in {"{python}"} and "/" not in executable:
                    required.add(executable)
                elif "/" in executable:
                    candidate = (service.working_directory / executable).resolve()
                    if not candidate.exists():
                        results.append(CheckResult("error", f"缺少程序: {candidate}"))
        elif service.driver == "wireguard":
            has_wireguard = True
            required.update({"wg", "wg-quick", "iptables", "iptables-save", "ip", "ping", "sudo"})
        elif service.driver in {"docker", "compose"}:
            required.add("docker")
    if any(service.autostart for service in services):
        required.add("crontab" if os.name != "nt" else "schtasks.exe")

    for executable in sorted(required):
        path = shutil.which(executable)
        if path:
            results.append(CheckResult("ok", f"系统程序可用: {executable} ({path})"))
        else:
            results.append(CheckResult("error", f"缺少系统程序: {executable}"))

    machine = platform.machine().lower()
    for service in services:
        if service.name != "frps" or service.driver != "process":
            continue
        command = _platform_command(service)
        if command and command[0] == "package/frps" and machine not in {"x86_64", "amd64"}:
            level = "error" if service.autostart else "warning"
            results.append(
                CheckResult(
                    level,
                    f"当前 FRP 程序是 x86-64 版本，目标系统架构为 {machine}；"
                    "需要换成对应 ARM 版本后才能启动",
                )
            )
        else:
            results.append(CheckResult("ok", f"目标系统架构: {machine}"))

    for service in services:
        values = list(dict.fromkeys(get_driver(service).config_values()))
        results.extend(check_config_paths(service, values))

    if has_wireguard and os.name != "nt":
        try:
            forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="ascii").strip()
        except OSError as exc:
            results.append(CheckResult("error", f"无法读取 IPv4 转发状态: {exc}"))
        else:
            if forwarding == "1":
                results.append(CheckResult("ok", "IPv4 转发已开启"))
            else:
                results.append(CheckResult("error", "IPv4 转发未开启"))
        sudo = subprocess.run(
            ("sudo", "-n", "wg", "show", "interfaces"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            check=False,
        )
        if sudo.returncode == 0:
            results.append(CheckResult("ok", "WireGuard 可使用免交互 sudo"))
        else:
            results.append(CheckResult("error", "尚未配置 WireGuard 免交互 sudo 权限"))

    for result in audit_services(root):
        level = "warning" if result.level == "error" and "密钥重复" in result.message else result.level
        results.append(CheckResult(level, result.message))
    return results


def _replace_endpoint(content: str, old: str, new: str) -> str:
    pattern = re.compile(r"(?im)^(\s*Endpoint\s*=\s*)" + re.escape(old) + r"\s*$")
    return pattern.sub(lambda match: f"{match.group(1)}{new}", content)


def update_wireguard_public_host(root: Path, public_host: str) -> tuple[int, int]:
    host = public_host.strip()
    if not host or any(character.isspace() for character in host) or "/" in host:
        raise HomelabError("公网地址必须是有效的 IP 或域名")
    services_updated = 0
    clients_updated = 0
    for service in load_all(root):
        if service.driver != "wireguard":
            continue
        raw = service.raw
        changed = False
        client_changes: list[tuple[Path, str]] = []
        interfaces = raw["spec"]["wireguard"].get("interfaces", [])
        for interface in interfaces:
            management = interface.get("peerManagement") if isinstance(interface, dict) else None
            if not isinstance(management, dict):
                continue
            old_endpoint = str(management.get("publicEndpoint", ""))
            _, separator, port = old_endpoint.rpartition(":")
            if not separator or not port.isdigit():
                raise HomelabError(
                    f"{service.name}/{interface.get('name')}: 公网入口格式无效: {old_endpoint}"
                )
            formatted_host = host
            if ":" in host and not host.startswith("["):
                formatted_host = f"[{host}]"
            new_endpoint = f"{formatted_host}:{port}"
            if old_endpoint == new_endpoint:
                continue
            management["publicEndpoint"] = new_endpoint
            changed = True
            output_value = str(management.get("clientOutputDirectory", "secrets/clients"))
            output_directory = resolve_declared_paths(service, [output_value])[0]
            if output_directory.exists():
                for config_path in output_directory.rglob("*.conf"):
                    try:
                        original = config_path.read_text(encoding="utf-8")
                    except OSError:
                        continue
                    updated = _replace_endpoint(original, old_endpoint, new_endpoint)
                    if updated != original:
                        client_changes.append((config_path, updated))
        if not changed:
            continue
        temporary = service.path.with_suffix(service.path.suffix + ".tmp")
        temporary.write_text(
            yaml.safe_dump(raw, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        os.replace(temporary, service.path)
        for config_path, updated in client_changes:
            temporary_config = config_path.with_suffix(config_path.suffix + ".tmp")
            temporary_config.write_text(updated, encoding="utf-8")
            os.replace(temporary_config, config_path)
            if os.name != "nt":
                config_path.chmod(0o600)
            clients_updated += 1
        services_updated += 1
    return services_updated, clients_updated


def configure_wireguard_host() -> str:
    if os.name == "nt":
        raise HomelabError("自动配置 WireGuard 主机权限仅支持 Linux")
    commands = ["wg", "wg-quick", "iptables", "iptables-save", "ip"]
    paths: list[str] = []
    for command in commands:
        path = shutil.which(command)
        if not path:
            raise HomelabError(f"缺少系统程序，无法配置权限: {command}")
        paths.append(str(Path(path)))
    username = getpass.getuser()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", username):
        raise HomelabError("当前用户名格式不适合自动生成 sudo 规则")
    sudoers = "\n".join(
        f"{username} ALL=(root) NOPASSWD: {path} *" for path in paths
    ) + "\n"
    sysctl = "net.ipv4.ip_forward=1\n"
    with tempfile.TemporaryDirectory(prefix="ncontrol-migrate-") as temp:
        temp_path = Path(temp)
        sudoers_path = temp_path / "ncontrol-sudoers"
        sysctl_path = temp_path / "99-ncontrol-forwarding.conf"
        sudoers_path.write_text(sudoers, encoding="utf-8")
        sysctl_path.write_text(sysctl, encoding="utf-8")
        validation = subprocess.run(
            ("sudo", "visudo", "-cf", str(sudoers_path)), shell=False, check=False
        )
        if validation.returncode != 0:
            raise HomelabError("生成的 sudo 权限规则未通过检查")
        for source, target, mode in (
            (sudoers_path, "/etc/sudoers.d/ncontrol", "0440"),
            (sysctl_path, "/etc/sysctl.d/99-ncontrol-forwarding.conf", "0644"),
        ):
            result = subprocess.run(
                ("sudo", "install", "-m", mode, str(source), target),
                shell=False,
                check=False,
            )
            if result.returncode != 0:
                raise HomelabError(f"无法安装系统配置: {target}")
        result = subprocess.run(
            ("sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"),
            shell=False,
            check=False,
        )
        if result.returncode != 0:
            raise HomelabError("无法开启 IPv4 转发")
    return "已配置 WireGuard 限定 sudo 权限和持久 IPv4 转发"

