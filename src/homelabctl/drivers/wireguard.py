from __future__ import annotations

import os
import sys

from ..config import resolve_declared_paths
from ..errors import UnsupportedOperation
from ..models import CommandPlan
from .base import Driver


def _is_windows() -> bool:
    return os.name == "nt"


class WireGuardDriver(Driver):
    def _interfaces(self) -> list[dict[str, object]]:
        section = self.service.spec["wireguard"]
        interfaces = section.get("interfaces")
        if isinstance(interfaces, list):
            return interfaces
        return [
            {
                "name": section["interface"],
                "config": section["config"],
                "sudo": section.get("sudo", True),
            }
        ]

    def _config_path(self, interface: dict[str, object]):
        return resolve_declared_paths(self.service, [str(interface["config"])])[0]

    def _linux_plans(self, operation: str) -> list[CommandPlan]:
        section = self.service.spec["wireguard"]
        plans: list[CommandPlan] = []
        interfaces = self._interfaces()
        if operation == "stop":
            for connection in reversed(section.get("connections", [])):
                if connection.get("autoConnect", False):
                    plans.append(
                        self.management_plan("disconnect", str(connection["name"]))
                    )
            interfaces = list(reversed(interfaces))
        for interface in interfaces:
            use_sudo = interface.get("sudo", section.get("sudo", True))
            prefix = ("sudo", "-n") if use_sudo else ()
            if operation == "status":
                argv = (*prefix, "wg", "show", str(interface["name"]))
            else:
                action = "up" if operation == "start" else "down"
                argv = (*prefix, "wg-quick", action, str(self._config_path(interface)))
            plans.append(CommandPlan(argv=argv, cwd=self.cwd))
        if operation == "start":
            for connection in section.get("connections", []):
                if connection.get("autoConnect", False):
                    plans.append(self.management_plan("connect", str(connection["name"])))
        return plans

    def _windows_plans(self, operation: str) -> list[CommandPlan]:
        section = self.service.spec["wireguard"]
        executable = str(
            section.get(
                "windowsExecutable",
                r"C:\Program Files\WireGuard\wireguard.exe",
            )
        )
        plans: list[CommandPlan] = []
        for interface in self._interfaces():
            name = str(interface["name"])
            if operation == "status":
                argv = ("sc.exe", "query", f"WireGuardTunnel${name}")
            elif operation == "start":
                argv = (
                    executable,
                    "/installtunnelservice",
                    str(self._config_path(interface)),
                )
            else:
                argv = (executable, "/uninstalltunnelservice", name)
            plans.append(CommandPlan(argv=argv, cwd=self.cwd))
        return plans

    def plans(self, operation: str, *, follow: bool = False, tail: int = 100) -> list[CommandPlan]:
        if operation in {"start", "stop", "status"}:
            if _is_windows():
                return self._windows_plans(operation)
            return self._linux_plans(operation)
        if operation == "restart":
            if _is_windows():
                return [
                    *self._windows_plans("stop"),
                    *self._windows_plans("start"),
                ]
            return [*self._linux_plans("stop"), *self._linux_plans("start")]
        raise UnsupportedOperation(
            "WireGuard 驱动不提供日志；请使用系统 WireGuard 日志工具"
        )

    def config_values(self) -> list[str]:
        values = super().config_values()
        values.extend(str(interface["config"]) for interface in self._interfaces())
        return values

    def management_plan(self, operation: str, *arguments: str) -> CommandPlan:
        """Build a plan for the Linux-only WireGuard management helper."""
        if _is_windows():
            raise UnsupportedOperation("WireGuard 网络连接和客户端管理目前只支持 Linux")
        return CommandPlan(
            argv=(
                sys.executable,
                "-m",
                "homelabctl.wireguard_control",
                str(self.service.path),
                operation,
                *arguments,
            ),
            cwd=self.cwd,
        )

