from __future__ import annotations

from ..models import CommandPlan
from .base import Driver


class SystemdDriver(Driver):
    def _systemctl(self, operation: str) -> list[str]:
        section = self.service.spec["systemd"]
        user_mode = section.get("user", False)
        args: list[str] = []
        if not user_mode and operation in {"start", "stop", "restart"} and section.get(
            "sudo", True
        ):
            args.extend(("sudo", "-n"))
        args.append("systemctl")
        if user_mode:
            args.append("--user")
        return args

    def plans(self, operation: str, *, follow: bool = False, tail: int = 100) -> list[CommandPlan]:
        self.ensure_operation(operation)
        unit = self.service.spec["systemd"]["unit"]
        if operation == "logs":
            args = ["journalctl", "--unit", unit, "--lines", str(tail)]
            if self.service.spec["systemd"].get("user", False):
                args.insert(1, "--user")
            if follow:
                args.append("--follow")
        else:
            action = "status" if operation == "status" else operation
            args = [*self._systemctl(operation), action, unit]
        return [CommandPlan(argv=tuple(args), cwd=self.cwd)]

