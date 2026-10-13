from __future__ import annotations

import sys

from ..models import CommandPlan
from .base import Driver


class ProcessDriver(Driver):
    operations = Driver.operations | {"prepare"}

    def plans(
        self,
        operation: str,
        *,
        follow: bool = False,
        tail: int = 100,
    ) -> list[CommandPlan]:
        self.ensure_operation(operation)
        argv = [
            sys.executable,
            "-m",
            "homelabctl.process_control",
            operation,
            str(self.service.path),
        ]
        if operation == "logs":
            argv.extend(("--tail", str(tail)))
            if follow:
                argv.append("--follow")
        return [CommandPlan(argv=tuple(argv), cwd=self.cwd)]

    def config_values(self) -> list[str]:
        values = super().config_values()
        files = self.service.spec["process"].get("environmentFromFiles", {})
        values.extend(str(value) for value in files.values())
        return values
