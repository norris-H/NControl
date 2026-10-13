from __future__ import annotations

from ..models import CommandPlan
from .base import Driver


class ComposeDriver(Driver):
    def _prefix(self) -> list[str]:
        config = self.service.spec["compose"]
        compose_file = (self.service.directory / config["file"]).resolve()
        args = ["docker", "compose", "-f", str(compose_file)]
        project_name = config.get("projectName")
        if project_name:
            args.extend(["--project-name", str(project_name)])
        return args

    def _services(self) -> list[str]:
        values = self.service.spec["compose"].get("services", [])
        return [str(value) for value in values]

    def plans(self, operation: str, *, follow: bool = False, tail: int = 100) -> list[CommandPlan]:
        self.ensure_operation(operation)
        args = self._prefix()
        services = self._services()
        if operation == "start":
            args.extend(["up", "-d", *services])
        elif operation == "stop":
            args.extend(["stop", *services])
        elif operation == "restart":
            args.extend(["restart", *services])
        elif operation == "status":
            args.extend(["ps", *services])
        else:
            args.extend(["logs", "--tail", str(tail)])
            if follow:
                args.append("--follow")
            args.extend(services)
        return [CommandPlan(argv=tuple(args), cwd=self.cwd)]

    def config_values(self) -> list[str]:
        values = super().config_values()
        values.append(self.service.spec["compose"]["file"])
        return values

