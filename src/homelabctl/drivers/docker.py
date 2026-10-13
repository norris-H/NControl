from __future__ import annotations

from ..models import CommandPlan
from .base import Driver


class DockerDriver(Driver):
    def plans(self, operation: str, *, follow: bool = False, tail: int = 100) -> list[CommandPlan]:
        self.ensure_operation(operation)
        container = self.service.spec["docker"]["container"]
        if operation in {"start", "stop", "restart"}:
            argv = ("docker", operation, container)
        elif operation == "status":
            argv = (
                "docker",
                "inspect",
                "--format",
                "{{.Name}} {{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
                container,
            )
        else:
            args = ["docker", "logs", "--tail", str(tail)]
            if follow:
                args.append("--follow")
            args.append(container)
            argv = tuple(args)
        return [CommandPlan(argv=argv, cwd=self.cwd)]

