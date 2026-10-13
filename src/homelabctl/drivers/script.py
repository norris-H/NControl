from __future__ import annotations

import sys
from typing import Any

from ..errors import ConfigError, UnsupportedOperation
from ..models import CommandPlan
from .base import Driver


class ScriptDriver(Driver):
    def plans(self, operation: str, *, follow: bool = False, tail: int = 100) -> list[CommandPlan]:
        self.ensure_operation(operation)
        value: Any = self.service.spec["script"]["commands"].get(operation)
        if value is None:
            raise UnsupportedOperation(f"{self.service.name}: 未配置脚本操作 {operation}")
        commands = self._normalize(value, operation)
        return [
            CommandPlan(argv=tuple(self._expand(command)), cwd=self.cwd)
            for command in commands
        ]

    def _expand(self, command: list[str]) -> list[str]:
        tokens = {
            "{python}": sys.executable,
            "{serviceDir}": str(self.service.directory),
            "{workingDirectory}": str(self.cwd),
            "{root}": str(self.service.directory.parent.parent),
        }
        return [tokens.get(value, value) for value in command]

    def clear_log_plans(self) -> list[CommandPlan]:
        value: Any = self.service.spec["script"]["commands"].get("clearLogs")
        if value is None:
            return super().clear_log_plans()
        commands = self._normalize(value, "clearLogs")
        return [
            CommandPlan(argv=tuple(self._expand(command)), cwd=self.cwd)
            for command in commands
        ]

    def _normalize(self, value: Any, operation: str) -> list[list[str]]:
        if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
            return [value]
        if (
            isinstance(value, list)
            and value
            and all(isinstance(command, list) and command and all(isinstance(item, str) for item in command) for command in value)
        ):
            return value
        raise ConfigError(
            f"{self.service.name}: script.commands.{operation} 必须是参数数组或参数数组列表"
        )

