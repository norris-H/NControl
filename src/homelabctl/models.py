from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ServiceDefinition:
    path: Path
    name: str
    description: str
    driver: str
    spec: dict[str, Any]
    raw: dict[str, Any]

    @property
    def directory(self) -> Path:
        return self.path.parent

    @property
    def working_directory(self) -> Path:
        value = self.spec.get("workingDirectory", ".")
        return (self.directory / value).resolve()

    @property
    def autostart(self) -> bool:
        return bool(self.spec.get("autostart", False))

    @property
    def start_order(self) -> int:
        return int(self.spec.get("startOrder", 50))


@dataclass(frozen=True)
class CommandPlan:
    argv: tuple[str, ...]
    cwd: Path | None = None

    def display(self) -> str:
        import shlex

        return shlex.join(self.argv)


@dataclass(frozen=True)
class CheckResult:
    level: str
    message: str

