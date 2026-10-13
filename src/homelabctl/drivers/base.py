from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ..errors import UnsupportedOperation
from ..models import CommandPlan, ServiceDefinition


class Driver(ABC):
    operations = {"start", "stop", "restart", "status", "logs"}

    def __init__(self, service: ServiceDefinition) -> None:
        self.service = service

    @abstractmethod
    def plans(self, operation: str, *, follow: bool = False, tail: int = 100) -> list[CommandPlan]:
        raise NotImplementedError

    def ensure_operation(self, operation: str) -> None:
        if operation not in self.operations:
            raise UnsupportedOperation(f"不支持的操作: {operation}")

    def config_values(self) -> list[str]:
        config = self.service.spec.get("config", {})
        files = config.get("files", []) if isinstance(config, dict) else []
        if not isinstance(files, list) or not all(isinstance(item, str) for item in files):
            raise UnsupportedOperation(f"{self.service.name}: spec.config.files 必须是字符串数组")
        return list(files)

    @property
    def cwd(self) -> Path:
        return self.service.working_directory

