from __future__ import annotations

from ..errors import UnsupportedOperation
from ..models import CommandPlan
from .base import Driver


class FrpDriver(Driver):
    def plans(self, operation: str, *, follow: bool = False, tail: int = 100) -> list[CommandPlan]:
        raise UnsupportedOperation(
            "FRP 驱动当前只支持 validate/config-check；请先用 systemd 驱动管理现有 frps/frpc 服务"
        )

    def config_values(self) -> list[str]:
        values = super().config_values()
        values.append(self.service.spec["frp"]["config"])
        return values

