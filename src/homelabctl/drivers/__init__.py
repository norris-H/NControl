from .base import Driver
from .compose import ComposeDriver
from .docker import DockerDriver
from .frp import FrpDriver
from .process import ProcessDriver
from .script import ScriptDriver
from .systemd import SystemdDriver
from .wireguard import WireGuardDriver

DRIVERS: dict[str, type[Driver]] = {
    "docker": DockerDriver,
    "compose": ComposeDriver,
    "systemd": SystemdDriver,
    "script": ScriptDriver,
    "frp": FrpDriver,
    "process": ProcessDriver,
    "wireguard": WireGuardDriver,
}


def get_driver(service):
    return DRIVERS[service.driver](service)


__all__ = ["DRIVERS", "Driver", "get_driver"]

