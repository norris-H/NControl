from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import os
from pathlib import Path
from typing import Any

import yaml

from .errors import HomelabError
from .layout import node_directory


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7890
PROXY_ENVIRONMENT_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)
DEFAULT_NO_PROXY = (
    "localhost,127.0.0.1,::1,.local,"
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
)


@dataclass(frozen=True)
class ProxySettings:
    enabled: bool
    host: str
    port: int

    @property
    def url(self) -> str:
        address = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{address}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["url"] = self.url
        value["scope"] = "host"
        return value

    def environment(self) -> dict[str, str]:
        if not self.enabled:
            return {}
        return {
            "HTTP_PROXY": self.url,
            "HTTPS_PROXY": self.url,
            "ALL_PROXY": self.url,
            "NO_PROXY": DEFAULT_NO_PROXY,
            "http_proxy": self.url,
            "https_proxy": self.url,
            "all_proxy": self.url,
            "no_proxy": DEFAULT_NO_PROXY,
        }


def config_path(root: Path) -> Path:
    return node_directory(root) / "proxy.yaml"


def _validate(host: str, port: int) -> tuple[str, int]:
    host = host.strip()
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise HomelabError("代理地址必须是 IPv4 或 IPv6 地址") from exc
    if address.is_unspecified:
        raise HomelabError("代理地址不能是 0.0.0.0 或 ::")
    if not 1 <= port <= 65535:
        raise HomelabError("代理端口必须在 1-65535 之间")
    return str(address), port


def load_settings(root: Path) -> ProxySettings:
    path = config_path(root)
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        value = {}
    except (OSError, yaml.YAMLError) as exc:
        raise HomelabError(f"代理配置读取失败: {exc}") from exc
    if not isinstance(value, dict):
        raise HomelabError("代理配置必须是一个对象")
    enabled = value.get("enabled", False)
    if not isinstance(enabled, bool):
        raise HomelabError("代理 enabled 必须是 true 或 false")
    host = str(value.get("host", DEFAULT_HOST))
    try:
        port = int(value.get("port", DEFAULT_PORT))
    except (TypeError, ValueError) as exc:
        raise HomelabError("代理端口无效") from exc
    host, port = _validate(host, port)
    return ProxySettings(enabled=enabled, host=host, port=port)


def save_settings(root: Path, *, enabled: bool, host: str, port: int) -> ProxySettings:
    host, port = _validate(host, int(port))
    settings = ProxySettings(enabled=bool(enabled), host=host, port=port)
    path = config_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "enabled": settings.enabled,
                "host": settings.host,
                "port": settings.port,
            },
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    os.replace(temporary, path)
    if os.name != "nt":
        path.chmod(0o600)
    return settings


def disable(root: Path) -> ProxySettings:
    current = load_settings(root)
    return save_settings(
        root,
        enabled=False,
        host=current.host,
        port=current.port,
    )


def apply_process_environment(root: Path) -> ProxySettings:
    """Apply this node's proxy to NControl and processes launched by it."""
    settings = load_settings(root)
    for key in PROXY_ENVIRONMENT_KEYS:
        os.environ.pop(key, None)
    os.environ.update(settings.environment())
    return settings
