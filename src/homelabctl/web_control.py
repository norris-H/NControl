from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from typing import Any

import psutil
import yaml

from .errors import HomelabError
from .layout import node_directory, runtime_directory


DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8765
_SPAWNED_PROCESSES: dict[int, subprocess.Popen[bytes]] = {}


@dataclass(frozen=True)
class WebStatus:
    enabled: bool
    running: bool
    bind: str
    port: int
    url: str
    pid: int | None = None


def config_path(root: Path) -> Path:
    return node_directory(root) / "web.yaml"


def token_path(root: Path) -> Path:
    return node_directory(root) / "secrets" / "web-token.txt"


def state_path(root: Path) -> Path:
    return runtime_directory(root) / "web.json"


def log_path(root: Path) -> Path:
    return runtime_directory(root) / "web.log"


def load_config(root: Path) -> dict[str, Any]:
    path = config_path(root)
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        value = {}
    except (OSError, yaml.YAMLError) as exc:
        raise HomelabError(f"Web 管理配置读取失败: {exc}") from exc
    if not isinstance(value, dict):
        raise HomelabError("Web 管理配置必须是一个对象")
    bind = str(value.get("bind", DEFAULT_BIND))
    try:
        port = int(value.get("port", DEFAULT_PORT))
    except (TypeError, ValueError) as exc:
        raise HomelabError("Web 管理端口无效") from exc
    _validate_endpoint(bind, port)
    return {
        "version": 1,
        "enabled": bool(value.get("enabled", False)),
        "bind": bind,
        "port": port,
    }


def _validate_endpoint(bind: str, port: int) -> None:
    try:
        address = ipaddress.ip_address(bind)
    except ValueError as exc:
        raise HomelabError("Web 管理监听地址必须是本机 IP，不能使用主机名") from exc
    if address.is_unspecified:
        raise HomelabError("Web 管理禁止监听 0.0.0.0 或 ::；请指定本机或 WireGuard IP")
    if address.version != 4:
        raise HomelabError("Web 管理目前只支持 IPv4 监听地址")
    if not 1 <= port <= 65535:
        raise HomelabError("Web 管理端口必须在 1-65535 之间")


def _local_ipv4_addresses() -> set[str]:
    values = {"127.0.0.1"}
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if address.family.name == "AF_INET":
                values.add(str(address.address))
    return values


def _atomic_yaml(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        yaml.safe_dump(value, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    os.replace(temporary, path)
    if os.name != "nt":
        path.chmod(0o600)


def _ensure_token(root: Path) -> str:
    path = token_path(root)
    try:
        token = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        token = ""
    if token:
        return token
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(token + "\n", encoding="utf-8")
    os.replace(temporary, path)
    if os.name != "nt":
        path.chmod(0o600)
    return token


def read_token(root: Path) -> str:
    try:
        token = token_path(root).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise HomelabError("Web 管理令牌不存在；请先启用 Web 管理") from exc
    if not token:
        raise HomelabError("Web 管理令牌为空；请重置令牌")
    return token


def enable(root: Path, bind: str = DEFAULT_BIND, port: int = DEFAULT_PORT) -> str:
    root = root.resolve()
    _validate_endpoint(bind, port)
    if bind not in _local_ipv4_addresses():
        raise HomelabError(f"监听地址 {bind} 不是当前主机的 IPv4 地址")
    previous = load_config(root)
    if _live_process(root) is not None and (
        bind != previous["bind"] or port != previous["port"]
    ):
        raise HomelabError("Web 管理正在运行；请先停止，再修改监听地址或端口")
    token = _ensure_token(root)
    _atomic_yaml(
        config_path(root),
        {"version": 1, "enabled": True, "bind": bind, "port": port},
    )
    return token


def rotate_token(root: Path) -> str:
    config = load_config(root)
    if not config["enabled"]:
        raise HomelabError("Web 管理尚未启用")
    was_running = _live_process(root) is not None
    if was_running:
        stop(root)
    path = token_path(root)
    path.unlink(missing_ok=True)
    token = _ensure_token(root)
    if was_running:
        start(root)
    return token


def _read_state(root: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(state_path(root).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _live_process(root: Path) -> psutil.Process | None:
    state = _read_state(root)
    if not state:
        return None
    try:
        process = psutil.Process(int(state["pid"]))
        if abs(process.create_time() - float(state["createTime"])) > 0.01:
            return None
        if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
            return None
        return process
    except (KeyError, TypeError, ValueError, psutil.Error):
        return None


def status(root: Path) -> WebStatus:
    config = load_config(root)
    process = _live_process(root)
    bind = str(config["bind"])
    port = int(config["port"])
    return WebStatus(
        enabled=bool(config["enabled"]),
        running=process is not None,
        bind=bind,
        port=port,
        url=f"http://{bind}:{port}/",
        pid=process.pid if process else None,
    )


def status_dict(root: Path) -> dict[str, Any]:
    return asdict(status(root))


def start(root: Path) -> WebStatus:
    root = root.resolve()
    config = load_config(root)
    if not config["enabled"]:
        raise HomelabError("Web 管理默认关闭；请先显式启用")
    running = _live_process(root)
    if running is not None:
        return status(root)
    _ensure_token(root)
    runtime = runtime_directory(root)
    runtime.mkdir(parents=True, exist_ok=True)
    web_log = log_path(root)
    web_log.touch(exist_ok=True)
    creation: dict[str, Any] = {}
    if os.name == "nt":
        creation["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        )
    else:
        creation["start_new_session"] = True
    with web_log.open("ab", buffering=0) as output:
        process = subprocess.Popen(
            (
                sys.executable,
                "-m",
                "homelabctl.web_server",
                "--root",
                str(root),
            ),
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            close_fds=True,
            shell=False,
            **creation,
        )
    _SPAWNED_PROCESSES[process.pid] = process
    try:
        create_time = psutil.Process(process.pid).create_time()
    except psutil.Error:
        create_time = time.time()
    state_path(root).write_text(
        json.dumps(
            {"version": 1, "pid": process.pid, "createTime": create_time},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    time.sleep(0.4)
    if process.poll() is not None:
        _SPAWNED_PROCESSES.pop(process.pid, None)
        state_path(root).unlink(missing_ok=True)
        try:
            recent = "\n".join(web_log.read_text(encoding="utf-8", errors="replace").splitlines()[-10:])
        except OSError:
            recent = ""
        raise HomelabError(f"Web 管理启动失败{': ' + recent if recent else ''}")
    return status(root)


def stop(root: Path) -> WebStatus:
    process = _live_process(root)
    if process is None:
        state_path(root).unlink(missing_ok=True)
        return status(root)
    try:
        children = process.children(recursive=True)
    except psutil.Error:
        children = []
    targets = [*children, process]
    for item in reversed(targets):
        try:
            item.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(targets, timeout=5)
    for item in alive:
        try:
            item.kill()
        except psutil.NoSuchProcess:
            pass
    spawned = _SPAWNED_PROCESSES.pop(process.pid, None)
    if spawned is not None:
        try:
            spawned.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    state_path(root).unlink(missing_ok=True)
    return status(root)


def disable(root: Path) -> WebStatus:
    stop(root)
    config = load_config(root)
    _atomic_yaml(
        config_path(root),
        {
            "version": 1,
            "enabled": False,
            "bind": config["bind"],
            "port": config["port"],
        },
    )
    return status(root)
