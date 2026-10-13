from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

import psutil

from .config import load_service
from .errors import HomelabError
from .models import ServiceDefinition


def _platform_name() -> str:
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _section(service: ServiceDefinition) -> dict[str, Any]:
    return service.spec["process"]


def _service_path(service: ServiceDefinition, value: str) -> Path:
    path = (service.directory / value).resolve()
    if not path.is_relative_to(service.directory.resolve()):
        raise HomelabError(f"{service.name}: 运行文件路径超出服务目录: {value}")
    return path


def _state_path(service: ServiceDefinition) -> Path:
    return _service_path(
        service,
        str(_section(service).get("stateFile", ".ncontrol/process.json")),
    )


def _log_path(service: ServiceDefinition) -> Path:
    return _service_path(
        service,
        str(_section(service).get("logFile", "logs/service.log")),
    )


def _tokens(service: ServiceDefinition) -> dict[str, str]:
    return {
        "{python}": sys.executable,
        "{serviceDir}": str(service.directory),
        "{workingDirectory}": str(service.working_directory),
        "{root}": str(service.directory.parent.parent),
    }


def _expand(service: ServiceDefinition, value: str) -> str:
    result = value
    for token, replacement in _tokens(service).items():
        result = result.replace(token, replacement)
    return result


def _command(service: ServiceDefinition) -> list[str]:
    section = _section(service)
    platform_commands = section.get("platformCommands", {})
    command = platform_commands.get(_platform_name(), section["command"])
    return [_expand(service, str(part)) for part in command]


def _prepare_command(service: ServiceDefinition) -> list[str]:
    section = _section(service)
    platform_commands = section.get("platformPrepareCommands", {})
    command = platform_commands.get(_platform_name(), section.get("prepareCommand"))
    if command is None:
        raise HomelabError(f"{service.name}: 未配置依赖准备命令")
    return [_expand(service, str(part)) for part in command]


def _environment(service: ServiceDefinition) -> dict[str, str]:
    section = _section(service)
    environment = os.environ.copy()
    for key, value in section.get("environment", {}).items():
        environment[str(key)] = _expand(service, str(value))
    for key, value in section.get("environmentFromFiles", {}).items():
        path = _service_path(service, str(value))
        try:
            environment[str(key)] = path.read_text(encoding="utf-8").strip()
        except FileNotFoundError as exc:
            raise HomelabError(f"{service.name}: 找不到环境变量文件: {path}") from exc
    return environment


def _read_state(service: ServiceDefinition) -> dict[str, Any] | None:
    path = _state_path(service)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _write_state(service: ServiceDefinition, value: dict[str, Any]) -> None:
    path = _state_path(service)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _remove_state(service: ServiceDefinition) -> None:
    try:
        _state_path(service).unlink()
    except FileNotFoundError:
        pass


def _live_process(state: dict[str, Any] | None) -> psutil.Process | None:
    if not state:
        return None
    try:
        pid = int(state["pid"])
        expected_create_time = float(state["createTime"])
        process = psutil.Process(pid)
        if abs(process.create_time() - expected_create_time) > 0.01:
            return None
        if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
            return None
        return process
    except (KeyError, TypeError, ValueError, psutil.Error):
        return None


def _tail(path: Path, count: int) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return list(deque(handle, maxlen=count)) if count else []
    except FileNotFoundError:
        return []


def start(service: ServiceDefinition) -> int:
    state = _read_state(service)
    running = _live_process(state)
    if running is not None:
        print(f"{service.name} 已在运行（PID {running.pid}）")
        return 0
    if state is not None:
        _remove_state(service)

    cwd = service.working_directory
    if not cwd.is_dir():
        raise HomelabError(f"{service.name}: 工作目录不存在: {cwd}")
    command = _command(service)
    log_path = _log_path(service)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(exist_ok=True)
    if os.name != "nt":
        log_path.chmod(0o600)

    creation: dict[str, Any] = {}
    if os.name == "nt":
        creation["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        )
    else:
        creation["start_new_session"] = True

    try:
        with log_path.open("ab", buffering=0) as log_handle:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=_environment(service),
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                close_fds=True,
                shell=False,
                **creation,
            )
    except FileNotFoundError as exc:
        raise HomelabError(f"{service.name}: 找不到可执行程序: {command[0]}") from exc
    except OSError as exc:
        raise HomelabError(f"{service.name}: 启动失败: {exc}") from exc

    try:
        create_time = psutil.Process(process.pid).create_time()
    except psutil.Error:
        create_time = time.time()
    _write_state(
        service,
        {
            "version": 1,
            "pid": process.pid,
            "createTime": create_time,
            "startedAt": datetime.now(timezone.utc).isoformat(),
            "platform": _platform_name(),
            "command": command,
        },
    )

    grace = float(_section(service).get("startupGraceSeconds", 0.5))
    if grace:
        time.sleep(grace)
    exit_code = process.poll()
    if exit_code is not None:
        _remove_state(service)
        recent = "".join(_tail(log_path, 20)).rstrip()
        detail = f"\n最近日志:\n{recent}" if recent else ""
        raise HomelabError(
            f"{service.name}: 进程启动后立即退出（退出码 {exit_code}）{detail}"
        )
    print(f"{service.name} 启动成功（PID {process.pid}）")
    return 0


def prepare(service: ServiceDefinition) -> int:
    command = _prepare_command(service)
    try:
        completed = subprocess.run(
            command,
            cwd=service.working_directory,
            env=_environment(service),
            stdin=subprocess.DEVNULL,
            shell=False,
            check=False,
        )
    except FileNotFoundError as exc:
        raise HomelabError(f"{service.name}: 找不到可执行程序: {command[0]}") from exc
    if completed.returncode != 0:
        raise HomelabError(
            f"{service.name}: 依赖准备失败（退出码 {completed.returncode}）"
        )
    print(f"{service.name} 依赖准备完成")
    return 0


def stop(service: ServiceDefinition) -> int:
    state = _read_state(service)
    process = _live_process(state)
    if process is None:
        _remove_state(service)
        print(f"{service.name} 未运行")
        return 0

    try:
        processes = process.children(recursive=True)
    except psutil.Error:
        processes = []
    processes.append(process)
    for item in reversed(processes):
        try:
            item.terminate()
        except psutil.NoSuchProcess:
            pass
    timeout = float(_section(service).get("stopTimeoutSeconds", 10))
    _, alive = psutil.wait_procs(processes, timeout=timeout)
    for item in alive:
        try:
            item.kill()
        except psutil.NoSuchProcess:
            pass
    if alive:
        psutil.wait_procs(alive, timeout=3)
    _remove_state(service)
    print(f"{service.name} 已停止")
    return 0


def status(service: ServiceDefinition) -> int:
    state = _read_state(service)
    process = _live_process(state)
    if process is None:
        if state is not None:
            _remove_state(service)
        print(f"{service.name} 未运行")
        return 3
    print(f"{service.name} 正在运行（PID {process.pid}）")
    return 0


def logs(service: ServiceDefinition, *, tail: int, follow: bool) -> int:
    path = _log_path(service)
    lines = _tail(path, tail)
    if not lines and not path.exists():
        print(f"{service.name} 暂无日志: {path}")
        return 0
    for line in lines:
        print(line, end="")
    if not follow:
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(0, os.SEEK_END)
        while True:
            line = handle.readline()
            if line:
                print(line, end="", flush=True)
            else:
                time.sleep(0.25)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="homelabctl.process_control")
    parser.add_argument(
        "operation",
        choices=("prepare", "start", "stop", "restart", "status", "logs"),
    )
    parser.add_argument("service_file", type=Path)
    parser.add_argument("--tail", type=int, default=100)
    parser.add_argument("--follow", action="store_true")
    return parser


def run(args: argparse.Namespace) -> int:
    service = load_service(args.service_file)
    if service.driver != "process":
        raise HomelabError(f"{service.name}: 不是 process 驱动")
    if args.operation == "prepare":
        return prepare(service)
    if args.operation == "start":
        return start(service)
    if args.operation == "stop":
        return stop(service)
    if args.operation == "restart":
        stop(service)
        return start(service)
    if args.operation == "status":
        return status(service)
    return logs(service, tail=args.tail, follow=args.follow)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except HomelabError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
