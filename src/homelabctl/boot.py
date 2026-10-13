from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

import yaml

from .config import find_service, load_all
from .drivers import get_driver
from .errors import HomelabError
from .health import runtime_state
from .layout import runtime_directory
from .runner import CommandRunner


def set_service_autostart(root: Path, service_name: str, enabled: bool) -> None:
    service = find_service(root, service_name)
    raw = service.raw
    raw["spec"]["autostart"] = enabled
    temporary = service.path.with_suffix(service.path.suffix + ".tmp")
    temporary.write_text(
        yaml.safe_dump(raw, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    os.replace(temporary, service.path)


def run_enabled(root: Path, *, dry_run: bool = False) -> int:
    failures = 0
    enabled = sorted(
        (service for service in load_all(root) if service.autostart),
        key=lambda service: (service.start_order, service.name),
    )
    if not enabled:
        print("没有启用开机启动的服务")
        return 0
    for service in enabled:
        try:
            state, summary, _ = runtime_state(service)
            if state != "stopped":
                print(f"跳过 {service.name}: {summary}")
                continue
            print(f"启动 {service.name}…")
            code = CommandRunner(dry_run=dry_run).execute(get_driver(service).plans("start"))
            if code != 0:
                failures += 1
                print(f"{service.name} 启动失败（退出码 {code}）")
        except (HomelabError, OSError) as exc:
            failures += 1
            print(f"{service.name} 启动失败：{exc}")
    return 1 if failures else 0


def _tag(root: Path) -> str:
    digest = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:12]
    return f"# NCONTROL_AUTOSTART:{digest}"


def _linux_crontab() -> tuple[int, str]:
    try:
        completed = subprocess.run(
            ("crontab", "-l"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            shell=False,
            check=False,
        )
    except FileNotFoundError as exc:
        raise HomelabError("系统未安装 crontab，无法注册开机入口") from exc
    return completed.returncode, completed.stdout


def _linux_lines(root: Path) -> tuple[str, str]:
    root = root.resolve()
    tag = _tag(root)
    launcher = root / "ncontrol"
    log_path = runtime_directory(root) / "autostart.log"
    command = (
        f"cd {shlex.quote(str(root))} && "
        f"{shlex.quote(str(launcher))} boot run >> {shlex.quote(str(log_path))} 2>&1"
    )
    return tag, f"@reboot {command}"


def install(root: Path) -> str:
    root = root.resolve()
    runtime_directory(root).mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        task_name = f"NControl-{hashlib.sha256(str(root).encode()).hexdigest()[:12]}"
        launcher = root / "ncontrol.cmd"
        command = (
            "schtasks.exe",
            "/Create",
            "/F",
            "/SC",
            "ONLOGON",
            "/TN",
            task_name,
            "/TR",
            f'cmd.exe /c "{launcher}" boot run',
        )
        result = subprocess.run(command, shell=False, check=False)
        if result.returncode != 0:
            raise HomelabError(f"注册 Windows 开机入口失败（退出码 {result.returncode}）")
        return f"已注册 Windows 登录启动任务 {task_name}"

    code, current = _linux_crontab()
    if code not in {0, 1}:
        raise HomelabError("无法读取当前用户的 crontab")
    tag, line = _linux_lines(root)
    rows = current.splitlines()
    filtered: list[str] = []
    skip_next = False
    for row in rows:
        if skip_next:
            skip_next = False
            continue
        if row.strip() == tag:
            skip_next = True
            continue
        filtered.append(row)
    filtered.extend([tag, line])
    content = "\n".join(filtered).rstrip() + "\n"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    try:
        result = subprocess.run(("crontab", str(temporary)), shell=False, check=False)
    finally:
        temporary.unlink(missing_ok=True)
    if result.returncode != 0:
        raise HomelabError(f"注册开机入口失败（退出码 {result.returncode}）")
    return "已注册 NControl 开机入口（crontab @reboot）"


def is_installed(root: Path) -> bool:
    root = root.resolve()
    if os.name == "nt":
        task_name = f"NControl-{hashlib.sha256(str(root).encode()).hexdigest()[:12]}"
        result = subprocess.run(
            ("schtasks.exe", "/Query", "/TN", task_name),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            check=False,
        )
        return result.returncode == 0
    code, current = _linux_crontab()
    return code == 0 and _tag(root) in current.splitlines()


def uninstall(root: Path) -> str:
    root = root.resolve()
    if os.name == "nt":
        task_name = f"NControl-{hashlib.sha256(str(root).encode()).hexdigest()[:12]}"
        result = subprocess.run(
            ("schtasks.exe", "/Delete", "/F", "/TN", task_name),
            shell=False,
            check=False,
        )
        if result.returncode != 0:
            raise HomelabError("删除 Windows 开机入口失败")
        return "已删除 NControl 登录启动任务"
    code, current = _linux_crontab()
    if code not in {0, 1}:
        raise HomelabError("无法读取当前用户的 crontab")
    tag = _tag(root)
    rows = current.splitlines()
    filtered: list[str] = []
    skip_next = False
    for row in rows:
        if skip_next:
            skip_next = False
            continue
        if row.strip() == tag:
            skip_next = True
            continue
        filtered.append(row)
    content = "\n".join(filtered).rstrip()
    if content:
        content += "\n"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    try:
        result = subprocess.run(("crontab", str(temporary)), shell=False, check=False)
    finally:
        temporary.unlink(missing_ok=True)
    if result.returncode != 0:
        raise HomelabError("删除 NControl 开机入口失败")
    return "已删除 NControl 开机入口"

