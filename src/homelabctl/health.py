from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import psutil

from .config import load_service
from .drivers import get_driver
from .errors import HomelabError, UnsupportedOperation
from .models import ServiceDefinition
from .process_control import _live_process, _read_state
from .wireguard_control import traffic_snapshot


@dataclass(frozen=True)
class HealthCheckResult:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class HealthResult:
    service: str
    state: str
    summary: str
    checks: list[HealthCheckResult]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _run_status_plans(service: ServiceDefinition) -> tuple[int, str]:
    output: list[str] = []
    for plan in get_driver(service).plans("status"):
        try:
            completed = subprocess.run(
                plan.argv,
                cwd=plan.cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                shell=False,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return 2, str(exc)
        output.append(completed.stdout.strip())
        if completed.returncode != 0:
            return completed.returncode, "\n".join(filter(None, output))
    return 0, "\n".join(filter(None, output))


def _process_runtime(service: ServiceDefinition) -> tuple[str, str, dict[str, Any]]:
    state = _read_state(service)
    process = _live_process(state)
    if process is None:
        return "stopped", "进程未运行", {}
    started_age: float | None = None
    if state and isinstance(state.get("startedAt"), str):
        try:
            started = datetime.fromisoformat(str(state["startedAt"]).replace("Z", "+00:00"))
            started_age = max(0.0, (datetime.now(timezone.utc) - started).total_seconds())
        except ValueError:
            pass
    return "healthy", f"进程 PID {process.pid} 正在运行", {
        "pid": process.pid,
        "process": process,
        "startedAge": started_age,
    }


def _wireguard_runtime(service: ServiceDefinition) -> tuple[str, str, dict[str, Any]]:
    snapshot = traffic_snapshot(service)
    interfaces = [item for item in snapshot.get("interfaces", []) if isinstance(item, dict)]
    running = [item for item in interfaces if item.get("running")]
    if not running:
        return "stopped", "WireGuard 接口均未运行", {"wireguard": snapshot}
    if len(running) != len(interfaces):
        return (
            "unhealthy",
            f"WireGuard 仅运行 {len(running)}/{len(interfaces)} 个接口",
            {"wireguard": snapshot},
        )
    return "healthy", f"WireGuard 接口全部运行 {len(running)}/{len(interfaces)}", {
        "wireguard": snapshot
    }


def runtime_state(service: ServiceDefinition) -> tuple[str, str, dict[str, Any]]:
    if service.driver == "process":
        return _process_runtime(service)
    if service.driver == "wireguard":
        return _wireguard_runtime(service)
    code, output = _run_status_plans(service)
    if service.driver == "docker" and code == 0:
        state = output.lower().split()
        if "running" not in state:
            return "stopped", "容器未运行", {}
    if code == 0:
        return "healthy", "运行状态正常", {}
    if code in {1, 3}:
        return "stopped", "服务未运行", {}
    return "unhealthy", output or f"状态检查失败（退出码 {code}）", {}


def _http_check(check: dict[str, Any], context: dict[str, Any]) -> HealthCheckResult:
    name = str(check.get("name", "HTTP"))
    url = str(check["url"])
    expected = set(check.get("expectedStatuses", []))
    try:
        request = Request(url, headers={"User-Agent": "NControl-Health/1"})
        with urlopen(request, timeout=float(check.get("timeoutSeconds", 3))) as response:
            status = int(response.status)
    except HTTPError as exc:
        status = int(exc.code)
    except (URLError, OSError, TimeoutError) as exc:
        return HealthCheckResult(name, False, f"HTTP 无法访问：{exc}")
    ok = status in expected if expected else 200 <= status < 400
    detail = f"HTTP {status} · {url}"
    if ok and check.get("processOwned", False):
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        owned, owner_detail = _process_owns_port(context, port)
        return HealthCheckResult(name, owned, f"{detail} · {owner_detail}")
    return HealthCheckResult(name, ok, detail)


def _process_owns_port(context: dict[str, Any], port: int) -> tuple[bool, str]:
    process = context.get("process")
    if not isinstance(process, psutil.Process):
        return False, "未找到受管进程"
    try:
        pids = {process.pid, *(child.pid for child in process.children(recursive=True))}
        listeners = psutil.net_connections(kind="tcp")
    except (psutil.Error, PermissionError) as exc:
        return False, f"无法读取端口归属：{exc}"
    for connection in listeners:
        if (
            connection.status == psutil.CONN_LISTEN
            and connection.laddr
            and connection.laddr.port == port
            and connection.pid in pids
        ):
            return True, f"端口由受管进程 PID {connection.pid} 监听"
    return False, "端口不是由当前受管进程监听"


def _tcp_check(check: dict[str, Any], context: dict[str, Any]) -> HealthCheckResult:
    name = str(check.get("name", "TCP"))
    host = str(check["host"])
    port = int(check["port"])
    try:
        with socket.create_connection(
            (host, port), timeout=float(check.get("timeoutSeconds", 3))
        ):
            pass
    except OSError as exc:
        return HealthCheckResult(name, False, f"TCP {host}:{port} 无法连接：{exc}")
    if check.get("processOwned", False):
        owned, detail = _process_owns_port(context, port)
        return HealthCheckResult(name, owned, f"TCP {host}:{port} · {detail}")
    return HealthCheckResult(name, True, f"TCP {host}:{port} 可连接")


def _handshake_check(check: dict[str, Any], context: dict[str, Any]) -> HealthCheckResult:
    name = str(check.get("name", "WireGuard 握手"))
    interface_name = str(check["interface"])
    snapshot = context.get("wireguard", {})
    interface = next(
        (
            item
            for item in snapshot.get("interfaces", [])
            if isinstance(item, dict) and item.get("name") == interface_name
        ),
        None,
    )
    if not interface or not interface.get("running"):
        return HealthCheckResult(name, False, f"接口 {interface_name} 未运行")
    latest = int(interface.get("latestHandshake", 0))
    if latest <= 0:
        return HealthCheckResult(name, False, f"接口 {interface_name} 尚未握手")
    age = max(0, int(time.time() - latest))
    maximum = int(check.get("maxAgeSeconds", 180))
    return HealthCheckResult(
        name,
        age <= maximum,
        f"接口 {interface_name} 最近握手 {age} 秒前（阈值 {maximum} 秒）",
    )


def _ping_check(check: dict[str, Any]) -> HealthCheckResult:
    name = str(check.get("name", "网络连通"))
    host = str(check["host"])
    timeout = max(1, int(float(check.get("timeoutSeconds", 3))))
    interface = check.get("interface")
    if os.name == "nt":
        argv = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    else:
        argv = ["ping", "-c", "1", "-W", str(timeout)]
        if interface:
            argv.extend(["-I", str(interface)])
        argv.append(host)
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
            shell=False,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return HealthCheckResult(name, False, f"连通性检查不可用：{exc}")
    suffix = f"（经 {interface}）" if interface else ""
    return HealthCheckResult(name, result.returncode == 0, f"{host}{suffix} {'可达' if result.returncode == 0 else '不可达'}")


def check_health(service: ServiceDefinition) -> HealthResult:
    try:
        state, summary, context = runtime_state(service)
    except (HomelabError, UnsupportedOperation, OSError, ValueError) as exc:
        return HealthResult(service.name, "unhealthy", f"状态检查失败：{exc}", [])
    if state == "stopped":
        return HealthResult(service.name, state, summary, [])

    results: list[HealthCheckResult] = []
    health = service.spec.get("health", {})
    for check in health.get("checks", []):
        check_type = check["type"]
        if check_type == "http":
            results.append(_http_check(check, context))
        elif check_type == "tcp":
            results.append(_tcp_check(check, context))
        elif check_type == "wireguard-handshake":
            results.append(_handshake_check(check, context))
        elif check_type == "ping":
            results.append(_ping_check(check))

    failures = [result for result in results if not result.ok]
    if state == "unhealthy" or failures:
        startup_period = float(health.get("startupPeriodSeconds", 15))
        age = context.get("startedAge")
        if isinstance(age, (int, float)) and age < startup_period:
            return HealthResult(service.name, "starting", "服务正在启动，健康检查尚未通过", results)
        detail = failures[0].detail if failures else summary
        return HealthResult(service.name, "unhealthy", detail, results)
    if results:
        return HealthResult(service.name, "healthy", f"{len(results)} 项健康检查通过", results)
    return HealthResult(service.name, "healthy", summary, results)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="homelabctl.health")
    parser.add_argument("service_file", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    service = load_service(args.service_file)
    result = check_health(service)
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False))
    else:
        print(f"{result.service}: {result.summary}")
        for check in result.checks:
            print(f"{'OK' if check.ok else 'ERROR'}  {check.name}: {check.detail}")
    return {"healthy": 0, "starting": 4, "stopped": 3, "unhealthy": 2}[result.state]


if __name__ == "__main__":
    raise SystemExit(main())
