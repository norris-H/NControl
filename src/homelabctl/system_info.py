from __future__ import annotations

import platform
from pathlib import Path
import time
from typing import Any

import psutil


CPU_SENSOR_NAMES = (
    "cpu_thermal",
    "coretemp",
    "k10temp",
    "zenpower",
    "soc_thermal",
    "acpitz",
    "thermal_zone0",
)
CPU_SENSOR_LABELS = ("package", "cpu", "tctl", "tdie", "core", "soc")


def _valid_temperature(value: Any) -> float | None:
    try:
        temperature = float(value)
    except (TypeError, ValueError):
        return None
    if -20.0 <= temperature <= 150.0:
        return temperature
    return None


def cpu_temperature() -> dict[str, Any]:
    """Return a best-effort CPU temperature without mistaking disks for CPUs."""
    reader = getattr(psutil, "sensors_temperatures", None)
    if reader is None:
        return {"available": False, "celsius": None, "source": ""}
    try:
        sensors = reader(fahrenheit=False) or {}
    except (OSError, RuntimeError, NotImplementedError):
        return {"available": False, "celsius": None, "source": ""}

    groups = {str(name).casefold(): entries for name, entries in sensors.items()}
    for preferred in CPU_SENSOR_NAMES:
        for group_name, entries in groups.items():
            if preferred not in group_name:
                continue
            candidates: list[tuple[float, str]] = []
            for entry in entries:
                current = _valid_temperature(getattr(entry, "current", None))
                if current is None:
                    continue
                label = str(getattr(entry, "label", "") or group_name)
                candidates.append((current, label))
            if candidates:
                current, label = max(candidates, key=lambda item: item[0])
                return {
                    "available": True,
                    "celsius": round(current, 1),
                    "source": label,
                }

    for group_name, entries in groups.items():
        for entry in entries:
            label = str(getattr(entry, "label", "") or "").casefold()
            if not any(marker in label for marker in CPU_SENSOR_LABELS):
                continue
            current = _valid_temperature(getattr(entry, "current", None))
            if current is not None:
                return {
                    "available": True,
                    "celsius": round(current, 1),
                    "source": str(getattr(entry, "label", "") or group_name),
                }
    return {"available": False, "celsius": None, "source": ""}


def _load_average() -> tuple[float | None, float | None, float | None]:
    try:
        values = psutil.getloadavg()
    except (AttributeError, OSError):
        return None, None, None
    return tuple(round(float(value), 2) for value in values)


def system_snapshot(root: Path) -> dict[str, Any]:
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage(str(root.resolve()))
    network = psutil.net_io_counters()
    frequency = psutil.cpu_freq()
    load1, load5, load15 = _load_average()
    sampled_at = time.time()
    boot_time = float(psutil.boot_time())
    return {
        "sampledAt": sampled_at,
        "host": {
            "hostname": platform.node() or "未知主机",
            "system": platform.system() or "未知系统",
            "release": platform.release(),
            "architecture": platform.machine(),
        },
        "cpu": {
            "percent": round(float(psutil.cpu_percent(interval=0.05)), 1),
            "physicalCores": psutil.cpu_count(logical=False),
            "logicalCores": psutil.cpu_count(logical=True),
            "frequencyMHz": (
                round(float(frequency.current), 0) if frequency is not None else None
            ),
            "load1": load1,
            "load5": load5,
            "load15": load15,
            "temperature": cpu_temperature(),
        },
        "memory": {
            "total": int(memory.total),
            "used": int(memory.used),
            "available": int(memory.available),
            "percent": round(float(memory.percent), 1),
            "swapTotal": int(swap.total),
            "swapUsed": int(swap.used),
            "swapPercent": round(float(swap.percent), 1),
        },
        "disk": {
            "path": str(root.resolve()),
            "total": int(disk.total),
            "used": int(disk.used),
            "free": int(disk.free),
            "percent": round(float(disk.percent), 1),
        },
        "network": {
            "received": int(network.bytes_recv) if network is not None else 0,
            "sent": int(network.bytes_sent) if network is not None else 0,
        },
        "uptimeSeconds": max(0, int(sampled_at - boot_time)),
    }
