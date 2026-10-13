from __future__ import annotations

import os
from pathlib import Path
import platform

import yaml

from .errors import HomelabError


def services_directory(root: Path) -> Path:
    """Return the node-local services directory, with legacy compatibility."""
    root = root.resolve()
    local_services = root / "local" / "services"
    legacy_services = root / "services"
    if local_services.exists() and legacy_services.exists():
        raise HomelabError(
            "同时发现 local/services 和旧 services 目录；为防止操作错服务，"
            "请先运行 ncontrol layout status 并处理目录冲突"
        )
    if local_services.exists():
        return local_services
    if legacy_services.exists():
        return legacy_services
    return local_services


def node_directory(root: Path) -> Path:
    return services_directory(root).parent


def runtime_directory(root: Path) -> Path:
    return node_directory(root) / ".ncontrol"


def layout_status(root: Path) -> tuple[str, Path]:
    service_root = services_directory(root)
    legacy = root.resolve() / "services"
    mode = "旧目录（尚未分离）" if service_root == legacy else "本机独立目录"
    return mode, service_root


def migrate_local_layout(root: Path) -> str:
    """Move node-owned files under local/ without stopping managed services."""
    root = root.resolve()
    local = root / "local"
    target_services = local / "services"
    source_services = root / "services"
    target_runtime = local / ".ncontrol"
    source_runtime = root / ".ncontrol"

    if target_services.exists() and source_services.exists():
        raise HomelabError(
            "无法迁移：local/services 和旧 services 同时存在，请先确认应保留哪一套"
        )
    if target_runtime.exists() and source_runtime.exists():
        raise HomelabError(
            "无法迁移：local/.ncontrol 和旧 .ncontrol 同时存在，请先处理状态目录冲突"
        )

    local.mkdir(parents=True, exist_ok=True)
    moved_services = False
    moved_runtime = False
    try:
        if source_services.exists():
            source_services.rename(target_services)
            moved_services = True
        else:
            target_services.mkdir(parents=True, exist_ok=True)

        if source_runtime.exists():
            source_runtime.rename(target_runtime)
            moved_runtime = True

        node_file = local / "node.yaml"
        if not node_file.exists():
            temporary = node_file.with_suffix(".yaml.tmp")
            temporary.write_text(
                yaml.safe_dump(
                    {"version": 1, "name": platform.node() or "unnamed-node"},
                    allow_unicode=True,
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            os.replace(temporary, node_file)
            if os.name != "nt":
                node_file.chmod(0o600)
    except Exception:
        if moved_runtime and target_runtime.exists() and not source_runtime.exists():
            target_runtime.rename(source_runtime)
        if moved_services and target_services.exists() and not source_services.exists():
            target_services.rename(source_services)
        raise

    return f"本机服务已整理到 {target_services}"
