from __future__ import annotations

import os
from pathlib import Path

from .config import resolve_declared_paths
from .models import CheckResult, ServiceDefinition

SENSITIVE_SUFFIXES = {".key", ".pem", ".env"}


def check_config_paths(service: ServiceDefinition, values: list[str]) -> list[CheckResult]:
    results: list[CheckResult] = []
    for path in resolve_declared_paths(service, values):
        if not path.exists():
            results.append(CheckResult("error", f"缺少配置: {path}"))
            continue
        results.append(CheckResult("ok", f"配置存在: {path}"))
        if os.name != "nt" and path.is_file():
            mode = path.stat().st_mode & 0o777
            sensitive = path.suffix.lower() in SENSITIVE_SUFFIXES or "private" in path.name.lower()
            if sensitive and mode & 0o077:
                results.append(
                    CheckResult("warning", f"敏感配置权限建议为 600，当前是 {mode:03o}: {path}")
                )
    return results

