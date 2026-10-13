from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess

from .errors import HomelabError


@dataclass(frozen=True)
class UpdateInfo:
    state: str
    current: str
    target: str
    ahead: int = 0
    behind: int = 0
    remote_url: str = ""
    detail: str = ""


def _git(root: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    if shutil.which("git") is None:
        raise HomelabError("系统未安装 Git，无法检查 NControl 更新")
    completed = subprocess.run(
        ("git", *arguments),
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        check=False,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise HomelabError(f"Git 操作失败：{detail or completed.returncode}")
    return completed


def _revision(root: Path, name: str) -> str:
    return _git(root, "rev-parse", name).stdout.strip()


def check_for_updates(root: Path, *, fetch: bool = True) -> UpdateInfo:
    root = root.resolve()
    if not (root / ".git").exists():
        raise HomelabError("当前 NControl 尚未绑定 Git 仓库，无法自动更新")

    inside = _git(root, "rev-parse", "--is-inside-work-tree").stdout.strip()
    if inside != "true":
        raise HomelabError("当前目录不是有效的 Git 工作目录")
    remote_url = _git(root, "remote", "get-url", "origin").stdout.strip()
    if fetch:
        _git(root, "fetch", "--quiet", "origin", "main")

    current = _revision(root, "HEAD")
    target = _revision(root, "origin/main")
    status = _git(root, "status", "--porcelain", "--untracked-files=all").stdout.strip()
    counts = _git(
        root,
        "rev-list",
        "--left-right",
        "--count",
        "HEAD...origin/main",
    ).stdout.split()
    if len(counts) != 2:
        raise HomelabError("无法判断本地代码与 GitHub 的版本差异")
    ahead, behind = (int(value) for value in counts)

    if status:
        return UpdateInfo(
            "dirty",
            current,
            target,
            ahead,
            behind,
            remote_url,
            "公共代码存在未提交改动；为避免覆盖，已阻止自动更新",
        )
    if ahead and behind:
        state = "diverged"
        detail = "本地与 GitHub 都有独立提交，无法自动快进更新"
    elif ahead:
        state = "ahead"
        detail = "本地代码包含尚未推送的提交，未执行自动更新"
    elif behind:
        state = "available"
        detail = f"发现 {behind} 个新提交"
    else:
        state = "current"
        detail = "当前已经是最新版本"
    return UpdateInfo(state, current, target, ahead, behind, remote_url, detail)


def apply_update(root: Path) -> UpdateInfo:
    root = root.resolve()
    info = check_for_updates(root)
    if info.state == "current":
        return info
    if info.state != "available":
        raise HomelabError(info.detail)
    _git(root, "merge", "--ff-only", "origin/main")
    updated = _revision(root, "HEAD")
    if updated != info.target:
        raise HomelabError("更新完成后的提交与 GitHub 不一致")
    return UpdateInfo(
        "updated",
        info.current,
        updated,
        0,
        0,
        info.remote_url,
        "NControl 公共代码已更新；local 目录未改动",
    )
