from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener, urlopen

from .errors import HomelabError
from .proxy_control import load_settings as load_proxy_settings


OFFICIAL_REPOSITORY = "norris-H/NControl"
OFFICIAL_COMMIT_API = (
    f"https://api.github.com/repos/{OFFICIAL_REPOSITORY}/commits/main"
)
FALLBACK_REPOSITORY_URL = (
    f"https://gh-proxy.org/https://github.com/{OFFICIAL_REPOSITORY}.git"
)


@dataclass(frozen=True)
class UpdateInfo:
    state: str
    current: str
    target: str
    ahead: int = 0
    behind: int = 0
    remote_url: str = ""
    detail: str = ""


def _git(
    root: Path,
    *arguments: str,
    check: bool = True,
    timeout: float = 30,
    use_proxy: bool = False,
) -> subprocess.CompletedProcess[str]:
    if shutil.which("git") is None:
        raise HomelabError("系统未安装 Git，无法检查 NControl 更新")
    command = ["git"]
    if use_proxy:
        proxy = load_proxy_settings(root)
        command.extend(("-c", f"http.proxy={proxy.url if proxy.enabled else ''}"))
    command.extend(arguments)
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise HomelabError(
            f"Git 操作超过 {int(timeout)} 秒；当前服务器可能无法连接 GitHub"
        ) from exc
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise HomelabError(f"Git 操作失败：{detail or completed.returncode}")
    return completed


def _revision(root: Path, name: str) -> str:
    return _git(root, "rev-parse", name).stdout.strip()


def _uses_official_repository(remote_url: str) -> bool:
    normalized = remote_url.replace("\\", "/").lower()
    return OFFICIAL_REPOSITORY.lower() in normalized


def _official_revision(
    root: Path | None = None,
    *,
    timeout: float = 10,
    attempts: int = 3,
) -> str:
    request = Request(
        OFFICIAL_COMMIT_API,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "NControl-Updater",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    last_error: Exception | None = None
    for attempt in range(max(1, attempts)):
        try:
            if root is None:
                response_context = urlopen(request, timeout=timeout)
            else:
                proxy = load_proxy_settings(root)
                proxies = {"http": proxy.url, "https": proxy.url} if proxy.enabled else {}
                response_context = build_opener(ProxyHandler(proxies)).open(
                    request,
                    timeout=timeout,
                )
            with response_context as response:
                payload = json.load(response)
            revision = payload.get("sha") if isinstance(payload, dict) else None
            if not isinstance(revision, str) or len(revision) != 40:
                raise ValueError("无法识别的提交编号")
            return revision
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            last_error = exc
            if attempt + 1 < max(1, attempts):
                time.sleep(attempt + 1)
    raise HomelabError(
        f"连续 {max(1, attempts)} 次无法通过 GitHub 官方 API 校验更新；"
        "为保证安全，已停止更新，请稍后重试"
    ) from last_error


def _verify_official_target(target: str, root: Path | None = None) -> None:
    official = _official_revision(root)
    if target != official:
        raise HomelabError(
            "更新入口尚未同步 GitHub 最新版本，或内容校验失败；已拒绝更新"
        )


def _fetch_updates(root: Path, remote_url: str) -> bool:
    """Fetch origin/main and return whether the verified fallback was used."""
    try:
        _git(
            root,
            "fetch",
            "--quiet",
            "origin",
            "main",
            timeout=8,
            use_proxy=True,
        )
        return False
    except HomelabError as direct_error:
        if not _uses_official_repository(remote_url):
            raise
        try:
            _git(
                root,
                "fetch",
                "--quiet",
                FALLBACK_REPOSITORY_URL,
                "main:refs/remotes/origin/main",
                timeout=20,
                use_proxy=True,
            )
        except HomelabError as fallback_error:
            raise HomelabError(
                "GitHub 直连和备用加速入口均不可用，无法检查更新"
            ) from fallback_error
        return True


def check_for_updates(root: Path, *, fetch: bool = True) -> UpdateInfo:
    root = root.resolve()
    if not (root / ".git").exists():
        raise HomelabError("当前 NControl 尚未绑定 Git 仓库，无法自动更新")

    inside = _git(root, "rev-parse", "--is-inside-work-tree").stdout.strip()
    if inside != "true":
        raise HomelabError("当前目录不是有效的 Git 工作目录")
    remote_url = _git(root, "remote", "get-url", "origin").stdout.strip()
    used_fallback = False
    if fetch:
        used_fallback = _fetch_updates(root, remote_url)

    current = _revision(root, "HEAD")
    target = _revision(root, "origin/main")
    if _uses_official_repository(remote_url):
        _verify_official_target(target, root)
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
    if used_fallback:
        detail += "（GitHub 直连失败，已通过备用入口完成校验）"
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
