from __future__ import annotations

import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from homelabctl.errors import HomelabError
from homelabctl.updates import (
    FALLBACK_REPOSITORY_URL,
    _fetch_updates,
    _official_revision,
    _uses_official_repository,
    _verify_official_target,
    apply_update,
    check_for_updates,
)


def run_git(directory: Path, *arguments: str) -> None:
    subprocess.run(
        ("git", *arguments),
        cwd=directory,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=True,
    )


class UpdateTests(unittest.TestCase):
    def test_official_revision_retries_transient_failure(self):
        revision = "a" * 40
        response = io.BytesIO(f'{{"sha":"{revision}"}}'.encode())
        with patch(
            "homelabctl.updates.urlopen",
            side_effect=[URLError("temporary"), response],
        ) as open_url, patch("homelabctl.updates.time.sleep") as sleep:
            self.assertEqual(_official_revision(timeout=1), revision)
        self.assertEqual(open_url.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_fetch_falls_back_without_changing_origin(self):
        completed = subprocess.CompletedProcess(("git",), 0, "", "")
        with patch(
            "homelabctl.updates._git",
            side_effect=[HomelabError("direct unavailable"), completed],
        ) as git:
            used_fallback = _fetch_updates(
                Path("."),
                "https://github.com/norris-H/NControl.git",
            )
        self.assertTrue(used_fallback)
        self.assertEqual(git.call_count, 2)
        self.assertEqual(git.call_args_list[1].args[3], FALLBACK_REPOSITORY_URL)
        self.assertIn(
            "main:refs/remotes/origin/main",
            git.call_args_list[1].args,
        )

    def test_unrelated_repository_does_not_use_ncontrol_fallback(self):
        with patch(
            "homelabctl.updates._git",
            side_effect=HomelabError("direct unavailable"),
        ) as git:
            with self.assertRaisesRegex(HomelabError, "direct unavailable"):
                _fetch_updates(Path("."), "https://example.test/project.git")
        self.assertEqual(git.call_count, 1)

    def test_official_repository_is_detected_inside_proxy_url(self):
        self.assertTrue(
            _uses_official_repository(
                "https://gh-proxy.org/https://github.com/norris-H/NControl.git"
            )
        )
        self.assertFalse(_uses_official_repository("C:/tmp/remote.git"))

    def test_mirror_revision_must_match_official_github_revision(self):
        revision = "a" * 40
        with patch(
            "homelabctl.updates._official_revision",
            return_value="b" * 40,
        ):
            with self.assertRaisesRegex(HomelabError, "校验失败"):
                _verify_official_target(revision)

        with patch(
            "homelabctl.updates._official_revision",
            return_value=revision,
        ):
            _verify_official_target(revision)

    def test_network_timeout_has_clear_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".git").mkdir()
            with patch(
                "homelabctl.updates.subprocess.run",
                side_effect=subprocess.TimeoutExpired(("git", "fetch"), 20),
            ):
                with self.assertRaisesRegex(HomelabError, "无法连接 GitHub"):
                    check_for_updates(root)

    def _repositories(self, root: Path) -> tuple[Path, Path]:
        remote = root / "remote.git"
        seed = root / "seed"
        node = root / "node"
        remote.mkdir()
        seed.mkdir()
        run_git(remote, "init", "--bare")
        run_git(seed, "init", "-b", "main")
        run_git(seed, "config", "user.name", "NControl Tests")
        run_git(seed, "config", "user.email", "tests@example.invalid")
        (seed / ".gitignore").write_text("local/\n", encoding="utf-8")
        (seed / "version.txt").write_text("one\n", encoding="utf-8")
        run_git(seed, "add", ".")
        run_git(seed, "commit", "-m", "first")
        run_git(seed, "remote", "add", "origin", str(remote))
        run_git(seed, "push", "-u", "origin", "main")
        subprocess.run(
            ("git", "clone", "--branch", "main", str(remote), str(node)),
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=True,
        )
        return seed, node

    def test_fast_forward_update_preserves_local_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            seed, node = self._repositories(Path(temp))
            local_file = node / "local" / "services" / "keep.txt"
            local_file.parent.mkdir(parents=True)
            local_file.write_text("private\n", encoding="utf-8")

            (seed / "version.txt").write_text("two\n", encoding="utf-8")
            run_git(seed, "add", "version.txt")
            run_git(seed, "commit", "-m", "second")
            run_git(seed, "push")

            info = check_for_updates(node)
            self.assertEqual(info.state, "available")
            self.assertEqual(info.behind, 1)
            result = apply_update(node)
            self.assertEqual(result.state, "updated")
            self.assertEqual((node / "version.txt").read_text(encoding="utf-8"), "two\n")
            self.assertEqual(local_file.read_text(encoding="utf-8"), "private\n")

    def test_dirty_public_code_blocks_update(self):
        with tempfile.TemporaryDirectory() as temp:
            _, node = self._repositories(Path(temp))
            (node / "version.txt").write_text("local change\n", encoding="utf-8")
            info = check_for_updates(node)
            self.assertEqual(info.state, "dirty")
            with self.assertRaises(HomelabError):
                apply_update(node)


if __name__ == "__main__":
    unittest.main()
