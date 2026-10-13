from __future__ import annotations

import subprocess
from collections.abc import Iterable

from .errors import HomelabError
from .models import CommandPlan


class CommandRunner:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def execute(self, plans: Iterable[CommandPlan]) -> int:
        final_code = 0
        for plan in plans:
            location = f"  (cwd: {plan.cwd})" if plan.cwd else ""
            print(f"+ {plan.display()}{location}")
            if self.dry_run:
                continue
            try:
                completed = subprocess.run(
                    plan.argv,
                    cwd=plan.cwd,
                    shell=False,
                    check=False,
                )
            except FileNotFoundError as exc:
                raise HomelabError(f"找不到可执行程序: {plan.argv[0]}") from exc
            final_code = completed.returncode
            if final_code != 0:
                return final_code
        return final_code

