#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ ! -x "$root/.venv/bin/python" ]; then
  python3 -m venv --clear "$root/.venv"
fi
"$root/.venv/bin/python" -m pip install --upgrade pip
"$root/.venv/bin/python" -m pip install -e "$root"

echo "NControl 环境已准备完成。运行: ./ncontrol"
