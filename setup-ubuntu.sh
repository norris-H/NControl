#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
assume_yes=0
public_host=""
start_services="ask"
install_boot="ask"
configure_wireguard="ask"
prepare_only=0

usage() {
  echo "用法: ./setup-ubuntu.sh [--yes] [--public-host IP或域名] [--no-start] [--no-boot] [--no-wireguard-host]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --yes) assume_yes=1 ;;
    --public-host)
      shift
      [ "$#" -gt 0 ] || { usage; exit 2; }
      public_host="$1"
      ;;
    --no-start) start_services="no" ;;
    --no-boot) install_boot="no" ;;
    --no-wireguard-host) configure_wireguard="no" ;;
    --prepare-only) prepare_only=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

if [ "$(uname -s)" != "Linux" ] || [ ! -f /etc/os-release ]; then
  echo "此初始化脚本只支持 Debian 系 Linux。" >&2
  exit 2
fi

. /etc/os-release
case "${ID:-}" in
  ubuntu|debian|raspbian) ;;
  *)
    case " ${ID_LIKE:-} " in
      *" debian "*) ;;
      *)
        echo "当前系统不是 Debian 系（Ubuntu / Debian / Raspberry Pi OS），无法自动安装依赖。" >&2
        exit 2
        ;;
    esac
    ;;
esac

packages=(python3 python3-venv python3-pip python3-dev build-essential nodejs npm wireguard-tools iptables iproute2 cron iputils-ping)
required_commands=(python3 node npm wg wg-quick iptables ip crontab ping)
needs_docker=0
if [ -d "$root/local/services/pairdrop" ] || [ -d "$root/local/services/beszel" ] || \
   [ -d "$root/services/pairdrop" ] || [ -d "$root/services/beszel" ]; then
  needs_docker=1
  packages+=(docker.io)
  required_commands+=(docker)
fi
missing=()
for command in "${required_commands[@]}"; do
  command -v "$command" >/dev/null 2>&1 || missing+=("$command")
done
if ! python3 -m venv --help >/dev/null 2>&1; then
  missing+=("python3-venv")
fi

ask_yes() {
  local prompt="$1"
  if [ "$assume_yes" -eq 1 ]; then
    return 0
  fi
  read -r -p "$prompt [Y/n] " answer
  case "${answer:-y}" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

if [ "${#missing[@]}" -gt 0 ]; then
  echo "缺少系统组件: ${missing[*]}"
  if ask_yes "是否安装 NControl 所需的 Debian 系软件包？"; then
    sudo apt-get update
    sudo apt-get install -y "${packages[@]}"
  else
    echo "缺少依赖，初始化已停止。" >&2
    exit 2
  fi
fi

if [ "$needs_docker" -eq 1 ] && ! docker info >/dev/null 2>&1; then
  current_user="$(id -un)"
  echo "PairDrop/Beszel 需要当前用户访问 Docker。"
  echo "注意：docker 组权限基本等同于系统管理员权限。"
  if [ "$current_user" != "root" ] && ask_yes "是否将 $current_user 加入 docker 组？（重新登录后生效）"; then
    sudo usermod -aG docker "$current_user"
    echo "已加入 docker 组；完成初始化后请退出 SSH 并重新登录一次。"
  else
    echo "未配置 Docker 用户权限；PairDrop/Beszel 暂时无法由 NControl 启动。"
  fi
fi

echo "正在为这台服务器重建 NControl Python 环境…"
python3 -m venv --clear "$root/.venv"
"$root/.venv/bin/python" -m pip install --upgrade pip
"$root/.venv/bin/python" -m pip install -e "$root"

if [ "$prepare_only" -eq 1 ]; then
  exec "$root/ncontrol" tui --migration
fi

if [ -z "$public_host" ] && [ -t 0 ]; then
  read -r -p "新服务器公网 IP 或域名（留空则保持 WireGuard 原入口）: " public_host
fi
if [ "$configure_wireguard" = "ask" ]; then
  if ask_yes "是否配置 WireGuard 所需的 IPv4 转发和限定 sudo 权限？"; then
    configure_wireguard="yes"
  else
    configure_wireguard="no"
  fi
fi
if [ "$install_boot" = "ask" ]; then
  if ask_yes "是否注册 NControl 开机启动入口？"; then
    install_boot="yes"
  else
    install_boot="no"
  fi
fi
if [ "$start_services" = "ask" ]; then
  if ask_yes "初始化完成后是否启动设为自动启动的服务？"; then
    start_services="yes"
  else
    start_services="no"
  fi
fi

args=(migrate init)
[ -n "$public_host" ] && args+=(--public-host "$public_host")
[ "$configure_wireguard" = "yes" ] && args+=(--configure-wireguard-host)
[ "$install_boot" = "yes" ] && args+=(--install-boot)
[ "$start_services" = "yes" ] && args+=(--start)

exec "$root/ncontrol" "${args[@]}"
