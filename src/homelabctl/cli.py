from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import yaml

from .config import find_service, load_all
from .drivers import get_driver
from .errors import HomelabError
from .layout import layout_status, migrate_local_layout, services_directory
from .runner import CommandRunner
from .security import check_config_paths

OPERATIONS = ("prepare", "start", "stop", "restart", "status", "logs")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="homelabctl", description="个人服务器统一服务管理器")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(os.environ.get("HOMELABCTL_ROOT", ".")),
        help="项目根目录（默认当前目录或 HOMELABCTL_ROOT）",
    )
    parser.add_argument("--dry-run", action="store_true", help="只显示将执行的命令")
    sub = parser.add_subparsers(dest="command", required=True)

    tui = sub.add_parser("tui", help="打开终端可视化界面")
    tui.add_argument("--migration", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("list", help="列出服务")
    validate = sub.add_parser("validate", help="校验服务定义")
    validate.add_argument("service", nargs="?", help="服务名；不填则校验全部")
    show = sub.add_parser("show", help="显示服务定义（敏感配置内容不会读取）")
    show.add_argument("service")
    check = sub.add_parser("config-check", help="只读检查配置文件路径与权限")
    check.add_argument("service", nargs="?", help="服务名；不填则检查全部")
    health = sub.add_parser("health", help="检查服务是否真正可用")
    health.add_argument("service")
    sub.add_parser("doctor", help="检查端口、网段和 WireGuard 密钥冲突")

    layout = sub.add_parser("layout", help="管理代码与本机服务的分离目录")
    layout_sub = layout.add_subparsers(dest="layout_command", required=True)
    layout_sub.add_parser("status", help="查看当前服务数据目录")
    layout_sub.add_parser("migrate", help="将旧 services 整理到本机 local 目录")

    boot = sub.add_parser("boot", help="管理开机启动")
    boot_sub = boot.add_subparsers(dest="boot_command", required=True)
    boot_sub.add_parser("run", help="启动已启用开机启动的服务")
    boot_sub.add_parser("install", help="注册 NControl 开机入口")
    boot_sub.add_parser("uninstall", help="删除 NControl 开机入口")
    boot_sub.add_parser("status", help="查看 NControl 开机入口状态")
    for command_name in ("enable", "disable"):
        command = boot_sub.add_parser(command_name)
        command.add_argument("service")

    migrate = sub.add_parser("migrate", help="检查或初始化迁移后的 Debian 系 Linux")
    migrate_sub = migrate.add_subparsers(dest="migrate_command", required=True)
    migrate_sub.add_parser("check", help="只读检查新服务器运行环境")
    migrate_init = migrate_sub.add_parser("init", help="初始化迁移后的服务器")
    migrate_init.add_argument("--public-host", help="新的公网 IP 或域名")
    migrate_init.add_argument("--configure-wireguard-host", action="store_true")
    migrate_init.add_argument("--install-boot", action="store_true")
    migrate_init.add_argument("--start", action="store_true")

    wireguard = sub.add_parser("wireguard", aliases=["wg"], help="WireGuard 连接和客端管理")
    wireguard_sub = wireguard.add_subparsers(dest="wireguard_command", required=True)
    for command_name in ("connections", "peers", "import-peers"):
        command = wireguard_sub.add_parser(command_name)
        command.add_argument("service")
        if command_name != "connections":
            command.add_argument("interface")
    for command_name in ("connection-status", "connect", "disconnect", "adopt-connection"):
        command = wireguard_sub.add_parser(command_name)
        command.add_argument("service")
        command.add_argument("connection")
    for command_name in ("interface-status", "start-interface", "stop-interface"):
        command = wireguard_sub.add_parser(command_name)
        command.add_argument("service")
        command.add_argument("interface")
    traffic = wireguard_sub.add_parser("traffic")
    traffic.add_argument("service")
    for command_name in ("add-connection", "edit-connection"):
        command = wireguard_sub.add_parser(command_name)
        command.add_argument("service")
        command.add_argument("name")
        command.add_argument("source")
        command.add_argument("target")
        command.add_argument("source_network")
        command.add_argument("destination_networks")
        command.add_argument("allow_return", choices=("true", "false"))
        command.add_argument("auto_connect", choices=("true", "false"))
    delete_connection = wireguard_sub.add_parser("delete-connection")
    delete_connection.add_argument("service")
    delete_connection.add_argument("name")
    add_peer = wireguard_sub.add_parser("add-peer")
    add_peer.add_argument("service")
    add_peer.add_argument("interface")
    add_peer.add_argument("name")
    add_peer.add_argument("--address")
    add_peer.add_argument("--profile")
    remove_peer = wireguard_sub.add_parser("remove-peer")
    remove_peer.add_argument("service")
    remove_peer.add_argument("interface")
    remove_peer.add_argument("peer_id")
    export_peer = wireguard_sub.add_parser("export-peer")
    export_peer.add_argument("service")
    export_peer.add_argument("interface")
    export_peer.add_argument("peer_id")
    export_peer.add_argument("--qr", action="store_true")
    create_server = wireguard_sub.add_parser("create-server")
    create_server.add_argument("service")
    create_server.add_argument("interface")
    create_server.add_argument("address")
    create_server.add_argument("address_pool")
    create_server.add_argument("listen_port", type=int)
    create_server.add_argument("public_endpoint")
    edit_server = wireguard_sub.add_parser("edit-server")
    edit_server.add_argument("service")
    edit_server.add_argument("interface")
    edit_server.add_argument("address")
    edit_server.add_argument("address_pool")
    edit_server.add_argument("listen_port", type=int)
    edit_server.add_argument("public_endpoint")
    delete_server = wireguard_sub.add_parser("delete-server")
    delete_server.add_argument("service")
    delete_server.add_argument("interface")
    delete_client = wireguard_sub.add_parser("delete-client")
    delete_client.add_argument("service")
    delete_client.add_argument("interface")
    import_client = wireguard_sub.add_parser("import-client")
    import_client.add_argument("service")
    import_client.add_argument("interface")
    import_client.add_argument("source_config")

    for operation in OPERATIONS:
        command = sub.add_parser(operation, help=f"{operation} 服务")
        command.add_argument("service")
        if operation == "logs":
            command.add_argument("--follow", "-f", action="store_true")
            command.add_argument("--tail", type=_positive_int, default=100)
    return parser


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("必须大于或等于 0")
    return number


def _selected(root: Path, name: str | None):
    return [find_service(root, name)] if name else load_all(root)


def run(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    if args.command == "tui":
        from .tui import run_tui

        return run_tui(root, open_migration=bool(args.migration))

    if args.command == "list":
        services = load_all(root)
        if not services:
            print(f"未发现服务；请在 {services_directory(root)} 下创建 <name>/service.yaml")
            return 0
        width = max(len(service.name) for service in services)
        for service in services:
            print(
                f"{service.name:<{width}}  {service.driver:<10}  "
                f"{'autostart' if service.autostart else 'manual':<9}  {service.description}"
            )
        return 0

    if args.command == "validate":
        services = _selected(root, args.service)
        for service in services:
            print(f"OK  {service.name}  ({service.driver})")
        print(f"校验通过：{len(services)} 个服务")
        return 0

    if args.command == "show":
        service = find_service(root, args.service)
        print(yaml.safe_dump(service.raw, allow_unicode=True, sort_keys=False).rstrip())
        return 0

    if args.command == "config-check":
        services = _selected(root, args.service)
        failed = False
        for service in services:
            driver = get_driver(service)
            values = list(dict.fromkeys(driver.config_values()))
            results = check_config_paths(service, values)
            if not results:
                print(f"OK  {service.name}: 未声明配置文件")
            for result in results:
                print(f"{result.level.upper():7} {service.name}: {result.message}")
                failed = failed or result.level == "error"
        return 1 if failed else 0

    if args.command == "health":
        from .health import check_health

        result = check_health(find_service(root, args.service))
        print(f"{result.service}: {result.summary}")
        for item in result.checks:
            print(f"{'OK' if item.ok else 'ERROR'}  {item.name}: {item.detail}")
        return {"healthy": 0, "starting": 4, "stopped": 3, "unhealthy": 2}[result.state]

    if args.command == "doctor":
        from .audit import audit_services

        failed = False
        for result in audit_services(root):
            print(f"{result.level.upper():7} {result.message}")
            failed = failed or result.level == "error"
        return 1 if failed else 0

    if args.command == "layout":
        if args.layout_command == "migrate":
            print(migrate_local_layout(root))
        mode, path = layout_status(root)
        print(f"目录模式：{mode}")
        print(f"服务位置：{path}")
        return 0

    if args.command == "boot":
        from .boot import install, is_installed, run_enabled, set_service_autostart, uninstall

        if args.boot_command == "run":
            return run_enabled(root, dry_run=args.dry_run)
        if args.boot_command in {"enable", "disable"}:
            enabled = args.boot_command == "enable"
            set_service_autostart(root, args.service, enabled)
            print(f"{args.service} 已{'启用' if enabled else '关闭'}开机启动")
            return 0
        if args.boot_command == "install":
            print(install(root))
            return 0
        if args.boot_command == "uninstall":
            print(uninstall(root))
            return 0
        print("已安装" if is_installed(root) else "未安装")
        return 0

    if args.command == "migrate":
        from .boot import install, run_enabled
        from .migration import (
            configure_wireguard_host,
            migration_checks,
            record_machine,
            update_wireguard_public_host,
        )

        if args.migrate_command == "check":
            failed = False
            for result in migration_checks(root):
                print(f"{result.level.upper():7} {result.message}")
                failed = failed or result.level == "error"
            return 1 if failed else 0
        if args.public_host:
            services_updated, clients_updated = update_wireguard_public_host(
                root, args.public_host
            )
            print(
                f"已更新 {services_updated} 个 WireGuard 服务定义和 "
                f"{clients_updated} 份本地客户端配置"
            )
            if clients_updated:
                print("已有 WireGuard 客户端需要重新导入配置或重新扫码")
        if args.configure_wireguard_host:
            print(configure_wireguard_host())
        if args.install_boot:
            print(install(root))
        print("\n迁移环境检查：")
        failed = False
        for result in migration_checks(root):
            print(f"{result.level.upper():7} {result.message}")
            failed = failed or result.level == "error"
        if failed:
            print("初始化尚有错误，请修复后再启动服务。", file=sys.stderr)
            return 1
        record_machine(root)
        if args.start:
            print("\n启动已启用开机启动的服务：")
            return run_enabled(root, dry_run=args.dry_run)
        print("初始化完成；未启动服务。")
        return 0

    if args.command in {"wireguard", "wg"}:
        service = find_service(root, args.service)
        if service.driver != "wireguard":
            raise HomelabError(f"{service.name} 不是 WireGuard 服务")
        driver = get_driver(service)
        command = args.wireguard_command
        if command == "connections":
            connections = service.spec["wireguard"].get("connections", [])
            if not connections:
                print("未声明网络连接")
            for connection in connections:
                print(
                    f"{connection['name']}\t{connection['from']} -> {connection['to']}\t"
                    f"{connection['sourceNetwork']}\t{connection.get('mode', 'masquerade')}"
                )
            return 0
        if command == "traffic":
            operation = ("traffic", "--json")
        elif command in {"add-connection", "edit-connection"}:
            operation = (
                command,
                args.name,
                args.source,
                args.target,
                args.source_network,
                args.destination_networks,
                args.allow_return,
                args.auto_connect,
            )
        elif command == "delete-connection":
            operation = (command, args.name)
        elif command in {"connection-status", "connect", "disconnect", "adopt-connection"}:
            operation = (command, args.connection)
        elif command in {"interface-status", "start-interface", "stop-interface"}:
            operation = (command, args.interface)
        elif command in {"peers", "import-peers"}:
            operation = (command, args.interface)
        elif command == "add-peer":
            operation = (
                "add-peer",
                args.interface,
                args.name,
                *(() if args.address is None else ("--address", args.address)),
                *(() if args.profile is None else ("--profile", args.profile)),
            )
        elif command == "remove-peer":
            operation = ("remove-peer", args.interface, args.peer_id)
        elif command == "export-peer":
            operation = (
                "export-peer",
                args.interface,
                args.peer_id,
                *(() if not args.qr else ("--qr",)),
            )
        elif command == "create-server":
            operation = (
                "create-server",
                args.interface,
                args.address,
                args.address_pool,
                str(args.listen_port),
                args.public_endpoint,
            )
        elif command == "edit-server":
            operation = (
                "edit-server",
                args.interface,
                args.address,
                args.address_pool,
                str(args.listen_port),
                args.public_endpoint,
            )
        elif command == "delete-server":
            operation = ("delete-server", args.interface)
        elif command == "delete-client":
            operation = ("delete-client", args.interface)
        elif command == "import-client":
            operation = ("import-client", args.interface, args.source_config)
        else:
            raise HomelabError(f"不支持的 WireGuard 命令: {command}")
        plan = driver.management_plan(*operation)
        return CommandRunner(dry_run=args.dry_run).execute([plan])

    service = find_service(root, args.service)
    driver = get_driver(service)
    plans = driver.plans(
        args.command,
        follow=getattr(args, "follow", False),
        tail=getattr(args, "tail", 100),
    )
    return CommandRunner(dry_run=args.dry_run).execute(plans)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    if not effective_argv:
        effective_argv = ["tui"]
    args = parser.parse_args(effective_argv)
    try:
        return run(args)
    except HomelabError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("已取消", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

