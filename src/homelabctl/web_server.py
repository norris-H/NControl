from __future__ import annotations

import argparse
import base64
from contextlib import redirect_stdout
from dataclasses import asdict
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO, StringIO
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import threading
import time
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlparse

import qrcode
from qrcode.image.svg import SvgPathImage

from .audit import audit_services
from .boot import install as install_boot
from .boot import run_enabled, set_service_autostart
from .config import find_service, load_all
from .drivers import get_driver
from .errors import HomelabError, UnsupportedOperation
from .health import check_health
from .migration import (
    configure_wireguard_host,
    migration_checks,
    record_machine,
    update_wireguard_public_host,
)
from .models import CommandPlan, ServiceDefinition
from .proxy_control import apply_process_environment as apply_proxy_environment
from .proxy_control import disable as disable_proxy
from .proxy_control import load_settings as load_proxy_settings
from .proxy_control import save_settings as save_proxy_settings
from .security import check_config_paths
from .updates import apply_update, check_for_updates
from .web_control import load_config, read_token, status_dict
from .wireguard_control import (
    add_connection,
    add_peer,
    adopt_connection,
    connect,
    connection_status,
    create_server_interface,
    delete_client_interface,
    delete_connection,
    delete_server_interface,
    disconnect,
    edit_connection,
    edit_server_interface,
    import_client_interface,
    import_peers,
    interface_addresses,
    interface_status,
    list_peer_records,
    peer_client_config_path,
    remove_peer,
    server_interface_settings,
    start_interface,
    stop_interface,
    sync_interface_runtime,
    traffic_snapshot,
)


ASSET_DIRECTORY = Path(__file__).resolve().parent / "web_assets"
MAX_BODY_BYTES = 1024 * 1024
MUTATING_ACTIONS_REQUIRING_CONFIRMATION = {
    "stop",
    "restart",
    "clear-logs",
    "delete-server",
    "delete-client",
    "remove-peer",
    "delete-connection",
    "disconnect",
    "stop-interface",
}


def _run_plans(plans: list[CommandPlan], *, timeout: int = 60) -> tuple[int, str]:
    outputs: list[str] = []
    final_code = 0
    for plan in plans:
        try:
            completed = subprocess.run(
                plan.argv,
                cwd=plan.cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                shell=False,
                check=False,
            )
        except FileNotFoundError as exc:
            raise HomelabError(f"找不到可执行程序: {plan.argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise HomelabError(f"操作超时: {plan.display()}") from exc
        final_code = completed.returncode
        if completed.stdout.strip():
            outputs.append(completed.stdout.strip())
        if final_code != 0:
            break
    return final_code, "\n".join(outputs)


def _capture(function: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, str]:
    output = StringIO()
    with redirect_stdout(output):
        value = function(*args, **kwargs)
    return value, output.getvalue().strip()


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


class WebBackend:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.mutation_lock = threading.Lock()

    def dashboard(self) -> dict[str, Any]:
        services: list[dict[str, Any]] = []
        for service in load_all(self.root):
            health = check_health(service).to_dict()
            services.append(
                {
                    "name": service.name,
                    "description": service.description,
                    "driver": service.driver,
                    "autostart": service.autostart,
                    "workingDirectory": str(service.working_directory),
                    "definitionFile": str(service.path),
                    "health": health,
                    "wireguard": service.driver == "wireguard",
                }
            )
        return {
            "services": services,
            "web": status_dict(self.root),
            "csrf": "",
            "timestamp": time.time(),
        }

    def logs(self, service_name: str, tail: int = 200) -> dict[str, Any]:
        service = find_service(self.root, service_name)
        tail = min(max(int(tail), 0), 2000)
        plans = get_driver(service).plans("logs", follow=False, tail=tail)
        code, output = _run_plans(plans, timeout=20)
        return {"service": service.name, "code": code, "output": output or "(暂无日志输出)"}

    def config_check(self, service_name: str) -> dict[str, Any]:
        service = find_service(self.root, service_name)
        values = list(dict.fromkeys(get_driver(service).config_values()))
        results = check_config_paths(service, values)
        return {"service": service.name, "results": [asdict(item) for item in results]}

    def service_action(self, service_name: str, body: dict[str, Any]) -> dict[str, Any]:
        action = str(body.get("action", ""))
        if action in MUTATING_ACTIONS_REQUIRING_CONFIRMATION and not body.get("confirmed"):
            raise HomelabError("该操作需要明确确认")
        with self.mutation_lock:
            service = find_service(self.root, service_name)
            if action in {"start", "stop", "restart"}:
                plans = get_driver(service).plans(action)
            elif action == "clear-logs":
                plans = get_driver(service).clear_log_plans()
            elif action == "set-autostart":
                enabled = _bool(body.get("enabled"))
                set_service_autostart(self.root, service.name, enabled)
                label = "启用" if enabled else "关闭"
                return {"ok": True, "message": f"开机启动已{label}"}
            else:
                raise HomelabError(f"不支持的服务操作: {action}")
            code, output = _run_plans(plans)
            if code != 0:
                raise HomelabError(output or f"操作失败（退出码 {code}）")
            return {"ok": True, "message": output or "操作已完成"}

    def doctor(self) -> dict[str, Any]:
        return {"results": [asdict(item) for item in audit_services(self.root)]}

    def update_info(self) -> dict[str, Any]:
        return asdict(check_for_updates(self.root))

    def apply_update(self, confirmed: bool) -> dict[str, Any]:
        if not confirmed:
            raise HomelabError("安装更新需要明确确认")
        with self.mutation_lock:
            return asdict(apply_update(self.root))

    def proxy_info(self) -> dict[str, Any]:
        return load_proxy_settings(self.root).to_dict()

    def configure_proxy(self, body: dict[str, Any]) -> dict[str, Any]:
        enabled = _bool(body.get("enabled"))
        with self.mutation_lock:
            if enabled:
                host = str(body.get("host", "")).strip()
                try:
                    port = int(body.get("port"))
                except (TypeError, ValueError) as exc:
                    raise HomelabError("代理端口无效") from exc
                current = save_proxy_settings(
                    self.root,
                    enabled=True,
                    host=host,
                    port=port,
                )
                apply_proxy_environment(self.root)
                message = f"代理已开启：{current.url}"
            else:
                current = disable_proxy(self.root)
                apply_proxy_environment(self.root)
                message = "代理已关闭"
        return {**current.to_dict(), "message": message}

    def migration(self) -> dict[str, Any]:
        return {"results": [asdict(item) for item in migration_checks(self.root)]}

    def migration_action(self, body: dict[str, Any]) -> dict[str, Any]:
        if not body.get("confirmed"):
            raise HomelabError("迁移初始化操作需要明确确认")
        action = str(body.get("action", ""))
        with self.mutation_lock:
            if action == "configure-wireguard-host":
                _, output = _capture(configure_wireguard_host)
            elif action == "install-boot":
                output = install_boot(self.root)
            elif action == "start-autostart":
                _, output = _capture(run_enabled, self.root)
            elif action == "apply-public-host":
                public_host = str(body.get("publicHost", "")).strip()
                if not public_host:
                    raise HomelabError("公网 IP 或域名不能为空")
                result, output = _capture(update_wireguard_public_host, self.root, public_host)
                output = output or f"已更新 {result[0]} 个服务和 {result[1]} 份客户端配置"
            elif action == "finish":
                checks = migration_checks(self.root)
                if any(item.level == "error" for item in checks):
                    raise HomelabError("迁移检查仍有错误，未标记完成")
                record_machine(self.root)
                output = "迁移初始化已标记完成"
            else:
                raise HomelabError(f"不支持的迁移操作: {action}")
        return {"ok": True, "message": output or "操作已完成"}

    def wireguard(self, service_name: str) -> dict[str, Any]:
        service = find_service(self.root, service_name)
        if service.driver != "wireguard":
            raise HomelabError(f"{service.name} 不是 WireGuard 服务")
        section = service.spec["wireguard"]
        definitions = section.get("interfaces")
        if not isinstance(definitions, list):
            definitions = [
                {"name": section["interface"], "role": "server", "config": section["config"]}
            ]
        try:
            traffic = traffic_snapshot(service)
            traffic_error = ""
        except (HomelabError, OSError, ValueError) as exc:
            traffic = {"interfaces": [], "connections": []}
            traffic_error = str(exc)
        traffic_interfaces = {
            str(item.get("name")): item
            for item in traffic.get("interfaces", [])
            if isinstance(item, dict)
        }
        interfaces: list[dict[str, Any]] = []
        for definition in definitions:
            name = str(definition.get("name", ""))
            runtime = traffic_interfaces.get(
                name,
                {
                    "name": name,
                    "running": False,
                    "receivedBytes": 0,
                    "sentBytes": 0,
                    "latestHandshake": 0,
                    "peers": [],
                },
            )
            peer_runtime = {
                str(item.get("publicKey")): item
                for item in runtime.get("peers", [])
                if isinstance(item, dict) and item.get("publicKey")
            }
            try:
                address = interface_addresses(service, name)
            except HomelabError as exc:
                address = f"读取失败: {exc}"
            peers: list[dict[str, Any]] = []
            profiles: list[dict[str, str]] = []
            if definition.get("role") == "server" and isinstance(
                definition.get("peerManagement"), dict
            ):
                for item in list_peer_records(service, name):
                    record = {
                        key: item.get(key)
                        for key in (
                            "id",
                            "name",
                            "address",
                            "profile",
                            "managed",
                            "publicKey",
                            "allowedIPs",
                            "createdAt",
                        )
                    }
                    record["runtime"] = peer_runtime.get(
                        str(item.get("publicKey")),
                        {"receivedBytes": 0, "sentBytes": 0, "latestHandshake": 0},
                    )
                    peers.append(record)
                management = definition["peerManagement"]
                for profile_name, profile in management.get("accessProfiles", {}).items():
                    profiles.append(
                        {
                            "name": str(profile_name),
                            "description": str(profile.get("description", "")),
                        }
                    )
            settings: dict[str, Any] = {}
            if definition.get("role") == "server":
                try:
                    settings = server_interface_settings(service, name)
                except HomelabError:
                    pass
            interfaces.append(
                {
                    "name": name,
                    "role": str(definition.get("role", "")),
                    "address": address,
                    "runtime": runtime,
                    "peers": peers,
                    "profiles": profiles,
                    "settings": settings,
                }
            )
        traffic_connections = {
            str(item.get("name")): item
            for item in traffic.get("connections", [])
            if isinstance(item, dict)
        }
        connections: list[dict[str, Any]] = []
        for definition in section.get("connections", []):
            item = dict(definition)
            try:
                item["connected"] = connection_status(
                    service, str(definition.get("name")), quiet=True
                )
                item["statusError"] = ""
            except HomelabError as exc:
                item["connected"] = False
                item["statusError"] = str(exc)
            item["runtime"] = traffic_connections.get(str(definition.get("name")), {})
            connections.append(item)
        return {
            "service": service.name,
            "interfaces": interfaces,
            "connections": connections,
            "trafficError": traffic_error,
            "sampledAt": traffic.get("sampledAt", time.time()),
        }

    def wireguard_action(self, service_name: str, body: dict[str, Any]) -> dict[str, Any]:
        service = find_service(self.root, service_name)
        if service.driver != "wireguard":
            raise HomelabError(f"{service.name} 不是 WireGuard 服务")
        action = str(body.get("action", ""))
        if action in MUTATING_ACTIONS_REQUIRING_CONFIRMATION and not body.get("confirmed"):
            raise HomelabError("该 WireGuard 操作需要明确确认")
        with self.mutation_lock:
            result: Any = None
            if action == "start-interface":
                result, output = _capture(start_interface, service, str(body["interface"]))
            elif action == "stop-interface":
                result, output = _capture(stop_interface, service, str(body["interface"]))
            elif action == "sync-interface":
                result, output = _capture(sync_interface_runtime, service, str(body["interface"]))
            elif action == "connect":
                result, output = _capture(connect, service, str(body["connection"]))
            elif action == "disconnect":
                result, output = _capture(disconnect, service, str(body["connection"]))
            elif action == "adopt-connection":
                result, output = _capture(adopt_connection, service, str(body["connection"]))
            elif action in {"add-connection", "edit-connection"}:
                function = add_connection if action == "add-connection" else edit_connection
                result, output = _capture(
                    function,
                    service,
                    str(body["name"]),
                    str(body["source"]),
                    str(body["target"]),
                    str(body["sourceNetwork"]),
                    str(body.get("destinationNetworks", "")),
                    _bool(body.get("allowReturnTraffic"), True),
                    _bool(body.get("autoConnect"), False),
                )
            elif action == "delete-connection":
                result, output = _capture(delete_connection, service, str(body["connection"]))
            elif action == "create-server":
                result, output = _capture(
                    create_server_interface,
                    service,
                    str(body["interface"]),
                    str(body["address"]),
                    str(body["addressPool"]),
                    int(body["listenPort"]),
                    str(body["publicEndpoint"]),
                )
            elif action == "edit-server":
                result, output = _capture(
                    edit_server_interface,
                    service,
                    str(body["interface"]),
                    str(body["address"]),
                    str(body["addressPool"]),
                    int(body["listenPort"]),
                    str(body["publicEndpoint"]),
                )
            elif action == "delete-server":
                result, output = _capture(delete_server_interface, service, str(body["interface"]))
            elif action == "import-client":
                result, output = _capture(
                    import_client_interface,
                    service,
                    str(body["interface"]),
                    str(body["sourceConfig"]),
                )
            elif action == "delete-client":
                result, output = _capture(delete_client_interface, service, str(body["interface"]))
            elif action == "add-peer":
                result, output = _capture(
                    add_peer,
                    service,
                    str(body["interface"]),
                    str(body["name"]),
                    requested_address=str(body.get("address") or "") or None,
                    profile_name=str(body.get("profile") or "") or None,
                )
            elif action == "import-peers":
                result, output = _capture(import_peers, service, str(body["interface"]))
            elif action == "remove-peer":
                result, output = _capture(
                    remove_peer,
                    service,
                    str(body["interface"]),
                    str(body["peer"]),
                )
            elif action in {"export-peer", "peer-qr"}:
                path = peer_client_config_path(
                    service, str(body["interface"]), str(body["peer"])
                )
                content = path.read_text(encoding="utf-8")
                if action == "peer-qr":
                    image = qrcode.make(content, image_factory=SvgPathImage, border=2)
                    buffer = BytesIO()
                    image.save(buffer)
                    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
                    return {
                        "ok": True,
                        "message": "已生成客户端二维码",
                        "qr": f"data:image/svg+xml;base64,{encoded}",
                        "filename": path.name,
                    }
                return {
                    "ok": True,
                    "message": "已读取客户端配置",
                    "content": content,
                    "filename": path.name,
                }
            else:
                raise HomelabError(f"不支持的 WireGuard 操作: {action}")
        return {"ok": True, "message": output or "操作已完成", "result": result}


class NControlHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], root: Path, token: str) -> None:
        self.backend = WebBackend(root)
        self.session_value = hmac.new(token.encode(), b"session", hashlib.sha256).hexdigest()
        self.csrf_value = hmac.new(token.encode(), b"csrf", hashlib.sha256).hexdigest()
        super().__init__(address, NControlRequestHandler)


class NControlRequestHandler(BaseHTTPRequestHandler):
    server: NControlHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.client_address[0]} - {format % args}", flush=True)

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; img-src 'self' data:; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )

    def _send(self, status: int, content: bytes, content_type: str) -> None:
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _json(self, status: int, value: Any) -> None:
        self._send(
            status,
            json.dumps(value, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def _cookies(self) -> SimpleCookie[str]:
        cookies: SimpleCookie[str] = SimpleCookie()
        cookies.load(self.headers.get("Cookie", ""))
        return cookies

    def _authenticated(self) -> bool:
        value = self._cookies().get("ncontrol_session")
        return bool(value) and hmac.compare_digest(value.value, self.server.session_value)

    def _csrf_valid(self) -> bool:
        token = self.headers.get("X-NControl-CSRF", "")
        if not hmac.compare_digest(token, self.server.csrf_value):
            return False
        origin = self.headers.get("Origin")
        if not origin:
            return True
        return urlparse(origin).netloc == self.headers.get("Host", "")

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise HomelabError("请求长度无效") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise HomelabError("请求内容过大")
        return self.rfile.read(length)

    def _read_json(self) -> dict[str, Any]:
        try:
            value = json.loads(self._read_body().decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HomelabError("JSON 请求格式无效") from exc
        if not isinstance(value, dict):
            raise HomelabError("JSON 请求必须是对象")
        return value

    def _login_page(self, error: str = "") -> bytes:
        message = f'<p class="error">{error}</p>' if error else ""
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NControl 登录</title><link rel="stylesheet" href="/assets/style.css"></head>
<body class="login-body"><main class="login-card"><div class="brand-mark">N</div><p class="eyebrow">LOCAL CONTROL PLANE</p>
<h1>NControl</h1><p class="muted">请输入本机 Web 管理令牌。</p>{message}
<form method="post" action="/login"><label for="token">管理令牌</label><input id="token" name="token" type="password" required autofocus autocomplete="current-password">
<button class="button primary" type="submit">进入控制台</button></form><p class="security-note">仅建议通过 localhost 或 WireGuard 访问</p></main></body></html>""".encode("utf-8")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/login":
            self._send(HTTPStatus.OK, self._login_page(), "text/html; charset=utf-8")
            return
        if path.startswith("/assets/"):
            asset = path.removeprefix("/assets/")
            allowed = {
                "style.css": "text/css; charset=utf-8",
                "app.js": "text/javascript; charset=utf-8",
            }
            if asset not in allowed:
                self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
                return
            try:
                content = (ASSET_DIRECTORY / asset).read_bytes()
            except OSError:
                self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
                return
            self._send(HTTPStatus.OK, content, allowed[asset])
            return
        if not self._authenticated():
            if path.startswith("/api/"):
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "未登录"})
            else:
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", "/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
            return
        if path == "/":
            self._send(
                HTTPStatus.OK,
                (ASSET_DIRECTORY / "index.html").read_bytes(),
                "text/html; charset=utf-8",
            )
            return
        try:
            self._handle_api_get(path)
        except (HomelabError, UnsupportedOperation, OSError, ValueError, KeyError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            self.log_error("GET %s failed: %r", path, exc)
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "服务器内部错误"})

    def _handle_api_get(self, path: str) -> None:
        if path == "/api/dashboard":
            result = self.server.backend.dashboard()
            result["csrf"] = self.server.csrf_value
            self._json(HTTPStatus.OK, result)
            return
        if path == "/api/doctor":
            self._json(HTTPStatus.OK, self.server.backend.doctor())
            return
        if path == "/api/update":
            self._json(HTTPStatus.OK, self.server.backend.update_info())
            return
        if path == "/api/proxy":
            self._json(HTTPStatus.OK, self.server.backend.proxy_info())
            return
        if path == "/api/migration":
            self._json(HTTPStatus.OK, self.server.backend.migration())
            return
        parts = [unquote(item) for item in path.strip("/").split("/")]
        if len(parts) == 4 and parts[:2] == ["api", "services"] and parts[3] == "logs":
            self._json(HTTPStatus.OK, self.server.backend.logs(parts[2]))
            return
        if len(parts) == 4 and parts[:2] == ["api", "services"] and parts[3] == "config-check":
            self._json(HTTPStatus.OK, self.server.backend.config_check(parts[2]))
            return
        if len(parts) == 3 and parts[:2] == ["api", "wireguard"]:
            self._json(HTTPStatus.OK, self.server.backend.wireguard(parts[2]))
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "接口不存在"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/login":
            try:
                form = parse_qs(self._read_body().decode("utf-8"))
                supplied = form.get("token", [""])[0]
                expected = read_token(self.server.backend.root)
            except (HomelabError, UnicodeDecodeError):
                supplied = ""
                expected = "invalid"
            if not hmac.compare_digest(supplied, expected):
                time.sleep(0.4)
                self._send(
                    HTTPStatus.UNAUTHORIZED,
                    self._login_page("令牌不正确"),
                    "text/html; charset=utf-8",
                )
                return
            self.send_response(HTTPStatus.SEE_OTHER)
            self._security_headers()
            self.send_header("Location", "/")
            self.send_header(
                "Set-Cookie",
                f"ncontrol_session={self.server.session_value}; Path=/; HttpOnly; SameSite=Strict",
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if not self._authenticated():
            try:
                self._read_body()
            except HomelabError:
                pass
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "未登录"})
            return
        if not self._csrf_valid():
            try:
                self._read_body()
            except HomelabError:
                pass
            self._json(HTTPStatus.FORBIDDEN, {"error": "安全校验失败，请刷新页面"})
            return
        if path == "/logout":
            self.send_response(HTTPStatus.SEE_OTHER)
            self._security_headers()
            self.send_header("Location", "/login")
            self.send_header(
                "Set-Cookie",
                "ncontrol_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            body = self._read_json()
            self._handle_api_post(path, body)
        except (HomelabError, UnsupportedOperation, OSError, ValueError, KeyError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            self.log_error("POST %s failed: %r", path, exc)
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "服务器内部错误"})

    def _handle_api_post(self, path: str, body: dict[str, Any]) -> None:
        if path == "/api/update":
            self._json(
                HTTPStatus.OK,
                self.server.backend.apply_update(_bool(body.get("confirmed"))),
            )
            return
        if path == "/api/proxy":
            self._json(HTTPStatus.OK, self.server.backend.configure_proxy(body))
            return
        if path == "/api/migration/action":
            self._json(HTTPStatus.OK, self.server.backend.migration_action(body))
            return
        parts = [unquote(item) for item in path.strip("/").split("/")]
        if len(parts) == 4 and parts[:2] == ["api", "services"] and parts[3] == "action":
            self._json(HTTPStatus.OK, self.server.backend.service_action(parts[2], body))
            return
        if len(parts) == 4 and parts[:2] == ["api", "wireguard"] and parts[3] == "action":
            self._json(HTTPStatus.OK, self.server.backend.wireguard_action(parts[2], body))
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "接口不存在"})


def serve(root: Path) -> None:
    config = load_config(root)
    if not config["enabled"]:
        raise HomelabError("Web 管理尚未启用")
    token = read_token(root)
    address = (str(config["bind"]), int(config["port"]))
    server = NControlHTTPServer(address, root, token)
    print(f"NControl Web 已启动: http://{address[0]}:{address[1]}/", flush=True)
    server.serve_forever(poll_interval=0.5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="homelabctl.web_server")
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args(argv)
    apply_proxy_environment(args.root.resolve())
    try:
        serve(args.root.resolve())
        return 0
    except HomelabError as exc:
        print(f"错误: {exc}", flush=True)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
