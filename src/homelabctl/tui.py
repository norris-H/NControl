from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

import yaml
from rich.markup import escape
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.events import Key
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from .config import load_all, load_service
from .audit import audit_services
from .boot import install as install_boot
from .boot import is_installed as boot_is_installed
from .boot import run_enabled, set_service_autostart
from .drivers import get_driver
from .errors import HomelabError, UnsupportedOperation
from .layout import services_directory
from .models import CommandPlan, ServiceDefinition
from .migration import (
    configure_wireguard_host,
    migration_checks,
    record_machine,
    update_wireguard_public_host,
    wireguard_public_hosts,
)
from .security import check_config_paths
from .updates import UpdateInfo, apply_update, check_for_updates
from .wireguard_control import (
    interface_addresses,
    interface_peer_networks,
    list_peer_records,
    peer_qr_text,
    server_interface_settings,
)


class WireGuardQrScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("escape", "close", "返回"),
        Binding("q", "close", "返回"),
    ]

    CSS = """
    WireGuardQrScreen {
        align: center middle;
        background: black;
    }
    WireGuardQrScreen #qr-title {
        height: 2;
        width: 1fr;
        content-align: center middle;
        color: white;
        text-style: bold;
    }
    WireGuardQrScreen #qr-scroll {
        width: 1fr;
        height: 1fr;
        align: center middle;
        overflow: auto;
    }
    WireGuardQrScreen #qr-code {
        width: auto;
        height: auto;
        color: white;
        background: black;
        text-align: center;
    }
    """

    def __init__(self, peer_name: str, qr_text: str) -> None:
        super().__init__()
        self.peer_name = peer_name
        self.qr_text = qr_text

    def compose(self) -> ComposeResult:
        yield Static(
            f"WireGuard 客户端：{escape(self.peer_name)}    Esc/Q 返回",
            id="qr-title",
            markup=True,
        )
        with VerticalScroll(id="qr-scroll"):
            yield Static(self.qr_text, id="qr-code", markup=False)

    def action_close(self) -> None:
        self.dismiss(None)


class ConfirmActionScreen(ModalScreen[bool]):
    BINDINGS = [
        Binding("escape", "cancel", "取消"),
        Binding("left", "focus_cancel", "选择取消", show=False),
        Binding("up", "focus_cancel", "选择取消", show=False),
        Binding("right", "focus_confirm", "选择确认", show=False),
        Binding("down", "focus_confirm", "选择确认", show=False),
        Binding("tab", "toggle_choice", "切换选项", show=False),
        Binding("shift+tab", "toggle_choice", "切换选项", show=False),
    ]

    CSS = """
    ConfirmActionScreen {
        align: center middle;
        background: $background 70%;
    }
    ConfirmActionScreen > Grid {
        width: 66;
        height: 12;
        grid-size: 2 3;
        grid-rows: 2 1fr 3;
        padding: 1 2;
        border: thick $warning;
        background: $surface;
    }
    ConfirmActionScreen Label {
        column-span: 2;
        content-align: center middle;
    }
    ConfirmActionScreen #confirm-title {
        text-style: bold;
        color: $warning;
    }
    ConfirmActionScreen Button { width: 100%; }
    """

    def __init__(self, title: str, message: str, confirm_label: str = "确认") -> None:
        super().__init__()
        self.dialog_title = title
        self.message = message
        self.confirm_label = confirm_label

    def compose(self) -> ComposeResult:
        with Grid():
            yield Label(self.dialog_title, id="confirm-title")
            yield Label(
                f"{self.message}\n←/→ 或 Tab 选择，Enter 确认，Esc 取消"
            )
            yield Button("取消", variant="primary", id="cancel")
            yield Button(self.confirm_label, variant="warning", id="confirm")

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)

    def action_focus_cancel(self) -> None:
        self.query_one("#cancel", Button).focus()

    def action_focus_confirm(self) -> None:
        self.query_one("#confirm", Button).focus()

    def action_toggle_choice(self) -> None:
        cancel = self.query_one("#cancel", Button)
        confirm = self.query_one("#confirm", Button)
        (cancel if confirm.has_focus else confirm).focus()


class AddWireGuardPeerScreen(ModalScreen[dict[str, str] | None]):
    BINDINGS = [Binding("escape", "cancel", "取消")]

    CSS = """
    AddWireGuardPeerScreen {
        align: center middle;
        background: $background 70%;
    }
    AddWireGuardPeerScreen > Vertical {
        width: 86;
        min-width: 70;
        height: 32;
        min-height: 26;
        max-height: 90%;
        padding: 1 2;
        border: thick $accent;
        background: $surface;
        overflow-y: auto;
    }
    AddWireGuardPeerScreen .field-label { margin-top: 1; }
    AddWireGuardPeerScreen #peer-actions { height: 3; margin-top: 1; }
    AddWireGuardPeerScreen Button { width: 1fr; }
    """

    def __init__(self, service: ServiceDefinition) -> None:
        super().__init__()
        self.service = service
        values = service.spec["wireguard"].get("interfaces", [])
        self.server_interfaces = [
            value
            for value in values
            if isinstance(value, dict)
            and value.get("role") == "server"
            and isinstance(value.get("peerManagement"), dict)
        ]

    def _profile_options(self, interface_name: str) -> list[tuple[str, str]]:
        interface = next(
            value for value in self.server_interfaces if value.get("name") == interface_name
        )
        management = interface["peerManagement"]
        return [
            (str(value.get("description", name)), str(name))
            for name, value in management.get("accessProfiles", {}).items()
        ]

    def compose(self) -> ComposeResult:
        first = str(self.server_interfaces[0]["name"])
        profiles = self._profile_options(first)
        management = self.server_interfaces[0]["peerManagement"]
        default_profile = str(
            management.get("defaultAccessProfile") or profiles[0][1]
        )
        with Vertical():
            yield Label("添加 WireGuard 客户端", id="add-peer-title")
            yield Label("服务端接口", classes="field-label")
            yield Select(
                [(str(value["name"]), str(value["name"])) for value in self.server_interfaces],
                value=first,
                allow_blank=False,
                id="peer-interface",
            )
            yield Label("客户端名称", classes="field-label")
            yield Input(placeholder="例如：phone、laptop、home-router", id="peer-name")
            yield Label("WireGuard 地址（留空自动分配）", classes="field-label")
            yield Input(placeholder="例如：10.10.0.6", id="peer-address")
            yield Label("访问权限", classes="field-label")
            yield Select(
                profiles,
                value=default_profile,
                allow_blank=False,
                id="peer-profile",
            )
            with Horizontal(id="peer-actions"):
                yield Button("取消", id="cancel")
                yield Button("生成客户端", variant="success", id="confirm")

    def on_mount(self) -> None:
        self.query_one("#peer-name", Input).focus()

    @on(Select.Changed, "#peer-interface")
    def on_interface_changed(self, event: Select.Changed) -> None:
        interface_name = str(event.value)
        options = self._profile_options(interface_name)
        profile = self.query_one("#peer-profile", Select)
        profile.set_options(options)
        interface = next(
            value for value in self.server_interfaces if value.get("name") == interface_name
        )
        default = interface["peerManagement"].get("defaultAccessProfile")
        profile.value = str(default or options[0][1])

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        name = self.query_one("#peer-name", Input).value.strip()
        if not name:
            self.query_one("#peer-name", Input).focus()
            self.notify("请输入客户端名称", severity="warning")
            return
        self.dismiss(
            {
                "interface": str(self.query_one("#peer-interface", Select).value),
                "name": name,
                "address": self.query_one("#peer-address", Input).value.strip(),
                "profile": str(self.query_one("#peer-profile", Select).value),
            }
        )

    def action_cancel(self) -> None:
        self.dismiss(None)


class CreateWireGuardServerScreen(ModalScreen[dict[str, str] | None]):
    BINDINGS = [Binding("escape", "cancel", "取消")]

    CSS = """
    CreateWireGuardServerScreen {
        align: center middle;
        background: $background 70%;
    }
    CreateWireGuardServerScreen > Vertical {
        width: 88;
        height: 34;
        max-height: 92%;
        padding: 1 2;
        border: thick $accent;
        background: $surface;
        overflow-y: auto;
    }
    CreateWireGuardServerScreen .field-label { margin-top: 1; }
    CreateWireGuardServerScreen .form-note { color: $text-muted; height: 2; }
    CreateWireGuardServerScreen #server-actions { height: 3; margin-top: 1; }
    CreateWireGuardServerScreen Button { width: 1fr; }
    """

    def __init__(self, defaults: dict[str, str], *, editing: bool = False) -> None:
        super().__init__()
        self.defaults = defaults
        self.editing = editing

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(
                "编辑 WireGuard 服务端" if self.editing else "新建 WireGuard 服务端",
                id="create-server-title",
            )
            yield Label(
                (
                    "保存时会短暂重启运行中的接口；失败会恢复原配置。"
                    if self.editing
                    else "生成独立密钥和配置，并尝试立即启动；不会修改云防火墙或安全组。"
                ),
                classes="form-note",
            )
            yield Label("接口名称", classes="field-label")
            yield Input(
                value=self.defaults["interface"],
                disabled=self.editing,
                id="server-interface",
            )
            yield Label("客户端地址池", classes="field-label")
            yield Input(value=self.defaults["address_pool"], id="server-address-pool")
            yield Label("服务端地址", classes="field-label")
            yield Input(value=self.defaults["address"], id="server-address")
            yield Label("UDP 监听端口", classes="field-label")
            yield Input(value=self.defaults["listen_port"], id="server-listen-port")
            yield Label("公网入口（IP或域名:端口）", classes="field-label")
            yield Input(value=self.defaults["public_endpoint"], id="server-public-endpoint")
            with Horizontal(id="server-actions"):
                yield Button("取消", id="cancel")
                yield Button(
                    "保存并重启" if self.editing else "创建并启动",
                    variant="success",
                    id="confirm",
                )

    def on_mount(self) -> None:
        self.query_one(
            "#server-address" if self.editing else "#server-interface", Input
        ).focus()

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        result = {
            "interface": self.query_one("#server-interface", Input).value.strip(),
            "address_pool": self.query_one("#server-address-pool", Input).value.strip(),
            "address": self.query_one("#server-address", Input).value.strip(),
            "listen_port": self.query_one("#server-listen-port", Input).value.strip(),
            "public_endpoint": self.query_one("#server-public-endpoint", Input).value.strip(),
        }
        if not all(result.values()):
            self.notify("请填写全部字段", severity="warning")
            return
        try:
            port = int(result["listen_port"])
        except ValueError:
            self.query_one("#server-listen-port", Input).focus()
            self.notify("监听端口必须是数字", severity="warning")
            return
        if not 1 <= port <= 65535:
            self.query_one("#server-listen-port", Input).focus()
            self.notify("监听端口必须在 1-65535 之间", severity="warning")
            return
        self.dismiss(result)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ConnectWireGuardServerScreen(ModalScreen[dict[str, str] | None]):
    BINDINGS = [Binding("escape", "cancel", "取消")]

    CSS = """
    ConnectWireGuardServerScreen {
        align: center middle;
        background: $background 70%;
    }
    ConnectWireGuardServerScreen > Vertical {
        width: 94;
        min-width: 72;
        height: 32;
        min-height: 24;
        max-height: 92%;
        padding: 1 2;
        border: thick $accent;
        background: $surface;
        overflow-y: auto;
    }
    ConnectWireGuardServerScreen .field-label { margin-top: 1; }
    ConnectWireGuardServerScreen .form-note { color: $text-muted; height: 3; }
    ConnectWireGuardServerScreen #client-actions { height: 3; margin-top: 1; }
    ConnectWireGuardServerScreen Button { width: 1fr; }
    """

    def __init__(self, interface_name: str) -> None:
        super().__init__()
        self.interface_name = interface_name

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("连接其他 WireGuard 服务端", id="connect-server-title")
            yield Label(
                "先在另一台 NControl 添加客户端并导出 .conf，再把该文件复制到本机后从这里导入。",
                classes="form-note",
            )
            yield Label("本机接口名称", classes="field-label")
            yield Input(value=self.interface_name, id="client-interface")
            yield Label("客户端配置文件路径", classes="field-label")
            yield Input(placeholder="例如：/home/ubuntu/remote-client.conf", id="client-config")
            with Horizontal(id="client-actions"):
                yield Button("取消", id="cancel")
                yield Button("导入并连接", variant="success", id="confirm")

    def on_mount(self) -> None:
        self.query_one("#client-config", Input).focus()

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        result = {
            "interface": self.query_one("#client-interface", Input).value.strip(),
            "source_config": self.query_one("#client-config", Input).value.strip(),
        }
        if not result["interface"]:
            self.query_one("#client-interface", Input).focus()
            self.notify("请输入本机接口名称", severity="warning")
            return
        if not result["source_config"]:
            self.query_one("#client-config", Input).focus()
            self.notify("请输入客户端配置文件路径", severity="warning")
            return
        self.dismiss(result)

    def action_cancel(self) -> None:
        self.dismiss(None)


class WireGuardConnectionScreen(ModalScreen[dict[str, str] | None]):
    BINDINGS = [Binding("escape", "cancel", "取消")]

    CSS = """
    WireGuardConnectionScreen {
        align: center middle;
        background: $background 70%;
    }
    WireGuardConnectionScreen > Vertical {
        width: 90;
        height: 38;
        max-height: 92%;
        padding: 1 2;
        border: thick $accent;
        background: $surface;
        overflow-y: auto;
    }
    WireGuardConnectionScreen .field-label { margin-top: 1; }
    WireGuardConnectionScreen .form-note { color: $text-muted; height: 3; }
    WireGuardConnectionScreen #connection-actions { height: 3; margin-top: 1; }
    WireGuardConnectionScreen Button { width: 1fr; }
    """

    def __init__(
        self,
        interface_names: list[str],
        defaults: dict[str, str],
        *,
        editing: bool = False,
    ) -> None:
        super().__init__()
        self.interface_names = interface_names
        self.defaults = defaults
        self.editing = editing

    def compose(self) -> ComposeResult:
        options = [(name, name) for name in self.interface_names]
        with Vertical():
            yield Label(
                "编辑网络连接" if self.editing else "添加网络连接",
                id="connection-form-title",
            )
            yield Label(
                (
                    "方向表示来源网段可以主动访问目标接口；已启用的连接保存时会短暂替换规则。"
                    if self.editing
                    else "方向表示来源网段可以主动访问目标接口；创建后再按 C 启用。双向主动访问需建立两个方向。"
                ),
                classes="form-note",
            )
            yield Label("连接名称", classes="field-label")
            yield Input(
                value=self.defaults["name"],
                disabled=self.editing,
                id="connection-name",
            )
            yield Label("来源接口", classes="field-label")
            yield Select(
                options,
                value=self.defaults["source"],
                allow_blank=False,
                id="connection-source",
            )
            yield Label("目标接口", classes="field-label")
            yield Select(
                options,
                value=self.defaults["target"],
                allow_blank=False,
                id="connection-target",
            )
            yield Label("来源网段", classes="field-label")
            yield Input(
                value=self.defaults["source_network"],
                placeholder="例如：10.20.0.0/24",
                id="connection-source-network",
            )
            yield Label("需要通过目标接口访问的网段（多个用逗号分隔）", classes="field-label")
            yield Input(
                value=self.defaults["destination_networks"],
                placeholder="例如：192.168.7.0/24, 192.168.31.0/24",
                id="connection-destination-networks",
            )
            yield Label("允许目标侧返回已建立连接的流量", classes="field-label")
            yield Select(
                [("允许", "true"), ("不允许", "false")],
                value=self.defaults["allow_return"],
                allow_blank=False,
                id="connection-allow-return",
            )
            yield Label("WireGuard 整体启动时自动启用", classes="field-label")
            yield Select(
                [("是", "true"), ("否", "false")],
                value=self.defaults["auto_connect"],
                allow_blank=False,
                id="connection-auto-connect",
            )
            with Horizontal(id="connection-actions"):
                yield Button("取消", id="cancel")
                yield Button(
                    "保存修改" if self.editing else "添加连接",
                    variant="success",
                    id="confirm",
                )

    def on_mount(self) -> None:
        self.query_one(
            "#connection-source-network" if self.editing else "#connection-name",
            Input,
        ).focus()

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        result = {
            "name": self.query_one("#connection-name", Input).value.strip(),
            "source": str(self.query_one("#connection-source", Select).value),
            "target": str(self.query_one("#connection-target", Select).value),
            "source_network": self.query_one(
                "#connection-source-network", Input
            ).value.strip(),
            "destination_networks": self.query_one(
                "#connection-destination-networks", Input
            ).value.strip(),
            "allow_return": str(
                self.query_one("#connection-allow-return", Select).value
            ),
            "auto_connect": str(
                self.query_one("#connection-auto-connect", Select).value
            ),
        }
        if not result["name"] or not result["source_network"]:
            self.notify("请填写连接名称和来源网段", severity="warning")
            return
        if result["source"] == result["target"]:
            self.notify("来源接口和目标接口不能相同", severity="warning")
            return
        self.dismiss(result)

    def action_cancel(self) -> None:
        self.dismiss(None)


class WireGuardTable(DataTable):
    """Data table that keeps Tab navigation inside the WireGuard manager."""

    BINDINGS = [
        Binding("tab", "focus_next_region", "下一个区域", show=False),
        Binding("ctrl+i", "focus_next_region", "下一个区域", show=False),
        Binding("shift+tab", "focus_previous_region", "上一个区域", show=False, priority=True),
    ]

    def on_key(self, event: Key) -> None:
        if event.key in ("tab", "ctrl+i"):
            event.stop()
            self.action_focus_next_region()
        elif event.key == "shift+tab":
            event.stop()
            self.action_focus_previous_region()

    def action_focus_next_region(self) -> None:
        action = getattr(self.screen, "action_focus_next_table", None)
        if action is not None:
            action()

    def action_focus_previous_region(self) -> None:
        action = getattr(self.screen, "action_focus_previous_table", None)
        if action is not None:
            action()


class WireGuardTabs(TabbedContent):
    """Tabbed container with explicit keyboard navigation for the manager."""

    def on_key(self, event: Key) -> None:
        if event.key in ("tab", "ctrl+i"):
            event.stop()
            action = getattr(self.screen, "action_focus_next_table", None)
            if action is not None:
                action()
        elif event.key == "shift+tab":
            event.stop()
            action = getattr(self.screen, "action_focus_previous_table", None)
            if action is not None:
                action()


class WireGuardManagerScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("escape", "close", "返回", priority=True),
        Binding("q", "close", "返回", priority=True),
        Binding("a", "add_selected", "添加", priority=True),
        Binding("i", "import_peers", "识别已有客户端", priority=True),
        Binding("c", "connect_selected", "连接", priority=True),
        Binding("y", "sync_interface", "同步配置", priority=True),
        Binding("x", "disconnect_or_delete_connection", "断开或删除", priority=True),
        Binding("d", "delete_or_disconnect", "删除或断开", priority=True),
        Binding("m", "adopt_connection", "接管旧规则", priority=True),
        Binding("e", "edit_or_export", "编辑或导出", priority=True),
        Binding("v", "peer_qr", "显示二维码", priority=True),
        Binding("r", "remove_peer", "撤销客户端", priority=True),
        Binding("n", "new_server", "新建服务端", priority=True),
        Binding("j", "connect_server", "连接其他服务端", priority=True),
        Binding("tab", "focus_next_table", "下一个区域", show=False),
        Binding("ctrl+i", "focus_next_table", "下一个区域", show=False),
        Binding("shift+tab", "focus_previous_table", "上一个区域", show=False, priority=True),
    ]

    CSS = """
    WireGuardManagerScreen { layout: vertical; }
    WireGuardManagerScreen #wg-title {
        height: 3;
        padding: 1 2;
        text-style: bold;
        background: $primary;
        color: $text;
    }
    WireGuardManagerScreen #wg-groups {
        height: 58%;
        padding: 0;
        border: round $accent;
    }
    WireGuardManagerScreen TabPane {
        padding: 0 1;
    }
    WireGuardManagerScreen .wg-section-note {
        height: 2;
        padding: 0 1;
        color: $text-muted;
    }
    WireGuardManagerScreen .wg-table {
        height: 1fr;
        border: round $accent;
    }
    WireGuardManagerScreen #wg-output {
        height: 1fr;
        border: round $secondary;
        padding: 0 1;
        overflow-x: auto;
    }
    WireGuardManagerScreen #wg-actions {
        height: 3;
        padding: 1 2;
        color: $text-muted;
        background: $panel;
    }
    """

    def __init__(self, service: ServiceDefinition) -> None:
        super().__init__()
        self.service = service
        self.row_values: dict[str, dict[str, Any]] = {}
        self.selected_key: str | None = None
        self.connection_states: dict[str, str] = {}
        self.interface_states: dict[str, str] = {}
        self._traffic_previous: dict[str, tuple[float, int, int]] = {}
        self._focused_table_id = "#wg0-items"
        self._traffic_timer = None

    def compose(self) -> ComposeResult:
        yield Static(
            f"WireGuard 管理  ·  {escape(self.service.description or self.service.name)}",
            id="wg-title",
        )
        with WireGuardTabs(initial="wg0-tab", id="wg-groups"):
            with TabPane("服务端接口", id="wg0-tab"):
                yield Static(
                    "云服务器的 WireGuard 地址，以及通过二维码接入的客户端。",
                    classes="wg-section-note",
                )
                yield WireGuardTable(id="wg0-items", classes="wg-table", cursor_type="row", zebra_stripes=True)
            with TabPane("客户端接口", id="wg1-tab"):
                yield Static(
                    "NControl 通过这个接口连接另一侧网络。",
                    classes="wg-section-note",
                )
                yield WireGuardTable(id="wg1-items", classes="wg-table", cursor_type="row", zebra_stripes=True)
            with TabPane("网络连接", id="connections-tab"):
                yield Static(
                    "控制各 WireGuard 接口之间的转发、返回流量和 NAT。",
                    classes="wg-section-note",
                )
                yield WireGuardTable(id="wg-connections", classes="wg-table", cursor_type="row", zebra_stripes=True)
        yield RichLog(id="wg-output", wrap=False, markup=True, highlight=True)
        yield Static("Tab/Shift+Tab 切换区域  Esc/Q 返回", id="wg-actions")

    def on_mount(self) -> None:
        for table_id, columns in {
            "#wg0-items": ("对象", "地址", "状态", "实时流量", "累计流量"),
            "#wg1-items": ("接口", "本机地址", "状态", "实时流量", "累计流量"),
            "#wg-connections": ("连接", "方向 / 网段", "状态", "实时流量", "累计流量"),
        }.items():
            table = self.query_one(table_id, DataTable)
            for index, label in enumerate(columns):
                table.add_column(
                    label,
                    key=("name", "route", "status", "speed", "total")[index],
                )
        self._reload_rows()
        self._focus_table("#wg0-items")
        self.refresh_interface_statuses()
        self.refresh_connection_statuses()
        self.refresh_traffic()
        self._traffic_timer = self.set_interval(2.0, self.refresh_traffic)

    async def on_unmount(self) -> None:
        if self._traffic_timer is not None:
            self._traffic_timer.pause()
        workers = self.app.workers.cancel_node(self)
        await asyncio.gather(*(worker.wait() for worker in workers), return_exceptions=True)

    def _write(self, value: str) -> None:
        self.query_one("#wg-output", RichLog).write(value)

    def _focus_table(self, table_id: str) -> None:
        table = self.query_one(table_id, DataTable)
        if not table.row_count:
            return
        tab_ids = {
            "#wg0-items": "wg0-tab",
            "#wg1-items": "wg1-tab",
            "#wg-connections": "connections-tab",
        }
        self.query_one("#wg-groups", TabbedContent).active = tab_ids[table_id]
        self._focused_table_id = table_id
        table.move_cursor(row=0)
        first_row_key = next(iter(table.rows), None)
        self.selected_key = (
            str(first_row_key.value) if first_row_key is not None else None
        )
        self._update_action_bar()
        self.app.call_after_refresh(self._set_table_focus, table_id)

    def _set_table_focus(self, table_id: str) -> None:
        self.app.set_focus(self.query_one(table_id, DataTable))

    def action_focus_next_table(self) -> None:
        table_ids = ["#wg0-items", "#wg1-items", "#wg-connections"]
        current = table_ids.index(self._focused_table_id) if self._focused_table_id in table_ids else 0
        for offset in range(1, len(table_ids) + 1):
            candidate = table_ids[(current + offset) % len(table_ids)]
            if self.query_one(candidate, DataTable).row_count:
                self._focus_table(candidate)
                return

    def action_focus_previous_table(self) -> None:
        table_ids = ["#wg0-items", "#wg1-items", "#wg-connections"]
        current = table_ids.index(self._focused_table_id) if self._focused_table_id in table_ids else 0
        for offset in range(1, len(table_ids) + 1):
            candidate = table_ids[(current - offset) % len(table_ids)]
            if self.query_one(candidate, DataTable).row_count:
                self._focus_table(candidate)
                return

    def _reload_rows(self) -> None:
        tables = {
            "wg0": self.query_one("#wg0-items", DataTable),
            "wg1": self.query_one("#wg1-items", DataTable),
            "connections": self.query_one("#wg-connections", DataTable),
        }
        for table in tables.values():
            table.clear()
        self.row_values = {}
        section = self.service.spec["wireguard"]
        role_names = {"server": "服务端", "client": "客户端"}
        addresses: dict[str, str] = {}
        for interface in section.get("interfaces", []):
            name = str(interface["name"])
            try:
                address = interface_addresses(self.service, name)
            except HomelabError as exc:
                address = "地址未读取"
                self._write(f"[yellow]{escape(str(exc))}[/yellow]")
            addresses[name] = address
            role = str(interface.get("role"))
            table = tables["wg0" if role == "server" else "wg1"]
            key = f"interface:{name}"
            self.row_values[key] = {"kind": "interface", **interface}
            table.add_row(
                name,
                address,
                "等待检查" if role == "server" else role_names.get(role, "由主界面管理"),
                "采样中",
                "-",
                key=key,
            )
            if isinstance(interface.get("peerManagement"), dict):
                try:
                    records = list_peer_records(self.service, name)
                except HomelabError as exc:
                    self._write(f"[red]{escape(str(exc))}[/red]")
                    records = []
                for record in records:
                    peer_id = str(record.get("id", "unregistered"))
                    public_key = str(record.get("publicKey", ""))
                    key = f"peer:{name}:{peer_id}:{public_key[:12]}"
                    self.row_values[key] = {
                        "kind": "peer",
                        "interface": name,
                        **record,
                    }
                    address = str(record.get("address") or ", ".join(record.get("allowedIPs", [])))
                    status = "可管理" if record.get("managed") else "只读导入"
                    tables["wg0"].add_row(
                        str(record.get("name")), address, status, "采样中", "-", key=key
                    )
        if not tables["wg0"].row_count:
            tables["wg0"].add_row(
                "暂无服务端接口", "-", "按 N 新建", "-", "-", key="empty:server"
            )
        if not tables["wg1"].row_count:
            tables["wg1"].add_row(
                "暂无客户端接口", "-", "按 J 连接", "-", "-", key="empty:client"
            )
        for interface in section.get("interfaces", []):
            name = str(interface["name"])
            if str(interface.get("role")) != "client":
                continue
            try:
                networks = interface_peer_networks(self.service, name)
            except HomelabError as exc:
                networks = ()
                self._write(f"[yellow]{escape(str(exc))}[/yellow]")
            tables["wg1"].update_cell(
                f"interface:{name}",
                "status",
                ", ".join(networks) if networks else "未读取对端网络",
            )
        for connection in section.get("connections", []):
            name = str(connection["name"])
            key = f"connection:{name}"
            self.row_values[key] = {"kind": "connection", **connection}
            source = str(connection["from"])
            target = str(connection["to"])
            source_address = addresses.get(source, "地址未知")
            target_address = addresses.get(target, "地址未知")
            tables["connections"].add_row(
                name,
                (
                    f"{source} ({source_address}) → {target} ({target_address}) · "
                    f"{connection['sourceNetwork']} ⇢ "
                    f"{', '.join(connection.get('destinationNetworks', [])) or '目标接口路由'}"
                ),
                "等待检查",
                "采样中",
                "-",
                key=key,
            )
        if not tables["connections"].row_count:
            tables["connections"].add_row(
                "暂无网络连接", "-", "按 A 添加", "-", "-", key="empty:connection"
            )
        first_key = next(iter(self.row_values), None)
        if first_key:
            self.selected_key = first_key
            first_value = self.row_values[first_key]
            if first_value.get("kind") == "connection":
                first_table = tables["connections"]
            elif first_value.get("kind") == "interface" and first_value.get("role") == "client":
                first_table = tables["wg1"]
            else:
                first_table = tables["wg0"]
            first_table.move_cursor(row=0)
        self._update_action_bar()

    def _select_row(self, event: DataTable.RowHighlighted, table_id: str) -> None:
        active_table = {
            "wg0-tab": "#wg0-items",
            "wg1-tab": "#wg1-items",
            "connections-tab": "#wg-connections",
        }.get(self.query_one("#wg-groups", TabbedContent).active)
        if active_table != table_id:
            return
        value = event.row_key.value
        self.selected_key = str(value) if value is not None else None
        self._focused_table_id = table_id
        self._update_action_bar()

    @on(DataTable.RowHighlighted, "#wg0-items")
    def on_wg0_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._select_row(event, "#wg0-items")

    @on(DataTable.RowHighlighted, "#wg1-items")
    def on_wg1_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._select_row(event, "#wg1-items")

    @on(DataTable.RowHighlighted, "#wg-connections")
    def on_connection_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._select_row(event, "#wg-connections")

    def _update_action_bar(self) -> None:
        if not self.is_mounted:
            return
        try:
            action_bar = self.query_one("#wg-actions", Static)
            active_tab = self.query_one("#wg-groups", TabbedContent).active
        except NoMatches:
            return
        actions = ["Tab/Shift+Tab 切换区域", "Esc/Q 返回"]
        if active_tab == "wg0-tab":
            actions.insert(0, "N 新建服务端")
        elif active_tab == "wg1-tab":
            actions.insert(0, "J 连接其他服务端")
        elif active_tab == "connections-tab":
            actions.insert(0, "A 添加连接")
        selected = self._selected()
        if selected is None:
            text = "  ".join(actions)
            action_bar.update(text)
            return

        kind = selected.get("kind")
        if kind == "interface":
            if isinstance(selected.get("peerManagement"), dict):
                interface_actions = [
                    "A 添加客户端",
                    "I 识别已有客户端",
                    "E 编辑服务端",
                    "D 删除服务端",
                ]
                state = self.interface_states.get(str(selected.get("name")), "unknown")
                interface_actions.insert(
                    0,
                    "X 断开服务端" if state == "connected" else "C 连接服务端",
                )
                if state == "connected":
                    interface_actions.insert(1, "Y 同步配置")
                actions[0:0] = interface_actions
            elif selected.get("role") == "client":
                actions.insert(0, "D 删除客户端")
        elif kind == "peer":
            if selected.get("managed"):
                actions[0:0] = ["E 导出配置", "V 二维码", "R 撤销客户端"]
        elif kind == "connection":
            actions[0:0] = ["E 编辑连接", "X 删除连接"]
            name = str(selected.get("name"))
            state = self.connection_states.get(name, "unknown")
            if state == "legacy":
                actions[0:0] = ["M 接管旧规则"]
            elif state == "connected":
                actions[0:0] = ["D 断开连接"]
            else:
                actions[0:0] = ["C 启用连接"]
        action_bar.update("  ".join(actions))

    def _selected(self, kind: str | None = None) -> dict[str, Any] | None:
        value = self.row_values.get(self.selected_key or "")
        if value is None or (kind is not None and value.get("kind") != kind):
            return None
        return value

    def action_close(self) -> None:
        self.dismiss(None)

    def _next_interface_name(self) -> str:
        names = {
            str(item.get("name"))
            for item in self.service.spec["wireguard"].get("interfaces", [])
            if isinstance(item, dict)
        }
        index = 0
        while f"wg{index}" in names:
            index += 1
        return f"wg{index}"

    def _new_server_defaults(self) -> dict[str, str]:
        interfaces = self.service.spec["wireguard"].get("interfaces", [])
        endpoint_host = "服务器公网IP或域名"
        ports: list[int] = []
        used_pools: set[str] = set()
        for item in interfaces:
            if not isinstance(item, dict):
                continue
            management = item.get("peerManagement")
            if not isinstance(management, dict):
                continue
            pool = management.get("addressPool")
            if pool:
                used_pools.add(str(pool))
            endpoint = str(management.get("publicEndpoint", ""))
            host, separator, port_value = endpoint.rpartition(":")
            if separator and host:
                endpoint_host = host
                try:
                    ports.append(int(port_value))
                except ValueError:
                    pass
        subnet = 20
        while f"10.{subnet}.0.0/24" in used_pools and subnet < 254:
            subnet += 1
        port = max(ports, default=51819) + 1
        if port > 65535:
            port = 51820
        return {
            "interface": self._next_interface_name(),
            "address_pool": f"10.{subnet}.0.0/24",
            "address": f"10.{subnet}.0.1",
            "listen_port": str(port),
            "public_endpoint": f"{endpoint_host}:{port}",
        }

    def action_new_server(self) -> None:
        active = self.query_one("#wg-groups", TabbedContent).active
        if active != "wg0-tab":
            return
        self.app.push_screen(
            CreateWireGuardServerScreen(self._new_server_defaults()),
            self._new_server_result,
        )

    def _new_server_result(self, result: dict[str, str] | None) -> None:
        if not result:
            return
        self.run_management(
            "create-server",
            result["interface"],
            result["address"],
            result["address_pool"],
            result["listen_port"],
            result["public_endpoint"],
            reload_rows=True,
            focus_after="#wg0-items",
        )

    def action_edit_or_export(self) -> None:
        selected = self._selected()
        if selected and selected.get("kind") == "interface":
            self.action_edit_server()
        elif selected and selected.get("kind") == "peer":
            self.action_export_peer()
        elif selected and selected.get("kind") == "connection":
            self.action_edit_connection()

    def action_edit_server(self) -> None:
        selected = self._selected("interface")
        if not selected or not isinstance(selected.get("peerManagement"), dict):
            return
        try:
            defaults = server_interface_settings(self.service, str(selected["name"]))
        except HomelabError as exc:
            self._write(f"[red]{escape(str(exc))}[/red]")
            return
        self.app.push_screen(
            CreateWireGuardServerScreen(defaults, editing=True),
            self._edit_server_result,
        )

    def _edit_server_result(self, result: dict[str, str] | None) -> None:
        if not result:
            return
        self.run_management(
            "edit-server",
            result["interface"],
            result["address"],
            result["address_pool"],
            result["listen_port"],
            result["public_endpoint"],
            reload_rows=True,
            focus_after="#wg0-items",
        )

    def action_delete_or_disconnect(self) -> None:
        selected = self._selected()
        if selected and selected.get("kind") == "interface":
            if selected.get("role") == "client":
                self.action_delete_client()
            else:
                self.action_delete_server()
        elif selected and selected.get("kind") == "connection":
            self.action_disconnect()

    def action_delete_server(self) -> None:
        selected = self._selected("interface")
        if not selected or not isinstance(selected.get("peerManagement"), dict):
            return
        name = str(selected["name"])
        self.app.push_screen(
            ConfirmActionScreen(
                "删除 WireGuard 服务端",
                f"将停止并从 NControl 移除 {name}。配置、密钥和客户端资料会移入归档目录。",
                "删除服务端",
            ),
            lambda confirmed: self.run_management(
                "delete-server",
                name,
                reload_rows=True,
                focus_after="#wg0-items",
            ) if confirmed else None,
        )

    def action_delete_client(self) -> None:
        selected = self._selected("interface")
        if not selected or selected.get("role") != "client":
            return
        name = str(selected["name"])
        self.app.push_screen(
            ConfirmActionScreen(
                "删除 WireGuard 客户端",
                f"将停止并从 NControl 移除 {name}。客户端配置会移入归档目录；如果仍被网络连接引用，删除会被阻止。",
                "删除客户端",
            ),
            lambda confirmed: self.run_management(
                "delete-client",
                name,
                reload_rows=True,
                focus_after="#wg1-items",
            ) if confirmed else None,
        )

    def action_connect_selected(self) -> None:
        selected = self._selected()
        if selected and selected.get("kind") == "interface":
            if not isinstance(selected.get("peerManagement"), dict):
                return
            name = str(selected["name"])
            if self.interface_states.get(name) == "connected":
                self._write(f"[yellow]服务端 {escape(name)} 已经连接。[/yellow]")
                return
            self.run_management("start-interface", name)
        elif selected and selected.get("kind") == "connection":
            self.action_connect()

    def action_sync_interface(self) -> None:
        selected = self._selected("interface")
        if not selected or not isinstance(selected.get("peerManagement"), dict):
            return
        name = str(selected["name"])
        if self.interface_states.get(name) != "connected":
            self._write(f"[yellow]服务端 {escape(name)} 尚未连接，不能同步配置。[/yellow]")
            return
        self.run_management("sync-interface", name)

    def action_disconnect_or_delete_connection(self) -> None:
        selected = self._selected()
        if selected and selected.get("kind") == "interface":
            self.action_disconnect_interface()
        elif selected and selected.get("kind") == "connection":
            self.action_delete_connection()

    def action_disconnect_interface(self) -> None:
        selected = self._selected("interface")
        if not selected or not isinstance(selected.get("peerManagement"), dict):
            return
        name = str(selected["name"])
        if self.interface_states.get(name) == "disconnected":
            self._write(f"[yellow]服务端 {escape(name)} 已经断开。[/yellow]")
            return
        self.app.push_screen(
            ConfirmActionScreen(
                "断开 WireGuard 服务端",
                f"将停止 {name}，已连接的客户端会立即断开；配置和客户端资料会保留。",
                "断开服务端",
            ),
            lambda confirmed: self.run_management("stop-interface", name) if confirmed else None,
        )

    def action_add_selected(self) -> None:
        active = self.query_one("#wg-groups", TabbedContent).active
        if active == "connections-tab":
            self.action_add_connection()
        elif active == "wg0-tab":
            self.action_add_peer()

    def _interface_names(self) -> list[str]:
        return [
            str(item["name"])
            for item in self.service.spec["wireguard"].get("interfaces", [])
            if isinstance(item, dict) and item.get("name")
        ]

    def _suggest_source_network(self, interface_name: str) -> str:
        interface = next(
            (
                item
                for item in self.service.spec["wireguard"].get("interfaces", [])
                if isinstance(item, dict) and item.get("name") == interface_name
            ),
            {},
        )
        management = interface.get("peerManagement")
        if isinstance(management, dict) and management.get("addressPool"):
            return str(management["addressPool"])
        try:
            networks = interface_peer_networks(self.service, interface_name)
            if networks:
                return str(networks[0])
        except HomelabError:
            pass
        return ""

    def _suggest_target_networks(self, interface_name: str) -> str:
        interface = next(
            (
                item
                for item in self.service.spec["wireguard"].get("interfaces", [])
                if isinstance(item, dict) and item.get("name") == interface_name
            ),
            {},
        )
        management = interface.get("peerManagement")
        if isinstance(management, dict) and management.get("addressPool"):
            return str(management["addressPool"])
        try:
            return ", ".join(interface_peer_networks(self.service, interface_name))
        except HomelabError:
            return ""

    def _new_connection_defaults(self) -> dict[str, str]:
        names = self._interface_names()
        source = names[0] if names else ""
        target = names[1] if len(names) > 1 else source
        existing = {
            str(item.get("name"))
            for item in self.service.spec["wireguard"].get("connections", [])
            if isinstance(item, dict)
        }
        base = f"{source}-to-{target}" if source and target else "new-connection"
        name = base
        suffix = 2
        while name in existing:
            name = f"{base}-{suffix}"
            suffix += 1
        return {
            "name": name,
            "source": source,
            "target": target,
            "source_network": self._suggest_source_network(source) if source else "",
            "destination_networks": self._suggest_target_networks(target) if target else "",
            "allow_return": "true",
            "auto_connect": "false",
        }

    def action_add_connection(self) -> None:
        names = self._interface_names()
        if len(names) < 2:
            self._write("[yellow]至少需要两个 WireGuard 接口才能添加网络连接。[/yellow]")
            return
        self.app.push_screen(
            WireGuardConnectionScreen(names, self._new_connection_defaults()),
            self._add_connection_result,
        )

    def _add_connection_result(self, result: dict[str, str] | None) -> None:
        if not result:
            return
        self.run_management(
            "add-connection",
            result["name"],
            result["source"],
            result["target"],
            result["source_network"],
            result["destination_networks"],
            result["allow_return"],
            result["auto_connect"],
            reload_rows=True,
            focus_after="#wg-connections",
        )

    def action_edit_connection(self) -> None:
        selected = self._selected("connection")
        if not selected:
            return
        defaults = {
            "name": str(selected["name"]),
            "source": str(selected["from"]),
            "target": str(selected["to"]),
            "source_network": str(selected["sourceNetwork"]),
            "destination_networks": ", ".join(
                str(value) for value in selected.get("destinationNetworks", [])
            ) or self._suggest_target_networks(str(selected["to"])),
            "allow_return": "true" if selected.get("allowReturnTraffic", True) else "false",
            "auto_connect": "true" if selected.get("autoConnect", False) else "false",
        }
        self.app.push_screen(
            WireGuardConnectionScreen(
                self._interface_names(), defaults, editing=True
            ),
            self._edit_connection_result,
        )

    def _edit_connection_result(self, result: dict[str, str] | None) -> None:
        if not result:
            return
        self.run_management(
            "edit-connection",
            result["name"],
            result["source"],
            result["target"],
            result["source_network"],
            result["destination_networks"],
            result["allow_return"],
            result["auto_connect"],
            reload_rows=True,
            focus_after="#wg-connections",
        )

    def action_delete_connection(self) -> None:
        selected = self._selected("connection")
        if not selected:
            return
        name = str(selected["name"])
        self.app.push_screen(
            ConfirmActionScreen(
                "删除网络连接",
                f"将移除 {selected['from']} → {selected['to']} 的规则和连接定义；接口本身不会停止。",
                "删除连接",
            ),
            lambda confirmed: self.run_management(
                "delete-connection",
                name,
                reload_rows=True,
                focus_after="#wg-connections",
            ) if confirmed else None,
        )

    def action_connect_server(self) -> None:
        active = self.query_one("#wg-groups", TabbedContent).active
        if active != "wg1-tab":
            return
        self.app.push_screen(
            ConnectWireGuardServerScreen(self._next_interface_name()),
            self._connect_server_result,
        )

    def _connect_server_result(self, result: dict[str, str] | None) -> None:
        if not result:
            return
        self.run_management(
            "import-client",
            result["interface"],
            result["source_config"],
            reload_rows=True,
            focus_after="#wg1-items",
        )

    def action_add_peer(self) -> None:
        interfaces = self.service.spec["wireguard"].get("interfaces", [])
        available = [
            item for item in interfaces
            if isinstance(item, dict) and isinstance(item.get("peerManagement"), dict)
        ]
        if not available:
            self._write("[yellow]没有已启用客户端管理的服务端接口。[/yellow]")
            return
        self.app.push_screen(AddWireGuardPeerScreen(self.service), self._add_peer_result)

    def _add_peer_result(self, result: dict[str, str] | None) -> None:
        if not result:
            return
        arguments = [result["interface"], result["name"]]
        if result["address"]:
            arguments.extend(["--address", result["address"]])
        if result["profile"]:
            arguments.extend(["--profile", result["profile"]])
        self.run_management("add-peer", *arguments, reload_rows=True)

    def action_import_peers(self) -> None:
        selected = self._selected("interface")
        if not selected or not isinstance(selected.get("peerManagement"), dict):
            self._write("[yellow]请先选中已启用客户端管理的服务端接口。[/yellow]")
            return
        self.run_management("import-peers", str(selected["name"]), reload_rows=True)

    def action_connect(self) -> None:
        selected = self._selected("connection")
        if not selected:
            self._write("[yellow]请先选中一条网络连接。[/yellow]")
            return
        name = str(selected["name"])
        state = self.connection_states.get(name, "unknown")
        if state == "connected":
            self._write("[yellow]这条网络连接已经生效。[/yellow]")
            return
        if state == "legacy":
            self._write("[yellow]检测到旧规则，请先按 M 接管。[/yellow]")
            return
        self.app.push_screen(
            ConfirmActionScreen(
                "启用网络连接",
                f"将添加 {selected['from']} → {selected['to']} 的转发和 NAT 规则。",
                "启用连接",
            ),
            lambda confirmed: self.run_management("connect", name) if confirmed else None,
        )

    def action_disconnect(self) -> None:
        selected = self._selected("connection")
        if not selected:
            self._write("[yellow]请先选中一条网络连接。[/yellow]")
            return
        name = str(selected["name"])
        if self.connection_states.get(name) != "connected":
            self._write("[yellow]当前连接没有可断开的 NControl 规则。[/yellow]")
            return
        self.app.push_screen(
            ConfirmActionScreen(
                "断开网络连接",
                f"将删除 {selected['from']} → {selected['to']} 的 NControl 转发规则。",
                "断开连接",
            ),
            lambda confirmed: self.run_management("disconnect", name) if confirmed else None,
        )

    def action_adopt_connection(self) -> None:
        selected = self._selected("connection")
        if not selected:
            self._write("[yellow]请先选中一条网络连接。[/yellow]")
            return
        name = str(selected["name"])
        if self.connection_states.get(name) != "legacy":
            self._write("[yellow]当前没有待接管的旧规则。[/yellow]")
            return
        self.app.push_screen(
            ConfirmActionScreen(
                "接管旧网络规则",
                "NControl 将先添加带标记的等价规则，再移除完全匹配的旧规则。",
                "接管规则",
            ),
            lambda confirmed: self.run_management("adopt-connection", name) if confirmed else None,
        )

    def action_export_peer(self) -> None:
        selected = self._selected("peer")
        if not selected:
            self._write("[yellow]请先选中一个可管理客户端。[/yellow]")
            return
        self.run_management("export-peer", str(selected["interface"]), str(selected["id"]))

    def action_peer_qr(self) -> None:
        selected = self._selected("peer")
        if not selected:
            self._write("[yellow]请先选中一个可管理客户端。[/yellow]")
            return
        try:
            qr_text = peer_qr_text(
                self.service,
                str(selected["interface"]),
                str(selected["id"]),
            )
        except HomelabError as exc:
            self._write(f"[red]{escape(str(exc))}[/red]")
            return
        self.app.push_screen(WireGuardQrScreen(str(selected.get("name")), qr_text))

    def action_remove_peer(self) -> None:
        selected = self._selected("peer")
        if not selected:
            self._write("[yellow]请先选中一个可管理客户端。[/yellow]")
            return
        if not selected.get("managed"):
            self._write("[yellow]从旧配置导入的客户端是只读的，不会被 NControl 删除。[/yellow]")
            return
        self.app.push_screen(
            ConfirmActionScreen(
                "撤销 WireGuard 客户端",
                f"客户端 {selected.get('name')} 将立即无法再连接。原配置会移入 revoked 目录。",
                "撤销客户端",
            ),
            lambda confirmed: self.run_management(
                "remove-peer",
                str(selected["interface"]),
                str(selected["id"]),
                reload_rows=True,
            ) if confirmed else None,
        )

    @work(exclusive=False, group="wg-management")
    async def run_management(
        self,
        operation: str,
        *arguments: str,
        reload_rows: bool = False,
        focus_after: str | None = None,
    ) -> None:
        self._write(f"[b cyan]正在执行 {escape(operation)}…[/b cyan]")
        try:
            driver = get_driver(self.service)
            plan = driver.management_plan(operation, *arguments)
            code, output = await self.app._run_plans([plan], timeout=30)
        except (UnsupportedOperation, HomelabError, OSError) as exc:
            self._write(f"[red]{escape(str(exc))}[/red]")
            return
        color = "green" if code == 0 else "red"
        if output:
            self._write(f"[{color}]{escape(output)}[/{color}]")
        if code != 0:
            self._write(f"[red]操作失败（退出码 {code}）。[/red]")
        if reload_rows and code == 0:
            self.service = load_service(self.service.path)
            self._reload_rows()
            if focus_after:
                self._focus_table(focus_after)
        self.refresh_interface_statuses()
        self.refresh_connection_statuses()

    @work(exclusive=True, group="wg-interface-status")
    async def refresh_interface_statuses(self) -> None:
        if not self.is_mounted:
            return
        table = self.query_one("#wg0-items", DataTable)
        for key, value in list(self.row_values.items()):
            if value.get("kind") != "interface" or value.get("role") != "server":
                continue
            name = str(value["name"])
            try:
                driver = get_driver(self.service)
                plan = driver.management_plan("interface-status", name)
                code, output = await self.app._run_plans([plan], timeout=12)
                if not self.is_mounted:
                    return
                if code == 0:
                    state = "connected"
                    status = Text("已连接", style="green")
                elif code == 3:
                    state = "disconnected"
                    status = Text("已断开", style="yellow")
                else:
                    state = "unknown"
                    label = "! 权限不足" if "免交互权限" in output else "! 不可用"
                    status = Text(label, style="red")
                self.interface_states[name] = state
                table.update_cell(
                    key,
                    "status",
                    status,
                )
                self._update_action_bar()
            except (UnsupportedOperation, HomelabError, OSError):
                self.interface_states[name] = "unknown"
                try:
                    table.update_cell(key, "status", Text("! 不可用", style="red"))
                    self._update_action_bar()
                except Exception:
                    return

    @staticmethod
    def _format_bytes(value: int) -> str:
        amount = float(max(0, value))
        for unit in ("B", "K", "M", "G", "T"):
            if amount < 1024 or unit == "T":
                if unit == "B":
                    return f"{int(amount)}{unit}"
                return f"{amount:.1f}{unit}"
            amount /= 1024
        return f"{amount:.1f}T"

    @classmethod
    def _format_total(cls, received: int, sent: int, *, directional: bool = False) -> str:
        left, right = ("←", "→") if directional else ("↓", "↑")
        return f"{left}{cls._format_bytes(received)} {right}{cls._format_bytes(sent)}"

    def _speed_text(
        self,
        key: str,
        sampled_at: float,
        received: int,
        sent: int,
        *,
        directional: bool = False,
    ) -> Text:
        previous = self._traffic_previous.get(key)
        self._traffic_previous[key] = (sampled_at, received, sent)
        if previous is None:
            return Text("采样中", style="dim")
        elapsed = sampled_at - previous[0]
        if elapsed <= 0:
            return Text("采样中", style="dim")
        received_delta = max(0, received - previous[1])
        sent_delta = max(0, sent - previous[2])
        received_rate = int(received_delta / elapsed)
        sent_rate = int(sent_delta / elapsed)
        if received_rate == 0 and sent_rate == 0:
            return Text("当前无传输", style="dim")
        left, right = ("←", "→") if directional else ("↓", "↑")
        return Text(
            f"{left}{self._format_bytes(received_rate)}/s "
            f"{right}{self._format_bytes(sent_rate)}/s",
            style="green",
        )

    @staticmethod
    def _handshake_text(latest: int, sampled_at: float) -> Text:
        if latest <= 0:
            return Text("未握手", style="yellow")
        age = max(0, int(sampled_at - latest))
        if age < 10:
            label = "刚刚握手"
        elif age < 60:
            label = f"{age}秒前握手"
        elif age < 3600:
            label = f"{age // 60}分钟前握手"
        elif age < 86400:
            label = f"{age // 3600}小时前握手"
        else:
            label = f"{age // 86400}天前握手"
        return Text(label, style="green" if age < 180 else "yellow")

    def _apply_traffic_snapshot(self, snapshot: dict[str, Any]) -> None:
        sampled_at = float(snapshot.get("sampledAt") or time.time())
        interface_stats = {
            str(item.get("name")): item
            for item in snapshot.get("interfaces", [])
            if isinstance(item, dict) and item.get("name")
        }
        server_table = self.query_one("#wg0-items", DataTable)
        client_table = self.query_one("#wg1-items", DataTable)
        connection_table = self.query_one("#wg-connections", DataTable)

        for row_key, value in list(self.row_values.items()):
            kind = value.get("kind")
            if kind == "interface":
                name = str(value.get("name"))
                stats = interface_stats.get(name)
                table = server_table if value.get("role") == "server" else client_table
                if not stats or not stats.get("running"):
                    table.update_cell(row_key, "speed", Text("已断开", style="dim"))
                    table.update_cell(row_key, "total", "-")
                    if value.get("role") == "client":
                        table.update_cell(row_key, "status", Text("已断开", style="yellow"))
                    continue
                received = int(stats.get("receivedBytes", 0))
                sent = int(stats.get("sentBytes", 0))
                table.update_cell(
                    row_key,
                    "speed",
                    self._speed_text(row_key, sampled_at, received, sent),
                )
                table.update_cell(row_key, "total", self._format_total(received, sent))
                if value.get("role") == "client":
                    table.update_cell(
                        row_key,
                        "status",
                        self._handshake_text(
                            int(stats.get("latestHandshake", 0)), sampled_at
                        ),
                    )
            elif kind == "peer":
                interface_name = str(value.get("interface"))
                stats = interface_stats.get(interface_name)
                peer = None
                if stats:
                    peer = next(
                        (
                            item
                            for item in stats.get("peers", [])
                            if item.get("publicKey") == value.get("publicKey")
                        ),
                        None,
                    )
                if not stats or not stats.get("running"):
                    server_table.update_cell(
                        row_key, "status", Text("接口已断开", style="yellow")
                    )
                    server_table.update_cell(row_key, "speed", "-")
                    server_table.update_cell(row_key, "total", "-")
                elif not peer:
                    server_table.update_cell(row_key, "status", Text("未加载", style="yellow"))
                else:
                    received = int(peer.get("receivedBytes", 0))
                    sent = int(peer.get("sentBytes", 0))
                    server_table.update_cell(
                        row_key,
                        "status",
                        self._handshake_text(
                            int(peer.get("latestHandshake", 0)), sampled_at
                        ),
                    )
                    server_table.update_cell(
                        row_key,
                        "speed",
                        self._speed_text(row_key, sampled_at, received, sent),
                    )
                    server_table.update_cell(
                        row_key, "total", self._format_total(received, sent)
                    )

        connection_stats = {
            str(item.get("name")): item
            for item in snapshot.get("connections", [])
            if isinstance(item, dict) and item.get("name")
        }
        for row_key, value in list(self.row_values.items()):
            if value.get("kind") != "connection":
                continue
            stats = connection_stats.get(str(value.get("name")))
            if not stats or not stats.get("available"):
                connection_table.update_cell(
                    row_key, "speed", Text("无活动规则", style="dim")
                )
                connection_table.update_cell(row_key, "total", "-")
                continue
            forward = int(stats.get("forwardBytes", 0))
            returned = int(stats.get("returnBytes", 0))
            connection_table.update_cell(
                row_key,
                "speed",
                self._speed_text(
                    row_key,
                    sampled_at,
                    returned,
                    forward,
                    directional=True,
                ),
            )
            connection_table.update_cell(
                row_key,
                "total",
                self._format_total(returned, forward, directional=True),
            )

    @work(exclusive=True, group="wg-traffic")
    async def refresh_traffic(self) -> None:
        if not self.is_mounted:
            return
        try:
            driver = get_driver(self.service)
            plan = driver.management_plan("traffic", "--json")
            code, output = await self.app._run_plans([plan], timeout=12)
            if not self.is_mounted:
                return
            if code != 0 or not output:
                return
            snapshot = json.loads(output)
            if isinstance(snapshot, dict):
                self._apply_traffic_snapshot(snapshot)
        except (
            UnsupportedOperation,
            HomelabError,
            OSError,
            ValueError,
            json.JSONDecodeError,
            NoMatches,
        ):
            return

    @work(exclusive=True, group="wg-status")
    async def refresh_connection_statuses(self) -> None:
        if not self.is_mounted:
            return
        table = self.query_one("#wg-connections", DataTable)
        for key, value in list(self.row_values.items()):
            if value.get("kind") != "connection":
                continue
            try:
                driver = get_driver(self.service)
                plan = driver.management_plan("connection-status", str(value["name"]))
                code, output = await self.app._run_plans([plan], timeout=12)
                if not self.is_mounted:
                    return
                if code == 0 and "旧规则" in output:
                    status = Text("待接管", style="yellow")
                    self.connection_states[str(value["name"])] = "legacy"
                else:
                    status = Text("已连接", style="green") if code == 0 else Text("未连接", style="yellow")
                    self.connection_states[str(value["name"])] = "connected" if code == 0 else "disconnected"
                table.update_cell(key, "status", status)
                self._update_action_bar()
            except (UnsupportedOperation, HomelabError, OSError):
                self.connection_states[str(value["name"])] = "unknown"
                try:
                    table.update_cell(key, "status", Text("! 不可用", style="red"))
                    self._update_action_bar()
                except Exception:
                    return


class MigrationScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("escape", "close", "返回", priority=True),
        Binding("q", "close", "返回", priority=True),
        Binding("r", "refresh", "重新检查"),
        Binding("h", "focus_host", "填写公网地址"),
        Binding("e", "apply_host", "更新公网地址"),
        Binding("w", "configure_wireguard", "配置 WireGuard 主机"),
        Binding("b", "install_boot", "注册开机入口"),
        Binding("s", "start_services", "启动自动服务"),
        Binding("a", "initialize", "一键初始化"),
        Binding("f", "finish", "完成迁移"),
    ]

    CSS = """
    MigrationScreen {
        layout: vertical;
        background: $surface;
    }
    MigrationScreen #migration-title {
        height: 3;
        padding: 1 2;
        background: $primary;
        color: $text;
        text-style: bold;
    }
    MigrationScreen #migration-note {
        height: 4;
        padding: 1 2;
        color: $text-muted;
    }
    MigrationScreen #migration-host {
        margin: 0 2 1 2;
    }
    MigrationScreen #migration-report {
        height: 1fr;
        margin: 0 2;
        border: round $accent;
        padding: 1;
    }
    MigrationScreen #migration-actions {
        height: 4;
        padding: 1 2;
        background: $panel;
        color: $text-muted;
    }
    """

    def __init__(self, root: Path) -> None:
        super().__init__()
        self.root_path = root.resolve()

    def compose(self) -> ComposeResult:
        yield Static("迁移初始化", id="migration-title")
        yield Static(
            "复制到新的 Debian 系 Linux 后在这里完成环境检查、WireGuard 主机配置、开机入口和服务启动。\n"
            "云安全组和外部设备地址仍需在对应平台修改。",
            id="migration-note",
        )
        yield Input(placeholder="新服务器公网 IP 或域名（留空则不修改）", id="migration-host")
        yield RichLog(id="migration-report", wrap=True, markup=True, highlight=True)
        yield Static(
            "A 一键初始化  E 更新公网地址  W 配置WireGuard主机  B 注册开机  "
            "S 启动服务  H 填写公网地址  R 检查  F 完成迁移  Esc/Q 返回",
            id="migration-actions",
        )

    def on_mount(self) -> None:
        hosts = wireguard_public_hosts(self.root_path)
        if hosts:
            self.query_one("#migration-host", Input).value = hosts[0]
        self.query_one("#migration-report", RichLog).focus()
        self.refresh_checks()

    def on_unmount(self) -> None:
        self.app.workers.cancel_node(self)

    def _write(self, message: str) -> None:
        self.query_one("#migration-report", RichLog).write(message)

    def action_close(self) -> None:
        self.dismiss(None)

    def action_refresh(self) -> None:
        self.refresh_checks()

    def action_focus_host(self) -> None:
        self.query_one("#migration-host", Input).focus()

    @on(Input.Submitted, "#migration-host")
    def on_public_host_submitted(self) -> None:
        self.action_apply_host()

    @work(exclusive=True, group="migration-check")
    async def refresh_checks(self) -> None:
        report = self.query_one("#migration-report", RichLog)
        report.clear()
        report.write("[b cyan]正在检查这台服务器…[/b cyan]")
        try:
            results = await asyncio.to_thread(migration_checks, self.root_path)
            boot_state = await asyncio.to_thread(boot_is_installed, self.root_path)
        except (HomelabError, OSError) as exc:
            report.write(f"[red]检查失败：{escape(str(exc))}[/red]")
            return
        if not self.is_mounted:
            return
        report.clear()
        for result in results:
            color = {"ok": "green", "warning": "yellow", "error": "red"}.get(
                result.level, "white"
            )
            mark = {"ok": "✓", "warning": "!", "error": "✗"}.get(result.level, "·")
            report.write(f"[{color}]{mark} {escape(result.message)}[/{color}]")
        report.write(
            "\n[green]✓ 开机入口已安装[/green]"
            if boot_state
            else "\n[yellow]! 开机入口尚未安装[/yellow]"
        )

    def action_apply_host(self) -> None:
        host = self.query_one("#migration-host", Input).value.strip()
        if not host:
            self._write("[yellow]请先填写新的公网 IP 或域名。[/yellow]")
            return
        self.app.push_screen(
            ConfirmActionScreen(
                "更新 WireGuard 公网入口",
                f"将服务端入口和本地客户端配置更新为 {host}。继续吗？",
                confirm_label="更新",
            ),
            lambda confirmed: self._apply_host_confirmed(confirmed, host),
        )

    def _apply_host_confirmed(self, confirmed: bool, host: str) -> None:
        if not confirmed:
            return
        try:
            services, clients = update_wireguard_public_host(self.root_path, host)
        except (HomelabError, OSError) as exc:
            self._write(f"[red]公网入口更新失败：{escape(str(exc))}[/red]")
            return
        self._write(
            f"[green]已更新 {services} 个 WireGuard 服务和 {clients} 份客户端配置。[/green]"
        )
        if clients:
            self._write("[yellow]已部署的客户端需要重新扫码或重新导入配置。[/yellow]")
        self.refresh_checks()

    def action_configure_wireguard(self) -> None:
        self.app.push_screen(
            ConfirmActionScreen(
                "配置 WireGuard 主机",
                "将开启并持久化 IPv4 转发，同时安装限定范围的免交互 sudo 权限。继续吗？",
                confirm_label="配置",
            ),
            self._configure_wireguard_confirmed,
        )

    def _configure_wireguard_confirmed(self, confirmed: bool) -> None:
        if not confirmed:
            return
        try:
            with self.app.suspend():
                message = configure_wireguard_host()
        except (HomelabError, OSError) as exc:
            self._write(f"[red]WireGuard 主机配置失败：{escape(str(exc))}[/red]")
            return
        self._write(f"[green]{escape(message)}[/green]")
        self.refresh_checks()

    def action_install_boot(self) -> None:
        try:
            message = install_boot(self.root_path)
        except (HomelabError, OSError) as exc:
            self._write(f"[red]开机入口安装失败：{escape(str(exc))}[/red]")
            return
        self._write(f"[green]{escape(message)}[/green]")
        self.refresh_checks()

    def action_start_services(self) -> None:
        self.app.push_screen(
            ConfirmActionScreen(
                "启动自动服务",
                "将启动已启用开机启动但目前未运行的服务。继续吗？",
                confirm_label="启动",
            ),
            self._start_services_confirmed,
        )

    def _start_services_confirmed(self, confirmed: bool) -> None:
        if not confirmed:
            return
        try:
            with self.app.suspend():
                code = run_enabled(self.root_path)
        except (HomelabError, OSError) as exc:
            self._write(f"[red]服务启动失败：{escape(str(exc))}[/red]")
            return
        color = "green" if code == 0 else "red"
        self._write(f"[{color}]自动服务启动流程完成（结果 {code}）。[/{color}]")
        self.refresh_checks()

    def action_initialize(self) -> None:
        self.app.push_screen(
            ConfirmActionScreen(
                "一键初始化新服务器",
                "将更新填写的公网入口、配置 WireGuard 主机、注册开机入口并启动自动服务。继续吗？",
                confirm_label="初始化",
            ),
            self._initialize_confirmed,
        )

    def _initialize_confirmed(self, confirmed: bool) -> None:
        if not confirmed:
            return
        host = self.query_one("#migration-host", Input).value.strip()
        try:
            if host:
                update_wireguard_public_host(self.root_path, host)
            with self.app.suspend():
                configure_wireguard_host()
                print(install_boot(self.root_path))
                results = migration_checks(self.root_path)
                errors = [result for result in results if result.level == "error"]
                if errors:
                    print("初始化检查仍有错误，未启动服务：")
                    for result in errors:
                        print(f"- {result.message}")
                    code = 1
                else:
                    code = run_enabled(self.root_path)
            if code != 0:
                self._write("[red]初始化尚未完成，请根据检查结果修复错误。[/red]")
                self.refresh_checks()
                return
            record_machine(self.root_path)
        except (HomelabError, OSError) as exc:
            self._write(f"[red]初始化失败：{escape(str(exc))}[/red]")
            return
        self._write("[green]新服务器初始化完成。[/green]")
        self.refresh_checks()

    def action_finish(self) -> None:
        try:
            results = migration_checks(self.root_path)
        except (HomelabError, OSError) as exc:
            self._write(f"[red]检查失败：{escape(str(exc))}[/red]")
            return
        errors = [result for result in results if result.level == "error"]
        if errors:
            self._write("[red]仍有错误，暂不能标记为迁移完成。[/red]")
            for result in errors:
                self._write(f"[red]✗ {escape(result.message)}[/red]")
            return
        record_machine(self.root_path)
        self._write("[green]已标记这台服务器完成迁移初始化。[/green]")


class StopConfirmScreen(ModalScreen[str | None]):
    BINDINGS = [
        Binding("escape", "cancel", "取消"),
        Binding("left", "focus_cancel", "选择取消", show=False),
        Binding("up", "focus_cancel", "选择取消", show=False),
        Binding("right", "focus_confirm", "选择停止", show=False),
        Binding("down", "focus_confirm", "选择停止", show=False),
        Binding("tab", "toggle_choice", "切换选项", show=False),
        Binding("shift+tab", "toggle_choice", "切换选项", show=False),
    ]

    CSS = """
    StopConfirmScreen {
        align: center middle;
        background: $background 70%;
    }

    StopConfirmScreen > Grid {
        width: 58;
        height: 11;
        grid-size: 2 3;
        grid-rows: 1fr 2 3;
        padding: 1 2;
        border: thick $error;
        background: $surface;
    }

    StopConfirmScreen Label {
        column-span: 2;
        content-align: center middle;
    }

    StopConfirmScreen #stop-title {
        text-style: bold;
        color: $error;
    }

    StopConfirmScreen Button {
        width: 100%;
    }
    """

    def __init__(self, service_name: str) -> None:
        super().__init__()
        self.service_name = service_name

    def compose(self) -> ComposeResult:
        with Grid():
            yield Label("确认停止服务", id="stop-title")
            yield Label(
                f"即将停止 {self.service_name}，是否继续？\n"
                "←/→ 或 Tab 选择，Enter 确认，Esc 取消"
            )
            yield Button("取消", variant="primary", id="cancel")
            yield Button("停止", variant="error", id="confirm")

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(self.service_name if event.button.id == "confirm" else None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_focus_cancel(self) -> None:
        self.query_one("#cancel", Button).focus()

    def action_focus_confirm(self) -> None:
        self.query_one("#confirm", Button).focus()

    def action_toggle_choice(self) -> None:
        cancel = self.query_one("#cancel", Button)
        confirm = self.query_one("#confirm", Button)
        (cancel if confirm.has_focus else confirm).focus()


class NControlApp(App[None]):
    TITLE = "NControl"
    SUB_TITLE = "个人服务器服务管理器"

    CSS = """
    Screen {
        layout: vertical;
    }

    #body {
        height: 1fr;
    }

    #services {
        width: 62%;
        min-width: 64;
        border: round $primary;
    }

    #right-pane {
        width: 1fr;
    }

    #detail {
        height: 44%;
        min-height: 12;
        border: round $accent;
        padding: 1 2;
        overflow-y: auto;
    }

    #output {
        height: 1fr;
        border: round $secondary;
        padding: 0 1;
    }

    DataTable > .datatable--cursor {
        background: $accent 35%;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "退出"),
        Binding("r", "refresh", "刷新状态"),
        Binding("s", "start_service", "启动服务"),
        Binding("x", "stop_service", "停止服务"),
        Binding("enter", "details", "服务详情"),
        Binding("l", "logs", "刷新日志"),
        Binding("k", "clear_logs", "清空日志"),
        Binding("c", "check_config", "配置检查"),
        Binding("d", "doctor", "系统检查"),
        Binding("a", "toggle_autostart", "切换开机启动"),
        Binding("m", "migration", "迁移初始化"),
        Binding("u", "update", "更新管理器"),
        Binding("w", "wireguard", "WireGuard 管理"),
        Binding("tab", "wireguard_tab_next", "下一个区域", show=False),
        Binding("ctrl+i", "wireguard_tab_next", "下一个区域", show=False),
        Binding("shift+tab", "wireguard_tab_previous", "上一个区域", show=False, priority=True),
    ]

    def __init__(
        self,
        root: Path,
        *,
        auto_refresh: bool = True,
        refresh_seconds: float = 15.0,
        open_migration: bool = False,
    ) -> None:
        super().__init__()
        self.root_path = root.resolve()
        self.services: list[ServiceDefinition] = []
        self.services_by_name: dict[str, ServiceDefinition] = {}
        self.selected_name: str | None = None
        self.health_results: dict[str, dict[str, Any]] = {}
        self.periodic_status_refresh = auto_refresh
        self.refresh_seconds = refresh_seconds
        self.open_migration = open_migration

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            yield DataTable(id="services", cursor_type="row", zebra_stripes=True)
            with Vertical(id="right-pane"):
                yield Static("正在读取服务…", id="detail", markup=True)
                yield RichLog(id="output", wrap=True, markup=True, highlight=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#services", DataTable)
        self.query_one("#output", RichLog).border_title = "当前服务日志"
        table.add_column("服务", key="name", width=16)
        table.add_column("状态", key="status", width=16)
        table.add_column("驱动", key="driver", width=10)
        table.add_column("开机", key="autostart", width=8)
        self._reload_services()
        if self.periodic_status_refresh:
            self.refresh_statuses()
            self.set_interval(self.refresh_seconds, self.refresh_statuses)
            self.set_interval(self.refresh_seconds, self.refresh_selected_logs)
        if self.open_migration:
            self.call_after_refresh(self.action_migration)

    def on_key(self, event: Key) -> None:
        screen = self.screen
        if isinstance(screen, WireGuardManagerScreen):
            if event.key in ("tab", "ctrl+i"):
                event.stop()
                screen.action_focus_next_table()
            elif event.key == "shift+tab":
                event.stop()
                screen.action_focus_previous_table()

    def action_focus_next(self) -> None:
        if isinstance(self.screen, WireGuardManagerScreen):
            self.screen.action_focus_next_table()
            return
        super().action_focus_next()

    def action_focus_previous(self) -> None:
        if isinstance(self.screen, WireGuardManagerScreen):
            self.screen.action_focus_previous_table()
            return
        super().action_focus_previous()

    def action_wireguard_tab_next(self) -> None:
        if isinstance(self.screen, WireGuardManagerScreen):
            self.screen.action_focus_next_table()
            return
        super().action_focus_next()

    def action_wireguard_tab_previous(self) -> None:
        if isinstance(self.screen, WireGuardManagerScreen):
            self.screen.action_focus_previous_table()
            return
        super().action_focus_previous()

    def _reload_services(self) -> None:
        table = self.query_one("#services", DataTable)
        table.clear()
        try:
            self.services = load_all(self.root_path)
        except HomelabError as exc:
            self.services = []
            self.services_by_name = {}
            self._write(f"[red]读取服务失败：{escape(str(exc))}[/red]")
            return

        self.services_by_name = {service.name: service for service in self.services}
        for service in self.services:
            autostart = Text("● 自动", style="green") if service.autostart else Text("○ 手动", style="dim")
            table.add_row(
                service.name,
                Text("等待检查", style="dim"),
                service.driver,
                autostart,
                key=service.name,
            )

        if self.services:
            self.selected_name = self.services[0].name
            table.move_cursor(row=0)
            self._render_details(self.services[0])
            if not self.open_migration:
                self._show_log_loading(self.services[0])
                self.load_logs(self.services[0])
        else:
            self.selected_name = None
            self.query_one("#detail", Static).update(
                f"[yellow]未发现服务[/yellow]\n{escape(str(services_directory(self.root_path)))}"
            )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        value = event.row_key.value
        if isinstance(value, str) and value in self.services_by_name:
            changed = value != self.selected_name
            self.selected_name = value
            service = self.services_by_name[value]
            self._render_details(service)
            if changed:
                self._show_log_loading(service)
                self.load_logs(service)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        value = event.row_key.value
        if isinstance(value, str) and value in self.services_by_name:
            changed = value != self.selected_name
            self.selected_name = value
            service = self.services_by_name[value]
            self._render_details(service)
            if changed:
                self._show_log_loading(service)
                self.load_logs(service)

    def _selected_service(self) -> ServiceDefinition | None:
        if self.selected_name is None:
            return None
        return self.services_by_name.get(self.selected_name)

    def _render_details(self, service: ServiceDefinition) -> None:
        lines = [
            f"[b cyan]{escape(service.name)}[/b cyan]",
            f"{escape(service.description)}",
            "",
            f"驱动        [b]{escape(service.driver)}[/b]",
            f"开机启动    {'[green]已启用[/green]' if service.autostart else '[dim]未启用[/dim]'}",
            f"定义文件    {escape(str(service.path))}",
            f"工作目录    {escape(str(service.working_directory))}",
        ]

        adoption_path = service.directory / "adoption.yaml"
        if adoption_path.exists():
            try:
                adoption = yaml.safe_load(adoption_path.read_text(encoding="utf-8")) or {}
                if isinstance(adoption, dict):
                    ports = adoption.get("ports")
                    if isinstance(ports, list):
                        lines.append(f"端口        {escape(', '.join(map(str, ports)))}")
                    completed = adoption.get("cutoverCompleted")
                    if completed is not None:
                        state = "已完成" if completed else "尚未切换"
                        lines.append(f"运行切换    {state}")
            except (OSError, yaml.YAMLError) as exc:
                lines.append(f"[red]接管信息读取失败：{escape(str(exc))}[/red]")

        health = self.health_results.get(service.name)
        if health:
            state_labels = {
                "healthy": "[green]正常[/green]",
                "starting": "[yellow]启动中[/yellow]",
                "unhealthy": "[red]异常[/red]",
                "stopped": "[dim]已停止[/dim]",
            }
            lines.extend(
                [
                    "",
                    f"健康状态    {state_labels.get(str(health.get('state')), '[red]未知[/red]')}",
                    f"状态说明    {escape(str(health.get('summary', '')))}",
                ]
            )
            for item in health.get("checks", []):
                if isinstance(item, dict):
                    mark = "[green]✓[/green]" if item.get("ok") else "[red]✗[/red]"
                    lines.append(
                        f"{mark} {escape(str(item.get('name', '检查')))}    "
                        f"{escape(str(item.get('detail', '')))}"
                    )
        if service.driver == "wireguard":
            interfaces = service.spec.get("wireguard", {}).get("interfaces", [])
            if isinstance(interfaces, list) and interfaces:
                lines.extend(["", "[b]WireGuard 接口[/b]"])
                role_names = {"server": "服务端", "client": "客户端"}
                for interface in interfaces:
                    if isinstance(interface, dict):
                        name = escape(str(interface.get("name", "?")))
                        try:
                            address = interface_addresses(service, str(interface.get("name", "?")))
                        except HomelabError:
                            address = "地址未读取"
                        role = role_names.get(
                            str(interface.get("role")), str(interface.get("role", "?"))
                        )
                        lines.append(f"{name}        {escape(address)}        {escape(role)}")
                connections = service.spec.get("wireguard", {}).get("connections", [])
                if isinstance(connections, list) and connections:
                    lines.extend(["", "[b]网络连接[/b]"])
                    for connection in connections:
                        if isinstance(connection, dict):
                            source_name = str(connection.get("from", "?"))
                            target_name = str(connection.get("to", "?"))
                            try:
                                source_address = interface_addresses(service, source_name)
                            except HomelabError:
                                source_address = "地址未知"
                            try:
                                target_address = interface_addresses(service, target_name)
                            except HomelabError:
                                target_address = "地址未知"
                            lines.append(
                                f"{escape(str(connection.get('name', '?')))}        "
                                f"{escape(source_name)} ({escape(source_address)}) → "
                                f"{escape(target_name)} ({escape(target_address)})        "
                                f"转发 {escape(str(connection.get('sourceNetwork', '?')))}"
                            )
                lines.extend(["", "[cyan]按 W 打开 WireGuard 客户端与网络连接管理。[/cyan]"])
        self.query_one("#detail", Static).update("\n".join(lines))

    def _write(self, message: str) -> None:
        self.query_one("#output", RichLog).write(message)

    def _show_log_loading(self, service: ServiceDefinition) -> None:
        output = self.query_one("#output", RichLog)
        output.border_title = f"{service.name} · 最近日志"
        output.clear()
        output.write(f"[dim]正在读取 {escape(service.name)} 日志…[/dim]")

    def _replace_service_logs(
        self,
        service: ServiceDefinition,
        message: str,
        *,
        color: str = "white",
    ) -> None:
        if service.name != self.selected_name:
            return
        output = self.query_one("#output", RichLog)
        output.border_title = f"{service.name} · 最近日志"
        output.clear()
        output.write(f"[{color}]{escape(message)}[/{color}]")

    def action_details(self) -> None:
        service = self._selected_service()
        if service:
            self._render_details(service)

    def action_refresh(self) -> None:
        self._reload_services()
        self.refresh_statuses()

    def action_check_config(self) -> None:
        service = self._selected_service()
        if not service:
            return
        try:
            driver = get_driver(service)
            values = list(dict.fromkeys(driver.config_values()))
            results = check_config_paths(service, values)
        except HomelabError as exc:
            self._write(f"[red]{escape(service.name)}：{escape(str(exc))}[/red]")
            return
        self._write(f"[b]{escape(service.name)} 配置检查[/b]")
        if not results:
            self._write("[green]未声明配置文件[/green]")
        for result in results:
            color = {"ok": "green", "warning": "yellow", "error": "red"}.get(
                result.level, "white"
            )
            self._write(f"[{color}]{escape(result.level.upper())}  {escape(result.message)}[/{color}]")

    def action_doctor(self) -> None:
        self._write("[b cyan]系统冲突检查[/b cyan]")
        try:
            results = audit_services(self.root_path)
        except (HomelabError, OSError) as exc:
            self._write(f"[red]{escape(str(exc))}[/red]")
            return
        for result in results:
            color = {"ok": "green", "warning": "yellow", "error": "red"}.get(
                result.level, "white"
            )
            self._write(f"[{color}]{escape(result.level.upper())}  {escape(result.message)}[/{color}]")

    def action_toggle_autostart(self) -> None:
        service = self._selected_service()
        if not service:
            return
        enabled = not service.autostart
        try:
            set_service_autostart(self.root_path, service.name, enabled)
            updated = load_service(service.path)
        except (HomelabError, OSError) as exc:
            self._write(f"[red]更新开机启动失败：{escape(str(exc))}[/red]")
            return
        self._remember_service(updated)
        label = Text("● 自动", style="green") if enabled else Text("○ 手动", style="dim")
        self.query_one("#services", DataTable).update_cell(service.name, "autostart", label)
        self._render_details(updated)
        self._write(
            f"[green]{escape(service.name)} 已{'启用' if enabled else '关闭'}开机启动。[/green]"
        )

    def action_migration(self) -> None:
        if isinstance(self.screen, MigrationScreen):
            return
        self.push_screen(MigrationScreen(self.root_path), self._migration_closed)

    def _migration_closed(self, _: None) -> None:
        service = self._selected_service()
        if service:
            self._show_log_loading(service)
            self.load_logs(service)

    def action_update(self) -> None:
        self.check_code_update()

    @work(exclusive=True, group="code-update")
    async def check_code_update(self) -> None:
        self._write("[b cyan]正在检查 NControl 更新…[/b cyan]")
        try:
            info = await asyncio.to_thread(check_for_updates, self.root_path)
        except (HomelabError, OSError) as exc:
            self._write(f"[red]检查更新失败：{escape(str(exc))}[/red]")
            return
        if info.state == "available":
            self._write(
                f"[green]{escape(info.detail)}：{info.current[:12]} → {info.target[:12]}[/green]"
            )
            self.push_screen(
                ConfirmActionScreen(
                    "更新 NControl 管理器",
                    f"将从 GitHub 安装 {info.behind} 个新提交。只更新公共代码，local/ 中的服务、配置、密钥和数据不会被修改。",
                    "安装更新",
                ),
                self._update_confirmed,
            )
            return
        color = "green" if info.state == "current" else "yellow"
        self._write(f"[{color}]{escape(info.detail)}[/{color}]")

    def _update_confirmed(self, confirmed: bool) -> None:
        if confirmed:
            self.install_code_update()

    @work(exclusive=True, group="code-update")
    async def install_code_update(self) -> None:
        self._write("[b cyan]正在更新 NControl 公共代码…[/b cyan]")
        try:
            info: UpdateInfo = await asyncio.to_thread(apply_update, self.root_path)
        except (HomelabError, OSError) as exc:
            self._write(f"[red]更新失败：{escape(str(exc))}[/red]")
            return
        self._write(
            f"[green]{escape(info.detail)}（{info.current[:12]} → {info.target[:12]}）[/green]"
        )
        self._write("[yellow]请按 Q 退出后重新运行 ./ncontrol，使新版本完全生效。[/yellow]")

    def action_logs(self) -> None:
        service = self._selected_service()
        if service:
            self._show_log_loading(service)
            self.load_logs(service)

    def refresh_selected_logs(self) -> None:
        service = self._selected_service()
        if service:
            self.load_logs(service)

    def action_clear_logs(self) -> None:
        service = self._selected_service()
        if service is None:
            return
        try:
            get_driver(service).clear_log_plans()
        except UnsupportedOperation as exc:
            self.notify(str(exc), severity="warning")
            return
        self.push_screen(
            ConfirmActionScreen(
                "清空服务日志",
                f"将清空 {service.name} 的已有日志，此操作无法撤销。",
                "清空日志",
            ),
            self._clear_logs_confirmed,
        )

    def _clear_logs_confirmed(self, confirmed: bool) -> None:
        if not confirmed:
            return
        service = self._selected_service()
        if service:
            self.clear_service_logs(service)

    def action_wireguard(self) -> None:
        service = self._selected_service()
        if not service or service.driver != "wireguard":
            self._write("[yellow]请先选中 WireGuard 服务。[/yellow]")
            return
        try:
            service = load_service(service.path)
        except (HomelabError, OSError) as exc:
            self._write(f"[red]重新读取 WireGuard 配置失败：{escape(str(exc))}[/red]")
            return
        self._remember_service(service)
        self.push_screen(WireGuardManagerScreen(service), self._wireguard_closed)

    def _remember_service(self, service: ServiceDefinition) -> None:
        self.services_by_name[service.name] = service
        self.services = [
            service if item.name == service.name else item for item in self.services
        ]

    def _wireguard_closed(self, _: None) -> None:
        service = self.services_by_name.get(self.selected_name or "")
        if service is None:
            return
        try:
            service = load_service(service.path)
        except (HomelabError, OSError):
            return
        self._remember_service(service)
        self._render_details(service)
        self.refresh_statuses()

    def action_start_service(self) -> None:
        service = self._selected_service()
        if not service:
            return
        self.run_operation(service, "start")

    def action_stop_service(self) -> None:
        service = self._selected_service()
        if not service:
            return
        self.push_screen(StopConfirmScreen(service.name), self._stop_confirmed)

    def _stop_confirmed(self, service_name: str | None) -> None:
        if service_name is None:
            return
        service = self.services_by_name.get(service_name)
        if service is not None:
            self.run_operation(service, "stop")

    @work(exclusive=True, group="operation")
    async def run_operation(self, service: ServiceDefinition, operation: str) -> None:
        operation_name = {"start": "启动", "stop": "停止"}.get(operation, operation)
        self._write(
            f"[b cyan]正在{operation_name} {escape(service.name)}…[/b cyan]"
        )
        try:
            plans = get_driver(service).plans(operation)
            code, output = await self._run_plans(plans, timeout=30)
        except (UnsupportedOperation, HomelabError, OSError) as exc:
            self._write(f"[red]{escape(str(exc))}[/red]")
            return
        if code == 0:
            self._write(
                f"[green]{escape(service.name)} {operation_name}成功。[/green]"
            )
        else:
            self._write(
                f"[red]{escape(service.name)} {operation_name}失败（退出码 {code}）。[/red]"
            )
        if output:
            self._write(escape(output))
        self.refresh_statuses()

    @work(exclusive=True, group="status")
    async def refresh_statuses(self) -> None:
        table = self.query_one("#services", DataTable)
        for service in list(self.services):
            try:
                plan = CommandPlan(
                    argv=(
                        sys.executable,
                        "-m",
                        "homelabctl.health",
                        str(service.path),
                        "--json",
                    ),
                    cwd=service.working_directory,
                )
                _, output = await self._run_plans([plan], timeout=20)
                result = json.loads(output)
                self.health_results[service.name] = result
                state = result.get("state")
                status = {
                    "healthy": Text("● 正常", style="green"),
                    "starting": Text("◐ 启动中", style="yellow"),
                    "unhealthy": Text("! 异常", style="red"),
                    "stopped": Text("○ 已停止", style="dim"),
                }.get(state, Text("! 不可用", style="red"))
            except UnsupportedOperation:
                status = Text("- 未支持", style="dim")
            except (HomelabError, OSError, ValueError, json.JSONDecodeError) as exc:
                status = Text("! 不可用", style="red")
                self.log.debug("status %s failed: %s", service.name, exc)
            try:
                table.update_cell(service.name, "status", status)
                if service.name == self.selected_name:
                    self._render_details(service)
            except Exception:
                return

    @work(exclusive=True, group="logs")
    async def load_logs(self, service: ServiceDefinition) -> None:
        try:
            plans = get_driver(service).plans("logs", follow=False, tail=200)
            code, output = await self._run_plans(plans, timeout=20)
        except UnsupportedOperation as exc:
            self._replace_service_logs(service, str(exc), color="yellow")
            return
        except (HomelabError, OSError) as exc:
            self._replace_service_logs(service, str(exc), color="red")
            return
        color = "white" if code == 0 else "red"
        self._replace_service_logs(service, output or "(暂无日志输出)", color=color)

    @work(exclusive=True, group="clear-logs")
    async def clear_service_logs(self, service: ServiceDefinition) -> None:
        self.workers.cancel_group(self, "logs")
        try:
            plans = get_driver(service).clear_log_plans()
            code, output = await self._run_plans(plans, timeout=20)
        except UnsupportedOperation as exc:
            self.notify(str(exc), severity="warning")
            return
        except (HomelabError, OSError) as exc:
            self._replace_service_logs(service, str(exc), color="red")
            return
        if code == 0:
            self._replace_service_logs(service, "日志已清空。", color="green")
            self.notify(f"{service.name} 日志已清空")
            return
        self._replace_service_logs(
            service,
            output or f"清空日志失败（退出码 {code}）",
            color="red",
        )

    async def _run_plans(
        self,
        plans: list[CommandPlan],
        *,
        timeout: float,
    ) -> tuple[int, str]:
        outputs: list[str] = []
        final_code = 0
        for plan in plans:
            creation = asyncio.create_task(
                asyncio.create_subprocess_exec(
                    *plan.argv,
                    cwd=plan.cwd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            )
            try:
                process = await asyncio.shield(creation)
            except asyncio.CancelledError:
                process = await creation
                if process.returncode is None:
                    process.kill()
                await process.communicate()
                raise
            except FileNotFoundError as exc:
                raise HomelabError(f"找不到可执行程序: {plan.argv[0]}") from exc
            try:
                stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.CancelledError:
                if process.returncode is None:
                    process.kill()
                await process.communicate()
                raise
            except TimeoutError:
                if process.returncode is None:
                    process.kill()
                await process.communicate()
                raise HomelabError(f"命令超时: {plan.display()}")
            final_code = process.returncode or 0
            outputs.append(stdout.decode("utf-8", errors="replace").rstrip())
            if final_code != 0:
                break
        return final_code, "\n".join(part for part in outputs if part)


def run_tui(root: Path, *, open_migration: bool = False) -> int:
    NControlApp(root, open_migration=open_migration).run()
    return 0
