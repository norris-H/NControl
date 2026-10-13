# homelabctl

一个面向个人服务器的轻量服务管理器。用统一的 `service.yaml` 描述服务，再用同一套界面管理跨平台进程、Docker、Docker Compose、systemd 和自定义脚本。

当前第一阶段已实现：

- 跨平台进程驱动：NControl 自己管理 PID、进程树和日志，不依赖 systemd
- Docker / Docker Compose / systemd：`start`、`stop`、`restart`、`status`、`logs`
- 自定义脚本：同样的操作接口，命令必须写成参数数组，不通过 shell 执行
- FRP / WireGuard：独立驱动；WireGuard 支持客户端向导、配置导出、热更新和命名网络连接
- `list`、`show`、`validate`、`config-check`、`--dry-run`
- 每个服务可独立设置开机启动，服务进程仍由 NControl 管理
- HTTP、TCP、进程端口归属、WireGuard 握手和目标网络健康检查
- 端口冲突、IP 网段重叠和 WireGuard 密钥重复检查
- 终端可视化界面：服务列表、状态、详情、配置检查和日志面板
- 可选 Web 控制台：复用 TUI 的服务、日志、WireGuard、检查、更新和迁移能力；默认关闭
- 为后续备份/迁移预留 `backup` 元数据

## 安装

建议在服务器上使用虚拟环境：

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Windows 首次使用：

```bat
bootstrap.cmd
ncontrol.cmd
```

复制到新系统后，Danmu 还需要按目标系统重新安装 Node 依赖：

```bash
./ncontrol prepare danmu-api
```

Windows 使用 `ncontrol.cmd prepare danmu-api`。目标系统需预先安装 Python 和 Node.js；
FRP 的 Windows 二进制按 `local/services/frps/package/windows/README.txt` 放置。

## 迁移到新的 Debian 系 Linux

复制整个 NControl 文件夹后，只需启动：

```bash
./ncontrol
```

支持 Ubuntu、Debian 和 Raspberry Pi OS（含 Lite）。启动器会识别新机器。环境不完整时
先在普通终端中准备系统软件包和 `.venv`，
随后自动打开 TUI 的“迁移初始化”页面。也可以随时在主界面按 `M` 进入。页面中
可以填写新的公网 IP 或域名、一键配置 WireGuard 主机、注册开机入口并启动自动
服务。不会使用 systemd 管理实际服务。

只想检查、不做系统修改时，在已有 NControl 环境中运行：

```bash
./ncontrol migrate check
```

无人值守初始化可使用：

```bash
bash setup-ubuntu.sh --yes --public-host vpn.example.com
```

在 ARM 树莓派上，随项目复制的 x86-64 FRP 程序不能直接运行；未启用 FRP 时只会提示
警告。如需启用，必须换成与 `uname -m` 对应的 FRP ARM 版本。若这台树莓派是新增设备
而不是替换原服务器，不要直接启动复制来的 WireGuard 配置，以免与原服务器重复使用
IP、端口和密钥。

云安全组、防火墙开放端口以及外部 FRP 客户端的服务器地址仍需在云平台或对应
设备上处理；NControl 不会隐藏修改云平台设置。

## 快速开始

管理器代码可以在多台服务器之间同步，`local/` 则只属于当前机器，并已被 Git 忽略：

```text
管理脚本/
├── ncontrol                 # 可同步
├── src/                     # 可同步
├── examples/                # 可同步的模板
├── local/                   # 不同步
│   ├── node.yaml
│   ├── web.yaml             # 本机 Web 设置（默认不存在 / 关闭）
│   ├── secrets/             # Web 登录令牌等本机秘密
│   └── services/
│       └── my-app/
│           ├── service.yaml
│           ├── compose.yaml
│           ├── .env
│           ├── config/
│           └── data/
└── ...
```

旧版根目录 `services/` 仍可读取。执行 `./ncontrol layout migrate` 可在不停止服务的
情况下整理为新结构；如果新旧目录同时存在，NControl 会拒绝运行以避免操作错机器。

可从 `examples/services/` 复制示例到 `local/services/`，然后执行：

```bash
./ncontrol validate
./ncontrol doctor
./ncontrol list
./ncontrol --dry-run start my-app
./ncontrol status my-app
./ncontrol logs my-app --tail 200 --follow
```

项目内的 `./ncontrol` 启动器不会依赖全局安装，因此整个目录复制到新服务器后仍可使用；
不带参数时会打开终端可视化界面。新服务器首次使用时执行 `./bootstrap.sh` 创建环境。
复制到 Windows 后执行 `bootstrap.cmd`，之后使用 `ncontrol.cmd`。

界面快捷键：

- `↑` / `↓`：选择服务
- `R`：刷新状态
- `S`：启动选中的 active 服务
- `X`：停止选中的 active 服务（需要二次确认）
- `Enter`：查看详情
- `C`：检查配置
- `D`：检查端口、网段和 WireGuard 密钥冲突
- `A`：切换选中服务的开机启动
- `M`：打开迁移初始化页面
- `U`：检查并安装管理器更新（不会修改 `local/`）
- `V`：打开 Web 管理（启用、监听地址、启动/停止、重置令牌）
- `L`：立即刷新最近日志（界面会自动刷新）
- `K`：清空选中服务的日志（需要二次确认）
- `Q`：退出

## Web 管理

Web 管理默认关闭，不会因为安装或更新 NControl 而启动，也禁止监听 `0.0.0.0`。
在 TUI 主界面按 `V` 打开“Web 管理”，填写当前机器真实存在的 IPv4 地址：

- 只在服务器本机访问时，使用 `127.0.0.1`；
- 通过 WireGuard 私网访问时，使用该服务器的 WireGuard 地址，例如 `10.10.0.1`；
- 不建议绑定公网网卡地址；NControl 不会自动修改防火墙或云安全组。

填写地址、端口和自定义登录令牌后点击“保存并启动”，设置保存和启动会一次完成。
令牌允许任意非空的单行内容，不强制长度或复杂度；使用过短令牌会降低安全性。运行中
修改设置或令牌时，主按钮会变为“保存并重启”，旧会话会随重启失效。“停止”只停止当前监听并
保留配置，“关闭功能”则停止监听并恢复为默认关闭。配置、登录令牌、运行状态和日志
均保存在当前节点的 `local/` 中，不会提交或同步到 GitHub。网页关闭后，TUI 和普通
命令行管理不受影响。

无人值守环境也可以使用以下命令；日常使用无需记忆，直接按 `V` 即可：

```bash
./ncontrol web enable --bind 127.0.0.1 --port 8765
./ncontrol web start
./ncontrol web status
./ncontrol web stop
```

网页使用令牌登录、仅限同源请求并校验 CSRF。停止服务、清空日志、删除 WireGuard
对象、改变网络连接和迁移初始化等操作仍会要求二次确认。

未安装为命令时也可在项目根目录运行：

```bash
python -m homelabctl --root . list
```

## 安全约定

- 所有外部命令都以参数数组直接执行，默认不启用 shell。
- Compose 的 `stop` 使用 `docker compose stop`，不会像 `down` 一样删除容器和网络。
- `--dry-run` 会打印计划但不执行，首次操作服务前建议先使用。
- 健康检查和系统冲突检查均为只读操作。
- `config-check` 只检查路径和权限，不输出密钥内容。
- 配置在服务目录外时，必须显式设置 `allowExternalConfig: true`。
- 密钥、`.env`、私钥和运行数据不应提交到版本库。
- Web 管理只允许绑定本机 IPv4，默认不启动；通过远程网络访问时优先绑定 WireGuard IP。

完整字段说明见 [docs/service-yaml.md](docs/service-yaml.md)。

