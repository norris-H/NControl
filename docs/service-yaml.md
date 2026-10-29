# `service.yaml` 规范（v1alpha1）

每个服务位于当前机器的 `local/services/<服务名>/service.yaml`。旧版
`services/<服务名>/service.yaml` 仍兼容，但不应与新目录同时存在。顶层结构：

```yaml
apiVersion: homelabctl/v1alpha1
kind: Service
metadata:
  name: my-app
  description: 示例服务
spec:
  driver: compose
  autostart: true
  workingDirectory: .
  compose:
    file: compose.yaml
  config:
    files:
      - .env
      - config/app.yaml
    allowExternalConfig: false
  backup:
    paths:
      - data/
    exclude:
      - data/cache/
  health:
    startupPeriodSeconds: 15
    checks:
      - name: web-api
        type: http
        url: http://127.0.0.1:8080/health
      - name: web-port
        type: tcp
        host: 127.0.0.1
        port: 8080
```

## 通用字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `apiVersion` | 是 | 当前固定为 `homelabctl/v1alpha1` |
| `kind` | 是 | 当前固定为 `Service` |
| `metadata.name` | 是 | 只能包含字母、数字、点、下划线和连字符 |
| `metadata.description` | 否 | 服务说明 |
| `spec.driver` | 是 | `process`、`docker`、`compose`、`systemd`、`script`、`frp`、`wireguard` |
| `spec.autostart` | 否 | 是否由 NControl 在系统启动时恢复服务，默认 `false` |
| `spec.workingDirectory` | 否 | 相对 `service.yaml` 所在目录；默认 `.` |
| `spec.config.files` | 否 | 需要检查和迁移的配置文件，不读取其内容 |
| `spec.config.allowExternalConfig` | 否 | 是否允许配置指向服务目录之外，默认 `false` |
| `spec.backup.paths` | 否 | 后续备份功能使用的路径清单 |
| `spec.backup.exclude` | 否 | 后续备份功能使用的排除清单 |

## 开机启动

每个服务通过 `spec.autostart` 独立控制。执行 `ncontrol boot install` 注册一次
NControl 开机入口；Linux 使用当前用户的 `crontab @reboot`，不使用 systemd。
Windows 使用登录启动任务。开机入口只调用 `ncontrol boot run`，实际服务仍由
NControl 的驱动启动和管理。

```bash
ncontrol boot enable my-app
ncontrol boot disable my-app
ncontrol boot status
```

## 健康检查

`spec.health.checks` 支持以下类型：

- `http`：检查 URL 和 HTTP 状态码；默认接受 200-399。process 服务可设置 `processOwned: true` 同时确认监听进程。
- `tcp`：检查主机端口；process 服务可设置 `processOwned: true`，同时确认端口由受管进程或其子进程监听。
- `wireguard-handshake`：检查指定接口最近握手时间。
- `ping`：检查目标地址连通性，可用 `interface` 指定 WireGuard 接口。

状态分为“正常”“启动中”“异常”“已停止”。进程启动后的
`startupPeriodSeconds` 内，尚未通过的检查显示为“启动中”。可用
`ncontrol health <服务名>` 查看详细结果。

`ncontrol doctor` 会只读检查所有服务声明的 TCP/UDP 端口、WireGuard 网段以及
WireGuard 接口密钥，报告端口冲突、网段重叠和重复密钥。

## 整目录迁移

将目录复制到受支持的 Debian/APT 或 RHEL/DNF 系 Linux 后运行 `./ncontrol`。启动器会识别机器变化和环境缺失，
必要时先重建 Python 虚拟环境，然后自动打开 TUI 的“迁移初始化”页面。主界面
也可按 `M` 随时进入。命令行的 `ncontrol migrate check` 始终只读，可重复执行。

## Docker

```yaml
spec:
  driver: docker
  docker:
    container: nginx
```

当前管理已经存在的容器，不负责创建容器。

## 跨平台进程

不依赖 systemd，由 NControl 保存 PID 与进程创建时间、管理整个进程树并把输出写入服务目录：

```yaml
spec:
  driver: process
  workingDirectory: source
  process:
    command: ["{python}", app.py]
    platformCommands:
      windows: ["{python}", app.py]
      linux: ["{python}", app.py]
    prepareCommand: [npm, ci, --omit=dev]
    platformPrepareCommands:
      windows: [npm.cmd, ci, --omit=dev]
    environment:
      DATA_DIR: "{serviceDir}/data"
    environmentFromFiles:
      ADMIN_TOKEN: secrets/admin-token.txt
    stateFile: .ncontrol/process.json
    logFile: logs/service.log
    startupGraceSeconds: 0.5
    stopTimeoutSeconds: 10
```

可用占位符：`{python}`、`{serviceDir}`、`{workingDirectory}`、`{root}`；其中
`{root}` 表示当前机器的数据根目录，新结构中即 `local/`。
`environmentFromFiles` 只把文件内容注入子进程环境，不会打印秘密内容。命令始终以参数数组执行，不经 shell。
需要安装服务依赖时，可配置 `prepareCommand`，然后执行 `ncontrol prepare <服务名>`。

## Docker Compose

```yaml
spec:
  driver: compose
  compose:
    file: compose.yaml
    projectName: my-app       # 可选
    services: [api, worker]   # 可选；空表示整个 Compose 项目
```

`start` 使用 `up -d`，`stop` 使用非破坏性的 `stop`。

## systemd

```yaml
spec:
  driver: systemd
  systemd:
    unit: frps.service
    user: false
    sudo: true              # 系统级服务启停默认使用 sudo -n
```

`user: true` 时调用 `systemctl --user`。系统级服务的启动、停止和重启默认使用
`sudo -n`，不会弹出密码输入；如运行 NControl 的账号本身已有相应权限，可设置 `sudo: false`。

## 自定义脚本

```yaml
spec:
  driver: script
  script:
    commands:
      start: ["./bin/app", "start"]
      stop: ["./bin/app", "stop"]
      restart:
        - ["./bin/app", "stop"]
        - ["./bin/app", "start"]
      status: ["./bin/app", "status"]
      logs: ["./bin/app", "logs"]
      clearLogs: ["./bin/app", "clear-logs"]
```

命令必须是参数数组；不会解析 `|`、`>`、`&&` 等 shell 语法。
`clearLogs` 是可选的；配置后，TUI 才会允许清空该脚本服务的日志。

## FRP / WireGuard

```yaml
spec:
  driver: frp
  frp:
    role: server
    config: config/frps.toml
```

```yaml
spec:
  driver: wireguard
  wireguard:
    interfaces:
      - name: wg0
        role: server
        config: config/wg0.conf
        peerManagement:
          addressPool: 10.10.0.0/24
          publicEndpoint: vpn.example.com:51820
          serverPublicKeyFile: secrets/wg0/public.key
          metadataDirectory: peers
          clientOutputDirectory: secrets/clients
          defaultAccessProfile: linked-networks
          accessProfiles:
            server-only:
              description: 仅访问云服务器
              allowedIPs: [10.10.0.1/32]
            linked-networks:
              description: 访问 WireGuard 和已连接的远程网络
              allowedIPs: [10.10.0.0/24, 192.168.31.0/24, 192.168.7.0/24]
      - name: wg1
        role: client
        config: config/wg1.conf
    connections:
      - name: wg0-to-wg1
        from: wg0
        to: wg1
        sourceNetwork: 10.10.0.0/24
        destinationNetworks: [192.168.31.0/24, 192.168.7.0/24]
        mode: masquerade
        allowReturnTraffic: true
        autoConnect: true
    sudo: true              # 可选；status 默认使用 sudo -n，只读且不会弹出密码提示
```

一个 WireGuard 服务可以包含多个接口，每个接口的 `role` 必须是 `server` 或
`client`。Linux 使用 `wg-quick` 启停，默认使用 `sudo -n`。

`connections` 把转发和 NAT 规则声明为有名连接。NControl 会用带标记的
iptables 规则进行幂等启用和定向删除，不会清空系统链。`autoConnect: true`
表示 WireGuard 完整启动后自动启用连接，停止接口前先断开连接。系统必须已开启
`net.ipv4.ip_forward=1`；NControl 只检查，不会隐藏修改系统设置。

`peerManagement` 仅配置在服务端接口。终端界面中按 `W` 进入 WireGuard 管理页，
可以识别旧客户端、自动分配地址、生成客户端配置、热更新运行中的服务端，
以及撤销由 NControl 创建的客户端。旧配置导入后默认只读，不会被删除。

在“服务端接口”页按 `N` 可以创建新的 WireGuard 服务端接口。NControl 会生成
独立密钥、配置和客户端管理目录，并尝试启动接口，但不会修改云防火墙或安全组。
选中服务端接口后，按 `E` 可以编辑地址、地址池、监听端口和公网入口，按 `D`
可以在确认后停止并移除接口；删除的配置、密钥和客户端资料会保留在归档目录中。
仍被网络连接引用的接口不能删除。
每个服务端接口会单独显示“已连接”或“已断开”。已断开时按 `C` 重新连接，
已连接时按 `X` 并确认后断开；这不会删除配置、密钥或客户端资料。
WireGuard 管理页每两秒读取一次计数器：服务端客户端行会显示最近握手、实时收发
速度和累计流量；客户端接口显示其对端流量；网络连接显示正向与返回方向的规则
流量。该统计只读取计数器，不读取或保存传输内容。
在“网络连接”页按 `A` 添加连接，按 `E` 编辑选中的连接，按 `X` 删除连接。
连接表单可选择来源接口、目标接口、来源网段和需要访问的目标网段；方向代表来源侧可以主动访问目标侧，
若两侧都需要主动访问，应分别声明两个方向。新连接保存后需按 `C` 启用。
NControl 会把目标网段同步到来源服务端所生成的客户端配置；已经部署的客户端需要
重新导出配置或重新扫码，才能采用新增路由。
在“客户端接口”页按 `J` 可以选择两种方式连接其他服务端：导入对方提供的
客户端 `.conf`，或手动填写本机隧道地址、远端服务端公钥、预共享密钥、端点、
允许网段和永久保活。手动创建时 NControl 会生成独立客户端密钥，并在结果区显示
需要登记到威联通/QNAP 等远端服务端的客户端公钥；远端 Peer 的允许 IP 应填写
本机隧道地址（通常是 `/32`）。选中客户端接口后按 `E` 可以查看客户端公钥、
远端公钥、端点、允许网段和保活设置并进行编辑；私钥不会在界面或 Web API 中显示。
新建完成后 TUI 会弹出威联通/QNAP 登记信息，可用“复制公钥”写入本地终端剪贴板；
客户端编辑页中的公钥也是可选择的只读文本，并提供相同的复制按钮。

