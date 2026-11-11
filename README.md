# VPN Keeper

Linux 上面向 **用户名 + 单一密码** 的 OpenConnect（Cisco AnyConnect 兼容）自动登录与保活工具。Python 3.11+，运行时无 Python 第三方依赖。

本项目是独立新实现，借鉴原工具的配置 / 连接 / 健康检查 / 保活职责划分；没有 OTP 矩阵、第二密码、公司配置、cookie 缓存或原仓库历史。这里只支持服务器本身允许的单密码流程，不绕过 MFA、SSO 或组织策略。

**版本：0.1.0 Alpha。提供单密码连接、健康检查与自动重连。**

## 安装

适用于 Linux，建议 Debian 12 / Ubuntu 24.04 或其他 Python >=3.11 发行版。以下命令是由用户在自己的机器上执行的安装示例，不是本次已经执行的操作：

```sh
sudo apt install openconnect vpnc-scripts iproute2 iputils-ping python3-venv
# 将本目录放到 /opt/vpn-keeper，确保代码及其父目录不允许普通用户修改。
cd /opt/vpn-keeper
sudo python3 -m venv .venv
sudo .venv/bin/pip install .
sudo install -d -m 700 /etc/vpn-keeper
sudo install -m 600 examples/config.toml /etc/vpn-keeper/config.toml
sudoedit /etc/vpn-keeper/config.toml
```

如配置非空 routes，需要额外安装 vpn-slice 到固定系统 PATH 可找到的位置（/usr/sbin、/usr/bin、/sbin、/bin），或在受信任的系统目录安装包装入口。不要从不可信来源安装脚本。默认空 routes 使用系统 vpnc-script；不同发行版路径可能不同。

### 密码

使用 `sudoedit /etc/vpn-keeper/password` 创建单行密码文件，再运行 `sudo chmod 600 /etc/vpn-keeper/password`。密码文件必须属于运行用户，不接受符号链接和组/其他用户访问权限。不要在命令行、环境变量、聊天或 Git 中写密码。

`connect` 可在 password_file 设为空字符串时交互输入密码；`run` 需要文件来无人值守重认证。每次重连都会重新读取密码文件，支持自行更新密码。凭据文件仅储存在你的部署机器；项目不附带密码。

### 使用

```sh
sudo /opt/vpn-keeper/.venv/bin/vpn-keeper validate
sudo /opt/vpn-keeper/.venv/bin/vpn-keeper doctor
sudo /opt/vpn-keeper/.venv/bin/vpn-keeper connect
# Ctrl-C 停止。run 会自动重连，connect 不进行外层重试。
sudo /opt/vpn-keeper/.venv/bin/vpn-keeper run
sudo /opt/vpn-keeper/.venv/bin/vpn-keeper status
sudo /opt/vpn-keeper/.venv/bin/vpn-keeper health
```

自定义路径使用 `vpn-keeper --config /absolute/config.toml --state-dir /absolute/private-state run`。

- validate：仅配置校验，不读取密码、不访问网络。
- doctor：检查配置与可执行文件，不实际验证 VPN。
- health：接口 UP、有全局 IPv4/IPv6 地址；配置 CIDR 必须存在于该接口路由表；可选接口绑定 ping。独立 health 不证明进程归属或应用服务可用。
- status：依据文件锁报告 supervisor 是否运行；进程退出后的陈旧 JSON 不被当成在线。需要以相同用户运行。
- TLS：使用 OpenConnect 默认系统 CA 验证，不提供跳过证书验证选项。私有 CA 请由管理员安装到系统信任库。
- routes 为空：由标准 vpnc-script 接受服务器下发路由/DNS，可能包含默认路由。
- routes 非空：调用 vpn-slice，仅支持明确 CIDR，不支持域名规则。DNS/IPv6 行为取决于 vpn-slice 和服务器；部署前验证，不提供防泄漏 kill switch。

### systemd

```sh
sudo install -m 644 systemd/vpn-keeper.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start vpn-keeper
sudo systemctl status vpn-keeper
# 可选开机启动：sudo systemctl enable vpn-keeper
# 停止：sudo systemctl stop vpn-keeper
```

服务以前台 supervisor 管理单个 OpenConnect 进程组，不使用 PID 文件随意杀进程。SIGINT/SIGTERM 先向整个自有进程组发送 TERM，保留组长 PID 并等待 10 秒，再发送 KILL 清理残留成员，最后回收组长；即使组长提前退出也会执行清理，避免回收后误杀复用的 PGID。因此普通停止或重试也包含 10 秒清理等待。健康探测收到停止信号后会取消当前命令，不再继续后续查询；systemd 留出 30 秒停止窗口。另建会话/进程组的后代不在本机制覆盖范围，服务模式依靠 systemd cgroup 提供最终清理。文件锁防止同一状态目录重复启动；运行前拒绝已存在的同名接口。使用不同配置启动多个实例必须使用不同接口、状态目录和单独 service。

## 重连与边界

OpenConnect 本身先尝试 30 秒会话恢复。外层在进程退出、启动超时或连续健康失败后重新认证；指数退避默认 5 秒到 120 秒。默认连续 5 个失败会话后停止，systemd 不再次自动拉起，避免无限密码重试。连续健康达到 300 秒后重置失败预算。实际连接启动超时检测精度受 interval 和每次探测耗时影响。

失败预算不能消除账号锁定风险：一次 OpenConnect 登录可能涉及服务器内部多次尝试；未知密码不要启动守护进程。工具不解析、保存或显示原始 OpenConnect 输出，避免泄漏认证数据，因此只报告通用状态，不能自动区分错误密码、MFA、网络和证书错误。排障可由管理员在终端手动使用系统 OpenConnect，注意输出保密。

进程活着并不等于内网服务可用。health_target 未配置时仅检查接口/路由；ICMP 被禁时不应启用 ping。网络和 DNS 由系统路由脚本修改，退出恢复、强制终止后的恢复、休眠唤醒和真实证书链需要在目标机器验证。

## 开发测试（完全离线）

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
PYTHONPATH=src python3 -m vpn_keeper.cli --config examples/config.toml validate
```

测试使用 mock 与本地假进程，不调用真实 VPN、修改路由或读取真实密码。CI 示例覆盖 Python 3.11–3.13；仓库内 CI 配置尚未在远端执行。见 TESTING.md。


## 贡献与安全

开发流程见 [CONTRIBUTING.md](CONTRIBUTING.md)，变更记录见 [CHANGELOG.md](CHANGELOG.md)。安全报告要求与清理边界见 [SECURITY.md](SECURITY.md)。私密安全联系渠道尚未指定，请勿在公开 issue 中披露漏洞或认证材料。本实现采用 [MIT 许可证](LICENSE)，版权署名为 `2026 xchen-zhao`；发布前仍需确认权属，外部依赖继续遵守各自许可证。
