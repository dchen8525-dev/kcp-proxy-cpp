# KCP Proxy (C++)

把本地 TCP 流量装进加密的 KCP/UDP 隧道，用 SOCKS5 接出来。

```
浏览器/应用 ──SOCKS5(TCP)──▶ kcp-proxy-client ══KCP/UDP·AES-128-GCM══▶ kcp-proxy-server ──TCP──▶ 目标
```

客户端监听 `127.0.0.1:1080`，服务端监听 UDP `8388`。

跨境线路、移动网络、晚高峰家宽这类链路上，TCP 一旦丢包就会缩窗并因队头阻塞整体卡住；
KCP 是跑在 UDP 上的 ARQ 协议，用更多带宽换更稳的延迟。本项目把 KCP 包进 AEAD，
客户端只暴露一个标准 SOCKS5 端口，浏览器和命令行工具无需改动。

代价要说在前面：它比裸 TCP 费流量，并且依赖 UDP 不被运营商或防火墙降级。所以需要 UDP 转发的
场景（HTTP/3、UDP DNS、SOCKS5 `UDP ASSOCIATE`）不适用，见[协议与加密](#协议与加密)末尾。

服务端与客户端为 C++17，GUI 为 Electron；发布包与版本历史见
[Releases](https://github.com/dchen8525-dev/kcp-proxy-cpp/releases)。

## 目录

- [特性](#特性)
- [快速开始](#快速开始)
- [服务端部署](#服务端部署)
- [客户端](#客户端)
- [命令行参考](#命令行参考)
- [前向纠错（FEC）](#前向纠错fec)
- [协议与加密](#协议与加密)
- [架构](#架构)
- [目录结构](#目录结构)
- [测试与 CI](#测试与-ci)
- [版本与兼容性](#版本与兼容性)
- [排障](#排障)

## 特性

**传输**

- SOCKS5 `CONNECT`（TCP），支持 `IPv4` / `IPv6` / `DOMAIN` 三种地址类型
- KCP 极速模式：`conv=1`、`mtu=1400`、`interval=10ms`、`nodelay=1`、`fast resend=5`、`nc=1`、收发窗口各 1024 段、会话超时 60s
- 服务端单 UDP Socket 多路复用全部会话；客户端每个本地 TCP 连接一个独立 UDP Socket
- 半关闭语义：一侧停止发送时用 `KCP_PROXY_FIN_V1` 通知对端，对端 `shutdown(SHUT_WR)` 而不是 `close()`，不丢在途响应
- 应用层心跳（30s）防止空闲隧道被误回收

**加密**

- AES-128-GCM + HKDF-SHA256，密钥由「密钥串 + 每会话随机盐」派生，会话之间不共享 nonce 序列
- nonce 内嵌方向标识（c2s `0x01` / s2c `0x02`），2048-bit 滑动窗口检测重放
- 密钥不落命令行：客户端与 GUI 通过 `KCP_PROXY_KEY` 环境变量传递

**抗丢包**

- 可选 Reed-Solomon FEC（如 `10:3`）：发送侧每 10 个数据报额外产生 3 个校验报，接收侧丢失 ≤3 个可本地重建，不必等重传
- 服务端逐会话自适应：客户端说 FEC 就按 FEC 回，不说就发明文裸 KCP 段，同一服务端可同时服务两类客户端

**运维**

- 每日密钥：`北京日期(YYYYMMDD)` + 后缀，服务端由 systemd timer 每 6 小时重启切换，客户端启动时本地推导
- SSRF 防护：默认拦截回环/私网/链路本地/组播等受限目标
- 未认证来源按秒限速；服务端最多 4096 会话，客户端最多 512 并发连接
- 日志行格式固定（`YYYY-MM-DD HH:MM:SS.mmm [LEVEL] module: message`），GUI 靠它解析状态与流量

**GUI（Electron）**

- 概览页实时上下行速率、峰值、累计流量与迷你曲线
- 托盘常驻（关窗不退出）、托盘启停、断线重连、开机自动连接、允许局域网
- 连接测试结果内联显示，不必翻日志
- 内置自动更新（GitHub Releases）

## 快速开始

### 直接下载

发布包在 [GitHub Releases](https://github.com/dchen8525-dev/kcp-proxy-cpp/releases)：

| 产物 | 平台 | 用途 |
|------|------|------|
| `kcp-proxy-server_<ver>_amd64.deb` | Linux amd64 | 服务端，装完即 systemd 服务 |
| `kcp-proxy-<ver>-linux-x64.tar.gz` | Linux x64 | 服务端/客户端命令行，解压即用 |
| `kcp-proxy-<ver>-windows-x64.zip` | Windows x64 | 服务端/客户端命令行 |
| `KCP-Proxy-<ver>-Setup.exe` | Windows | GUI 安装包（NSIS，推荐） |
| `KCP-Proxy-<ver>-Portable.exe` | Windows | GUI 免安装单文件 |
| `KCP-Proxy-<ver>.AppImage` | Linux | GUI |
| `SHA256SUMS` | — | 以上全部产物的校验和 |

```bash
# 校验（下载到同一目录后）
sha256sum -c SHA256SUMS --ignore-missing
```

GUI 的 `latest.yml` / `latest-linux.yml` / `.blockmap` 是自动更新用的元数据，不需要手动下载。

### 从源码构建

依赖由 **vcpkg** 管理，构建由 **CMake 3.22+** 驱动：

| 依赖 | 用途 |
|------|------|
| asio | 全异步网络、定时器、信号（standalone，无 Boost） |
| openssl | AES-128-GCM、HKDF、`OPENSSL_cleanse` |
| fmt | 字符串与日志格式化 |
| spdlog | 日志后端 |
| kcp-cpp | KCP 协议栈 C++17 移植（`ports/kcp-cpp` overlay，含 Reed-Solomon 编解码） |
| doctest | 单元测试框架 |
| CLI11 | 命令行解析 |

**Linux / macOS**

```bash
git clone https://github.com/dchen8525-dev/kcp-proxy-cpp.git
cd kcp-proxy-cpp
./build.sh                      # 自动处理 vcpkg，产物进 bin/linux/
```

**Windows（MSVC）**

需要 Visual Studio 2019+ 的「使用 C++ 的桌面开发」工作负载、CMake、Git for Windows。

```powershell
.\build_vs.bat                  # 产物进 bin\windows\，附带所需 DLL
```

**手动构建**（两端同法）

```bash
export VCPKG_ROOT=/path/to/vcpkg      # Windows: $env:VCPKG_ROOT = "C:\path\to\vcpkg"
cmake --preset default
cmake --build --preset release --parallel
```

产物：`kcp-proxy-server`、`kcp-proxy-client`，位于 `build/Release/`（多配置生成器）或 `build/`。
Presets 另有 `debug`。

vcpkg 查找顺序为 `VCPKG_ROOT` → 仓库内 `vcpkg/` → 自动克隆。不建议用 VS 自带的
`BuildTools\VC\vcpkg`，它常缺 `builtin-baseline` 支持；脚本会跳过它。

> **`-DKCP_PROXY_ENABLE_NATIVE_TUNE=ON` 只用于本机提速**（`-march=native`）。发布包一律保持
> 关闭：带 AVX-512 的产物在旧 CPU 上会非法指令崩溃。

## 服务端部署

### deb 安装（推荐）

```bash
VERSION=0.2.2                       # 换成要安装的版本，见 Releases
wget https://github.com/dchen8525-dev/kcp-proxy-cpp/releases/download/v$VERSION/kcp-proxy-server_${VERSION}_amd64.deb
sudo dpkg -i kcp-proxy-server_${VERSION}_amd64.deb

sudo systemctl status kcp-proxy-server
```

安装后：

| 项 | 位置 |
|----|------|
| 二进制 | `/usr/local/bin/kcp-proxy/kcp-proxy-server` |
| 配置 | `/etc/kcp-proxy/server.env`（`chmod 600`） |
| 日志 | `/var/log/kcp-proxy/server.log`，或 journald |
| 服务 / 定时器 | `kcp-proxy-server.service`、`kcp-proxy-server-key-refresh.timer` |
| 运行用户 | 系统用户 `kcpproxy`（无 home、nologin） |
| 内核参数 | `/etc/sysctl.d/99-kcp-proxy.conf` |

### `server.env`

```ini
SUFFIX=你的密钥后缀        # 8-128 位 [A-Za-z0-9._-]
PORT=8388
HOST=0.0.0.0
LOG_LEVEL=INFO
LOG_FILE=/var/log/kcp-proxy/server.log   # 置空则只输出到 journald
FEC=10:3                                 # 置空或 0:0 表示用内建自适应默认值
```

改完 `sudo systemctl restart kcp-proxy-server` 生效。`LOG_FILE` 必须留在
`/var/log/kcp-proxy` 下：unit 开了 `ProtectSystem=strict`，写别处会被拒绝。
日志超过 10 MiB 时在下次重启时轮转为 `.1`，只保留一代。

### 密钥轮换

完整密钥 = `北京日期(YYYYMMDD)` + `SUFFIX`。`kcp-proxy-server-key-refresh.timer` 在北京时间
00:00 / 06:00 / 12:00 / 18:00 重启服务，让服务端拿到当天日期。

定时器故意写成 UTC 形式（`OnCalendar=*-*-* 04,10,16,22:00:00 UTC`）：裸 `OnCalendar=` 按**主机时区**
解析，在非 UTC+8 机器上午夜触发点可能偏离北京日期切换近 14 小时；北京固定 UTC+8 且无夏令时，UTC 才是精确的。
systemd < 228 不支持 `UTC` 后缀，安装脚本会探测并回退为换算后的本地时间。

**客户端也要重启**才能拿到新日期的密钥，否则会持续 `DECRYPT_FAILED`。

### 内核 UDP 缓冲（重要）

服务端启动时申请 4 MiB 收发缓冲，但内核会**静默**钳制到 `net.core.rmem_max` / `wmem_max`
（Debian 默认仅 208 KiB），而 `setsockopt` 照样返回成功。缓冲变小后突发流量溢出被丢，
KCP 把丢包当拥塞、整窗重传，现象是连接卡住直至 `ERR_CONNECTION_CLOSED`。

因此 deb 的 postinst 与 `install-service.sh` 会在**启动服务之前**写入
`/etc/sysctl.d/99-kcp-proxy.conf`，把上限提到 4 MiB：

- **只升不降**：当前值已 ≥ 4 MiB 时完全不写文件。
- 缺 `sysctl` 的最小化主机跳过并告警，安装不失败。
- 卸载会删 drop-in，但**不会**把已生效的值降回来。

启动日志会打出生效值，被钳制时额外一条 WARNING：

```
UDP socket buffers so_rcvbuf=4194304 so_sndbuf=4194304
UDP socket buffer clamped by the kernel: so_rcvbuf requested=4194304 effective=212992 ...
```

### 防火墙

```bash
sudo ufw allow 8388/udp && sudo ufw reload
```

只需要 UDP。客户端到服务端不建立 TCP 连接。

### 从源码远程部署

```bash
./build.sh                                  # 先产出 Linux 二进制
./deploy.sh root@your-server-ip             # 上传并安装为 systemd 服务
./deploy.sh root@1.2.3.4 -P 2222            # 自定义 SSH 端口
./deploy.sh root@1.2.3.4 --prompt-suffix    # 隐藏交互输入后缀（推荐）
./deploy.sh root@1.2.3.4 --dry-run          # 只验证打包，不连接
./deploy.sh root@1.2.3.4 --uninstall
```

`deploy.sh` / `deploy.bat` 只是 `scripts/deploy/deploy.py` 的入口（Python 3 标准库 + 系统
`ssh`/`scp`，Windows 自带 OpenSSH 即可）。后缀也可用环境变量
`KCP_PROXY_DEPLOY_SUFFIX` 传入；`--suffix VALUE` 会出现在 shell 历史与 `ps` 输出里，不建议。
省略后缀时沿用服务端现有值。

## 客户端

### Windows GUI

下载 `KCP-Proxy-<ver>-Setup.exe` 安装，或直接用 `KCP-Proxy-<ver>-Portable.exe`。

1. **连接设置**：服务器地址（IP/域名）、服务器端口（默认 8388）、密钥后缀、本地 SOCKS 端口（默认 1080）
2. **按需勾选**：启用 FEC（填与服务端一致的 `数据:校验`，默认 `10:3`）、允许局域网使用、打开应用时自动连接、断线重连
3. **保存设置** → **启动连接**（「保存设置」才写盘；「启动连接」按当前表单执行）
4. 应用侧代理指向 `socks5://127.0.0.1:1080`

```bash
# 验证：返回的应该是服务器 IP
curl -x socks5h://127.0.0.1:1080 https://httpbin.org/ip
```

GUI 关闭窗口默认收进托盘；托盘菜单可启停、安装更新。

### 命令行客户端

适合无 GUI 的机器或需要脚本化：

```bash
kcp-proxy-client -s example.com -l 1080 -k "$(TZ=Asia/Shanghai date +%Y%m%d)YOURSUFFIX"

# 或让密钥走环境变量，避免出现在 ps 里
KCP_PROXY_KEY="$(TZ=Asia/Shanghai date +%Y%m%d)YOURSUFFIX" \
  kcp-proxy-client -s example.com -l 1080
```

不传 `--fec` 即关闭 FEC。密钥模式上命令行更灵活：可以传固定的长密钥（≥16 字符），
只要两端一致且不依赖每日轮换。

## 命令行参考

### `kcp-proxy-server`

```bash
kcp-proxy-server -k <密钥> [-H 0.0.0.0] [-p 8388] [-T 1] [-L INFO] [--fec 10:3] [--allow-target HOST[:PORT]]
```

| 参数 | 默认 | 说明 |
|------|------|------|
| `-k, --key` | 必填 | 加密密钥，≥16 字符；也可用环境变量 `KCP_PROXY_KEY` |
| `-H, --host` | `0.0.0.0` | UDP 绑定地址 |
| `-p, --port` | `8388` | UDP 监听端口（严格十进制，1–65535） |
| `-T, --threads` | `1` | io_context 工作线程数，1–64。KCP 更新始终跑在单个共享 10ms tick 上，多线程只分摊 UDP/TCP I/O |
| `-L, --log-level` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `--fec` | 未设 | FEC 分片参数 `DATA:PARITY`（如 `10:3`，`0:0` 关闭）。**服务端本身逐会话自适应**，此值只决定适配时用哪组分片，未设时用内建 `10:3` |
| `--allow-target` | 空 | 放行指定目标绕过 SSRF 防护，可重复，`主机[:端口]`。**仅限实验室**，默认空即全防护 |

解析是失败关闭式的：端口写 `abc`、FEC 写成 `3:10`（校验位多于数据位）都会直接拒绝启动，
不会退回默认值。

### `kcp-proxy-client`

```bash
kcp-proxy-client -s <服务端地址> -k <密钥> [-p 8388] [-H 127.0.0.1] [-l 1080] [-L INFO] [--fec 10:3] [--half-close-grace 120]
```

| 参数 | 默认 | 说明 |
|------|------|------|
| `-s, --server` | 必填 | 远端 KCP 服务端地址 |
| `-p, --server-port` | `8388` | 远端 UDP 端口 |
| `-k, --key` | 必填 | 加密密钥，≥16 字符；也可用 `KCP_PROXY_KEY` |
| `-H, --listen-host` | `127.0.0.1` | 本地 SOCKS5 绑定地址（`0.0.0.0` 即允许局域网） |
| `-l, --listen-port` | `1080` | 本地 SOCKS5 端口 |
| `-L, --log-level` | `INFO` | 日志级别 |
| `--fec` | 未设 | `DATA:PARITY`，如 `10:3`；`0:0` 或省略即关闭。**客户端决定本端是否用 FEC 成帧** |
| `--half-close-grace` | `120`（2×超时） | 本地应用停止发送后，目标多久没有新数据就回收隧道。计时只由真实数据推进，心跳不算 |

> 0.2.0 起 FEC 参数是 `--fec`（双横线）。旧写法 `-fec 10:3` 会得到一个明确的迁移提示，
> 而不是 CLI11 的「arguments were not expected」。

## 前向纠错（FEC）

KCP 的快速重传只能在**丢包被检测到之后**才开始补救，一个 RTT 内丢的包仍会让应用卡顿。
`--fec 10:3` 让发送侧每 10 个数据报额外产生 3 个校验报，接收侧任意丢 ≤3 个即可本地重建。
代价是 30% 额外上行带宽，只在跨境、无线等丢包明显的链路上开。

**两端语义不同，这是最容易踩错的地方：**

| 端 | `--fec` 的含义 |
|----|----------------|
| 客户端 | **显式**：本端是否用 FEC 成帧，同时决定它期望收到什么 |
| 服务端 | **自适应**：会话首个解密后的数据报带 FEC 头就按 FEC 成帧，是裸 KCP 段就保持裸帧。`--fec` 只提供适配时的分片参数，未设则用内建 `10:3` |

因此两端参数不一致**不会**导致完全不通：数据分片各自独立有效，仍能传输，只是校验修复能力下降
（跨丢包链路会表现为速度变慢而不是断流）。要拿到完整修复能力，两端写同一个 `DATA:PARITY`。

配置约束：`DATA ≥ 1`、`PARITY ≥ 1`、`DATA + PARITY ≤ 256`、`PARITY ≤ DATA`（冗余不超过 100%）。
解析失败即拒绝启动，不静默降级成「无 FEC」——一条「能连上但不通」的隧道比启动报错难查得多。

线路上限由编译期 `static_assert` 兜住：FEC 成帧后的最坏尺寸连同 salt/nonce 与 IP/UDP 头仍在
1500 MTU 之内，不会触发 IP 分片（分片丢一个片就等于整包丢失，对 KCP 是最坏情况）。

## 协议与加密

每个本地 TCP 连接对应一个独立 KCP/UDP 会话。客户端先在 KCP 内发送认证加密的
`KCP_PROXY_HELLO_V2`，收到服务端 `KCP_PROXY_HELLO_ACK_V2` 后才把会话标记为 connected。
兼容性上，服务端也接受首个有效加密 payload 直接是 SOCKS5 CONNECT 请求（不要求 HELLO），
并继续接受 `KCP_PROXY_HELLO_V1` 的旧客户端；V2 相比 V1 只多出半关闭支持。

半关闭由 `KCP_PROXY_FIN_V1`（payload 为 `magic || session_salt`）表达：服务端在目标 EOF 时发送，
客户端在本地应用停止发送时发送。接收方停止在该方向读 KCP，并对相应 socket 执行
`shutdown(SHUT_WR)`，避免丢掉应用尚未读走的数据。没有它，隧道只能靠 60s 空闲扫描收尾。

密钥串不会直接 SHA-256 截断，而是用 HKDF-SHA256 派生 AES-128-GCM 密钥：

```
cipher:   AES-128-GCM
HKDF:     SHA-256，salt = "kcp-proxy-hkdf-salt-v1" || session_salt(16B)
info:     "kcp-proxy/c2s/v1"（客户端→服务端） / "kcp-proxy/s2c/v1"（服务端→客户端）
nonce:    12B = [8B 单调计数器][1B 方向][3B 零]
wire:     [session_salt(16)][nonce(12)][ciphertext][tag(16)]
```

每次会话由客户端生成 16 字节随机 salt 并明文随包携带，双方用 `PSK + salt` 派生独立的会话密钥，
保证 nonce 永不跨会话复用（AES-GCM 的 nonce 复用后果是灾难性的）。服务端拒绝与在线会话共享
同一 salt 的新会话。计数器起值由 salt 前 6 字节派生，单会话加密 2^48 次后拒绝继续，需重建连接。

SOCKS5 支持范围：

- 支持 `CONNECT`，地址类型 `IPv4` / `IPv6` / `DOMAIN`
- 不支持 `UDP ASSOCIATE` 与 `BIND`，返回 command not supported
- 不转发 QUIC/HTTP3、UDP DNS 等 UDP 流量；浏览器如需稳定通过本代理，请关闭 QUIC/HTTP3

## 架构

```
KCPProxyClient
  ├── TCP acceptor（本地 SOCKS5）
  └── 每个本地 TCP 连接:
      ├── KCPClientSession（独立 UDP socket）
      │   ├── KcpWrapper（KCP 状态机）
      │   └── Crypto（AES-128-GCM 实例）
      └── SOCKS5 握手内联处理

KCPServer
  ├── 单个 UDP socket（所有会话共用）
  └── unordered_map<ip:port, KCPSession>
      └── KCPSession
          ├── KcpWrapper
          └── Crypto
```

| 组件 | 职责 |
|------|------|
| `KcpWrapper` | 对 kcp-cpp 的 RAII 封装，输出回调把 KCP 产生的数据交给加密层与 UDP |
| `Crypto` | AES-128-GCM 加解密、单调 nonce 计数器、重放窗口 |
| `KCPSession` | 服务端会话：一个客户端端点一个，共享服务端 UDP socket |
| `KCPClientSession` | 客户端会话：一个本地 TCP 连接一个，独立 UDP socket |
| `KCPServer` | 会话映射、SSRF 防护、未认证来源限速、超时清理（60s 扫描） |
| `KCPProxyClient` | 接受本地 SOCKS5 连接、反压（`wait_send` 超阈值暂停读）、半关闭收尾 |

## 目录结构

```text
kcp-proxy-cpp/
├── CMakeLists.txt / CMakePresets.json / vcpkg.json / vcpkg-configuration.json
├── build.sh / build_vs.bat            # 一键构建（Linux/macOS、Windows）
├── deploy.sh / deploy.bat             # 部署入口 → scripts/deploy/deploy.py
├── ports/kcp-cpp/                     # vcpkg overlay port（KCP + FEC）
├── src/
│   ├── main_server.cpp / main_client.cpp
│   ├── cli_helpers.hpp                # CLI11 校验器、密钥清零
│   └── kcp_proxy/                     # 核心：server / client / kcp_* / crypto / socks5 / logger / config
├── tests/
│   ├── unit/test_core.cpp             # doctest
│   ├── smoke/smoke_test.py            # 打包/部署不变量 + 变更行 clang-format 门禁
│   └── e2e/                           # tunnel / robustness / adversarial / fec_loss
├── gui/electron/                      # Electron GUI（main.js / renderer.js / utils.js / styles.css）
├── scripts/
│   ├── deploy/                        # deploy.py、install-service.sh、uninstall-service.sh
│   ├── package/package.py             # 统一打包（纯标准库）
│   ├── runtime/                       # 本地起服务端/客户端
│   └── templates/                     # systemd 密钥轮换 service/timer
├── docs/                              # PROTOCOL / TESTING / TROUBLESHOOTING / ANDROID_INTEROP / FINAL_REPORT
├── build/ bin/ dist/                  # 构建、二进制、发布包（均 .gitignore）
```

## 测试与 CI

```bash
ctest --test-dir build -C Release --output-on-failure   # 6 个用例
```

| ctest 用例 | 覆盖 |
|------------|------|
| `kcp_proxy_test` | doctest 单元测试：加解密与失败路径、SOCKS5 解析/应答、受限目标（SSRF）判定、FEC 编解码与服务端逐会话自适应、会话路由与半关闭、日志节流、配置行格式 |
| `kcp_proxy_smoke` | 打包与部署不变量（deb/zip 布局、systemd 模板、北京时区调度换算），以及**变更行的 clang-format 门禁** |
| `kcp_proxy_e2e_tunnel` | 离线端到端：SOCKS5 → KCP → 目标，字节级校验 |
| `kcp_proxy_e2e_robustness` | 错密钥、垃圾包洪泛、并发、会话回收、日志行格式 |
| `kcp_proxy_e2e_adversarial` | SOCKS5 协议滥用、多源洪泛（全局认证预算）、客户端会话上限、上游连接卡死、服务端重启与换密钥 |
| `kcp_proxy_e2e_fec_loss` | 8% 双向丢包下 FEC 修复生效（并有 `off` 对照组） |

格式门禁只在缺失 clang-format 时不硬失败；`KCP_REQUIRE_CLANG_FORMAT=1` 时缺失即失败（CI 的
hygiene job 就是这种模式），`KCP_SMOKE_DIFF_BASE` 指定比对基线。版本固定在 22，避免格式化结果
随**开发者本机**的 clang-format 漂移。

GUI：

```bash
cd gui/electron
npm run check     # JS 语法 + electron-builder 配置 JSON 校验
npm test          # node --test：密钥派生、参数拼装、启动契约
```

CI（`.github/workflows/ci.yml`）分五块：hygiene（空白检查、格式门禁、打包冒烟）、
gui-checks、build-linux、build-windows、build-macos。打 tag 触发 `release.yml`，
先校验 `CMakeLists.txt` 的 `project(... VERSION)` 与 tag 一致，再打包 deb / tar.gz / zip /
AppImage / NSIS / Portable 并合并 `SHA256SUMS` 发布。

## 版本与兼容性

- **0.2.2**：仅重构。181 处手写 `std::to_string` 拼接统一到 `fmt`，`secure_wipe` 改用
  `OPENSSL_cleanse`，删除死代码 `get_env`。协议、线格式、KCP 参数均无变化，0.2.1 与 0.2.2 可互连。
- **0.2.1**：修 0.2.0 发布后才被发现的缺陷——`--help` 退出码、日志级别注册竞态、格式门禁从未真正执行。
- **0.2.0**：基础设施迁移（spdlog / doctest / CLI11 / clang-format 门禁）。**破坏性变更：`-fec` → `--fec`**。
- 升级时**两端二进制一起换**。启用 FEC 时 GUI 两端也需要同版本。

日志行格式属于协议：`YYYY-MM-DD HH:MM:SS.mmm [LEVEL] module: message`。GUI 与 e2e 都会解析
`TRAFFIC tx=… rx=…`、`FAIL_STAGE=…`、`KCP config …` 这些行，改动措辞等同于改动协议。

## 排障

先看日志级别 `DEBUG` 下的启动横幅：`KCP config …` 与 `FEC config shards=…` 会打印两端实际参数，
参数不一致通常在这里就能看出来。

| 现象 | 常见原因 |
|------|----------|
| 客户端一直连不上 | UDP 8388 未放行；服务端未运行；地址写成域名但本地 DNS 不通 |
| 握手成功但立即断开 | 两端密钥不同（日期已变而客户端未重启，或后缀不一致） |
| 能连但极慢、周期性卡住 | 内核 UDP 缓冲被钳制（见[内核 UDP 缓冲](#内核-udp-缓冲重要)）；或链路上 UDP 被限速 |
| `DECRYPT_FAILED` 持续刷 | 密钥不匹配；服务端刚轮换而客户端仍持旧日期 |
| 浏览器部分站点异常 | 浏览器走了 QUIC/HTTP3，本代理不转发 UDP |
| 局域网其他设备连不上 | GUI 未勾选「允许局域网使用」（默认只绑 127.0.0.1） |

更多见 [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)；协议细节见
[docs/PROTOCOL.md](docs/PROTOCOL.md)，测试细节见 [docs/TESTING.md](docs/TESTING.md)。
