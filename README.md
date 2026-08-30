# KCP Proxy (C++)

基于 KCP 协议的 SOCKS5 代理，将 TCP 流量通过加密的 KCP (UDP) 隧道进行转发。

```
本地应用 --TCP--> 客户端 SOCKS5 --[加密/KCP/UDP]--> 服务端 --TCP--> 目标服务器
```

## 目录与发布产物

脚本的规范实现按职责位于 `scripts/runtime/`、`scripts/deploy/`、`scripts/package/` 和 `scripts/templates/`，根目录只保留 4 个入口：`build.sh`、`build_vs.bat`、`deploy.sh`、`deploy.bat`（后两者转发到 `scripts/deploy/deploy.py`）。`build/` 是 CMake 临时目录，`bin/` 是本地构建二进制，`dist/staging/` 是临时打包目录，`dist/releases/` 保存正式发布包。

Electron (`gui/electron`) 是主 GUI，提供跨平台的图形界面。


- SOCKS5 CONNECT TCP 代理支持（不支持 UDP ASSOCIATE）
- KCP 可靠 UDP 传输（极速模式，10ms 刷新间隔）
- AES-128-GCM 加密，方向标识防跨方向重放，滑动窗口检测重放包
- 基于 Asio 的全异步架构，无阻塞调用
- 服务端单 UDP Socket 多路复用所有会话

## 构建

项目使用 **vcpkg** 管理依赖，**CMake** 构建。依赖项：

| 依赖 | 来源 | 说明 |
|------|------|------|
| OpenSSL | vcpkg | TLS / AES-128-GCM |
| Asio | vcpkg | 异步网络库（standalone，无 Boost） |
| KCP | vcpkg | 可靠 UDP 传输 |

### 通用前置条件

- **CMake 3.22+**
- **vcpkg**（脚本会自动检测或引导安装，见下方说明）

克隆仓库后即可构建：

```bash
git clone https://github.com/dchen8525-dev/kcp-proxy-cpp.git
cd kcp-proxy-cpp
```

### Linux / macOS

**前置依赖：**
- GCC 7+（或 Clang 6+）
- make / ninja（任选构建工具）

**一键构建：**

```bash
./build.sh
```

**手动构建：**

```bash
# 设置 VCPKG_ROOT（如果尚未设置）
export VCPKG_ROOT=/path/to/vcpkg

cmake --preset default
cmake --build --preset release
```

**本地 CPU 优化（可选）：**

默认构建使用通用指令集，便于分发。如需针对本机 CPU 优化（`-march=native`），configure 时开启：

```bash
cmake -B build -DKCP_PROXY_ENABLE_NATIVE_TUNE=ON
```

> **不要**用该选项构建发布包：`-march=native` 产物可能含目标用户 CPU 不支持的指令（如 AVX-512），在旧机器上会非法指令崩溃。CI 打包流程保持默认关闭。

### Windows (MSVC)

**前置依赖：**
- Visual Studio 2019 或更高版本（Community / Professional / Enterprise / BuildTools），需安装 **"使用 C++ 的桌面开发"** 工作负载
- CMake 3.22+（VS 安装器中勾选 "C++ CMake 工具 for Windows" 可一并安装）
- Git for Windows

**一键构建：**

```powershell
.\build_vs.bat
```

脚本会自动：
1. 检测并设置 MSVC 编译环境
2. 按优先级选择 vcpkg：用户 `VCPKG_ROOT` 环境变量 > 项目本地 `vcpkg/` > 自动克隆并引导安装
3. 通过 vcpkg 安装依赖（asio、openssl、kcp）
4. CMake 配置、编译并输出到 `bin\windows\`

**手动构建：**

```powershell
# 设置 VCPKG_ROOT（如果尚未设置）
$env:VCPKG_ROOT = "C:\path\to\vcpkg"

cmake --preset default
cmake --build --preset release --parallel
```

### vcpkg 说明

构建时会自动使用 vcpkg 安装依赖。vcpkg 的查找优先级：

1. 环境变量 `VCPKG_ROOT` 指向的 vcpkg 实例
2. 项目目录下的 `vcpkg/` 文件夹
3. 如果都不存在，脚本会自动从 GitHub 克隆并引导安装

> **注意：** 不建议使用 VS 内置的 vcpkg 实例（位于 `BuildTools\VC\vcpkg`），它可能缺少 `builtin-baseline` 支持。脚本会自动跳过它，使用项目本地 vcpkg。

### CMake Presets

| Preset | 说明 |
|--------|------|
| `default` | 默认配置（使用 vcpkg 工具链） |
| `release` | Release 构建 |
| `debug` | Debug 构建 |

构建产物：
- `kcp-proxy-server` — 服务端
- `kcp-proxy-client` — 客户端
- 输出目录：`build/`（多配置：`build/Release/`、`build/Debug/`）
- 一键构建会自动复制到 `bin/linux/` 或 `bin/windows/`

## 部署与使用

### 服务端部署（Ubuntu/Debian）

#### 方法1：使用deb包（推荐）

从 [GitHub Releases](https://github.com/dchen8525-dev/kcp-proxy-cpp/releases) 下载最新的deb包：

```bash
# 下载deb包（以v0.3.0为例）
wget https://github.com/dchen8525-dev/kcp-proxy-cpp/releases/download/v0.3.0/kcp-proxy-server_0.3.0_amd64.deb

# 安装
sudo dpkg -i kcp-proxy-server_0.3.0_amd64.deb

# 启动服务
sudo systemctl start kcp-proxy-server

# 设置开机自启
sudo systemctl enable kcp-proxy-server

# 查看状态
sudo systemctl status kcp-proxy-server
```

**配置说明**：
- 服务自动监听 UDP 8388 端口
- 密钥配置：`/etc/kcp-proxy/server.env`
- 日志查看：`journalctl -u kcp-proxy-server -f`
- 默认密钥：Beijing Date (YYYYMMDD) + suffix

#### 方法2：从源码部署

如果需要自定义构建，可以使用一键部署脚本：

```bash
# 先构建Linux二进制
./build.sh

# 部署到远程服务器
./deploy.sh root@your-server-ip

# 可选参数
./deploy.sh root@1.2.3.4 -P 2222              # 自定义SSH端口
./deploy.sh root@1.2.3.4 --suffix 'MyS3cret!'  # 自定义密钥后缀
./deploy.sh root@1.2.3.4 --uninstall           # 卸载
```

---

### 客户端使用（Windows GUI）

#### 下载与安装

从 [GitHub Releases](https://github.com/dchen8525-dev/kcp-proxy-cpp/releases) 下载Windows GUI客户端：

```
KCP-Proxy-Client-Windows-v0.3.0.zip (106MB)
```

解压后运行 `KCP Proxy Client.exe`。

#### GUI使用步骤

1. **配置服务器**：
   - 地址：填写服务器IP或域名（例如：`example.com` 或 `192.168.1.100`）
   - 端口：默认 `8388`
   - 本地SOCKS端口：默认 `1080`

2. **配置密钥**：
   - 选择"固定密钥"模式
   - 输入密钥（至少16字符）
   - 或选择"每日密钥"模式（Beijing Date + suffix）

3. **启动代理**：
   - 点击「启动代理」按钮
   - 查看日志确认连接成功

4. **使用代理**：
   - 浏览器或其他应用配置SOCKS5代理：`127.0.0.1:1080`
   - 测试连接：`curl -x socks5h://127.0.0.1:1080 https://example.com`

#### GUI特性

- ✅ 系统托盘支持（关闭窗口不退出）
- ✅ 开机自启动选项
- ✅ 实时日志显示
- ✅ 托盘快速启动/停止
- ✅ 配置自动保存

#### 密钥模式说明

**固定密钥**：
- 手动输入密钥（至少16字符）
- 例如：`remote_test_key_123456`

**每日密钥**：
- 格式：`YYYYMMDD` + suffix
- 例如：日期`20260818`，后缀`abc` → 密钥`20260818abc`
- 服务端每天自动轮换

---

### 防火墙配置

**服务端（Ubuntu）**：

```bash
# 开放UDP 8388端口
sudo ufw allow 8388/udp
sudo ufw reload

# 或使用iptables
sudo iptables -A INPUT -p udp --dport 8388 -j ACCEPT
```

---

### 测试连接

**通过GUI客户端**：
1. 启动GUI，填写服务器地址和密钥
2. 点击「启动代理」
3. 浏览器配置代理：`127.0.0.1:1080`
4. 访问网站测试

**验证代理**：
```bash
# Windows (PowerShell)
curl -x socks5h://127.0.0.1:1080 https://httpbin.org/ip

# 应该返回服务器的IP地址
```

## 运行参数（可选）

如果需要使用命令行版本（高级用户）：

### 服务端命令行

```bash
kcp-proxy-server -k <密钥> [-H 0.0.0.0] [-p 8388] [-L info]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-k, --key` | （必填） | 加密密钥，最少 16 字符 |
| `-H, --host` | `0.0.0.0` | UDP 绑定地址 |
| `-p, --port` | `8388` | UDP 监听端口 |
| `-L, --log-level` | `INFO` | 日志级别 |

### 客户端命令行

```bash
kcp-proxy-client -s <服务端地址> -k <密钥> [-p 8388] [-H 127.0.0.1] [-l 1080]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-s, --server` | （必填） | 远端 KCP 服务端地址 |
| `-k, --key` | （必填） | 加密密钥，最少 16 字符 |
| `-p, --server-port` | `8388` | 远端 KCP 服务端端口 |
| `-H, --listen-host` | `127.0.0.1` | 本地 SOCKS5 监听地址 |
| `-l, --listen-port` | `1080` | 本地 SOCKS5 监听端口 |
| `-L, --log-level` | `INFO` | 日志级别 |

**推荐**：普通用户使用Electron GUI，更直观易用。

## 协议与加密

每个本地 TCP 连接会创建一个独立 KCP/UDP 会话。C++ 客户端会先在 KCP 内发送认证加密的
`KCP_PROXY_HELLO_V1`，服务端返回 `KCP_PROXY_HELLO_ACK_V1` 后客户端才把该会话标记为 connected。
作为兼容模式，服务端也接受首个有效加密 KCP payload 直接是 SOCKS5 CONNECT 请求（不要求 HELLO）。
超时、错密钥、服务端未运行或 UDP 被阻断都会导致连接失败。

密钥字符串不会直接 SHA-256 截断。实现使用 HKDF-SHA256 派生 AES-128-GCM 密钥：

- cipher: `AES-128-GCM`
- HKDF salt: 固定字符串 `kcp-proxy-hkdf-salt-v1` 拼接 16 字节随机 per-session salt
- client -> server info: `kcp-proxy/c2s/v1`
- server -> client info: `kcp-proxy/s2c/v1`
- tag length: 16 bytes
- CLI 最小密钥长度: 16 字符
- wire format: `[session_salt(16)][nonce(12)][ciphertext][tag(16)]`

每个会话由客户端生成 16 字节随机 salt（明文随每包携带），双方用 `PSK + salt` 通过 HKDF 派生
独立的会话密钥，保证各会话计数器/nonce 永不跨会话复用（AES-GCM nonce 复用的后果是灾难性的）。
服务端拒绝任何与在线会话共享同一 salt 的新会话。

Nonce（12 字节）结构为：

```
[8 字节单调递增计数器][1 字节方向标识][3 字节零填充]
```

计数器起始值由 salt 前 6 字节派生（大端），使 nonce 序列即使在被强制共享密钥的会话间也唯一。

方向标识：客户端 `0x01`，服务端 `0x02`，防止跨方向重放攻击。普通接收端维护 2048-bit 滑动窗口
检测重放包；服务端首次包预认证（首个数据包即建立会话并播种重放窗口），不使用全局重放窗口。
单个会话达到 2^48 次加密后拒绝继续加密，需重新建立连接。

服务端会拦截指向回环/私网/链路本地/组播等受限地址的 CONNECT（SSRF 防护），并对未认证来源的
会话建立尝试做每秒限速，避免垃圾 UDP 洪泛耗尽 CPU。

SOCKS5 支持范围：

- 支持 `CONNECT`
- 支持地址类型 `IPv4`、`IPv6`、`DOMAIN`
- 不支持 `UDP ASSOCIATE` 和 `BIND`，会返回 SOCKS5 command not supported
- 不转发 QUIC/HTTP3、UDP DNS 等 UDP 流量；浏览器如需稳定通过本代理访问，请禁用 QUIC/HTTP3

## 架构

```
KCPProxyClient (客户端)
  ├── TCP Acceptor (本地 SOCKS5 监听)
  └── 每个 TCP 连接创建:
      ├── Crypto (加密实例)
      └── KCPClientSession (独立 UDP Socket + KcpWrapper)

KCPServer (服务端)
  ├── 单个 UDP Socket (所有会话共享)
  └── unordered_map<ip:port, KCPSession>
      └── 每个 KCPSession:
          ├── KcpWrapper (KCP 状态机)
          └── Crypto (加密实例)
```

- **KcpWrapper** — 对 vendored `ikcp` 的 C++ RAII 封装，通过输出回调将 KCP 产生的数据交给加密层和 UDP 发送
- **Crypto** — AES-128-GCM 加解密，单调递增 Nonce 计数器
- **KCPSession** — 服务端会话，每个客户端端点一个，共享服务端 UDP Socket
- **KCPClientSession** — 客户端会话，每个 TCP 连接一个，独立 UDP Socket
- **KCPServer** — 服务端主类，管理会话映射，定期清理超时会话（60 秒）
- **KCPProxyClient** — 客户端主类，接受本地 SOCKS5 连接，内联处理 SOCKS5 握手

## 目录结构

```text
kcp-proxy-cpp/
├── README.md              # 项目主文档
├── AGENTS.md              # AI开发指南
├── CLAUDE.md              # Claude AI指南
├── CMakeLists.txt         # CMake配置
├── CMakePresets.json      # CMake预设
├── vcpkg.json             # vcpkg依赖管理
├── build.sh               # Linux/macOS构建脚本
├── build_vs.bat           # Windows构建脚本
├── deploy.sh / deploy.bat # 部署快捷入口（转发到 scripts/deploy/deploy.py）
│
├── src/                   # 源代码
│   └── kcp_proxy/         # 核心库实现
│       ├── *.hpp          # 头文件
│       ├── *.cpp          # 实现文件
│       ├── main_server.cpp # 服务端入口
│       └── main_client.cpp # 客户端入口
│
├── tests/                 # 测试代码
│   ├── smoke/             # 烟雾测试
│   └── unit/              # 单元测试
│
├── docs/                  # 文档
│   ├── TESTING.md         # 测试指南
│   └── ANDROID_INTEROP.md # Android互操作说明
│
├── scripts/               # 脚本（按职责分类）
│   ├── deploy/            # 部署脚本
│   │   ├── deploy.py      # 一键远程部署（Python3，仅标准库 + 系统 ssh/scp）
│   │   ├── install-service.sh   # systemd安装
│   │   └── uninstall-service.sh # 卸载服务
│   ├── package/           # 打包脚本
│   │   └── package.py     # 统一打包（Python3.12，纯标准库，跨平台）
│   ├── runtime/           # 运行时脚本
│   │   └── common.sh      # 共享配置（suffix、端口等）
│   └── templates/         # 配置模板
│       ├── kcp-proxy-server-key-refresh.service # 密钥轮换 service
│       └── kcp-proxy-server-key-refresh.timer   # 密钥轮换 timer
│
├── gui/                   # GUI客户端
│   ├── electron/          # Electron GUI（主GUI，推荐）
│   │   ├── main.js        # 主进程
│   │   ├── renderer.js    # 渲染进程
│   │   ├── package.json   # Node.js依赖
│   │   └── dist/          # 构建产物（.gitignore）
│   └── windows/           # Windows原生GUI（legacy）
│       └── KcpProxyGui/   # C# WinForms实现
│
├── build/                 # CMake构建目录（.gitignore）
├── bin/                   # 编译产物（.gitignore）
│   ├── linux/             # Linux二进制
│   │   ├── kcp-proxy-server
│   │   └── kcp-proxy-client
│   └── windows/           # Windows二进制
│       ├── kcp-proxy-server.exe
│       ├── kcp-proxy-client.exe
│       └── *.dll          # 依赖DLL
│
└── dist/                  # 发布包（.gitignore）
    ├── *.deb              # Debian包
    └── *.zip              # Windows GUI包
```

### 主要目录说明

**源代码与测试**：
- `src/kcp_proxy/` - 核心实现，包括服务端、客户端、加密、KCP封装
- `tests/unit/` - 单元测试，覆盖加密、SOCKS5解析等核心功能
- `tests/smoke/` - 烟雾测试，验证基本功能

**脚本与部署**：
- `scripts/deploy/` - 远程部署脚本，支持一键部署到服务器
- `scripts/package/package.py` - 统一打包入口（Python3.12，纯标准库，Linux/macOS/Windows 通用）：
  - `python3 scripts/package/package.py standalone` - CLI 发布包（linux/macos 打 tar.gz，windows 打 zip）
  - `python3 scripts/package/package.py deb` - Debian 服务包（有 dpkg-deb 时优先用，否则用标准库构造）
- `scripts/runtime/` - 运行时脚本，本地启动服务端/客户端
- `scripts/templates/` - 配置模板，服务端环境变量等

**GUI客户端**：
- `gui/electron/` - **主GUI**，基于Electron，支持Windows/Linux/macOS
  - 现代化界面，系统托盘支持
  - 开机自启动，实时日志显示

**构建与发布**：
- `build/` - CMake构建目录，包含中间产物
- `bin/` - 编译后的二进制文件，按平台分目录
- `dist/` - 最终发布包（deb、zip等）

**文档**：
- `docs/TESTING.md` - 测试指南和流程
- `docs/ANDROID_INTEROP.md` - Android客户端互操作说明
- `AGENTS.md` - AI开发助手指南
- `CLAUDE.md` - Claude AI特定指南

**配置文件**：
- `CMakeLists.txt` - CMake构建配置（必须在根目录）
- `CMakePresets.json` - CMake预设，简化构建命令
- `vcpkg.json` - vcpkg依赖清单（OpenSSL、Asio、KCP）

**快捷脚本**：
- `build.sh` / `build_vs.bat` - 一键构建
- `deploy.sh` / `deploy.bat` - 部署快捷入口（转发到 `scripts/deploy/deploy.py`）

**文档**：
- `README.md` - 项目主文档（本文件）
- `AGENTS.md` / `CLAUDE.md` - AI开发指南

### 根目录文件说明

## 依赖

| 依赖 | 来源 |
|------|------|
| OpenSSL | vcpkg |
| Asio | vcpkg（standalone，无 Boost） |
| KCP | vcpkg |

KCP 基于 UDP 的可靠 ARQ 协议，以极速模式运行：`conv=1`，`mtu=1400`，`nodelay=1`，`interval=10ms`，`fast resend=5`，`nc=1`，发送窗口 `256`，接收窗口 `512`，会话超时 `60s`。

更多协议、测试和排障细节见 `docs/PROTOCOL.md`、`docs/TESTING.md`、`docs/TROUBLESHOOTING.md`。
