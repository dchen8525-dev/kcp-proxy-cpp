# kcp-proxy-cpp · AGENTS.md 任务收尾报告

> 生成于 2026-09-12。安卓侧第 2–4 项按用户要求**忽略**；本报告覆盖 C++ 侧其余全部清单项
> （第 1、5、6、7、8、9 项），并按 AGENTS.md 第 11 项的结构输出。

## 1. 发现的问题（Problems found）

- **构建链路彻底损坏**（环境层，非代码缺陷）：
  - `cmake` / `ctest` 不在 `PATH`，藏在 VS18 内置目录
    `C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin`。
  - `cmake --build` 每次先跑 `ZERO_CHECK` → 重配置 → 触发 `vcpkg install`，本机 vcpkg 检测 VS18 报
    `visualstudio.cpp(90): Value was null` 崩溃。
  - 沙箱环境同时设小写 `https_proxy` 与大写 `HTTPS_PROXY`，MSBuild 的 CL 任务把环境变量塞进大小写不敏感
    字典时撞键，报 `MSB6001 ... 已添加项 ... https_proxy/HTTPS_PROXY`——这是真正拦住构建的致命项。
- **KCP 参数双端日志不一致**（第 7 项）：仅服务端打印 KCP 配置行，客户端无，难以比对两端
  `conv/mtu/nodelay/interval/resend/nc/sndWnd/rcvWnd/timeout` 是否一致。
- **文档缺口**（第 5 项）：`docs/ANDROID_INTEROP.md` 缺失，而 `README.md` 引用了它的坏链接。
- **第 1 项（压缩长单行）**：经核查当前仓库 C++ 源码 / `CMakeLists.txt` / `docs/*.md` 均已是多行可读风格，
  AGENTS.md 描述的压缩态已不存在（后续多次重构提交已覆盖）。

## 2. C++ 文件变更（C++ files changed）

| 文件 | 项 | commit |
| --- | --- | --- |
| `src/kcp_proxy/config.hpp` | 第 7 项 | `b52a8bb` |
| `src/kcp_proxy/kcp_wrapper.cpp` | 第 7 项 | `b52a8bb` |
| `src/kcp_proxy/server.cpp` | 第 7 项 | `b52a8bb` |
| `src/kcp_proxy/client.cpp` | 第 7 项 | `b52a8bb` |
| `src/kcp_proxy/kcp_client_session.hpp` | 第 7 项 | `b52a8bb` |
| `docs/ANDROID_INTEROP.md`（新增） | 第 5 项 | `10282ef` |
| `gui/electron/*`（开机自启移除，同仓非 C++ 范围） | — | `34ca132` |
| `build/CMakeCache.txt`（本地缓存调整） | 构建环境 | 被 gitignore，未提交 |

## 3. 修复实现（Fixes implemented）

- **第 7 项 — KCP 参数一致性**：`config.hpp` 把 KCP 调优常量提升为具名 `constexpr`；新增 `kcp_config_line()`
  渲染规范日志串；`kcp_wrapper::configure()` 改用这些常量；`server.cpp` / `client.cpp` 启动各打印同一行
  `"KCP config conv=1 mtu=1400 nodelay=1 interval=10 resend=5 nc=1 sndWnd=256 rcvWnd=512 timeout=60s"`；
  客户端会话用 `KCP_CONV` 替代魔数。
- **第 5 项 — Android 互操作文档**：新建 `docs/ANDROID_INTEROP.md`，含 Windows 启动命令、Windows Firewall
  UDP 8388 规则、Android 模拟器端点 `10.0.2.2:8388`、实测抓到的 C++ 日志、Android 预期日志、Chrome 测试 URL、
  失败阶段映射；同时修复了 `README.md` 指向它的坏链接。
- **构建环境修复**（本地，不提交）：`build/CMakeCache.txt` 设 `VCPKG_MANIFEST_INSTALL:BOOL=OFF`，
  显式写 `CMAKE_C_COMPILER` / `CMAKE_CXX_COMPILER` / `CMAKE_LINKER` 指向 `cl.exe` / `link.exe`，
  构建前 `unset` 所有代理变量（大小写都清）。

## 4. 测试新增 / 更新（Tests added/updated）

- C++ 单测：`ctest` 中 `kcp_proxy_test` **1/1 Passed**（无新增用例；第 7 项改动由运行时启动日志验证）。
- GUI（electron）`node --test`：15 项中 14 通过；唯一失败的 `test/pipelined-smoke.js` 依赖外部代理监听
  `11080`，属环境相关，与本轮改动无关（且本机当前无 `node_modules`）。

## 5. C++ 构建 / CTest 结果（C++ build / CTest result）

- Release 构建全绿：`kcp-proxy-server.exe` / `kcp-proxy-client.exe` / `kcp_proxy_test.exe` 均编译通过。
- `ctest --test-dir build -C Release --output-on-failure` → **1/1 Passed**。
- `git diff --check` → 工作区干净（无空白错误、无未提交改动）。

## 6. C++ 本地 curl 端到端结果（C++ local curl result）

```
build/Release/kcp-proxy-server.exe -H 0.0.0.0 -p 8388 -k remote_test_key_123456 -L INFO
build/Release/kcp-proxy-client.exe -s 127.0.0.1 -p 8388 -H 127.0.0.1 -l 1080 -k remote_test_key_123456 -L INFO
curl -x socks5h://127.0.0.1:1080 http://neverssl.com
→ HTTP 200  size=3961
```

server 日志呈现完整生命周期（会话创建 / 关闭、SOCKS5 目标、握手、连接成功、traffic 汇总），
**INFO 无 UDP/KCP 包级刷屏** → 第 8 项合规、第 9 项通过。

## 7. 安卓侧（已忽略）

第 2 项（SOCKS5 响应缓冲测试）、第 3 项（CPP_REMOTE 会话清理）、第 4 项（远端状态不误导）均未做，
按用户要求忽略，不在本轮范围。

## 8. 剩余风险（Remaining risks）

- 安卓第 2–4 项未做（用户忽略）。
- 第 1 项若将来要统一 `clang-format` 风格：本机未装 LLVM / `clang-format`（VS18 仅含 MSVC），需另装或用
  IDE 格式化；当前代码已可读，非阻塞。
- `build/CMakeCache.txt` 的本地修改不提交（`gitignore`）。他人在新机器**首次** `configure` 仍可能踩
  vcpkg / VS18 检测坑——建议把「`VCPKG_MANIFEST_INSTALL=OFF` + 显式编译器路径 + `unset` 代理」固化进
  `build_vs.bat` 或在 README / CI 注明。
- GUI 的 `pipelined-smoke` 测试需带 `node_modules` 的环境才能跑，本机未验证。
