# KCP Proxy Client - Electron GUI

基于 Electron 的现代化 GUI 客户端，支持 Windows 和 Linux 平台。

## 特性

- 现代化 Win11 风格界面
- 系统托盘支持
- 开机自启动
- 实时日志显示
- 自动检测进程状态
- 轻量级、跨平台

## 安装依赖

```bash
cd gui/electron
npm install
```

## 开发模式运行

```bash
npm start
```

## 打包为可执行文件

### Windows:
```bash
npm run build:win
```

打包结果：`dist/KCP-Proxy-Client-<版本>-Setup.exe`

安装程序为完整向导（非一键安装）：
- 可选安装目录
- 可选创建桌面/开始菜单快捷方式
- 安装完成后可选立即运行

### Linux:
```bash
npm run build:linux
```

打包结果：`dist/kcp-proxy-client-<版本>.AppImage`

## 配置文件

配置保存在：
- Windows: `%APPDATA%/kcp-proxy-gui/config.json`
- Linux: `~/.config/kcp-proxy-gui/config.json`

## 功能说明

### 服务器设置
- **地址**: 服务器 IP 或域名
- **端口**: 服务器端口（默认 8388）
- **本地 SOCKS 端口**: 本地代理端口（默认 1080）

### 密钥模式
1. **每日密钥**: 北京日期 (YYYYMMDD) + 后缀
   - 例如：日期为 20260818，后缀为 `xyz`，密钥为 `20260818xyz`
2. **固定密钥**: 手动输入密钥（至少 16 个字符）

### 按钮说明
- **保存设置**: 保存当前配置
- **启动代理**: 启动 kcp-proxy-client 进程
- **停止代理**: 停止代理进程
- **开机自动启动**: 勾选后随系统启动

## 注意事项

1. 首次运行前需要先构建 `kcp-proxy-client` 二进制文件
2. Windows 下需要 `kcp-proxy-client.exe` 在以下位置之一：
   - 与 GUI 同目录
   - `bin/windows/kcp-proxy-client.exe`
   - `build/Release/kcp-proxy-client.exe`
3. 关闭窗口不会退出程序，会最小化到系统托盘
4. 右键托盘图标可快速启动/停止代理

## 开发技术栈

- Electron 28+
- 原生 HTML/CSS/JavaScript（无框架依赖）
- electron-store（配置持久化）
- electron-builder（打包）

## 文件结构

```
gui/electron/
├── main.js          # 主进程（进程管理、托盘、配置）
├── preload.js       # 预加载脚本（安全 API 暴露）
├── index.html       # 主界面
├── renderer.js      # 渲染进程（界面交互）
├── styles.css       # 样式表
├── assets/          # 图标等资源
├── package.json     # 项目配置
└── README.md        # 本文件
```

## 许可证

MIT