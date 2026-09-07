const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const dns = require('dns');
const net = require('net');
const zlib = require('zlib');
const { generateKey: buildKey, validateLaunchConfig } = require('./utils');

// Auto-updater (electron-updater) — loaded lazily to keep dev/preview simple.
let autoUpdater = null;
try {
  const updater = require('electron-updater');
  autoUpdater = updater.autoUpdater || null;
} catch (err) {
  console.error('electron-updater unavailable:', err.message);
}

// ── Lightweight config store (replaces electron-store, saves ~2.5MB in ASAR) ──
class ConfigStore {
  constructor(defaults) {
    this.defaults = defaults;
    this.filePath = null; // set on first use, after app is ready/paths available
    this._data = null;
  }

  // lazy init to guarantee app.getPath('userData') is available
  _ensure() {
    if (!this.filePath) {
      this.filePath = path.join(app.getPath('userData'), 'config.json');
    }
    if (this._data) return;
    try {
      const raw = fs.readFileSync(this.filePath, 'utf-8');
      this._data = { ...this.defaults, ...JSON.parse(raw) };
    } catch {
      this._data = { ...this.defaults };
    }
  }

  get store() {
    this._ensure();
    return { ...this._data };
  }

  get(key) {
    this._ensure();
    return this._data[key] !== undefined ? this._data[key] : this.defaults[key];
  }

  set(key, value) {
    this._ensure();
    this._data[key] = value;
    try {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.filePath, JSON.stringify(this._data, null, 2), 'utf-8');
    } catch (err) {
      console.error('Failed to save config:', err.message);
    }
  }
}

// Persistent configuration storage
const store = new ConfigStore({
  serverHost: '',
  serverPort: '8388',
  localPort: '1080',
  keySuffix: '',
  autoReconnect: true, // Auto reconnect on disconnect
  reconnectDelay: 3000, // Delay before reconnect (ms)
  maxReconnectAttempts: 10, // Max reconnect attempts (0 = unlimited)
  legacyAutoStartCleared: false // One-time cleanup of the removed 开机自启 registry entry
});

// ── File-backed log (rotation at ~1MB, keeps one backup) ──
const MAX_LOG_BYTES = 1024 * 1024;
let appLogPath = null; // lazily initialized after app ready

function writeLogFile(level, message) {
  try {
    if (!appLogPath) {
      const logDir = path.join(app.getPath('userData'), 'logs');
      if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
      appLogPath = path.join(logDir, 'app.log');
    }

    // Rotate when the current log exceeds the cap
    try {
      if (fs.existsSync(appLogPath) && fs.statSync(appLogPath).size > MAX_LOG_BYTES) {
        fs.renameSync(appLogPath, appLogPath + '.1');
      }
    } catch { /* rotation is best-effort */ }

    const line = `[${new Date().toISOString()}] [${level}] ${message}\n`;
    fs.appendFileSync(appLogPath, line, 'utf-8');
  } catch (err) {
    console.error('Failed to write log file:', err.message);
  }
}

let mainWindow = null;
let tray = null;
// Menu shown by the tray. Kept in a module-level variable because Electron's
// Tray exposes NO public `contextMenu` property (only setContextMenu), so
// updateStatus() cannot reach the menu through the tray object.
let trayMenu = null;
let clientProcess = null;
let isRunning = false;
let reconnectAttempts = 0;
let reconnectTimer = null;
let isManualStop = false; // Track if user manually stopped

// Path to kcp-proxy-client executable
function getClientPath() {
  const executable = process.platform === 'win32'
    ? 'kcp-proxy-client.exe'
    : 'kcp-proxy-client';

  const candidates = [
    path.join(process.resourcesPath, executable),
    // Dev-mode layout: gui/electron -> ../../bin/windows (repo root's bin dir).
    path.join(__dirname, '../../bin', process.platform === 'win32' ? 'windows' : process.platform, executable),
    path.join(__dirname, '../../../build/Release', executable),
    path.join(__dirname, executable)
  ];

  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

// Generate key based on mode (Beijing date + suffix, or fixed key)
function generateKey() {
  return buildKey('daily', { suffix: store.get('keySuffix') });
}

// Create main window
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 520,
    height: 680,
    minWidth: 480,
    minHeight: 600,
    frame: false, // Frameless for custom title bar
    transparent: false,
    backgroundColor: '#f5f5f5',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      // The preload bridges utils.js (validateLaunchConfig/formatBytes) to the
      // renderer via require('./utils'). A sandboxed preload's polyfilled
      // require only serves electron/events/timers/url and rejects local
      // files, which killed the whole preload — and with it every button in
      // the UI. Disable the sandbox so the preload keeps full Node require;
      // the renderer itself stays isolated (contextIsolation + no
      // nodeIntegration) and loads only local, CSP-restricted content.
      sandbox: false
    },
    icon: path.join(__dirname, 'assets/icon.png'),
    show: false
  });

  mainWindow.loadFile('index.html');

  // Show the window when ready. A launch carrying --hidden starts minimized
  // to the tray; that flag is only ever passed by a legacy "开机自启"
  // registry Run entry left behind by an older build (cleared on startup, see
  // removeLegacyAutoStartEntry). A normal, user-initiated launch must always
  // show the main window.
  mainWindow.once('ready-to-show', () => {
    if (process.argv.includes('--hidden')) {
      if (!store.get('hasHiddenOnce')) {
        tray?.displayBalloon({
          title: 'KCP Proxy Client',
          content: '程序已随系统启动并最小化到系统托盘，点击托盘图标可打开主界面'
        });
        store.set('hasHiddenOnce', true);
      }
    } else {
      mainWindow.show();
    }
  });

  // Hide to tray instead of closing
  mainWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();

      // Show notification on first hide
      if (!store.get('hasHiddenOnce')) {
        tray?.displayBalloon({
          title: 'KCP Proxy Client',
          content: '程序已最小化到系统托盘，点击托盘图标可重新打开'
        });
        store.set('hasHiddenOnce', true);
      }
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Keep the custom maximize button's glyph in sync (covers double-click on
  // the drag region and Win+Up as well as our own button).
  const sendMaximizeState = () => {
    mainWindow?.webContents.send('maximize-state', mainWindow.isMaximized());
  };
  mainWindow.on('maximize', sendMaximizeState);
  mainWindow.on('unmaximize', sendMaximizeState);
}

// Create system tray
function createTray() {
  let icon;

  // Try multiple icon paths
  const iconPaths = [
    path.join(__dirname, 'assets/icon.png'),
    path.join(__dirname, 'assets/icon.ico'),
    path.join(process.resourcesPath, 'assets/icon.png'),
    path.join(process.resourcesPath, 'assets/icon.ico')
  ];

  for (const iconPath of iconPaths) {
    if (fs.existsSync(iconPath)) {
      try {
        icon = nativeImage.createFromPath(iconPath);
        if (!icon.isEmpty()) {
          break;
        }
      } catch (err) {
        console.error('Failed to load icon:', iconPath, err);
      }
    }
  }

  // Fallback: create icons programmatically (running = green, stopped = gray)
  if (!icon || icon.isEmpty()) {
    icon = createStatusIcon(false); // Start with stopped icon
  }

  try {
    tray = new Tray(icon.resize({ width: 16, height: 16 }));
  } catch (err) {
    console.error('Failed to create tray:', err);
    return;
  }

  const contextMenu = Menu.buildFromTemplate([
    {
      label: '显示主界面',
      click: () => {
        mainWindow.show();
        mainWindow.focus();
      }
    },
    { type: 'separator' },
    {
      id: 'tray-start',
      label: '启动代理',
      click: () => startProxy()
    },
    {
      id: 'tray-stop',
      label: '停止代理',
      click: () => stopProxy()
    },
    { type: 'separator' },
    {
      label: '退出',
      click: () => {
        app.isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setToolTip('KCP Proxy Client');
  tray.setContextMenu(contextMenu);
  trayMenu = contextMenu;

  tray.on('double-click', () => {
    mainWindow.show();
    mainWindow.focus();
  });
}

// Minimal RGBA PNG encoder (zlib-based). nativeImage does NOT decode SVG data
// URLs (returns an empty image), so the status icon is emitted as a real PNG
// buffer instead of an <svg> string.
function encodePng(rgba, width, height) {
  // PNG signature
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  // IHDR: 8-bit RGBA, no interlace
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  // Raw image: each scanline prefixed with filter byte 0
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0;
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const idat = zlib.deflateSync(raw);

  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const typeBuf = Buffer.from(type, 'ascii');
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
    return Buffer.concat([len, typeBuf, data, crc]);
  };

  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    chunk('IDAT', idat),
    chunk('IEND', Buffer.alloc(0))
  ]);
}

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// Create status icon programmatically (green = running, gray = stopped)
function createStatusIcon(running) {
  const color = running ? [0x10, 0x7c, 0x10, 0xff] : [0x61, 0x61, 0x61, 0xff]; // Green or Gray
  const size = 16;
  const cx = 8, cy = 8, r = 6.5; // 16x16 circle with 1.5px margin

  // Build RGBA pixel buffer (transparent background + solid circle)
  const pixels = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = x + 0.5 - cx;
      const dy = y + 0.5 - cy;
      const off = (y * size + x) * 4;
      if (Math.sqrt(dx * dx + dy * dy) <= r) {
        pixels[off] = color[0];
        pixels[off + 1] = color[1];
        pixels[off + 2] = color[2];
        pixels[off + 3] = color[3];
      }
    }
  }

  return nativeImage.createFromBuffer(encodePng(pixels, size, size));
}

// Start proxy client process
async function startProxy(opts = {}) {
  if (isRunning) return;

  // Reset reconnect state on manual start. Auto-reconnect calls skip this so the
  // maxReconnectAttempts budget isn't zeroed on every reconnect cycle.
  if (!opts.fromAutoReconnect) {
    isManualStop = false;
    reconnectAttempts = 0;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  }

  const clientPath = getClientPath();
  if (!clientPath) {
    const msg = `未找到 ${process.platform === 'win32' ? 'kcp-proxy-client.exe' : 'kcp-proxy-client'}`;
    sendLog(msg, 'error');
    // Only show a modal for user-initiated starts — not during auto-reconnect.
    if (!opts.fromAutoReconnect) {
      dialog.showErrorBox('错误', msg + '\n请先构建客户端。');
    }
    return;
  }

  const serverHost = store.get('serverHost');
  const serverPort = store.get('serverPort');
  const localPort = store.get('localPort');

  // Single validation pass over all launch parameters (shared with unit tests)
  const validationError = validateLaunchConfig({
    serverHost,
    serverPort,
    localPort,
    keyMode: 'daily',
    keySuffix: store.get('keySuffix')
  });
  if (validationError) {
    sendLog(validationError, 'error');
    // Only show a modal for user-initiated starts — not during auto-reconnect.
    if (!opts.fromAutoReconnect) {
      dialog.showErrorBox('错误', validationError);
    }
    return;
  }

  const key = generateKey();

  const args = [
    '-s', serverHost,
    '-p', serverPort,
    '-H', '127.0.0.1',
    '-l', localPort,
    '-L', 'info'
  ];

  try {
    clientProcess = spawn(clientPath, args, {
      cwd: path.dirname(clientPath),
      stdio: ['ignore', 'pipe', 'pipe'],
      // Pass the key via the environment, NOT argv: the command line of a
      // process is visible to every local user (Task Manager / wmic), while
      // the environment is readable only by the same user.
      env: { ...process.env, KCP_PROXY_KEY: key }
    });

    isRunning = true;
    updateStatus(true);
    sendLog(`已启动: ${clientPath} server=${serverHost}:${serverPort} socks5=127.0.0.1:${localPort} key_mode=daily key_len=${key.length}`, 'info');

    // Capture stdout (client rarely uses it — everything goes to stderr)
    const pushStdoutLine = createLogLineStream((line) => sendLog(line, 'info'));
    clientProcess.stdout.on('data', (data) => pushStdoutLine(data));

    // Capture stderr (client logs to stderr)
    const pushStderrLine = createLogLineStream(handleClientLine);
    clientProcess.stderr.on('data', (data) => pushStderrLine(data));

    // Handle process exit
    clientProcess.on('close', (code) => {
      isRunning = false;
      updateStatus(false);
      if (isManualStop) {
        // Expected termination from 停止代理 — a killed process has no exit
        // code on Windows (code === null), which read like a crash before.
        sendLog('代理已停止', 'info');
      } else if (code === null || code === undefined) {
        sendLog('进程异常终止', 'error');
      } else if (code === 0) {
        sendLog('进程已退出 (代码: 0)', 'info');
      } else {
        sendLog(`进程已退出 (代码: ${code})`, 'warn');
      }
      clientProcess = null;

      // Auto reconnect if enabled and not manually stopped
      if (!isManualStop && store.get('autoReconnect')) {
        scheduleReconnect();
      }
    });

    clientProcess.on('error', (err) => {
      isRunning = false;
      updateStatus(false);
      sendLog(`进程启动失败: ${err.message}`, 'error');
      clientProcess = null;

      // Auto reconnect on error
      if (!isManualStop && store.get('autoReconnect')) {
        scheduleReconnect();
      }
    });

  } catch (err) {
    sendLog(`启动失败: ${err.message}`, 'error');
  }
}

// Stop proxy client process
function stopProxy() {
  isManualStop = true; // Mark as manual stop to prevent auto reconnect
  reconnectAttempts = 0;
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }

  if (!clientProcess) {
    isRunning = false;
    updateStatus(false);
    return;
  }

  try {
    // Capture THIS process: the module-level clientProcess may already point
    // to a new process if the user restarts within the 3s window, and killing
    // that would murder a freshly started proxy.
    const proc = clientProcess;
    proc.kill('SIGTERM');
    setTimeout(() => {
      // exitCode === null means still running. (subprocess.killed is true the
      // moment SIGTERM is *delivered*, so the old !killed check made this
      // escalation unreachable on POSIX.)
      if (proc.exitCode === null) {
        proc.kill('SIGKILL');
      }
    }, 3000);
  } catch (err) {
    sendLog(`停止失败: ${err.message}`, 'error');
  }
}

// Schedule auto reconnect
function scheduleReconnect() {
  // Guard against double-scheduling: a failed spawn can emit both 'error' and
  // 'close' for the same process, which would otherwise burn two attempts.
  if (reconnectTimer) return;

  const maxAttempts = store.get('maxReconnectAttempts');
  const delay = store.get('reconnectDelay');

  // Check if max attempts reached (0 = unlimited)
  if (maxAttempts > 0 && reconnectAttempts >= maxAttempts) {
    sendLog(`已达到最大重连次数 (${maxAttempts})，停止重连`, 'warn');
    return;
  }

  reconnectAttempts++;
  sendLog(`将在 ${delay / 1000} 秒后自动重连 (第 ${reconnectAttempts} 次)`, 'info');

  reconnectTimer = setTimeout(async () => {
    reconnectTimer = null; // timer fired → allow scheduling a new one
    if (!isRunning && !isManualStop) {
      sendLog('正在自动重连...', 'info');
      await startProxy({ fromAutoReconnect: true });
    }
  }, delay);
}

// Update UI status
function updateStatus(running) {
  mainWindow?.webContents.send('status-update', running);

  // Update tray icon and tooltip
  const statusIcon = createStatusIcon(running);
  tray?.setImage(statusIcon.resize({ width: 16, height: 16 }));
  tray?.setToolTip(running ? 'KCP Proxy Client (运行中)' : 'KCP Proxy Client (未运行)');

  // Update tray menu. Address items by id, not by array index: the template
  // grows over time and index-based access silently toggles the wrong item
  // after any edit (this is exactly what happened to items[2]/items[3]).
  if (trayMenu) {
    const startItem = trayMenu.getMenuItemById('tray-start');
    const stopItem = trayMenu.getMenuItemById('tray-stop');
    if (startItem) startItem.enabled = !running;
    if (stopItem) stopItem.enabled = running;
  }
}

// Send log to renderer + file (levels: info/warn/error)
function log(level, ...parts) {
  const message = parts.map(String).join(' ').trim();
  try {
    writeLogFile(level, message);
  } catch (err) {
    console.error('log write failed', err);
  }
  if (process.env.ELECTRON_LOG) console.log(`[${level}] ${message}`);
  mainWindow?.webContents.send('log', { message, level, timestamp: Date.now() });
}

// Send log to renderer (legacy alias — kept for backward-compat callers)
function sendLog(message, level = 'info') {
  log(level, message);
}

// Client stderr is UTF-8 except for strings that come straight from the OS
// (socket error messages), which arrive in the system ANSI codepage — GBK on
// zh-CN Windows — and render as mojibake when force-decoded as UTF-8. Decode
// each line strictly as UTF-8 and fall back to GBK when that fails.
function decodeLogLine(buf) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    try {
      return new TextDecoder('gbk').decode(buf);
    } catch {
      return buf.toString('latin1');
    }
  }
}

// Split client output into complete lines across chunk events. Chunks are not
// guaranteed to be line-aligned, so a partial trailing line is buffered.
function createLogLineStream(onLine) {
  let pending = Buffer.alloc(0);
  return (chunk) => {
    pending = Buffer.concat([pending, chunk]);
    let idx;
    while ((idx = pending.indexOf(0x0a)) !== -1) {
      let line = pending.subarray(0, idx);
      pending = pending.subarray(idx + 1);
      if (line.length && line[line.length - 1] === 0x0d) {
        line = line.subarray(0, line.length - 1);
      }
      const text = decodeLogLine(line);
      if (text.trim()) onLine(text);
    }
  };
}

// Process one line of client output:
//   - TRAFFIC tx=<bytes> rx=<bytes> → live traffic counters only (not a log entry)
//   - other lines → map the client's [INFO]/[WARNING]/[ERROR] tag to our levels,
//     and strip the client's timestamp/level/module prefix for a cleaner display.
function handleClientLine(line) {
  const text = line.trimEnd();
  if (!text) return;

  // Traffic stats (emitted every 2s) are for the counter, not the log panel.
  const trafficMatch = text.match(/TRAFFIC tx=(\d+) rx=(\d+)/);
  if (trafficMatch) {
    mainWindow?.webContents.send('traffic-update', {
      tx: parseInt(trafficMatch[1], 10),
      rx: parseInt(trafficMatch[2], 10)
    });
    return;
  }

  let level = 'info';
  const levelMatch = text.match(/\[(DEBUG|INFO|WARNING|ERROR)\]/);
  if (levelMatch) {
    level = levelMatch[1] === 'ERROR' ? 'error'
      : levelMatch[1] === 'WARNING' ? 'warn'
      : 'info';
  }

  // Strip "<yyyy-mm-dd hh:mm:ss.mmm> [LEVEL] module: " prefix.
  const message = text.replace(
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \[(?:DEBUG|INFO|WARNING|ERROR)\] \w+: /,
    ''
  );
  sendLog(message || text, level);
}

// IPC handlers
ipcMain.handle('get-config', () => store.store);

ipcMain.handle('save-config', (event, config) => {
  Object.keys(config).forEach(key => {
    store.set(key, config[key]);
  });
  return true;
});

ipcMain.handle('start-proxy', async () => {
  await startProxy();
  return isRunning;
});

ipcMain.handle('stop-proxy', () => {
  stopProxy();
  return false;
});

ipcMain.handle('get-status', () => isRunning);

// Test connection to the server. The server listens on UDP, so a TCP connect
// proves nothing (it would RST against a perfectly healthy server, or false-
// succeed if something else happens to listen on that TCP port). Instead:
//   1) resolve the host, and
//   2) briefly spawn the real client binary, drive a SOCKS5 CONNECT through
//      it, and watch its log for the KCP handshake result — the only
//      meaningful end-to-end probe.
// The CONNECT is mandatory: the client only starts its KCP session (and logs
// the handshake) when a local SOCKS5 client issues CONNECT — see client.cpp's
// per-connection session->connect(). A probe that merely waits for log output
// would always report a bogus timeout.
// The probe binds the local SOCKS5 listener to a free ephemeral port so it
// never collides with a running proxy. Killing the probe afterwards leaves one
// idle session on the server, reaped by its 60s idle sweep.
function probeKcpHandshake(clientPath, host, port, timeoutMs = 10000) {
  return getFreePort().then((listenPort) => new Promise((resolve) => {
    let settled = false;
    let timer = null;
    let proc = null;
    let probeSock = null;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try {
        if (probeSock) probeSock.destroy();
      } catch { /* best effort */ }
      try {
        if (proc && proc.exitCode === null) proc.kill();
      } catch { /* best effort */ }
      resolve(result);
    };

    try {
      proc = spawn(clientPath, [
        '-s', host,
        '-p', String(port),
        '-H', '127.0.0.1',
        '-l', String(listenPort),
        '-L', 'info'
      ], {
        cwd: path.dirname(clientPath),
        stdio: ['ignore', 'ignore', 'pipe'],
        env: { ...process.env, KCP_PROXY_KEY: generateKey() }
      });
    } catch (err) {
      finish({ ok: false, message: `启动测试进程失败: ${err.message}` });
      return;
    }

    timer = setTimeout(() => {
      finish({ ok: false, message: `握手超时 (${host}:${port}，服务器不可达或密钥不匹配)` });
    }, timeoutMs);

    // Send a minimal SOCKS5 greeting + CONNECT to the probe client. The
    // destination (1.1.1.1:80) is irrelevant — the KCP handshake fires before
    // the upstream TCP connect, and we only watch the client's log.
    const driveProbe = () => {
      probeSock = net.connect(listenPort, '127.0.0.1', () => {
        probeSock.write(Buffer.from([0x05, 0x01, 0x00])); // greeting: no-auth
      });
      probeSock.on('error', () => { /* probe socket failures are non-fatal */ });
      let stage = 0;
      probeSock.on('data', (d) => {
        if (stage === 0 && d.length >= 2) {
          stage = 1;
          probeSock.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0, 80]));
        }
      });
    };

    // The client logs to stderr (line-streamed, UTF-8/GBK aware).
    const pushProbeLine = createLogLineStream((line) => {
      // Listener is up (logged after listen()) → trigger the handshake.
      if (line.includes('SOCKS5 proxy listening')) driveProbe();
      if (line.includes('KCP handshake confirmed')) {
        finish({ ok: true, message: `连接成功: KCP 握手确认 (${host}:${port})` });
        return;
      }
      const resolveMatch = line.match(/resolve error: (.+)/);
      if (resolveMatch) {
        finish({ ok: false, message: `域名解析失败: ${resolveMatch[1]} (${host})` });
        return;
      }
      if (line.includes('KCP handshake timeout') || line.includes('KCP handshake failed')) {
        finish({ ok: false, message: `握手失败 (${host}:${port}，服务器不可达或密钥不匹配)` });
        return;
      }
    });
    proc.stderr.on('data', (data) => pushProbeLine(data));

    proc.on('error', (err) => finish({ ok: false, message: `测试进程启动失败: ${err.message}` }));
    proc.on('close', (code) => finish({ ok: false, message: `客户端进程异常退出 (代码 ${code})` }));
  }));
}

// Reserve a free TCP port for the probe's SOCKS5 listener (bind port 0, read
// the assigned port, release). Tiny TOCTOU window is acceptable for a probe.
function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

ipcMain.handle('test-connection', async (event, host, port) => {
  const h = (host || store.get('serverHost') || '').trim();
  const p = parseInt(port || store.get('serverPort'), 10);

  if (!h || !p) {
    return { ok: false, message: '请填写服务器地址和端口' };
  }

  const validationError = validateLaunchConfig({
    serverHost: h,
    serverPort: p, // validate the port the user actually asked to test —
                   // previously this read the saved value, so an unsaved
                   // port change was validated against the stale port.
    localPort: store.get('localPort'),
    keyMode: 'daily',
    keySuffix: store.get('keySuffix')
  });
  if (validationError) {
    return { ok: false, message: validationError };
  }

  // 1) DNS / literal-IP check gives an immediate, precise failure reason.
  let address;
  try {
    const resolved = await dns.promises.lookup(h);
    address = resolved.address;
  } catch (err) {
    return { ok: false, message: `域名解析失败: ${err.message} (${h})` };
  }

  // 2) End-to-end KCP handshake probe (requires the client binary).
  const clientPath = getClientPath();
  if (!clientPath) {
    return { ok: true, message: `域名解析成功 (${h} → ${address})；未找到客户端程序，无法测试 UDP 握手` };
  }

  return probeKcpHandshake(clientPath, h, p);
});

// IPC for updater (stubs — real mechanism lives in main process)
ipcMain.handle('check-for-updates', async () => {
  if (autoUpdater) {
    autoUpdater.checkForUpdates();
    return true;
  }
  return false;
});

ipcMain.handle('quit-and-install', async () => {
  if (autoUpdater) {
    autoUpdater.quitAndInstall();
    return true;
  }
  return false;
});

ipcMain.on('window-minimize', () => {
  mainWindow?.minimize();
});

ipcMain.on('window-maximize', () => {
  if (!mainWindow) return;
  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow.maximize();
  }
});

ipcMain.on('window-close', () => {
  if (mainWindow) {
    mainWindow.hide();
  }
});

// ── App lifecycle ──
// Set Windows AppUserModelID so notifications/taskbar group correctly
if (process.platform === 'win32') {
  app.setAppUserModelId('com.kcp.proxy');
}

// ── Auto-updater lifecycle (only in packaged app) ──
function setupAutoUpdater() {
  if (!autoUpdater || app.isPackaged === false) return;
  if (process.env.KCP_DISABLE_UPDATE === '1') return; // opt-out switch

  // Optional generic feed override (e.g. self-hosted mirror).
  // Otherwise electron-updater reads app-update.yml baked by electron-builder (GitHub provider).
  if (process.env.KCP_UPDATE_URL) {
    try {
      autoUpdater.setFeedURL({ provider: 'generic', url: process.env.KCP_UPDATE_URL });
    } catch (err) {
      sendLog(`更新源设置失败: ${err.message}`, 'error');
    }
  }

  autoUpdater.autoDownload = true;
  autoUpdater.on('checking-for-update', () => {
    sendLog('正在检查更新...', 'info');
  });
  autoUpdater.on('update-available', (info) => {
    sendLog(`发现新版本: ${info.version}，正在下载...`, 'info');
    mainWindow?.webContents.send('update-status', {
      status: 'available',
      version: info.version
    });
  });
  autoUpdater.on('update-not-available', () => {
    sendLog('已是最新版本', 'info');
    mainWindow?.webContents.send('update-status', { status: 'not-available' });
  });
  autoUpdater.on('error', (err) => {
    sendLog(`更新检查失败: ${err.message}`, 'error');
    mainWindow?.webContents.send('update-status', { status: 'error' });
  });
  autoUpdater.on('update-downloaded', (info) => {
    sendLog(`新版本已下载: ${info.version}，重启后生效`, 'info');
    mainWindow?.webContents.send('update-status', {
      status: 'downloaded',
      version: info.version
    });
  });
  autoUpdater.checkForUpdatesAndNotify();
}

app.whenReady().then(() => {
  // Remove default application menu (File/Edit/View...) — we have a custom title bar
  Menu.setApplicationMenu(null);

  createWindow();
  createTray();
  setupAutoUpdater();
  removeLegacyAutoStartEntry();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  app.isQuitting = true;
  if (clientProcess) {
    clientProcess.kill();
  }
});

// Prevent multiple instances
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}