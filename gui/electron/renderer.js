// DOM elements
const elements = {
  serverHost: document.getElementById('serverHost'),
  serverPort: document.getElementById('serverPort'),
  localPort: document.getElementById('localPort'),
  keySuffix: document.getElementById('keySuffix'),
  autoStart: document.getElementById('autoStart'),
  autoReconnect: document.getElementById('autoReconnect'),
  btnTest: document.getElementById('btn-test'),
  btnStart: document.getElementById('btn-start'),
  btnStop: document.getElementById('btn-stop'),
  btnMinimize: document.getElementById('btn-minimize'),
  btnMaximize: document.getElementById('btn-maximize'),
  btnClose: document.getElementById('btn-close'),
  statusDot: document.getElementById('status-dot'),
  statusText: document.getElementById('status-text'),
  trafficIndicator: document.getElementById('traffic-indicator'),
  trafficUp: document.querySelector('.traffic-up'),
  trafficDown: document.querySelector('.traffic-down'),
  logCard: document.getElementById('log-card'),
  logToggle: document.getElementById('log-toggle'),
  logContainer: document.getElementById('log-container')
};

// State
let config = {};
let isRunning = false;

// Initialize
async function init() {
  if (!window.electronAPI) {
    // The preload failed (e.g. sandboxed require of a local module). Without
    // the bridge nothing can work — say so instead of leaving every button
    // silently dead.
    appendLog('初始化失败：preload 未加载，界面交互不可用。请查看日志或重新安装。', 'error');
    return;
  }

  // Attach listeners BEFORE loading config so window controls and buttons stay
  // responsive even if the config read below throws.
  setupEventListeners();
  setupIPCHandlers();

  try {
    // Load saved config
    config = await window.electronAPI.getConfig();
    populateForm(config);

    // Load current status
    isRunning = await window.electronAPI.getStatus();
    updateStatus(isRunning);
  } catch (err) {
    appendLog(`读取配置失败: ${err.message}`, 'error');
  }

  appendLog('提示：填写完成后点击「启动代理」即可。', 'info');
}

// Populate form with saved config
function populateForm(config) {
  elements.serverHost.value = config.serverHost || '';
  elements.serverPort.value = config.serverPort || '8388';
  elements.localPort.value = config.localPort || '1080';
  elements.keySuffix.value = config.keySuffix || '';
  elements.autoStart.checked = config.autoStart || false;
  elements.autoReconnect.checked = config.autoReconnect !== false;
}

// Setup event listeners
function setupEventListeners() {
  // Window controls
  elements.btnMinimize.addEventListener('click', () => {
    window.electronAPI.minimizeWindow();
  });

  elements.btnMaximize.addEventListener('click', () => {
    window.electronAPI.maximizeWindow();
  });

  elements.btnClose.addEventListener('click', () => {
    window.electronAPI.closeWindow();
  });

  // Save button
  elements.btnTest.addEventListener('click', testConnection);

  // Start/Stop buttons
  elements.btnStart.addEventListener('click', startProxy);
  elements.btnStop.addEventListener('click', stopProxy);

  // Auto-save: every field persists as soon as it changes (text fields commit
  // on blur / Enter via the DOM 'change' event). No log line — auto-save runs
  // too often to spam the panel.
  for (const id of ['serverHost', 'serverPort', 'localPort', 'keySuffix']) {
    elements[id].addEventListener('change', saveSettings);
  }
  elements.autoStart.addEventListener('change', saveSettings);
  elements.autoReconnect.addEventListener('change', saveSettings);

  // Log panel: expanded by default, the title toggles it
  elements.logToggle.addEventListener('click', () => {
    elements.logCard.classList.toggle('collapsed');
  });
}

// Setup IPC handlers
function setupIPCHandlers() {
  window.electronAPI.onStatusUpdate((running) => {
    updateStatus(running);
  });

  window.electronAPI.onLog((data) => {
    appendLog(data.message, data.level);
  });

  window.electronAPI.onConfigUpdated((newConfig) => {
    // Only the tray can currently change settings outside this form (the 开机自启
    // checkbox). Sync just that, instead of repopulating the whole form which
    // would clobber in-progress input in the other fields.
    config = newConfig;
    elements.autoStart.checked = Boolean(newConfig.autoStart);
  });

  window.electronAPI.onTrafficUpdate((data) => {
    updateTraffic(data);
  });

  window.electronAPI.onUpdateStatus((data) => {
    if (data.status === 'available' || data.status === 'downloaded') {
      appendLog(`发现新版本: ${data.version}，请稍后在设置中更新`, 'info');
    }
  });

  // Maximize button glyph mirrors the window state (also covers double-click
  // on the title bar and Win+Up, since the main process emits on both).
  window.electronAPI.onMaximizeState((maximized) => {
    elements.btnMaximize.textContent = maximized ? '❐' : '□';
  });
}

// Save settings (auto-save: called on every field change, stays silent)
async function saveSettings() {
  const newConfig = {
    serverHost: elements.serverHost.value.trim(),
    serverPort: elements.serverPort.value.trim() || '8388',
    localPort: elements.localPort.value.trim() || '1080',
    keySuffix: elements.keySuffix.value.trim(),
    autoStart: elements.autoStart.checked,
    autoReconnect: elements.autoReconnect.checked
  };

  await window.electronAPI.saveConfig(newConfig);
  config = newConfig;
}

// Test connection
async function testConnection() {
  await saveSettings();

  const host = config.serverHost;
  if (!host) {
    appendLog('请填写服务器地址后再测试', 'error');
    return;
  }

  elements.btnTest.disabled = true;
  elements.btnTest.textContent = '测试中...';
  appendLog(`测试连接 ${host}:${config.serverPort} ...`, 'info');

  try {
    const result = await window.electronAPI.testConnection(host, config.serverPort);
    if (result.ok) {
      appendLog(`✓ ${result.message}`, 'info');
    } else {
      appendLog(`✗ ${result.message}`, 'error');
    }
  } catch (err) {
    appendLog(`测试连接失败: ${err.message}`, 'error');
  } finally {
    // Always restore the button, even if the IPC call threw.
    elements.btnTest.disabled = false;
    elements.btnTest.textContent = '测试连接';
  }
}

// Start proxy
async function startProxy() {
  await saveSettings();

  // Single validation pass (same rules as the main process)
  const validationError = window.utils.validateLaunchConfig({
    serverHost: config.serverHost,
    serverPort: config.serverPort,
    localPort: config.localPort,
    keyMode: 'daily',
    keySuffix: config.keySuffix
  });
  if (validationError) {
    appendLog(validationError, 'error');
    return;
  }

  appendLog('正在启动代理...', 'info');
  await window.electronAPI.startProxy();
}

// Stop proxy
async function stopProxy() {
  appendLog('正在停止代理...', 'info');
  await window.electronAPI.stopProxy();
}

// Update UI status
function updateStatus(running) {
  isRunning = running;
  elements.btnStart.disabled = running;
  elements.btnStop.disabled = !running;

  if (running) {
    elements.statusDot.classList.add('running');
    elements.statusText.textContent = '运行中';
    elements.trafficIndicator.hidden = false;
  } else {
    elements.statusDot.classList.remove('running');
    elements.statusText.textContent = '未运行';
    elements.trafficIndicator.hidden = true;
  }
}

// Update traffic display
function updateTraffic({ tx, rx }) {
  elements.trafficUp.textContent = `↑ ${window.utils.formatBytes(tx)}`;
  elements.trafficDown.textContent = `↓ ${window.utils.formatBytes(rx)}`;
}

// Append log entry
function appendLog(message, level = 'info') {
  const entry = document.createElement('div');
  entry.className = `log-entry ${level}`;

  const timestamp = new Date().toLocaleTimeString('zh-CN', { hour12: false });
  entry.textContent = `[${timestamp}] ${message}`;

  elements.logContainer.appendChild(entry);

  // Auto-scroll to bottom
  elements.logContainer.scrollTop = elements.logContainer.scrollHeight;

  // Limit log entries
  const maxEntries = 1000;
  while (elements.logContainer.children.length > maxEntries) {
    elements.logContainer.removeChild(elements.logContainer.firstChild);
  }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);