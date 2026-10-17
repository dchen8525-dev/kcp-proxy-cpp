// DOM elements
const elements = {
  serverHost: document.getElementById('serverHost'),
  serverPort: document.getElementById('serverPort'),
  localPort: document.getElementById('localPort'),
  keySuffix: document.getElementById('keySuffix'),
  autoReconnect: document.getElementById('autoReconnect'),
  btnTest: document.getElementById('btn-test'),
  btnToggle: document.getElementById('btn-toggle'),
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
  logContainer: document.getElementById('log-container'),
  ovSocks: document.getElementById('ov-socks'),
  ovUpstream: document.getElementById('ov-upstream'),
  testResult: document.getElementById('test-result'),
  sideFoot: document.getElementById('side-foot')
};

// State
let config = {};
let isRunning = false;

// Initialize
async function init() {
  // The sidebar is pure DOM, so wire it before any bridge check — that keeps
  // navigation working even in a bare browser preview where electronAPI is
  // absent (the rest of the controls need the bridge and stay inert there).
  setupNav();

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

  // Cosmetic: replace the hardcoded fallback in the sidebar footer with the
  // real packaged version so it never drifts on a release.
  try {
    const version = await window.electronAPI.getAppVersion();
    if (version) elements.sideFoot.textContent = `v${version} · 纸感墨白`;
  } catch { /* version label is cosmetic — keep the HTML fallback */ }

  appendLog('提示：填写完成后点击「启动连接」即可。', 'info');
}

// Populate form with saved config
function populateForm(config) {
  elements.serverHost.value = config.serverHost || '';
  elements.serverPort.value = config.serverPort || '8388';
  elements.localPort.value = config.localPort || '1080';
  elements.keySuffix.value = config.keySuffix || '';
  elements.autoReconnect.checked = config.autoReconnect !== false;
  refreshOverview();
}

// Keep the overview's read-only summary in sync with the form values.
function refreshOverview() {
  const localPort = elements.localPort.value.trim() || '1080';
  elements.ovSocks.textContent = `socks5://127.0.0.1:${localPort}`;

  const host = elements.serverHost.value.trim();
  const serverPort = elements.serverPort.value.trim() || '8388';
  elements.ovUpstream.textContent = host ? `${host}:${serverPort}` : '—';
}

// Sidebar view switching: show the section whose id matches the nav link's
// data-v, and mark that link active. The mockup uses the same data-v contract.
function setupNav() {
  const links = document.querySelectorAll('.nav a[data-v]');
  const views = document.querySelectorAll('.view');

  const activate = (a) => {
    links.forEach((x) => {
      x.classList.remove('on');
      x.removeAttribute('aria-current');
    });
    a.classList.add('on');
    a.setAttribute('aria-current', 'page');
    views.forEach((v) => { v.hidden = v.id !== a.dataset.v; });
  };

  links.forEach((a) => {
    a.addEventListener('click', () => activate(a));
    // The links carry role="button" + tabindex (no href), so Enter/Space must
    // activate them — a real <a href> would handle this for free.
    a.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        activate(a);
      }
    });
  });
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

  // Toggle button: one control for both directions. The label/style follow
  // the current state (see updateStatus), so a click always does the one
  // thing the button advertises.
  elements.btnToggle.addEventListener('click', () => {
    if (isRunning) {
      stopProxy();
    } else {
      startProxy();
    }
  });

  // Auto-save: every field persists as soon as it changes (text fields commit
  // on blur / Enter via the DOM 'change' event). No log line — auto-save runs
  // too often to spam the panel.
  for (const id of ['serverHost', 'serverPort', 'localPort', 'keySuffix']) {
    elements[id].addEventListener('change', saveSettings);
  }
  elements.autoReconnect.addEventListener('change', saveSettings);

  // Log panel: expanded by default, the title toggles it
  const toggleLog = () => elements.logCard.classList.toggle('collapsed');
  elements.logToggle.addEventListener('click', toggleLog);
  // log-toggle carries role="button" + tabindex, so Enter/Space must toggle too.
  elements.logToggle.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggleLog();
    }
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

    window.electronAPI.onTrafficUpdate((data) => {
    updateTraffic(data);
  });

  window.electronAPI.onUpdateStatus((data) => {
    if (data.status === 'available') {
      appendLog(`发现新版本: ${data.version}，正在后台自动下载...`, 'info');
    } else if (data.status === 'downloaded') {
      appendLog(`新版本 ${data.version} 已下载，右键系统托盘图标选择"安装更新并重启"完成升级`, 'info');
    }
  });

  // Maximize button glyph mirrors the window state (also covers double-click
  // on the title bar and Win+Up, since the main process emits on both).
  window.electronAPI.onMaximizeState((maximized) => {
    elements.btnMaximize.textContent = maximized ? '❐' : '□';
  });
}

// Save settings (auto-save: called on every field change, stays silent).
// Never rejects. It is wired directly to the fields' 'change' event, where a
// rejection would surface as an unhandled rejection with nothing for the user
// to act on; callers that await it (startProxy/testConnection) must not be
// aborted by a failed write either.
async function saveSettings() {
  const newConfig = {
    serverHost: elements.serverHost.value.trim(),
    serverPort: elements.serverPort.value.trim() || '8388',
    localPort: elements.localPort.value.trim() || '1080',
    keySuffix: elements.keySuffix.value.trim(),
    autoReconnect: elements.autoReconnect.checked
  };

  // Adopt the form values first: they are what the next launch validates, and
  // persisting them is best-effort, so a failed write must not leave `config`
  // describing the previous values.
  config = newConfig;
  refreshOverview();
  try {
    await window.electronAPI.saveConfig(newConfig);
  } catch (err) {
    console.error('saveConfig failed:', err);
  }
}

// Test connection
//
// The probe's own progress lives in the runtime-log view, but the button sits
// on the overview page — without an inline result there, a user who stays on
// the overview sees the button flash "测试中..." and change nothing else, which
// reads as "the button does nothing". So every outcome also lands in
// #test-result (aria-live), right next to the button, in the mockup's
// restrained ink-on-paper voice.
async function testConnection() {
  // The probe reads the values in `config`, so persist the form first — but a
  // failed save must not silently kill the test (the user asked to test what
  // is on screen, not to verify the disk). Never rejects.
  try {
    await saveSettings();
  } catch (err) {
    appendLog(`设置保存失败（仍按当前表单测试）: ${err.message}`, 'error');
  }

  const host = config.serverHost;
  if (!host) {
    showTestResult('error', '请先填写服务器地址');
    appendLog('请填写服务器地址后再测试', 'error');
    return;
  }

  elements.btnTest.disabled = true;
  elements.btnTest.textContent = '测试中...';
  showTestResult('pending', `正在测试 ${host}:${config.serverPort} ...`);
  appendLog(`测试连接 ${host}:${config.serverPort} ...`, 'info');

  try {
    const result = await window.electronAPI.testConnection(host, config.serverPort);
    if (result.ok) {
      showTestResult('success', result.message);
      appendLog(`✓ ${result.message}`, 'info');
    } else {
      showTestResult('error', result.message);
      appendLog(`✗ ${result.message}`, 'error');
    }
  } catch (err) {
    // An IPC throw (bridge gone, handler crashed) — the button is the only
    // thing the user can act on, so it must not stay stuck on "测试中...".
    showTestResult('error', `测试失败: ${err.message}`);
    appendLog(`测试连接失败: ${err.message}`, 'error');
  } finally {
    // Always restore the button, even if the IPC call threw.
    elements.btnTest.disabled = false;
    elements.btnTest.textContent = '测试连接';
  }
}

// Inline outcome beside the 测试连接 button: one quiet line, ink on paper.
// state is 'pending' | 'success' | 'error'; the message is shown verbatim.
function showTestResult(state, message) {
  const el = elements.testResult;
  if (!el) return;
  el.textContent = message;
  el.dataset.state = state;
  el.hidden = false;
}

// Start proxy
async function startProxy() {
  await saveSettings();

  // Single validation pass, run in the main process against the same utils.js
  // the launch itself uses (the preload cannot require local files under the
  // sandbox, and a second copy of these rules would be free to drift).
  const validationError = await window.electronAPI.validateConfig({
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
  try {
    await window.electronAPI.startProxy();
  } catch (err) {
    // IPC failures (e.g. the client binary is missing) must surface in the
    // UI instead of becoming an unhandled rejection with a dead button.
    appendLog(`启动失败: ${err && err.message ? err.message : err}`, 'error');
  }
}

// Stop proxy
async function stopProxy() {
  appendLog('正在停止代理...', 'info');
  try {
    await window.electronAPI.stopProxy();
  } catch (err) {
    appendLog(`停止操作失败: ${err && err.message ? err.message : err}`, 'error');
  }
}

// Update UI status
function updateStatus(running) {
  isRunning = running;

  // The single toggle button is never disabled — its label and color carry
  // the state: 朱砂 fill invites a start, 墨 fill marks the live session and
  // offers the disconnect.
  if (running) {
    elements.btnToggle.textContent = '断开连接';
    elements.btnToggle.classList.remove('btn-fill');
    elements.btnToggle.classList.add('btn-dark');
    elements.statusDot.classList.add('running');
    elements.statusText.textContent = '运行中';
    elements.trafficIndicator.hidden = false;
  } else {
    elements.btnToggle.textContent = '启动连接';
    elements.btnToggle.classList.remove('btn-dark');
    elements.btnToggle.classList.add('btn-fill');
    elements.statusDot.classList.remove('running');
    elements.statusText.textContent = '未运行';
    elements.trafficIndicator.hidden = true;
    // Reset the counters, not just hide them: the client only emits a TRAFFIC
    // line when the numbers change, so a restart would otherwise re-show the
    // PREVIOUS run's totals and leave them there until new traffic arrives.
    elements.trafficUp.textContent = '↑ 0 B';
    elements.trafficDown.textContent = '↓ 0 B';
  }
}

// Update traffic display. The main process already humanized the counters
// (utils.js lives there), so these arrive as display strings.
function updateTraffic({ tx, rx }) {
  elements.trafficUp.textContent = `↑ ${tx}`;
  elements.trafficDown.textContent = `↓ ${rx}`;
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