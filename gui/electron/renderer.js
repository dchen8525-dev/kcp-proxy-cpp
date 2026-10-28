// DOM elements
const elements = {
  serverHost: document.getElementById('serverHost'),
  serverPort: document.getElementById('serverPort'),
  localPort: document.getElementById('localPort'),
  keySuffix: document.getElementById('keySuffix'),
  autoConnect: document.getElementById('autoConnect'),
  allowLan: document.getElementById('allowLan'),
  autoReconnect: document.getElementById('autoReconnect'),
  btnTest: document.getElementById('btn-test'),
  btnToggle: document.getElementById('btn-toggle'),
  btnSave: document.getElementById('btn-save'),
  saveResult: document.getElementById('save-result'),
  btnMinimize: document.getElementById('btn-minimize'),
  btnMaximize: document.getElementById('btn-maximize'),
  btnClose: document.getElementById('btn-close'),
  statusDot: document.getElementById('status-dot'),
  statusText: document.getElementById('status-text'),
  uptime: document.getElementById('uptime'),
  trafficIndicator: document.getElementById('traffic-indicator'),
  trafficDownRate: document.getElementById('traffic-down-rate'),
  trafficDownSpark: document.getElementById('traffic-down-spark'),
  trafficDownCap: document.getElementById('traffic-down-cap'),
  trafficUpRate: document.getElementById('traffic-up-rate'),
  trafficUpSpark: document.getElementById('traffic-up-spark'),
  trafficUpCap: document.getElementById('traffic-up-cap'),
  logCard: document.getElementById('log-card'),
  logContainer: document.getElementById('log-container'),
  ovSocks: document.getElementById('ov-socks'),
  ovUpstream: document.getElementById('ov-upstream'),
  ovTodayKey: document.getElementById('ov-todaykey'),
  testResult: document.getElementById('test-result'),
  fecEnabled: document.getElementById('fecEnabled'),
  fecPair: document.getElementById('fecPair'),
  sideFoot: document.getElementById('side-foot')
};

// State
let config = {};
let isRunning = false;
// Today's Beijing date (YYYYMMDD), fetched once per launch. The overview's
// 今日密钥 row composes it with the form's key suffix, exactly the way
// utils.js generateKey's daily branch does (date + suffix, no separator).
let todayKeyDate = '';

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

  // The footer version arrives from the preload, which read app.getVersion()
  // out of process.argv before this page loaded. Set it before the first await
  // so the label is correct on the very first paint; the HTML fallback carries
  // no version number, so nothing stale can ever show.
  if (window.electronAPI.appVersion) {
    elements.sideFoot.textContent = `v${window.electronAPI.appVersion} · 纸感墨白`;
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

  // Today's Beijing date for the overview's 今日密钥 row. Computed in the main
  // process from utils.js (the same clock that mints the key), fetched once per
  // launch — the value only changes at Beijing midnight, and the app restarting
  // is a natural (if belated) refresh for that edge case. The suffix half comes
  // from the form so the row tracks live edits like the other overview rows.
  try {
    const keyDate = await window.electronAPI.getKeyDate();
    if (keyDate) {
      todayKeyDate = keyDate;
      refreshOverview();
    }
  } catch { /* keep the HTML placeholder */ }

  appendLog('提示：填写完成后点击「启动连接」即可。', 'info');
}

// Populate form with saved config
function populateForm(config) {
  elements.serverHost.value = config.serverHost || '';
  elements.serverPort.value = config.serverPort || '8388';
  elements.localPort.value = config.localPort || '1080';
  elements.keySuffix.value = config.keySuffix || '';
  elements.autoConnect.checked = config.autoConnect === true;
  elements.allowLan.checked = config.allowLan === true;
  elements.autoReconnect.checked = config.autoReconnect !== false;
  // FEC: disabled by default; the pair placeholder matches the C++-side
  // recommendation (kcp-go's 10:3) so enabling needs no typing.
  elements.fecEnabled.checked = config.fecEnabled === true;
  elements.fecPair.value = config.fecPair || '10:3';
  syncFecInputs();
  refreshOverview();
}

// Keep the overview's read-only summary in sync with the form values. The
// SOCKS address mirrors the actual listen host — 0.0.0.0 when LAN sharing is
// on (the client binds all interfaces), 127.0.0.1 otherwise — so the dropped
// 绑定地址 row is still legible right inside this one.
function refreshOverview() {
  const localPort = elements.localPort.value.trim() || '1080';
  const listenHost = elements.allowLan.checked ? '0.0.0.0' : '127.0.0.1';
  elements.ovSocks.textContent = `socks5://${listenHost}:${localPort}`;

  const host = elements.serverHost.value.trim();
  const serverPort = elements.serverPort.value.trim() || '8388';
  elements.ovUpstream.textContent = host ? `${host}:${serverPort}` : '—';

  // 今日密钥 = 北京日期 + 密钥后缀，mirroring utils.js generateKey's daily
  // branch (plain concatenation, no separator). An empty suffix means the key
  // is not complete, so the row keeps its placeholder instead of showing a
  // bare date that would never validate.
  const suffix = elements.keySuffix.value.trim();
  elements.ovTodayKey.textContent = todayKeyDate && suffix
    ? todayKeyDate + suffix
    : '—';
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
    // Logs appended while the view was hidden couldn't scroll (display:none
    // has scrollHeight 0), so landing on the log view must jump to the tail.
    if (a.dataset.v === 'v-log') scrollLogToTail();
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

  // Auto-save is gone: the settings page only persists on 保存设置. The
  // change listeners remain so the overview's read-only summary (SOCKS
  // address, bind host, upstream) tracks the form live — without writing
  // anything to disk.
  for (const id of ['serverHost', 'serverPort', 'localPort', 'keySuffix']) {
    elements[id].addEventListener('change', refreshOverview);
  }
  elements.autoConnect.addEventListener('change', refreshOverview);
  elements.allowLan.addEventListener('change', refreshOverview);
  elements.autoReconnect.addEventListener('change', refreshOverview);
  // FEC 分片输入只在启用时有效：关掉就禁用输入框，表单状态一眼可读。
  elements.fecEnabled.addEventListener('change', syncFecInputs);

  elements.btnSave.addEventListener('click', saveSettings);
}

// Enable/disable the FEC pair input to mirror the FEC checkbox. Called from
// the change listener and after populateForm so a loaded config renders the
// input in the right state.
function syncFecInputs() {
  elements.fecPair.disabled = !elements.fecEnabled.checked;
}

// Scroll the log to its tail. Called both from appendLog and when the log
// view becomes visible: while the view is hidden (display:none) the
// container has scrollHeight 0, so appends that happened on other tabs
// leave the scroll position at the top — a fresh view must jump to the end.
function scrollLogToTail() {
  elements.logContainer.scrollTop = elements.logContainer.scrollHeight;
}

// Setup IPC handlers
function setupIPCHandlers() {
  window.electronAPI.onStatusUpdate(({ running, startedAt }) => {
    updateStatus(running, startedAt);
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

// Read the form as one snapshot. The form is the launch source of truth
// (启动连接/测试连接 use it verbatim); the saved config is only what a
// 保存设置 click persisted.
function readForm() {
  return {
    serverHost: elements.serverHost.value.trim(),
    serverPort: elements.serverPort.value.trim() || '8388',
    localPort: elements.localPort.value.trim() || '1080',
    keySuffix: elements.keySuffix.value.trim(),
    autoConnect: elements.autoConnect.checked,
    allowLan: elements.allowLan.checked,
    autoReconnect: elements.autoReconnect.checked,
    fecEnabled: elements.fecEnabled.checked,
    fecPair: elements.fecPair.value.trim() || '10:3'
  };
}

// Save settings — bound ONLY to the 保存设置 button (no auto-save). Never
// rejects; every outcome lands in #save-result next to the button.
async function saveSettings() {
  const newConfig = readForm();

  // Adopt the form values as the saved snapshot first: persisting is
  // best-effort, and a failed write must not leave `config` stale.
  config = newConfig;
  refreshOverview();

  const result = elements.saveResult;
  try {
    await window.electronAPI.saveConfig(newConfig);
    if (result) {
      result.textContent = '已保存';
      result.dataset.state = 'success';
      result.hidden = false;
      clearTimeout(saveSettings._timer);
      saveSettings._timer = setTimeout(() => { result.hidden = true; }, 2000);
    }
  } catch (err) {
    console.error('saveConfig failed:', err);
    if (result) {
      result.textContent = `保存失败: ${err.message}`;
      result.dataset.state = 'error';
      result.hidden = false;
    }
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
  // The probe runs against the FORM values: what is on screen is what gets
  // tested. Nothing is persisted — the saved config only changes on 保存设置.
  const host = elements.serverHost.value.trim();
  const port = elements.serverPort.value.trim() || '8388';
  const keySuffix = elements.keySuffix.value.trim();

  if (!host) {
    showTestResult('error', '请先填写服务器地址');
    appendLog('请填写服务器地址后再测试', 'error');
    return;
  }

  elements.btnTest.disabled = true;
  elements.btnTest.textContent = '测试中...';
  showTestResult('pending', `正在测试 ${host}:${port} ...`);
  appendLog(`测试连接 ${host}:${port} ...`, 'info');

  const startedAt = Date.now();
  try {
    const result = await window.electronAPI.testConnection(host, port, keySuffix, {
      fecEnabled: elements.fecEnabled.checked,
      fecPair: elements.fecPair.value.trim() || '10:3'
    });
    showTestResultAfterMinPending(result.ok ? 'success' : 'error', result.message, startedAt);
    appendLog(`${result.ok ? '✓' : '✗'} ${result.message}`, result.ok ? 'info' : 'error');
  } catch (err) {
    // An IPC throw (bridge gone, handler crashed) — the button is the only
    // thing the user can act on, so it must not stay stuck on "测试中...".
    showTestResultAfterMinPending('error', `测试失败: ${err.message}`, startedAt);
    appendLog(`测试连接失败: ${err.message}`, 'error');
  } finally {
    // Always restore the button, even if the IPC call threw.
    elements.btnTest.disabled = false;
    elements.btnTest.textContent = '测试连接';
  }
}

// Inline outcome beside the 测试连接 button: one quiet line, ink on paper.
// state is 'pending' | 'success' | 'error'; the message is shown verbatim.
// Success/error auto-dismiss after 5s: it is a transient probe outcome, not
// persistent state (the real state lives in the 启动/断开 button and the log
// view). Pending never auto-dismisses — it lasts exactly as long as the probe.
const TEST_RESULT_VISIBLE_MS = 5000;
const TEST_RESULT_MIN_PENDING_MS = 1000;
let testResultTimer = null;
let testResultDelayTimer = null;

function showTestResult(state, message) {
  const el = elements.testResult;
  if (!el) return;
  // A new outcome cancels BOTH timers: the dismiss timer of the previous
  // result and the min-pending delay of a stale one (a second click during
  // the delay must never let the old result overwrite the new pending line).
  if (testResultTimer) {
    clearTimeout(testResultTimer);
    testResultTimer = null;
  }
  if (testResultDelayTimer) {
    clearTimeout(testResultDelayTimer);
    testResultDelayTimer = null;
  }
  el.textContent = message;
  el.dataset.state = state;
  el.hidden = false;
  if (state !== 'pending') {
    testResultTimer = setTimeout(() => {
      testResultTimer = null;
      el.hidden = true;
      el.textContent = '';
    }, TEST_RESULT_VISIBLE_MS);
  }
}

// The pending line must stay readable for at least 1s: a fast probe (instant
// validation failure, nearby server) otherwise flashes "正在测试" for
// milliseconds and the result pops in before the eye found the line.
function showTestResultAfterMinPending(state, message, startedAt) {
  const remainMs = Math.max(0, TEST_RESULT_MIN_PENDING_MS - (Date.now() - startedAt));
  if (remainMs === 0) {
    showTestResult(state, message);
    return;
  }
  testResultDelayTimer = setTimeout(() => {
    testResultDelayTimer = null;
    showTestResult(state, message);
  }, remainMs);
}

// Start proxy
async function startProxy() {
  // Launch with the FORM values: what is on screen is what starts. The values
  // ride along as a launch-time override — they are NOT persisted here; the
  // disk copy only changes on 保存设置. (Otherwise "启动连接" would silently
  // save unsaved edits, defeating the explicit-save button.)
  const form = readForm();

  // Single validation pass, run in the main process against the same utils.js
  // the launch itself uses (the preload cannot require local files under the
  // sandbox, and a second copy of these rules would be free to drift).
  const validationError = await window.electronAPI.validateConfig({
    serverHost: form.serverHost,
    serverPort: form.serverPort,
    localPort: form.localPort,
    keyMode: 'daily',
    keySuffix: form.keySuffix,
    fecEnabled: form.fecEnabled,
    fecPair: form.fecPair
  });
  if (validationError) {
    appendLog(validationError, 'error');
    return;
  }

  appendLog('正在启动代理...', 'info');
  try {
    await window.electronAPI.startProxy(form);
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

// Session uptime, shown beside the status word once a tunnel is live. The start
// timestamp comes from the main process (see status-update), so a page that
// loads mid-session still counts from the real start rather than from paint.
// Each tick recomputes from the clock instead of incrementing a counter: a
// throttled background window or a paused interval cannot make it drift.
let uptimeTimer = null;
let uptimeStartedAt = 0;

function formatUptime(ms) {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

function paintUptime() {
  if (!uptimeStartedAt) return;
  elements.uptime.textContent = `已运行 ${formatUptime(Date.now() - uptimeStartedAt)}`;
}

function startUptime(startedAt) {
  stopUptime();
  // A missing timestamp (should not happen) degrades to "starts now" instead of
  // hiding the line; the elapsed time is then relative to the event, not to zero.
  uptimeStartedAt = Number(startedAt) > 0 ? Number(startedAt) : Date.now();
  elements.uptime.hidden = false;
  paintUptime();
  uptimeTimer = setInterval(paintUptime, 1000);
}

function stopUptime() {
  if (uptimeTimer) {
    clearInterval(uptimeTimer);
    uptimeTimer = null;
  }
  uptimeStartedAt = 0;
  elements.uptime.hidden = true;
}

// Update UI status
function updateStatus(running, startedAt) {
  isRunning = running;

  // The single toggle button is never disabled — its label and color carry
  // the state: 松绿 fill invites a start (green = go), 朱砂 fill marks the
  // live session and offers the disconnect (red = stop). Cinnabar stays the
  // primary/warning color elsewhere (保存设置); it only appears here once a
  // session is actually live.
  if (running) {
    elements.btnToggle.textContent = '断开连接';
    elements.btnToggle.classList.remove('btn-pine');
    elements.btnToggle.classList.add('btn-fill');
    elements.statusDot.classList.add('running');
    elements.statusText.textContent = '运行中';
    startUptime(startedAt);
    elements.trafficIndicator.hidden = false;
  } else {
    elements.btnToggle.textContent = '启动连接';
    elements.btnToggle.classList.remove('btn-fill');
    elements.btnToggle.classList.add('btn-pine');
    elements.statusDot.classList.remove('running');
    elements.statusText.textContent = '未运行';
    stopUptime();
    elements.trafficIndicator.hidden = true;
    // Reset the display, not just hide it: the client only emits a TRAFFIC
    // line when the numbers change, so a restart would otherwise re-show the
    // PREVIOUS run's sparkline and totals until new traffic arrives.
    resetTrafficDisplay();
  }
}

// Traffic display. The main process humanizes everything (utils.js lives
// there) AND derives the session history: this side is pure presentation —
// fill the strings, plot the sparkline. histUp/histDown are RAW bytes/sec
// samples (oldest first, ≤30 points ≈ 60 s at the client's TRAFFIC cadence).
const SPARK = {
  WIDTH: 100, HEIGHT: 30,
  PADDING: 2,                       // keep the stroke clear of the viewBox edge
  UP_COLOR: '#47685a',              // 松绿 — matches --traffic-up
  DOWN_COLOR: '#2e5f74'             // 黛蓝 — matches --traffic-down (朱砂 is
                                    // reserved for stop/error, so download
                                    // must not use it)
};

function updateTraffic({ tx, rx, txRate, rxRate, txPeak, rxPeak, histUp, histDown }) {
  elements.trafficDownRate.textContent = rxRate;
  elements.trafficUpRate.textContent = txRate;
  elements.trafficDownCap.textContent = `峰值 ${rxPeak} · 累计 ${rx}`;
  elements.trafficUpCap.textContent = `峰值 ${txPeak} · 累计 ${tx}`;
  drawSpark(elements.trafficDownSpark, Array.isArray(histDown) ? histDown : [],
    SPARK.DOWN_COLOR);
  drawSpark(elements.trafficUpSpark, Array.isArray(histUp) ? histUp : [],
    SPARK.UP_COLOR);
}

// Clear the whole traffic block (used when a run ends). Plain strings rather
// than a loop over a shared "cells" list keep each element's id greppable.
function resetTrafficDisplay() {
  elements.trafficDownRate.textContent = '0 B/s';
  elements.trafficUpRate.textContent = '0 B/s';
  elements.trafficDownCap.textContent = '峰值 0 B/s · 累计 0 B';
  elements.trafficUpCap.textContent = '峰值 0 B/s · 累计 0 B';
  elements.trafficDownSpark.innerHTML = '';
  elements.trafficUpSpark.innerHTML = '';
}

// Render a sparkline as an inline SVG: light area fill + 1.2px stroke, scaled
// to the sample maximum (×1.15 headroom, floored at 1 B/s so an all-zero
// history still draws as a flat baseline). preserveAspectRatio="none" stretches
// to the container while vector-effect="non-scaling-stroke" keeps the stroke
// hairline-thin. Newest sample sits at the RIGHT edge; the curve grows in from
// there until the 30-sample window is full. innerHTML is safe here: the only
// interpolated values are numbers we computed and two hardcoded colors.
function drawSpark(container, samples, color) {
  if (!samples.length) {
    container.innerHTML = '';
    return;
  }
  const { WIDTH, HEIGHT, PADDING } = SPARK;
  const max = Math.max(...samples);
  const scale = Math.max(max * 1.15, 1);
  const usable = HEIGHT - 2 * PADDING;
  const step = WIDTH / (samples.length - 1 || 1);
  const points = samples.map((v, i) => {
    const x = i * step;
    const y = HEIGHT - PADDING - (v / scale) * usable;
    return `${x.toFixed(2)} ${y.toFixed(2)}`;
  });
  const line = `M${points.join(' L')}`;
  const area = `${line} L${WIDTH} ${HEIGHT} L0 ${HEIGHT} Z`;
  container.innerHTML =
    `<svg viewBox="0 0 ${WIDTH} ${HEIGHT}" preserveAspectRatio="none">` +
    `<path d="${area}" fill="${color}1a"/>` +
    `<path d="${line}" fill="none" stroke="${color}" stroke-width="1.2" ` +
    'vector-effect="non-scaling-stroke"/></svg>';
}

// Append log entry
function appendLog(message, level = 'info') {
  const entry = document.createElement('div');
  entry.className = `log-entry ${level}`;

  const timestamp = new Date().toLocaleTimeString('zh-CN', { hour12: false });
  entry.textContent = `[${timestamp}] ${message}`;

  elements.logContainer.appendChild(entry);

  // Auto-scroll to bottom — only while visible; a hidden container has no
  // layout, and the view-switch handler catches up on return to the tab.
  if (elements.logContainer.offsetParent !== null) scrollLogToTail();

  // Limit log entries
  const maxEntries = 1000;
  while (elements.logContainer.children.length > maxEntries) {
    elements.logContainer.removeChild(elements.logContainer.firstChild);
  }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);