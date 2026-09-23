// This preload runs SANDBOXED (see createWindow's webPreferences), so it must
// not require any local file: the sandboxed require() only serves
// electron/events/timers/url. Everything it exposes is therefore either a thin
// ipcRenderer wrapper or self-contained.
const { contextBridge, ipcRenderer } = require('electron');

// Track registered listeners for cleanup
const channelListeners = new Map();

function safeOn(channel, callback) {
  // Remove only the listener this helper registered for the channel — a
  // blanket removeAllListeners(channel) would also wipe any other subscriber.
  const prev = channelListeners.get(channel);
  if (prev) ipcRenderer.removeListener(channel, prev);
  const listener = (event, data) => callback(data);
  channelListeners.set(channel, listener);
  ipcRenderer.on(channel, listener);
}

// Expose protected methods to renderer
contextBridge.exposeInMainWorld('electronAPI', {
  // Configuration
  getConfig: () => ipcRenderer.invoke('get-config'),
  saveConfig: (config) => ipcRenderer.invoke('save-config', config),
  // Returns an error-message string, or null when the config may be launched.
  // Validated in the main process so utils.js stays the single source of truth
  // for rules that must agree with the server (see the handler in main.js).
  validateConfig: (config) => ipcRenderer.invoke('validate-config', config),

  // Proxy control
  startProxy: () => ipcRenderer.invoke('start-proxy'),
  stopProxy: () => ipcRenderer.invoke('stop-proxy'),
  getStatus: () => ipcRenderer.invoke('get-status'),
  testConnection: (host, port) => ipcRenderer.invoke('test-connection', host, port),

  // Window control
  minimizeWindow: () => ipcRenderer.send('window-minimize'),
  maximizeWindow: () => ipcRenderer.send('window-maximize'),
  closeWindow: () => ipcRenderer.send('window-close'),

  // Events (auto-cleanup on each registration)
  onStatusUpdate: (callback) => safeOn('status-update', callback),
  onLog: (callback) => safeOn('log', callback),
  onTrafficUpdate: (callback) => safeOn('traffic-update', callback),
  onUpdateStatus: (callback) => safeOn('update-status', callback),
  onMaximizeState: (callback) => safeOn('maximize-state', callback)
});