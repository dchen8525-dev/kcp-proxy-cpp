const { contextBridge, ipcRenderer } = require('electron');
const { formatBytes, validateLaunchConfig } = require('./utils');

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

// Expose pure helpers (from utils.js) to the renderer. utils.js is CommonJS and
// can't be loaded via <script> in the sandboxed renderer (module is undefined),
// so it is required here (Node context) and bridged instead.
contextBridge.exposeInMainWorld('utils', {
  formatBytes,
  validateLaunchConfig
});