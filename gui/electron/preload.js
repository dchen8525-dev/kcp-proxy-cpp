const { contextBridge, ipcRenderer } = require('electron');
const { formatBytes, validateLaunchConfig } = require('./utils');

// Track registered listeners for cleanup
function safeOn(channel, callback) {
  // Remove previous listener for this channel to prevent leaks
  ipcRenderer.removeAllListeners(channel);
  ipcRenderer.on(channel, (event, data) => callback(data));
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

  // Updater
  checkForUpdates: () => ipcRenderer.invoke('check-for-updates'),
  quitAndInstall: () => ipcRenderer.invoke('quit-and-install'),

  // Events (auto-cleanup on each registration)
  onStatusUpdate: (callback) => safeOn('status-update', callback),
  onLog: (callback) => safeOn('log', callback),
  onTrafficUpdate: (callback) => safeOn('traffic-update', callback),
  onUpdateStatus: (callback) => safeOn('update-status', callback),
  onMaximizeState: (callback) => safeOn('maximize-state', callback),

  // Remove all listeners
  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  }
});

// Expose pure helpers (from utils.js) to the renderer. utils.js is CommonJS and
// can't be loaded via <script> in the sandboxed renderer (module is undefined),
// so it is required here (Node context) and bridged instead.
contextBridge.exposeInMainWorld('utils', {
  formatBytes,
  validateLaunchConfig
});