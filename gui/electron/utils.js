'use strict';

// Pure helpers shared between the Electron main process (main.js) and unit
// tests. No Electron imports — keep this file dependency-free.

// Beijing date (YYYYMMDD) for the "daily key" mode. Beijing is UTC+8.
function getBeijingDate(now = new Date()) {
  const beijing = new Date(now.getTime() + (8 * 60 * 60 * 1000));
  const year = beijing.getUTCFullYear();
  const month = String(beijing.getUTCMonth() + 1).padStart(2, '0');
  const day = String(beijing.getUTCDate()).padStart(2, '0');
  return `${year}${month}${day}`;
}

// Compose the wire key from the configured mode.
//   keyMode 'fixed' -> fixedKey (verbatim)
//   keyMode 'daily' -> Beijing date + suffix
function generateKey(keyMode, { date, suffix, fixedKey } = {}) {
  if (keyMode === 'fixed') return fixedKey || '';
  const d = date || getBeijingDate();
  return d + (suffix || '');
}

// Server suffix / key validation (kept in sync with main.js checks).
const SUFFIX_RE = /^[A-Za-z0-9._-]{8,128}$/;
const FIXED_KEY_RE = /^[\x21-\x7e]{16,256}$/;

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, i);
  return value.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function isValidPort(value) {
  return /^\d+$/.test(String(value).trim()) && parseInt(value, 10) >= 1 && parseInt(value, 10) <= 65535;
}

// Return an error message string, or null if the config is valid for a launch.
// cfg: { serverHost, serverPort, localPort, keyMode, keySuffix, fixedKey, keyDate? }
//   keyDate gives a fixed date for deterministic tests; otherwise today's Beijing date is used.
function validateLaunchConfig(cfg) {
  if (!cfg.serverHost) return '请填写服务器地址';
  if (!isValidPort(cfg.serverPort)) return '服务器端口必须是 1-65535 之间的整数';
  if (!isValidPort(cfg.localPort)) return '本地 SOCKS 端口必须是 1-65535 之间的整数';

  const key = generateKey(cfg.keyMode, {
    date: cfg.keyDate,
    suffix: cfg.keySuffix,
    fixedKey: cfg.fixedKey
  });
  if (!key || key.length < 16) return '密钥长度不足 16 个字符';
  if (cfg.keyMode === 'daily' && !SUFFIX_RE.test(cfg.keySuffix || '')) {
    return '每日密钥后缀必须是 8-128 位字母、数字、点、下划线或短横线';
  }
  if (cfg.keyMode === 'fixed' && !FIXED_KEY_RE.test(key)) {
    return '固定密钥必须是 16-256 个可打印字符';
  }
  return null;
}

module.exports = {
  getBeijingDate,
  generateKey,
  formatBytes,
  isValidPort,
  validateLaunchConfig,
  SUFFIX_RE,
  FIXED_KEY_RE
};