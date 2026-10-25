'use strict';

// Pure helpers shared between the Electron main process (main.js) and unit
// tests. No Electron imports — keep this file dependency-free.

const fs = require('node:fs');
const path = require('node:path');

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
  if (!bytes || bytes <= 0) return '0 B'; // 0, negative, NaN -> '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, i);
  return value.toFixed(i === 0 ? 0 : 2) + ' ' + units[i];
}

// Humanize a rate (bytes per second) for the real-time traffic display.
// Reuses formatBytes so unit boundaries and decimals can never drift apart.
function formatBytesPerSec(bytesPerSec) {
  if (!bytesPerSec || bytesPerSec <= 0) return '0 B/s';
  return formatBytes(bytesPerSec) + '/s';
}

function isValidPort(value) {
  return /^\d+$/.test(String(value).trim()) && parseInt(value, 10) >= 1 && parseInt(value, 10) <= 65535;
}

// Return an error message string, or null if the config is valid for a launch.
// cfg: { serverHost, serverPort, localPort, keyMode, keySuffix, fixedKey, keyDate?,
//        fecEnabled?, fecData?, fecParity? }
//   keyDate gives a fixed date for deterministic tests; otherwise today's Beijing date is used.
// FEC validation mirrors the C++ parse_fec_config (config.hpp): when enabled the
// pair must satisfy 1 <= PARITY <= DATA <= 255 so the redundancy ratio never
// exceeds 100%; while disabled the fields are ignored entirely.
function validateLaunchConfig(cfg) {
  if (!cfg.serverHost) return '请填写服务器地址';
  if (!isValidPort(cfg.serverPort)) return '服务器端口必须是 1-65535 之间的整数';
  if (!isValidPort(cfg.localPort)) return '本地 SOCKS 端口必须是 1-65535 之间的整数';

  if (cfg.fecEnabled) {
    // Digits-only first (same rule as the C++ parse): Number() would otherwise
    // silently accept '0x10' or '10.0' and canonicalize them into the argv.
    const dataRaw = String(cfg.fecData ?? '');
    const parityRaw = String(cfg.fecParity ?? '');
    const fecData = /^\d+$/.test(dataRaw) ? Number(dataRaw) : NaN;
    const fecParity = /^\d+$/.test(parityRaw) ? Number(parityRaw) : NaN;
    if (!Number.isInteger(fecData) || !Number.isInteger(fecParity) ||
        fecData < 1 || fecParity < 1 || fecParity > fecData ||
        fecData + fecParity > 256) {
      return 'FEC 参数必须是 DATA:PARITY，满足 1 ≤ PARITY ≤ DATA ≤ 255（例如 10:3）';
    }
  }

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

// Compose the client's argv from the launch configuration. The key is
// deliberately ABSENT from these args: it travels through KCP_PROXY_KEY in
// the environment (see buildClientEnv) because a process command line is
// visible to every local user, while its environment is not.
// allowLan binds the SOCKS listener to 0.0.0.0 instead of loopback only —
// the default stays 127.0.0.1 so a fresh install never exposes the proxy.
// FEC rides as "-fec DATA:PARITY" ONLY when enabled: an absent flag is the
// disabled form, keeping the argv (and the wire) byte-identical to pre-FEC
// launches. Both peers must run identical values — there is no negotiation.
function buildClientArgs({ serverHost, serverPort, localPort, allowLan,
                           fecEnabled, fecData, fecParity }) {
  const args = [
    '-s', String(serverHost),
    '-p', String(serverPort),
    '-H', allowLan ? '0.0.0.0' : '127.0.0.1',
    '-l', String(localPort),
    '-L', 'info'
  ];
  if (fecEnabled) {
    // Guard the pair here as well as in validateLaunchConfig: buildClientArgs is
    // also reachable from paths that skip validation (the connectivity probe,
    // unit tests, a future caller), and `Number(undefined)` would put a literal
    // "-fec NaN:NaN" on the argv, which the client's fail-closed parser rejects
    // by refusing to start at all. Defaulting keeps a half-filled form usable.
    const data = Number.isInteger(Number(fecData)) && Number(fecData) > 0
      ? Number(fecData) : 10;
    const parity = Number.isInteger(Number(fecParity)) && Number(fecParity) > 0
      ? Number(fecParity) : 3;
    args.push('-fec', `${data}:${parity}`);
  }
  return args;
}

// Compose the spawn environment for the client: the secret rides in
// KCP_PROXY_KEY on top of the parent environment.
function buildClientEnv(key, baseEnv = process.env) {
  return { ...baseEnv, KCP_PROXY_KEY: key };
}

// Resolve the app icon asset for the window/tray. The Electron main process
// looks in the app directory first (dev and unpacked builds) and then in
// process.resourcesPath (where some packaging layouts relocate assets).
// PNG is preferred over ICO: it decodes on every platform, while the ICO is
// the Windows-only multi-size ladder. Returns null when no asset exists —
// the caller decides how to degrade (window: Electron default; tray: skip).
function resolveAppIconPath(appDir, resourcesDir, exists = fs.existsSync) {
  for (const dir of [appDir, resourcesDir]) {
    if (!dir) continue;
    for (const name of ['icon.png', 'icon.ico']) {
      const candidate = path.join(dir, 'assets', name);
      if (exists(candidate)) return candidate;
    }
  }
  return null;
}

module.exports = {
  getBeijingDate,
  generateKey,
  formatBytes,
  formatBytesPerSec,
  isValidPort,
  validateLaunchConfig,
  buildClientArgs,
  buildClientEnv,
  resolveAppIconPath,
  SUFFIX_RE,
  FIXED_KEY_RE
};