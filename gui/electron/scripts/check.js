'use strict';

// Entry point for `npm run check` (also invoked by CI).
//
// It syntax-checks every shipped JS file and validates every electron-builder
// config plus package.json as JSON. This lives in its own file rather than in
// the npm script so the file list can grow without the script becoming one
// unreadable several-hundred-character line.

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

const SYNTAX_FILES = [
  'main.js',
  'preload.js',
  'renderer.js',
  'utils.js',
  'test/utils.test.js',
  'test/launch-contract.test.js',
  'test/pipelined-smoke.js'
];

let failed = false;

function fail(message) {
  failed = true;
  console.error(message);
}

for (const relative of SYNTAX_FILES) {
  const target = path.join(ROOT, relative);
  if (!fs.existsSync(target)) {
    fail(`missing file: ${relative}`);
    continue;
  }
  // --check parses the file; it never executes it.
  const result = spawnSync(process.execPath, ['--check', target], { stdio: 'inherit' });
  if (result.status !== 0) {
    fail(`syntax error: ${relative}`);
  }
}

// An empty match set would make this loop a no-op, so treat it as a failure:
// it means the configs were renamed and a broken one could ship unnoticed.
const jsonFiles = fs.readdirSync(ROOT)
  .filter((name) => name.startsWith('electron-builder') && name.endsWith('.json'))
  .concat(['package.json']);

if (jsonFiles.length <= 1) {
  fail('no electron-builder configs found');
}

for (const name of jsonFiles) {
  try {
    JSON.parse(fs.readFileSync(path.join(ROOT, name), 'utf8'));
  } catch (err) {
    fail(`invalid JSON in ${name}: ${err.message}`);
  }
}

if (failed) {
  process.exit(1);
}

console.log(`check passed (${SYNTAX_FILES.length} files syntax-checked, ${jsonFiles.length} JSON files)`);
