#!/usr/bin/env node
'use strict';
// Locate the platform package binary and forward CLI arguments.
const { spawnSync } = require('child_process');
const path = require('path');
const { existsSync } = require('fs');

const PKGS = {
  'linux-x64': '@rsrsai/linux-x64',
  'linux-arm64': '@rsrsai/linux-arm64',
  'darwin-arm64': '@rsrsai/macos-arm64',
  'win32-x64': '@rsrsai/win-x64',
  'win32-arm64': '@rsrsai/win-arm64',
};

const key = `${process.platform}-${process.arch}`;
let pkg = PKGS[key];
if (process.platform === 'linux') {
  const libc = process.env.RSRS_LIBC || 'musl';
  if (libc !== 'musl' && libc !== 'glibc') {
    console.error('rsrs: RSRS_LIBC must be musl or glibc.');
    process.exit(1);
  }
  if (pkg && libc === 'glibc') pkg += '-gnu';
}
if (!pkg) {
  if (key === 'darwin-x64') {
    console.error(
      'rsrs: Intel Mac is unsupported.\n' +
      '  Use Apple Silicon (arm64), Linux or Windows.\n' +
      '  See https://github.com/risense-ai/respire-cli#use-and-distribution'
    );
  } else {
    console.error(`rsrs: unsupported platform ${key} (supported: ${Object.keys(PKGS).join(' ')})`);
  }
  process.exit(1);
}

const exe = process.platform === 'win32' ? 'rsrs.exe' : 'rsrs';
function resolveBin(pkgName, exeName) {
  try {
    return require.resolve(`${pkgName}/bin/${exeName}`);
  } catch {
    /* optional dep missing or installed as a global sibling */
  }
  const rel = path.join(...pkgName.split('/'), 'bin', exeName);
  let dir = __dirname;
  for (let i = 0; i < 12; i++) {
    const hits = [path.join(dir, 'node_modules', rel), path.join(dir, rel)];
    for (const p of hits) {
      if (existsSync(p)) return p;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}
const bin = resolveBin(pkg, exe);
if (!bin) {
  console.error(`rsrs: platform package ${pkg} is missing. Install: npm i -g ${pkg}`);
  process.exit(1);
}

// UI assets are embedded at compile time; no runtime web-dist lookup is needed.
const r = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit', env: process.env });
if (r.error) {
  console.error(`rsrs: ${r.error.message}`);
  process.exit(1);
}
process.exit(r.status ?? 1);
