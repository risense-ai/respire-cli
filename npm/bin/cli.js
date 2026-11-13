#!/usr/bin/env node
'use strict';
// Locate the platform package binary and forward CLI arguments.
const { spawnSync } = require('child_process');
const path = require('path');
const { existsSync, readFileSync } = require('fs');
const manifest = require('../package.json');
const version = manifest.version;

const PKGS = {
  'linux-x64': '@rsrsai/linux-x64',
  'linux-arm64': '@rsrsai/linux-arm64',
  'darwin-arm64': '@rsrsai/macos-arm64',
  'darwin-x64': '@rsrsai/macos-x64',
  'win32-x64': '@rsrsai/win-x64',
  'win32-arm64': '@rsrsai/win-arm64',
};

const key = `${process.platform}-${process.arch}`;
let pkg = PKGS[key];
if (process.platform === 'linux') {
  const configuredLibc = process.env.RSRS_LIBC ?? process.env.ONEMEMORY_LIBC ?? process.env.RESPIRE_LIBC;
  let libc = configuredLibc ?? 'musl';
  if (configuredLibc === undefined && pkg === '@rsrsai/linux-arm64'
      && manifest.optionalDependencies && !Object.prototype.hasOwnProperty.call(manifest.optionalDependencies, pkg)
      && process.report?.getReport?.()?.header?.glibcVersionRuntime) {
    libc = 'glibc';
  }
  if (libc !== 'musl' && libc !== 'glibc') {
    console.error('rsrs: RSRS_LIBC must be musl or glibc.');
    process.exit(1);
  }
  if (pkg && libc === 'glibc') pkg += '-gnu';
}
if (!pkg) {
  console.error(`rsrs: unsupported platform ${key} (supported: ${Object.keys(PKGS).join(' ')})`);
  process.exit(1);
}
if (pkg === '@rsrsai/linux-arm64' && manifest.optionalDependencies
    && !Object.prototype.hasOwnProperty.call(manifest.optionalDependencies, pkg)) {
  console.error(`rsrs: platform package ${pkg} is not published for ${version}. Linux ARM64 musl is deferred for CLI 2.x DEV: https://github.com/risense-ai/respire-cli/issues/272`);
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
  console.error(`rsrs: platform package ${pkg} is missing. Install: npm i -g ${pkg}@${version}`);
  process.exit(1);
}

try {
  const platform = JSON.parse(readFileSync(path.join(path.dirname(path.dirname(bin)), 'package.json'), 'utf8'));
  if (platform.name !== pkg || platform.version !== version) {
    throw new Error(`expected ${pkg}@${version}, found ${platform.name}@${platform.version}`);
  }
} catch (error) {
  console.error(`rsrs: incompatible platform package: ${error.message}. Install: npm i -g ${pkg}@${version}`);
  process.exit(1);
}

// The CLI opens the hosted dashboard; no UI assets are bundled.
const r = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit', env: process.env });
if (r.error) {
  console.error(`rsrs: ${r.error.message}`);
  process.exit(1);
}
process.exit(r.status ?? 1);
