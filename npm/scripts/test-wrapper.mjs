import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import vm from 'node:vm';

const source = readFileSync(new URL('../bin/cli.js', import.meta.url), 'utf8');
const version = '1.0.11-dev.5';
const manifest = JSON.parse(readFileSync(new URL('../artifact-manifest.json', import.meta.url)));
const optionalDependencies = Object.fromEntries(manifest.targets.map(t => [t.pkg, version]));
const targets = [
  ['linux', 'x64', 'musl', 'linux-x64'],
  ['linux', 'x64', 'glibc', 'linux-x64-gnu'],
  ['linux', 'arm64', 'musl', 'linux-arm64'],
  ['linux', 'arm64', 'glibc', 'linux-arm64-gnu'],
  ['linux', 'arm64', '', 'linux-arm64-gnu'],
  ['darwin', 'x64', '', 'macos-x64'],
  ['darwin', 'arm64', '', 'macos-arm64'], ['win32', 'x64', '', 'win-x64'],
  ['win32', 'arm64', '', 'win-arm64'],
];
let cases = 0;
for (const [platform, arch, libc, name] of targets) {
  for (const resolution of ['module', 'global-sibling']) {
    for (const launcher of [['@rsrsai', 'cli'], ['rsrs-cli']]) {
    for (const installed of [null, '1.0.9', version, 'invalid-manifest']) {
      const root = mkdtempSync(path.join(os.tmpdir(), 'rsrs-wrapper-'));
      try {
        const directory = path.join(root, 'node_modules', ...launcher, 'bin');
        mkdirSync(directory, { recursive: true });
        const pkg = `@rsrsai/${name}`;
        const packageRoot = path.join(root, 'node_modules', '@rsrsai', name);
        const binary = path.join(packageRoot, 'bin', platform === 'win32' ? 'rsrs.exe' : 'rsrs');
        if (installed) {
          mkdirSync(path.dirname(binary), { recursive: true });
          writeFileSync(binary, 'fixture');
          writeFileSync(path.join(packageRoot, 'package.json'), installed === 'invalid-manifest' ? '{' : JSON.stringify({ name: pkg, version: installed }));
        }
        let spawned = false, exit, stderr = '';
        const quit = {};
        const require = (name) => {
          if (name === '../package.json') return { version, optionalDependencies };
          if (name === 'fs') return fs;
          if (name === 'path') return path;
          if (name === 'child_process') return { spawnSync: () => { spawned = true; return { status: 0 }; } };
          throw new Error(name);
        };
        require.resolve = () => {
          if (resolution === 'module' && installed) return binary;
          throw new Error('missing');
        };
        try {
          vm.runInNewContext(source, { require, __dirname: directory,
            console: { error: (message) => { stderr += message; } },
            process: { platform, arch, env: libc ? { RSRS_LIBC: libc } : {},
              report: { getReport: () => ({header: resolution === 'module' ? {glibcVersionRuntime:'2.39'} : {}}) }, argv: ['node', 'cli', '--version'],
              exit: (code) => { exit = code; throw quit; } } });
        } catch (error) { if (error !== quit) throw error; }
        const deferred = platform === 'linux' && arch === 'arm64'
          && (libc === 'musl' || (!libc && resolution === 'global-sibling'));
        assert.equal(spawned, !deferred && installed === version);
        assert.equal(exit, !deferred && installed === version ? 0 : 1);
        if (deferred) assert.ok(stderr.includes('not published') && stderr.includes('/issues/272'), stderr);
        else if (installed !== version) assert.ok(stderr.includes(`${pkg}@${version}`), stderr);
        cases++;
      } finally { rmSync(root, { recursive: true, force: true }); }
    }
  }
}
}
for (const [platform, arch] of [['win32', 'ia32']]) {
  let exit, stderr = '';
  const quit = {};
  const require = (name) => {
    if (name === '../package.json') return { version };
    if (name === 'fs') return fs;
    if (name === 'path') return path;
    if (name === 'child_process') return { spawnSync: () => { throw new Error('Unsupported platform launched a binary'); } };
    throw new Error(name);
  };
  try {
    vm.runInNewContext(source, { require, __dirname: '.',
      console: { error: (message) => { stderr += message; } },
      process: { platform, arch, env: {}, argv: ['node', 'cli', '--version'],
        exit: (code) => { exit = code; throw quit; } } });
  } catch (error) { if (error !== quit) throw error; }
  assert.equal(exit, 1);
  assert.ok(stderr.includes(`unsupported platform ${platform}-${arch}`), stderr);
  cases++;
}
console.log(`Wrapper version regression: ${cases} cases passed`);
