#!/usr/bin/env node
// Assemble npm packages: node npm/scripts/pack.mjs --root <bin-root> [--publish]
// --root layout: <rust-triple>/rsrs[.exe]; default scan is target/<triple>/release.
// Writes npm/dist/<pkg>/ then publishes platform packages then the umbrella package.
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, cpSync, existsSync, chmodSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { createHash } from 'node:crypto';

const arg = (n, d) => { const i = process.argv.indexOf(n); return i > -1 ? process.argv[i + 1] : d; };
const doPublish = process.argv.includes('--publish');
const npmTag = arg('--tag', 'latest');
const repoRoot = path.resolve(arg('--repo', '.'));
const outDir = path.join(repoRoot, 'npm', 'dist');
const manifestPath = path.join(repoRoot, 'npm', 'artifact-manifest.json');

const cargoMatch = readFileSync(path.join(repoRoot, 'cli', 'Cargo.toml'), 'utf8')
  .match(/^version\s*=\s*"([^"]+)"/m);
const version = cargoMatch ? cargoMatch[1] : '';
if (!version) {
  console.error('cannot read version from cli/Cargo.toml');
  process.exit(1);
}
if (doPublish && version.includes('-dev') && npmTag === 'latest') {
  console.error(`refusing to publish dev version ${version} with npm tag latest; use --tag dev`);
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
if (manifest.cliVersion !== version) {
  console.error(`artifact-manifest cliVersion ${manifest.cliVersion} != Cargo.toml ${version}`);
  process.exit(1);
}
const SCOPE = manifest.npmScope;
const TARGETS = Object.fromEntries(
  manifest.targets.map((t) => [t.triple, { pkg: t.pkg, os: t.os, cpu: t.cpu, libc: t.libc }]),
);

const searchRoots = [arg('--root'), 'target/ci', 'target'].filter(Boolean)
  .map((r) => path.resolve(repoRoot, r));

function findBin(triple) {
  const exe = triple.includes('windows') ? `${manifest.binaryName}.exe` : manifest.binaryName;
  const candidates = [
    ...searchRoots.map((r) => path.join(r, triple, exe)),
    ...searchRoots.map((r) => path.join(r, triple, 'release', exe)),
  ];
  return candidates.find(existsSync);
}

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });
const built = [];

for (const [triple, t] of Object.entries(TARGETS)) {
  const src = findBin(triple);
  if (!src) {
    console.warn(`skip ${triple} (no binary)`);
    continue;
  }
  const dir = path.join(outDir, t.pkg);
  mkdirSync(path.join(dir, 'bin'), { recursive: true });
  copyFileSync(path.join(repoRoot, 'LICENSE'), path.join(dir, 'LICENSE'));
  const binFile = path.basename(src);
  copyFileSync(src, path.join(dir, 'bin', binFile));
  const runtime = JSON.parse(readFileSync(path.join(path.dirname(src), 'core-runtime.json'), 'utf8'));
  if (runtime.target !== triple) throw new Error(`runtime target mismatch: ${triple}`);
  if (!runtime.files.some(file => file.path === 'core-notices/native/CORE-SDK-NOTICE.txt')) {
    throw new Error(`Core SDK license notice missing: ${triple}`);
  }
  if (!runtime.files.some(file => file.path === 'core-notices/CORE-SDK-LICENSE.txt')) {
    throw new Error(`Core SDK redistribution license missing: ${triple}`);
  }
  if (doPublish && runtime.redistribution !== 'permitted-under-included-license') {
    throw new Error('Core SDK redistribution is not permitted under the included license');
  }
  for (const file of runtime.files) {
    if (file.path.includes('\\') || file.path.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('Unsafe runtime path');
    const bytes = readFileSync(path.join(path.dirname(src), file.path));
    if (createHash('sha256').update(bytes).digest('hex') !== file.sha256) throw new Error(`runtime checksum mismatch: ${file.path}`);
    const destination = path.join(dir, 'bin', file.path);
    mkdirSync(path.dirname(destination), {recursive:true});
    writeFileSync(destination, bytes);
  }
  copyFileSync(path.join(path.dirname(src), 'core-runtime.json'), path.join(dir, 'bin', 'core-runtime.json'));
  chmodSync(path.join(dir, 'bin', binFile), 0o755);
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: t.pkg, version,
    description: 'rsrs CLI platform binary',
    repository: { type: 'git', url: 'git+https://github.com/risense-ai/respire-cli.git' },
    license: 'SEE LICENSE IN bin/core-notices/CORE-SDK-LICENSE.txt', os: t.os, cpu: t.cpu, ...(t.libc ? {libc: t.libc} : {}), files: ['bin', 'LICENSE'],
    exports: { [`./bin/${binFile}`]: `./bin/${binFile}` },
  }, null, 2) + '\n');
  built.push({ name: t.pkg, dir });
}

// The umbrella package must always declare every supported platform package.
// Otherwise a release assembled without one downloaded artifact publishes
// successfully, but npm never installs that platform's binary and the
// wrapper reports it as missing at runtime.
const optionalDependencies = Object.fromEntries(
  manifest.targets.map((t) => [t.pkg, version]),
);
const missingTargets = manifest.targets.filter((t) => !built.some((b) => b.name === t.pkg));
if (doPublish && missingTargets.length) {
  console.error(`missing platform binaries: ${missingTargets.map((t) => t.pkg).join(', ')}`);
  process.exit(1);
}

const mainDir = path.join(outDir, SCOPE);
mkdirSync(path.join(mainDir, 'bin'), { recursive: true });
copyFileSync(path.join(repoRoot, 'npm', 'bin', 'cli.js'), path.join(mainDir, 'bin', 'cli.js'));
chmodSync(path.join(mainDir, 'bin', 'cli.js'), 0o755);
cpSync(path.join(repoRoot, 'npm', 'README.md'), path.join(mainDir, 'README.md'));
copyFileSync(path.join(repoRoot, 'LICENSE'), path.join(mainDir, 'LICENSE'));
const webDist = path.join(repoRoot, 'npm', 'web-dist');
if (!existsSync(path.join(webDist, 'index.html'))) {
  console.error('npm/web-dist/index.html is missing; cargo embeds it into the CLI at build time');
  process.exit(1);
}

writeFileSync(path.join(mainDir, 'package.json'), JSON.stringify({
  name: SCOPE, version,
  description: 'rsrs CLI — encrypted cross-device AI memory',
  license: 'MIT',
  repository: { type: 'git', url: 'git+https://github.com/risense-ai/respire-cli.git' },
  bin: { 'rsrs': './bin/cli.js' },
  files: ['bin', 'README.md', 'LICENSE'],
  engines: { node: '>=16' },
  optionalDependencies,
}, null, 2) + '\n');
built.push({ name: SCOPE, dir: mainDir });

console.log(`version ${version}: packed ${built.length} packages -> npm/dist/`);
for (const b of built) console.log(`  ${b.name}${doPublish ? '' : ' (dry run)'}`);

if (doPublish) {
  for (const b of built) {
    console.log(`\nnpm publish ${b.dir} --access public`);
    const r = spawnSync('npm', ['publish', b.dir, '--access', 'public', '--tag', npmTag], { stdio: 'inherit' });
    if (r.status !== 0) {
      console.error(`publish failed: ${b.name}`);
      process.exit(1);
    }
  }
  console.log('\npublish complete');
}
