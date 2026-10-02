import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const selection = process.argv[2];
if (!['protocol', 'sdk'].includes(selection)) throw new Error('Select protocol or sdk');
if (!process.env.CARGO_REGISTRY_TOKEN) throw new Error('CARGO_REGISTRY_TOKEN is required for explicit publication');
const path = join(root, 'crates', selection === 'sdk' ? 'core-sdk' : 'protocol', 'Cargo.toml');
const manifest = readFileSync(path, 'utf8');
const name = /^name\s*=\s*"([^"]+)"/m.exec(manifest)?.[1], version = /^version\s*=\s*"([^"]+)"/m.exec(manifest)?.[1];
if (!name || !version) throw new Error('Missing crate metadata');
const url = `https://static.crates.io/crates/${name}/${name}-${version}.crate`;
const response = await fetch(url);
await response.body?.cancel();
if (response.ok) {
  if (selection === 'protocol') console.log(`Protocol ${version} already exists; using its registry version`);
  else throw new Error(`SDK binding ${version} already exists; choose a new crate version`);
} else {
  if (response.status !== 403 && response.status !== 404) throw new Error(`Registry availability check failed: HTTP ${response.status}`);
  const result = spawnSync('cargo', ['publish', '--locked', '--manifest-path', path], { cwd: root, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('Cargo publication failed');
  let ready = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    const check = await fetch(url);
    await check.body?.cancel();
    if (check.ok) { ready = true; break; }
    await new Promise(done => setTimeout(done, 2000));
  }
  if (!ready) throw new Error('Published crate is not yet downloadable; stop before publishing dependent crates');
}
