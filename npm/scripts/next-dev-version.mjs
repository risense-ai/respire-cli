import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';

const manifest = JSON.parse(readFileSync('npm/artifact-manifest.json', 'utf8'));
const match = /^(\d+\.\d+\.\d+)(?:-dev\.\d+)?$/.exec(manifest.cliVersion);
if (!match) throw new Error('Invalid CLI development version base');
const base = match[1];
const pattern = new RegExp(`^v?${base.replaceAll('.', '\\.')}\\-dev\\.(\\d+)$`);
let highest = 0;
function observe(version) {
  const found = pattern.exec(version);
  if (!found) return;
  const number = Number(found[1]);
  if (!Number.isSafeInteger(number)) throw new Error('Invalid existing development sequence');
  highest = Math.max(highest, number);
}

// Tags and draft releases reserve numbers even when npm metadata is still propagating.
execFileSync('git', ['tag', '--list', `v${base}-dev.*`], {encoding: 'utf8'})
  .trim().split(/\r?\n/).forEach(observe);
const repository = process.env.GITHUB_REPOSITORY || 'risense-ai/respire-cli';
execFileSync('gh', ['api', `repos/${repository}/releases?per_page=100`, '--paginate', '--jq', '.[].tag_name'], {encoding: 'utf8'})
  .trim().split(/\r?\n/).forEach(observe);

// Inspect all eight packages so a partially published release cannot reuse its version.
await Promise.all([manifest.npmScope, ...manifest.targets.map(target => target.pkg)].map(async name => {
  const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}?sequence=${Date.now()}`, {
    headers: {'Cache-Control': 'no-cache'}, signal: AbortSignal.timeout(15000),
  });
  if (response.status === 404) return;
  if (!response.ok) throw new Error(`Cannot read published versions for ${name}: HTTP ${response.status}`);
  const metadata = await response.json();
  if (!metadata.versions || typeof metadata.versions !== 'object') throw new Error(`Invalid npm metadata for ${name}`);
  Object.keys(metadata.versions).forEach(observe);
}));
if (!Number.isSafeInteger(highest + 1)) throw new Error('Development sequence exhausted');
console.log(`${base}-dev.${highest + 1}`);
