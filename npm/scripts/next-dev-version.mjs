import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';

const manifest = JSON.parse(readFileSync('npm/artifact-manifest.json', 'utf8'));
const integer = '(0|[1-9]\\d*)';
function parse(version, development = false) {
  const pattern = new RegExp(`^${integer}\\.${integer}\\.${integer}${development ? `(?:-dev\\.${integer})?` : ''}$`);
  const found = pattern.exec(version);
  if (!found) throw new Error(`Invalid version: ${version}`);
  const parts = found.slice(1).filter(part => part !== undefined).map(Number);
  if (!parts.every(Number.isSafeInteger)) throw new Error(`Version number exceeds safe integer range: ${version}`);
  return parts.slice(0, 3);
}
function compare(left, right) {
  for (let index = 0; index < 3; index++) {
    if (left[index] !== right[index]) return left[index] > right[index] ? 1 : -1;
  }
  return 0;
}
const target = parse(manifest.cliVersion, true);
const tags = execFileSync('git', ['tag', '--list'], {encoding: 'utf8'}).trim().split(/\r?\n/).filter(Boolean);
const repository = process.env.GITHUB_REPOSITORY || 'risense-ai/respire-cli';
const releases = execFileSync('gh', ['api', `repos/${repository}/releases?per_page=100`, '--paginate', '--jq', '.[] | {tag_name,draft,prerelease} | @json'], {encoding: 'utf8'})
  .trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
let stable;
function observeStable(version) {
  const parts = parse(version);
  if (!stable || compare(parts, stable) > 0) stable = parts;
}
for (const tag of tags) {
  if (new RegExp(`^v${integer}\\.${integer}\\.${integer}$`).test(tag)) observeStable(tag.slice(1));
}
for (const release of releases) {
  if (typeof release.tag_name !== 'string' || typeof release.draft !== 'boolean' || typeof release.prerelease !== 'boolean') {
    throw new Error('Invalid GitHub release metadata');
  }
  if (!release.draft && !release.prerelease) observeStable(release.tag_name.replace(/^v/, ''));
}

// Inspect all eight packages so a partially published release cannot reuse its version.
const packages = await Promise.all([manifest.npmScope, ...manifest.targets.map(target => target.pkg)].map(async name => {
  const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}?sequence=${Date.now()}`, {
    headers: {'Cache-Control': 'no-cache'}, signal: AbortSignal.timeout(15000),
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`Cannot read published versions for ${name}: HTTP ${response.status}`);
  const metadata = await response.json();
  if (!metadata.versions || typeof metadata.versions !== 'object' || Array.isArray(metadata.versions)) throw new Error(`Invalid npm metadata for ${name}`);
  const latest = metadata['dist-tags']?.latest;
  if (latest !== undefined) {
    if (typeof latest !== 'string') throw new Error(`Invalid npm latest metadata for ${name}`);
    const identifier = '(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)';
    const prerelease = new RegExp(`^(${integer}\\.${integer}\\.${integer})-${identifier}(?:\\.${identifier})*(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$`).exec(latest);
    if (prerelease) parse(prerelease[1]);
    else observeStable(latest);
  }
  return metadata;
}));
let next = target;
if (stable && compare(target, stable) <= 0) {
  if (!Number.isSafeInteger(stable[2] + 1)) throw new Error('Stable patch version exhausted');
  next = [stable[0], stable[1], stable[2] + 1];
}
const base = next.join('.');
const pattern = new RegExp(`^v?${base.replaceAll('.', '\\.')}-dev\\.${integer}$`);
let highest = 0;
function observe(version) {
  const found = pattern.exec(version);
  if (!found) {
    if (version.replace(/^v/, '').startsWith(`${base}-dev.`)) throw new Error('Invalid existing development sequence');
    return;
  }
  const number = Number(found[1]);
  if (!Number.isSafeInteger(number)) throw new Error('Invalid existing development sequence');
  highest = Math.max(highest, number);
}
// Tags and every release, including drafts, reserve development numbers.
tags.forEach(observe);
releases.forEach(release => observe(release.tag_name));
packages.filter(Boolean).forEach(metadata => Object.keys(metadata.versions).forEach(observe));
if (!Number.isSafeInteger(highest + 1)) throw new Error('Development sequence exhausted');
console.log(`${base}-dev.${highest + 1}`);
