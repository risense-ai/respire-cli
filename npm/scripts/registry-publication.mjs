// Immutable npm publication helpers. Public registry reads never use npm credentials.
import {createHash} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

export const REGISTRY = 'https://registry.npmjs.org';
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const packageName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

export class PackageNotVisibleError extends Error {}

function identity(expected) {
  if (!expected || !packageName.test(expected.name) || !versionPattern.test(expected.version)) {
    throw new Error('Invalid expected npm package identity');
  }
  if (!/^sha512-[A-Za-z0-9+/]{86}==$/.test(expected.integrity || '')
      || !/^[a-f0-9]{40}$/.test(expected.shasum || '')) {
    throw new Error(`Missing or invalid pack integrity/shasum: ${expected.name}@${expected.version}`);
  }
  return `${expected.name}@${expected.version}`;
}

function archiveName(filename) {
  if (typeof filename !== 'string' || !/^[a-zA-Z0-9@._-]+\.tgz$/.test(filename)
      || path.basename(filename) !== filename) throw new Error('Unsafe npm pack filename');
  return filename;
}

export function assertPackMatches(actual, expected) {
  const label = identity(expected);
  identity(actual);
  for (const field of ['name', 'version', 'integrity', 'shasum']) {
    if (actual[field] !== expected[field]) throw new Error(`Pack ${field} mismatch: ${label}`);
  }
  return actual;
}

export function readExpectedPacks(dist, manifest, version = manifest.cliVersion) {
  if (manifest.cliVersion !== version) throw new Error('Pack receipt manifest/version mismatch');
  const names = [...manifest.targets.map(target => target.pkg), manifest.npmScope];
  if (new Set(names).size !== names.length) throw new Error('Duplicate npm package in manifest');
  return names.map(name => {
    if (!packageName.test(name)) throw new Error('Invalid manifest npm package name');
    const dir = path.resolve(dist, name);
    const pkg = JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8'));
    const report = JSON.parse(readFileSync(path.join(dir, 'release.pack.json'), 'utf8'));
    if (!Array.isArray(report) || report.length !== 1 || pkg.name !== name || pkg.version !== version
        || report[0].name !== name || report[0].version !== version) {
      throw new Error(`Verified pack receipt identity mismatch: ${name}@${version}`);
    }
    const expected = {...report[0], filename: archiveName(report[0].filename), dir};
    identity(expected);
    return expected;
  });
}

function hashBytes(bytes) {
  return {
    integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
    shasum: createHash('sha1').update(bytes).digest('hex'),
  };
}

export function packPackage(dir, dest, options = {}) {
  mkdirSync(dest, {recursive: true});
  const pkg = JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8'));
  const result = (options.spawnImpl || spawnSync)(npm,
    ['pack', '--json', '--ignore-scripts', '--pack-destination', path.resolve(dest)],
    {cwd: dir, encoding: 'utf8', shell: process.platform === 'win32'});
  if (result.error || result.status !== 0) throw new Error(`npm pack failed: ${pkg.name}\n${result.error?.message || result.stderr || ''}`);
  const raw = JSON.parse(result.stdout);
  // npm <= 11 emits an array; npm 12 emits an object keyed by package name.
  const report = Array.isArray(raw) ? raw : raw && typeof raw === 'object' &&
    Object.keys(raw).length === 1 && Object.hasOwn(raw, pkg.name) ? [raw[pkg.name]] : null;
  if (!report || report.length !== 1 || report[0]?.name !== pkg.name || report[0]?.version !== pkg.version) {
    throw new Error(`npm pack report identity mismatch: ${pkg.name}`);
  }
  const expected = {...report[0], filename: archiveName(report[0].filename), dir: path.resolve(dir)};
  identity(expected);
  expected.tarballPath = path.resolve(dest, expected.filename);
  assertPackMatches({...expected, ...hashBytes(readFileSync(expected.tarballPath))}, expected);
  return expected;
}

function registryUrl(raw) {
  const url = new URL(raw);
  if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.port
      || url.username || url.password || url.hash || url.search) {
    throw new Error('Unsafe registry URL; only credential-free HTTPS registry.npmjs.org URLs are allowed');
  }
  return url.href;
}

async function get(raw, options, tarball = false) {
  const url = registryUrl(raw);
  const requestedTimeout = tarball ? (options.tarballTimeoutMs ?? 240000) : (options.requestTimeoutMs ?? 30000);
  const requestTimeoutMs = options.deadline === undefined ? requestedTimeout
    : Math.min(requestedTimeout, Math.max(1, options.deadline - (options.now || Date.now)()));
  if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) throw new Error('Invalid registry request timeout');
  const response = await (options.fetchImpl || globalThis.fetch)(url, {
    method: 'GET', headers: {'Accept': 'application/json', 'Cache-Control': 'no-cache'},
    credentials: 'omit', redirect: 'error', cache: 'no-store',
    signal: AbortSignal.timeout(Math.max(1, Math.ceil(requestTimeoutMs))),
  });
  // fetchImpl is injectable for offline tests; native fetch supplies response.url.
  if (response.url && registryUrl(response.url) !== url) throw new Error('Unexpected registry redirect');
  if (response.status !== 200 && response.status !== 404) {
    throw new Error(`Registry HTTP ${response.status}: ${url}`);
  }
  return response;
}

async function verifyTarball(metadata, expected, options) {
  const response = await get(metadata.dist.tarball, options, true);
  if (response.status === 404) throw new PackageNotVisibleError(`Registry tarball is not visible: ${identity(expected)}`);
  const sha512 = createHash('sha512');
  const sha1 = createHash('sha1');
  let length = 0;
  const maxTarballBytes = options.maxTarballBytes ?? 1024 * 1024 * 1024;
  const add = bytes => {
    length += bytes.length;
    if (length > maxTarballBytes) throw new Error(`Registry tarball exceeds size limit: ${identity(expected)}`);
    sha512.update(bytes); sha1.update(bytes);
  };
  if (response.body?.[Symbol.asyncIterator]) {
    for await (const chunk of response.body) add(chunk);
  } else {
    throw new Error('Registry tarball response must provide a streaming body');
  }
  assertPackMatches({name: expected.name, version: expected.version,
    integrity: `sha512-${sha512.digest('base64')}`, shasum: sha1.digest('hex')}, expected);
}

// Only an exact-version metadata HTTP 404 is treated as an absent package.
export async function checkPackage(expected, options = {}) {
  const label = identity(expected);
  const response = await get(`${REGISTRY}/${encodeURIComponent(expected.name)}/${encodeURIComponent(expected.version)}`, options);
  if (response.status === 404) return null;
  const metadata = await response.json();
  if (metadata.name !== expected.name || metadata.version !== expected.version) throw new Error(`Registry identity mismatch: ${label}`);
  if (expected.dependencies) {
    const entries = value => value && typeof value === 'object' && !Array.isArray(value)
      ? JSON.stringify(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))) : null;
    if (entries(metadata.dependencies) !== entries(expected.dependencies)) throw new Error(`Registry dependencies mismatch: ${label}`);
  }
  if (!metadata.dist || typeof metadata.dist.tarball !== 'string') throw new Error(`Registry dist missing: ${label}`);
  assertPackMatches({name: metadata.name, version: metadata.version,
    integrity: metadata.dist.integrity, shasum: metadata.dist.shasum}, expected);
  await verifyTarball(metadata, expected, options);
  return metadata;
}

export async function waitForPackage(expected, options = {}) {
  identity(expected);
  const timeoutMs = options.timeoutMs ?? 600000;
  const pollMs = options.pollMs ?? 3000;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0 || !Number.isFinite(pollMs) || pollMs <= 0) {
    throw new Error('Invalid registry propagation timeout/poll interval');
  }
  const now = options.now || Date.now;
  const deadline = now() + timeoutMs;
  while (true) {
    try {
      const metadata = await checkPackage(expected, {...options, deadline});
      if (metadata) return metadata;
    } catch (error) {
      if (!(error instanceof PackageNotVisibleError)) throw error;
    }
    const remaining = deadline - now();
    if (remaining <= 0) throw new PackageNotVisibleError(`Registry propagation timed out: ${identity(expected)}`);
    await (options.sleep || pause)(Math.min(pollMs, remaining));
  }
}

// SemVer precedence, including numeric prerelease identifiers (dev.10 > dev.9).
export function compareVersions(left, right) {
  const a = typeof left === 'string' && left.match(versionPattern);
  const b = typeof right === 'string' && right.match(versionPattern);
  if (!a || !b) throw new Error(`Cannot safely compare npm tag versions: ${left}, ${right}`);
  for (let i = 1; i <= 3; i++) {
    if (BigInt(a[i]) !== BigInt(b[i])) return BigInt(a[i]) > BigInt(b[i]) ? 1 : -1;
  }
  if (!a[4] || !b[4]) return a[4] === b[4] ? 0 : a[4] ? -1 : 1;
  const ap = a[4].split('.'), bp = b[4].split('.');
  for (let i = 0; i < Math.max(ap.length, bp.length); i++) {
    if (ap[i] === bp[i]) continue;
    if (ap[i] === undefined || bp[i] === undefined) return ap[i] === undefined ? -1 : 1;
    const an = /^\d+$/.test(ap[i]), bn = /^\d+$/.test(bp[i]);
    if (an && bn) {
      if (BigInt(ap[i]) === BigInt(bp[i])) continue;
      return BigInt(ap[i]) > BigInt(bp[i]) ? 1 : -1;
    }
    if (an !== bn) return an ? -1 : 1;
    return ap[i] > bp[i] ? 1 : -1;
  }
  return 0;
}

export async function assertTagSafe(expected, tag, options = {}) {
  identity(expected);
  if (!/^[a-z][a-z0-9._-]*$/i.test(tag || '')) throw new Error('Invalid npm distribution tag');
  if (expected.version.includes('-dev') && tag === 'latest') throw new Error('Refusing to publish a dev version under latest');
  const response = await get(`${REGISTRY}/-/package/${encodeURIComponent(expected.name)}/dist-tags`, options);
  if (response.status === 404) return;
  const tags = await response.json();
  if (!tags || typeof tags !== 'object' || Array.isArray(tags)) throw new Error('Invalid npm distribution tags response');
  if (Object.hasOwn(tags, tag) && compareVersions(tags[tag], expected.version) > 0) {
    throw new Error(`Refusing npm tag rollback: ${expected.name} ${tag}=${tags[tag]} > ${expected.version}`);
  }
}

export async function publishPackage(dir, expected, tag, options = {}) {
  identity(expected);
  if (!/^[a-z][a-z0-9._-]*$/i.test(tag || '')) throw new Error('Invalid npm distribution tag');
  if (expected.version.includes('-dev') && tag === 'latest') throw new Error('Refusing to publish a dev version under latest');
  // Check the verified local receipt before either skipping or publishing.
  const temp = mkdtempSync(path.join(tmpdir(), 'rsrs-npm-publish-'));
  try {
    const packed = packPackage(dir, temp, options);
    assertPackMatches(packed, expected);
    let existing;
    try { existing = await checkPackage(expected, options); }
    catch (error) {
      if (!(error instanceof PackageNotVisibleError)) throw error;
      existing = await waitForPackage(expected, options);
    }
    if (existing) return {status: 'existing', metadata: existing};
    await assertTagSafe(expected, tag, options);
    // Publish the checked bytes, never repack a mutable directory inside npm publish.
    // A failed/uncertain submission is never repeated here: only visibility is retried.
    let result;
    try {
      result = (options.spawnImpl || spawnSync)(npm,
        ['publish', packed.tarballPath, '--access', 'public', '--tag', tag, '--ignore-scripts', '--registry', REGISTRY],
        {stdio: 'inherit', shell: process.platform === 'win32'});
    } catch (error) { result = {status: null, error}; }
    const accepted = result.status === 0 && !result.error;
    try {
      const metadata = await waitForPackage(expected, options);
      return {status: accepted ? 'published' : 'recovered', metadata};
    } catch (error) {
      if (!accepted) throw new Error(`npm publish failed or was uncertain for ${identity(expected)}; registry did not confirm matching bytes: ${error.message}`, {cause: error});
      throw error;
    }
  } finally { rmSync(temp, {recursive: true, force: true}); }
}
