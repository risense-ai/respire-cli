import {createHash} from 'node:crypto';
import {appendFileSync, chmodSync, copyFileSync, existsSync, statSync, createReadStream, createWriteStream, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {open} from 'node:fs/promises';
import {dirname, join, resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {frontendLayout, releaseAssetNames, validateBuildMetadata, verifyBinary} from './verify-binary.mjs';
import {pathToFileURL} from 'node:url';
import {Transform, Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {createGunzip} from 'node:zlib';
import {packPackage, verifyPackFile} from './registry-publication.mjs';


const sha256 = value => createHash('sha256').update(value).digest('hex');
const requireValue = (condition, message) => { if (!condition) throw new Error(message); };
const ownKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const hashPattern = /^[a-f0-9]{64}$/;
const versionPattern = /^\d+\.\d+\.\d+(?:-dev\.\d+)?$/;
const sourcePattern = /^[a-f0-9]{40}$/;
const positiveID = value => Number.isSafeInteger(value) && value > 0;
export function publishedAssetNames(kind, target) {
  const extension = target.includes('windows') ? '.exe' : '';
  return kind === 'cli'
    ? releaseAssetNames({artifactLayout:'cli-frontend-v2', binaryName:'rsrs'}, target).reverse()
    : [`runtime-build-${target}.json`, `rsrs-runtime-${target}${extension}`, `rsrs-runtime-${target}.tar.gz`];
}
export function parsePublishedAssets(text, expectedHash, targets) {
  requireValue(typeof text === 'string' && Buffer.byteLength(text) <= 60000 && hashPattern.test(expectedHash || '')
    && sha256(text) === expectedHash, 'Published asset manifest hash/size mismatch');
  const spec = JSON.parse(text);
  requireValue(ownKeys(spec, ['schema', 'cli', 'runtime']) && spec.schema === 2, 'Published asset manifest schema differs');
  requireValue(Array.isArray(targets) && targets.length === 7 && new Set(targets).size === 7, 'Seven unique targets required');
  for (const kind of ['cli', 'runtime']) {
    const part = spec[kind];
    requireValue(ownKeys(part, ['repository', 'release_id', 'version', 'source_sha', 'producer', 'assets'])
      && part.repository === `risense-ai/respire-${kind}` && positiveID(part.release_id)
      && versionPattern.test(part.version || '') && sourcePattern.test(part.source_sha || '')
      && ownKeys(part.producer, ['run_id','run_attempt']) && positiveID(part.producer.run_id) && positiveID(part.producer.run_attempt), `Invalid published ${kind} identity`);
    const names = targets.flatMap(target => publishedAssetNames(kind, target));
    requireValue(Array.isArray(part.assets) && part.assets.length === names.length, `Incomplete published ${kind} assets`);
    const ids = new Set(), found = new Set();
    for (const asset of part.assets) {
      requireValue(ownKeys(asset, ['id', 'name', 'size', 'sha256']) && positiveID(asset.id)
        && names.includes(asset.name) && !ids.has(asset.id) && !found.has(asset.name)
        && Number.isSafeInteger(asset.size) && asset.size > 0 && asset.size <= 2 ** 31
        && (!asset.name.endsWith('.json') || asset.size <= 2 ** 20)
        && hashPattern.test(asset.sha256 || ''), `Invalid or duplicate published ${kind} asset`);
      ids.add(asset.id); found.add(asset.name);
    }
  }
  return spec;
}
export function validateArtifactRequest(env, targets) {
  const mode = env.ARTIFACT_SOURCE || 'build';
  requireValue(['build', 'published-assets'].includes(mode), 'Unknown artifact source');
  if (mode === 'build') {
    requireValue(!env.PUBLISHED_ASSETS && !env.PUBLISHED_ASSETS_SHA256, 'Build mode forbids published asset inputs');
    return null;
  }
  requireValue(env.GITHUB_EVENT_NAME === 'workflow_dispatch' && env.GITHUB_REPOSITORY === 'risense-ai/respire-cli'
    && env.REQUEST_PUBLISH === 'false' && env.VALIDATION_PROFILE === 'full'
    && !env.DEV_VERSION && !env.PREPARED_RUN
    && ['REUSE_DEV12', 'REPAIR_DEV12', 'REPAIR_DEV14', 'RESUME_DEV6'].every(key => !env[key] || env[key] === 'false'),
  'Published assets require explicit full, publish=false, no version allocation/prepared/recovery');
  const spec = parsePublishedAssets(env.PUBLISHED_ASSETS, env.PUBLISHED_ASSETS_SHA256, targets);
  requireValue(sourcePattern.test(env.GITHUB_SHA || '') && env.RELEASE_REF === env.GITHUB_SHA,
    'Published assets require the exact trusted harness SHA as ref; product sources come only from the manifest');
  return spec;
}
export function validatePublishedRelease(part, release, assets, tagSHA) {
  requireValue(release.id === part.release_id && release.tag_name === `v${part.version}`
    && release.draft === false && typeof release.published_at === 'string'
    && Number.isFinite(Date.parse(release.published_at)) && tagSHA === part.source_sha, 'Published release/source mismatch');
  requireValue(Array.isArray(assets) && new Set(assets.map(a => a.id)).size === assets.length
    && new Set(assets.map(a => a.name)).size === assets.length, 'Duplicate public asset inventory');
  for (const expected of part.assets) {
    const actual = assets.find(a => a.id === expected.id);
    requireValue(actual && actual.name === expected.name && actual.size === expected.size
      && actual.state === 'uploaded' && actual.digest === `sha256:${expected.sha256}`, 'Public asset ID/name/size/digest mismatch');
  }
}
export function validatePublishedMetadata(spec, target, cli, runtime) {
  const cliNames = publishedAssetNames('cli', target), runtimeNames = publishedAssetNames('runtime', target);
  const expected = (kind, name) => spec[kind].assets.find(a => a.name === name).sha256;
  const cliAsset = spec.cli.assets.find(asset => asset.name === cliNames[1]);
  validateBuildMetadata(cli, {artifactLayout:'cli-frontend-v2', binaryName:'rsrs'}, target,
    {sha:spec.cli.source_sha, version:spec.cli.version, ...spec.cli.producer},
    {file:cliNames[1], size:cliAsset.size, sha256:cliAsset.sha256});
  requireValue(runtime.schema_version === 2 && runtime.source_commit === spec.runtime.source_sha
    && runtime.runtime_version === spec.runtime.version && runtime.target_triple === target
    && runtime.binary_file === runtimeNames[1] && runtime.archive_file === runtimeNames[2]
    && runtime.binary_sha256 === expected('runtime', runtimeNames[1])
    && runtime.archive_sha256 === expected('runtime', runtimeNames[2])
    && runtime.protocol_range?.minimum === 1 && runtime.protocol_range?.maximum === 1
    && runtime.capabilities?.business_executor === '1' && runtime.capabilities?.mcp_server === '1', 'Published Runtime metadata mismatch');
  requireValue(Array.isArray(runtime.files) && runtime.files.length > 0 && runtime.files.length <= 4096, 'Missing Runtime file inventory');
  const seen = new Set();
  for (const file of runtime.files) {
    requireValue(typeof file.path === 'string' && !/[\\:\x00-\x1f\x7f]/.test(file.path)
      && file.path.split('/').every(p => p && p !== '.' && p !== '..')
      && !seen.has(file.path.toLowerCase()) && Number.isSafeInteger(file.size) && file.size >= 0
      && hashPattern.test(file.sha256 || ''), 'Invalid Runtime payload inventory');
    seen.add(file.path.toLowerCase());
  }
}
function safePayloadPath(path) {
  requireValue(typeof path === 'string' && path.length <= 1024 && !/[\\:\x00-\x1f\x7f]/.test(path)
    && path.split('/').every(p => p && p !== '.' && p !== '..' && !/[. ]$/.test(p)
      && !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p)), 'Unsafe published payload path');
  return path;
}
// Extract only bounded regular files/directories. Never delegate archive paths or links to tar.
export async function extractPublishedArchive(archive, destination) {
  mkdirSync(destination, {recursive: false});
  const input = createReadStream(archive).pipe(createGunzip());
  const iterator = input[Symbol.asyncIterator](); let buffer = Buffer.alloc(0), total = 0, count = 0;
  async function take(size) {
    while (buffer.length < size) {
      const next = await iterator.next();
      requireValue(!next.done, 'Truncated published archive');
      buffer = Buffer.concat([buffer, next.value]);
    }
    const value = buffer.subarray(0, size); buffer = buffer.subarray(size); return value;
  }
  const seen = new Set(); let pending = null, zeroes = 0;
  const field = (header, start, size) => header.subarray(start, start + size).toString('utf8').split('\0')[0];
  const octal = value => { requireValue(/^[0-7]+$/.test(value.trim()), 'Invalid tar numeric field'); return parseInt(value.trim(), 8); };
  try {
    while (true) {
      const header = await take(512);
      if (header.every(byte => byte === 0)) { if (++zeroes === 2) break; continue; }
      requireValue(zeroes === 0 && ++count <= 8192, 'Invalid tar terminator or entry count');
      const checksum = [...header].reduce((sum, byte, i) => sum + (i >= 148 && i < 156 ? 32 : byte), 0);
      requireValue(checksum === octal(field(header, 148, 8)), 'Tar checksum mismatch');
      const size = octal(field(header, 124, 12)), type = String.fromCharCode(header[156] || 48);
      requireValue(Number.isSafeInteger(size) && size <= 256 * 2 ** 20 && (total += size) <= 1024 * 2 ** 20, 'Published payload exceeds extraction limit');
      if (type === 'x' || type === 'L') {
        requireValue(pending === null && size <= 65536, 'Invalid tar extended path');
        const data = await take(size);
        if (type === 'L') pending = data.toString('utf8').replace(/\0$/, '');
        else {
          let offset = 0;
          while (offset < data.length) {
            const space = data.indexOf(32, offset), length = Number(data.subarray(offset, space).toString());
            requireValue(space > offset && Number.isSafeInteger(length) && length > space - offset + 2 && offset + length <= data.length, 'Invalid PAX record');
            const record = data.subarray(space + 1, offset + length).toString('utf8');
            requireValue(record.endsWith('\n'), 'Invalid PAX terminator');
            const equal = record.indexOf('='), key = record.slice(0, equal), value = record.slice(equal + 1, -1);
            requireValue(['path','mtime','atime','ctime','uid','gid','uname','gname'].includes(key), 'Unsupported PAX attribute');
            if (key === 'path') { requireValue(pending === null, 'Duplicate PAX path'); pending = value; }
            offset += length;
          }
        }
        await take((512 - size % 512) % 512); continue;
      }
      requireValue(type === '0' || type === '5', 'Linked or special published payload refused');
      let path = pending ?? [field(header, 345, 155), field(header, 0, 100)].filter(Boolean).join('/'); pending = null;
      path = path.replace(/^\.\//, '').replace(/\/$/, '');
      if ((path === '.' || path === '') && type === '5') { requireValue(size === 0, 'Invalid archive root'); continue; }
      safePayloadPath(path);
      requireValue(!seen.has(path.toLowerCase()), 'Duplicate published archive path'); seen.add(path.toLowerCase());
      const file = join(destination, path);
      if (type === '5') { requireValue(size === 0, 'Nonempty archive directory'); mkdirSync(file, {recursive: true}); }
      else {
        mkdirSync(dirname(file), {recursive: true});
        const output = await open(file, 'wx', 0o600);
        try {
          for (let remaining = size; remaining;) {
            const chunk = await take(Math.min(remaining, 65536)); await output.writeFile(chunk); remaining -= chunk.length;
          }
        } finally { await output.close(); }
        chmodSync(file, octal(field(header, 100, 8)) & 0o111 ? 0o755 : 0o644);
      }
      await take((512 - size % 512) % 512);
    }
    requireValue(pending === null, 'Unused tar extended path');
    requireValue(buffer.every(byte => byte === 0), 'Unexpected trailing tar data');
    for await (const chunk of { [Symbol.asyncIterator]: () => iterator }) requireValue(chunk.every(byte => byte === 0), 'Unexpected trailing tar data');
  } finally { input.destroy(); }
}
function payloadFiles(directory, prefix = '') {
  return readdirSync(join(directory, prefix), {withFileTypes: true}).flatMap(entry => {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    requireValue(!entry.isSymbolicLink(), 'Linked published payload');
    if (entry.isDirectory()) return payloadFiles(directory, path);
    requireValue(entry.isFile(), 'Special published payload'); return [path];
  });
}
function verifyFile(directory, file) {
  safePayloadPath(file.path);
  const path = join(directory, file.path), info = lstatSync(path);
  requireValue(info.isFile() && !info.isSymbolicLink() && (file.size === undefined || info.size === file.size)
    && hashPattern.test(file.sha256 || '') && sha256(readFileSync(path)) === file.sha256, 'Published payload hash/size mismatch: ' + file.path);
}
export function verifyCorePayload(directory, target, lock, inventory) {
  const bytes = readFileSync(join(directory, 'core-runtime.json')), core = JSON.parse(bytes);
  requireValue(core.schema_version === 1 && core.target === target && core.sdk_version === lock.sdk_version
    && core.redistribution === 'permitted-under-included-license' && Array.isArray(core.files)
    && core.files.length > 0 && core.files.length <= 4094 && lock.redistribution === 'approved'
    && hashPattern.test(lock.manifest_sha256 || '') && hashPattern.test(lock.archive_sha256 || ''), 'Published Core identity/license mismatch');
  const expected = new Map([['core-runtime.json', null]]);
  for (const file of core.files) {
    safePayloadPath(file.path);
    requireValue(!expected.has(file.path.toLowerCase()), 'Duplicate Core payload entry');
    expected.set(file.path.toLowerCase(), file); verifyFile(directory, file);
  }
  requireValue(core.files.some(file => file.path === 'core-notices/CORE-SDK-LICENSE.txt'), 'Missing Core redistribution license');
  if (inventory) {
    requireValue(inventory.length === expected.size + 1 && payloadFiles(directory).length === inventory.length, 'Runtime/Core inventory differs');
    for (const file of inventory) {
      verifyFile(directory, file);
      if (file.path === 'core-runtime.json') requireValue(sha256(bytes) === file.sha256, 'Unbound Core manifest');
      else if (expected.has(file.path.toLowerCase())) requireValue(expected.get(file.path.toLowerCase()).sha256 === file.sha256, 'Runtime/Core file binding differs');
    }
  } else requireValue(payloadFiles(directory).length === expected.size, 'Unexpected CLI bundle payload');
  return {sdk_version: core.sdk_version, sdk_manifest_expected_sha256: lock.manifest_sha256,
    sdk_archive_expected_sha256: lock.archive_sha256, core_manifest_sha256: sha256(bytes), files_verified: core.files.length};
}
function compareVersion(a, b) {
  requireValue(versionPattern.test(a || '') && versionPattern.test(b || ''), 'Invalid compatibility version');
  const parts = v => { const [base, dev] = v.split('-dev.'); return [...base.split('.').map(Number), dev === undefined ? Number.MAX_SAFE_INTEGER : Number(dev)]; };
  const x = parts(a), y = parts(b);
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}
export function validatePublishedCompatibility(spec, runtime, pin) {
  requireValue(pin.required === spec.runtime.version, 'Published CLI requires a different Runtime');
  const range = /^>=(\d+\.\d+\.\d+(?:-dev\.\d+)?),<(\d+\.\d+\.\d+(?:-dev\.\d+)?)$/.exec(pin.accept || '');
  requireValue(range && compareVersion(spec.runtime.version, range[1]) >= 0 && compareVersion(spec.runtime.version, range[2]) < 0,
    'Published Runtime outside CLI acceptance range');
  requireValue(runtime.compat && compareVersion(spec.cli.version, runtime.compat.min_cli) >= 0
    && (runtime.compat.max_cli === '*' || compareVersion(spec.cli.version, runtime.compat.max_cli) < 0), 'Published CLI outside Runtime compatibility range');
}
async function publishedSourceJSON(part, path, options) {
  const blob = await readGitHub(`${part.repository}/contents/${path}?ref=${part.source_sha}`, options.token, options.fetcher ?? fetch);
  requireValue(blob.type === 'file' && blob.encoding === 'base64' && blob.size > 0 && blob.size <= 2 ** 20, 'Invalid published source file');
  const bytes = Buffer.from(blob.content, 'base64');
  requireValue(bytes.length === blob.size && createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${bytes.length}\0`), bytes])).digest('hex') === blob.sha,
    'Published source blob mismatch');
  return JSON.parse(bytes);
}
export async function consumePublishedTarget(spec, target, source, destination, manifestHash, options = {}) {
  for (const kind of ['cli','runtime']) for (const name of publishedAssetNames(kind, target)) {
    const asset = spec[kind].assets.find(a => a.name === name); requireValue(asset, 'Missing published asset');
    verifyFile(join(source, kind), {...asset, path: name});
  }
  const cli = JSON.parse(readFileSync(join(source,'cli',`cli-build-${target}.json`))), runtime = JSON.parse(readFileSync(join(source,'runtime',`runtime-build-${target}.json`)));
  validatePublishedMetadata(spec, target, cli, runtime);
  const pin = await publishedSourceJSON(spec.cli, 'runtime-pin.json', options);
  validatePublishedCompatibility(spec, runtime, pin);
  const runtimeLock = (await publishedSourceJSON(spec.runtime, 'crates/core-sdk/core-sdk.lock.json', options)).targets?.[target];
  requireValue(runtimeLock, 'Published Runtime Core SDK lock missing');
  const cliManifest = await publishedSourceJSON(spec.cli, 'npm/artifact-manifest.json', options);
  requireValue(frontendLayout(cliManifest)
    && cliManifest.targets?.some(item => item.triple === target), 'Published CLI frontend manifest mismatch');
  mkdirSync(dirname(destination), {recursive: true});
  mkdirSync(destination, {recursive:true});
  requireValue(!existsSync(join(destination,'core-runtime.json')) && !existsSync(join(destination,'core-notices')), 'Frontend CLI must not contain Core');
  const runtimeDirectory = join(destination, 'runtime');
  await extractPublishedArchive(join(source,'runtime',runtime.archive_file), runtimeDirectory);
  requireValue(payloadFiles(runtimeDirectory).length === runtime.files.length, 'Unexpected Runtime archive payload');
  const runtimeCore = verifyCorePayload(runtimeDirectory, target, runtimeLock, runtime.files);
  const binaryEntry = runtime.files.find(f => f.path === runtime.binary_file);
  requireValue(binaryEntry?.sha256 === runtime.binary_sha256, 'Runtime archive binary differs from raw asset');
  const extension = target.includes('windows') ? '.exe' : '', binary = join(destination,'rsrs'+extension);
  copyFileSync(join(source,'cli',cli.binary_file), binary); chmodSync(binary,0o755);
  const runtimeBinary = join(runtimeDirectory,runtime.binary_file); chmodSync(runtimeBinary,0o755);
  verifyBinary(binary,target); verifyBinary(runtimeBinary,target);
  // Existing migration joins consume this exact metadata filename, never synthesized metadata.
  copyFileSync(join(source,'cli',`cli-build-${target}.json`),join(source,`cli-build-${target}.json`));
  const identity = {manifest_sha256:manifestHash,target,harness_sha:process.env.GITHUB_SHA ?? null,
    product_sources:{cli:spec.cli.source_sha,runtime:spec.runtime.source_sha},cli_artifact_layout:cli.artifact_layout,runtime_core:runtimeCore,
    producers:{cli:spec.cli.producer,runtime:spec.runtime.producer},
    cli_binary_sha256:cli.binary_sha256,runtime_binary_sha256:runtime.binary_sha256,runtime_bundle_sha256:runtime.archive_sha256};
  writeFileSync(join(destination,'published-consumer-identity.json'),JSON.stringify(identity,null,2)+'\n');
  return {identity, env:{RSRS_ARTIFACT_SOURCE:'published-assets',RSRS_RUNTIME_BIN:resolve(runtimeBinary),
    RSRS_PUBLISHED_RUNTIME_SHA256:runtime.binary_sha256,RSRS_PUBLISHED_RUNTIME_VERSION:spec.runtime.version,
    RSRS_PUBLISHED_ASSETS_SHA256:manifestHash,RSRS_PUBLISHED_BUNDLE_SHA256:runtime.archive_sha256,
    RSRS_PUBLISHED_RUNTIME_ARCHIVE:resolve(source,'runtime',runtime.archive_file),
    RSRS_PUBLISHED_RUNTIME_METADATA:resolve(source,'runtime',`runtime-build-${target}.json`),
    RSRS_PUBLISHED_RUNTIME_METADATA_SHA256:sha256(readFileSync(join(source,'runtime',`runtime-build-${target}.json`))),
    RSRS_RUNTIME_TRIPLE:target}};
}
async function readGitHub(path, token, fetcher) {
  const response = await fetcher(`https://api.github.com/repos/${path}`, {headers: {
    Accept: 'application/vnd.github+json', 'User-Agent': 'respire-published-full',
    ...(token ? {Authorization: `Bearer ${token}`} : {}),
  }, signal: AbortSignal.timeout(30000)});
  requireValue(response.status === 200, `GitHub metadata HTTP ${response.status}`);
  return response.json();
}
export async function inspectPublishedRelease(part, {token, fetcher = fetch} = {}) {
  const read = path => readGitHub(`${part.repository}/${path}`, token, fetcher);
  const release = await read(`releases/${part.release_id}`);
  let object = (await read(`git/ref/tags/v${part.version}`)).object;
  for (let depth = 0; object?.type === 'tag' && depth < 8; depth++) {
    requireValue(sourcePattern.test(object.sha), 'Invalid annotated tag SHA');
    object = (await read(`git/tags/${object.sha}`)).object;
  }
  requireValue(object?.type === 'commit' && sourcePattern.test(object.sha), 'Tag must resolve to an exact commit');
  const assets = [];
  for (let page = 1; ; page++) {
    requireValue(page <= 100, 'Public asset pagination exceeded');
    const batch = await read(`releases/${part.release_id}/assets?per_page=100&page=${page}`);
    requireValue(Array.isArray(batch) && batch.length <= 100, 'Invalid public asset page');
    assets.push(...batch);
    if (batch.length < 100) break;
  }
  validatePublishedRelease(part, release, assets, object.sha);
  const producer = part.producer;
  requireValue(producer && positiveID(producer.run_id) && positiveID(producer.run_attempt), 'Published producer identity missing');
  const run = await readGitHub(`${part.repository}/actions/runs/${producer.run_id}/attempts/${producer.run_attempt}`, token, fetcher);
  requireValue(run.id === producer.run_id && run.run_attempt === producer.run_attempt
    && run.head_sha === part.source_sha && run.status === 'completed' && run.conclusion === 'success'
    && run.path === '.github/workflows/release.yml' && run.repository?.full_name === part.repository,
    'Published producer run/source/attempt mismatch');
  return {release_id: release.id, published_at: release.published_at, source_sha: object.sha, producer};
}
export async function inspectRuntimeProducer(part, target, {token, fetcher = fetch, artifactTransport} = {}) {
  const producer = part.producer, names = publishedAssetNames('runtime', target);
  requireValue(part.repository === 'risense-ai/respire-runtime' && positiveID(producer?.run_id)
    && positiveID(producer.run_attempt) && sourcePattern.test(part.source_sha), 'Invalid Runtime producer');
  const expected = names.map(name => part.assets.find(asset => asset.name === name));
  requireValue(expected.every(Boolean), 'Missing Runtime producer assets');
  const list = async (path, key) => {
    const result = [];
    for (let page = 1; ; page++) {
      requireValue(page <= 100, 'Runtime producer pagination exceeded');
      const response = await readGitHub(`${part.repository}/actions/${path}?per_page=100&page=${page}`, token, fetcher);
      requireValue(Array.isArray(response[key]) && response[key].length <= 100, 'Invalid Runtime producer page');
      result.push(...response[key]);
      if (response[key].length < 100) return result;
    }
  };
  const jobs = await list(`runs/${producer.run_id}/attempts/${producer.run_attempt}/jobs`, 'jobs');
  const artifacts = await list(`runs/${producer.run_id}/artifacts`, 'artifacts');
  const evidence = [];
  for (const [name, jobName, files] of [
    [`runtime-release-${target}`, `Release (${target})`, expected.filter((_, i) => i !== 1)],
    [`runtime-smoke-${target}`, `Native regression (${target})`, [{name:`runtime-smoke-${target}.json`}]],
  ]) {
    const matches = jobs.filter(job => job.name === jobName), found = artifacts.filter(artifact => artifact.name === name);
    const job = matches[0], artifact = found[0];
    requireValue(matches.length === 1 && job.status === 'completed' && job.conclusion === 'success'
      && positiveID(job.id) && job.run_id === producer.run_id && job.run_attempt === producer.run_attempt
      && job.head_sha === part.source_sha, 'Runtime producer job/source/attempt mismatch');
    // Artifact names are reused across attempts. Bind creation to the selected job, not the latest run.
    requireValue(found.length === 1 && positiveID(artifact.id) && artifact.expired === false
      && artifact.workflow_run?.id === producer.run_id && artifact.workflow_run.head_sha === part.source_sha
      && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || '') && positiveID(artifact.size_in_bytes)
      && artifact.size_in_bytes <= 256 * 2 ** 20
      && Date.parse(job.started_at) <= Date.parse(artifact.created_at)
      && Date.parse(artifact.created_at) <= Date.parse(artifact.updated_at)
      && Date.parse(artifact.updated_at) <= Date.parse(job.completed_at), 'Runtime producer artifact is missing, foreign, stale or undigested');
    const command = artifactTransport ?? ((args, options) => {
      requireValue(token, 'Runtime producer download requires the explicit workflow token');
      try {
        return execFileSync('gh', args, {...options, env:{...process.env, GH_TOKEN:token}, windowsHide:true});
      } catch { throw new Error(`Runtime producer artifact download failed: ${artifact.id}`); }
    });
    const bytes = command(['api', '--hostname', 'github.com', `repos/${part.repository}/actions/artifacts/${artifact.id}/zip`],
      {encoding:'buffer', timeout:60000, maxBuffer:256 * 2 ** 20});
    requireValue(Buffer.isBuffer(bytes) && bytes.length === artifact.size_in_bytes
      && `sha256:${sha256(bytes)}` === artifact.digest, 'Runtime producer ZIP hash/size mismatch');
    // Reuse the bounded Python zipfile reader pattern; inspect bytes only, never extract or execute artifacts.
    const rows = JSON.parse(execFileSync(process.platform === 'win32' ? 'py' : 'python3',
      [...(process.platform === 'win32' ? ['-3'] : []), '-I', '-c', `import hashlib,io,json,stat,sys,zipfile
with zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())) as z:
 entries=z.infolist(); names=[e.filename for e in entries]; expected=json.loads(sys.argv[1])
 assert len(names)==len(set(names)) and sorted(names)==sorted(expected), 'Unexpected Runtime producer ZIP inventory'
 result=[]
 for e in entries:
  limit=1024**2 if e.filename.endswith('.json') else 256*1024**2
  assert not e.is_dir() and stat.S_IFMT(e.external_attr>>16) in (0,stat.S_IFREG), 'Non-regular Runtime producer entry'
  assert 0<e.file_size<=limit and e.compress_type in (0,8), 'Oversized or unsupported Runtime producer entry'
  digest=hashlib.sha256(); size=0; data=[]
  with z.open(e) as stream:
   while chunk:=stream.read(65536):
    size+=len(chunk); assert size<=limit, 'Oversized Runtime producer bytes'; digest.update(chunk)
    if e.filename.endswith('.json'): data.append(chunk)
  assert size==e.file_size, 'Runtime producer member size mismatch'
  row={'name':e.filename,'size':size,'sha256':digest.hexdigest()}
  if data: row['json']=json.loads(b''.join(data))
  result.append(row)
 print(json.dumps(result))`, JSON.stringify(files.map(file => file.name))],
      {input:bytes, encoding:'utf8', timeout:30000, maxBuffer:2 ** 21, windowsHide:true}));
    for (const file of files) {
      const row = rows.find(row => row.name === file.name);
      if (file.sha256) requireValue(row.sha256 === file.sha256 && row.size === file.size, 'Runtime producer bytes differ from selected release assets');
      else {
        const report = row.json;
        requireValue(report?.passed === true && report.target === target && report.version === part.version
          && report.source_commit === part.source_sha && report.run_id === String(producer.run_id)
          && report.run_attempt === String(producer.run_attempt)
          && report.archive_sha256 === expected[2].sha256 && report.binary_sha256 === expected[1].sha256,
        'Runtime native report/source/attempt/bytes mismatch');
      }
    }
    evidence.push({id:artifact.id, name, job_id:job.id, zip_sha256:artifact.digest.slice(7),
      files:rows.map(({json, ...file}) => file)});
  }
  return {...producer, source_sha:part.source_sha, target, metadata_sha256:expected[0].sha256,
    archive_sha256:expected[2].sha256, binary_sha256:expected[1].sha256, artifacts:evidence};
}
export async function downloadPublishedAsset(part, asset, directory, {token, fetcher = fetch} = {}) {
  const path = join(directory, asset.name);
  const response = await fetcher(`https://api.github.com/repos/${part.repository}/releases/assets/${asset.id}`, {
    headers: {Accept: 'application/octet-stream', 'User-Agent': 'respire-published-full',
      ...(token ? {Authorization: `Bearer ${token}`} : {})}, signal: AbortSignal.timeout(600000)});
  requireValue(response.status === 200 && response.body, `Public asset download HTTP ${response.status}`);
  const hash = createHash('sha256'); let size = 0, created = false;
  const counter = new Transform({transform(chunk, _encoding, callback) {
    size += chunk.length;
    if (size > asset.size) return callback(new Error('Public asset exceeds approved size'));
    hash.update(chunk); callback(null, chunk);
  }});
  const output = createWriteStream(path, {flags: 'wx', mode: 0o600});
  output.once('open', () => { created = true; });
  try {
    await pipeline(Readable.fromWeb(response.body), counter, output);
    requireValue(size === asset.size && hash.digest('hex') === asset.sha256, 'Downloaded public asset hash/size mismatch');
  } catch (error) {
    if (created) rmSync(path);
    throw error;
  }
}
export async function verifyPublishedTarget(spec, target, destination, manifestHash, options = {}) {
  mkdirSync(destination, {recursive: false});
  const receipt = {schema: 1, kind: 'published-assets-verification-only', manifest_sha256: manifestHash,
    target, harness_sha: process.env.GITHUB_SHA ?? null, workflow_sha: process.env.GITHUB_SHA ?? null,
    product_sources: {cli: spec.cli.source_sha, runtime: spec.runtime.source_sha}, run_id: process.env.GITHUB_RUN_ID ?? null,
    run_attempt: process.env.GITHUB_RUN_ATTEMPT ?? null,
    assets_verified: false, full_passed: false, g1Passed: false, actual_processes: [],
    remaining: ['Runtime archive/Core payload inspection and extraction', 'published CLI runtime-pin and compatibility', 'full consumers', 'actual running image digests'], releases: {}, assets: []};
  try {
    for (const kind of ['cli', 'runtime']) {
      const part = spec[kind], directory = join(destination, kind);
      mkdirSync(directory);
      receipt.releases[kind] = {repository: part.repository, version: part.version, ...await inspectPublishedRelease(part, options)};
      for (const name of publishedAssetNames(kind, target)) {
        const asset = part.assets.find(a => a.name === name);
        await downloadPublishedAsset(part, asset, directory, options);
        receipt.assets.push({repository: part.repository, ...asset});
      }
    }
    validatePublishedMetadata(spec, target,
      JSON.parse(readFileSync(join(destination, 'cli', `cli-build-${target}.json`), 'utf8')),
      JSON.parse(readFileSync(join(destination, 'runtime', `runtime-build-${target}.json`), 'utf8')));
    receipt.runtime_producer = await inspectRuntimeProducer(spec.runtime, target, options);
    verifyBinary(join(destination, 'cli', publishedAssetNames('cli', target)[1]), target);
    verifyBinary(join(destination, 'runtime', publishedAssetNames('runtime', target)[1]), target);
    receipt.assets_verified = true;
    const consumed = await consumePublishedTarget(spec, target, destination, join(destination,'inspected'), manifestHash, options);
    receipt.payloads_verified = true; receipt.payload_identity = consumed.identity;
    receipt.remaining = ['full consumers', 'actual running image digests'];
  } catch (error) {
    receipt.error = String(error);
    throw error;
  } finally {
    writeFileSync(join(destination, 'published-assets-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
  }
  return receipt;
}
export function validatePublishedProcessEvidence(report, spec, target, manifestHash) {
  const expected = spec.runtime.assets.find(a => a.name === publishedAssetNames('runtime',target)[1]).sha256;
  const bundle = spec.runtime.assets.find(a => a.name === publishedAssetNames('runtime',target)[2]).sha256;
  requireValue(report.passed === true && report.runtime_mode === 'standalone_runtime' && report.standalone_runtime_evidence === true
    && report.runtime_binary_sha256 === expected && report.runtime_version === spec.runtime.version
    && Array.isArray(report.runtime_identity_receipts) && report.runtime_identity_receipts.length > 0, 'Missing actual standalone Runtime evidence: ' + target);
  for (const receipt of report.runtime_identity_receipts) {
    requireValue(receipt.manifest_sha256 === manifestHash && receipt.bundle_sha256 === bundle
      && receipt.image_sha256 === expected && typeof receipt.exe === 'string' && receipt.exe.length > 0
      && positiveID(receipt.pid) && (typeof receipt.process_start_id === 'string' && receipt.process_start_id.length > 0
        || typeof receipt.create_time === 'number' && receipt.create_time > 0)
      && typeof receipt.installation_root === 'string' && receipt.installation_root.length > 0
      && typeof receipt.data_dir === 'string' && receipt.data_dir.length > 0
      && typeof receipt.account_id === 'string' && receipt.account_id.length > 0
      && typeof receipt.instance_id === 'string' && receipt.instance_id.length > 0
      && positiveID(receipt.generation) && receipt.protocol_v === 1, 'Actual Runtime process identity differs: ' + target);
  }
  return report.runtime_identity_receipts;
}
export function validatePublishedPackage(pkg, manifest, name, core, packedFiles) {
  const frontend = frontendLayout(manifest);
  requireValue(pkg.name === name && pkg.version === manifest.cliVersion
    && pkg.repository?.url.endsWith('/risense-ai/respire-cli.git'), 'Published npm identity/version/repository mismatch');
  if (name === manifest.npmScope) {
    requireValue(pkg.dependencies === undefined && JSON.stringify(pkg.bin) === JSON.stringify({rsrs:'./bin/cli.js'})
      && JSON.stringify(pkg.optionalDependencies) === JSON.stringify(Object.fromEntries(manifest.targets.map(t => [t.pkg,manifest.cliVersion]))), 'Published npm launcher/optional dependencies mismatch');
  } else if (!frontend) requireValue(core?.redistribution === 'permitted-under-included-license', 'Published npm SDK redistribution mismatch');
  if (frontend) requireValue(!core && ![...packedFiles].some(file => file === 'bin/core-runtime.json' || file.startsWith('bin/core-notices/')), 'Frontend package must not include Core');
  requireValue(pkg.license === 'SEE LICENSE IN LICENSE' && packedFiles.has('LICENSE')
    && !packedFiles.has('LICENSE-MIT-LEGACY') && (name === manifest.npmScope || frontend || packedFiles.has('bin/core-notices/CORE-SDK-LICENSE.txt')), 'Published npm package license mismatch');
}
async function packPublished(spec, targets, source, manifestHash) {
  const manifest = JSON.parse(readFileSync('npm/artifact-manifest.json'));
  requireValue(manifest.cliVersion === spec.cli.version, 'Harness package manifests must use the fixed product version');
  for (const target of targets) await consumePublishedTarget(spec,target,join(source,'published-assets-verification-'+target),
    join('target/ci',target,'release'),manifestHash,{token:process.env.GH_TOKEN});
  execFileSync(process.execPath,['npm/scripts/pack.mjs','--root','target/ci'],{stdio:'inherit'});
  const packages = [];
  for (const name of [...manifest.targets.map(t => t.pkg),manifest.npmScope]) {
    const directory = join('npm/dist',name), pkg = JSON.parse(readFileSync(join(directory,'package.json')));
    const core = name === manifest.npmScope || frontendLayout(manifest) ? null : JSON.parse(readFileSync(join(directory,'bin/core-runtime.json')));
    const packed = packPackage(resolve(directory),resolve('npm/release-packages'));
    validatePublishedPackage(pkg,manifest,name,core,new Set(packed.files.map(f => f.path)));
    verifyPackFile(packed.tarballPath,packed,resolve(directory));
    if (name !== manifest.npmScope) {
      const target = manifest.targets.find(t => t.pkg === name).triple;
      const expected = spec.cli.assets.find(a => a.name === publishedAssetNames('cli',target)[1]);
      requireValue(sha256(readFileSync(join(directory,'bin','rsrs'+(target.includes('windows')?'.exe':'')))) === expected.sha256, 'Packed CLI binary differs from published image');
    }
    const {tarballPath,dir,...report} = packed;
    writeFileSync(join(directory,'release.pack.json'),JSON.stringify([report],null,2)+'\n');
    packages.push({name,version:pkg.version,file:packed.filename,sha256:sha256(readFileSync(packed.tarballPath))});
  }
  // A published-asset pack check is never a reusable preparation/publication receipt.
  writeFileSync('npm/release-packages/published-package-validation.json',JSON.stringify({schema:1,artifact_source:'published-assets',
    harness_sha:process.env.GITHUB_SHA,manifest_sha256:manifestHash,product_sources:{cli:spec.cli.source_sha,runtime:spec.runtime.source_sha},
    run_id:Number(process.env.GITHUB_RUN_ID),run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT),packages},null,2)+'\n');
}
export function validatePublishedFull(spec, targets, manifestHash, directory, jobs, context) {
  requireValue(sourcePattern.test(context.sha || '') && positiveID(context.run_id) && positiveID(context.run_attempt), 'Invalid full run identity');
  const processes = [], reports = [];
  function job(predicate, label) {
    const matches = jobs.filter(predicate);
    requireValue(matches.length === 1 && matches[0].status === 'completed' && matches[0].conclusion === 'success'
      && matches[0].run_id === context.run_id && matches[0].run_attempt === context.run_attempt
      && matches[0].head_sha === context.sha, 'Missing successful exact-attempt full job: ' + label);
  }
  function read(artifact, name) {
    const folder = join(directory,artifact);
    const paths = payloadFiles(folder).filter(path => path === name || path.endsWith('/'+name));
    requireValue(paths.length === 1, 'Missing or duplicate full report: ' + artifact + '/' + name);
    const bytes = readFileSync(join(folder,paths[0]));
    reports.push({artifact,path:paths[0],sha256:sha256(bytes)}); return JSON.parse(bytes);
  }
  const identity = (r,target) => {
    const binaryHash = spec.cli.assets.find(a => a.name === publishedAssetNames('cli',target)[1]).sha256;
    requireValue(r.source_sha === spec.cli.source_sha && r.version === spec.cli.version && r.binary_sha256 === binaryHash, 'Full report product identity differs');
  };
  for (const target of targets) {
    job(j => j.name === `validate / Release (${target})`,target+' asset validation');
    job(j => j.name === `native-regression / Native (${target})`,target+' native');
    const verified = read('published-assets-verification-'+target,'published-assets-receipt.json');
    requireValue(verified.assets_verified === true && verified.payloads_verified === true && !verified.error
      && verified.target === target && verified.manifest_sha256 === manifestHash && verified.harness_sha === context.sha
      && Number(verified.run_id) === context.run_id && Number(verified.run_attempt) === context.run_attempt
      && verified.product_sources.cli === spec.cli.source_sha && verified.product_sources.runtime === spec.runtime.source_sha, 'Published asset proof differs');
    for (const kind of ['cli','runtime']) {
      const release = verified.releases?.[kind], expected = spec[kind];
      requireValue(release?.repository === expected.repository && release.release_id === expected.release_id
        && release.source_sha === expected.source_sha && release.version === expected.version
        && release.producer?.run_id === expected.producer.run_id
        && release.producer?.run_attempt === expected.producer.run_attempt, 'Full producer identity differs');
    }
    const binding = verified.runtime_producer, runtimeNames = publishedAssetNames('runtime', target);
    requireValue(binding?.run_id === spec.runtime.producer.run_id && binding.run_attempt === spec.runtime.producer.run_attempt
      && binding.source_sha === spec.runtime.source_sha && binding.target === target
      && ['metadata_sha256','binary_sha256','archive_sha256'].every((key, i) =>
        binding[key] === spec.runtime.assets.find(asset => asset.name === runtimeNames[i]).sha256)
      && Array.isArray(binding.artifacts) && binding.artifacts.length === 2
      && [`runtime-release-${target}`,`runtime-smoke-${target}`].every(name => binding.artifacts.filter(artifact =>
        artifact.name === name && positiveID(artifact.id) && positiveID(artifact.job_id) && hashPattern.test(artifact.zip_sha256)).length === 1),
    'Full Runtime producer byte binding differs');
    const expectedAssets=['cli','runtime'].flatMap(kind=>publishedAssetNames(kind,target).map(name=>({repository:spec[kind].repository,...spec[kind].assets.find(a=>a.name===name)})));
    requireValue(Array.isArray(verified.assets) && verified.assets.length===expectedAssets.length && expectedAssets.every(a=>verified.assets.filter(b=>['repository','id','name','size','sha256'].every(k=>a[k]===b[k])).length===1), 'Full asset identities differ');
    const native = read('resident-concurrency-'+target,'real-account-return-verification.json');
    requireValue(Array.isArray(native) && native.length === 1 && native[0].binary_sha256 === spec.cli.assets.find(a => a.name === publishedAssetNames('cli',target)[1]).sha256, 'Native report binary differs');
    processes.push(...validatePublishedProcessEvidence(native[0],spec,target,manifestHash));
    requireValue(read('resident-concurrency-'+target,'resident-stress-metrics.json').passed === true, 'Resident stress incomplete');
    read('resident-concurrency-'+target,'fixture-dependencies.json');
    const bounded = read('resident-concurrency-'+target,'fixture-process-verification.json');
    requireValue(Array.isArray(bounded) && bounded.length > 0 && bounded.every(r => r.passed === true), 'Fixture process bounds incomplete');
    const upgrades = read('published-upgrades-'+target,'published-upgrades.json');
    requireValue(upgrades.passed === true && upgrades.profile === 'full' && upgrades.full_coverage === true
      && upgrades.all_published_sources_covered === true && upgrades.target === target
      && upgrades.candidate_sha256 === native[0].binary_sha256 && upgrades.selected_sources?.length > 0
      && upgrades.sources?.length === upgrades.selected_sources.length, 'Full historical upgrades incomplete');
    for (const version of upgrades.selected_sources) {
      const row = upgrades.sources.filter(r => 'v'+r.version === version);
      requireValue(row.length === 1 && (row[0].passed === true || row[0].status === 'not-applicable' && typeof row[0].reason === 'string'), 'Missing full upgrade source result');
      if (row[0].passed) {
        const check = read('published-upgrades-'+target,version+'/results/real-account-return-verification.json');
        requireValue(Array.isArray(check) && check.length === 1 && check[0].binary_sha256 === native[0].binary_sha256, 'Upgrade process binary differs');
        processes.push(...validatePublishedProcessEvidence(check[0],spec,target,manifestHash));
      }
    }
    if (target !== 'x86_64-unknown-linux-gnu') {
      job(j => j.name.startsWith('cloud-sweep (') && j.name.endsWith(', '+target+')'),target+' cloud');
      const base = read('base-release-sweep-'+target,'coverage.json');
      requireValue(base.source_sha === spec.cli.source_sha && base.binary_sha256 === native[0].binary_sha256
        && base.observed_version === spec.cli.version && base.expected_version === spec.cli.version
        && base.base_complete === true && base.failed === 0 && base.required_missing?.length === 0, 'Base sweep incomplete');
      if (target.includes('linux')) {
        const combined = read('release-sweep-'+target,'combined-coverage.json'); identity(combined,target);
        requireValue(combined.complete === true, 'Full supplement join incomplete');
        const outcomes = read('release-sweep-'+target,'suite-results.json');
        requireValue(Array.isArray(outcomes) && outcomes.length===6 && ['outbox','ai_inject','runtime','legacy_vault','profile_migration','login_interruption'].every(name=>outcomes.filter(r=>r.suite===name&&r.passed===true&&r.exit===0).length===1), 'Full suite outcomes incomplete');
        for (const name of ['ai-inject-coverage.json','legacy-vault-coverage.json','migration-coverage.json','interruption-coverage.json']) {
          const r=read('release-sweep-'+target,name); identity(r,target);
          requireValue(r.passed===true || name==='ai-inject-coverage.json' && r.status==='passed', 'Full raw supplement incomplete');
        }
        for (const name of ['outbox-coverage.json','runtime-coverage.json']) {
          const r = read('release-sweep-'+target,name); identity(r,target);
          processes.push(...validatePublishedProcessEvidence(r,spec,target,manifestHash));
        }
        const migration = read('secret-service-profile-migration-'+target,'migration-platform-gate.json'); identity(migration,target);
        requireValue(migration.passed === true, 'Secret Service migration incomplete');
        const login = read('secret-service-profile-migration-'+target,'interruption-coverage.json'); identity(login,target);
        requireValue(login.passed === true, 'Native login interruption incomplete');
      } else {
        job(j => j.name === `Native migration (${target})`,target+' migration');
        job(j => j.name === `Migration gate (${target})`,target+' migration join');
        const migration = read('native-profile-migration-'+target,'migration-platform-gate.json'); identity(migration,target);
        requireValue(migration.complete === true, 'Native migration join incomplete');
      }
    }
  }
  const login = read('gnu-login-interruption','interruption-coverage.json'); identity(login,'x86_64-unknown-linux-gnu');
  requireValue(login.passed === true, 'GNU login interruption incomplete');
  job(j => j.name === 'validate / npm-dry-run','npm packaging');
  const packages=read('npm-release-packages','published-package-validation.json');
  const expectedPackages=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url)));
  const packageNames=[...expectedPackages.targets.map(t=>t.pkg),expectedPackages.npmScope];
  requireValue(packageNames.length===targets.length+1 && packageNames.every(name=>packages.packages?.filter(p=>p.name===name).length===1) && packages.artifact_source==='published-assets' && packages.harness_sha===context.sha && packages.manifest_sha256===manifestHash
    && packages.product_sources?.cli===spec.cli.source_sha && packages.product_sources?.runtime===spec.runtime.source_sha
    && packages.run_id===context.run_id && packages.run_attempt===context.run_attempt
    && packages.packages?.length===targets.length+1 && new Set(packages.packages.map(p=>p.name)).size===targets.length+1
    && packages.packages.every(p=>p.version===spec.cli.version && hashPattern.test(p.sha256)), 'Published package validation differs');
  for(const packed of packages.packages) verifyFile(join(directory,'npm-release-packages'),{path:packed.file,sha256:packed.sha256});
  job(j => j.name === 'api-smoke','API');
  const apiIdentity=read('dev-api-coverage','published-api-identity.json');
  requireValue(apiIdentity.harness_sha===context.sha && apiIdentity.manifest_sha256===manifestHash
    && apiIdentity.run_id===context.run_id && apiIdentity.run_attempt===context.run_attempt, 'API report run binding differs');
  for (const name of ['dev-api-coverage.json','dev-github-api-coverage.json']) {
    const api = read('dev-api-coverage',name);
    requireValue(api.complete === true && !api.error
      && (name!=='dev-api-coverage.json' || api.cli_workflow_sha===context.sha)
      && apiIdentity.reports?.[name]===reports.at(-1).sha256, 'API coverage incomplete or stale');
  }
  return {schema:1,kind:'published-assets-full',manifest_sha256:manifestHash,harness_sha:context.sha,
    product_sources:{cli:spec.cli.source_sha,runtime:spec.runtime.source_sha},...context,
    reports,actual_processes:processes,full_passed:true,g1Passed:false,
    limits:['CLI full acceptance does not authorize cross-product fullG1 or stable publication','Process image receipts hash OS-identified executable files, not loaded memory pages','Seven current dev platforms only; Intel macOS, Client2 and real user database copies are not covered','API fixtures are server-contract evidence, not CLI asset execution','Core bytes are checked against published metadata and exact-source SDK locks, not an independent private SDK archive download','npm packaging uses the trusted harness wrapper plus immutable published binaries; it is not a download of the published npm tarballs']};
}
async function completePublished(spec,targets,directory) {
  const context = {sha:process.env.GITHUB_SHA,run_id:Number(process.env.GITHUB_RUN_ID),run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT)};
  const run=await readGitHub(`${process.env.GITHUB_REPOSITORY}/actions/runs/${context.run_id}`,process.env.GH_TOKEN,fetch);
  requireValue(run.id===context.run_id && run.run_attempt===context.run_attempt && run.head_sha===context.sha
    && run.head_repository?.full_name==='risense-ai/respire-cli' && run.event==='workflow_dispatch'
    && run.status==='in_progress' && run.conclusion===null, 'Full run cancelled, stale or not active');
  const jobs = [];
  for (let page=1; ;page++) {
    requireValue(page<=100,'Full job pagination exceeded');
    const batch = await readGitHub(`${process.env.GITHUB_REPOSITORY}/actions/runs/${context.run_id}/attempts/${context.run_attempt}/jobs?per_page=100&page=${page}`,process.env.GH_TOKEN,fetch);
    requireValue(Array.isArray(batch.jobs),'Invalid full job page'); jobs.push(...batch.jobs);
    if (jobs.length===batch.total_count) break;
    requireValue(batch.jobs.length>0 && jobs.length<batch.total_count,'Incomplete full job inventory');
  }
  const result = validatePublishedFull(spec,targets,process.env.PUBLISHED_ASSETS_SHA256,directory,jobs,context);
  writeFileSync(join(directory,'published-full-result.json'),JSON.stringify(result,null,2)+'\n');
}
function extractBuildArtifact() {
  const [source, destination] = process.argv.slice(2);
  if (!source || !destination) throw new Error('Pass artifact source and destination');
  const target = process.env.CLI_TARGET, sha = process.env.CLI_SHA, version = process.env.CLI_VERSION;
  const manifest = JSON.parse(readFileSync('npm/artifact-manifest.json', 'utf8'));
  if (!manifest.targets.some(item => item.triple === target) || !/^[a-f0-9]{40}$/.test(sha || '') || manifest.cliVersion !== version) {
    throw new Error('CLI target, source or version mismatch');
  }
  const metadata = JSON.parse(readFileSync(join(source, `cli-build-${target}.json`), 'utf8'));
  const extension = target.includes('windows') ? '.exe' : '';
  const binary = `${manifest.binaryName}-${target}${extension}`, runtime = `${manifest.binaryName}-${target}-runtime.tar.gz`;
  const hash = file => createHash('sha256').update(readFileSync(join(source, file))).digest('hex');
  const frontend = frontendLayout(manifest);
  validateBuildMetadata(metadata, manifest, target, {sha, version},
    {file:binary, size:statSync(join(source, binary)).size, sha256:hash(binary)},
    frontend ? undefined : {file:runtime, sha256:hash(runtime)});
  if (frontend && (existsSync(join(source, runtime)) || existsSync(join(destination, 'core-runtime.json'))
      || existsSync(join(destination, 'core-notices')))) throw Error('Frontend artifact contains a legacy SDK payload');
  mkdirSync(destination, {recursive:true});
  verifyBinary(join(source, binary), target);
  copyFileSync(join(source, binary), join(destination, manifest.binaryName+extension));
  copyFileSync(join(source, `cli-build-${target}.json`), join(destination, `cli-build-${target}.json`));
  if (!extension) chmodSync(join(destination, manifest.binaryName), 0o755);
  const tar = process.platform === 'win32' ? join(process.env.SystemRoot, 'System32', 'tar.exe') : 'tar';
  if (!frontend) execFileSync(tar, ['-xzf', resolve(source, runtime), '-C', resolve(destination)]);
  console.log(`Extracted verified ${target}@${version} from ${sha}`);
}
async function main() {
  if (['--validate-published', '--verify-published', '--consume-published', '--complete-published', '--pack-published'].includes(process.argv[2])) {
    const manifest = JSON.parse(readFileSync('npm/artifact-manifest.json', 'utf8'));
    const targets = manifest.targets.map(t => t.triple);
    const spec = validateArtifactRequest(process.env, targets);
    if (process.argv[2] === '--pack-published') {
      requireValue(spec && process.argv[3], 'Published package input directory required');
      await packPublished(spec,targets,resolve(process.argv[3]),process.env.PUBLISHED_ASSETS_SHA256);
    }
    if (process.argv[2] === '--complete-published') {
      requireValue(spec && process.argv[3], 'Full report directory required');
      await completePublished(spec,targets,resolve(process.argv[3]));
    }
    if (process.argv[2] === '--validate-published' && spec && process.env.GITHUB_OUTPUT) {
      appendFileSync(process.env.GITHUB_OUTPUT, `product_sha=${spec.cli.source_sha}\nversion=${spec.cli.version}\n`);
    }
    if (process.argv[2] === '--consume-published') {
      requireValue(spec && targets.includes(process.env.CLI_TARGET) && process.argv[3] && process.argv[4], 'Published source/destination required');
      const result = await consumePublishedTarget(spec, process.env.CLI_TARGET, resolve(process.argv[3]), resolve(process.argv[4]), process.env.PUBLISHED_ASSETS_SHA256, {token:process.env.GH_TOKEN});
      if (process.env.GITHUB_ENV) for (const [key,value] of Object.entries(result.env)) {
        requireValue(!/[\r\n]/.test(value), 'Invalid published environment value'); appendFileSync(process.env.GITHUB_ENV, `${key}=${value}\n`);
      }
    }
    if (process.argv[2] === '--verify-published') {
      requireValue(spec && targets.includes(process.env.CLI_TARGET) && process.argv[3], 'Published target/destination required');
      await verifyPublishedTarget(spec, process.env.CLI_TARGET, resolve(process.argv[3]), process.env.PUBLISHED_ASSETS_SHA256,
        {token: process.env.GH_TOKEN});
    }
    return;
  }
  if (process.env.ARTIFACT_SOURCE === 'published-assets') {
    process.argv.splice(2,0,'--consume-published'); return main();
  }
  extractBuildArtifact();
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
