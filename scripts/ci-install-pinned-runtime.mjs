// CI fixture installation only: product verification remains in the caller.
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {setTimeout as delay} from 'node:timers/promises';

const readTimeout = 'Network Error: Network Error: Error encountered in the status line: timed out reading response: Network Error: Error encountered in the status line: timed out reading response: timed out reading response';
const windowsTimeout = 'A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond. (os error 10060)';
const connectTimeout = `Network Error: Network Error: Error encountered in the status line: ${windowsTimeout}: Network Error: Error encountered in the status line: ${windowsTimeout}: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond. (os error 10060)`;

function networkReason(reason) {
  return /^(?:status code (?:429|502|503|504))$/.test(reason) || reason === readTimeout || reason === connectTimeout;
}

function retryable(result, url) {
  if (result.error || result.signal || result.status !== 1) return false;
  let doc;
  try { doc = JSON.parse(result.stdout.toString('utf8')); } catch { return false; }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return false;
  if (Object.keys(doc).sort().join(',') !== 'actions,command,details,errors,items,related,status,summary') return false;
  if (doc.command !== 'cli' || doc.status !== 'fail' ||
      JSON.stringify(doc.summary) !== '{"reason":"runtime_error"}' ||
      JSON.stringify(doc.details) !== '{"error_type":"runtime"}') return false;
  if (!['items', 'actions', 'related'].every(key => Array.isArray(doc[key]) && doc[key].length === 0)) return false;
  if (!Array.isArray(doc.errors) || doc.errors.length !== 1 || typeof doc.errors[0] !== 'string') return false;
  const prefix = `release metadata request failed (${url}): ${url}: `;
  const error = doc.errors[0];
  if (error.startsWith(prefix)) return networkReason(error.slice(prefix.length));
  const archivePrefix = 'runtime download failed: ';
  if (!error.startsWith(archivePrefix)) return false;
  const failures = error.slice(archivePrefix.length).split('; ');
  const origins = ['https://github.com', 'https://gh-proxy.com/https://github.com'];
  if (failures.length !== origins.length) return false;
  const archive = url.replace(/\/runtime-build-([^/]+)\.json$/, '/rsrs-runtime-$1.tar.gz');
  return origins.every((origin, index) => {
    const asset = archive.replace('https://github.com', origin);
    const expected = `${origin}: download failed (${asset}): ${asset}: `;
    return failures[index].startsWith(expected) && networkReason(failures[index].slice(expected.length));
  });
}

export async function installPinnedRuntime(cli, {env}, target, {
  spawn = spawnSync, pause = delay, stdout = process.stdout, stderr = process.stderr,
} = {}) {
  const pin = JSON.parse(readFileSync(new URL('../runtime-pin.json', import.meta.url), 'utf8'));
  if (!/^\d+\.\d+\.\d+(?:-[a-z]+\.\d+)?$/.test(pin.required) || !/^[a-z0-9_]+(?:-[a-z0-9_]+)+$/.test(target)) {
    throw new Error('Invalid pinned Runtime metadata identity');
  }
  const url = `https://github.com/risense-ai/respire-runtime/releases/download/v${pin.required}/runtime-build-${target}.json`;
  for (let attempt = 1; attempt <= 2; attempt++) {
    const result = spawn(cli, ['--json', 'runtime', 'install'], {env, stdio: ['inherit', 'pipe', 'pipe']});
    if (result.stdout) stdout.write(result.stdout);
    if (result.stderr) stderr.write(result.stderr);
    if (attempt === 2 || !retryable(result, url)) return result;
    stderr.write('Official pinned Runtime download network failure; retrying once after 2s.\n');
    await pause(2000);
  }
}
