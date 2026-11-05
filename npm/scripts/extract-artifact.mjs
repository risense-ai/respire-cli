import {createHash} from 'node:crypto';
import {chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, statSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {frontendLayout, validateBuildMetadata, verifyBinary} from './verify-binary.mjs';

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
