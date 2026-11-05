import {createHash} from 'node:crypto';
import {copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {frontendLayout, validateBuildMetadata, verifyBinary} from './verify-binary.mjs';

const [target] = process.argv.slice(2);
const manifest = JSON.parse(readFileSync('npm/artifact-manifest.json', 'utf8'));
if (!manifest.targets.some(item => item.triple === target)) throw new Error('Unknown CLI target');
const directory = join('target/ci', target, 'release');
const extension = target.includes('windows') ? '.exe' : '';
const source = join(directory, manifest.binaryName+extension);
const frontend = frontendLayout(manifest);
verifyBinary(source, target);
const actualVersion = execFileSync(source, ['--version'], {encoding:'utf8'}).trim();
if (actualVersion !== `${manifest.binaryName} ${manifest.cliVersion}`) {
  throw new Error(`CLI binary version mismatch: ${actualVersion}`);
}
const hash = path => createHash('sha256').update(readFileSync(path)).digest('hex');
mkdirSync('dist', {recursive:true});
const binary_file = `${manifest.binaryName}-${target}${extension}`;
const git_sha = execFileSync('git', ['rev-parse', 'HEAD'], {encoding:'utf8'}).trim();
if (frontend) {
  if (existsSync(join(directory, 'core-runtime.json')) || existsSync(join(directory, 'core-notices'))) {
    throw Error('Frontend build directory still contains a Core SDK payload');
  }
  const info = {schema_version:2, artifact_layout:manifest.artifactLayout, git_sha,
    version:manifest.cliVersion, target, binary_file, binary_size:statSync(source).size,
    binary_sha256:hash(source), producer:{run_id:process.env.GITHUB_RUN_ID, run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT)}};
  validateBuildMetadata(info, manifest, target, {sha:git_sha, version:manifest.cliVersion},
    {file:binary_file, size:statSync(source).size, sha256:hash(source)});
  copyFileSync(source, join('dist', binary_file));
  writeFileSync(join('dist', `cli-build-${target}.json`), JSON.stringify(info, null, 2)+'\n');
  console.log(`Staged verified ${actualVersion} frontend for ${target}`);
  process.exit(0);
}
const runtime = JSON.parse(readFileSync(join(directory, 'core-runtime.json'), 'utf8'));
if (runtime.target !== target || runtime.redistribution !== 'permitted-under-included-license') {
  throw new Error('CLI runtime target or redistribution license mismatch');
}
for (const file of runtime.files) {
  if (hash(join(directory, file.path)) !== file.sha256) throw new Error(`Runtime checksum mismatch: ${file.path}`);
}
const runtime_file = `${manifest.binaryName}-${target}-runtime.tar.gz`;
copyFileSync(source, join('dist', binary_file));
execFileSync('tar', ['-czf', join('dist', runtime_file), '-C', directory, 'core-runtime.json', 'core-notices',
  ...runtime.files.filter(file => !file.path.includes('/')).map(file => file.path)]);
writeFileSync(join('dist', `cli-build-${target}.json`), JSON.stringify({
  schema_version:1,
  git_sha,
  version:manifest.cliVersion, target, binary_file, runtime_file,
  binary_sha256:hash(join('dist', binary_file)), runtime_sha256:hash(join('dist', runtime_file)),
}, null, 2)+'\n');
console.log(`Staged verified ${actualVersion} binary/runtime for ${target}`);
