import {createHash} from 'node:crypto';
import {appendFileSync, cpSync, existsSync, mkdirSync, readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {homedir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export function cacheKey(kind, identity) {
  if (!['workspace', 'coverage'].includes(kind)) throw Error('Unknown Rust cache kind');
  return `rust-ci-v1-${kind}-${createHash('sha256').update(JSON.stringify(identity)).digest('hex')}`;
}

function metadata() {
  return JSON.parse(execFileSync('cargo', ['metadata', '--locked', '--no-deps', '--format-version', '1'], {encoding: 'utf8'}));
}

function main(action, kind) {
  cacheKey(kind, {});
  const target = kind === 'coverage' ? 'target/llvm-cov-target' : 'target';
  const registry = path.join(process.env.CARGO_HOME || path.join(homedir(), '.cargo'), 'registry');
  const stage = '.rust-ci-cache';
  if (action === 'key') {
    const files = [...metadata().packages.map(p => p.manifest_path), 'Cargo.lock', '.cargo/config.toml',
      'rust-toolchain.toml', 'sdk/core-sdk.lock.json', 'crates/core-sdk/core-sdk.lock.json', '.github/workflows/ci.yml'];
    const identity = {
      rust: execFileSync('rustc', ['-Vv'], {encoding: 'utf8'}),
      coverage: kind === 'coverage' ? execFileSync('cargo', ['llvm-cov', '--version'], {encoding: 'utf8'}) : null,
      platform: process.platform, arch: process.arch, image: process.env.ImageOS,
      flags: Object.entries(process.env).filter(([key]) => key.startsWith('CARGO_PROFILE_') ||
        ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET'].includes(key)).sort(),
      files: files.filter(existsSync).sort().map(file => [path.relative(process.cwd(), path.resolve(file)),
        createHash('sha256').update(readFileSync(file)).digest('hex')]),
    };
    appendFileSync(process.env.GITHUB_OUTPUT, `key=${cacheKey(kind, identity)}\n`);
  } else if (action === 'restore') {
    for (const [from, to] of [[`${stage}/target/debug`, `${target}/debug`],
      [`${stage}/cargo/cache`, `${registry}/cache`], [`${stage}/cargo/index`, `${registry}/index`]]) {
      if (existsSync(from)) { mkdirSync(path.dirname(to), {recursive: true}); cpSync(from, to, {recursive: true}); }
    }
  } else if (action === 'pack') {
    // Cache dependency builds only; workspace binaries and old coverage cannot prove a new run.
    const args = ['clean', '--target-dir', target];
    for (const pkg of metadata().packages) args.push('-p', pkg.name);
    execFileSync('cargo', args, {stdio: 'inherit'});
    const archive = path.join(process.env.RUNNER_TEMP, `rust-build-${kind}.tar.gz`);
    execFileSync('tar', ['--hard-dereference', '-I', 'gzip -1', '-cf', archive,
      '--transform=s,^debug,target/debug,', '--transform=s,^cache,cargo/cache,', '--transform=s,^index,cargo/index,',
      '-C', path.resolve(target), 'debug', '-C', registry, 'cache', 'index'], {stdio: 'inherit'});
  } else throw Error('Expected key, restore or pack');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(...process.argv.slice(2));
}
