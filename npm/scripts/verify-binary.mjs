import {readFileSync} from 'node:fs';

export function frontendLayout(manifest) {
  if (manifest.artifactLayout === undefined) return false;
  if (manifest.artifactLayout !== 'cli-frontend-v2') throw Error('Unknown CLI artifact layout');
  return true;
}

export function releaseAssetNames(manifest, target) {
  const binary = `${manifest.binaryName || 'rsrs'}-${target}${target.includes('windows') ? '.exe' : ''}`;
  return [binary, `cli-build-${target}.json`,
    ...(!frontendLayout(manifest) ? [`${manifest.binaryName || 'rsrs'}-${target}-runtime.tar.gz`] : [])];
}

// Callers supply hashes and sizes of actual files, never metadata claims.
export function validateBuildMetadata(info, manifest, target, source, binary, runtime) {
  const names = releaseAssetNames(manifest, target);
  const fail = () => { throw Error('CLI artifact metadata/source/size/checksum mismatch'); };
  if (info.git_sha !== source.sha || info.version !== source.version || info.target !== target
      || info.binary_file !== names[0] || binary.file !== names[0]
      || !/^[a-f0-9]{64}$/.test(info.binary_sha256 || '') || info.binary_sha256 !== binary.sha256) fail();
  if (frontendLayout(manifest)) {
    const keys = ['schema_version','artifact_layout','git_sha','version','target','binary_file','binary_size','binary_sha256','producer'];
    const positive = value => /^[1-9]\d*$/.test(String(value)) && Number.isSafeInteger(Number(value));
    if (info.schema_version !== 2 || info.artifact_layout !== manifest.artifactLayout
        || Object.keys(info).sort().join() !== keys.sort().join()
        || !Number.isSafeInteger(binary.size) || binary.size <= 0 || info.binary_size !== binary.size
        || !info.producer || Object.keys(info.producer).sort().join() !== 'run_attempt,run_id'
        || !positive(info.producer.run_id) || !positive(info.producer.run_attempt)
        || (source.run_id !== undefined && String(info.producer.run_id) !== String(source.run_id))
        || (source.run_attempt !== undefined && Number(info.producer.run_attempt) !== Number(source.run_attempt))
        || runtime !== undefined) fail();
  } else if (info.schema_version !== 1 || info.artifact_layout !== undefined
      || info.runtime_file !== names[2] || runtime?.file !== names[2]
      || !/^[a-f0-9]{64}$/.test(info.runtime_sha256 || '') || info.runtime_sha256 !== runtime?.sha256) fail();
  return info;
}

// Execution alone accepts x64 under Windows ARM emulation; inspect the image too.
export function verifyBinary(file, target) {
  // This published asset label is the manifest's darwin/arm64 alias.
  const darwinArmAlias = target === 'aarch64-apple-darwin';
  const bytes = readFileSync(file);
  const arm = darwinArmAlias || target.startsWith('aarch64-');
  if (!arm && !target.startsWith('x86_64-')) throw new Error(`Unsupported binary target: ${target}`);
  let matches = false;
  if (target.endsWith('-pc-windows-msvc') && bytes.subarray(0, 2).toString() === 'MZ') {
    const offset = bytes.readUInt32LE(0x3c);
    matches = bytes.subarray(offset, offset + 4).equals(Buffer.from('PE\0\0'))
      && bytes.readUInt16LE(offset + 4) === (arm ? 0xaa64 : 0x8664)
      && bytes.readUInt16LE(offset + 24) === 0x20b;
  } else if (darwinArmAlias || target.endsWith('-apple-darwin')) {
    matches = bytes.readUInt32LE(0) === 0xfeedfacf
      && bytes.readUInt32LE(4) === (arm ? 0x100000c : 0x1000007);
  } else if (/^\w+-unknown-linux-(gnu|musl)$/.test(target)) {
    matches = bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
      && bytes[4] === 2 && bytes[5] === 1
      && bytes.readUInt16LE(18) === (arm ? 183 : 62);
  }
  if (!matches) throw new Error(`Binary header does not match ${target}: ${file}`);
}
