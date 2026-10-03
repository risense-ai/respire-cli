import {createHash} from 'node:crypto';
import {copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const [destination] = process.argv.slice(2);
if (!destination || !process.env.RESPIRE_CORE_SDK_DIR) throw new Error('Set RESPIRE_CORE_SDK_DIR and pass the binary directory');
const sdk = resolve(process.env.RESPIRE_CORE_SDK_DIR), output = resolve(destination);
const manifest = JSON.parse(readFileSync(join(sdk,'manifest.json'),'utf8'));
const files = [];
for (const file of manifest.files) {
  let path;
  if (file.path.startsWith('runtime/')) path = file.path.slice(8);
  else if (file.path.startsWith('notices/')) path = `core-notices/${file.path.slice(8)}`;
  else if (file.path === 'LICENSE.txt') path = 'core-notices/CORE-SDK-LICENSE.txt';
  else continue;
  if (path.includes('\\') || path.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('Unsafe runtime path');
  const bytes = readFileSync(join(sdk,file.path));
  if (createHash('sha256').update(bytes).digest('hex') !== file.sha256) throw new Error(`SDK checksum mismatch: ${file.path}`);
  mkdirSync(dirname(join(output,path)),{recursive:true});
  copyFileSync(join(sdk,file.path),join(output,path));
  files.push({path,sha256:file.sha256});
}
if (manifest.redistribution === 'permitted-under-included-license' && !files.some(file => file.path === 'core-notices/CORE-SDK-LICENSE.txt')) {
  throw new Error('Released Core SDK is missing its redistribution license');
}
const modelNotices = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'model-notices');
for (const entry of readdirSync(modelNotices, {withFileTypes:true})) {
  if (!entry.isFile()) continue;
  const bytes = readFileSync(join(modelNotices, entry.name));
  const path = `core-notices/models/${entry.name}`;
  mkdirSync(dirname(join(output,path)), {recursive:true});
  writeFileSync(join(output,path), bytes);
  files.push({path,sha256:createHash('sha256').update(bytes).digest('hex')});
}
const dependencyNotices = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'dependency-notices');
for (const entry of readdirSync(dependencyNotices, {withFileTypes:true})) {
  if (!entry.isFile()) continue;
  const bytes = readFileSync(join(dependencyNotices, entry.name));
  const path = `core-notices/consumer/${entry.name}`;
  mkdirSync(dirname(join(output,path)), {recursive:true});
  writeFileSync(join(output,path), bytes);
  files.push({path,sha256:createHash('sha256').update(bytes).digest('hex')});
}
writeFileSync(join(output,'core-runtime.json'),JSON.stringify({schema_version:1,target:manifest.target,
  sdk_version:manifest.sdk_version,redistribution:manifest.redistribution,files},null,2)+'\n');
console.log(`Staged ${files.length} runtime/notice files next to the CLI`);
