import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {parsePublishedAssets, publishedAssetNames, validatePublishedRelease} from '../npm/scripts/extract-artifact.mjs';

const args = process.argv.slice(2);
assert.equal(args.length, 4, 'Usage: node scripts/create-published-assets.mjs CLI_TAG CLI_RUN_ID RUNTIME_TAG RUNTIME_RUN_ID');
const targets = JSON.parse(readFileSync(new URL('../npm/artifact-manifest.json', import.meta.url))).targets.map(t => t.triple);
const api = path => JSON.parse(execFileSync('gh', ['api', path], {encoding: 'utf8'}));
const spec = {schema: 2};
for (const [kind, tag, runID] of [['cli', args[0], args[1]], ['runtime', args[2], args[3]]]) {
  assert.match(tag, /^v\d+\.\d+\.\d+(?:-dev\.\d+)?$/, 'Require an explicit public release tag');
  assert.match(runID, /^[1-9]\d*$/, 'Require an explicit producer run ID');
  const repository = `risense-ai/respire-${kind}`;
  const prefix = `repos/${repository}`;
  const release = api(`${prefix}/releases/tags/${tag}`);
  const source = api(`${prefix}/commits/${tag}`);
  const run = api(`${prefix}/actions/runs/${runID}`);
  assert.equal(run.id, Number(runID));
  assert.equal(run.repository?.full_name, repository);
  assert.equal(run.path, '.github/workflows/release.yml');
  assert.equal(run.head_sha, source.sha, 'Producer must match the actual public tag source');
  assert.equal(run.status, 'completed');
  assert.equal(run.conclusion, 'success');
  const assets = JSON.parse(execFileSync('gh', ['api', '--paginate', '--slurp',
    `${prefix}/releases/${release.id}/assets?per_page=100`], {encoding: 'utf8'})).flat();
  const part = {
    repository, release_id: release.id, version: tag.slice(1), source_sha: source.sha,
    producer: {run_id: run.id, run_attempt: run.run_attempt},
    assets: targets.flatMap(target => publishedAssetNames(kind, target)).map(name => {
      const matches = assets.filter(asset => asset.name === name);
      assert.equal(matches.length, 1, `Require one public asset: ${repository}/${name}`);
      const asset = matches[0];
      assert.match(asset.digest ?? '', /^sha256:[a-f0-9]{64}$/, `Missing public SHA-256: ${name}`);
      return {id: asset.id, name, size: asset.size, sha256: asset.digest.slice(7)};
    }),
  };
  validatePublishedRelease(part, release, assets, source.sha);
  spec[kind] = part;
}
const json = JSON.stringify(spec);
const sha256 = createHash('sha256').update(json, 'utf8').digest('hex');
parsePublishedAssets(json, sha256, targets);
console.error(`published_assets_sha256=${sha256}`);
process.stdout.write(json);
