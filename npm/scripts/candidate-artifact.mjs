// Unpublished CLI Actions bytes, paired with the exact official pinned Runtime.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {appendFileSync, copyFileSync, mkdirSync, readFileSync, statSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {publishedAssetNames, inspectPublishedRelease, inspectRuntimeProducer, downloadPublishedAsset, consumePublishedTarget, validatePublishedFull} from './extract-artifact.mjs';

export const candidateHash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const api = path => JSON.parse(execFileSync('gh',['api',path],{encoding:'utf8'}));
const pages = path => JSON.parse(execFileSync('gh',['api','--paginate','--slurp',path],{encoding:'utf8'})).flat();
const targets = () => JSON.parse(readFileSync('npm/artifact-manifest.json')).targets.map(t=>t.triple);
export function validateCandidate(candidate, env=process.env) {
  assert.equal(candidate.schema,1);
  assert.equal(candidate.kind,'unpublished-cli-candidate');
  assert.equal(candidate.source.repository,'risense-ai/respire-cli');
  assert.match(candidate.source.sha,/^[a-f0-9]{40}$/);
  assert.match(candidate.source.version,/^\d+\.\d+\.\d+-dev\.[1-9]\d*$/);
  for(const key of ['run_id','run_attempt'])assert.ok(Number.isSafeInteger(candidate.source[key])&&candidate.source[key]>0);
  assert.equal(candidate.source.sha,env.CLI_SHA);
  assert.equal(candidate.source.version,env.CLI_VERSION);
  assert.equal(candidate.source.run_id,Number(env.CLI_PRODUCER_RUN_ID || env.GITHUB_RUN_ID));
  assert.equal(candidate.source.run_attempt,Number(env.CLI_PRODUCER_ATTEMPT || env.GITHUB_RUN_ATTEMPT));
  if(env.CLI_PRODUCER_RUN_ID){
    assert.equal(env.GITHUB_REF,'refs/heads/main');
    assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');
    assert.match(env.GITHUB_SHA,/^[a-f0-9]{40}$/);
  }else assert.equal(candidate.source.sha,env.GITHUB_SHA,'Candidates must use the exact main harness source');
  assert.match(candidate.client2.release,/^v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/);
  assert.match(candidate.client2.source_sha,/^[a-f0-9]{40}$/);
  const runtime=candidate.runtime;
  assert.equal(runtime.repository,'risense-ai/respire-runtime');
  assert.equal(runtime.version,JSON.parse(readFileSync('runtime-pin.json')).required);
  assert.match(runtime.source_sha,/^[a-f0-9]{40}$/);
  const names=targets().flatMap(t=>publishedAssetNames('runtime',t));
  assert.deepEqual(runtime.assets.map(a=>a.name).sort(),names.sort());
  for(const a of runtime.assets){assert.match(a.sha256,/^[a-f0-9]{64}$/);assert.ok(a.id>0&&a.size>0);}
  return candidate;
}
export async function resolveCandidate() {
  assert.equal(process.env.GITHUB_REF,'refs/heads/main');
  assert.equal(process.env.GITHUB_EVENT_NAME,'workflow_dispatch');
  const version=JSON.parse(readFileSync('runtime-pin.json')).required;
  const repository='risense-ai/respire-runtime', prefix=`repos/${repository}`;
  const release=api(`${prefix}/releases/tags/v${version}`),sha=api(`${prefix}/commits/v${version}`).sha;
  // Never guess a producer from an unbound latest run or from a release description.
  const runs=pages(`${prefix}/actions/workflows/release.yml/runs?head_sha=${sha}&per_page=100`).flatMap(p=>p.workflow_runs)
    .filter(r=>r.head_sha===sha&&r.status==='completed'&&r.conclusion==='success'&&r.path==='.github/workflows/release.yml');
  assert.equal(runs.length,1,'Require one successful exact-source pinned Runtime producer');
  const assets=pages(`${prefix}/releases/${release.id}/assets?per_page=100`);
  const runtime={repository,release_id:release.id,version,source_sha:sha,producer:{run_id:runs[0].id,run_attempt:runs[0].run_attempt},
    assets:targets().flatMap(t=>publishedAssetNames('runtime',t)).map(name=>{
      const matches=assets.filter(a=>a.name===name);assert.equal(matches.length,1);
      const a=matches[0];assert.match(a.digest,/^sha256:[a-f0-9]{64}$/);
      return {id:a.id,name,size:a.size,sha256:a.digest.slice(7)};
    })};
  await inspectPublishedRelease(runtime,{token:process.env.GH_TOKEN});
  const candidate=validateCandidate({schema:1,kind:'unpublished-cli-candidate',client2:{release:process.env.CLIENT2_RELEASE,source_sha:process.env.CLIENT2_COMMIT},source:{repository:'risense-ai/respire-cli',
    sha:process.env.CLI_SHA,version:process.env.CLI_VERSION,run_id:Number(process.env.GITHUB_RUN_ID),run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT)},runtime});
  appendFileSync(process.env.GITHUB_OUTPUT,`candidate=${JSON.stringify(candidate)}\n`);
}
export async function consumeCandidate(source,destination,target) {
  const candidate=validateCandidate(JSON.parse(process.env.CANDIDATE_ASSETS));
  assert.ok(targets().includes(target));
  const folder=join(process.env.RUNNER_TEMP,'candidate-assets-'+target);
  mkdirSync(folder);mkdirSync(join(folder,'cli'));mkdirSync(join(folder,'runtime'));
  const cliAssets=publishedAssetNames('cli',target).map(name=>{
    const path=join(source,name),bytes=readFileSync(path);copyFileSync(path,join(folder,'cli',name));
    return {name,size:statSync(path).size,sha256:createHash('sha256').update(bytes).digest('hex')};
  });
  const spec={runtime:candidate.runtime,cli:{repository:candidate.source.repository,source_sha:candidate.source.sha,
    version:candidate.source.version,producer:{run_id:candidate.source.run_id,run_attempt:candidate.source.run_attempt},assets:cliAssets}};
  const options={token:process.env.GH_TOKEN,candidate:true};
  await inspectPublishedRelease(spec.runtime,options);
  const producer=await inspectRuntimeProducer(spec.runtime,target,options);
  for(const name of publishedAssetNames('runtime',target))await downloadPublishedAsset(spec.runtime,spec.runtime.assets.find(a=>a.name===name),join(folder,'runtime'),options);
  const consumed=await consumePublishedTarget(spec,target,folder,destination,candidateHash(candidate),options);
  const receipt={schema:1,kind:'candidate-assets-verification',candidate,target,manifest_sha256:candidateHash(candidate),
    assets_verified:true,payloads_verified:true,cli_assets:cliAssets,runtime_producer:producer,payload_identity:consumed.identity};
  writeFileSync(join(destination,'candidate-assets-receipt.json'),JSON.stringify(receipt,null,2)+'\n');
  // Existing fixture receipts use these hash fields for both asset sources.
  consumed.env.RSRS_ARTIFACT_SOURCE='build';
  for(const [key,value] of Object.entries(consumed.env)){
    assert.ok(!/[\r\n]/.test(value));appendFileSync(process.env.GITHUB_ENV,`${key}=${value}\n`);
  }
  return receipt;
}
export function completeCandidate(candidate,assets,directory,jobs,source,options={}) {
  validateCandidate(candidate,options.env || process.env);
  assert.equal(candidate.source.sha,source.sha);assert.equal(candidate.source.version,source.version);
  const producer=source.producer || source;
  assert.equal(candidate.source.run_id,Number(producer.run_id));assert.equal(candidate.source.run_attempt,Number(producer.run_attempt));
  const spec={runtime:candidate.runtime,cli:{repository:source.repository,source_sha:source.sha,version:source.version,
    producer:{run_id:Number(producer.run_id),run_attempt:Number(producer.run_attempt)},assets:assets.map(({file,...a})=>({name:file,...a}))}};
  const result=validatePublishedFull(spec,targets(),candidateHash(candidate),directory,jobs,
    {sha:source.workflow_head_sha || source.sha,run_id:Number(source.run_id),run_attempt:Number(source.run_attempt)},{candidate,...options});
  assert.equal(result.full_passed,true);
  return result;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  if(process.argv[2]==='resolve')await resolveCandidate();
  else throw Error('Expected resolve');
}
