// Temporary branch-only diagnosis: original product source and current harness are distinct.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {appendFileSync,copyFileSync,mkdirSync,readFileSync,statSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {candidateHash,validateCandidate} from '../npm/scripts/candidate-artifact.mjs';
import {consumePublishedTarget,inspectPublishedRelease,inspectRuntimeProducer,downloadPublishedAsset,publishedAssetNames} from '../npm/scripts/extract-artifact.mjs';
const original={sha:'a8cd68c46eaad307d32cf48d2e4d82406d122581',run_id:44098649710,run_attempt:1};
const candidate=validateCandidate(JSON.parse(process.env.CANDIDATE_ASSETS),{
  ...process.env,CLI_SHA:original.sha,CLI_VERSION:'2.0.0-dev.19',
  GITHUB_SHA:original.sha,GITHUB_RUN_ID:String(original.run_id),GITHUB_RUN_ATTEMPT:'1',
});
assert.deepEqual(candidate.client2,{release:'v2.0.0-dev.15',source_sha:'f3455ce639cc2ab9e35762c2668367fccb3d2ad5'});
assert.equal(candidate.runtime.version,'2.0.0-dev.24');
assert.equal(candidate.runtime.source_sha,'7e8ae8dc55f832dd2e22d5e6031a37c4c7905d3b');
// Ensure the actual executed probe is precisely the merged repair, not an unreviewed product change.
const repaired=execFileSync('git',['show','b23ed8c4213fed3dd59b724d8623295cc4d59d9a:scripts/probe-client2-gui.ps1']);
assert.equal(repaired.toString('utf8').replaceAll('\r\n','\n'),readFileSync('scripts/probe-client2-gui.ps1','utf8').replaceAll('\r\n','\n'));
const target=process.env.CLI_TARGET, root=join(process.env.RUNNER_TEMP,'diagnostic-assets');
mkdirSync(root); for(const kind of ['cli','runtime'])mkdirSync(join(root,kind));
const cliAssets=publishedAssetNames('cli',target).map(name=>{
  const path=join(process.env.RUNNER_TEMP,'original-cli',name),bytes=readFileSync(path);
  copyFileSync(path,join(root,'cli',name));
  return {name,size:statSync(path).size,sha256:createHash('sha256').update(bytes).digest('hex')};
});
const metadata=JSON.parse(readFileSync(join(root,'cli',`cli-build-${target}.json`)));
assert.equal(metadata.producer.run_id,String(original.run_id));assert.equal(metadata.producer.run_attempt,'1');
const spec={runtime:candidate.runtime,cli:{repository:'risense-ai/respire-cli',source_sha:original.sha,
  version:'2.0.0-dev.19',producer:{run_id:original.run_id,run_attempt:1},assets:cliAssets}};
const options={token:process.env.GH_TOKEN,candidate:true};
const release=await inspectPublishedRelease(spec.runtime,options);
const runtimeProducer=await inspectRuntimeProducer(spec.runtime,target,options);
for(const name of publishedAssetNames('runtime',target))
  await downloadPublishedAsset(spec.runtime,spec.runtime.assets.find(a=>a.name===name),join(root,'runtime'),options);
const destination=join(process.env.RUNNER_TEMP,'diagnostic-consumed');
const consumed=await consumePublishedTarget(spec,target,root,destination,candidateHash(candidate),options);
assert.equal(consumed.identity.harness_sha,process.env.GITHUB_SHA);
for(const [key,value] of Object.entries({...consumed.env,RSRS_ARTIFACT_SOURCE:'build'})){
  assert.ok(!/[\r\n]/.test(value));appendFileSync(process.env.GITHUB_ENV,`${key}=${value}\n`);
}
// Probe must consume the identity receipt and bytes from the same verified directory.
copyFileSync(join(destination,'candidate-consumer-identity.json'),join(process.env.RUNNER_TEMP,'diagnostic-cli','candidate-consumer-identity.json'));
writeFileSync(join(process.env.RUNNER_TEMP,'diagnostic-input-proof.json'),JSON.stringify({diagnostic_only:true,
  full_passed:false,harness_sha:process.env.GITHUB_SHA,repaired_probe_commit:'b23ed8c4213fed3dd59b724d8623295cc4d59d9a',
  candidate,release,runtimeProducer,identity:consumed.identity},null,2)+'\n');
