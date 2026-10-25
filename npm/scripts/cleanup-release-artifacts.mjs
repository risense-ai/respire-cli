import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtempSync,readFileSync,writeFileSync,rmSync,appendFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {validateScoped,validateAlias,RELEASE_ARTIFACT_CLEANUP_POLICY} from './release-publication.mjs';

export const REPOSITORY='risense-ai/respire-cli';
export const CLEANUP_POLICY=RELEASE_ARTIFACT_CLEANUP_POLICY;
const RELEASE='.github/workflows/release.yml', ALIAS='.github/workflows/npm-alias.yml';
const id=value=>Number.isSafeInteger(Number(value))&&Number(value)>0;
const timestamp=value=>{const n=Date.parse(value);if(!Number.isFinite(n))throw Error('Missing terminal timestamp');return n;};
const terminal=run=>run.status==='completed';
const workflow=(run,file)=>run.path===file&&run.head_repository?.full_name===REPOSITORY;
const samePolicy=p=>p?.schema===1&&p.after_consumers_seconds===3600&&Object.keys(p).length===2;
export function requireRegressions(jobs,targets){
  const native=jobs.filter(j=>j.name.includes('native-regression / Native ('));
  const cloud=jobs.filter(j=>j.name.startsWith('cloud-sweep ('));
  const api=jobs.filter(j=>j.name==='api-smoke');
  if(native.length!==4||cloud.length!==3||api.length!==1||new Set(native.map(j=>j.name)).size!==4||new Set(cloud.map(j=>j.name)).size!==3||!targets.every(t=>native.some(j=>j.name.endsWith(`Native (${t})`)))||!targets.filter(t=>t!=='x86_64-unknown-linux-gnu').every(t=>cloud.some(j=>j.name.includes(t)))||[...native,...cloud,...api].some(j=>j.status!=='completed'||j.conclusion!=='success'))throw Error('All eight regressions must finish successfully');
  if(jobs.some(j=>j.status!=='completed')||!jobs.some(j=>j.name==='publish'&&j.conclusion==='success'))throw Error('Source consumers/publisher are not complete');
}
export function requirePublished(release,scoped,tag){
  const s=scoped.source;
  if(release.id!==Number(s.release_id)||release.draft!==false||!release.published_at||release.tag_name!==`v${s.version}`||release.target_commitish!==s.sha||release.prerelease!==(s.channel==='dev')||tag?.type!=='commit'||tag.sha!==s.sha)throw Error('Exact public release/tag required');
  if(release.assets.length!==scoped.assets.length||!scoped.assets.every(e=>release.assets.some(a=>a.name===e.name&&a.size===e.size&&a.state==='uploaded'&&a.digest===`sha256:${e.sha256}`)))throw Error('Public release assets differ');
}
export function allowedSourceArtifact(name,source,targets){
  if(name===`scoped-ready-${source.run_id}-${source.run_attempt}`)return true;
  if(['npm-release-packages','npm-release-validation','dev-api-coverage','gnu-login-interruption'].includes(name))return true;
  return targets.some(t=>['cli-release-','release-sweep-','base-release-sweep-','resident-concurrency-','published-upgrades-','native-profile-migration-','secret-service-profile-migration-'].some(p=>name===p+t));
}
function boundArtifact(a,run){
  if(!id(a.id)||a.expired||a.workflow_run?.id!==run.id||a.workflow_run?.head_sha!==run.head_sha||!/^sha256:[a-f0-9]{64}$/.test(a.digest||''))throw Error('Artifact identity/digest/attempt changed');
}
function runStamp(r){return [r.id,r.run_attempt,r.status,r.conclusion,r.updated_at,r.head_sha,r.path];}
export async function planCleanup(io,runId,manifest,now=Date.now()){
  if(io.repository!==REPOSITORY||!id(runId))throw Error('Cleanup repository/run scope refused');
  const run=await io.run(runId);
  if(!workflow(run,RELEASE)||!['push','workflow_dispatch'].includes(run.event)||!terminal(run)||run.conclusion!=='success')return {skip:'source-not-successfully-complete'};
  const artifacts=await io.artifacts(run.id), readyName=`scoped-ready-${run.id}-${run.run_attempt}`;
  const ready=artifacts.filter(a=>a.name===readyName&&!a.expired);
  if(ready.length!==1)return {skip:'no-unique-scoped-receipt'};
  boundArtifact(ready[0],run);
  const scoped=await io.receipt(ready[0],'scoped-ready.json');
  // An explicit opt-in written by NEW publication code prevents retroactive
  // deletion of historical artifacts not covered by a confirmed batch.
  if(!samePolicy(scoped.cleanup_policy))return {skip:'historical-release-not-opted-in'};
  validateScoped(scoped,manifest);
  const source=scoped.source;
  if(source.recovery||String(source.run_id)!==String(run.id)||Number(source.run_attempt)!==run.run_attempt)return {skip:'unsupported-or-stale-attempt'};
  const jobs=await io.jobs(run.id,run.run_attempt);requireRegressions(jobs,manifest.targets.map(t=>t.triple));
  const release=await io.release(source.release_id),tag=await io.tag(`v${source.version}`);requirePublished(release,scoped,tag);
  // Include even unsuccessful/duplicate/manual alias consumers. Unbound manual
  // inputs are not exposed in run metadata, so this barrier is conservative.
  const consumers=await io.consumers(run.created_at);
  if(consumers.some(r=>!workflow(r,ALIAS)||!terminal(r)))return {skip:'alias-consumer-still-active'};
  let provedAlias=false;const aliasArtifacts=[];
  for(const consumer of consumers){
    const childJobs=await io.jobs(consumer.id,consumer.run_attempt);
    if(childJobs.some(j=>j.status!=='completed'))return {skip:'alias-jobs-not-terminal'};
    const name=`alias-ready-${run.id}-${run.run_attempt}-${consumer.id}-${consumer.run_attempt}`;
    for(const a of (await io.artifacts(consumer.id)).filter(a=>a.name===name&&!a.expired)){
      boundArtifact(a,consumer);
      const receipt=await io.receipt(a,'alias-ready.json');
      validateAlias(receipt,scoped,consumer,childJobs);provedAlias=true;aliasArtifacts.push(a);
    }
  }
  if(!provedAlias)return {skip:'no-completed-alias-install-proof'};
  const selected=artifacts.filter(a=>!a.expired&&allowedSourceArtifact(a.name,source,manifest.targets.map(t=>t.triple)));
  for(const a of selected)boundArtifact(a,run);
  const all=[...selected,...aliasArtifacts];
  const finished=Math.max(timestamp(run.updated_at),timestamp(release.published_at),...jobs.map(j=>timestamp(j.completed_at||run.updated_at)),...consumers.map(r=>timestamp(r.updated_at)),...all.map(a=>timestamp(a.created_at)));
  if(now-finished<3600_000)return {skip:'one-hour-after-consumers-not-reached',eligible_at:new Date(finished+3600_000).toISOString()};
  // Keep proof until the payloads are gone. A partial failure leaves receipts
  // intact where possible; subsequent invocations inventory again, never retry
  // an uncertain DELETE blindly.
  const payload=selected.filter(a=>a.id!==ready[0].id);
  return {run,source,scoped,release,tag,consumers,finished,artifacts:[...payload,...aliasArtifacts,ready[0]],preserved:artifacts.filter(a=>!all.some(x=>x.id===a.id)).map(a=>({id:a.id,name:a.name}))};
}
export async function executeCleanup(io,plan,{apply=false,now=()=>Date.now(),audit=()=>{}}={}){
  if(plan.skip){audit(plan);return [];}
  const deleted=[];
  for(const expected of plan.artifacts){
    // Recheck the ENTIRE source and every consumer before EACH deletion. In
    // particular, child completion alone cannot erase a receipt awaitAlias is
    // still downloading in the live parent Release.
    const current=await io.run(plan.run.id),consumers=await io.consumers(plan.run.created_at);
    if(!workflow(current,RELEASE)||consumers.some(r=>!workflow(r,ALIAS))||JSON.stringify(runStamp(current))!==JSON.stringify(runStamp(plan.run))||!terminal(current)||current.conclusion!=='success'||consumers.some(r=>!terminal(r))||JSON.stringify(consumers.map(runStamp).sort())!==JSON.stringify(plan.consumers.map(runStamp).sort())||now()-plan.finished<3600_000)throw Error('Consumption fence changed; cleanup stopped');
    requirePublished(await io.release(plan.source.release_id),plan.scoped,await io.tag(`v${plan.source.version}`));
    const actual=await io.artifact(expected.id);
    if(actual===null){audit({action:'already-absent',id:expected.id});continue;}
    if(actual.id!==expected.id||actual.name!==expected.name||actual.digest!==expected.digest||actual.size_in_bytes!==expected.size_in_bytes||actual.workflow_run?.id!==expected.workflow_run.id||actual.workflow_run?.head_sha!==expected.workflow_run.head_sha)throw Error('Artifact changed; cleanup stopped');
    audit({action:apply?'delete':'would-delete',run:plan.run.id,attempt:plan.run.run_attempt,release:plan.source.version,id:actual.id,name:actual.name,bytes:actual.size_in_bytes,digest:actual.digest});
    if(apply){await io.deleteArtifact(actual.id);if(await io.artifact(actual.id)!==null)throw Error('DELETE not verified absent; inspect before retrying');deleted.push(actual.id);}
  }
  return deleted;
}

export function githubAdapter(repository=process.env.GITHUB_REPOSITORY,{transport}={}){
  const command=transport||((args,options={})=>execFileSync('gh',args,{encoding:'utf8',timeout:30000,maxBuffer:16*1024*1024,...options}));
  const api=p=>JSON.parse(command(['api',p]));
  const pages=p=>JSON.parse(command(['api','--paginate','--slurp',p]));
  const base=`repos/${repository}`;
  const adapter={repository,
    run:id=>api(`${base}/actions/runs/${id}`),
    jobs:(id,attempt)=>pages(`${base}/actions/runs/${id}/attempts/${attempt}/jobs?per_page=100`).flatMap(p=>p.jobs),
    artifacts:id=>pages(`${base}/actions/runs/${id}/artifacts?per_page=100`).flatMap(p=>p.artifacts),
    consumers:created=>pages(`${base}/actions/workflows/npm-alias.yml/runs?per_page=100&created=%3E%3D${encodeURIComponent(created)}`).flatMap(p=>p.workflow_runs),
    release:id=>api(`${base}/releases/${id}`),
    tag:name=>{let o=api(`${base}/git/ref/tags/${name}`).object;for(let i=0;o?.type==='tag'&&i<5;i++)o=api(`${base}/git/tags/${o.sha}`).object;return o;},
    artifact:id=>{try{return api(`${base}/actions/artifacts/${id}`);}catch(e){if(String(e.stderr).includes('(HTTP 404)'))return null;throw e;}},
    deleteArtifact:id=>{command(['api','--method','DELETE',`${base}/actions/artifacts/${id}`]);},
  };
  // Archive contents are data only: exactly one bounded JSON file, never an
  // extracted/executed checkout, script, or path supplied by the artifact.
  adapter.receipt=(artifact,name)=>{
    if(artifact.size_in_bytes>128*1024)throw Error('Receipt ZIP too large');
    const temp=mkdtempSync(path.join(process.env.RUNNER_TEMP||tmpdir(),'release-cleanup-'));
    try{
      const zip=path.join(temp,'receipt.zip'),bytes=command(['api',`${base}/actions/artifacts/${artifact.id}/zip`],{encoding:'buffer',maxBuffer:128*1024});
      if(createHash('sha256').update(bytes).digest('hex')!==artifact.digest.slice(7))throw Error('Receipt ZIP digest mismatch');
      writeFileSync(zip,bytes);
      const names=execFileSync('unzip',['-Z1',zip],{encoding:'utf8',maxBuffer:4096}).trim().split('\n');
      if(names.length!==1||names[0]!==name)throw Error('Unexpected receipt ZIP inventory');
      return JSON.parse(execFileSync('unzip',['-p',zip,name],{encoding:'utf8',maxBuffer:1024*1024}));
    }finally{rmSync(temp,{recursive:true,force:true});}
  };
  return adapter;
}
export async function main(){
  const apply=process.argv.includes('--apply');
  if(process.argv.slice(2).some(a=>!['--apply','--dry-run'].includes(a))||process.argv.includes('--apply')&&process.argv.includes('--dry-run'))throw Error('Use --dry-run or --apply');
  const io=githubAdapter();if(io.repository!==REPOSITORY)throw Error('Repository scope refused');
  const manifest=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url)));
  const since=new Date(Date.now()-48*3600_000).toISOString();
  const runs=JSON.parse(execFileSync('gh',['api','--paginate','--slurp',`repos/${REPOSITORY}/actions/workflows/release.yml/runs?status=completed&per_page=100&created=%3E%3D${encodeURIComponent(since)}`],{encoding:'utf8',maxBuffer:16*1024*1024})).flatMap(p=>p.workflow_runs);
  const audit=value=>{const line=JSON.stringify(value);console.log(line);if(process.env.GITHUB_STEP_SUMMARY)appendFileSync(process.env.GITHUB_STEP_SUMMARY,`\n\`\`\`json\n${line}\n\`\`\`\n`);};
  for(const run of runs){try{const plan=await planCleanup(io,run.id,manifest);audit({mode:apply?'apply':'dry-run',source_run:run.id,skip:plan.skip||null,preserved:plan.preserved||[]});await executeCleanup(io,plan,{apply,audit});}catch(error){audit({source_run:run.id,error:error.message});throw error;}}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(e=>{console.error(e.message);process.exitCode=1;});
