// Protocol 2: npm acceptance is the write barrier; propagation/install is read-only.
import {appendFileSync,readFileSync} from 'node:fs';
import {packPackage, publishAcceptedPackage, readExpectedPacks} from './registry-publication.mjs';
import {RELEASE_ARTIFACT_CLEANUP_POLICY, validateSource, validateScopedPayload,
  packIdentity, assertSourceRun, assertActive, assertDraft, assertTag, selectRelease,
  api, pages, output, artifact, command, manifest, read, write, digest, sleep,
  verifyPackages, publicInstall} from './release-publication.mjs';
import {readdirSync, statSync} from 'node:fs';
import path from 'node:path';
import {checkVersionFence,checkReservationFence,bindFenceNotes,persistVersionFence} from './publication-fence.mjs';
const ALIAS = '.github/workflows/npm-alias.yml';
export const scopedAcceptedName = s => `scoped-accepted-${s.run_id}-${s.run_attempt}`;
export const aliasAcceptedName = (s, r) => `alias-accepted-${s.run_id}-${s.run_attempt}-${r.id}-${r.run_attempt}`;
const same = (a,b) => JSON.stringify(a) === JSON.stringify(b);
const id = v => /^[1-9]\d*$/.test(String(v));
const instant = v => typeof v === 'string' && Number.isFinite(Date.parse(v));

export function validateAcceptance(proof, expected) {
  if (proof?.schema !== 1 || proof.state !== 'accepted' || !instant(proof.accepted_at) ||
      !same(packIdentity(proof), packIdentity(expected)) ||
      !['npm-exit-zero', 'verified-public-bytes'].includes(proof.evidence) ||
      (proof.evidence === 'npm-exit-zero' && (proof.exit_code !== 0 || proof.signal !== null))) {
    throw Error('Missing exact successful npm acceptance');
  }
  return proof;
}
export function validateAcceptedScoped(receipt, m) {
  if (receipt?.schema !== 2 || receipt.kind !== 'scoped-accepted' || receipt.state !== 'accepted') throw Error('Invalid accepted scoped receipt');
  validateScopedPayload(receipt, m);
  if(receipt.source.recovery)throw Error('Historical recovery remains on protocol 1');
  if (!Array.isArray(receipt.acceptances) || receipt.acceptances.length !== receipt.packages.length ||
      new Set(receipt.acceptances.map(p => p.name)).size !== receipt.packages.length) throw Error('Incomplete npm acceptance inventory');
  for (const expected of receipt.packages) validateAcceptance(receipt.acceptances.find(p => p.name === expected.name), expected);
  if (receipt.install !== undefined || receipt.verified_at !== undefined) throw Error('Acceptance cannot claim installation verification');
  return receipt;
}
export function validateAcceptedAlias(receipt, scoped, run, jobs) {
  if (receipt?.schema !== 2 || receipt.kind !== 'alias-accepted' || receipt.state !== 'accepted' ||
      !same(receipt.source, scoped.source) || !same(receipt.scoped_packages, scoped.packages) ||
      receipt.alias?.name !== 'rsrs-cli' || receipt.alias?.version !== scoped.source.version ||
      !/^sha512-[A-Za-z0-9+/]{86}==$/.test(receipt.alias?.integrity || '') || !/^[a-f0-9]{40}$/.test(receipt.alias?.shasum || '') ||
      !same(receipt.dependencies, {'@rsrsai/cli': scoped.source.version}) ||
      receipt.publisher?.workflow !== ALIAS || String(receipt.publisher.run_id) !== String(run.id) ||
      Number(receipt.publisher.run_attempt) !== Number(run.run_attempt) || run.path !== ALIAS ||
      run.event !== 'workflow_run' || run.head_repository?.full_name !== scoped.source.repository ||
      !jobs.some(j => j.name === 'publish-integrated' && j.status === 'completed' && j.conclusion === 'success') ||
      receipt.install !== undefined || receipt.verified_at !== undefined) throw Error('Alias acceptance/publisher binding mismatch');
  validateAcceptance(receipt.acceptance, receipt.alias);
  return receipt;
}
// This validator is read-only. Write paths continue to call assertActive unchanged.
export function assertCompletedSource(run, source) {
  validateSource(source);
  if (String(run.id) !== String(source.run_id) || Number(run.run_attempt) !== Number(source.run_attempt) ||
      run.path !== source.workflow || run.head_repository?.full_name !== source.repository ||
      !['push','workflow_dispatch'].includes(run.event) || run.status !== 'completed' || !run.conclusion || source.recovery) {
    throw Error('Background verification requires the exact terminal Release attempt');
  }
}
export function validateVerified(receipt, scoped, alias) {
  if (receipt?.schema !== 2 || receipt.kind !== 'publication-verified' || receipt.state !== 'verified' ||
      !same(receipt.source, scoped.source) || !same(receipt.packages, [...scoped.packages, alias.alias]) ||
      !same(receipt.alias_publisher, alias.publisher) || !instant(receipt.verified_at) ||
      receipt.install?.platform !== 'linux-x64-gnu' || receipt.install?.version !== scoped.source.version ||
      !scoped.binaries.some(b => b.package === '@rsrsai/linux-x64-gnu' && b.sha256 === receipt.install?.binary_sha256)) {
    throw Error('Missing exact public content/install verification');
  }
  return receipt;
}
export async function reconcilePriorSubmissions(journal, expected, verify = verifyPackages) {
  if (journal?.schema !== 2 || !Array.isArray(journal.submissions)) throw Error('Invalid prior submission journal');
  const acceptances=[];
  for (const event of journal.submissions) {
    const match = expected.find(p => p.name === event.package?.name && p.version === event.package?.version);
    if (!match) continue; // A different immutable version cannot be replayed by this batch.
    if (!same(packIdentity(match),packIdentity(event.package))) throw Error('Prior submission content changed');
    if (event.state === 'accepted') acceptances.push(validateAcceptance(event.package, match));
    else if (event.state === 'unknown') {
      await verify([match]); // Read-only; never another npm publish.
      acceptances.push({...packIdentity(match),schema:1,state:'accepted',evidence:'verified-public-bytes',accepted_at:new Date().toISOString()});
    }
    else throw Error('Invalid prior submission state');
  }
  return acceptances;
}
export function assertSubmissionActive() {
  const repo=process.env.GITHUB_REPOSITORY, runId=process.env.GITHUB_RUN_ID, attempt=process.env.GITHUB_RUN_ATTEMPT;
  if(repo!=='risense-ai/respire-cli' || !id(runId) || !id(attempt))throw Error('Invalid submission authority');
  const run=api(`repos/${repo}/actions/runs/${runId}`);
  if(String(run.id)!==runId || Number(run.run_attempt)!==Number(attempt) || run.status!=='in_progress' ||
    run.path!=='.github/workflows/release.yml' || run.head_repository?.full_name!==repo || !['push','workflow_dispatch'].includes(run.event))throw Error('Submission source attempt is inactive or stale');
}
async function guardAccepted() {
  const repo = process.env.GITHUB_REPOSITORY, runId = process.env.GITHUB_RUN_ID, attempt = Number(process.env.GITHUB_RUN_ATTEMPT);
  if(repo!=='risense-ai/respire-cli' || !id(runId) || !id(attempt)) throw Error('Invalid submission run');
  assertSubmissionActive();
  checkVersionFence(); // Includes other run IDs and survives Actions artifact expiry.
  const expected = readExpectedPacks('npm/dist',manifest(),process.env.CLI_VERSION).map(packIdentity);
  const acceptances=[];
  for(let previous=1;previous<attempt;previous++) {
    const jobs=pages(`repos/${repo}/actions/runs/${runId}/attempts/${previous}/jobs?per_page=100`).flatMap(p=>p.jobs);
    const crossed=jobs.some(j=>j.name==='publish' && j.steps?.some(s=>s.name==='Publish npm using Trusted Publishing' && s.conclusion!=='skipped' && s.started_at));
    if(!crossed) continue;
    const journal=artifact(runId,`npm-submissions-${runId}-${previous}`,repo);
    if(!journal || String(journal.run_id)!==runId || Number(journal.run_attempt)!==previous) throw Error('Prior submission journal unavailable; inspect before retrying publication');
    acceptances.push(...await reconcilePriorSubmissions(journal,expected));
  }
  persistVersionFence(expected); // Durable intent precedes every possible scoped/alias npm write.
  write('prior-scoped-acceptances.json',{run_id:runId,run_attempt:attempt,acceptances});
}
async function scopedAccepted() {
  const m = manifest(), sha = command('git', ['rev-parse','HEAD']).trim();
  if (sha !== process.env.CLI_SHA || m.cliVersion !== process.env.CLI_VERSION) throw Error('Checkout/version differs from release plan');
  const release = selectRelease(pages(`repos/${process.env.GITHUB_REPOSITORY}/releases?per_page=100`), m.cliVersion);
  const source = validateSource({repository: process.env.GITHUB_REPOSITORY, workflow: '.github/workflows/release.yml',
    run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT, sha,
    version: m.cliVersion, channel: process.env.CLI_CHANNEL, release_id: release.id});
  assertActive(source);
  const submissions = read('scoped-submissions.json');
  if (submissions.schema !== 2 || submissions.state !== 'accepted' || String(submissions.run_id) !== String(source.run_id) ||
      Number(submissions.run_attempt) !== Number(source.run_attempt)) throw Error('Submissions belong to another attempt');
  const packages = readExpectedPacks('npm/dist', m).map(packIdentity);
  const assets = readdirSync('release-assets').sort().map(name => ({name, size: statSync(path.join('release-assets',name)).size, sha256: digest(path.join('release-assets',name))}));
  const binaries = m.targets.map(t => {
    const b = read(`release-assets/cli-build-${t.triple}.json`);
    if (b.git_sha !== sha || b.version !== m.cliVersion || b.target !== t.triple) throw Error('Build metadata source mismatch');
    return {package:t.pkg,target:t.triple,file:b.binary_file,sha256:b.binary_sha256};
  });
  const receipt = validateAcceptedScoped({schema:2,kind:'scoped-accepted',state:'accepted',source,packages,assets,binaries,
    cleanup_policy:RELEASE_ARTIFACT_CLEANUP_POLICY,acceptances:submissions.packages.map(p=>p.acceptance)},m);
  assertActive(source); assertDraft(api(`repos/${source.repository}/releases/${source.release_id}`),receipt); assertTag(source);
  write('scoped-accepted.json',receipt);
}
export function acceptedScopedOutput(receipt, run, attempt) {
  if (String(receipt.source.run_id) !== String(run.id) || Number(receipt.source.run_attempt) !== Number(attempt)) throw Error('Receipt does not belong to source event');
  assertSourceRun(run,receipt.source);
  return {eligible:'true',sha:receipt.source.sha,product_sha:receipt.source.sha,version:receipt.source.version,
    protocol:'2',artifact:scopedAcceptedName(receipt.source),file:'scoped-accepted.json'};
}
async function publishAliasAccepted() {
  const raw = read('scoped-accepted.json');
  const source = raw.source;
  const journal = state => write('alias-submissions.json',{schema:2,source,run_id:process.env.GITHUB_RUN_ID,
    run_attempt:process.env.GITHUB_RUN_ATTEMPT,submissions:state?[state]:[]});
  journal(); // No write has occurred; preflight failures must remain recoverable.
  const scoped = validateAcceptedScoped(raw,manifest());
  if (command('git',['rev-parse','HEAD']).trim() !== source.sha || String(source.run_id) !== process.env.SOURCE_RUN ||
      Number(source.run_attempt) !== Number(process.env.SOURCE_ATTEMPT)) throw Error('Pinned alias checkout/source mismatch');
  assertActive(source);
  command('node',['npm/scripts/pack-alias.mjs','--version',source.version]);
  const pkg = JSON.parse(readFileSync('npm/dist/rsrs-cli/package.json','utf8'));
  if (!same(pkg.dependencies,{'@rsrsai/cli':source.version})) throw Error('Local alias dependency mismatch');
  const packed = packPackage('npm/dist/rsrs-cli',process.env.RUNNER_TEMP);
  const expected = packIdentity(packed);
  if (expected.name !== 'rsrs-cli' || expected.version !== source.version) throw Error('Alias pack identity mismatch');
  // The existing alias lock serializes writers, including duplicate wake-ups.
  // Reconcile earlier interrupted writers for this source before any new write.
  const created = assertActive(source).created_at;
  const priorRuns = pages(`repos/${source.repository}/actions/workflows/npm-alias.yml/runs?event=workflow_run&per_page=100&created=%3E%3D${encodeURIComponent(created)}`).flatMap(p=>p.workflow_runs);
  const knownAcceptances=[];
  for(const prior of priorRuns) {
    for(let attempt=1;attempt<=Number(prior.run_attempt);attempt++) {
      if(String(prior.id)===process.env.GITHUB_RUN_ID && attempt>=Number(process.env.GITHUB_RUN_ATTEMPT)) continue;
      const journalEntries=pages(`repos/${source.repository}/actions/runs/${prior.id}/artifacts?per_page=100`).flatMap(p=>p.artifacts)
        .filter(a=>new RegExp(`^alias-submissions-[1-9][0-9]*-[1-9][0-9]*-${prior.id}-${attempt}$`).test(a.name));
      if(journalEntries.length>1)throw Error('Duplicate alias submission journals');
      const entry=journalEntries[0], journal=entry?artifact(prior.id,entry.name,source.repository):null;
      if(journal) {
        validateSource(journal.source);
        if(entry.name!==`alias-submissions-${journal.source.run_id}-${journal.source.run_attempt}-${prior.id}-${attempt}` ||
          String(journal.run_id)!==String(prior.id) || Number(journal.run_attempt)!==attempt) throw Error('Foreign alias submission journal');
        knownAcceptances.push(...await reconcilePriorSubmissions(journal,[expected]));
      } else {
        const jobs=pages(`repos/${source.repository}/actions/runs/${prior.id}/attempts/${attempt}/jobs?per_page=100`).flatMap(p=>p.jobs);
        if(jobs.some(j=>j.name==='publish-integrated' && j.steps?.some(s=>s.name==='Publish the matching short entry (legacy also verifies installation)' && s.started_at && s.conclusion!=='skipped'))) {
          // A matching accepted receipt is also a durable acknowledgement.
          // Without a journal or receipt, an interrupted writer is ambiguous.
          const bound=artifact(prior.id,aliasAcceptedName(source,{id:prior.id,run_attempt:attempt}),source.repository);
          if(bound) {validateAcceptedAlias(bound,scoped,{...prior,run_attempt:attempt},jobs);knownAcceptances.push(bound.acceptance);}
          else throw Error('Earlier alias writer has no durable outcome journal; inspect before retrying');
        }
      }
    }
  }
  assertActive(source); // No public propagation wait and no replay around this write.
  const result = await publishAcceptedPackage('npm/dist/rsrs-cli',{...expected,dependencies:pkg.dependencies},source.channel,
    {knownAcceptances,onSubmission:()=>{assertActive(source);journal({state:'unknown',package:expected});}});
  journal({state:'accepted',package:result.acceptance});
  validateAcceptance(result.acceptance,expected);
  write('alias-accepted.json',{schema:2,kind:'alias-accepted',state:'accepted',source,scoped_packages:scoped.packages,
    alias:expected,dependencies:pkg.dependencies,acceptance:result.acceptance,
    publisher:{workflow:ALIAS,run_id:process.env.GITHUB_RUN_ID,run_attempt:process.env.GITHUB_RUN_ATTEMPT}});
}
export async function findAcceptedAlias(scoped, createdAt) {
  const source = scoped.source;
  const runs = pages(`repos/${source.repository}/actions/workflows/npm-alias.yml/runs?event=workflow_run&per_page=100&created=%3E%3D${encodeURIComponent(createdAt)}`).flatMap(p=>p.workflow_runs);
  for (const run of runs) {
    const jobs = pages(`repos/${source.repository}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`).flatMap(p=>p.jobs);
    if (!jobs.some(j=>j.name==='publish-integrated' && j.status==='completed' && j.conclusion==='success')) continue;
    const receipt = artifact(run.id,aliasAcceptedName(source,run),source.repository);
    if (!receipt) continue;
    validateAcceptedAlias(receipt,scoped,run,jobs);
    return {run,receipt};
  }
  return null;
}
async function awaitAliasAccepted() {
  const scoped = validateAcceptedScoped(read('scoped-accepted.json'),manifest()), source = scoped.source;
  const created = assertActive(source).created_at, deadline = Date.now()+20*60*1000;
  while(Date.now()<deadline) {
    assertActive(source);
    const found = await findAcceptedAlias(scoped,created);
    if(found) {
      assertActive(source); assertDraft(api(`repos/${source.repository}/releases/${source.release_id}`),scoped);
      write('publication-accepted.json',{schema:2,state:'accepted',source,alias_run:found.run.id,
        alias_attempt:found.run.run_attempt,alias_receipt:found.receipt,packages:[...scoped.packages,found.receipt.alias]});
      return;
    }
    await sleep(10000);
  }
  throw Error('Matching successful alias npm acceptance missing; release remains draft');
}
function finalizeAccepted() {
  const scoped = validateAcceptedScoped(read('scoped-accepted.json'),manifest()), complete = read('publication-accepted.json');
  const s = scoped.source;
  if (complete.schema!==2 || complete.state!=='accepted' || !same(complete.source,s) || !id(complete.alias_run) || !id(complete.alias_attempt) ||
      String(s.run_id)!==process.env.GITHUB_RUN_ID || Number(s.run_attempt)!==Number(process.env.GITHUB_RUN_ATTEMPT) ||
      !same(complete.packages,[...scoped.packages,complete.alias_receipt?.alias])) throw Error('Missing exact acceptance barrier');
  assertActive(s);
  const run = api(`repos/${s.repository}/actions/runs/${complete.alias_run}/attempts/${complete.alias_attempt}`);
  const jobs = pages(`repos/${s.repository}/actions/runs/${complete.alias_run}/attempts/${complete.alias_attempt}/jobs?per_page=100`).flatMap(p=>p.jobs);
  validateAcceptedAlias(complete.alias_receipt,scoped,run,jobs);
  assertDraft(api(`repos/${s.repository}/releases/${s.release_id}`),scoped); assertTag(s);
  const sourceRun=assertActive(s);
  command('gh',['release','edit',`v${s.version}`,'--repo',s.repository,'--draft=false'],{stdio:'inherit'});
  // Confirm the read response after the write. A transport ambiguity never
  // becomes success and never causes another release edit here.
  const published=api(`repos/${s.repository}/releases/${s.release_id}`);
  if(published.draft!==false || !published.published_at)throw Error('Release publication result not confirmed; inspect without replaying');
  assertDraft({...published,draft:true},scoped);assertTag(s,{requireExisting:true});
  const allNpmAccepted=Math.max(...scoped.acceptances.map(p=>Date.parse(p.accepted_at)),Date.parse(complete.alias_receipt.acceptance.accepted_at));
  const acceptedAt=Math.max(allNpmAccepted,Date.parse(published.published_at));
  write('publication-accepted.json',{...complete,accepted_at:new Date(acceptedAt).toISOString(),
    release_published_at:published.published_at,all_npm_accepted_at:new Date(allNpmAccepted).toISOString(),
    source_run_created_at:sourceRun.created_at,trigger_to_accepted_seconds:(acceptedAt-Date.parse(sourceRun.created_at))/1000,
    public_verification:'pending'});
  const summary=`Release v${s.version} public; all ${complete.packages.length} npm submissions accepted. Public propagation/install verification pending. Trigger to acceptance: ${(acceptedAt-Date.parse(sourceRun.created_at))/1000}s.\n`;
  console.log(summary);
  if(process.env.GITHUB_STEP_SUMMARY)appendFileSync(process.env.GITHUB_STEP_SUMMARY,summary);
}
async function verifyAccepted() {
  const repo = process.env.GITHUB_REPOSITORY, runId = process.env.SOURCE_RUN, attempt = process.env.SOURCE_ATTEMPT;
  if(repo!=='risense-ai/respire-cli' || !id(runId) || !id(attempt)) throw Error('Invalid verification source event');
  const scoped = artifact(runId,scopedAcceptedName({run_id:runId,run_attempt:attempt}),repo);
  if(!scoped) { output({eligible:'false'}); return; } // Legacy workflow has its existing synchronous proof.
  validateAcceptedScoped(scoped,manifest());
  if(String(scoped.source.run_id)!==runId || Number(scoped.source.run_attempt)!==Number(attempt)) throw Error('Wrong verification source');
  const s = scoped.source;
  const assertCurrent = () => {
    const run = api(`repos/${repo}/actions/runs/${runId}/attempts/${attempt}`);
    assertCompletedSource(run,s);
    const release = api(`repos/${repo}/releases/${s.release_id}`);
    if(release.draft!==false || !release.published_at || release.tag_name!==`v${s.version}` || release.target_commitish!==s.sha ||
      release.prerelease!==(s.channel==='dev')) throw Error('Exact public Release required');
    assertDraft({...release,draft:true},scoped); assertTag(s,{requireExisting:true});
    return run;
  };
  const run = assertCurrent(), found = await findAcceptedAlias(scoped,run.created_at);
  if(!found) throw Error('Accepted alias publisher proof missing');
  const packages = [...scoped.packages,found.receipt.alias];
  await verifyPackages(packages.map(p=>p.name==='rsrs-cli'?{...p,dependencies:found.receipt.dependencies}:p),{requireInstallIndex:true,timeoutMs:60*60*1000});
  const install = await publicInstall(scoped,found.receipt.alias,assertCurrent);
  assertCurrent();
  const verified = validateVerified({schema:2,kind:'publication-verified',state:'verified',source:s,packages,
    alias_publisher:found.receipt.publisher,verified_at:new Date().toISOString(),install},scoped,found.receipt);
  write('publication-verified.json',verified); output({eligible:'true'});
}
export async function main(action) {
  if(action==='check-fence-accepted')return checkVersionFence();
  if(action==='guard-reservation-accepted')return checkReservationFence();
  if(action==='bind-fence-notes-accepted')return bindFenceNotes();
  if(action==='guard-accepted') return guardAccepted();
  if(action==='scoped-accepted') return scopedAccepted();
  if(action==='publish-alias-accepted') return publishAliasAccepted();
  if(action==='await-alias-accepted') return awaitAliasAccepted();
  if(action==='finalize-accepted') return finalizeAccepted();
  if(action==='verify-accepted') return verifyAccepted();
  throw Error('Unknown acceptance action');
}
