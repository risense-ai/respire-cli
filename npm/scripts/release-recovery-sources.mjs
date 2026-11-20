import assert from 'node:assert/strict';

export const armRecoveryRun = '44718206331';

const sources = {
  [armRecoveryRun]: {sha: 'e5f36e0861b8f3615151c8db3a440711d5d14440', version: '2.0.0-dev.24'},
  '44276673815': {sha: '3930ba500b96a0c52eb7aa735b7ddb4117ad4e9f', version: '2.0.0-dev.19'},
  '44362424899': {sha: '0acf92481b29b69e6bf9536dc6a13b2c569c5abd', version: '2.0.0-dev.20'},
};

export function hasApprovedRecoveryProducer(part) {
  const runId = String(part.producer?.run_id);
  if (!Object.hasOwn(sources, runId)) return false;
  const source = sources[runId];
  return part.repository === 'risense-ai/respire-cli'
    && part.producer.run_attempt === 1
    && part.source_sha === source.sha
    && part.version === source.version;
}

export function approvedRecoveryProducer(runId) {
  const run_id = String(runId);
  assert.ok(Object.hasOwn(sources, run_id), 'Unapproved release candidate for recovery');
  return {
    repository: 'risense-ai/respire-cli',
    workflow: '.github/workflows/release.yml',
    run_id,
    run_attempt: 1,
    ...sources[run_id],
  };
}
