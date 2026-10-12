import {publishPackage} from './registry-publication.mjs';

// Only platform propagation overlaps. The umbrella remains behind a complete
// barrier, and the workflow's existing publication lock still owns this batch.
export async function publishScopedPackages(expected, umbrellaName, tag, options = {}) {
  const names = expected.map(receipt => receipt.name);
  if (new Set(names).size !== names.length) throw new Error('Duplicate publication package');
  const umbrella = expected.find(receipt => receipt.name === umbrellaName);
  const platforms = expected.filter(receipt => receipt.name !== umbrellaName);
  if (!umbrella || !platforms.length || platforms.some(receipt => receipt.version !== umbrella.version)) {
    throw new Error('Incomplete or mixed-version scoped publication batch');
  }
  const publish = options.publishImpl || publishPackage;
  const results = new Map();
  let next = 0;
  let failed = false;
  const errors = [];
  const worker = async () => {
    while (!failed && next < platforms.length) {
      const receipt = platforms[next++];
      try {
        results.set(receipt.name, await publish(receipt.dir, receipt, tag));
      } catch (error) {
        failed = true;
        errors.push(error);
      }
    }
  };
  // Wait for every in-flight operation even on failure: no orphaned publication
  // or temporary-file cleanup after the job reports completion. No retries here.
  await Promise.all(Array.from({length: Math.min(4, platforms.length)}, worker));
  if (errors.length) throw new AggregateError(errors, 'Platform publication failed; umbrella was not published');
  results.set(umbrella.name, await publish(umbrella.dir, umbrella, tag));
  return expected.map(receipt => ({...results.get(receipt.name), name: receipt.name}));
}
