"""Freeze and join one-source Apple Silicon historical upgrade evidence."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re

from published_upgrade_evidence import validate_upgrade_result
from published_upgrade_policy import DATABASE_DEV_CHECKPOINTS


TARGET = 'aarch64-apple-darwin'
SUMMARY = 'published-upgrades.json'
RESULT = 'results/real-account-return-verification.json'
INVENTORY_KEYS = ('published_formal_sources', 'database_dev_checkpoints',
                  'registry_formal_versions', 'additional_draft_baselines')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    return json.loads(path.read_bytes())


def write_json(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(value, indent=2) + '\n')


def run_identity():
    run = {key: os.environ[name] for key, name in (
        ('repository', 'GITHUB_REPOSITORY'), ('run_id', 'GITHUB_RUN_ID'),
        ('run_attempt', 'GITHUB_RUN_ATTEMPT'), ('workflow_sha', 'GITHUB_SHA'),
    )}
    require(all(re.fullmatch(r'[1-9][0-9]*', run[key]) for key in ('run_id', 'run_attempt'))
            and re.fullmatch(r'[0-9a-f]{40}', run['workflow_sha']), 'Invalid GitHub run identity')
    return run


def check_run_id():
    value = os.environ['MACOS_UPGRADE_CHECK_RUN_ID']
    require(re.fullmatch(r'[1-9][0-9]*', value), 'Invalid Apple Silicon check run ID')
    return value


def expected_tags(inventory):
    formal = inventory['published_formal_sources']
    require(bool(formal) and len(formal) == len(set(formal))
            and all(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag)
                    and tuple(map(int, tag[1:].split('.'))) >= (1, 0, 6) for tag in formal)
            and set(inventory['registry_formal_versions']) <= {tag[1:] for tag in formal}
            and inventory['database_dev_checkpoints'] == DATABASE_DEV_CHECKPOINTS
            and inventory['additional_draft_baselines'] == [], 'Invalid full historical inventory')
    return sorted(set(formal) | DATABASE_DEV_CHECKPOINTS.keys())


def validate_identity(identity):
    digests = {'cli_sha256', 'runtime_sha256', 'manifest_sha256', 'bundle_sha256'}
    require(set(identity) == digests | {'runtime_version', 'model_key', 'fixture_sha'}
            and all(re.fullmatch(r'[0-9a-f]{64}', identity[key]) for key in digests)
            and re.fullmatch(r'[0-9a-f]{40}', identity['fixture_sha'])
            and re.fullmatch(r'native-model-v1-[0-9a-f]{64}', identity['model_key'])
            and isinstance(identity['runtime_version'], str) and identity['runtime_version'],
            'Invalid plan byte identity')


def make_plan(report, sources, releases, identity):
    validate_identity(identity)
    inventory = {key: report[key] for key in INVENTORY_KEYS}
    tags = expected_tags(inventory)
    require(sorted(sources) == tags, 'Full historical inventory differs')
    counts = Counter(item['tag_name'] for item in releases)
    names = {f'rsrs-{TARGET}', f'rsrs-{TARGET}-runtime.tar.gz', f'cli-build-{TARGET}.json'}
    inputs = {}
    for tag in tags:
        release = sources[tag]
        require(counts[tag] == 1 and type(release['id']) is int and release['id'] > 0,
                'Invalid historical release identity: ' + tag)
        assets = [asset for asset in release['assets'] if asset['name'] in names]
        require(len(assets) == len(names) and {asset['name'] for asset in assets} == names,
                'Missing or duplicate historical assets: ' + tag)
        require(all(type(asset['id']) is int and asset['id'] > 0 and
                    re.fullmatch(r'sha256:[0-9a-f]{64}', asset.get('digest') or '')
                    for asset in assets) and len({asset['id'] for asset in assets}) == len(names),
                'Invalid historical asset identity: ' + tag)
        inputs[tag] = {'release_id': release['id'], 'assets': {
            asset['name']: {'id': asset['id'], 'digest': asset['digest']}
            for asset in sorted(assets, key=lambda item: item['name'])}}
    return {'schema': 1, 'target': TARGET, 'run': run_identity(),
            'identity': identity, 'inventory': inventory, 'inputs': inputs}


def file_digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_shard_process(check, plan, tag):
    historical = plan['inputs'][tag]['assets'][f'rsrs-{TARGET}']['digest']
    require(check.get('seed_source') == tag and 'sha256:' + check.get('seed_sha256', '') == historical,
            'Historical seed evidence differs from the plan: ' + tag)
    require(check.get('runtime_installed_after_legacy_data') is True,
            'Runtime installation order was not proved: ' + tag)
    identity = plan['identity']
    for receipt in check['runtime_identity_receipts']:
        require(receipt.get('image_sha256') == identity['runtime_sha256']
                and receipt.get('manifest_sha256') == identity['manifest_sha256']
                and receipt.get('bundle_sha256') == identity['bundle_sha256']
                and receipt.get('runtime_version') == identity['runtime_version']
                and all(type(receipt.get(key)) is int and receipt[key] > 0 for key in ('pid', 'generation'))
                and all(isinstance(receipt.get(key), str) and receipt[key] for key in (
                    'exe', 'process_start_id', 'installation_root', 'data_dir', 'account_id', 'instance_id'))
                and type(receipt.get('protocol_v')) is int and receipt['protocol_v'] == 1,
                'Actual Runtime process identity differs: ' + tag)


def merge(plan_path, shards, destination):
    require(__debug__, 'Historical evidence requires Python assertions')
    aggregate_check_run_id = check_run_id()
    plan_bytes = plan_path.read_bytes()
    plan = json.loads(plan_bytes)
    require(type(plan['schema']) is int and plan['schema'] == 1 and plan['target'] == TARGET
            and plan['run'] == run_identity(), 'Plan belongs to a different run, attempt or target')
    inventory = plan['inventory']
    tags = expected_tags(inventory)
    require(sorted(plan['inputs']) == tags, 'Plan sources differ from full inventory')
    require(sorted(entry.name for entry in shards.iterdir()) == tags,
            'Missing, duplicate or unexpected shard directories')
    identity = plan['identity']
    validate_identity(identity)
    plan_digest = hashlib.sha256(plan_bytes).hexdigest()
    rows, evidence, files = [], [], []
    seen_digests = set()
    seen_checks = {aggregate_check_run_id}
    for tag in tags:
        folder = shards / tag
        shard = read_json(folder / SUMMARY)
        require(all(shard[key] == inventory[key] for key in INVENTORY_KEYS)
                and shard['target'] == TARGET and shard['profile'] == 'full'
                and shard['upgrade_contract'] == 'standalone-v1'
                and shard['candidate_sha256'] == identity['cli_sha256']
                and shard['diagnostic_sources'] == shard['selected_sources'] == [tag]
                and shard['passed'] is True and shard['post_upgrade_sync_checked'] is True
                and shard['full_coverage'] is False and shard['all_published_sources_covered'] is False
                and shard['first_platform_release'] is False,
                'Shard scope, identity or outcome differs: ' + tag)
        relative = Path(tag) / RESULT
        path = folder / relative
        require(list(folder.rglob(Path(RESULT).name)) == [path],
                'Missing or duplicate process report: ' + tag)
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        require(digest not in seen_digests, 'Process evidence was reused across sources: ' + tag)
        seen_digests.add(digest)
        producer = shard['macos_shard']['check_run_id']
        require(re.fullmatch(r'[1-9][0-9]*', producer) and producer not in seen_checks,
                'Missing or reused shard check run ID: ' + tag)
        seen_checks.add(producer)
        binding = {'source': tag, 'plan_sha256': plan_digest, 'identity': identity,
                   'process_report_sha256': digest, 'check_run_id': producer}
        require(shard['macos_shard'] == binding, 'Shard evidence binding differs: ' + tag)
        checks = json.loads(payload)
        row = validate_upgrade_result(checks, tag=tag, formal=tag in inventory['published_formal_sources'],
                                      upgrade_contract='standalone-v1', candidate_sha256=identity['cli_sha256'],
                                      runtime_sha256=identity['runtime_sha256'], runtime_version=identity['runtime_version'],
                                      report_path=relative.as_posix())
        validate_shard_process(checks[0], plan, tag)
        require(len(shard['sources']) == 1 and {**shard['sources'][0], 'report': row['report']} == row,
                'Shard source summary differs from process evidence: ' + tag)
        rows.append(row)
        evidence.append({'source': tag, 'process_report_sha256': digest, 'check_run_id': producer})
        files.append((relative, payload))

    # Write the full summary last so an interrupted copy cannot produce one.
    destination.mkdir(parents=True)
    for relative, payload in files:
        path = destination / relative
        path.parent.mkdir(parents=True)
        path.write_bytes(payload)
    (destination / 'macos-shard-plan.json').write_bytes(plan_bytes)
    write_json(destination / SUMMARY, {
        **inventory, 'target': TARGET, 'profile': 'full', 'upgrade_contract': 'standalone-v1',
        'candidate_sha256': identity['cli_sha256'], 'selected_sources': tags, 'sources': rows,
        'passed': True, 'first_platform_release': False, 'post_upgrade_sync_checked': True,
        'full_coverage': True, 'all_published_sources_covered': True,
        'macos_shards': {'plan_sha256': plan_digest, 'run': plan['run'], 'identity': identity,
                         'check_run_id': aggregate_check_run_id, 'source_evidence': evidence},
    })


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path)
    parser.add_argument('shards', type=Path, help='One directory per exact source tag')
    parser.add_argument('output', type=Path, help='New directory for the merged evidence')
    args = parser.parse_args()
    merge(args.plan, args.shards, args.output)
