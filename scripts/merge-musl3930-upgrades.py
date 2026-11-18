"""One bounded merge: eleven original 385 results plus new v1.0.8. No product execution."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import types


def validator(commit):
    source = subprocess.check_output(['git', 'show', commit + ':scripts/test-published-upgrades.py'], text=True)
    function = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'verify_upgrade')
    start = next(i for i, n in enumerate(function.body) if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'check' for t in n.targets))
    body = function.body[start:]
    return compile(ast.fix_missing_locations(ast.Module(body=[ast.FunctionDef(
        name='verify_saved', args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
        body=body, decorator_list=[])], type_ignores=[])), commit + ':saved-source-validator', 'exec')


def merge(old, new, destination, fixture, runtime_sha, runtime_version):
    original = json.loads((old / 'published-upgrades.json').read_text())
    diagnostic = json.loads((new / 'published-upgrades.json').read_text())
    assert original['target'] == diagnostic['target'] == 'x86_64-unknown-linux-musl'
    assert original['candidate_sha256'] == diagnostic['candidate_sha256']
    assert diagnostic['diagnostic_sources'] == diagnostic['selected_sources'] == ['v1.0.8']
    assert diagnostic['passed'] is True and diagnostic['full_coverage'] is False
    assert diagnostic['all_published_sources_covered'] is False
    policy_source = subprocess.check_output(['git', 'show', '3930ba5:scripts/published_upgrade_policy.py'], text=True)
    policy = {}; exec(compile(policy_source, 'original-policy', 'exec'), policy)
    assert original['database_dev_checkpoints'] == diagnostic['database_dev_checkpoints'] == policy['DATABASE_DEV_CHECKPOINTS']
    selected = sorted(set(original['published_formal_sources']) | set(policy['DATABASE_DEV_CHECKPOINTS']))
    assert original['selected_sources'] == selected and len(selected) == 12 and 'v1.0.8' in selected
    assert diagnostic['published_formal_sources'] == original['published_formal_sources']
    assert original['additional_draft_baselines'] == diagnostic['additional_draft_baselines'] == []
    old_validator, new_validator = validator('385c3c9'), validator(fixture)
    assert subprocess.check_output(['git', 'rev-parse', fixture + ':scripts/test-published-upgrades.py']) == \
        subprocess.check_output(['git', 'rev-parse', '385c3c9:scripts/test-published-upgrades.py']), 'DB report contract changed'
    assert not destination.exists(); destination.mkdir(parents=True)
    rows, evidence = [], []
    for tag in selected:
        root, revision, code = (new, fixture, new_validator) if tag == 'v1.0.8' else (old, '385c3c9', old_validator)
        names = list(root.glob('**/' + tag + '/results/real-account-return-verification.json'))
        assert len(names) == 1, 'Missing/duplicate source result'
        saved = names[0].read_bytes(); checks = json.loads(saved)
        assert isinstance(checks, list) and len(checks) == 1
        result = destination / tag / 'results'; result.mkdir(parents=True)
        env = dict(checks=checks, tag=tag, args=types.SimpleNamespace(runtime_binary=True,
                   runtime_sha256=runtime_sha, runtime_version=runtime_version),
                   report=original, upgrade_contract='standalone-v1',
                   checkpoint_args=[tag] if tag in policy['DATABASE_DEV_CHECKPOINTS'] else [],
                   formal_sources=original['published_formal_sources'], result=result)
        exec(code, env); row = env['verify_saved']()
        assert row['passed'] is True
        row['report'] = tag + '/results/real-account-return-verification.json'
        shutil.copyfile(names[0], result / 'real-account-return-verification.json')
        assert (result / 'real-account-return-verification.json').read_bytes() == saved
        rows.append(row)
        evidence.append(dict(source=tag, contract='historical-385',
                             fixture_commit=subprocess.check_output(['git', 'rev-parse', revision], text=True).strip(),
                             validator_blob=subprocess.check_output(['git', 'rev-parse', revision + ':scripts/test-published-upgrades.py'], text=True).strip(),
                             report_sha256=hashlib.sha256(saved).hexdigest()))
    merged = {**original, 'sources': rows, 'passed': True, 'full_coverage': True,
              'all_published_sources_covered': True, 'post_upgrade_sync_checked': True,
              'source_evidence': evidence, 'composition': 'fixed-musl3930-11-plus-1'}
    (destination / 'published-upgrades.json').write_text(json.dumps(merged, indent=2) + '\n', encoding='utf-8')
    return evidence


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('old', type=Path); parser.add_argument('new', type=Path); parser.add_argument('destination', type=Path)
    parser.add_argument('fixture'); parser.add_argument('runtime_sha'); parser.add_argument('runtime_version')
    args = parser.parse_args()
    merge(args.old, args.new, args.destination, args.fixture, args.runtime_sha, args.runtime_version)
