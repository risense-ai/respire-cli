"""One disposable AI diagnostic; never publish captured product output."""
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tarfile
import zipfile

REPOSITORY = Path(__file__).resolve().parent.parent
FIXED = REPOSITORY / 'scripts/fixtures/arm64-ai-native-20261118.json'
MANIFEST_HASH = '29dffa8d41d52070df33db4c916512a64429c943910c8b77074832e12653ac26'


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fixed():
    raw = FIXED.read_bytes()
    assert digest(raw) == MANIFEST_HASH, 'fixed_manifest_changed'
    return json.loads(raw)


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def git_file(commit, path):
    return subprocess.run(['git', 'show', commit + ':' + path], cwd=REPOSITORY,
        check=True, capture_output=True).stdout


def cli_node(source):
    cls = next(n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == 'Smoke')
    return next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'cli')


def project(spec, destination):
    name = 'scripts/dev-ai-inject-smoke.py'
    original = git_file(spec['fixture_source'], name)
    reviewed = git_file(spec['diagnostic_commit'], name)
    old, new = original.decode('utf-8'), reviewed.decode('utf-8')
    before, after = cli_node(old), cli_node(new)
    replacement = ''.join(new.splitlines(keepends=True)[after.lineno - 1:after.end_lineno])
    lines = old.splitlines(keepends=True)
    projected = (''.join(lines[:before.lineno - 1]) + replacement + ''.join(lines[before.end_lineno:])).encode()
    assert {key: digest(value) for key, value in (
        ('original', original), ('cli_method', replacement.encode()), ('projected', projected))} == spec['projection'], 'projection_changed'
    old_tree, new_tree = ast.parse(old), ast.parse(projected)
    # Removing only cli must leave the complete original business/cleanup AST unchanged.
    for tree in (old_tree, new_tree):
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Smoke')
        cls.body = [n for n in cls.body if not isinstance(n, ast.FunctionDef) or n.name != 'cli']
    assert ast.dump(old_tree) == ast.dump(new_tree), 'business_projection_changed'
    destination.mkdir()
    archive = subprocess.run(['git', 'archive', spec['fixture_source'], 'scripts', 'runtime-pin.json'],
        cwd=REPOSITORY, check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(destination, filter='data')
    (destination / name).write_bytes(projected)
    return projected


def api(path):
    return json.loads(subprocess.run(['gh', 'api', '--hostname', 'github.com', path],
        check=True, capture_output=True).stdout)


def prepare(root):
    spec = fixed()
    root.mkdir()
    project(spec, root / 'original-harness')
    cli = spec['cli']
    prefix = 'repos/' + cli['repository']
    run = api(prefix + '/actions/runs/' + str(cli['run_id']))
    assert (run['head_sha'], run['run_attempt'], run['path'], run['status'], run['event']) == (
        cli['sha'], 1, '.github/workflows/release.yml', 'completed', 'workflow_dispatch'), 'original_run_changed'
    job = api(prefix + '/actions/jobs/' + str(spec['build_job_id']))
    assert (job['run_id'], job['head_sha'], job['run_attempt'], job['conclusion'], job['name']) == (
        cli['run_id'], cli['sha'], 1, 'success', 'validate / Release (' + spec['target'] + ')'), 'build_job_changed'
    asset = spec['artifact']
    remote = api(prefix + '/actions/artifacts/' + str(asset['id']))
    assert (remote['name'], remote['size_in_bytes'], remote['digest'], remote['expired'],
        remote['workflow_run']['id'], remote['workflow_run']['head_sha']) == (
        asset['name'], asset['size'], 'sha256:' + asset['sha256'], False, cli['run_id'], cli['sha']), 'artifact_changed'
    assert job['started_at'] <= remote['created_at'] <= remote['updated_at'] <= job['completed_at'], 'artifact_job_binding_changed'
    payload = subprocess.run(['gh', 'api', '--hostname', 'github.com',
        prefix + '/actions/artifacts/' + str(asset['id']) + '/zip'], check=True, capture_output=True).stdout
    assert len(payload) == asset['size'] and digest(payload) == asset['sha256'], 'artifact_zip_changed'
    source = root / 'assets'
    (source / 'cli').mkdir(parents=True)
    (source / 'runtime').mkdir()
    names = {'cli-build-' + spec['target'] + '.json', 'rsrs-' + spec['target']}
    inventory = []
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        rows = archive.infolist()
        assert len(rows) == len(names) and {r.filename for r in rows} == names, 'artifact_inventory_changed'
        for row in rows:
            assert not row.is_dir() and not row.flag_bits & 1 and not stat.S_ISLNK(row.external_attr >> 16), 'artifact_entry_invalid'
            value = archive.read(row)
            (source / 'cli' / row.filename).write_bytes(value)
            inventory.append({'name': row.filename, 'size': len(value), 'sha256': digest(value)})
    binary = source / 'cli' / ('rsrs-' + spec['target'])
    assert digest(binary.read_bytes()) == spec['binary_sha256'], 'cli_binary_changed'
    metadata = json.loads((source / 'cli' / ('cli-build-' + spec['target'] + '.json')).read_bytes())
    assert str(metadata['producer']['run_id']) == str(cli['run_id']) and metadata['producer']['run_attempt'] == 1, 'cli_producer_changed'
    consumer = {'cli': {'repository': cli['repository'], 'source_sha': cli['sha'], 'version': cli['version'],
        'producer': {'run_id': cli['run_id'], 'run_attempt': 1}, 'assets': inventory}, 'runtime': spec['runtime']}
    write(root / 'consumer-input.json', consumer)
    write(root / 'provenance.json', {'schema': 1, 'kind': spec['kind'], 'diagnostic_only': True,
        'publication_reusable': False, 'full_acceptance': False, 'manifest_sha256': MANIFEST_HASH,
        'workflow_sha': os.environ.get('GITHUB_SHA'), 'run_id': os.environ.get('GITHUB_RUN_ID'),
        'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'), 'fixed': spec, 'cli_files': inventory})


def fixture(root):
    spec = fixed()
    entry = root / 'original-harness/scripts/dev-ai-inject-smoke.py'
    sys.path.insert(0, str(entry.parent))
    sys.argv = [str(entry), '--binary', str(root / 'consumed/rsrs'), '--binary-sha256', spec['binary_sha256'],
        '--version', spec['cli']['version'], '--source-sha', spec['cli']['sha'], '--root', str(root / 'ai')]
    try:
        return runpy.run_path(str(entry))['main']()
    except Exception as error:
        record = {'phase': 'fixture_bootstrap', 'error_type': type(error).__name__ if type(error).__name__ in
            ('RuntimeError', 'ValueError', 'KeyError', 'OSError', 'FileNotFoundError', 'TimeoutExpired') else 'Exception'}
        # An offline install can fail before Smoke/report exists. Retain its fixed diagnostic only.
        prefix = 'selected published Runtime offline install failed: exit '
        text = str(error)
        if isinstance(error, RuntimeError) and text.startswith(prefix) and '; diagnostic=' in text:
            value = json.loads(text.split('; diagnostic=', 1)[1])
            record['installer'] = {'exit_code': value.get('exit_code') if type(value.get('exit_code')) is int else None}
            for key, allowed in (('structured_reason', ('invalid_input', 'runtime_error', 'request_outcome_unknown')),
                    ('category', ('unclassified', 'owner_roots_mismatch')), ('envelope', ('invalid_json', 'non_object', 'object'))):
                record['installer'][key] = value.get(key) if value.get(key) in allowed else 'unknown'
        write(root / 'bootstrap.json', record)
        return 1


def execute(root):
    env = {key: value for key, value in os.environ.items() if key not in ('GH_TOKEN', 'GITHUB_TOKEN')}
    assert env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    assert sys.platform.startswith('linux') and os.uname().machine == 'aarch64'
    script = root / 'original-harness/scripts/dev-secret-service-keyring-selftest.py'
    command = ['dbus-run-session', '--', 'env', 'RSRS_SS_FIXTURE_BUS=private', sys.executable, str(script),
        '--root', str(root / 'credentials'), '--timeout', '1500', '--', sys.executable, str(Path(__file__).resolve()),
        'fixture', str(root)]
    # Captures stay in memory; product/traceback output is never printed or uploaded.
    result = subprocess.run(command, env=env, capture_output=True, timeout=1800)
    write(root / 'exit.json', {'exit_code': result.returncode})
    return result.returncode


def collect(root):
    output = root / 'safe-report'
    output.mkdir(exist_ok=True)
    if (root / 'provenance.json').is_file():
        write(output / 'provenance.json', json.loads((root / 'provenance.json').read_bytes()))
    if (root / 'bootstrap.json').is_file():
        write(output / 'bootstrap.json', json.loads((root / 'bootstrap.json').read_bytes()))
    result = {'diagnostic_only': True, 'report': 'absent'}
    if (root / 'exit.json').is_file():
        result.update(json.loads((root / 'exit.json').read_bytes()))
    path = root / 'ai/ai-inject-coverage.json'
    if path.is_file():
        report = json.loads(path.read_bytes())
        tree = ast.parse((root / 'original-harness/scripts/dev-ai-inject-smoke.py').read_bytes())
        fixed_failures = {n.args[1].value for n in ast.walk(tree) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and n.func.id == 'require' and len(n.args) == 2
            and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str)}
        fixed_failures.update(prefix + command for prefix in ('cli_failed_', 'cli_error_', 'cli_invalid_json_')
            for command in ('remember', 'model', 'doctor', 'show', 'prompt', 'inject', 'agent-config', 'root-create',
                'classify', 'tree-deepen', 'tree-cure', 'register'))
        required = ast.literal_eval(next(n.value for n in tree.body if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'REQUIRED' for t in n.targets)))
        result.update(report='present', status=report.get('status') if report.get('status') in ('passed', 'failed') else 'unknown',
            failure=report.get('failure') if report.get('failure') in fixed_failures else 'unclassified',
            passed_cases=[name for name in required if report.get('cases', {}).get(name, {}).get('passed') is True])
        value = report.get('cli_failure', {})
        result['cli_failure'] = {
            'exit_code': value.get('exit_code') if type(value.get('exit_code')) is int else None,
            'stage': value.get('stage') if value.get('stage') in ('process_exit', 'json_decode', 'envelope_validation') else 'unknown',
            'structured_reason': value.get('structured_reason') if value.get('structured_reason') in
                ('invalid_input', 'runtime_error', 'request_outcome_unknown') else 'unknown',
            'error_type': value.get('error_type') if value.get('error_type') in ('user', 'runtime', 'outcome_unknown') else 'unknown'}
        cleanup = report.get('cloud_cleanup', {})
        result['cleanup'] = {key: cleanup.get(key) is True for key in ('passed', 'self_purge_confirmed', 'old_token_rejected')}
        remaining = cleanup.get('remaining_users')
        result['cleanup']['remaining_user_count'] = len(remaining) if isinstance(remaining, list) else None
        result['provider_credential_cleanup_passed'] = report.get('provider_credential_cleanup', {}).get('passed') is True
    path = root / 'credentials/business-keyring-selftest.json'
    if path.is_file():
        wrapper = json.loads(path.read_bytes())
        result['credential_wrapper'] = {key: wrapper.get(key) is True for key in ('passed', 'business_passed',
            'credential_before_passed', 'credential_after_passed', 'business_credential_cleanup_passed')}
        result['credential_wrapper']['keyring_cleanup_passed'] = wrapper.get('keyring_cleanup', {}).get('passed') is True
    write(output / 'result.json', result)
    print(json.dumps(result))


if __name__ == '__main__':
    mode, path = sys.argv[1:]
    root = Path(path).resolve()
    try:
        if mode == 'prepare':
            prepare(root)
        elif mode == 'execute':
            sys.exit(execute(root))
        elif mode == 'fixture':
            sys.exit(fixture(root))
        elif mode == 'collect':
            collect(root)
        else:
            raise ValueError('unknown_mode')
    except Exception as error:
        print(json.dumps({'phase': mode, 'error_type': type(error).__name__}))
        sys.exit(1)
