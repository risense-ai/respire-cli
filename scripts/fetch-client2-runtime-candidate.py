"""Read one reviewed, fixed public Runtime artifact; never build or execute a product."""
import argparse
import base64
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import zipfile

REPOSITORY = 'risense-ai/respire-runtime'
TARGET = 'x86_64-pc-windows-msvc'
ARCHIVE = f'rsrs-runtime-{TARGET}.tar.gz'
METADATA = f'runtime-build-{TARGET}.json'
BINARY = f'rsrs-runtime-{TARGET}.exe'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_freeze(path):
    freeze = json.loads(Path(path).read_text(encoding='utf-8'))
    # This check precedes every API, artifact download, and output-directory creation.
    require(freeze.get('status') == 'ready', 'Runtime candidate freeze is draft/unready; no download or product permitted')
    require(freeze['schema_version'] == 1 and freeze['repository'] == REPOSITORY and freeze['target'] == TARGET,
            'Candidate repository/schema/target differs')
    for key in ['workflow_head_sha', 'runtime_source_sha']:
        require(isinstance(freeze[key], str) and re.fullmatch('[a-f0-9]{40}', freeze[key]), 'Invalid frozen source SHA')
    for key in ['artifact_sha256', 'archive_sha256', 'metadata_sha256', 'binary_sha256', 'core_runtime_sha256', 'sdk_lock_sha256']:
        require(isinstance(freeze[key], str) and re.fullmatch('[a-f0-9]{64}', freeze[key]), 'Missing frozen artifact/hash identity')
    for key in ['run_id', 'run_attempt', 'build_job_id', 'artifact_id', 'artifact_size']:
        require(type(freeze[key]) is int and freeze[key] > 0, 'Missing frozen producer identity')
    require(freeze['artifact_size'] <= 512 * 2**20, 'Candidate ZIP exceeds 512 MiB bound')
    require(isinstance(freeze['runtime_version'], str) and re.fullmatch(r'\d+\.\d+\.\d+-dev\.\d+', freeze['runtime_version']),
            'Candidate must identify an exact DEV build, not a stable release')
    sdk = freeze['sdk']
    require(isinstance(sdk['sdk_version'], str) and re.fullmatch(r'\d+\.\d+\.\d+(?:-dev\.\d+)?', sdk['sdk_version'])
            and sdk['release_tag'] == 'sdk-v' + sdk['sdk_version'], 'Missing exact SDK identity')
    for key in ['manifest_sha256', 'archive_sha256']:
        require(isinstance(sdk[key], str) and re.fullmatch('[a-f0-9]{64}', sdk[key]), 'Missing frozen SDK pin')
    return freeze


def api(path, raw=False):
    result = subprocess.run(['gh', 'api', 'repos/' + REPOSITORY + '/' + path],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
    return result.stdout if raw else json.loads(result.stdout)


def fetch(freeze, output):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('RUNNER_OS') == 'Windows', 'Candidate artifact consumer requires isolated GitHub-hosted Windows')
    output = Path(output).resolve()
    temporary = Path(os.environ['RUNNER_TEMP']).resolve()
    require(output != temporary and output.is_relative_to(temporary) and not output.exists(), 'Require a fresh output strictly under RUNNER_TEMP')
    run_id, attempt = freeze['run_id'], freeze['run_attempt']
    run = api(f'actions/runs/{run_id}/attempts/{attempt}')
    require(run['id'] == run_id and run['run_attempt'] == attempt and run['repository']['full_name'] == REPOSITORY
            and run['path'] == '.github/workflows/release.yml' and run['event'] == 'workflow_dispatch'
            and run['head_sha'] == freeze['workflow_head_sha'] and run['head_branch'] == 'main', 'Frozen trusted producer workflow differs')
    jobs = api(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')['jobs']
    job, = [job for job in jobs if job['id'] == freeze['build_job_id']]
    require(job['name'] == f'Release ({TARGET})' and job['status'] == 'completed' and job['conclusion'] == 'success',
            'Frozen platform build job is not successful')
    artifact = api(f"actions/artifacts/{freeze['artifact_id']}")
    require(artifact['id'] == freeze['artifact_id'] and artifact['name'] == f'runtime-release-{TARGET}' and not artifact['expired']
            and artifact['workflow_run']['id'] == run_id and artifact['workflow_run']['head_sha'] == freeze['workflow_head_sha']
            and artifact['size_in_bytes'] == freeze['artifact_size'] and artifact['digest'] == 'sha256:' + freeze['artifact_sha256'],
            'Frozen artifact API identity differs')
    timestamp = lambda value: datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(timestamp(job['started_at']) <= timestamp(artifact['created_at']) <= timestamp(job['completed_at']),
            'Artifact creation is outside the frozen build job/attempt')
    lock_entry = api('contents/sdk/core-sdk.lock.json?ref=' + freeze['runtime_source_sha'])
    lock_bytes = base64.b64decode(lock_entry['content'])
    require(digest(lock_bytes) == freeze['sdk_lock_sha256'], 'SDK lock bytes at exact Runtime source differ')
    sdk_lock = json.loads(lock_bytes)['targets'][TARGET]
    require(all(sdk_lock[key] == value for key, value in freeze['sdk'].items()) and sdk_lock['redistribution'] == 'approved',
            'Runtime source SDK pins differ from the reviewed freeze')
    raw = api(f"actions/artifacts/{freeze['artifact_id']}/zip", raw=True)
    require(len(raw) == freeze['artifact_size'] and digest(raw) == freeze['artifact_sha256'], 'Original artifact ZIP bytes differ')
    with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
        entries = bundle.infolist()
        require(len(entries) == 2 and {entry.filename for entry in entries} == {ARCHIVE, METADATA}, 'Unexpected artifact members')
        require(all(not entry.is_dir() and stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG)
                    and entry.file_size <= 512 * 2**20 for entry in entries), 'Unsupported artifact member')
        archive, metadata = bundle.read(ARCHIVE), bundle.read(METADATA)
    require(digest(archive) == freeze['archive_sha256'] and digest(metadata) == freeze['metadata_sha256'], 'Original archive/build metadata bytes differ')
    build = json.loads(metadata)
    expected = dict(schema_version=2, runtime_version=freeze['runtime_version'], tag='v' + freeze['runtime_version'],
                    channel='dev', target_triple=TARGET, archive_file=ARCHIVE, archive_sha256=freeze['archive_sha256'],
                    source_commit=freeze['runtime_source_sha'], binary_file=BINARY, binary_sha256=freeze['binary_sha256'])
    require(all(build.get(key) == value for key, value in expected.items()), 'Runtime build report binding differs')
    files = {item['path']: item for item in build['files']}
    require(len(files) == len(build['files']) and files[BINARY]['sha256'] == freeze['binary_sha256']
            and files['core-runtime.json']['sha256'] == freeze['core_runtime_sha256'], 'Build file identities differ')
    # Read only two fixed regular members; the existing CLI installer retains complete payload validation.
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as bundle:
        for name, expected_hash in [(BINARY, freeze['binary_sha256']), ('core-runtime.json', freeze['core_runtime_sha256'])]:
            member, = [item for item in bundle.getmembers() if item.name.removeprefix('./') == name]
            require(member.isreg() and not member.pax_headers and member.size == files[name]['size']
                    and member.size <= 256 * 2**20, 'Invalid fixed Runtime payload member')
            data = bundle.extractfile(member).read(member.size + 1)
            require(len(data) == member.size and digest(data) == expected_hash, 'Actual Runtime payload hash differs')
            if name == 'core-runtime.json':
                core = json.loads(data)
    require(core['schema_version'] == 1 and core['target'] == TARGET and core['sdk_version'] == freeze['sdk']['sdk_version'],
            'Actual staged Core runtime identity differs')
    require(all(files.get(item['path']) == item for item in core['files']), 'Staged Core declarations differ from build file hashes')
    proof = dict(schema_version=1, mode='frozen-runtime-candidate', freeze_sha256=digest(json.dumps(freeze,sort_keys=True,separators=(',',':')).encode()),
                 runtime_source_sha=freeze['runtime_source_sha'], runtime_version=freeze['runtime_version'], target=TARGET,
                 archive_sha256=freeze['archive_sha256'], binary_sha256=freeze['binary_sha256'], core_runtime_sha256=freeze['core_runtime_sha256'],
                 producer=dict(run_id=run_id, run_attempt=attempt, workflow_head_sha=freeze['workflow_head_sha'], build_job_id=job['id'],
                               artifact_id=artifact['id'], artifact_sha256=freeze['artifact_sha256'], run_status=run['status'], run_conclusion=run['conclusion']),
                 sdk_lock_sha256=freeze['sdk_lock_sha256'], sdk=freeze['sdk'],
                 actual_native_sdk_archive='not-evaluated', sdk_source_commit='not-observed', full_gui_acceptance='not-evaluated', g1_passed=False)
    output.mkdir()
    for name, data in [(ARCHIVE, archive), (METADATA, metadata), ('candidate-source.json', (json.dumps(proof,indent=2)+'\n').encode())]:
        with (output/name).open('xb') as stream:
            stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check-freeze', 'fetch'])
    parser.add_argument('--freeze', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path)
    args = parser.parse_args()
    freeze = read_freeze(args.freeze)
    if args.action == 'fetch':
        require(args.output_directory is not None, 'Missing candidate staging output')
        fetch(freeze, args.output_directory)


if __name__ == '__main__':
    main()
