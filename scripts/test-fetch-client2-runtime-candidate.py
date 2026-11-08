"""Pure fixed-artifact checks. No network, products, Cargo, UIA or native APIs."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('fetch-client2-runtime-candidate.py'))
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


def synthetic():
    native = b'synthetic Core payload'
    core = json.dumps({'schema_version': 1, 'target': candidate.TARGET, 'sdk_version': '1.1.0-dev.1',
                       'files': [{'path': 'core.dll', 'size': len(native), 'sha256': candidate.digest(native)}]}).encode()
    binary = b'synthetic Runtime payload'
    payload = {candidate.BINARY: binary, 'core-runtime.json': core, 'core.dll': native}
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz', format=tarfile.USTAR_FORMAT) as bundle:
        for name, data in payload.items():
            info = tarfile.TarInfo('./' + name)
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))
    archive = archive.getvalue()
    sdk = {'sdk_version': '1.1.0-dev.1', 'release_tag': 'sdk-v1.1.0-dev.1',
           'manifest_sha256': 'a' * 64, 'archive_sha256': 'b' * 64}
    lock = json.dumps({'targets': {candidate.TARGET: {**sdk, 'redistribution': 'approved'}}}).encode()
    build = {'schema_version': 2, 'runtime_version': '1.1.0-dev.1', 'tag': 'v1.1.0-dev.1', 'channel': 'dev',
             'target_triple': candidate.TARGET, 'archive_file': candidate.ARCHIVE, 'archive_sha256': candidate.digest(archive),
             'source_commit': 'c' * 40, 'binary_file': candidate.BINARY, 'binary_sha256': candidate.digest(binary),
             'files': [{'path': name, 'size': len(data), 'sha256': candidate.digest(data)} for name, data in payload.items()]}
    metadata = json.dumps(build).encode()
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, 'w') as bundle:
        bundle.writestr(candidate.ARCHIVE, archive)
        bundle.writestr(candidate.METADATA, metadata)
    raw = raw.getvalue()
    freeze = {'schema_version': 1, 'status': 'ready', 'repository': candidate.REPOSITORY, 'target': candidate.TARGET,
              'workflow_head_sha': 'd' * 40, 'runtime_source_sha': 'c' * 40, 'runtime_version': '1.1.0-dev.1',
              'run_id': 101, 'run_attempt': 2, 'build_job_id': 202, 'artifact_id': 303,
              'artifact_size': len(raw), 'artifact_sha256': candidate.digest(raw),
              'archive_sha256': candidate.digest(archive), 'metadata_sha256': candidate.digest(metadata),
              'binary_sha256': candidate.digest(binary), 'core_runtime_sha256': candidate.digest(core),
              'sdk_lock_sha256': candidate.digest(lock), 'sdk': sdk}
    run = {'id': 101, 'run_attempt': 2, 'repository': {'full_name': candidate.REPOSITORY},
           'path': '.github/workflows/release.yml', 'event': 'workflow_dispatch', 'head_sha': 'd' * 40,
           'head_branch': 'main', 'status': 'completed', 'conclusion': 'failure'}
    job = {'id': 202, 'name': f'Release ({candidate.TARGET})', 'status': 'completed', 'conclusion': 'success',
           'started_at': '2026-11-08T00:00:00Z', 'completed_at': '2026-11-08T00:10:00Z'}
    artifact = {'id': 303, 'name': f'runtime-release-{candidate.TARGET}', 'expired': False,
                'workflow_run': {'id': 101, 'head_sha': 'd' * 40}, 'size_in_bytes': len(raw),
                'digest': 'sha256:' + candidate.digest(raw), 'created_at': '2026-11-08T00:09:00Z'}
    import base64
    responses = {'actions/runs/101/attempts/2': run, 'actions/runs/101/attempts/2/jobs?per_page=100': {'jobs': [job]},
                 'actions/artifacts/303': artifact, 'actions/artifacts/303/zip': raw,
                 'contents/sdk/core-sdk.lock.json?ref=' + 'c' * 40: {'content': base64.b64encode(lock).decode()}}
    return freeze, responses


class FixedCandidateChecks(unittest.TestCase):
    def execute(self, mutate=None):
        freeze, responses = synthetic()
        if mutate:
            mutate(freeze, responses)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            calls = []
            def fake_api(path, raw=False):
                calls.append(path)
                self.assertEqual(raw, path.endswith('/zip'))
                return responses[path]
            with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                                         'RUNNER_OS': 'Windows', 'RUNNER_TEMP': directory}), patch.object(candidate, 'api', fake_api):
                candidate.fetch(freeze, output)
            proof = json.loads((output / 'candidate-source.json').read_text())
            self.assertEqual(proof['runtime_source_sha'], freeze['runtime_source_sha'])
            self.assertEqual(proof['producer']['run_conclusion'], 'failure')
            self.assertEqual(proof['actual_native_sdk_archive'], 'not-evaluated')
            self.assertEqual(proof['full_gui_acceptance'], 'not-evaluated')
            self.assertIs(proof['g1_passed'], False)
            self.assertEqual(candidate.digest((output / candidate.ARCHIVE).read_bytes()), freeze['archive_sha256'])
            self.assertEqual(candidate.digest((output / candidate.METADATA).read_bytes()), freeze['metadata_sha256'])
            return calls

    def test_original_bytes_and_partial_run_are_honestly_recorded(self):
        self.assertEqual(len(self.execute()), 5)

    def test_draft_refuses_without_api_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'freeze.json'
            path.write_text('{"status":"draft/unready"}', encoding='utf-8')
            with patch.object(candidate, 'api', side_effect=AssertionError('No network permitted')):
                with self.assertRaisesRegex(RuntimeError, 'draft/unready'):
                    candidate.read_freeze(path)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_ready_requires_all_exact_fields(self):
        freeze, _ = synthetic()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'freeze.json'
            path.write_text(json.dumps(freeze), encoding='utf-8')
            self.assertEqual(candidate.read_freeze(path), freeze)
            for key, bad in [('runtime_source_sha', None), ('artifact_sha256', 'latest'), ('artifact_id', True),
                             ('artifact_size', 513 * 2**20), ('runtime_version', '1.1.0')]:
                with self.subTest(key=key):
                    altered = copy.deepcopy(freeze)
                    altered[key] = bad
                    path.write_text(json.dumps(altered), encoding='utf-8')
                    with self.assertRaises(RuntimeError):
                        candidate.read_freeze(path)

    def test_isolation_refuses_before_api(self):
        freeze, _ = synthetic()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                                         'RUNNER_OS': 'Linux', 'RUNNER_TEMP': directory}), patch.object(candidate, 'api', side_effect=AssertionError('No API')):
                with self.assertRaisesRegex(RuntimeError, 'Windows'):
                    candidate.fetch(freeze, output)
            output.mkdir()
            with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                                         'RUNNER_OS': 'Windows', 'RUNNER_TEMP': directory}), patch.object(candidate, 'api', side_effect=AssertionError('No API')):
                for target in [Path(directory), output, Path(directory).parent / 'outside-candidate-output']:
                    with self.subTest(target=target.name), self.assertRaisesRegex(RuntimeError, 'fresh output'):
                        candidate.fetch(freeze, target)

    def test_remote_identity_and_original_hash_rejections(self):
        cases = [
            ('run-source', lambda f, r: r['actions/runs/101/attempts/2'].update(head_sha='e' * 40)),
            ('run-attempt', lambda f, r: r['actions/runs/101/attempts/2'].update(run_attempt=1)),
            ('workflow', lambda f, r: r['actions/runs/101/attempts/2'].update(path='.github/workflows/other.yml')),
            ('trusted-main', lambda f, r: r['actions/runs/101/attempts/2'].update(head_branch='untrusted')),
            ('job-result', lambda f, r: r['actions/runs/101/attempts/2/jobs?per_page=100']['jobs'][0].update(conclusion='failure')),
            ('artifact-id', lambda f, r: r['actions/artifacts/303'].update(id=404)),
            ('artifact-name', lambda f, r: r['actions/artifacts/303'].update(name='other')),
            ('artifact-digest', lambda f, r: r['actions/artifacts/303'].update(digest='sha256:' + '0' * 64)),
            ('artifact-attempt-time', lambda f, r: r['actions/artifacts/303'].update(created_at='2026-11-07T00:09:00Z')),
            ('lock-bytes', lambda f, r: f.update(sdk_lock_sha256='0' * 64)),
            ('zip-bytes', lambda f, r: r.update({'actions/artifacts/303/zip': b'changed original ZIP'})),
            ('archive-hash', lambda f, r: f.update(archive_sha256='0' * 64)),
            ('metadata-hash', lambda f, r: f.update(metadata_sha256='0' * 64)),
            ('binary-hash', lambda f, r: f.update(binary_sha256='0' * 64)),
            ('core-hash', lambda f, r: f.update(core_runtime_sha256='0' * 64)),
        ]
        for name, mutate in cases:
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                self.execute(mutate)


if __name__ == '__main__':
    unittest.main()
