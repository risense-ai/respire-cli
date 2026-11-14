"""Reproduce #285 with the official dev.3 CLI and a candidate on native macOS arm64.

Uses an empty, explicitly supplied directory and native Keychain credentials.
Never deletes the fixture or publishes keygen output. Existing model files may
be reused with --m3-dir. A failure leaves the fixture available for inspection.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import time
import urllib.request


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old-cli', type=Path, required=True)
    parser.add_argument('--old-metadata', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--m3-dir', type=Path)
    args = parser.parse_args()
    if (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
        raise RuntimeError('requires native macOS arm64; do not substitute another platform')
    old = args.old_cli.resolve(strict=True)
    candidate = args.candidate.resolve(strict=True)
    metadata = json.loads(args.old_metadata.read_text(encoding='utf-8'))
    if metadata.get('binary_sha256') != digest(old):
        raise ValueError('old CLI differs from its official release metadata')
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise ValueError('--root must be empty; existing homes are never modified')
    data = root / 'data'
    stable = data / 'bin' / 'rsrs'
    stable.parent.mkdir(parents=True)
    shutil.copy2(old, stable)
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('RSRS_', 'ONEMEMORY_', 'RESPIRE_', 'XDG_'))
           and key not in ('GH_TOKEN', 'GITHUB_TOKEN', 'CORE_SDK_READ_TOKEN')}
    env.update(HOME=str(root), RSRS_DATA_DIR=str(data), RSRS_BIN_DIR=str(stable.parent),
               RSRS_RPC_PORT=str(port), RSRS_ENGINE='cpu', RSRS_LOG='info')
    if args.m3_dir:
        env['RSRS_M3_DIR'] = str(args.m3_dir.resolve(strict=True))
    report = {'issue': 285, 'passed': False, 'checks': [],
              'old_cli_sha256': digest(old), 'candidate_sha256': digest(candidate)}
    report_path = root / 'upgrade-report.json'

    def run(binary, *arguments):
        report['stage'] = ' '.join(arguments[:2])
        started = time.monotonic()
        result = subprocess.run([str(binary), '--json', *arguments], env=env,
                                capture_output=True, timeout=600)
        # Keygen stdout can include a recovery kit: never put raw output in reports.
        if result.returncode:
            try:
                failure = json.loads(result.stdout)
            except (ValueError, UnicodeError):
                failure = {}
            report['failure'] = {'exit': result.returncode,
                                 'elapsed_seconds': time.monotonic() - started,
                                 'errors': failure.get('errors', []) if failure.get('status') == 'fail' else []}
            print(json.dumps(report['failure']))
            raise RuntimeError('command failed: ' + ' '.join(arguments[:2])
                               + '; inspect the retained fixture logs')
        value = json.loads(result.stdout)
        if value.get('status') != 'ok':
            raise RuntimeError('command did not report success: ' + arguments[0])
        return value

    def health():
        request = urllib.request.Request(f'http://127.0.0.1:{port}/api/health',
                                         headers={'X-Respire-Health': 'runtime-v1'})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=5) as response:
            return json.load(response)

    try:
        version = subprocess.check_output([str(old), '--version'], env=env, timeout=15)
        if version.strip() != b'rsrs 2.0.0-dev.3':
            raise ValueError('expected CLI 2.0.0-dev.3')
        run(old, 'runtime', 'install')
        run(old, 'status')
        run(old, 'keygen')
        run(old, 'runtime', 'start')
        run(old, 'model', 'install')
        content = 'Issue 285 retained offline memory'
        stored = run(old, 'remember', content, '--title', 'issue-285-before-upgrade',
                     '--importance', 'important', '--force')
        memory_id = stored['summary']['id']
        original_memory = run(old, 'show', memory_id)['details']['entry']
        original_health = health()
        if original_health.get('runtime_version') != '2.0.0-dev.14':
            raise AssertionError('fixture did not start Runtime dev.14')
        old_release = data / 'runtime' / '2.0.0-dev.14'
        if not old_release.is_dir():
            raise AssertionError('fixture does not use the reported legacy layout')
        journal_path = data / '.login-recovery.json'
        journal_bytes = journal_path.read_bytes()
        journal = json.loads(journal_bytes)
        if (journal.get('schema_version') != 2 or journal.get('active') is not None
                or not any(item.get('phase') == 'committed' and item.get('backend') == 'native'
                           for item in journal.get('operations', []))):
            raise AssertionError('fixture does not contain the reported committed native receipt')
        session = data / 'session.json'
        original_session = session.read_bytes()
        report['checks'].append('dev.3/dev.14 running with committed native receipt and stored memory')

        installed = run(candidate, 'runtime', 'install')['summary']
        if installed.get('restarted') is not True or digest(stable) != digest(candidate):
            raise AssertionError('upgrade did not refresh the CLI and restart the old owner')
        if not old_release.is_dir() or journal_path.read_bytes() != journal_bytes:
            raise AssertionError('upgrade removed the old release or changed recovery evidence')
        if session.read_bytes() != original_session:
            raise AssertionError('upgrade changed the original offline session')
        upgraded_health = health()
        if upgraded_health.get('runtime_version') == '2.0.0-dev.14':
            raise AssertionError('old Runtime still serves after upgrade')
        report['checks'].append('in-place restart with original session, journal and old release retained')
        run(candidate, 'status')
        restored = run(candidate, 'show', memory_id)['details']['entry']
        if (restored['id'], restored['content']) != (original_memory['id'], original_memory['content']):
            raise AssertionError('pre-upgrade memory changed')
        written = run(candidate, 'remember', 'Issue 285 post-upgrade write', '--force')['summary']['id']
        run(candidate, 'show', written)
        if not run(candidate, 'recall', content, '--titles')['items']:
            raise AssertionError('recall returned no memories after upgrade')
        report['checks'].append('status/show/remember/recall succeed against the upgraded original home')
        repeated = run(candidate, 'runtime', 'install')['summary']
        if repeated.get('restarted') is not False or health()['pid'] != upgraded_health['pid']:
            raise AssertionError('repeated installation restarted an already compatible owner')
        run(candidate, 'runtime', 'stop')
        report['checks'].append('repeat installation is idempotent; normal stop succeeds')
        report['passed'] = True
    finally:
        report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(report_path)


if __name__ == '__main__':
    main()
