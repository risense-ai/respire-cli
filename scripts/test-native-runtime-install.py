"""Offline fixture installation tests; no credentials, downloads or live processes."""
import hashlib
import ast
import json
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from native_fixture_process import install_official_runtime, same_existing_path, canonical_scope_path, runtime_scope_ids


class FixtureInstallationTests(unittest.TestCase):
    def test_published_autostart_uses_verified_archive_and_requires_hosted_registration(self):
        scripts = Path(__file__).resolve().parent
        workflow = (scripts.parent / '.github/workflows/release-native-validation.yml').read_text(encoding='utf-8')
        self.assertIn('os: macos-15\n            target: aarch64-apple-darwin', workflow)
        name = 'Verify OS autostart registration from published release bytes'
        step = workflow.split('      - name: ' + name + '\n')[1].split('\n      - ')[0]
        self.assertIn("if: inputs.artifact_source == 'published-assets' && inputs.validation_profile == 'full'", step)
        self.assertIn('set -euo pipefail', step)
        self.assertIn('unset GH_TOKEN GITHUB_TOKEN RSRS_RUNTIME_BIN', step)
        for variable in ('RSRS_PUBLISHED_RUNTIME_ARCHIVE', 'RSRS_PUBLISHED_RUNTIME_VERSION'):
            self.assertIn('${' + variable + ':?Verified published Runtime ', step)
        self.assertIn('exe="target/ci/${{ matrix.target }}/release/rsrs"', step)
        self.assertIn('exe="$exe.exe"', step)
        self.assertIn('py="$RUNNER_TEMP/upgrade-python/bin/python"', step)
        self.assertIn('py="$RUNNER_TEMP/upgrade-python/Scripts/python.exe"', step)
        self.assertIn('"$py" scripts/test-runtime-autostart.py --binary "$exe" --register \\\n'
                      '            --runtime-archive "$RSRS_PUBLISHED_RUNTIME_ARCHIVE" --runtime-version "$RSRS_PUBLISHED_RUNTIME_VERSION"', step)
        self.assertLess(workflow.index('run: node npm/scripts/extract-artifact.mjs validated-cli'), workflow.index(name))
        preparation = 'Prepare isolated upgrade Python and the fixed Windows wheel key'
        self.assertLess(workflow.index(preparation), workflow.index(name))
        self.assertEqual(workflow.count('python -m venv "$RUNNER_TEMP/upgrade-python"'), 1)
        for dependency in ('dbus-x11 gnome-keyring', 'SecretStorage==3.3.3 jeepney==0.9.0'):
            self.assertEqual(workflow.count(dependency), 1)
            self.assertLess(workflow.index(dependency), workflow.index(name))
        self.assertNotIn('login-regression-python', workflow)
        self.assertIn('dbus-run-session -- env RSRS_SS_FIXTURE_BUS=private "$RUNNER_TEMP/upgrade-python/bin/python" scripts/dev-login-interruption-smoke.py', workflow)
        for forbidden in ('--previous-binary', '--runtime-binary', 'cargo ', 'continue-on-error', '|| true'):
            self.assertNotIn(forbidden, step)
        for actions, runner in [('false', 'github-hosted'), ('true', 'self-hosted'), ('true', '')]:
            with self.subTest(actions=actions, runner=runner):
                result = subprocess.run([sys.executable, str(scripts / 'test-runtime-autostart.py'),
                                         '--binary', 'must-not-execute', '--register'],
                                        env={**os.environ, 'GITHUB_ACTIONS': actions, 'RUNNER_ENVIRONMENT': runner},
                                        capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('OS registration acceptance is limited to an ephemeral GitHub-hosted runner', result.stderr)
        source = (scripts / 'test-runtime-autostart.py').read_text(encoding='utf-8')
        self.assertLess(source.index('assert not root.exists()'), source.index('        foreground(False)'))
        self.assertLess(source.index('        foreground(False)'), source.index('        seed_local_credentials(binary, env, keys)'))
        self.assertLess(source.index('        seed_local_credentials(binary, env, keys)'), source.index('        health = foreground(True)'))
        self.assertLess(source.index('        binary = str(base / "bin"'), source.index('        seed_local_credentials(binary, env, keys)'))
        for proof in ('health["credential_state"] == "required"', '"keyless startup created a session"',
                      '"keyless startup opened a library"', 'keys.configure_business_env(env)',
                      'keys.configure_env(env)', 'hosted_user_bus=True', 'keys.cleanup()',
                      '"registration changed the CLI image used for key custody"',
                      '"synthetic native credential cleanup failed; fixture retained"'):
            self.assertIn(proof, source)
        for proof in ('query.returncode == 0, "unlocked foreground status failed"',
                      'query.returncode == 2 and status_reply["status"] == "warn"',
                      'status_reply["summary"]["credential_state"] == "required"',
                      'status_reply["summary"]["store_ready"] is False'):
            self.assertIn(proof, source)
        self.assertNotIn('"session.json").write', source)
        self.assertNotIn('keys.put(', source)
        # Execute the actual seeding helper; subprocesses stand in only for this offline contract.
        helpers = runpy.run_path(str(scripts / 'test-runtime-autostart.py'))
        seed = helpers['seed_local_credentials']
        ready = helpers['foreground_health_ready']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / 'official-runtime'
            runtime.write_bytes(b'offline-image-never-executed')
            foreign = root / 'foreign'
            foreign.mkdir()
            health = dict(server='respire', managed_id=None, exe=str(runtime),
                installation_root=str(root), data_dir=str(root), pid=123, instance_id='owned-instance',
                process_start_id='owned-birth', image_sha256='a'*64, store_ready=False, startup_complete=False)
            owner, complete = ready(health, root, runtime, False, None)
            self.assertFalse(complete, 'store_ready=false must not accept incomplete startup')
            for expected in (False, True):
                for startup in (None, False, True):
                    candidate = dict(health, store_ready=expected, startup_complete=startup)
                    self.assertEqual(ready(candidate, root, runtime, expected, owner)[1], startup is True)
                self.assertFalse(ready(dict(health, startup_complete=True), root, runtime, not health['store_ready'], owner)[1])
            for field, value in (('data_dir', str(foreign)), ('installation_root', str(foreign)),
                                 ('exe', str(root)), ('instance_id', 'replacement'), ('pid', 124),
                                 ('process_start_id', 'replacement'), ('image_sha256', 'b'*64)):
                with self.subTest(health=field), self.assertRaises(AssertionError):
                    ready(dict(health, **{field: value}), root, runtime, False, owner)
        self.assertIn('health.get("startup_complete") is True', source)
        operation = '12345678-1234-4234-9234-123456789abc'
        alias = 'login-' + 'fedcba98' * 4  # Native alias is independent of the operation ID.
        for fault in ('', 'keygen', 'keygen_early', 'keygen_prepared', 'keygen_nonjson', 'keygen_original_changed', 'keygen_cleanup', 'handoff', 'locked',
                      'bound', 'foreign', 'material', 'session_alias', 'backend', 'stop'):
            with self.subTest(seed=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                keys = types.SimpleNamespace(entries=set(), credential_backend='native')
                calls = []
                def cli(command, **kwargs):
                    calls.append(command[2:])
                    self.assertEqual(command[:2], ['owned-cli', '--json'])
                    self.assertTrue(kwargs['capture_output'])
                    self.assertEqual(kwargs['timeout'], 45)
                    if command[2:] == ['keygen']:
                        if fault != 'keygen_early':
                            journal = root / 'runtime/autostart/offline-keygen.json'
                            journal.parent.mkdir(parents=True)
                            if fault == 'foreign':
                                (root / 'foreign').mkdir()
                            journal.write_text(json.dumps({'schema': 1, 'operation_id': operation,
                                'stage': 'prepared' if fault.startswith('keygen') else 'committed',
                                'root': str(root), 'source': str(root),
                                'profile': str(root / 'foreign' if fault == 'foreign' else root),
                                'material': None if fault in ('keygen_prepared', 'keygen_original_changed') else {'vault_version': 4, 'auth_operation_id': operation if fault != 'material' else 'foreign',
                                             'keyring_account': alias, 'keyring_backend': 'foreign' if fault == 'backend' else 'native'}}), encoding='utf-8')
                            session = {'vault_version': 4, 'keyring_account': 'login-' + 'a'*32 if fault == 'session_alias' else alias,
                                       'keyring_backend': 'native'}
                            if fault == 'bound':
                                session['user'] = 'foreign-account'
                            (root / 'session.json').write_text(json.dumps(session), encoding='utf-8')
                        return types.SimpleNamespace(returncode=int(fault.startswith('keygen')),
                            stdout='private-sentinel-never-report' if fault == 'keygen_nonjson' else json.dumps({'summary': {'super': 'private-sentinel-never-report'},
                                               'errors': [('offline keygen original operation changed' if fault == 'keygen_original_changed' else 'host auth credential write failed') + ': private-sentinel-never-report']}),
                            stderr='private-sentinel-never-report')
                    if command[2:] == ['runtime', 'status']:
                        return types.SimpleNamespace(returncode=0, stdout=json.dumps(
                            {'summary': {'runtime': {'store_ready': fault != 'locked'}}}))
                    return types.SimpleNamespace(returncode=int(
                        fault == 'handoff' and command[2:] == ['runtime', 'start']
                        or fault in ('stop', 'keygen_cleanup') and command[2:] == ['runtime', 'stop']),
                        stdout='private-sentinel-never-report', stderr='private-sentinel-never-report')
                with patch('subprocess.run', side_effect=cli):
                    if fault:
                        with self.assertRaises(AssertionError) as raised:
                            seed('owned-cli', {'RSRS_DATA_DIR': str(root)}, keys)
                        self.assertNotIn('private-sentinel-never-report', str(raised.exception))
                        if fault.startswith('keygen'):
                            self.assertIn('synthetic CLI keygen failed', str(raised.exception))
                            self.assertIn('"category": "' + ('unclassified' if fault == 'keygen_nonjson' else 'original_operation_changed' if fault == 'keygen_original_changed' else 'native_custody') + '"', str(raised.exception))
                            if fault == 'keygen_cleanup':
                                self.assertIn('cleanup also failed', raised.exception.__notes__[0])
                                self.assertNotIn('private-sentinel-never-report', str(raised.exception.__cause__))
                    else:
                        seed('owned-cli', {'RSRS_DATA_DIR': str(root)}, keys)
                self.assertEqual(calls[0], ['keygen'])
                self.assertEqual(calls[-1], ['runtime', 'stop'])
                self.assertEqual(calls.count(['keygen']), 1)
                self.assertEqual(keys.entries, set() if fault in ('foreign', 'material', 'backend', 'keygen_early', 'keygen_prepared', 'keygen_original_changed') else
                    {('rsrs', 'super:' + alias)})
                if not fault:
                    self.assertEqual(calls, [['keygen'], ['runtime', 'start'], ['runtime', 'status'], ['runtime', 'stop']])

    def test_scope_ids_use_os_canonical_paths_and_preserve_bound_accounts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            profile = root / 'profile'
            profile.mkdir()
            expected_root = canonical_scope_path(root)
            expected_profile = canonical_scope_path(profile)
            expected = tuple(hashlib.sha256(value.encode()).hexdigest()
                             for value in (expected_root, expected_profile))
            self.assertEqual(runtime_scope_ids(root, profile, {}), expected)
            self.assertEqual(runtime_scope_ids(root / '.', profile / '..' / 'profile', {}), expected)
            bound = hashlib.sha256(b'fixture-account').hexdigest()
            self.assertEqual(runtime_scope_ids(root, profile, {'user': 'fixture-account'}), (expected[0], bound))
            self.assertNotEqual(runtime_scope_ids(root, root, {})[1], expected[1])
            with self.assertRaises(OSError):
                runtime_scope_ids(root, root / 'missing', {})
            with self.assertRaises(ValueError):
                runtime_scope_ids(root, profile, {'user': 1})
            if os.name == 'nt':
                self.assertTrue(expected_root.startswith('\\\\?\\'))
                self.assertEqual(runtime_scope_ids(expected_root, expected_profile, {}), expected)
                self.assertNotEqual(hashlib.sha256(str(root).encode()).hexdigest(), expected[0])

    def test_path_identity_requires_the_same_existing_file_or_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / 'first', root / 'second'
            first.write_bytes(b'one')
            second.write_bytes(b'one')
            self.assertTrue(same_existing_path(first, root / '.' / 'first'))
            self.assertTrue(same_existing_path(root, root.resolve()))
            self.assertFalse(same_existing_path(first, second))
            self.assertFalse(same_existing_path(first, root))
            self.assertFalse(same_existing_path(first, root / 'missing'))
            self.assertFalse(same_existing_path('', root))
            self.assertFalse(same_existing_path(1, root))
            self.assertFalse(same_existing_path({'path': str(root)}, root))
            if os.name == 'nt':
                self.assertTrue(same_existing_path('\\\\?\\' + str(first.resolve()), first))
                self.assertTrue(same_existing_path('\\\\?\\' + str(root.resolve()), root))

    def test_upgrade_fixture_downloads_runtime_after_legacy_data_and_handoff(self):
        tree = ast.parse(Path(__file__).with_name('test-real-m3-account-switch.py').read_text())
        branches = [node for node in ast.walk(tree) if isinstance(node, ast.If)]
        fresh = next(node for node in branches
                     if ast.unparse(node.test) == 'not (args.seed_binary and args.runtime_binary)')
        upgrade = next(node for node in branches
                       if ast.unparse(node.test) == 'args.seed_binary and args.runtime_binary')
        calls = [node for node in ast.walk(upgrade) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name)]
        install = next(node for node in calls if node.func.id == 'install_official_runtime')
        stage = next(node for node in calls if node.func.id == 'stage_fixture_cli')
        self.assertLess(stage.lineno, install.lineno)
        session = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Attribute) and node.func.attr == 'write_text'
                       and any(isinstance(part, ast.Constant) and part.value == 'session.json'
                               for part in ast.walk(node.func.value)))
        handoff = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == 'legacy_handoff_actor'
                               for target in node.targets)
                       and isinstance(node.value, ast.Constant) and node.value.value == 'fixture')
        self.assertLess(fresh.end_lineno, session.lineno)
        self.assertLess(session.lineno, handoff.lineno)
        self.assertLess(handoff.lineno, install.lineno)
        snapshot_assert = next(node for node in ast.walk(upgrade) if isinstance(node, ast.Assert)
                               and any(isinstance(part, ast.Name) and part.id == 'legacy_data'
                                       for part in ast.walk(node.test)))
        self.assertGreater(snapshot_assert.lineno, install.lineno)

    def run_fixture(self, fault=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'fixture'
            root.mkdir()
            (root / 'bin').mkdir()
            version, triple = '1.0.21-dev.17', 'synthetic-target'
            image = b'synthetic Runtime; never executed'
            digest = hashlib.sha256(image).hexdigest()
            env = {'RSRS_DATA_DIR': str(root), 'RSRS_RUNTIME_TRIPLE': triple,
                   'RSRS_RUNTIME_BIN': '/external/runtime', 'GH_TOKEN': 'not-real',
                   'GITHUB_TOKEN': 'not-real', 'RSRS_CORE_TEST_MODE': '1'}
            metadata = {'schema_version': 2, 'runtime_version': version,
                        'target_triple': triple, 'binary_sha256': digest}
            installed = root / 'bin/runtime' / version / ('rsrs-runtime.exe' if os.name == 'nt' else 'rsrs-runtime')

            def installer(command, **kwargs):
                self.assertEqual(command, ['fixture-cli', '--json', 'runtime', 'install'])
                for key in ('RSRS_RUNTIME_BIN', 'RSRS_CORE_TEST_MODE', 'GH_TOKEN', 'GITHUB_TOKEN'):
                    self.assertNotIn(key, kwargs['env'])
                self.assertEqual(kwargs['env']['RSRS_DATA_DIR'], str(root))
                if fault == 'exit':
                    return types.SimpleNamespace(returncode=1)
                installed.parent.mkdir(parents=True)
                installed.write_bytes(b'corrupt' if fault == 'image' else image)
                if fault == 'target':
                    metadata['target_triple'] = 'wrong-target'
                encoded = json.dumps(metadata)
                proof = {'metadata_json': encoded,
                         'metadata_sha256': hashlib.sha256(encoded.encode()).hexdigest()}
                if fault == 'proof':
                    proof['metadata_sha256'] = '0' * 64
                receipt = {'version': version, 'sha256': digest, 'release': proof}
                if fault == 'version':
                    receipt['version'] = '1.0.21-dev.16'
                (root / 'bin/runtime.json').write_text(json.dumps(receipt))
                return types.SimpleNamespace(returncode=0)

            if fault == 'existing':
                (root / 'bin/runtime.json').write_text('{}')
            hosted = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                      'RUNNER_TEMP': temporary}
            if fault == 'host':
                hosted['RUNNER_ENVIRONMENT'] = 'self-hosted'
            if fault == 'outside':
                hosted['RUNNER_TEMP'] = str(root)
            with patch.dict(os.environ, hosted, clear=True), patch('subprocess.run', side_effect=installer) as run:
                if fault:
                    with self.assertRaises((ValueError, RuntimeError)):
                        install_official_runtime('fixture-cli', env, version, digest)
                    self.assertEqual(env['RSRS_RUNTIME_BIN'], '/external/runtime')
                    if fault in ('host', 'outside', 'existing'):
                        run.assert_not_called()
                else:
                    result = install_official_runtime('fixture-cli', env, version, digest)
                    self.assertEqual(result, installed.resolve())
                    self.assertEqual(env['RSRS_RUNTIME_BIN'], str(result))
                    run.assert_called_once()

    def test_fixture_receives_its_own_verified_installation(self):
        self.run_fixture()
        startup = Path(__file__).with_name('test-windows-host-startup.ps1').read_text(encoding='utf-8-sig')
        self.assertIn('--installation-root $profileRoot', startup)
        self.assertLess(startup.index('Copy-Item -LiteralPath $nativeExecutable -Destination $stableCli'),
                        startup.index('Start-ScheduledTask -TaskName $taskName'))
        self.assertIn('Get-FileHash -LiteralPath $stableCli -Algorithm SHA256', startup)
        self.assertIn("('bin/runtime/' + $managedReceipt.version + '/rsrs-runtime.exe')", startup)
        self.assertEqual(startup.count("-Headers @{'X-Respire-Health' = 'runtime-v1'}"), 3)
        self.assertIn('task_result_parsed = ($null -ne $taskEnvelope); task_error_code = $taskErrorCode;', startup)
        bundle = ast.parse(Path(__file__).with_name('runtime-acceptance-bundle.py').read_text(encoding='utf-8'))
        entrypoint = next(node for node in bundle.body if isinstance(node, ast.If))
        call = next(node for node in ast.walk(entrypoint) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == 'stage_runtime')
        self.assertTrue(any(arg.arg == 'installation_root' and isinstance(arg.value, ast.Attribute)
                            and arg.value.attr == 'installation_root' for arg in call.keywords))
        workflows = Path(__file__).resolve().parents[1] / '.github/workflows'
        programs = []
        for name, product_job in [('runtime-autostart-validation.yml', 'user-runtime'),
                                  ('windows-startup-validation.yml', 'startup')]:
            text = (workflows / name).read_text(encoding='utf-8')
            source, product = text.split('\n  ' + product_job + ':\n')
            self.assertIn('  source-checks:\n', source)
            self.assertNotIn('installPinnedRuntime', source)
            self.assertNotIn('test-runtime-autostart.py --binary', source)
            self.assertNotIn('./scripts/test-windows-host-startup.ps1', source)
            self.assertIn('Source and fixture checks only.', source)
            self.assertIn("if: github.event_name == 'workflow_dispatch'", product)
            self.assertIn('needs: source-checks', product)
            self.assertIn('EXPECTED_RUNTIME_SOURCE_SHA: ${{ inputs.runtime_source_sha }}', product)
            self.assertIn('      runtime_source_sha:\n', source)
            self.assertIn('        required: true\n', source)
            self.assertNotIn('continue-on-error', text)
            body = product.split("node --input-type=module <<'NODE'\n")[1].split('          NODE')[0]
            body = re.sub(r'^\s*import .+;\s*$', '', body, flags=re.MULTILINE)
            body = body.replace("const {installPinnedRuntime} = await import('./scripts/ci-install-pinned-runtime.mjs');", '')
            matrix = None
            if name == 'runtime-autostart-validation.yml':
                self.assertNotIn('previous', product)
                self.assertNotIn('npm install', product)
                self.assertNotIn('model_maintenance', product)
                self.assertIn('--register\n', product)
                self.assertIn('macos-15-intel', product)
                preparation = product.split('      - name: Prepare hosted Linux credentials and user systemd\n')[1].split('      - uses:')[0]
                for proof in ('test "$GITHUB_ACTIONS" = true', 'test "$RUNNER_ENVIRONMENT" = github-hosted',
                              'dbus-user-session dbus-x11 gnome-keyring', 'SecretStorage==3.3.3 jeepney==0.9.0 cryptography==46.0.3',
                              'sudo loginctl enable-linger "$(id -un)"', 'sudo systemctl restart "user@$uid.service"',
                              'sudo systemctl is-active --quiet "user@$uid.service"',
                              "stat -c '%u:%a'", 'test -S "$XDG_RUNTIME_DIR/bus"',
                              "NameHasOwner s org.freedesktop.systemd1)",
                              "GetConnectionUnixUser s org.freedesktop.systemd1)",
                              "= 'b true'", '= "u $uid"', '"DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS"'):
                    self.assertIn(proof, preparation)
                self.assertNotIn('dbus-run-session', preparation)
                self.assertLess(product.index('Prepare hosted Linux credentials and user systemd'), product.index('Build the current native CLI'))
                matrix = re.search(r'        include: \$\{\{ (.+) \}\}', product)[1]
            programs.append({'target': 'x86_64-pc-windows-msvc' if product_job == 'startup'
                             else 'x86_64-unknown-linux-gnu', 'program': body, 'matrix': matrix})
        # Execute only the workflow verifier with synthetic bytes; never install a product.
        check = r'''
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {posix} from 'node:path';
import {runInNewContext} from 'node:vm';
const programs=JSON.parse(readFileSync(0,'utf8'));
for(const {matrix} of programs) if(matrix) {
 for(const platform of ['all','windows-latest','macos-15-intel','ubuntu-latest']) {
  const selected=JSON.parse(JSON.stringify(runInNewContext(matrix,{inputs:{platform},fromJSON:JSON.parse})));
  assert.deepEqual(selected.map(row=>row.os),platform==='all'?['windows-latest','macos-15-intel','ubuntu-latest']:[platform]);
  for(const row of selected) assert.equal(row.target,{'windows-latest':'x86_64-pc-windows-msvc','macos-15-intel':'x86_64-apple-darwin','ubuntu-latest':'x86_64-unknown-linux-gnu'}[row.os]);
 }
}
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
for(const {target,program} of programs)for(const fault of ['', 'input', 'source', 'proof', 'image', 'core', 'target', 'version', 'installer']){
 const version='3.4.0-dev.1',suffix=target.includes('windows')?'.exe':'';
 const runtime=`/fixture/bin/runtime/${version}/rsrs-runtime${suffix}`;
 const core=Buffer.from('synthetic core inventory'),image=Buffer.from('synthetic Runtime; never executed');
 const metadata={schema_version:2,runtime_version:version,target_triple:target,source_commit:(fault==='source'?'b':'a').repeat(40),
  binary_sha256:hash(image),files:[{path:'core-runtime.json',sha256:hash(core)}]};
 if(fault==='target')metadata.target_triple='wrong-target';
 const encoded=JSON.stringify(metadata);
 const receipt={version:fault==='version'?'3.4.0-dev.2':version,sha256:hash(image),release:{metadata_json:encoded,metadata_sha256:fault==='proof'?'0'.repeat(64):hash(encoded)}};
 const files=new Map([['runtime-pin.json',JSON.stringify({required:version})],['/fixture/bin/runtime.json',JSON.stringify(receipt)],
  [runtime,fault==='image'?Buffer.from('changed'):image],[`/fixture/bin/runtime/${version}/core-runtime.json`,fault==='core'?Buffer.from('changed'):core]]);
 const writes=[];
 const sandbox={assert,createHash,join:posix.join,resolve:()=>'/cli',spawnSync:()=>assert.fail('No product execution in self-check'),
  mkdtempSync:()=>'/fixture',realpathSync:value=>value,statSync:()=>({isFile:()=>true}),
  readFileSync:file=>{assert(files.has(file),`Unexpected file ${file}`);return files.get(file);},appendFileSync:(file,value)=>writes.push(value),
  installPinnedRuntime:async()=>({status:fault==='installer'?1:0}),
  process:{env:{GITHUB_ACTIONS:'true',RUNTIME_FIXTURE_HOSTED:'true',EXPECTED_RUNTIME_SOURCE_SHA:fault==='input'?'':'a'.repeat(40),
   SDK_TARGET:target,EXE_SUFFIX:suffix,RUNNER_TEMP:'/temp',GITHUB_ENV:'/output'}}};
 const run=()=>runInNewContext('(async()=>{'+program+'})()',sandbox);
 if(fault){await assert.rejects(run);assert.equal(writes.length,0);}
 else {await run();assert.deepEqual(writes,[`RSRS_RUNTIME_BIN=${runtime}\n`]);}
}
console.log('PASS: both workflow verifiers bind explicit source and original receipt/image/core hashes; no product executed');
'''
        result = subprocess.run(['node', '--input-type=module', '-e', check], input=json.dumps(programs),
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_invalid_installation_never_rebinds_runtime(self):
        for fault in ('exit', 'image', 'target', 'proof', 'version', 'existing', 'host', 'outside'):
            with self.subTest(fault=fault):
                self.run_fixture(fault)


if __name__ == '__main__':
    unittest.main()
