"""Offline fixture installation tests; no credentials, downloads or live processes."""
import hashlib
import ast
import json
import os
import re
import subprocess
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from native_fixture_process import install_official_runtime, same_existing_path, canonical_scope_path, runtime_scope_ids


class FixtureInstallationTests(unittest.TestCase):
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
            programs.append({'target': 'x86_64-pc-windows-msvc' if product_job == 'startup'
                             else 'x86_64-unknown-linux-gnu', 'program': body})
        # Execute only the workflow verifier with synthetic bytes; never install a product.
        check = r'''
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {posix} from 'node:path';
import {runInNewContext} from 'node:vm';
const programs=JSON.parse(readFileSync(0,'utf8'));
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
