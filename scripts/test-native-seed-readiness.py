"""Local control-flow tests, not a substitute for real native M3 evidence."""
import ast
import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace

SOURCE = pathlib.Path(__file__).with_name('test-real-m3-account-switch.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)
WAIT = next(node for node in ast.walk(TREE) if isinstance(node, ast.FunctionDef) and node.name == 'wait_index_ready')
SEED = next(node for node in ast.walk(TREE) if isinstance(node, ast.For)
            and ast.unparse(node.target) == 'profile'
            and any(isinstance(child, ast.If) and ast.unparse(child.test) == 'args.seed_binary' for child in node.body))


def execute(nodes, namespace):
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<fixture-control-flow>', 'exec'), namespace)


class SeedReadinessTests(unittest.TestCase):
    def exercise_ai(self, ready_after=2, missing=False, failure=None):
        tree = ast.parse(pathlib.Path(__file__).with_name('dev-ai-inject-smoke.py').read_text(encoding='utf-8'))
        wait = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'wait_index_ready')
        self.assertEqual(len(wait.args.args), 1)
        state = {'polls': 0}

        def cli(*command):
            self.assertEqual(command, ('doctor',))  # No tree-cure write is replayed.
            state['polls'] += 1
            if failure == 'command':
                raise RuntimeError('cli_failed_doctor')
            ready = state['polls'] >= ready_after
            doctor = {'command': 'doctor', 'status': 'ok' if ready else 'warn', 'errors': [],
                      'items': [{'name': name, 'status': 'ok' if ready else 'warn'}
                                for name in (('embedder',) if missing else ('embedder', 'model index'))],
                      'details': {'retrieval_index': {'state': 'ready' if ready else 'running', 'error': None}}}
            if failure == 'status':
                doctor['status'] = 'fail'
            elif failure == 'errors':
                doctor['errors'] = ['actual doctor failure']
            elif failure == 'item':
                doctor['items'][0]['status'] = 'fail'
            elif failure == 'row-status':
                doctor['items'][0]['status'] = 'unsupported'
            elif failure in ('failed', 'unsupported', 'paused'):
                doctor['details']['retrieval_index']['state'] = failure
            elif failure == 'index-error':
                doctor['details']['retrieval_index']['error'] = 'index failed'
            elif failure == 'diagnostic':
                del doctor['details']['retrieval_index']
            return doctor

        def require(value, code):
            if not value:
                raise RuntimeError(code)

        def sleep(seconds):
            self.assertIsNone(failure, 'doctor failure must not enter another wait')

        namespace = dict(require=require, time=SimpleNamespace(sleep=sleep))
        execute([wait], namespace)
        namespace['wait_index_ready'](SimpleNamespace(cli=cli))
        run = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'run')
        statements = [ast.unparse(node) for node in run.body]
        orphan = next(i for i, text in enumerate(statements) if text.startswith('orphan ='))
        self.assertEqual(statements[orphan + 2], 'self.wait_index_ready()')
        self.assertEqual(statements[orphan + 3], "result = self.cli('tree-cure', '--auto', '--min', '0.5')")
        self.assertIn("result['status'] == 'ok'", statements[orphan + 5])
        return state

    def exercise(self, directory, *, historical=False, runtime=True, artifacts='ready', ready_after=2,
                 seed_version='1.0.7', occupied=False):
        main = pathlib.Path(directory) / 'main'
        alternate = pathlib.Path(directory) / 'alternate'
        main.mkdir(); alternate.mkdir()
        if occupied:
            (main / 'rsrs.db').touch()
        events = []
        self.legacy_commands = []
        state = {'profile': None, 'alive': False, 'polls': 0, 'clock': 0}

        def select(profile):
            self.assertFalse(state['alive'], 'profile changed before owner stopped')
            state.update(profile=profile, polls=0)
            events.append(('select', profile.name))

        def run(*command, **kwargs):
            if 'remember' in command:
                state['alive'] = runtime
                events.append(('remember', state['profile'].name))
                return {}
            self.assertEqual(command, ('doctor',))
            self.assertTrue(state['alive'], 'readiness queried after owner stopped')
            state['polls'] += 1
            events.append(('doctor', state['profile'].name))
            ready = state['polls'] >= ready_after
            if ready and artifacts != 'missing':
                index = state['profile'] / 'core-index'
                index.mkdir(exist_ok=True)
                if artifacts != 'empty-directory':
                    (index / 'fixture.index').write_bytes(b'actual-test-bytes' if artifacts == 'ready' else b'')
            return {'items': [{'name': name, 'status': 'ok' if ready else 'pending'}
                              for name in ('embedder', 'model index')]}

        def captured_run(command, **kwargs):
            if '--stop' in command:
                self.assertTrue(state['alive'])
                events.append(('stop', state['profile'].name))
                state['alive'] = False
            else:
                self.assertTrue(historical)
                self.assertIn('--direct', command)
                events.append(('legacy', state['profile'].name))
                self.legacy_commands.append((state['profile'].name, tuple(command[3:])))
                if command[-1] == '--version':
                    return SimpleNamespace(returncode=0, stdout=('rsrs ' + seed_version).encode('utf-8'), stderr=b'')
                if command[-1] == 'v':
                    return SimpleNamespace(returncode=0,
                                           stdout=json.dumps({'summary': {'version': seed_version}}).encode('utf-8'), stderr=b'')
            return SimpleNamespace(returncode=0, stdout=b'{"summary":{"id":"tombstone"}}', stderr=b'')

        def sleep(seconds):
            state['clock'] += 60  # Exercise the actual deadline without wall-clock waiting.

        namespace = dict(args=SimpleNamespace(seed_binary='old' if historical else None,
                                             runtime_binary='runtime' if runtime else None,
                                             database_dev_checkpoint=None),
                         main=main, alternate=alternate, binary='cli', pathlib=pathlib, json=json,
                         env={}, seed_env={}, select=select, run=run, captured_run=captured_run,
                         time=SimpleNamespace(monotonic=lambda: state['clock'], sleep=sleep))
        execute([WAIT], namespace)
        self.events, self.state = events, state
        execute([SEED], namespace)
        return events

    def test_each_selected_owner_finishes_index_before_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            events = self.exercise(directory)
            self.assertEqual(events, [(event, profile) for profile in ('main', 'alternate')
                                     for event in ('select', 'remember', 'doctor', 'doctor', 'stop')])
        self.assertEqual(self.exercise_ai()['polls'], 2)

    def test_timeout_fails_without_stopping_or_selecting_next_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AssertionError):
                self.exercise(directory, ready_after=100)
            self.assertTrue(self.state['alive'])
            self.assertEqual(sum(event == 'doctor' for event, _ in self.events), 4)
            self.assertFalse(any(event == 'stop' or profile == 'alternate' for event, profile in self.events))

    def test_missing_index_fails_even_with_ok_doctor(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                self.exercise(directory, artifacts='missing')
            self.assertFalse(any(event == 'stop' for event, _ in self.events))
        with self.assertRaisesRegex(RuntimeError, 'cure_index_readiness_missing'):
            self.exercise_ai(ready_after=1, missing=True)
        for failure in ('command', 'status', 'errors', 'item', 'row-status', 'failed', 'unsupported', 'paused', 'index-error'):
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                self.exercise_ai(failure=failure)
        with self.assertRaises(KeyError):
            self.exercise_ai(failure='diagnostic')

    def test_empty_actual_artifacts_fail_even_with_ok_doctor(self):
        for artifacts in ('empty-directory', 'empty-file'):
            with self.subTest(artifacts=artifacts), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(AssertionError, 'seed index artifacts missing or empty'):
                    self.exercise(directory, artifacts=artifacts)
                self.assertFalse(any(event == 'stop' for event, _ in self.events))

    def test_historical_seeding_stays_direct_without_new_readiness_calls(self):
        for version in ('1.0.7', '1.0.8', '1.0.9', '1.0.21', '1.0.20-dev.1'):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                self.exercise(directory, historical=True, seed_version=version)
                self.assertEqual([command[:3] for _, command in self.legacy_commands],
                                 [('v',), ('model', 'activate', 'm3'), ('remember', 'Real account return fixture main', '--title'),
                                  ('remember', 'Historical encrypted deletion main', '--title'), ('forget', 'tombstone'),
                                  ('v',), ('model', 'activate', 'm3'), ('remember', 'Real account return fixture alternate', '--title'),
                                  ('remember', 'Historical encrypted deletion alternate', '--title'), ('forget', 'tombstone')])
        for version in ('1.0.11-dev.1', '1.0.11', '1.0.12', '1.0.15', '1.0.16',
                        '1.0.17-dev.6', '1.0.18', '1.0.19', '1.0.20'):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                events = self.exercise(directory, historical=True, seed_version=version)
                self.assertEqual(events, [(event, profile) for profile in ('main', 'alternate')
                                         for event in ('select', 'legacy', 'legacy', 'legacy', 'legacy')])
                self.assertFalse(any(command[:2] == ('model', 'activate') for _, command in self.legacy_commands))
                self.assertTrue(all('--importance' in command and 'important' in command and '--force' in command
                                    for _, command in self.legacy_commands if command[0] == 'remember'))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(AssertionError, 'historical seed profile is not empty'):
                self.exercise(directory, historical=True, seed_version='1.0.20', occupied=True)
            self.assertEqual(self.legacy_commands, [('main', ('v',))])
        with tempfile.TemporaryDirectory() as directory:
            self.exercise(directory, historical=True)
            old_host = next(node for node in ast.walk(TREE) if isinstance(node, ast.If)
                            and any(isinstance(child, ast.Assign) and any(
                                isinstance(target, ast.Name) and target.id == 'web_help'
                                for target in child.targets) for child in node.body))
            execute([old_host], dict(args=SimpleNamespace(seed_binary='old'), database_upgrade=True))
            reopen = next(node for node in ast.walk(TREE) if isinstance(node, ast.If)
                          and ast.unparse(node.test) == 'database_upgrade')
            main, alternate = pathlib.Path(directory) / 'main', pathlib.Path(directory) / 'alternate'
            for stop_code, same_owner, corrupt in ((0, False, False), (1, False, False),
                                                   (0, True, False), (0, False, True)):
                events = []
                state = {'closed': False, 'profile': main}
                snapshots = {str(main): 'main-state', str(alternate): 'alternate-state'}

                def stop(*command, **kwargs):
                    events.append('stop')
                    self.assertIn('--stop', command[0])
                    state['closed'] = True
                    return SimpleNamespace(returncode=stop_code)

                def run(*command):
                    self.assertNotIn('restart', command)
                    if command[0] == 'account':
                        events.append('open-' + command[2])
                        self.assertTrue(state['closed'])
                        state['profile'] = main if command[2] == 'main' else alternate
                        return {}
                    self.assertEqual(command[0], 'recall')
                    if corrupt:
                        snapshots[str(state['profile'])] = 'changed-record-or-key'
                    return {'items': ['actual-fixture-result']}

                namespace = dict(database_upgrade=True, normal_reopen_checked=False,
                    main=main, alternate=alternate, binary='cli', env={},
                    recovery_factors={str(main): {}, str(alternate): {}},
                    snapshot=lambda profile: snapshots[str(profile)], library_state=lambda value, factors: value,
                    observe_runtime=lambda: {'pid': 7, 'instance_id': 'old' if not state['closed'] or same_owner else 'new'},
                    psutil=SimpleNamespace(Process=lambda pid: SimpleNamespace(pid=pid, create_time=lambda: 1,
                        children=lambda **kwargs: [])),
                    captured_run=stop, confirm_workers_exited=lambda identities: events.append('reap'),
                    run=run, wait_index_ready=lambda: events.append('ready'))
                if stop_code or same_owner or corrupt:
                    with self.assertRaises(AssertionError):
                        execute([reopen], namespace)
                    self.assertFalse(namespace['normal_reopen_checked'])
                else:
                    execute([reopen], namespace)
                    self.assertTrue(namespace['normal_reopen_checked'])
                    self.assertEqual(events[:3], ['stop', 'reap', 'open-main'])
                    self.assertIn('open-alternate', events)
                if stop_code:
                    self.assertEqual(events, ['stop'])

    def test_in_process_seeding_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.exercise(directory, runtime=False),
                             [(event, profile) for profile in ('main', 'alternate')
                              for event in ('select', 'remember')])


if __name__ == '__main__':
    unittest.main()
