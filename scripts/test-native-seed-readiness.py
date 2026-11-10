"""Local control-flow tests, not a substitute for real native M3 evidence."""
import ast
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
    def exercise(self, directory, *, historical=False, runtime=True, artifacts='ready', ready_after=2):
        main = pathlib.Path(directory) / 'main'
        alternate = pathlib.Path(directory) / 'alternate'
        main.mkdir(); alternate.mkdir()
        events = []
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
            return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

        def sleep(seconds):
            state['clock'] += 60  # Exercise the actual deadline without wall-clock waiting.

        namespace = dict(args=SimpleNamespace(seed_binary='old' if historical else None,
                                             runtime_binary='runtime' if runtime else None),
                         main=main, alternate=alternate, binary='cli', pathlib=pathlib,
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

    def test_empty_actual_artifacts_fail_even_with_ok_doctor(self):
        for artifacts in ('empty-directory', 'empty-file'):
            with self.subTest(artifacts=artifacts), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(AssertionError, 'seed index artifacts missing or empty'):
                    self.exercise(directory, artifacts=artifacts)
                self.assertFalse(any(event == 'stop' for event, _ in self.events))

    def test_historical_seeding_stays_direct_without_new_readiness_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.exercise(directory, historical=True),
                             [(event, profile) for profile in ('main', 'alternate')
                              for event in ('select', 'legacy', 'legacy')])

    def test_in_process_seeding_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.exercise(directory, runtime=False),
                             [(event, profile) for profile in ('main', 'alternate')
                              for event in ('select', 'remember')])


if __name__ == '__main__':
    unittest.main()
