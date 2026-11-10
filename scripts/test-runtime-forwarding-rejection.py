"""Synthetic subprocess/socket tests only; never launch CLI or Runtime."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('runtime_smoke', Path(__file__).with_name('dev-runtime-smoke.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
SECRET = 'private-token-user-path-secret'
CASES = [('0.0.0.0', 'nonloopback_unspecified_ipv4'),
         ('192.0.2.1', 'nonloopback_documentation_ipv4'),
         ('example.invalid', 'nonloopback_dns')]


class RejectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.smoke = runtime.Smoke.__new__(runtime.Smoke)
        self.smoke.root = Path(self.temp.name)
        (self.smoke.root / 'runtime').mkdir()
        self.smoke.args = types.SimpleNamespace(binary=Path(SECRET), runtime_binary=Path('owned-runtime'))
        self.smoke.env = {'HOME': SECRET}
        self.smoke.port = 12345
        self.smoke.report = {}
        self.socket_patch = patch.object(runtime.socket, 'socket')
        self.sock = self.socket_patch.start().return_value.__enter__.return_value
        self.sock.connect_ex.return_value = 111
        self.addCleanup(self.socket_patch.stop)

    def results(self, host):
        reason = ('local runtime requires a literal loopback IP or localhost' if host == 'example.invalid'
                  else 'local runtime cannot bind a non-loopback address')
        return [subprocess.CompletedProcess([], 2, f'runtime=starting host={host} port=12345\n',
                                             'rsrs-runtime: ' + reason + '\n'),
                subprocess.CompletedProcess([], 2, '', '')]

    def test_all_hosts_two_separate_paths_and_no_secrets(self):
        for host, case in CASES:
            with patch.object(runtime, 'contained_rejection_run', side_effect=self.results(host)) as run:
                self.smoke.nonloopback(host, case)
                self.assertEqual(run.call_count, 2)
                self.assertEqual(run.call_args_list[0].args[0], ['owned-runtime', 'serve', '--host', host, '--port', '12345'])
                self.assertIn('--runtime-internal', run.call_args_list[1].args[0])
                self.assertNotIn('--supervised', run.call_args_list[0].args[0])
                self.assertEqual(self.smoke.report, {})
        self.assertEqual(self.sock.connect_ex.call_count, 15)

    def test_wrong_exit_in_either_path_fails_closed(self):
        for host, case in CASES:
            for index in (0, 1):
                for code in (0, 1, 3, -11, True, None):
                    results = self.results(host)
                    results[index].returncode = code
                    with patch.object(runtime, 'contained_rejection_run', side_effect=results):
                        with self.assertRaisesRegex(runtime.Failure, '^nonloopback_exit_mismatch$'):
                            self.smoke.nonloopback(host, case)
                    self.assertNotIn(SECRET, json.dumps(self.smoke.report))

    def test_wrong_reason_clap_panic_auth_and_mixed_output_rejected(self):
        for host, case in CASES:
            for index in (0, 1):
                for field in ('stdout', 'stderr'):
                    for text in ('error: unexpected argument', 'thread panicked',
                                 'rsrs-runtime: runtime launch grant is missing or consumed\n',
                                 SECRET, 'success\n', '',
                                 'rsrs-runtime: local runtime requires an exclusively loopback localhost address\n'):
                        if index == 1 and text == '':
                            continue
                        results = self.results(host)
                        setattr(results[index], field, text)
                        with patch.object(runtime, 'contained_rejection_run', side_effect=results):
                            with self.assertRaises(runtime.Failure):
                                self.smoke.nonloopback(host, case)
                        self.assertNotIn(SECRET, json.dumps(self.smoke.report))
            results = self.results(host)
            results[0].stderr += SECRET
            with patch.object(runtime, 'contained_rejection_run', side_effect=results):
                with self.assertRaisesRegex(runtime.Failure, 'reason_mismatch'):
                    self.smoke.nonloopback(host, case)

    def test_no_listener_endpoint_or_token_before_or_after_each_process(self):
        host, case = CASES[0]
        for name in ('endpoint.json', 'token'):
            target = self.smoke.root / 'runtime' / name
            for stage in ('before', 0, 1):
                target.unlink(missing_ok=True)
                results = iter(self.results(host))
                calls = []
                def run(*args, **kwargs):
                    calls.append(1)
                    if len(calls) - 1 == stage:
                        target.write_text(SECRET)
                    return next(results)
                if stage == 'before':
                    target.write_text(SECRET)
                with patch.object(runtime, 'contained_rejection_run', side_effect=run):
                    with self.assertRaisesRegex(runtime.Failure, 'created_endpoint_or_token'):
                        self.smoke.nonloopback(host, case)
                self.assertEqual(len(calls), 0 if stage == 'before' else stage + 1)
                target.unlink()
        for stage in (0, 2, 4):
            self.sock.connect_ex.side_effect = [111] * stage + [0]
            with patch.object(runtime, 'contained_rejection_run', side_effect=self.results(host)):
                with self.assertRaisesRegex(runtime.Failure, 'left_listener'):
                    self.smoke.nonloopback(host, case)
        self.sock.connect_ex.side_effect = None

    def test_execution_errors_redacted(self):
        for error in (OSError(SECRET), subprocess.TimeoutExpired(SECRET, 90, output=SECRET, stderr=SECRET)):
            with patch.object(runtime, 'contained_rejection_run', side_effect=error):
                with self.assertRaisesRegex(runtime.Failure, '^nonloopback_execution_failed$'):
                    self.smoke.nonloopback(*CASES[0])
            self.assertNotIn(SECRET, json.dumps(self.smoke.report))

    def test_exception_always_runs_postcheck(self):
        for error in (OSError(SECRET), runtime.Failure('nonloopback_cleanup_failed')):
            for effect in ('listener', 'endpoint.json', 'token'):
                def fail(*args, **kwargs):
                    if effect == 'listener':
                        self.sock.connect_ex.return_value = 0
                    else:
                        (self.smoke.root / 'runtime' / effect).write_text(SECRET)
                    raise error
                with patch.object(runtime, 'contained_rejection_run', side_effect=fail):
                    with self.assertRaisesRegex(runtime.Failure, 'left_listener|created_endpoint_or_token'):
                        self.smoke.nonloopback(*CASES[0])
                self.sock.connect_ex.return_value = 111
                for name in ('endpoint.json', 'token'):
                    (self.smoke.root / 'runtime' / name).unlink(missing_ok=True)

    def test_supervisor_cleans_on_timeout_success_and_failure(self):
        from unittest.mock import MagicMock
        for error in (None, OSError(SECRET), subprocess.TimeoutExpired(SECRET, 90)):
            for leaked in (False, True):
                connection = MagicMock()
                process = MagicMock()
                process.poll.return_value = 2
                process.returncode = 2
                if error:
                    process.communicate.side_effect = error
                else:
                    process.communicate.return_value = ('', '')
                with patch.object(runtime.ctypes, 'CDLL') as libc, \
                     patch.object(runtime.signal, 'signal'), \
                     patch.object(runtime, 'preflight_rejection_pidfd'), \
                     patch.object(runtime.subprocess, 'Popen', return_value=process), \
                     patch.object(runtime, 'reap_rejection_children', return_value=leaked) as cleanup:
                    libc.return_value.prctl.return_value = 0
                    runtime.rejection_supervisor(connection, ['owned'], {}, '.', 90)
                    cleanup.assert_called_once()
                    process.wait.assert_called_once()
                    result = connection.send.call_args.args[0]
                    self.assertNotIn(SECRET, json.dumps(result))
                    self.assertEqual('error' in result, leaked or error is not None)
                    if leaked:
                        self.assertEqual(result['error'], 'nonloopback_descendant_cleanup_required')

    def test_reaper_kills_only_owned_children_and_waits_for_adoption(self):
        # Child 20 detaches, then is adopted after CLI 10 is killed/reaped.
        with patch.object(runtime, 'rejection_children', side_effect=[[10], [20], []]), \
             patch.object(runtime, 'kill_rejection_child') as kill, \
             patch.object(runtime.os, 'waitpid', side_effect=[(10, 0), (0, 0), (20, 0), (0, 0)]), \
             patch.object(runtime.time, 'sleep'):
            self.assertTrue(runtime.reap_rejection_children(runtime.time.monotonic() + 5))
            self.assertEqual([call.args[0] for call in kill.call_args_list], [10, 20])

    def test_pidfd_birth_and_ancestry_checked_before_signal(self):
        fields = ['S'] + ['0'] * 18 + ['123']
        raw = '20 (owned) ' + ' '.join(fields)
        for changed, owned in ((False, True), (True, True), (False, False)):
            reads = [raw, raw.replace('123', '456') if changed else raw]
            with patch.object(Path, 'read_text', side_effect=reads), \
                 patch.object(runtime.os, 'pidfd_open', return_value=99), \
                 patch.object(runtime.os, 'close') as close, \
                 patch.object(runtime, 'rejection_children', return_value=[20] if owned else []), \
                 patch.object(runtime.signal, 'pidfd_send_signal') as kill:
                if changed or not owned:
                    with self.assertRaisesRegex(runtime.Failure, 'identity_failed'):
                        runtime.kill_rejection_child(20)
                    kill.assert_not_called()
                else:
                    runtime.kill_rejection_child(20)
                    kill.assert_called_once_with(99, runtime.signal.SIGKILL)
                close.assert_called_once_with(99)

    def test_partial_cleanup_attempts_every_child_and_preserves_failure(self):
        with patch.object(runtime, 'rejection_children', side_effect=[[10, 20], [10], []]), \
             patch.object(runtime, 'kill_rejection_child', side_effect=[OSError(SECRET), False, False]) as kill, \
             patch.object(runtime.os, 'waitpid', return_value=(0, 0)), \
             patch.object(runtime.time, 'sleep'):
            with self.assertRaisesRegex(runtime.Failure, '^nonloopback_cleanup_failed$'):
                runtime.reap_rejection_children(runtime.time.monotonic() + 5)
            self.assertEqual([call.args[0] for call in kill.call_args_list], [10, 20, 10])

    def test_pidfd_unavailable_prevents_product_launch(self):
        from unittest.mock import MagicMock
        connection = MagicMock()
        with patch.object(runtime.ctypes, 'CDLL') as libc, \
             patch.object(runtime.signal, 'signal'), \
             patch.object(runtime.os, 'pidfd_open', side_effect=OSError(SECRET)), \
             patch.object(runtime.subprocess, 'Popen') as launch, \
             patch.object(runtime, 'reap_rejection_children', return_value=False):
            libc.return_value.prctl.return_value = 0
            runtime.rejection_supervisor(connection, ['owned'], {}, '.', 90)
            launch.assert_not_called()
            self.assertEqual(connection.send.call_args.args[0], {'error': 'nonloopback_execution_failed'})

    def test_resource_failure_fallback_requires_owned_unreaped_child(self):
        raw = '20 (owned) ' + ' '.join(['S'] + ['0'] * 18 + ['123'])
        for owned in (True, False):
            with patch.object(Path, 'read_text', return_value=raw), \
                 patch.object(runtime.os, 'pidfd_open', side_effect=OSError(SECRET)), \
                 patch.object(runtime, 'rejection_children', return_value=[20] if owned else []), \
                 patch.object(runtime.os, 'kill') as kill:
                if owned:
                    self.assertTrue(runtime.kill_rejection_child(20))
                    kill.assert_called_once_with(20, runtime.signal.SIGKILL)
                else:
                    with self.assertRaises(runtime.Failure):
                        runtime.kill_rejection_child(20)
                    kill.assert_not_called()

    def test_wrapper_lifecycle_success_start_eof_poll_and_join_failures(self):
        from unittest.mock import MagicMock
        for scenario in ('success', 'start', 'eof', 'poll_timeout', 'poll_recovered', 'join_live', 'exit_failed', 'cleanup_failed'):
            context, reader, writer, process = (MagicMock() for _ in range(4))
            context.Pipe.return_value = (reader, writer)
            context.Process.return_value = process
            process.is_alive.return_value = False
            process.exitcode = 0
            reader.poll.return_value = True
            reader.recv.return_value = {'returncode': 2, 'stdout': '', 'stderr': ''}
            if scenario == 'start':
                process.start.side_effect = OSError(SECRET)
            if scenario == 'eof':
                reader.recv.side_effect = EOFError(SECRET)
            if scenario == 'poll_timeout':
                reader.poll.return_value = False
            if scenario == 'poll_recovered':
                reader.poll.side_effect = [False, True]
            if scenario == 'join_live':
                process.is_alive.return_value = True
            if scenario == 'exit_failed':
                process.exitcode = 1
            if scenario == 'cleanup_failed':
                reader.recv.return_value = {'error': 'nonloopback_cleanup_failed'}
            with patch.object(runtime.multiprocessing, 'get_context', return_value=context):
                if scenario == 'success':
                    self.assertEqual(runtime.contained_rejection_run(['owned'], {}, '.', 1).returncode, 2)
                else:
                    with self.assertRaises(runtime.Failure) as caught:
                        runtime.contained_rejection_run(['owned'], {}, '.', 1)
                    self.assertNotIn(SECRET, str(caught.exception))
            reader.close.assert_called()
            writer.close.assert_called()
            if scenario == 'start':
                process.join.assert_not_called()
                process.terminate.assert_not_called()
            if scenario == 'join_live':
                process.terminate.assert_called()
                self.assertIn(((10,), {}), [(call.args, call.kwargs) for call in process.join.call_args_list])

    def test_legacy_stays_on_original_contract_and_invalid_case_never_runs(self):
        self.smoke.args.runtime_binary = None
        with patch.object(self.smoke, 'direct') as direct, patch.object(runtime, 'contained_rejection_run') as run:
            self.smoke.nonloopback(*CASES[0])
            self.assertEqual(direct.call_args.kwargs['expected'], 1)
            with self.assertRaisesRegex(runtime.Failure, 'case_invalid'):
                self.smoke.nonloopback(SECRET, SECRET)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
