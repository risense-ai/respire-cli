"""Bound native-test process waits, including Windows handle inspection.

The inspector preserves boundary assertions in a disposable process: a hung
psutil native call must fail acceptance rather than hang its Python controller.
"""
import json
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import secrets


def add_runtime_arguments(parser):
    parser.add_argument('--runtime-binary', default=os.environ.get('RSRS_RUNTIME_BIN'))
    parser.add_argument('--runtime-sha256', default=os.environ.get('RSRS_PUBLISHED_RUNTIME_SHA256'))
    parser.add_argument('--runtime-version', default=os.environ.get('RSRS_PUBLISHED_RUNTIME_VERSION'))


def runtime_inputs(args, cli_binaries):
    values = (args.runtime_binary, args.runtime_sha256, args.runtime_version)
    published = os.environ.get('RSRS_ARTIFACT_SOURCE') == 'published-assets'
    if not published and not any(values[1:]):
        args.runtime_binary = None
        return
    if not all(values):
        raise ValueError('complete standalone Runtime path, digest and version required')
    if published and (os.environ.get('GITHUB_ACTIONS') != 'true'
                      or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise ValueError('published Runtime fixtures require a dedicated GitHub-hosted runner')
    args.runtime_binary = pathlib.Path(args.runtime_binary).resolve(strict=True)
    if any(args.runtime_binary.samefile(path) for path in cli_binaries):
        raise ValueError('CLI shim cannot substitute for standalone Runtime')
    args.runtime_sha256 = args.runtime_sha256.lower()
    if len(args.runtime_sha256) != 64 or any(c not in '0123456789abcdef' for c in args.runtime_sha256):
        raise ValueError('invalid Runtime image digest')
    with args.runtime_binary.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != args.runtime_sha256:
            raise ValueError('Runtime image digest mismatch')
    for key in ('RSRS_PUBLISHED_ASSETS_SHA256', 'RSRS_PUBLISHED_BUNDLE_SHA256'):
        value = os.environ.get(key, '')
        if published and (len(value) != 64 or any(c not in '0123456789abcdef' for c in value)):
            raise ValueError('published Runtime provenance missing: ' + key)
    args.runtime_identity_receipts = []


def process_start_id(pid):
    if sys.platform.startswith('linux'):
        raw = pathlib.Path('/proc', str(pid), 'stat').read_text()
        fields = raw[raw.rindex(')') + 2:].split()
        if fields[0] == 'Z':
            raise ProcessLookupError('Runtime owner is a zombie')
        return 'linux-starttime-' + fields[19]
    if sys.platform == 'win32':
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                raise ctypes.WinError(ctypes.get_last_error())
            exit_code = wintypes.DWORD()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                raise ctypes.WinError(ctypes.get_last_error())
            if exit_code.value != 259:  # STILL_ACTIVE
                raise ProcessLookupError('Runtime owner exited')
            return 'windows-filetime-' + str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)
        finally:
            kernel.CloseHandle(handle)
    if sys.platform == 'darwin':
        value = captured_run(['ps', '-p', str(pid), '-o', 'lstart='],
                             env={**os.environ, 'LC_ALL': 'C'}, timeout=5)
        if value.returncode or not value.stdout.strip():
            raise ProcessLookupError('Runtime birth unavailable')
        return 'darwin-lstart-' + value.stdout.decode().strip()
    raise RuntimeError('authoritative Runtime birth unsupported on this platform')


def install_official_runtime(binary, env, version, binary_hash):
    """Install the pinned Runtime into a fresh source-build fixture, then bind its identity."""
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise ValueError('official installation requires a dedicated GitHub-hosted runner')
    root = pathlib.Path(env['RSRS_DATA_DIR'])
    if root.is_symlink():
        raise ValueError('official installation root must not be linked')
    root = root.resolve()
    if not any(root != pathlib.Path(os.environ[key]).resolve()
               and root.is_relative_to(pathlib.Path(os.environ[key]).resolve())
               for key in ('RUNNER_TEMP', 'GITHUB_WORKSPACE') if os.environ.get(key)):
        raise ValueError('official installation must remain inside the owned runner workspace')
    if (root / 'runtime.json').exists():
        raise ValueError('source-build fixture must start without a Runtime receipt')
    install_env = {key: value for key, value in env.items()
                   if key not in ('RSRS_RUNTIME_BIN', 'RSRS_CORE_TEST_MODE', 'GH_TOKEN', 'GITHUB_TOKEN')
                   and not key.endswith(('_TOKEN', '_API_KEY'))}
    result = subprocess.run([str(binary), '--json', 'runtime', 'install'],
                            env=install_env, capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError('official Runtime fixture install failed: exit ' + str(result.returncode))
    receipt = json.loads((root / 'runtime.json').read_text(encoding='utf-8'))
    proof = receipt.get('release') or {}
    metadata_bytes = proof.get('metadata_json', '').encode('utf-8')
    metadata = json.loads(metadata_bytes)
    installed = root / 'runtime' / version / ('rsrs-runtime.exe' if os.name == 'nt' else 'rsrs-runtime')
    if (receipt.get('version') != version or receipt.get('sha256') != binary_hash
            or proof.get('metadata_sha256') != hashlib.sha256(metadata_bytes).hexdigest()
            or metadata.get('schema_version') != 2 or metadata.get('runtime_version') != version
            or (metadata.get('target_triple') or metadata.get('triple')) != env['RSRS_RUNTIME_TRIPLE']
            or metadata.get('binary_sha256') != binary_hash
            or installed.is_symlink() or not installed.resolve().is_relative_to(root)):
        raise ValueError('fixture installation differs from the selected official Runtime')
    with installed.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != binary_hash:
            raise ValueError('fixture Runtime image differs from the selected asset')
    env['RSRS_RUNTIME_BIN'] = str(installed.resolve(strict=True))
    return installed.resolve(strict=True)


def install_published_runtime(binary, env):
    """Use the real offline installer with the selected release's unchanged bytes."""
    if os.environ.get('RSRS_ARTIFACT_SOURCE') != 'published-assets':
        return None
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise ValueError('published installation requires a dedicated GitHub-hosted runner')
    root = pathlib.Path(env.get('RSRS_DATA_DIR') or pathlib.Path(env['HOME']) / '.rsrs')
    if root.is_symlink():
        raise ValueError('published installation root must not be linked')
    root = root.resolve()
    if not any(root != pathlib.Path(os.environ[key]).resolve()
               and root.is_relative_to(pathlib.Path(os.environ[key]).resolve())
               for key in ('RUNNER_TEMP', 'GITHUB_WORKSPACE') if os.environ.get(key)):
        raise ValueError('published installation must remain inside the owned runner workspace')
    archive = pathlib.Path(os.environ['RSRS_PUBLISHED_RUNTIME_ARCHIVE']).resolve(strict=True)
    metadata_path = pathlib.Path(os.environ['RSRS_PUBLISHED_RUNTIME_METADATA']).resolve(strict=True)
    version = os.environ['RSRS_PUBLISHED_RUNTIME_VERSION']
    triple = os.environ['RSRS_RUNTIME_TRIPLE']
    if metadata_path != archive.with_name('runtime-build-' + triple + '.json'):
        raise ValueError('offline installation requires the selected adjacent metadata')
    metadata_bytes = metadata_path.read_bytes()
    metadata_hash = hashlib.sha256(metadata_bytes).hexdigest()
    with archive.open('rb') as stream:
        archive_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    metadata = json.loads(metadata_bytes)
    binary_hash = os.environ['RSRS_PUBLISHED_RUNTIME_SHA256']
    if (metadata_hash != os.environ['RSRS_PUBLISHED_RUNTIME_METADATA_SHA256']
            or archive_hash != os.environ['RSRS_PUBLISHED_BUNDLE_SHA256']
            or metadata.get('schema_version') != 2 or metadata.get('runtime_version') != version
            or metadata.get('target_triple') != triple or metadata.get('archive_sha256') != archive_hash
            or metadata.get('binary_sha256') != binary_hash):
        raise ValueError('selected published Runtime bytes or identity changed')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == 'posix':
        root.chmod(0o700)
    receipt_path = root / 'runtime.json'
    if not receipt_path.exists():
        install_env = {key: value for key, value in env.items()
                       if key not in ('RSRS_RUNTIME_BIN', 'RSRS_CORE_TEST_MODE', 'GH_TOKEN', 'GITHUB_TOKEN')
                       and not key.endswith(('_TOKEN', '_API_KEY'))}
        install_env.update(RSRS_DATA_DIR=str(root), RSRS_RUNTIME_TRIPLE=triple,
                           RSRS_UPDATE_CHECK='0', RSRS_NO_AUTOSYNC='1')
        result = subprocess.run([str(binary), '--json', 'runtime', 'install', '--file', str(archive),
                                 '--version', version], env=install_env, capture_output=True, timeout=180)
        if result.returncode:
            raise RuntimeError('selected published Runtime offline install failed: exit ' + str(result.returncode))
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    proof = receipt.get('release', {})
    installed = root / 'runtime' / version / ('rsrs-runtime.exe' if os.name == 'nt' else 'rsrs-runtime')
    if (receipt.get('version') != version or receipt.get('sha256') != binary_hash
            or proof.get('metadata_sha256') != metadata_hash
            or proof.get('metadata_json', '').encode('utf-8') != metadata_bytes
            or installed.is_symlink() or not installed.resolve().is_relative_to(root)):
        raise ValueError('managed installation does not preserve the selected release proof')
    with installed.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != binary_hash:
            raise ValueError('managed installation image differs from the selected asset')
    env['RSRS_RUNTIME_BIN'] = str(installed.resolve(strict=True))
    env['RSRS_RUNTIME_TRIPLE'] = triple
    return installed.resolve(strict=True)


def verify_runtime_health(args, health, root, profile, pid=None):
    import psutil
    root, profile = pathlib.Path(root).resolve(strict=True), pathlib.Path(profile).resolve(strict=True)
    if not profile.is_relative_to(root):
        raise AssertionError('Runtime profile escaped the owned fixture installation')
    if os.name == 'posix' and (root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077):
        raise AssertionError('Runtime fixture installation must be private and owned')
    owner = psutil.Process(health['pid'])
    birth, created = process_start_id(owner.pid), owner.create_time()
    image = pathlib.Path(owner.exe()).resolve(strict=True)
    session_path = profile / 'session.json'
    session = json.loads(session_path.read_text(encoding='utf-8')) if session_path.exists() else {}
    account_source = session.get('user') or health.get('data_dir', '')
    if (type(health.get('v')) is not int or health['v'] != 1 or (pid is not None and owner.pid != pid)
            or image != ((root / 'runtime' / args.runtime_version /
                          ('rsrs-runtime.exe' if os.name == 'nt' else 'rsrs-runtime')).resolve()
                         if os.environ.get('RSRS_ARTIFACT_SOURCE') == 'published-assets' else args.runtime_binary)
            or pathlib.Path(health.get('exe', '')).resolve() != image
            or pathlib.Path(health.get('image_path', '')).resolve() != image
            or health.get('process_start_id') != birth
            or health.get('runtime_version') != args.runtime_version
            or health.get('bin') != args.runtime_version
            or pathlib.Path(health.get('installation_root', '')).resolve() != root
            or health.get('installation_id') != hashlib.sha256(health.get('installation_root', '').encode()).hexdigest()
            or pathlib.Path(health.get('data_dir', '')).resolve() != profile
            or health.get('account_id') != hashlib.sha256(account_source.encode()).hexdigest()
            or not isinstance(health.get('instance_id'), str) or not health['instance_id']
            or not isinstance(health.get('generation'), int)
            or isinstance(health.get('generation'), bool) or health['generation'] <= 0):
        raise AssertionError('standalone Runtime process/health/scope mismatch')
    identity = (owner.pid, birth, health['instance_id'], health['account_id'], health['generation'])
    previous = next((item for item in args.runtime_identity_receipts
                     if item['_identity'] == identity), None)
    def file_identity(stat):
        # Windows stat/fstat expose different legacy ctime semantics in Python 3.12.
        timestamp = stat.st_birthtime_ns if sys.platform == 'win32' else stat.st_ctime_ns
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, timestamp)
    # procfs binds the open file to the live Linux process image. Other platforms
    # prove a stable OS path/birth and the opened disk file, not loaded memory bytes.
    source = pathlib.Path('/proc', str(owner.pid), 'exe') if sys.platform.startswith('linux') else image
    with source.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        opened_identity = file_identity(opened)
        if opened_identity != file_identity(image.stat()):
            raise AssertionError('OS image and verified Runtime disk file differ')
        if previous is None:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        else:
            if previous['_file_identity'] != opened_identity:
                raise AssertionError('Runtime disk file changed after verification')
            digest = previous['image_sha256']
        if (file_identity(os.fstat(stream.fileno())) != opened_identity
                or file_identity(image.stat()) != opened_identity):
            raise AssertionError('Runtime image file changed during digest inspection')
        if digest != args.runtime_sha256 or health.get('image_sha256') != digest:
            raise AssertionError('standalone Runtime disk image digest mismatch')
        # New psutil objects force independent post-inspection OS queries.
        if (process_start_id(owner.pid) != birth or psutil.Process(owner.pid).create_time() != created
                or pathlib.Path(psutil.Process(owner.pid).exe()).resolve(strict=True) != image):
            raise AssertionError('Runtime OS identity changed during inspection')
    if previous is None:
        receipt = {key: health[key] for key in ('installation_root', 'data_dir', 'account_id',
                   'instance_id', 'generation', 'process_start_id')}
        receipt.update(exe=str(image), os_image_path=str(image), image_sha256=digest,
                       disk_file_digest=digest, file_identity=list(opened_identity),
                       file_identity_fields=['device', 'inode', 'size', 'mtime_ns',
                                             'birthtime_ns' if sys.platform == 'win32' else 'ctime_ns'],
                       image_evidence=('linux_proc_exe_handle' if sys.platform.startswith('linux') else
                                       'stable_os_path_birth_and_open_disk_file'),
                       loaded_memory_digest=False, pid=owner.pid, create_time=created,
                       protocol_v=health['v'], runtime_version=args.runtime_version,
                       manifest_sha256=os.environ.get('RSRS_PUBLISHED_ASSETS_SHA256'),
                       bundle_sha256=os.environ.get('RSRS_PUBLISHED_BUNDLE_SHA256'),
                       provenance_evidence='upstream_verified_digest_references',
                       _identity=identity, _file_identity=opened_identity)
    else:
        receipt = previous
    if previous is None:
        args.runtime_identity_receipts.append(receipt)
    return {key: value for key, value in receipt.items() if not key.startswith('_')}


def runtime_report(args, passed):
    receipts = [{key: value for key, value in item.items() if not key.startswith('_')}
                for item in getattr(args, 'runtime_identity_receipts', [])]
    return {'runtime_mode': 'standalone_runtime' if args.runtime_binary else 'explicit_cli_shim',
            'standalone_runtime_evidence': bool(args.runtime_binary and passed and receipts),
            'runtime_binary_sha256': args.runtime_sha256 if args.runtime_binary else None,
            'runtime_version': args.runtime_version if args.runtime_binary else None,
            'runtime_identity_receipts': receipts}


def scoped_rpc_request(health, args, method='cli.exec'):
    scope = {key: health[key] for key in ('account_id', 'instance_id', 'generation')}
    if (type(health.get('v')) is not int or health['v'] != 1
            or not all(isinstance(scope[key], str) and scope[key]
            for key in ('account_id', 'instance_id'))
            or not isinstance(scope['generation'], int) or isinstance(scope['generation'], bool)
            or scope['generation'] <= 0):
        raise AssertionError('RPC requires complete health scope')
    operation = secrets.token_hex(16)
    return {'v': 1, 'id': secrets.token_hex(16), 'operation_id': operation,
            'idempotency_key': operation, 'scope': scope, 'method': method, 'args': args}


def verify_rpc_receipt(request, response):
    scope = response.get('scope')
    if (type(response.get('v')) is not int or not isinstance(scope, dict)
            or type(scope.get('generation')) is not int):
        raise AssertionError('RPC receipt protocol/scope type mismatch')
    for key in ('v', 'id', 'operation_id', 'idempotency_key', 'scope'):
        if response.get(key) != request[key]:
            raise AssertionError('RPC receipt mismatch: ' + key)
    if (not isinstance(response.get('exit'), int) or isinstance(response['exit'], bool)
            or response['exit'] < 0 or response.get('ok') is not (response['exit'] == 0)):
        raise AssertionError('RPC receipt ok/exit mismatch')


class FixtureCancelled(Exception):
    """An owned fixture command was explicitly stopped and reaped."""


def captured_run(command, *, env, timeout, cancel=None):
    # Regular files avoid communicate() waiting forever for inherited pipe EOF
    # after Windows subprocess.run() kills a timed-out direct child.
    started_unix = time.time()
    started_monotonic = time.monotonic()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr)
        try:
            if cancel is None:
                process.wait(timeout=timeout)
            else:
                deadline = started_monotonic + timeout
                while process.poll() is None:
                    if cancel.is_set():
                        raise FixtureCancelled('owned foreground probe stopped')
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    try:
                        process.wait(timeout=min(.05, remaining))
                    except subprocess.TimeoutExpired:
                        pass
            wait_completed_monotonic = time.monotonic()
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            raise
        stdout.seek(0)
        stderr.seek(0)
        result = subprocess.CompletedProcess(command, process.returncode, stdout.read(), stderr.read())
        result.fixture_timing = {'client_pid': process.pid, 'started_unix': started_unix,
            'started_monotonic': started_monotonic, 'wait_completed_monotonic': wait_completed_monotonic}
        return result


class ForegroundOverlapProbe:
    """Keep at most two real foreground calls in flight during a bounded window.

    The caller must supply an operation honoring its remaining timeout and the
    cancellation event. Only an
    actual same-snapshot pair of active inference lanes completes the challenge;
    queued work or activity in two different snapshots is insufficient.
    """
    def __init__(self, invoke, timeout=120):
        self.invoke = invoke
        self.started = time.monotonic()
        self.deadline = self.started + timeout
        self.observed = threading.Event()
        self.stopped = threading.Event()
        self.cancelled = threading.Event()
        self.calls = []
        self.errors = []
        self.threads = [threading.Thread(target=self._run, name=f'foreground-overlap-{i}', daemon=True)
                        for i in range(2)]

    def start(self):
        for thread in self.threads:
            thread.start()

    def _run(self):
        try:
            while not self.stopped.is_set() and not self.observed.is_set():
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    return
                self.calls.append(self.invoke(remaining, self.cancelled))
        except FixtureCancelled as error:
            if not self.cancelled.is_set():
                self.errors.append(error)
        except BaseException as error:
            self.errors.append(error)

    def observe(self, inference):
        # A late first overlapping heartbeat must not turn an expired challenge
        # into success (HTTP or boundary inspection can cross the deadline).
        self.check()
        if inference.get('foreground', {}).get('active') and inference.get('background', {}).get('active'):
            self.observed.set()

    def check(self):
        if self.errors:
            raise RuntimeError('foreground overlap probe failed: ' + str(self.errors[0])) from self.errors[0]
        if not self.observed.is_set() and time.monotonic() >= self.deadline:
            raise TimeoutError('concurrent foreground/background activity was not observed before the overlap deadline')

    def close(self, cancel_pending=False):
        self.stopped.set()
        if cancel_pending:
            self.cancelled.set()
        # In-flight captured_run calls honor cancellation and the shared deadline,
        # reaping their child in either case. On success, drain submitted calls
        # so their errors and completion are checked before later index checks.
        for thread in self.threads:
            thread.join(timeout=max(0, self.deadline - time.monotonic()) + 6)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError('foreground overlap probe did not stop')
        if self.errors:
            raise RuntimeError('foreground overlap probe failed: ' + str(self.errors[0])) from self.errors[0]


def inspect_worker(request, phase):
    import psutil
    phase('children')
    host = psutil.Process(request['host_pid'])
    if request.get('runtime_binary'):
        assert pathlib.Path(host.exe()).resolve() == pathlib.Path(request['runtime_binary']).resolve()
        assert process_start_id(host.pid) == request['process_start_id']
    else:
        assert '--runtime-internal' in host.cmdline(), 'inspection must target the fixture runtime'
    children = [child for child in host.children(recursive=True)
                if not (sys.platform == 'win32' and child.name().lower() == 'conhost.exe')]
    assert len(children) == 1, 'expected exactly one supervised Core worker'
    worker = children[0]
    assert worker.pid == request['worker_pid'] and worker.ppid() == host.pid
    assert '--core-worker-internal' in worker.cmdline()
    assert pathlib.Path(worker.exe()).resolve() == pathlib.Path(host.exe()).resolve()
    phase('open_files')
    assert not any(pathlib.Path(file.path).name in ('rsrs.db', 'lock.db') for file in worker.open_files())
    phase('environ')
    assert not {'GH_TOKEN', 'GITHUB_TOKEN', 'OPENAI_API_KEY', 'RSRS_SUPER'} & worker.environ().keys()
    phase('identity')
    return [worker.pid, worker.create_time()]


class WorkerInspector:
    def __init__(self, directory, timeout=5):
        self.directory = pathlib.Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.timeout = timeout
        self.sequence = 0
        self.log = (self.directory / 'inspector.log').open('wb')
        self.process = subprocess.Popen([sys.executable, '-u', __file__, str(self.directory)],
                                        stdin=subprocess.PIPE, stdout=self.log, stderr=self.log)

    def inspect(self, request):
        self.sequence += 1
        request = {**request, 'sequence': self.sequence}
        response = self.directory / ('response-' + str(self.sequence) + '.json')
        self.process.stdin.write((json.dumps(request) + '\n').encode())
        self.process.stdin.flush()
        deadline = time.monotonic() + self.timeout
        while True:
            if self.process.poll() is not None:
                self.record_failure('worker inspector exited')
                raise RuntimeError('worker inspector exited; see ' + str(self.directory / 'inspector.log'))
            if time.monotonic() >= deadline:
                self.record_failure('worker boundary inspection exceeded deadline')
                self.close()
                raise TimeoutError('worker boundary inspection exceeded ' + str(self.timeout) +
                                   's; see ' + str(self.directory / 'inspector.log'))
            try:
                result = json.loads(response.read_text(encoding='utf-8'))
                break
            except (FileNotFoundError, PermissionError):
                # Windows may briefly deny access while a just-renamed file is
                # being closed or scanned. This shares the inspection deadline.
                time.sleep(.005)
        if not result['passed']:
            self.record_failure(result.get('error', 'worker boundary assertion failed'))
            raise AssertionError(result.get('error'))
        return tuple(result['identity'])

    def record_failure(self, reason):
        # Persist before kill/wait: a cleanup failure cannot erase the cause.
        (self.directory / 'inspection-failure.json').write_text(json.dumps({
            'passed': False, 'sequence': self.sequence, 'helper_pid': self.process.pid,
            'deadline_seconds': self.timeout, 'error': reason,
        }, indent=2), encoding='utf-8')

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=5)
        finally:
            self.process.stdin.close()
            self.log.close()


def serve(directory):
    import faulthandler
    faulthandler.enable()
    directory = pathlib.Path(directory)
    import psutil
    print(json.dumps({'inspector_pid': os.getpid(), 'psutil': psutil.__version__}), flush=True)
    # One watchdog for the helper lifetime; do not create/join a timer thread
    # for every high-frequency check, and cover response I/O as well as psutil.
    faulthandler.dump_traceback_later(3, repeat=True)
    try:
        for line in sys.stdin:
            request = json.loads(line)
            sequence = request['sequence']
            def phase(name):
                print(json.dumps({'sequence': sequence, 'phase': name, 'monotonic': time.monotonic()}), flush=True)
            try:
                identity = inspect_worker(request, phase)
                result = {'passed': True, 'identity': identity}
            except Exception:
                result = {'passed': False, 'error': traceback.format_exc()}
            phase('response')
            temporary = directory / 'response.tmp'
            temporary.write_text(json.dumps(result), encoding='utf-8')
            os.replace(temporary, directory / ('response-' + str(sequence) + '.json'))
            phase('responded')
    finally:
        faulthandler.cancel_dump_traceback_later()


if __name__ == '__main__':
    if sys.argv[1] == '--install-published':
        print(install_published_runtime(sys.argv[2], dict(os.environ)))
    else:
        serve(sys.argv[1])
